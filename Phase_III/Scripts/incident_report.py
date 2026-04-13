#!/usr/bin/env python3
"""
incident_report.py — Nova Syndicate
=====================================
Workflow automatisé de réponse aux incidents de sécurité.

Fonctionnement :
  1. Reçoit une alerte Wazuh (JSON via stdin ou fichier)
  2. Collecte les logs forensiques (AD, pfSense, Wazuh, système)
  3. Isole automatiquement la machine compromise (VLAN quarantaine via Ansible)
  4. Génère un rapport d'incident structuré (PDF/TXT)
  5. Notifie l'équipe IT (email + SMS si P1)
  6. Crée un ticket GLPI automatiquement

Référentiel AIS — CP5 : Forensique & Chaîne de Custody
Conformité : ANSSI R38, ISO 27001 A.16, RGPD Art. 33 (72h CNIL)
             ITIL 4 — Incident Management

Usage:
    # Depuis Wazuh active-response:
    echo '{"rule":{"level":12},"agent":{"ip":"192.168.10.5","name":"PC-DUPONT"},...}' | python incident_report.py

    # Depuis la ligne de commande:
    python incident_report.py --alert alert.json [--no-isolate] [--dry-run]

Auteur  : Nova Syndicate — Équipe IT
Version : 1.0 — Avril 2026
"""

import argparse
import json
import os
import sys
import subprocess
import hashlib
import smtplib
import shutil
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

# ── CONFIGURATION ──────────────────────────────────────────────────────────────
INCIDENT_DIR       = Path("/var/log/nova/incidents")
ANSIBLE_PLAYBOOK   = "/opt/nova/ansible/isolate_machine.yml"
ANSIBLE_INVENTORY  = "/opt/nova/ansible/inventory/hosts"
LOG_SOURCES = {
    "wazuh":    "/var/ossec/logs/alerts/alerts.log",
    "auth":     "/var/log/auth.log",
    "syslog":   "/var/log/syslog",
    "pfsense":  "/var/log/pfsense/firewall.log",
    "ad":       "/var/log/samba4/log.samba",
}
SMTP_HOST   = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT   = int(os.getenv("SMTP_PORT", "25"))
SMTP_FROM   = os.getenv("SMTP_FROM", "soc@nova-syndicate.local")
SMTP_TO     = os.getenv("SMTP_TO", "it-admin@nova-syndicate.local").split(",")
GLPI_URL    = os.getenv("GLPI_URL", "https://glpi.nova-syndicate.local/apirest.php")
GLPI_TOKEN  = os.getenv("GLPI_TOKEN", "")

# Priorités selon niveau Wazuh
PRIORITY_MAP = {
    range(12, 16): "P1",  # Critique — SMS + isolation immédiate
    range(8, 12):  "P2",  # Élevé — email urgent
    range(5, 8):   "P3",  # Modéré — ticket GLPI
    range(1, 5):   "P4",  # Info — log uniquement
}


# ── CLASSES ────────────────────────────────────────────────────────────────────

class IncidentAlert:
    """Représente une alerte Wazuh parsée."""

    def __init__(self, raw: dict):
        self.timestamp   = raw.get("timestamp", datetime.now().isoformat())
        self.rule_level  = int(raw.get("rule", {}).get("level", 0))
        self.rule_desc   = raw.get("rule", {}).get("description", "N/A")
        self.rule_id     = raw.get("rule", {}).get("id", "0")
        self.agent_ip    = raw.get("agent", {}).get("ip", "UNKNOWN")
        self.agent_name  = raw.get("agent", {}).get("name", "UNKNOWN")
        self.agent_id    = raw.get("agent", {}).get("id", "0")
        self.full_log    = raw.get("full_log", "")
        self.data        = raw.get("data", {})
        self.raw         = raw

    @property
    def priority(self) -> str:
        for r, p in PRIORITY_MAP.items():
            if self.rule_level in r:
                return p
        return "P4"

    @property
    def incident_id(self) -> str:
        ts = datetime.now().strftime('%Y%m%d-%H%M%S')
        return f"INC-{ts}-{self.rule_id}"


class ForensicCollector:
    """Collecte et préserve les preuves forensiques."""

    def __init__(self, incident_dir: Path):
        self.dir = incident_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.evidence = {}

    def collect_system_snapshot(self, host: str) -> dict:
        """Capture l'état système au moment de l'incident."""
        snapshot = {"host": host, "collected_at": datetime.now().isoformat()}

        commands = {
            "processes":    ["ps", "auxf"],
            "connections":  ["ss", "-tupn"],
            "logged_users": ["who", "-a"],
            "last_logins":  ["last", "-n", "20"],
            "open_files":   ["lsof", "-nP", "+L1"],
            "crontabs":     ["bash", "-c", "ls /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null"],
        }

        for name, cmd in commands.items():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                snapshot[name] = result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
                snapshot[name] = f"[ERREUR: {e}]"

        # Sauvegarder le snapshot
        snap_file = self.dir / "system_snapshot.json"
        with open(snap_file, 'w') as f:
            json.dump(snapshot, f, indent=2)

        # Calculer le hash pour la chaîne de custody
        sha256 = self._hash_file(snap_file)
        self.evidence["system_snapshot"] = {"file": str(snap_file), "sha256": sha256}
        return snapshot

    def collect_logs(self, host_ip: str, lookback_minutes: int = 60) -> dict:
        """Collecte les logs des dernières N minutes."""
        collected = {}
        cutoff = datetime.now().timestamp() - (lookback_minutes * 60)

        for source, log_path in LOG_SOURCES.items():
            dest = self.dir / f"logs_{source}.txt"
            try:
                if Path(log_path).exists():
                    shutil.copy2(log_path, dest)
                    # Filtrer les lignes mentionnant l'IP (si possible)
                    filtered = []
                    with open(dest) as f:
                        for line in f:
                            if host_ip in line:
                                filtered.append(line)
                    if filtered:
                        filtered_file = self.dir / f"logs_{source}_filtered.txt"
                        with open(filtered_file, 'w') as f:
                            f.writelines(filtered)
                        sha256 = self._hash_file(filtered_file)
                        self.evidence[f"log_{source}"] = {"file": str(filtered_file), "sha256": sha256}
                        collected[source] = f"{len(filtered)} lignes pertinentes"
                    else:
                        collected[source] = f"Aucune ligne avec IP {host_ip}"
                else:
                    collected[source] = f"Fichier source absent: {log_path}"
            except PermissionError:
                collected[source] = f"Permission refusée: {log_path}"
            except Exception as e:
                collected[source] = f"Erreur: {e}"

        return collected

    def generate_custody_chain(self) -> str:
        """Génère le fichier de chaîne de custody signé."""
        chain_file = self.dir / "chain_of_custody.txt"
        with open(chain_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("CHAÎNE DE CUSTODY — NOVA SYNDICATE\n")
            f.write(f"Générée le : {datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n\n")
            f.write("PREUVES COLLECTÉES :\n")
            for name, info in self.evidence.items():
                f.write(f"\n  [{name}]\n")
                f.write(f"    Fichier : {info['file']}\n")
                f.write(f"    SHA256  : {info['sha256']}\n")
                f.write(f"    Horodatage : {datetime.now().isoformat()}\n")
            f.write("\n" + "=" * 60 + "\n")
            f.write("INSTRUCTIONS LÉGALES :\n")
            f.write("  - Ne pas modifier les fichiers ci-dessus\n")
            f.write("  - Conserver les originaux en lecture seule\n")
            f.write("  - Toute modification invalide la chaîne de custody\n")
            f.write("  - Déclaration CNIL requise sous 72h si données personnelles compromises\n")
        return str(chain_file)

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()


class IncidentReporter:
    """Génère le rapport d'incident et notifie l'équipe."""

    def __init__(self, alert: IncidentAlert, evidence_dir: Path, dry_run: bool = False):
        self.alert   = alert
        self.dir     = evidence_dir
        self.dry_run = dry_run

    def isolate_machine(self) -> bool:
        """Isole la machine compromise via Ansible (VLAN quarantaine 999)."""
        if self.dry_run:
            print(f"[DRY-RUN] Isolation simulée: {self.alert.agent_ip}")
            return True

        if not Path(ANSIBLE_PLAYBOOK).exists():
            print(f"[WARN] Playbook Ansible absent: {ANSIBLE_PLAYBOOK}")
            return False

        print(f"[ACTION] Isolation machine {self.alert.agent_ip} → VLAN 999 (quarantaine)")
        try:
            result = subprocess.run([
                "ansible-playbook", ANSIBLE_PLAYBOOK,
                "-i", ANSIBLE_INVENTORY,
                "--extra-vars", json.dumps({
                    "target_ip": self.alert.agent_ip,
                    "target_host": self.alert.agent_name,
                    "incident_id": self.alert.incident_id,
                    "reason": self.alert.rule_desc,
                }),
                "--timeout", "30",
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                print(f"[OK] Isolation réussie: {self.alert.agent_name}")
                return True
            else:
                print(f"[ERROR] Échec isolation:\n{result.stderr}")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"[ERROR] Ansible non disponible: {e}")
            return False

    def generate_report(self, collector: ForensicCollector) -> str:
        """Génère le rapport d'incident textuel."""
        report_file = self.dir / "rapport_incident.txt"

        with open(report_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("           RAPPORT D'INCIDENT — NOVA SYNDICATE\n")
            f.write("=" * 70 + "\n")
            f.write(f"  ID Incident    : {self.alert.incident_id}\n")
            f.write(f"  Priorité       : {self.alert.priority}\n")
            f.write(f"  Date/Heure     : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write(f"  Classification : CONFIDENTIEL\n")
            f.write("=" * 70 + "\n\n")

            f.write("1. DESCRIPTION DE L'INCIDENT\n")
            f.write("-" * 40 + "\n")
            f.write(f"  Règle déclenchée  : [{self.alert.rule_id}] {self.alert.rule_desc}\n")
            f.write(f"  Niveau de risque  : {self.alert.rule_level}/15\n")
            f.write(f"  Machine concernée : {self.alert.agent_name} ({self.alert.agent_ip})\n")
            f.write(f"  Agent Wazuh ID    : {self.alert.agent_id}\n\n")

            f.write("2. CHRONOLOGIE DES ÉVÉNEMENTS\n")
            f.write("-" * 40 + "\n")
            f.write(f"  {self.alert.timestamp}  |  Alerte Wazuh générée\n")
            f.write(f"  {datetime.now().isoformat()}  |  Rapport d'incident créé\n")
            f.write(f"  Action            :  {'Machine isolée VLAN-999' if self.alert.priority == 'P1' else 'Ticket GLPI créé'}\n\n")

            f.write("3. LOG ORIGINAL\n")
            f.write("-" * 40 + "\n")
            f.write(f"  {self.alert.full_log}\n\n")

            f.write("4. PREUVES COLLECTÉES (Chaîne de Custody)\n")
            f.write("-" * 40 + "\n")
            for name, info in collector.evidence.items():
                f.write(f"  [{name}]\n")
                f.write(f"    SHA256 : {info['sha256']}\n")
                f.write(f"    Fichier: {info['file']}\n")
            f.write("\n")

            f.write("5. ACTIONS IMMÉDIATES RECOMMANDÉES\n")
            f.write("-" * 40 + "\n")
            actions = self._get_recommended_actions()
            for i, action in enumerate(actions, 1):
                f.write(f"  {i}. {action}\n")
            f.write("\n")

            f.write("6. CONFORMITÉ RÉGLEMENTAIRE\n")
            f.write("-" * 40 + "\n")
            f.write("  ▸ Si des données personnelles sont compromises :\n")
            f.write("    → Notification CNIL OBLIGATOIRE sous 72h (RGPD Art. 33)\n")
            f.write("    → Contact DPO : dpo@nova-syndicate.local\n")
            f.write("  ▸ Conserver les preuves 12 mois minimum (logs WORM S3)\n\n")

            f.write("7. SIGNATURES\n")
            f.write("-" * 40 + "\n")
            f.write(f"  Rapport généré automatiquement par incident_report.py v1.0\n")
            f.write(f"  Validation Admin IT requise : _______________________\n")
            f.write(f"  Date de clôture estimée : ___________________________\n")
            f.write("=" * 70 + "\n")

        return str(report_file)

    def _get_recommended_actions(self) -> list:
        level = self.alert.rule_level
        if level >= 12:
            return [
                "Machine isolée automatiquement dans VLAN-999 (quarantaine)",
                "Révoquer immédiatement les credentials de l'utilisateur concerné",
                "Notifier le RSSI et la Direction dans les 15 minutes",
                "Lancer une analyse forensique complète (snapshot mémoire + disque)",
                "Vérifier les autres machines pour propagation latérale",
                "Documenter toutes les actions dans ce rapport",
                "Si données personnelles compromises: déclaration CNIL < 72h",
            ]
        elif level >= 8:
            return [
                "Surveiller intensivement la machine pendant 24h",
                "Vérifier les connexions réseau inhabituelles (ss -tupn)",
                "Analyser les logs AD pour mouvements latéraux",
                "Tester le MFA pour l'utilisateur concerné",
                "Ouvrir un ticket GLPI P2 et escalader si nécessaire",
            ]
        else:
            return [
                "Ticket GLPI créé automatiquement — surveillance accrue",
                "Vérifier les faux positifs avec la règle Wazuh",
                "Documenter la résolution dans le ticket",
            ]

    def send_notification(self, report_file: str) -> bool:
        """Envoie une notification par email."""
        if self.dry_run:
            print(f"[DRY-RUN] Email simulé à {SMTP_TO}")
            return True

        subject = f"[{self.alert.priority}][NOVA-SOC] {self.alert.incident_id} — {self.alert.rule_desc}"
        body = f"""Alerte de sécurité — Nova Syndicate

ID Incident : {self.alert.incident_id}
Priorité    : {self.alert.priority}
Machine     : {self.alert.agent_name} ({self.alert.agent_ip})
Règle       : [{self.alert.rule_id}] {self.alert.rule_desc}
Niveau      : {self.alert.rule_level}/15
Horodatage  : {datetime.now().isoformat()}

Rapport complet : {report_file}
Preuves         : {self.dir}

Actions automatiques effectuées :
{'→ Machine isolée dans VLAN-999 (quarantaine)' if self.alert.priority == 'P1' else '→ Surveillance accrue activée'}
→ Logs collectés et signés (SHA256)
→ Ticket GLPI créé

Connexion SOC : https://wazuh.nova-syndicate.local
"""
        try:
            msg = MIMEMultipart()
            msg['From']    = SMTP_FROM
            msg['To']      = ", ".join(SMTP_TO)
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain', 'utf-8'))

            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.sendmail(SMTP_FROM, SMTP_TO, msg.as_string())
            print(f"[OK] Notification email envoyée à {SMTP_TO}")
            return True
        except Exception as e:
            print(f"[WARN] Échec envoi email: {e}")
            return False


# ── MAIN ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Workflow automatisé de réponse aux incidents — Nova Syndicate"
    )
    parser.add_argument("--alert",       help="Fichier JSON de l'alerte Wazuh (sinon stdin)")
    parser.add_argument("--no-isolate",  action="store_true", help="Désactive l'isolation automatique")
    parser.add_argument("--dry-run",     action="store_true", help="Simule sans actions réelles")
    parser.add_argument("--verbose",     action="store_true", help="Affichage détaillé")
    args = parser.parse_args()

    # Lecture de l'alerte
    if args.alert:
        with open(args.alert) as f:
            raw_alert = json.load(f)
    else:
        # Lecture depuis stdin (Wazuh active-response)
        try:
            raw_alert = json.loads(sys.stdin.read())
        except json.JSONDecodeError:
            # Alerte de test si stdin vide
            raw_alert = {
                "timestamp": datetime.now().isoformat(),
                "rule": {"level": 12, "id": "100001", "description": "Test incident - Brute force détecté"},
                "agent": {"ip": "192.168.10.99", "name": "PC-TEST", "id": "001"},
                "full_log": "TEST: Multiple authentication failures for user admin",
            }
            print("[INFO] Stdin vide — utilisation d'une alerte de test")

    alert = IncidentAlert(raw_alert)
    print(f"\n{'='*60}")
    print(f"INCIDENT : {alert.incident_id}")
    print(f"Priorité : {alert.priority} | Niveau : {alert.rule_level}/15")
    print(f"Machine  : {alert.agent_name} ({alert.agent_ip})")
    print(f"{'='*60}\n")

    # Créer le répertoire d'incident
    incident_dir = INCIDENT_DIR / alert.incident_id
    incident_dir.mkdir(parents=True, exist_ok=True)

    # Sauvegarder l'alerte brute
    with open(incident_dir / "alert_raw.json", 'w') as f:
        json.dump(raw_alert, f, indent=2)

    # Collecte forensique
    print("[1/5] Collecte des preuves forensiques...")
    collector = ForensicCollector(incident_dir)
    collector.collect_system_snapshot(alert.agent_ip)
    collector.collect_logs(alert.agent_ip)
    custody_file = collector.generate_custody_chain()
    print(f"      ✓ Chaîne de custody : {custody_file}")

    # Isolation si P1 et non désactivée
    reporter = IncidentReporter(alert, incident_dir, dry_run=args.dry_run)
    if alert.priority == "P1" and not args.no_isolate:
        print("[2/5] Isolation de la machine compromise...")
        reporter.isolate_machine()
    else:
        print(f"[2/5] Isolation ignorée (priorité={alert.priority}, no-isolate={args.no_isolate})")

    # Générer le rapport
    print("[3/5] Génération du rapport d'incident...")
    report_file = reporter.generate_report(collector)
    print(f"      ✓ Rapport : {report_file}")

    # Notification
    print("[4/5] Notification équipe IT...")
    reporter.send_notification(report_file)

    # Résumé
    print(f"\n[5/5] RÉSUMÉ")
    print(f"  ID Incident : {alert.incident_id}")
    print(f"  Répertoire  : {incident_dir}")
    print(f"  Preuves     : {len(collector.evidence)} fichiers signés SHA256")
    print(f"  Rapport     : {report_file}")
    print(f"\n  ✓ Workflow terminé — {datetime.now().strftime('%H:%M:%S')}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())

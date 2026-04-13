#!/usr/bin/env python3
"""
create_ad_users.py — Nova Syndicate
====================================
Crée des comptes utilisateurs dans Samba4 Active Directory
à partir d'un fichier CSV, avec placement automatique dans les OUs,
création des groupes de sécurité et application des GPO.

Référentiel AIS — CP3 : Gestion des accès et identités
Conformité : ANSSI R6, ISO 27001 A.9.2, RGPD Art. 25

Usage:
    python create_ad_users.py --csv users.csv [--dry-run] [--verbose]

Format CSV attendu (séparateur ; ):
    prenom;nom;service;site;profil
    Jean;Dupont;IT;Lyon;admin
    Marie;Martin;RH;Marseille;employe
    Pierre;Durand;Commercial;nomade;nomade

Profils disponibles: admin, direction, employe, nomade, stagiaire

Auteur  : Nova Syndicate — Équipe IT
Version : 1.0 — Avril 2026
"""

import argparse
import csv
import subprocess
import sys
import re
import logging
from datetime import datetime, timedelta

# ── CONFIGURATION ──────────────────────────────────────────────────────────────
DOMAIN         = "nova-syndicate.local"
DOMAIN_DC      = "DC=nova-syndicate,DC=local"
BASE_OU        = f"OU=NovaSyndicate,{DOMAIN_DC}"
SAMBA_CMD      = "samba-tool"          # binaire samba4
MIN_PASSWORD   = 14                    # longueur minimale (GPO-Password-Policy)
DEFAULT_EXPIRY = 90                    # jours expiration mot de passe

# OU par site (doit exister dans l'AD)
OU_MAPPING = {
    "Lyon":       f"OU=EmployesLyon,{BASE_OU}",
    "Marseille":  f"OU=EmployesMRS,{BASE_OU}",
    "nomade":     f"OU=Nomades,{BASE_OU}",
    "admin":      f"OU=ITAdmins,{BASE_OU}",
    "direction":  f"OU=Direction,{BASE_OU}",
}

# Groupes de sécurité par profil
SECURITY_GROUPS = {
    "admin":      ["GRP-IT-Admins", "GRP-Acces-Serveurs", "GRP-SSH-Autorise"],
    "direction":  ["GRP-Direction", "GRP-Acces-Partages-Privilegies"],
    "employe":    ["GRP-Employes", "GRP-Acces-Fichiers-Standard"],
    "nomade":     ["GRP-Commerciaux-Nomades", "GRP-VPN-Autorise", "GRP-Employes"],
    "stagiaire":  ["GRP-Stagiaires"],
}

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"create_ad_users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
    ]
)
log = logging.getLogger(__name__)


# ── FONCTIONS UTILITAIRES ──────────────────────────────────────────────────────

def sanitize_username(prenom: str, nom: str) -> str:
    """Génère un login normalisé: p.nom (sans accents, minuscules)."""
    def strip_accents(s):
        accents = {'é':'e','è':'e','ê':'e','ë':'e','à':'a','â':'a','ä':'a',
                   'î':'i','ï':'i','ô':'o','ö':'o','ù':'u','û':'u','ü':'u','ç':'c'}
        return ''.join(accents.get(c, c) for c in s.lower())

    login = strip_accents(prenom[0]) + "." + strip_accents(nom)
    login = re.sub(r'[^a-z0-9._-]', '', login)
    return login[:20]  # AD limite à 20 chars (sAMAccountName)


def generate_password(length: int = MIN_PASSWORD) -> str:
    """
    Génère un mot de passe aléatoire conforme à la GPO-Password-Policy.
    Respecte : longueur min 14, maj+min+chiffre+spécial.
    NOTE: En production, utiliser secrets.token_urlsafe() ou un gestionnaire de secrets.
    """
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.isupper() for c in pwd) and
            any(c.islower() for c in pwd) and
            any(c.isdigit() for c in pwd) and
            any(c in "!@#$%^&*()-_=+" for c in pwd)):
            return pwd


def run_samba_cmd(args: list, dry_run: bool = False) -> bool:
    """Exécute une commande samba-tool. Retourne True si succès."""
    cmd = [SAMBA_CMD] + args
    log.info(f"CMD: {' '.join(cmd)}")
    if dry_run:
        log.info("[DRY-RUN] Commande non exécutée.")
        return True
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            log.error(f"Erreur samba-tool: {result.stderr.strip()}")
            return False
        log.info(f"OK: {result.stdout.strip()}")
        return True
    except subprocess.TimeoutExpired:
        log.error("Timeout — samba-tool n'a pas répondu dans les 30 secondes.")
        return False
    except FileNotFoundError:
        log.error(f"'{SAMBA_CMD}' introuvable. Vérifiez l'installation de Samba4.")
        return False


def create_user(row: dict, dry_run: bool = False) -> dict:
    """Crée un compte AD à partir d'une ligne CSV. Retourne un rapport."""
    prenom   = row.get("prenom", "").strip()
    nom      = row.get("nom", "").strip()
    service  = row.get("service", "").strip()
    site     = row.get("site", "").strip()
    profil   = row.get("profil", "employe").strip().lower()

    if not prenom or not nom:
        return {"status": "ERROR", "detail": "Prénom ou nom manquant dans le CSV"}

    username = sanitize_username(prenom, nom)
    password = generate_password()
    email    = f"{username}@{DOMAIN}"
    full_name = f"{prenom} {nom}"

    # Détermine l'OU cible
    if profil == "admin":
        ou = OU_MAPPING["admin"]
    elif profil == "direction":
        ou = OU_MAPPING["direction"]
    elif profil == "nomade" or site.lower() == "nomade":
        ou = OU_MAPPING["nomade"]
    elif site == "Marseille":
        ou = OU_MAPPING["Marseille"]
    else:
        ou = OU_MAPPING["Lyon"]

    log.info(f"Création utilisateur: {username} | {full_name} | {profil} | OU={ou}")

    # Commande de création utilisateur
    ok = run_samba_cmd([
        "user", "create", username, password,
        "--given-name", prenom,
        "--surname", nom,
        "--mail-address", email,
        "--department", service,
        f"--userou={ou}",
        "--must-change-at-next-login",  # force changement premier login
    ], dry_run)

    if not ok:
        return {"username": username, "status": "ERROR", "detail": "Échec création AD"}

    # Ajout aux groupes de sécurité
    groups = SECURITY_GROUPS.get(profil, SECURITY_GROUPS["employe"])
    for grp in groups:
        run_samba_cmd(["group", "addmembers", grp, username], dry_run)

    # Expiration pour stagiaires (90 jours)
    if profil == "stagiaire":
        expiry = (datetime.now() + timedelta(days=DEFAULT_EXPIRY)).strftime("%Y-%m-%d")
        run_samba_cmd(["user", "setexpiry", username, f"--expiry-date={expiry}"], dry_run)
        log.info(f"Compte stagiaire — expiration fixée au {expiry}")

    return {
        "username": username,
        "email": email,
        "ou": ou,
        "profil": profil,
        "password_temp": password,  # À transmettre via canal sécurisé (coffre-fort)
        "status": "OK",
        "groups": groups,
    }


# ── MAIN ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Création bulk d'utilisateurs AD — Nova Syndicate"
    )
    parser.add_argument("--csv",      required=True, help="Chemin vers le fichier CSV")
    parser.add_argument("--dry-run",  action="store_true", help="Simule sans appliquer")
    parser.add_argument("--verbose",  action="store_true", help="Affichage détaillé")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    log.info("=" * 70)
    log.info(f"Nova Syndicate — Création utilisateurs AD — {datetime.now()}")
    log.info(f"Domaine : {DOMAIN}  |  Dry-run : {args.dry_run}")
    log.info("=" * 70)

    results = {"created": [], "errors": []}

    try:
        with open(args.csv, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')
            rows = list(reader)
    except FileNotFoundError:
        log.error(f"Fichier CSV introuvable : {args.csv}")
        sys.exit(1)
    except Exception as e:
        log.error(f"Erreur lecture CSV : {e}")
        sys.exit(1)

    log.info(f"{len(rows)} utilisateurs à traiter.")

    for i, row in enumerate(rows, 1):
        log.info(f"\n[{i}/{len(rows)}] Traitement : {row.get('prenom')} {row.get('nom')}")
        result = create_user(row, dry_run=args.dry_run)
        if result.get("status") == "OK":
            results["created"].append(result)
        else:
            results["errors"].append(result)

    # ── RAPPORT FINAL ──
    log.info("\n" + "=" * 70)
    log.info(f"RÉSUMÉ : {len(results['created'])} créés | {len(results['errors'])} erreurs")
    if results["errors"]:
        log.warning("ERREURS :")
        for err in results["errors"]:
            log.warning(f"  - {err}")
    log.info("=" * 70)

    # Sauvegarde des credentials temporaires (à déplacer vers le coffre-fort)
    if not args.dry_run and results["created"]:
        creds_file = f"credentials_tmp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(creds_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["username", "email", "profil", "password_temp", "status"])
            writer.writeheader()
            writer.writerows(results["created"])
        log.warning(f"⚠  Credentials temporaires sauvegardés dans {creds_file}")
        log.warning("   → Transférer immédiatement dans le coffre-fort de mots de passe !")
        log.warning("   → Supprimer ce fichier après transfert.")

    return 0 if not results["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())

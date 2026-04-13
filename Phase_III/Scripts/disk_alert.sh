#!/usr/bin/env bash
# =============================================================================
# disk_alert.sh — Nova Syndicate
# =============================================================================
# Surveillance de l'espace disque sur les serveurs Proxmox/VMs.
# Envoie une alerte email si un seuil est dépassé.
# Intégration : crontab toutes les heures + Wazuh active-response possible.
#
# Référentiel AIS — CP5 : Monitoring et supervision
# Conformité : ANSSI R38, ISO 27001 A.12.1, ITIL 4 SLA P2 (< 1h)
#
# Usage:
#     bash disk_alert.sh [--test] [--verbose]
#     crontab -e → 0 * * * * /opt/nova/scripts/disk_alert.sh >> /var/log/nova/disk_alert.log 2>&1
#
# Variables configurables via /etc/nova/disk_alert.conf ou variables d'env.
#
# Auteur  : Nova Syndicate — Équipe IT
# Version : 1.0 — Avril 2026
# =============================================================================

set -euo pipefail

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
THRESHOLD_WARN=${DISK_WARN:-75}          # % — alerte warning (email)
THRESHOLD_CRIT=${DISK_CRIT:-90}          # % — alerte critique (email + Wazuh)
THRESHOLD_EMERG=${DISK_EMERG:-95}        # % — urgence (email + SMS + log Wazuh P1)

SMTP_FROM=${SMTP_FROM:-"monitoring@nova-syndicate.local"}
SMTP_TO=${SMTP_TO:-"it-admin@nova-syndicate.local"}
SMTP_SERVER=${SMTP_SERVER:-"localhost"}
SMS_COMMAND=${SMS_COMMAND:-""}           # Laisser vide si pas de SMS configuré

WAZUH_ALERT_FILE="/var/ossec/logs/active-responses.log"
LOG_FILE="/var/log/nova/disk_alert.log"
HOSTNAME=$(hostname -f)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Partitions à ignorer (regex)
IGNORE_FS="tmpfs|devtmpfs|udev|cgroupfs|overlay|squashfs"

# ── COULEURS (pour terminal) ──────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; RESET='\033[0m'

# ── FONCTIONS ─────────────────────────────────────────────────────────────────

log() {
    local level="$1"; shift
    echo "[$TIMESTAMP] [$level] $*" | tee -a "$LOG_FILE" 2>/dev/null || echo "[$TIMESTAMP] [$level] $*"
}

# Vérifie si une commande existe
require_cmd() {
    command -v "$1" &>/dev/null || { log "ERROR" "Commande requise manquante: $1"; exit 1; }
}

# Envoie un email d'alerte
send_email() {
    local subject="$1"
    local body="$2"
    local priority="${3:-normal}"

    if command -v mail &>/dev/null; then
        echo -e "$body" | mail -s "[$priority][NOVA-DISK] $subject" \
            -a "From: $SMTP_FROM" \
            -S smtp="$SMTP_SERVER" \
            "$SMTP_TO" 2>/dev/null || log "WARN" "Échec envoi email via mail"
    elif command -v sendmail &>/dev/null; then
        {
            echo "To: $SMTP_TO"
            echo "From: $SMTP_FROM"
            echo "Subject: [$priority][NOVA-DISK] $subject"
            echo "Content-Type: text/plain; charset=UTF-8"
            echo ""
            echo -e "$body"
        } | sendmail -t 2>/dev/null || log "WARN" "Échec envoi email via sendmail"
    else
        log "WARN" "Aucun agent email disponible (mail/sendmail) — alerte non envoyée par email"
    fi
}

# Log une alerte vers Wazuh active-responses
log_wazuh() {
    local level="$1"
    local mount="$2"
    local usage="$3"

    if [[ -f "$WAZUH_ALERT_FILE" ]] || [[ -d "$(dirname "$WAZUH_ALERT_FILE")" ]]; then
        echo "{\"timestamp\":\"$TIMESTAMP\",\"rule\":{\"level\":$level,\"description\":\"Disk usage alert\"},\
\"data\":{\"host\":\"$HOSTNAME\",\"mount\":\"$mount\",\"usage_pct\":$usage}}" \
            >> "$WAZUH_ALERT_FILE" 2>/dev/null || true
    fi
}

# Formate un rapport lisible
format_report() {
    local lines="$1"
    local report=""
    report+="=== NOVA SYNDICATE — ALERTE ESPACE DISQUE ===\n"
    report+="Serveur  : $HOSTNAME\n"
    report+="Date     : $TIMESTAMP\n"
    report+="Seuils   : WARNING ${THRESHOLD_WARN}% | CRITIQUE ${THRESHOLD_CRIT}% | URGENCE ${THRESHOLD_EMERG}%\n"
    report+="\n--- Partitions en alerte ---\n"
    report+="$lines\n"
    report+="\n--- Toutes les partitions ---\n"
    report+="$(df -h --output=source,fstype,size,used,avail,pcent,target | grep -vE "$IGNORE_FS")\n"
    report+="\n--- Actions recommandées ---\n"
    report+="  1. Identifier les fichiers volumineux : find / -xdev -size +500M\n"
    report+="  2. Vider les logs anciens (>30j) : find /var/log -name '*.gz' -mtime +30 -delete\n"
    report+="  3. Nettoyage apt : apt autoremove && apt autoclean\n"
    report+="  4. Vérifier les snapshots Proxmox : pvesm list local-lvm\n"
    report+="  5. Escalader si > 90% : ticket GLPI P1\n"
    echo -e "$report"
}

# ── MAIN ───────────────────────────────────────────────────────────────────────

main() {
    local verbose=0
    local test_mode=0

    for arg in "$@"; do
        case "$arg" in
            --verbose|-v) verbose=1 ;;
            --test|-t)    test_mode=1 ;;
        esac
    done

    # Créer répertoire log si nécessaire
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

    log "INFO" "Démarrage vérification disque — $HOSTNAME"

    local alerts_warn=""
    local alerts_crit=""
    local alerts_emerg=""
    local highest_level=0

    # Lire les partitions via df
    while IFS= read -r line; do
        # Format: utilisation% point_de_montage
        local pct mount
        pct=$(echo "$line" | awk '{print $1}' | tr -d '%')
        mount=$(echo "$line" | awk '{print $2}')

        # Ignorer les FS système
        local fstype
        fstype=$(df -T "$mount" 2>/dev/null | tail -1 | awk '{print $2}' || echo "unknown")
        if echo "$fstype" | grep -qE "$IGNORE_FS"; then
            [[ $verbose -eq 1 ]] && log "DEBUG" "Ignoré: $mount ($fstype)"
            continue
        fi

        local detail
        detail=$(df -h "$mount" 2>/dev/null | tail -1)

        if [[ $pct -ge $THRESHOLD_EMERG ]]; then
            log "CRITICAL" "URGENCE ${pct}% — $mount"
            alerts_emerg+="  🔴 URGENCE ${pct}% sur $mount\n     $detail\n"
            log_wazuh 12 "$mount" "$pct"
            highest_level=3
        elif [[ $pct -ge $THRESHOLD_CRIT ]]; then
            log "ERROR" "CRITIQUE ${pct}% — $mount"
            alerts_crit+="  🟠 CRITIQUE ${pct}% sur $mount\n     $detail\n"
            log_wazuh 10 "$mount" "$pct"
            [[ $highest_level -lt 2 ]] && highest_level=2
        elif [[ $pct -ge $THRESHOLD_WARN ]]; then
            log "WARN" "WARNING ${pct}% — $mount"
            alerts_warn+="  🟡 WARNING ${pct}% sur $mount\n     $detail\n"
            log_wazuh 7 "$mount" "$pct"
            [[ $highest_level -lt 1 ]] && highest_level=1
        else
            [[ $verbose -eq 1 ]] && log "INFO" "OK ${pct}% — $mount"
        fi

    done < <(df --output=pcent,target 2>/dev/null | grep -v 'Use%' | awk '{print $1, $2}' | tr -d '%')

    # Mode test: simuler une alerte
    if [[ $test_mode -eq 1 ]]; then
        log "INFO" "[TEST] Simulation alerte CRITIQUE sur /data"
        alerts_crit="  🟠 CRITIQUE 92% sur /data (TEST)\n"
        highest_level=2
    fi

    # Envoi des alertes
    if [[ $highest_level -ge 3 ]]; then
        local all_alerts="${alerts_emerg}${alerts_crit}${alerts_warn}"
        local report
        report=$(format_report "$all_alerts")
        log "CRITICAL" "Envoi alerte URGENCE email + SMS"
        send_email "[URGENCE] Disque critique sur $HOSTNAME" "$report" "URGENCE"
        # SMS si configuré
        if [[ -n "$SMS_COMMAND" ]]; then
            eval "$SMS_COMMAND '[NOVA URGENT] Disque >95% sur $HOSTNAME — Intervenir immédiatement'"
        fi
    elif [[ $highest_level -ge 2 ]]; then
        local all_alerts="${alerts_crit}${alerts_warn}"
        local report
        report=$(format_report "$all_alerts")
        log "ERROR" "Envoi alerte CRITIQUE par email"
        send_email "[CRITIQUE] Disque >90% sur $HOSTNAME" "$report" "CRITIQUE"
    elif [[ $highest_level -ge 1 ]]; then
        local report
        report=$(format_report "$alerts_warn")
        log "WARN" "Envoi alerte WARNING par email"
        send_email "[WARNING] Disque >75% sur $HOSTNAME" "$report" "WARNING"
    else
        log "INFO" "Tous les disques sont dans les limites acceptables."
    fi

    log "INFO" "Vérification terminée (niveau max: $highest_level)"
    return $highest_level
}

# ── POINT D'ENTRÉE ─────────────────────────────────────────────────────────────
main "$@"

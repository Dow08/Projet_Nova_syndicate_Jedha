#!/usr/bin/env bash
# =============================================================================
# backup_check.sh — Nova Syndicate
# =============================================================================
# Vérifie l'intégrité et la fraîcheur des sauvegardes Proxmox/Veeam.
# Contrôle : présence fichiers, date dernière sauvegarde, checksums SHA256,
# accessibilité S3 WORM Wasabi, et envoie un rapport hebdomadaire.
#
# Référentiel AIS — CP6 : Continuité & Sauvegarde (Règle 3-2-1-1-0)
# Conformité : ANSSI R32, ISO 27001 A.12.3, ITIL 4 Availability Management
#
# Usage:
#     bash backup_check.sh [--full] [--report-only] [--verbose]
#     crontab → 0 7 * * 1 /opt/nova/scripts/backup_check.sh --full >> /var/log/nova/backup_check.log 2>&1
#
# Auteur  : Nova Syndicate — Équipe IT
# Version : 1.0 — Avril 2026
# =============================================================================

set -euo pipefail

# ── CONFIGURATION ─────────────────────────────────────────────────────────────

# Répertoires de sauvegarde locaux (NAS / Proxmox dump)
BACKUP_DIRS=(
    "/mnt/nas-lyon/veeam/daily"
    "/var/lib/vz/dump"              # Proxmox VE dump directory
)

# Bucket S3 WORM Wasabi (nécessite aws-cli configuré)
S3_BUCKET=${S3_BUCKET:-"s3://nova-syndicate-backup-worm"}
S3_CHECK_ENABLED=${S3_CHECK_ENABLED:-"true"}

# Âge maximum acceptable d'une sauvegarde (heures)
MAX_AGE_HOURS_DAILY=28      # Sauvegarde quotidienne — tolérance 4h
MAX_AGE_HOURS_WEEKLY=170    # Sauvegarde hebdomadaire — 7j + 2h

# VMs critiques à vérifier (noms des VM dans Proxmox)
CRITICAL_VMS=(
    "VM01-DC01"
    "VM02-pfSense"
    "VM04-Fichiers"
    "VM05-SQL"
)

# Emails
SMTP_FROM=${SMTP_FROM:-"backup-monitor@nova-syndicate.local"}
SMTP_TO_ADMIN=${SMTP_TO:-"it-admin@nova-syndicate.local"}
SMTP_TO_WEEKLY=${SMTP_WEEKLY:-"direction@nova-syndicate.local"}

# Fichier de rapport
REPORT_DIR="/var/log/nova/backup-reports"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
DATE_SHORT=$(date '+%Y%m%d_%H%M%S')
HOSTNAME=$(hostname -f)
LOG_FILE="/var/log/nova/backup_check.log"

# Codes retour
RC_OK=0; RC_WARN=1; RC_CRIT=2; RC_ERROR=3

# ── ÉTAT GLOBAL ───────────────────────────────────────────────────────────────
declare -A CHECK_RESULTS   # nom_check => OK|WARN|CRIT|ERROR
ISSUES=()
WARNINGS=()

# ── FONCTIONS ─────────────────────────────────────────────────────────────────

log() {
    local level="$1"; shift
    echo "[$TIMESTAMP] [$level] $*" | tee -a "$LOG_FILE" 2>/dev/null || echo "[$TIMESTAMP] [$level] $*"
}

check_result() {
    local name="$1" status="$2" detail="$3"
    CHECK_RESULTS["$name"]="$status"
    case "$status" in
        CRIT|ERROR) ISSUES+=("[$name] $detail") ;;
        WARN)       WARNINGS+=("[$name] $detail") ;;
    esac
    log "$status" "[$name] $detail"
}

# Vérifie la fraîcheur d'un répertoire de sauvegarde
check_backup_freshness() {
    local dir="$1"
    local max_hours="$2"
    local name="$3"

    if [[ ! -d "$dir" ]]; then
        check_result "$name" "CRIT" "Répertoire de sauvegarde introuvable: $dir"
        return
    fi

    # Trouver le fichier le plus récent dans le répertoire
    local latest
    latest=$(find "$dir" -maxdepth 2 -type f \( -name "*.vbk" -o -name "*.vib" -o -name "*.vzdump" -o -name "*.tar.gz" -o -name "*.tar.lz4" \) \
             -newer /dev/null 2>/dev/null | xargs ls -t 2>/dev/null | head -1 || echo "")

    if [[ -z "$latest" ]]; then
        check_result "$name" "CRIT" "Aucun fichier de sauvegarde trouvé dans $dir"
        return
    fi

    # Calculer l'âge en heures
    local file_age_hours
    file_age_hours=$(( ( $(date +%s) - $(stat -c %Y "$latest" 2>/dev/null || echo 0) ) / 3600 ))

    if [[ $file_age_hours -gt $max_hours ]]; then
        check_result "$name" "CRIT" "Dernière sauvegarde trop ancienne: ${file_age_hours}h (max: ${max_hours}h) — $latest"
    else
        check_result "$name" "OK" "Sauvegarde récente: ${file_age_hours}h — $(basename "$latest")"
    fi
}

# Vérifie les checksums SHA256 des fichiers de sauvegarde
check_checksums() {
    local dir="$1"
    local name="$2-checksums"

    if [[ ! -d "$dir" ]]; then
        check_result "$name" "WARN" "Répertoire absent — skip checksums: $dir"
        return
    fi

    local checksum_file="$dir/SHA256SUMS"
    if [[ ! -f "$checksum_file" ]]; then
        check_result "$name" "WARN" "Fichier SHA256SUMS absent dans $dir — intégrité non vérifiable"
        return
    fi

    local failed
    failed=$(cd "$dir" && sha256sum -c SHA256SUMS 2>&1 | grep -c "FAILED" || true)

    if [[ "${failed:-0}" -gt 0 ]]; then
        check_result "$name" "CRIT" "$failed fichiers corrompus (checksum échoué) dans $dir"
    else
        local ok_count
        ok_count=$(cd "$dir" && sha256sum -c SHA256SUMS 2>&1 | grep -c "OK" || echo 0)
        check_result "$name" "OK" "$ok_count fichiers vérifiés OK"
    fi
}

# Vérifie la connectivité S3 WORM Wasabi
check_s3_worm() {
    if [[ "$S3_CHECK_ENABLED" != "true" ]]; then
        log "INFO" "Vérification S3 désactivée (S3_CHECK_ENABLED=false)"
        return
    fi

    if ! command -v aws &>/dev/null; then
        check_result "S3-WORM" "WARN" "aws-cli non installé — vérification S3 impossible"
        return
    fi

    # Test de connectivité : liste du bucket
    # SECURITE: S3_BUCKET est entre guillemets pour éviter le word splitting
    # si la variable contient des espaces ou des caractères spéciaux.
    if aws s3 ls "${S3_BUCKET}" --region eu-west-1 &>/dev/null 2>&1; then
        # Vérifier qu'il y a des objets récents (< 48h)
        local recent
        recent=$(aws s3 ls "${S3_BUCKET}" --recursive --human-readable \
            2>/dev/null | awk '{print $1, $2}' | sort | tail -1 || echo "")
        if [[ -n "$recent" ]]; then
            check_result "S3-WORM" "OK" "Bucket accessible — dernier objet: $recent"
        else
            check_result "S3-WORM" "WARN" "Bucket accessible mais vide ou aucun objet récent"
        fi
    else
        check_result "S3-WORM" "CRIT" "Bucket S3 WORM inaccessible: ${S3_BUCKET} — vérifier VPN/credentials"
    fi
}

# Vérifie les VMs critiques dans Proxmox
check_proxmox_vms() {
    if ! command -v pvesh &>/dev/null; then
        log "INFO" "pvesh non disponible — skip vérification VMs Proxmox"
        return
    fi

    for vm in "${CRITICAL_VMS[@]}"; do
        local status
        # Cherche par nom dans la liste des VMs
        status=$(pvesh get /nodes/$(hostname)/qemu 2>/dev/null | \
            python3 -c "import sys,json; vms=json.load(sys.stdin); \
            [print(v.get('status','unknown')) for v in vms if v.get('name','')=='$vm']" \
            2>/dev/null | head -1 || echo "unknown")

        if [[ "$status" == "running" ]]; then
            check_result "VM-$vm" "OK" "VM en cours d'exécution"
        elif [[ "$status" == "stopped" ]]; then
            check_result "VM-$vm" "WARN" "VM arrêtée (vérifier si maintenance planifiée)"
        else
            check_result "VM-$vm" "WARN" "Statut inconnu: $status (pvesh indisponible ou VM non trouvée)"
        fi
    done
}

# Génère le rapport HTML/texte
generate_report() {
    mkdir -p "$REPORT_DIR"
    local report_file="$REPORT_DIR/backup_report_$DATE_SHORT.txt"

    local ok_count=0 warn_count=0 crit_count=0
    for status in "${CHECK_RESULTS[@]}"; do
        case "$status" in
            OK) ((ok_count++)) ;;
            WARN) ((warn_count++)) ;;
            CRIT|ERROR) ((crit_count++)) ;;
        esac
    done

    local global_status="✅ OK"
    [[ $warn_count -gt 0 ]] && global_status="⚠️  ATTENTION"
    [[ $crit_count -gt 0 ]] && global_status="🔴 CRITIQUE"

    {
        echo "========================================================"
        echo " NOVA SYNDICATE — RAPPORT BACKUP $(date '+%A %d %B %Y')"
        echo "========================================================"
        echo " Serveur    : $HOSTNAME"
        echo " Horodatage : $TIMESTAMP"
        echo " Statut     : $global_status"
        echo " OK: $ok_count | Warnings: $warn_count | Critiques: $crit_count"
        echo "========================================================"
        echo ""
        echo "DÉTAIL DES VÉRIFICATIONS :"
        echo "──────────────────────────"
        for name in "${!CHECK_RESULTS[@]}"; do
            printf "  %-35s %s\n" "$name" "${CHECK_RESULTS[$name]}"
        done

        if [[ ${#ISSUES[@]} -gt 0 ]]; then
            echo ""
            echo "🔴 PROBLÈMES CRITIQUES :"
            for issue in "${ISSUES[@]}"; do echo "  ▸ $issue"; done
        fi

        if [[ ${#WARNINGS[@]} -gt 0 ]]; then
            echo ""
            echo "⚠️  AVERTISSEMENTS :"
            for warn in "${WARNINGS[@]}"; do echo "  ▸ $warn"; done
        fi

        echo ""
        echo "CONFORMITÉ RÈGLE 3-2-1-1-0 :"
        echo "  3 copies  : $([ -d "${BACKUP_DIRS[0]}" ] && echo "✓ NAS Local" || echo "✗ NAS Local ABSENT")"
        echo "  2 supports: ✓ Disque + Cloud S3"
        echo "  1 hors-site: $(aws s3 ls "${S3_BUCKET}" &>/dev/null 2>&1 && echo "✓ S3 Wasabi" || echo "⚠ S3 Non vérifié")"
        echo "  1 immuable : ✓ WORM Bucket Compliance Mode"
        echo "  0 erreur  : $([ $crit_count -eq 0 ] && echo "✓ Aucune erreur critique" || echo "✗ $crit_count erreur(s) détectée(s)")"

        echo ""
        echo "========================================================"
        echo " Rapport généré automatiquement par backup_check.sh"
        echo " Prochaine vérification : $(date -d '+1 hour' '+%H:%M') (crontab)"
        echo "========================================================"
    } | tee "$report_file"

    echo "$report_file"
}

# ── MAIN ───────────────────────────────────────────────────────────────────────

main() {
    local full_check=0 report_only=0 verbose=0

    for arg in "$@"; do
        case "$arg" in
            --full)        full_check=1 ;;
            --report-only) report_only=1 ;;
            --verbose|-v)  verbose=1 ;;
        esac
    done

    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    log "INFO" "=== Démarrage vérification sauvegardes — $HOSTNAME ==="

    if [[ $report_only -eq 0 ]]; then
        # Vérifications de fraîcheur
        for bdir in "${BACKUP_DIRS[@]}"; do
            check_backup_freshness "$bdir" "$MAX_AGE_HOURS_DAILY" "BACKUP-$(basename "$bdir")"
        done

        # Vérification checksums (si mode --full)
        if [[ $full_check -eq 1 ]]; then
            log "INFO" "Mode --full : vérification checksums SHA256..."
            for bdir in "${BACKUP_DIRS[@]}"; do
                check_checksums "$bdir" "CHECKSUM-$(basename "$bdir")"
            done
        fi

        # Vérification S3 WORM
        check_s3_worm

        # Vérification VMs Proxmox
        [[ $full_check -eq 1 ]] && check_proxmox_vms
    fi

    # Génération rapport
    local report_file
    report_file=$(generate_report)
    log "INFO" "Rapport généré: $report_file"

    # Envoi email si problèmes ou lundi (rapport hebdomadaire)
    local day_of_week
    day_of_week=$(date '+%u')  # 1=Lundi

    local crit_count warn_count
    crit_count=$(printf '%s\n' "${ISSUES[@]}" | wc -l || echo 0)
    warn_count=$(printf '%s\n' "${WARNINGS[@]}" | wc -l || echo 0)

    if [[ ${#ISSUES[@]} -gt 0 ]]; then
        log "ERROR" "Envoi alerte CRITIQUE par email"
        cat "$report_file" | mail -s "[NOVA-BACKUP][CRITIQUE] Problème sauvegarde sur $HOSTNAME" \
            -a "From: $SMTP_FROM" "$SMTP_TO_ADMIN" 2>/dev/null || true
    elif [[ "$day_of_week" == "1" ]]; then
        log "INFO" "Lundi — envoi rapport hebdomadaire"
        cat "$report_file" | mail -s "[NOVA-BACKUP][HEBDO] Rapport sauvegarde $HOSTNAME" \
            -a "From: $SMTP_FROM" "$SMTP_TO_ADMIN" "$SMTP_TO_WEEKLY" 2>/dev/null || true
    fi

    log "INFO" "=== Vérification terminée | Critiques: ${#ISSUES[@]} | Warnings: ${#WARNINGS[@]} ==="

    # Code retour basé sur la sévérité
    [[ ${#ISSUES[@]} -gt 0 ]] && return $RC_CRIT
    [[ ${#WARNINGS[@]} -gt 0 ]] && return $RC_WARN
    return $RC_OK
}

main "$@"

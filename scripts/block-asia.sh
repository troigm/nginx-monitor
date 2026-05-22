#!/bin/bash
# Block all Asian IP ranges at kernel level with ipset + iptables
# Ubicación: /opt/docker/nginx-monitor/scripts/block-asia.sh
# Autor: Claude Code
# Fecha: 2026-03-18
# Propósito: Bloquear todo el tráfico de Asia (49 países) a nivel kernel

set -euo pipefail

IPSET_NAME="asia-block"
DATA_DIR="/var/lib/asia-block"
ZONE_DIR="${DATA_DIR}/zones"
IPSET_SAVE="${DATA_DIR}/asia-block.ipset"
LOG_FILE="/var/log/asia-block.log"
BASE_URL="https://www.ipdeny.com/ipblocks/data/aggregated"
SCRIPT_PATH="$(readlink -f "$0")"
SYSTEMD_UNIT="/etc/systemd/system/asia-block.service"
CRON_FILE="/etc/cron.d/asia-block"
MIN_CIDRS=30000

# 49 Asian country codes
COUNTRIES=(af am az bh bd bt bn kh cn cy ge hk in id ir iq il jp jo kz kp kr kw kg la lb mo my mv mn mm np om pk ps ph qa sa sg lk sy tw tj th tl tm ae uz vn ye)

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: Este script debe ejecutarse como root${NC}"
        exit 1
    fi
}

download_zones() {
    mkdir -p "$ZONE_DIR"
    local failed=0
    local total=${#COUNTRIES[@]}

    echo "Descargando ${total} zone files..."
    for cc in "${COUNTRIES[@]}"; do
        if ! curl -sf -o "${ZONE_DIR}/${cc}.zone" "${BASE_URL}/${cc}-aggregated.zone"; then
            echo -e "${YELLOW}  Warning: fallo descarga ${cc}${NC}"
            ((failed++))
        fi
    done

    if [[ $failed -gt 10 ]]; then
        echo -e "${RED}Error: demasiados fallos de descarga (${failed}/${total})${NC}"
        return 1
    fi

    log "Zones descargadas: $((total - failed))/${total} exitosas"
}

count_cidrs() {
    local count=0
    for f in "${ZONE_DIR}"/*.zone; do
        [[ -f "$f" ]] || continue
        count=$((count + $(grep -c '^[0-9]' "$f" 2>/dev/null || echo 0)))
    done
    echo "$count"
}

build_restore_file() {
    local target="$1"
    local tmp
    tmp=$(mktemp)

    echo "create ${IPSET_NAME}-tmp hash:net maxelem 300000 hashsize 16384" > "$tmp"
    for f in "${ZONE_DIR}"/*.zone; do
        [[ -f "$f" ]] || continue
        while IFS= read -r cidr || [[ -n "$cidr" ]]; do
            [[ -z "$cidr" || ! "$cidr" =~ ^[0-9] ]] && continue
            echo "add ${IPSET_NAME}-tmp ${cidr}"
        done < "$f"
    done >> "$tmp"

    mv "$tmp" "$target"
}

atomic_load() {
    local restore_file="$1"

    # Create tmp set via ipset restore (bulk load)
    ipset restore -f "$restore_file"

    # Create main set if it doesn't exist (same params)
    if ! ipset list -n 2>/dev/null | grep -q "^${IPSET_NAME}$"; then
        ipset create "$IPSET_NAME" hash:net maxelem 300000 hashsize 16384
    fi

    # Atomic swap
    ipset swap "${IPSET_NAME}-tmp" "$IPSET_NAME"
    ipset destroy "${IPSET_NAME}-tmp"

    # Save for boot restore
    ipset save "$IPSET_NAME" > "$IPSET_SAVE"
}

add_iptables_rule() {
    # Skip if rule already exists
    if iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
        return 0
    fi

    # Find position: after manual-blacklist if it exists, else position 1
    local pos=1
    if iptables -C INPUT -m set --match-set "manual-blacklist" src -j DROP 2>/dev/null; then
        pos=$(iptables -L INPUT -n --line-numbers | grep "manual-blacklist" | awk '{print $1}')
        pos=$((pos + 1))
    fi

    iptables -I INPUT "$pos" -m set --match-set "$IPSET_NAME" src -j DROP
    log "Regla iptables insertada en posición ${pos} de INPUT"
}

remove_iptables_rule() {
    while iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; do
        iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP
    done
}

install_systemd() {
    cat > "$SYSTEMD_UNIT" << EOF
[Unit]
Description=Restore asia-block ipset at boot
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${SCRIPT_PATH} restore
ExecStop=${SCRIPT_PATH} stop

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable asia-block.service
    log "Servicio systemd instalado y habilitado"
}

install_cron() {
    cat > "$CRON_FILE" << EOF
# Actualizar bloqueo de IPs de Asia semanalmente (domingos 3AM)
0 3 * * 0 root ${SCRIPT_PATH} update >> ${LOG_FILE} 2>&1
EOF

    chmod 644 "$CRON_FILE"
    log "Cron semanal instalado: ${CRON_FILE}"
}

cmd_install() {
    ensure_root

    echo "=== Instalando bloqueo de IPs de Asia ==="
    echo ""

    # 1. Install ipset if needed
    if ! command -v ipset &>/dev/null; then
        log "Instalando ipset..."
        apt-get update -qq && apt-get install -y -qq ipset
    fi

    # 2. Download zone files
    download_zones

    # 3. Sanity check
    local cidr_count
    cidr_count=$(count_cidrs)
    echo "CIDRs encontrados: ${cidr_count}"

    if [[ "$cidr_count" -lt "$MIN_CIDRS" ]]; then
        echo -e "${RED}Error: solo ${cidr_count} CIDRs (mínimo: ${MIN_CIDRS}). Abortando.${NC}"
        exit 1
    fi

    # 4. Build restore file and atomic load
    local restore_file
    restore_file=$(mktemp)
    build_restore_file "$restore_file"
    atomic_load "$restore_file"
    rm -f "$restore_file"

    # 5. iptables rule
    add_iptables_rule

    # 6. systemd service
    install_systemd

    # 7. Cron
    install_cron

    echo ""
    echo -e "${GREEN}Instalación completada${NC}"
    echo "  CIDRs bloqueados: ${cidr_count}"
    echo "  Servicio: asia-block.service (enabled)"
    echo "  Cron: domingos 3AM"
    log "INSTALL completado: ${cidr_count} CIDRs"
}

cmd_update() {
    ensure_root

    log "UPDATE: iniciando actualización de zones"

    download_zones

    local cidr_count
    cidr_count=$(count_cidrs)
    log "UPDATE: ${cidr_count} CIDRs encontrados"

    if [[ "$cidr_count" -lt "$MIN_CIDRS" ]]; then
        log "UPDATE ABORTADO: solo ${cidr_count} CIDRs (mínimo: ${MIN_CIDRS})"
        echo -e "${RED}Error: solo ${cidr_count} CIDRs. No se actualiza.${NC}"
        exit 1
    fi

    local restore_file
    restore_file=$(mktemp)
    build_restore_file "$restore_file"
    atomic_load "$restore_file"
    rm -f "$restore_file"

    # Ensure iptables rule is in place
    add_iptables_rule

    log "UPDATE completado: ${cidr_count} CIDRs"
    echo -e "${GREEN}Actualización completada: ${cidr_count} CIDRs${NC}"
}

cmd_status() {
    echo "=== Estado: Asia Block ==="
    echo ""

    # ipset status
    if ipset list -n 2>/dev/null | grep -q "^${IPSET_NAME}$"; then
        local entries
        entries=$(ipset list "$IPSET_NAME" | grep -c '^[0-9]' || echo 0)
        echo -e "ipset ${IPSET_NAME}: ${GREEN}ACTIVO${NC}"
        echo "  Entradas (CIDRs): ${entries}"
    else
        echo -e "ipset ${IPSET_NAME}: ${RED}NO EXISTE${NC}"
    fi

    echo ""

    # iptables
    if iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
        local pos
        pos=$(iptables -L INPUT -n --line-numbers | grep "$IPSET_NAME" | awk '{print $1}')
        echo -e "Regla iptables: ${GREEN}ACTIVA${NC} (posición: ${pos})"
    else
        echo -e "Regla iptables: ${RED}NO EXISTE${NC}"
    fi

    echo ""

    # Persistence
    if [[ -f "$IPSET_SAVE" ]]; then
        echo "Archivo persistencia: ${IPSET_SAVE}"
        echo "  Última modificación: $(stat -c '%y' "$IPSET_SAVE" 2>/dev/null | cut -d. -f1)"
    else
        echo "Archivo persistencia: No existe"
    fi

    # systemd
    echo ""
    if systemctl is-enabled asia-block.service &>/dev/null; then
        echo -e "Servicio systemd: ${GREEN}HABILITADO${NC}"
    else
        echo -e "Servicio systemd: ${YELLOW}NO HABILITADO${NC}"
    fi

    # Cron
    if [[ -f "$CRON_FILE" ]]; then
        echo -e "Cron semanal: ${GREEN}INSTALADO${NC}"
    else
        echo -e "Cron semanal: ${YELLOW}NO INSTALADO${NC}"
    fi
}

cmd_uninstall() {
    ensure_root

    echo "=== Desinstalando bloqueo de IPs de Asia ==="

    # 1. Remove iptables rule
    remove_iptables_rule
    log "Regla iptables eliminada"

    # 2. Destroy ipset
    if ipset list -n 2>/dev/null | grep -q "^${IPSET_NAME}$"; then
        ipset destroy "$IPSET_NAME"
        log "ipset ${IPSET_NAME} destruido"
    fi

    # 3. Remove systemd service
    if [[ -f "$SYSTEMD_UNIT" ]]; then
        systemctl disable asia-block.service 2>/dev/null || true
        rm -f "$SYSTEMD_UNIT"
        systemctl daemon-reload
        log "Servicio systemd eliminado"
    fi

    # 4. Remove cron
    if [[ -f "$CRON_FILE" ]]; then
        rm -f "$CRON_FILE"
        log "Cron eliminado"
    fi

    # 5. Remove data
    if [[ -d "$DATA_DIR" ]]; then
        rm -rf "$DATA_DIR"
        log "Datos eliminados: ${DATA_DIR}"
    fi

    echo -e "${GREEN}Desinstalación completada${NC}"
    log "UNINSTALL completado"
}

cmd_restore() {
    # Called by systemd at boot
    if [[ ! -f "$IPSET_SAVE" ]]; then
        log "RESTORE: no se encontró ${IPSET_SAVE}, nada que restaurar"
        exit 0
    fi

    # Restore the saved ipset
    ipset restore -f "$IPSET_SAVE" 2>/dev/null || true

    # If the set was saved with its real name, it's already loaded
    # If not, nothing more to do
    if ! ipset list -n 2>/dev/null | grep -q "^${IPSET_NAME}$"; then
        log "RESTORE: ipset no pudo restaurarse"
        exit 1
    fi

    # Add iptables rule
    add_iptables_rule

    local entries
    entries=$(ipset list "$IPSET_NAME" | grep -c '^[0-9]' || echo 0)
    log "RESTORE completado: ${entries} CIDRs restaurados"
}

cmd_stop() {
    # Called by systemd on stop — save current state
    if ipset list -n 2>/dev/null | grep -q "^${IPSET_NAME}$"; then
        mkdir -p "$DATA_DIR"
        ipset save "$IPSET_NAME" > "$IPSET_SAVE"
        log "STOP: ipset guardado en ${IPSET_SAVE}"
    fi
}

usage() {
    cat << EOF
Bloqueo de IPs de Asia con ipset + iptables

USO:
    $(basename "$0") <comando>

COMANDOS:
    install     Instalar: descargar zones, crear ipset, iptables, systemd, cron
    update      Re-descargar zones y recargar ipset (atomic swap)
    status      Mostrar estado: entradas, regla iptables, última actualización
    uninstall   Eliminar todo: regla, ipset, systemd, cron, datos

COMANDOS INTERNOS:
    restore     Restaurar ipset al arrancar (llamado por systemd)
    stop        Guardar ipset al parar (llamado por systemd)

EJEMPLOS:
    sudo $(basename "$0") install
    sudo $(basename "$0") status
    sudo $(basename "$0") update
    sudo $(basename "$0") uninstall
EOF
}

# Main
case "${1:-}" in
    install)    cmd_install ;;
    update)     cmd_update ;;
    status)     cmd_status ;;
    uninstall)  cmd_uninstall ;;
    restore)    cmd_restore ;;
    stop)       cmd_stop ;;
    help|--help|-h) usage ;;
    *)          usage; exit 1 ;;
esac

#!/bin/bash
# Script para gestionar blacklist de IPs con ipset
# Ubicación: /usr/local/sbin/manage-blacklist.sh
# Autor: Claude Code
# Fecha: 2026-02-03
# Propósito: Bloqueo manual de IPs a nivel kernel con ipset

set -euo pipefail

IPSET_NAME="manual-blacklist"
BLACKLIST_FILE="/var/lib/blacklist/manual-blacklist.txt"
LOG_FILE="/var/log/blacklist-manage.log"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

usage() {
    cat << EOF
Gestión de Blacklist con ipset

USO:
    $(basename "$0") <comando> [opciones]

COMANDOS:
    add <ip> [descripción]    Añadir IP a blacklist
    remove <ip>               Eliminar IP de blacklist
    list                      Listar todas las IPs bloqueadas
    check <ip>                Verificar si una IP está bloqueada
    import <archivo>          Importar IPs desde archivo (una por línea)
    export                    Exportar blacklist a stdout
    count                     Mostrar número de IPs bloqueadas
    init                      Inicializar ipset (ejecutar una vez)
    status                    Estado del ipset y reglas iptables

EJEMPLOS:
    $(basename "$0") add 192.168.1.100 "Scanner detectado"
    $(basename "$0") add 10.0.0.0/8 "Bloquear red completa"
    $(basename "$0") remove 192.168.1.100
    $(basename "$0") import /tmp/ips-maliciosas.txt
    $(basename "$0") check 192.168.1.100

NOTAS:
    - Soporta IPs individuales y rangos CIDR
    - Los cambios se aplican inmediatamente (kernel-level)
    - La blacklist persiste entre reinicios
    - Las IPs se guardan en: $BLACKLIST_FILE
EOF
}

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: Este script debe ejecutarse como root${NC}"
        exit 1
    fi
}

ensure_dir() {
    mkdir -p "$(dirname "$BLACKLIST_FILE")"
    touch "$BLACKLIST_FILE"
}

init_ipset() {
    ensure_root
    ensure_dir

    # Crear ipset si no existe
    if ! ipset list -n | grep -q "^${IPSET_NAME}$"; then
        log "Creando ipset: $IPSET_NAME"
        ipset create "$IPSET_NAME" hash:net -exist
    fi

    # Añadir regla iptables si no existe
    if ! iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
        log "Añadiendo regla iptables para $IPSET_NAME"
        # Insertar al principio para que se evalúe antes que otras reglas
        iptables -I INPUT 1 -m set --match-set "$IPSET_NAME" src -j DROP
    fi

    # Cargar IPs existentes del archivo
    local count=0
    while IFS='|' read -r ip desc || [[ -n "$ip" ]]; do
        [[ -z "$ip" || "$ip" =~ ^# ]] && continue
        ip="${ip%%|*}"  # Solo la IP
        ipset add "$IPSET_NAME" "$ip" -exist 2>/dev/null && ((count++)) || true
    done < "$BLACKLIST_FILE"

    log "ipset $IPSET_NAME inicializado con $count IPs"

    # Guardar configuración
    ipset save > /etc/ipset.conf

    echo -e "${GREEN}Blacklist inicializada correctamente${NC}"
}

add_ip() {
    ensure_root
    ensure_dir

    local ip="$1"
    local desc="${2:-Sin descripción}"

    # Validar formato IP/CIDR
    if ! echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$'; then
        echo -e "${RED}Error: Formato de IP inválido: $ip${NC}"
        exit 1
    fi

    # Verificar si ya existe
    if ipset test "$IPSET_NAME" "$ip" 2>/dev/null; then
        echo -e "${YELLOW}IP $ip ya está en la blacklist${NC}"
        exit 0
    fi

    # Añadir a ipset
    if ipset add "$IPSET_NAME" "$ip"; then
        # Guardar en archivo con descripción y fecha
        echo "${ip}|${desc}|$(date '+%Y-%m-%d %H:%M:%S')" >> "$BLACKLIST_FILE"
        ipset save > /etc/ipset.conf
        log "ADD: $ip - $desc"
        echo -e "${GREEN}IP $ip añadida a blacklist${NC}"
    else
        echo -e "${RED}Error añadiendo IP a ipset${NC}"
        exit 1
    fi
}

remove_ip() {
    ensure_root

    local ip="$1"

    # Eliminar de ipset
    if ipset del "$IPSET_NAME" "$ip" 2>/dev/null; then
        # Eliminar de archivo
        local temp_file=$(mktemp)
        grep -v "^${ip}|" "$BLACKLIST_FILE" > "$temp_file" || true
        mv "$temp_file" "$BLACKLIST_FILE"
        ipset save > /etc/ipset.conf
        log "REMOVE: $ip"
        echo -e "${GREEN}IP $ip eliminada de blacklist${NC}"
    else
        echo -e "${YELLOW}IP $ip no estaba en la blacklist${NC}"
    fi
}

list_ips() {
    echo "=== Blacklist Manual ($IPSET_NAME) ==="
    echo ""

    if [[ -f "$BLACKLIST_FILE" ]] && [[ -s "$BLACKLIST_FILE" ]]; then
        printf "%-20s %-40s %s\n" "IP" "DESCRIPCIÓN" "FECHA"
        printf "%s\n" "$(printf '=%.0s' {1..80})"

        while IFS='|' read -r ip desc date || [[ -n "$ip" ]]; do
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            printf "%-20s %-40s %s\n" "$ip" "${desc:0:40}" "${date:-N/A}"
        done < "$BLACKLIST_FILE"
    else
        echo "La blacklist está vacía"
    fi

    echo ""
    echo "Total: $(ipset list "$IPSET_NAME" 2>/dev/null | grep -c '^[0-9]' || echo 0) IPs"
}

check_ip() {
    local ip="$1"

    if ipset test "$IPSET_NAME" "$ip" 2>/dev/null; then
        echo -e "${RED}IP $ip ESTÁ BLOQUEADA${NC}"

        # Mostrar detalles si existe en el archivo
        if grep -q "^${ip}|" "$BLACKLIST_FILE" 2>/dev/null; then
            grep "^${ip}|" "$BLACKLIST_FILE" | while IFS='|' read -r _ desc date; do
                echo "  Descripción: $desc"
                echo "  Fecha: $date"
            done
        fi
        return 0
    else
        echo -e "${GREEN}IP $ip NO está bloqueada${NC}"
        return 1
    fi
}

import_ips() {
    ensure_root

    local file="$1"

    if [[ ! -f "$file" ]]; then
        echo -e "${RED}Error: Archivo no encontrado: $file${NC}"
        exit 1
    fi

    local added=0
    local skipped=0
    local invalid=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Ignorar líneas vacías y comentarios
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        # Extraer IP (primer campo si hay separador)
        local ip="${line%%[,|	 ]*}"
        local desc="${line#*[,|	 ]}"
        [[ "$desc" == "$ip" ]] && desc="Importado desde $file"

        # Validar formato
        if ! echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$'; then
            ((invalid++))
            continue
        fi

        # Añadir si no existe
        if ipset test "$IPSET_NAME" "$ip" 2>/dev/null; then
            ((skipped++))
        elif ipset add "$IPSET_NAME" "$ip" 2>/dev/null; then
            echo "${ip}|${desc}|$(date '+%Y-%m-%d %H:%M:%S')" >> "$BLACKLIST_FILE"
            ((added++))
        fi
    done < "$file"

    ipset save > /etc/ipset.conf
    log "IMPORT: $file - añadidas: $added, omitidas: $skipped, inválidas: $invalid"

    echo -e "${GREEN}Importación completada${NC}"
    echo "  Añadidas: $added"
    echo "  Omitidas (ya existían): $skipped"
    echo "  Inválidas: $invalid"
}

export_ips() {
    if [[ -f "$BLACKLIST_FILE" ]]; then
        cat "$BLACKLIST_FILE"
    fi
}

show_count() {
    local count=$(ipset list "$IPSET_NAME" 2>/dev/null | grep -c '^[0-9]' || echo 0)
    echo "IPs bloqueadas: $count"
}

show_status() {
    echo "=== Estado de Blacklist ==="
    echo ""

    # Estado ipset
    if ipset list -n | grep -q "^${IPSET_NAME}$"; then
        echo -e "ipset $IPSET_NAME: ${GREEN}ACTIVO${NC}"
        echo "  Entradas: $(ipset list "$IPSET_NAME" | grep -c '^[0-9]' || echo 0)"
    else
        echo -e "ipset $IPSET_NAME: ${RED}NO EXISTE${NC}"
        echo "  Ejecuta: $(basename "$0") init"
    fi

    echo ""

    # Estado iptables
    if iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
        echo -e "Regla iptables: ${GREEN}ACTIVA${NC}"
        local pos=$(iptables -L INPUT -n --line-numbers | grep "$IPSET_NAME" | awk '{print $1}')
        echo "  Posición en INPUT: $pos"
    else
        echo -e "Regla iptables: ${RED}NO EXISTE${NC}"
    fi

    echo ""

    # Archivo de persistencia
    if [[ -f "$BLACKLIST_FILE" ]]; then
        echo "Archivo persistencia: $BLACKLIST_FILE"
        echo "  Líneas: $(wc -l < "$BLACKLIST_FILE")"
    else
        echo "Archivo persistencia: No existe"
    fi
}

# Main
case "${1:-}" in
    add)
        [[ -z "${2:-}" ]] && { echo "Error: Especifica una IP"; exit 1; }
        add_ip "$2" "${3:-}"
        ;;
    remove|del|rm)
        [[ -z "${2:-}" ]] && { echo "Error: Especifica una IP"; exit 1; }
        remove_ip "$2"
        ;;
    list|ls)
        list_ips
        ;;
    check|test)
        [[ -z "${2:-}" ]] && { echo "Error: Especifica una IP"; exit 1; }
        check_ip "$2"
        ;;
    import)
        [[ -z "${2:-}" ]] && { echo "Error: Especifica un archivo"; exit 1; }
        import_ips "$2"
        ;;
    export)
        export_ips
        ;;
    count)
        show_count
        ;;
    init)
        init_ipset
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac

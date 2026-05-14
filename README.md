# Nginx Monitor

Dashboard de monitoreo de seguridad y tráfico web para servidores con Nginx, Fail2Ban, UFW y SSH.

## Características

### Página Nginx
- **Monitoreo de tráfico web**: Visitas, IPs únicas, estadísticas por sitio/aplicación
- **Reportes CSP**: Recepción y visualización de violaciones Content Security Policy
- **Logs de Nginx**: Errores, rate limiting, bad bots, códigos HTTP, User Agent
- **Fail2Ban**: Eventos de ban/unban, intentos detectados por jail
- **Top IPs bloqueadas** con etiquetas de tipo de bloqueo
- **Tablas paginadas**: Navegación eficiente hasta 2000 entradas con filtro por IP

### Página SSH/VPN
- **Autenticación SSH real**: Logins exitosos y fallidos desde `/var/log/auth.log`
- **Detección de scanners/bots**: Identificación de intentos automatizados
- **Top IPs y usuarios**: Estadísticas de acceso y ataques (layout compacto)
- **Gráfica de ataques por país**: Doughnut chart con top 12 países atacantes
- **IPs baneadas permanentemente**: Tab con listado ordenable desde `/etc/fail2ban/ip.blacklist`
- **Tabla de eventos SSH**: Ordenable, filtrable por tipo/usuario/IP y paginada

### Página UFW Firewall
- **Conexiones bloqueadas**: Total de eventos por acción (BLOCK/ALLOW)
- **Top puertos atacados**: Gráfica de puertos más atacados
- **Categorías de bloqueo**: SSH, DB, Web, SMB, RDP, Telnet, VPN, etc.
- **Top IPs bloqueadas** con motivo de bloqueo y puerto principal
- **Tabla de eventos UFW**: Ordenable, filtrable por acción/proto/puerto/IP y paginada

### Página IP Lists
- **Gestion de Whitelist/Blacklist**: CRUD completo de IPs
- **Validacion IPv4/IPv6**: Verificacion de formato de IP
- **Importacion/Exportacion CSV**: Carga masiva y backup de listas
- **Generacion Nginx Config**: Directivas `geo` listas para usar
- **Expiracion automatica**: IPs temporales con fecha de expiracion
- **Geolocalizacion**: Banderas de pais para cada IP

### General
- **Geolocalización de IPs**: Integración con ip-api.com
- **Dashboard interactivo**: Gráficas con Chart.js, filtros, ordenación
- **Limpieza automática**: Retención de 3 meses de datos
- **Multi-vhost**: Parseo independiente de logs por virtual host con cutoff por site
- **Logs rotados**: Lectura automática de logs `.log.1` (logrotate)

## Arquitectura

```
nginx-monitor/
├── app/
│   ├── app.py              # Aplicación Flask principal
│   └── templates/
│       ├── base.html       # Template base con navegación
│       ├── nginx.html      # Página Nginx + Fail2Ban
│       ├── ssh_vpn.html    # Página SSH/VPN
│       ├── ufw.html        # Página UFW Firewall
│       └── ip_list.html    # Página IP Whitelist/Blacklist
├── data/                   # Datos locales (backup SQLite)
├── migrate_to_postgres.py  # Script de migración SQLite → PostgreSQL
├── docker-compose.yml      # Configuración Docker
├── Dockerfile              # Imagen Docker
├── requirements.txt        # Dependencias Python
├── CHANGELOG.md            # Historial de cambios
└── .env                    # Variables de entorno
```

## Requisitos

- Docker y Docker Compose
- Acceso a logs de Nginx (`/var/log/nginx/`)
- Acceso a log de Fail2Ban (`/var/log/fail2ban.log`)
- Acceso a log de UFW (`/var/log/ufw.log`)
- Acceso a log de autenticación (`/var/log/auth.log`)

## Instalación

1. Clonar el repositorio:
```bash
git clone <url-repositorio>
cd nginx-monitor
```

2. Configurar variables de entorno:
```bash
cp .env.example .env
# Editar .env con credenciales seguras
```

3. Iniciar el servicio:
```bash
docker compose up -d
```

4. Acceder al dashboard:
```
http://localhost:5000
```

## Configuración

### Variables de entorno

| Variable | Descripción | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Clave secreta Flask | `change-me-in-production` |
| `AUTH_USER` | Usuario de acceso | `admin` |
| `AUTH_PASS` | Contraseña de acceso | `change-me-in-production` |
| `POSTGRES_PASSWORD` | Contraseña PostgreSQL | `change-me-in-production` |
| `DATABASE_URL` | URL de conexión BD | `postgresql://monitor:...@postgres:5432/monitor` |
| `MONITOR_SITES` | Dominios a monitorizar (comas) | `example.com` |
| `MONITOR_APPS` | Apps web `slug:Label` (comas) | `wordpress:WordPress` |
| `MONITOR_LOG_MAP` | Mapeo site a prefijo de log `site:prefix` (comas) | _(vacío)_ |
| `MONITOR_SITE_APP` | Mapeo site a app `site:app_slug` (comas) | _(vacío)_ |
| `MONITOR_SSH_PORTS` | Puertos SSH para UFW (comas) | `22,2222` |
| `MONITOR_VPN_PORTS` | Puertos VPN `puerto:Nombre` (comas) | `22:SSH,1194:OpenVPN,51820:WireGuard` |

### Multi-vhost (múltiples sitios)

Si tu Nginx tiene virtual hosts con logs separados (ej. `blog_access.log`, `shop_access.log`), usa `MONITOR_LOG_MAP` para mapear cada site a su prefijo de log:

```bash
# .env
MONITOR_SITES=blog.example.com,shop.example.com
MONITOR_LOG_MAP=blog.example.com:blog,shop.example.com:shop
```

Esto hará que nginx-monitor parsee `/var/log/nginx/blog_access.log`, `blog_error.log`, `shop_access.log`, `shop_error.log` (y sus versiones rotadas `.log.1`).

Opcionalmente, mapea sites directamente a apps con `MONITOR_SITE_APP`:

```bash
MONITOR_SITE_APP=shop.example.com:woocommerce
```

### Configuración con Nginx Proxy

Si se usa detrás de un proxy Nginx con path `/nginx-monitor/`:

```nginx
# Requiere tener definidas las zonas limit_req (ejemplo):
# limit_req_zone $binary_remote_addr zone=general:10m rate=30r/s;
# limit_req_zone $binary_remote_addr zone=api:10m     rate=30r/s;

location /nginx-monitor/ {
    limit_req zone=general burst=20 nodelay;
    proxy_pass http://127.0.0.1:5000/;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /nginx-monitor/api/ {
    limit_req zone=api burst=20 nodelay;
    proxy_pass http://127.0.0.1:5000/api/;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Recomendado adicionalmente: restringir el path `/nginx-monitor/` al rango de la
VPN de administración con `allow <vpn-cidr>; deny all;` (el endpoint `/csp-report`
debe seguir siendo público para recibir reportes del navegador).

### Protección brute-force con Fail2Ban (opcional pero recomendado)

Además de la autenticación HTTP Basic del propio app, conviene desplegar un
jail de fail2ban que banee IPs con ráfagas de `401` contra `/nginx-monitor/`.

**Filtro** — `/etc/fail2ban/filter.d/nginx-monitor-auth.conf`:

```ini
[INCLUDES]
before = common.conf

[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD) /nginx-monitor/[^"]*" 401 
ignoreregex =
datepattern = {^LN-BEG}
```

**Jail** — añadir a `/etc/fail2ban/jail.local`:

```ini
[nginx-monitor-auth]
enabled  = true
filter   = nginx-monitor-auth
action   = iptables-multiport[name=nginx-monitor-auth, port="http,https"]
logpath  = /var/log/nginx/access.log
backend  = auto
findtime = 300
maxretry = 5
bantime  = 86400
```

### VPN setup (host-side)

Para que el dashboard muestre actividad de OpenVPN y WireGuard, el contenedor
necesita acceso a datos que viven en el host con permisos restringidos
(`openvpn-status.log` es `root:root 600`, `wg show` requiere `CAP_NET_ADMIN`).
El patrón usado es un **cron en el host que vuelca periódicamente** los datos a
una ruta legible por el contenedor.

**1.** Asegúrate de que OpenVPN tiene `verb 3` en `/etc/openvpn/server.conf`
para que el journal contenga eventos por cliente (`Peer Connection Initiated`,
`TLS Auth Error`, etc.). Reinicia el servicio si lo cambias.

**2.** Crea el directorio de volcado y el script de dump (como root):

```bash
sudo bash <<'EOF'
mkdir -p /var/log/nginx-monitor
chmod 755 /var/log/nginx-monitor

cat > /usr/local/bin/nginx-monitor-vpn-dump.sh <<'SH'
#!/bin/bash
set -u
TARGET=/var/log/nginx-monitor
umask 022

journalctl -u openvpn@server.service \
    --since '12 minutes ago' --no-pager --output=short-iso \
    > "$TARGET/openvpn-journal.log" 2>/dev/null || true

[ -r /etc/openvpn/openvpn-status.log ] && \
    cp /etc/openvpn/openvpn-status.log "$TARGET/openvpn-status.log"

command -v wg >/dev/null 2>&1 && \
    wg show all dump > "$TARGET/wg-dump.txt" 2>/dev/null || true

chmod 644 "$TARGET"/*.log "$TARGET"/*.txt 2>/dev/null || true
SH
chmod 755 /usr/local/bin/nginx-monitor-vpn-dump.sh

cat > /etc/cron.d/nginx-monitor-vpn <<'CRON'
*/5 * * * * root /usr/local/bin/nginx-monitor-vpn-dump.sh
CRON
chmod 644 /etc/cron.d/nginx-monitor-vpn

/usr/local/bin/nginx-monitor-vpn-dump.sh  # primer dump inmediato
EOF
```

**3.** El `docker-compose.yml` ya monta `/var/log/nginx-monitor` como
`read-only` dentro del contenedor. Si no tienes el cron, los endpoints
`/api/vpn-stats` y `/api/vpn-peers` simplemente devuelven listas vacías.

**Adaptar a tu setup**: si tu unit de OpenVPN no se llama `openvpn@server.service`
(p. ej. usas el paquete `openvpn-server.service` o systemd-networkd para WG),
edita el journalctl `--unit` correspondientemente. WireGuard funciona sin
cambios siempre que `wg show` esté instalado y se ejecute como root.

### Endpoint CSP

Para recibir reportes CSP, configurar el header en Nginx:

```nginx
add_header Content-Security-Policy "...; report-uri https://tu-dominio/nginx-monitor/csp-report";
```

El endpoint `/csp-report` no requiere autenticación para permitir reportes del navegador.

## API Endpoints

### Páginas Web

| Endpoint | Descripción |
|----------|-------------|
| `/` | Dashboard Nginx (página principal) |
| `/ssh-vpn` | Dashboard SSH/VPN |
| `/ufw` | Dashboard UFW Firewall |
| `/ip-list` | Gestión IP Whitelist/Blacklist |
| `/health` | Health check (sin auth) |

### APIs de Datos

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/dashboard-stats` | GET | Estadísticas del dashboard Nginx |
| `/api/visits-timeline` | GET | Timeline de visitas |
| `/api/csp-reports` | GET | Lista de reportes CSP |
| `/api/nginx-logs` | GET | Logs de Nginx |
| `/api/fail2ban-stats` | GET | Estadísticas Fail2Ban |
| `/api/fail2ban-events` | GET | Eventos Fail2Ban |
| `/api/ssh-auth-stats` | GET | Estadísticas autenticación SSH |
| `/api/ssh-auth-events` | GET | Eventos de autenticación SSH |
| `/api/permanent-blacklist` | GET | IPs baneadas permanentemente (fail2ban) |
| `/api/ufw-stats` | GET | Estadísticas UFW |
| `/api/ufw-events` | GET | Eventos UFW |
| `/api/geoip` | POST | Geolocalización de IPs |
| `/api/sync` | POST | Forzar sincronización de logs |
| `/api/cleanup` | POST | Limpiar datos antiguos |
| `/api/ip-list` | GET | Lista de IPs whitelist/blacklist |
| `/api/ip-list` | POST | Crear entrada IP |
| `/api/ip-list/<id>` | PUT | Actualizar entrada IP |
| `/api/ip-list/<id>` | DELETE | Eliminar entrada IP |
| `/api/ip-list/stats` | GET | Estadísticas IP list |
| `/api/ip-list/bulk-import` | POST | Importar múltiples IPs |
| `/api/ip-list/export` | GET | Exportar como CSV |
| `/api/ip-list/nginx-config` | GET | Generar config Nginx |
| `/csp-report` | POST | Recepción de reportes CSP (sin auth) |

### Parámetros comunes

- `hours`: Período en horas (default: 24, max: 2160)
- `site`: Filtrar por sitio
- `app`: Filtrar por aplicación (configurable via `MONITOR_APPS`)
- `limit`: Registros por página (default: 100, max: 2000)
- `page`: Número de página (default: 1)
- `ip`: Filtrar por dirección IP (exacta)

### Filtros del Dashboard

| Filtro | Opciones |
|--------|----------|
| Sitio | Todos los sitios detectados en logs |
| Aplicación | Configurable via `MONITOR_APPS` |
| Período | 1 hora, 6 horas, 24 horas, 3 días, 1 semana, 1 mes, 3 meses |

## Categorías de Bloqueo UFW

El sistema categoriza automáticamente los bloqueos según el puerto atacado:

| Categoría | Puertos | Descripción |
|-----------|---------|-------------|
| SSH | Configurable via `MONITOR_SSH_PORTS` | Ataques a servicios SSH |
| Base de Datos | 3306, 5432, 27017, 6379, 1433 | MySQL, PostgreSQL, MongoDB, Redis, MSSQL |
| Web | 80, 443, 8080, 8443 | Escaneo de servicios web |
| SMB/Windows | 445, 139 | Ataques a comparticiones Windows |
| Correo | 25, 587, 465, 110, 143, 993, 995 | Escaneo de servicios de correo |
| VPN | Configurable via `MONITOR_VPN_PORTS` | OpenVPN, WireGuard, etc. |
| Telnet | 23 | Ataques Telnet |
| RDP | 3389 | Ataques a escritorio remoto |
| Escaneo | Otros | Escaneo general de puertos |

## Tipos de Eventos SSH

| Tipo | Descripción |
|------|-------------|
| `accepted` | Login exitoso |
| `failed` | Contraseña incorrecta |
| `invalid_user` | Usuario no existe |
| `preauth_close` | Conexión cerrada antes de auth (scanner) |
| `banner_error` | Error de banner SSH (bot) |

## Stack tecnológico

- **Backend**: Python 3.14, Flask 3.1, Flask-SQLAlchemy, APScheduler, Gunicorn 25
- **Frontend**: HTML5, CSS3, JavaScript, Chart.js 4.4
- **Base de datos**: PostgreSQL 18 (Alpine), psycopg3
- **Contenedor**: Docker con Python slim

## Servicios Docker

| Servicio | Imagen | CPU | RAM | Descripción |
|----------|--------|-----|-----|-------------|
| nginx-monitor | python:3.14-slim | 1.0 | 512MB | Aplicación Flask |
| postgres | postgres:18-alpine | 0.5 | 256MB | Base de datos |

Ambos servicios tienen:
- Healthchecks configurados
- Restart policy: unless-stopped
- Logging con rotación (10MB x 3 archivos)

## Sincronización de logs

Los logs se sincronizan automáticamente cada 5 minutos mediante APScheduler con:
- `coalesce=True`: agrupa ejecuciones perdidas si el sistema estuvo ocupado
- `max_instances=1`: evita ejecuciones solapadas

También se puede forzar una sincronización manual desde el botón "Sincronizar Logs" en el dashboard.

## Limpieza automática de datos

Para mantener la base de datos en un tamaño razonable, se ejecuta una limpieza automática diaria a las 4:00 AM que elimina registros con más de 3 meses de antigüedad.

**Tablas limpiadas:**
- `nginx_logs` - Logs de errores y accesos
- `csp_reports` - Reportes CSP
- `fail2ban_events` - Eventos de Fail2Ban
- `ufw_events` - Eventos de UFW/iptables
- `ssh_auth_events` - Eventos de autenticación SSH
- `visit_stats` - Estadísticas de visitas agregadas
- `ip_list` - IPs con fecha de expiración vencida

**Limpieza manual:**
```bash
# Limpiar datos >3 meses (default)
curl -u admin:password -X POST https://tu-dominio/nginx-monitor/api/cleanup

# Limpiar datos >6 meses
curl -u admin:password -X POST "https://tu-dominio/nginx-monitor/api/cleanup?months=6"
```

## Seguridad

- Autenticación HTTP Basic en todos los endpoints excepto `/health` y `/csp-report`
- Contenedor ejecutado como usuario www-data (UID 33)
- Logs montados en modo solo lectura
- Puerto expuesto solo en localhost por defecto
- Headers de seguridad: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
- Validación de parámetros de entrada (límites en hours, limit, months)
- Dependencias actualizadas sin vulnerabilidades conocidas
- Límites de recursos Docker para evitar DoS
- `no-new-privileges:true` en ambos contenedores (bloquea escalada vía binarios setuid)
- Postgres ejecutándose como UID 70 explícito (no root)

### Recomendaciones de despliegue

- **Permisos del `.env`**: `chmod 600 .env` y `chown root:root` (contiene
  `SECRET_KEY`, `AUTH_PASS` y `POSTGRES_PASSWORD` en claro). Docker Compose
  lo lee con el usuario que ejecuta `docker compose up`, no necesita ACL extra.
- **Rotación de secretos**: al cambiar `POSTGRES_PASSWORD` recuerda rotar
  también la contraseña dentro de la base ya inicializada:
  `docker exec nginx-monitor-postgres psql -U monitor -d monitor -c "ALTER USER monitor WITH PASSWORD '<nuevo>'"`.
  Cambiar solo `.env` no altera el password efectivo en el volumen persistente.
- **Rate-limit en el proxy nginx** (ver sección "Configuración con Nginx Proxy")
  y jail `nginx-monitor-auth` de fail2ban para brute-force sobre BasicAuth.
- **Restringir el path a la VPN de administración** si no es necesario que el
  dashboard sea accesible públicamente.
- **Backup automático**: el proyecto está integrado en el backup maestro
  `/opt/docker-projects/backups/backup_all.sh` (cron diario 03:00 UTC del usuario
  `troig`). Los dumps comprimidos con `zstd --ultra -22` se guardan en
  `/opt/docker-projects/backups/nginx-monitor/` con retención 10 días. La base
  de ~2 GB comprime a ~45 MB por dump.
  Restaurar un dump:
  ```bash
  cd /opt/docker-projects/nginx-monitor
  docker compose exec -T postgres psql -U monitor -d postgres \
      -c 'DROP DATABASE IF EXISTS monitor; CREATE DATABASE monitor;'
  zstd -dc /opt/docker-projects/backups/nginx-monitor/postgres_YYYYMMDD_HHMMSS.sql.zst \
      | docker compose exec -T postgres psql -U monitor -d monitor
  ```

## Desarrollo

Para desarrollo local sin Docker:

```bash
# Crear entorno virtual
python -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar
cd app
python app.py
```

## Mejoras implementadas

### Seguridad (v1.2.1)
- ✅ CVE-2023-49293 corregido (python-dateutil actualizado)
- ✅ Validación de parámetros de entrada (DoS prevention)
- ✅ Headers de seguridad (X-Frame-Options, X-Content-Type-Options, etc.)

### Rendimiento (v1.3.0 → v2.4.0)
- ✅ Python 3.14 (upgrade desde 3.13), Gunicorn 25
- ✅ 10 índices compuestos en base de datos
- ✅ Dockerfile optimizado (non-root, healthcheck)
- ✅ Fix N+1 en 4 funciones de sync (batch load)
- ✅ `DATE_TRUNC` en queries timeline (mejor uso de índices)

### Infraestructura (v2.0.0 → v2.4.0)
- ✅ PostgreSQL 18 Alpine (upgrade desde 16)
- ✅ psycopg3 (reemplaza psycopg2)
- ✅ Connection pooling ampliado (pool_size=5, max_overflow=10)
- ✅ 500,000+ registros en producción

### Estabilidad (v2.0.1)
- ✅ Scheduler con coalescencia (sin ejecuciones solapadas)
- ✅ Límites de recursos Docker (CPU/RAM)
- ✅ Logging con rotación automática

### Rendimiento (v2.0.2)
- ✅ Optimización queries N+1 con CTEs y DISTINCT ON
- ✅ Compatibilidad PostgreSQL (to_char en lugar de strftime)

### Funcionalidad (v2.1.0)
- ✅ Gestión de IP Whitelist/Blacklist
- ✅ Importación/exportación CSV
- ✅ Generación de configuración Nginx
- ✅ Soporte para expiración automática de IPs

### Escalabilidad (v2.2.0)
- ✅ Paginación en tablas de logs (hasta 2000 entradas)
- ✅ Filtro por IP en todas las tablas de eventos
- ✅ Controles de navegación (anterior/siguiente/indicador)
- ✅ Estructura de respuesta API unificada con metadata

### UI/UX (v2.5.0 → v2.6.0)
- ✅ Gráfica de ataques SSH por país (doughnut chart, top 12 países)
- ✅ Layout compacto en todas las cards de IPs y usuarios
- ✅ Gráficas expandibles que ocupan el 100% del card disponible
- ✅ Layout responsive de 3 columnas en sección SSH
- ✅ Tab "IPs Baneadas Permanentemente" con tabla ordenable y filtro por IP/país

### Multi-vhost y parseo mejorado (v2.7.0)
- ✅ Soporte multi-vhost con `MONITOR_LOG_MAP` y `MONITOR_SITE_APP`
- ✅ Lectura automática de logs rotados (`.log.1`)
- ✅ Cutoff por site (sincronización independiente por virtual host)
- ✅ Parseo de access log completo (todos los status codes, filtro de bots/estáticos/IPs internas)
- ✅ Clasificación mejorada: `access`, `http_4xx`, `http_5xx`, `bad_bot`, `http_429`

## Uso de IP Lists

### Generar configuración Nginx

1. Accede a la página "IP Lists" en el dashboard
2. Añade IPs a whitelist o blacklist
3. Click en "Generar Config Nginx" para descargar `ip_access.conf`
4. Incluye el archivo en tu configuración Nginx:

```nginx
# En nginx.conf o dentro de http {}
include /etc/nginx/conf.d/ip_access.conf;

# En tu server block
server {
    # Bloquear IPs en blacklist
    if ($ip_blacklist) {
        return 403;
    }

    # Saltar rate limiting para whitelist
    # (usar con limit_req_zone)
    set $limit_key $binary_remote_addr;
    if ($ip_whitelist) {
        set $limit_key "";
    }
}
```

### Formato CSV para importación

```csv
192.168.1.100,Bot de spam conocido
10.0.0.50,Scanner automatizado
2001:db8::1,IPv6 malicioso
```

## Licencia

MIT

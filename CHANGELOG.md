# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

## [2.7.0] - 2026-03-18

### Añadido
- **Soporte multi-vhost** - Parseo independiente de logs por virtual host
  - `MONITOR_LOG_MAP`: mapeo de site a prefijo de log Nginx (`site:prefix`)
  - `MONITOR_SITE_APP`: mapeo directo de site a app (`site:app_slug`)
  - Cutoff por site: sincronización independiente por cada virtual host
- **Lectura de logs rotados** - Parseo automático de archivos `.log.1` (logrotate)
  - Access logs y error logs rotados incluidos en sincronización
  - Visit stats también incluyen logs rotados
- **Parseo de access log completo** - Captura todos los status codes, no solo errores
  - Nuevos tipos: `access` (2xx/3xx), `http_4xx`, `http_5xx`
  - Filtrado de bots, IPs internas y recursos estáticos
  - Líneas de lectura aumentadas a 5000 (antes 1000)

### Mejorado
- **`detect_app()` con contexto de site** - Mapeo directo `MONITOR_SITE_APP` antes de detección por URI
- **Mensajes de error** incluyen la ruta del log que falló
- **Badges CSS** para nuevos tipos de log: `access`, `http_4xx`, `http_5xx`
- **Docker Compose** actualizado con variables `MONITOR_LOG_MAP` y `MONITOR_SITE_APP`

### Nuevas variables de entorno
- `MONITOR_LOG_MAP`: Mapeo site→prefijo de log (`blog.example.com:blog`)
- `MONITOR_SITE_APP`: Mapeo site→app (`shop.example.com:woocommerce`)

## [2.6.0] - 2026-03-10

### Añadido
- **Tab "IPs Baneadas Permanentemente"** en sección SSH/VPN
  - Nuevo endpoint `/api/permanent-blacklist` que lee `/etc/fail2ban/ip.blacklist`
  - Enriquecido con intentos SSH y fecha de último ataque desde base de datos
  - Tabla ordenable por IP, País, Intentos SSH y Último Ataque
  - Filtro por IP y por nombre de país
  - Geolocalización en batches de 100 IPs
  - Carga lazy al hacer click en la tab
- **Volumen Docker** para `/etc/fail2ban/ip.blacklist` (read-only)

## [2.5.0] - 2026-03-10

### Añadido
- **Gráfica de ataques SSH por país** - Doughnut chart con top 12 países atacantes
  - Nuevo campo `attack_ips_geo` en API `/api/ssh-auth-stats` (top 100 IPs atacantes)
  - Resolución geográfica y agregación por país en frontend
  - Tooltips con porcentaje y conteo absoluto

### Mejorado
- **Layout SSH compacto** - Cards de IPs y usuarios rediseñadas con clase `compact`
  - Padding, fuentes e iconos reducidos para mayor densidad de información
  - Sección IPs cambiada a layout de 3 columnas (Login Exitoso + Intentos Fallidos + Gráfica País)
- **Layout UFW compacto** - Card "Top IPs Bloqueadas" con estilo compact
- **Layout Nginx compacto** - Todas las cards de IPs con estilo compact
- **Gráficas expandibles** - Nueva clase CSS `chart-card-fill` / `chart-container-fill`
  - Gráfica "Categorías de Bloqueo" (UFW) ocupa 100% del card
  - Gráfica "Visitas por Aplicación" (Nginx) ocupa 100% del card
- **CSS responsive** - Soporte para grid de 3 columnas (`charts-row-3`) con breakpoints

## [2.4.0] - 2026-02-11

### Cambiado
- **Python 3.13 → 3.14** - Imagen base actualizada a `python:3.14-slim`
- **PostgreSQL 16 → 18** - Major version upgrade (backward-compatible)
- **Gunicorn 23 → 25** - Fix request smuggling (v24+), mejoras de rendimiento
- **psycopg2 → psycopg3** - Driver PostgreSQL mantenido activamente (`psycopg[binary]`)
- **Dialect SQLAlchemy** - `postgresql+psycopg://` para detección automática de psycopg3

### Mejorado
- **Fix N+1 en sync_visits_internal** - Batch load de registros existentes en una query
- **Fix N+1 en sync_fail2ban_internal** - Keys existentes cargadas en set
- **Fix N+1 en sync_ufw_internal** - Keys existentes cargadas en set
- **Fix N+1 en sync_ssh_auth_internal** - Keys existentes cargadas en set
- **`DATE_TRUNC` en queries timeline** - Reemplaza `to_char` para mejor uso de índices (fail2ban, ufw, vpn)
- **Pool de conexiones ampliado** - `pool_size=5`, `max_overflow=10`

## [2.3.0] - 2026-02-11

### Cambiado
- **Configuracion externalizada a variables de entorno** - Todo configurable via `.env`
  - `MONITOR_SITES`: Dominios/sites a monitorizar (separados por comas)
  - `MONITOR_APPS`: Aplicaciones web en formato `slug:Label`
  - `MONITOR_SSH_PORTS`: Puertos SSH para categorizar bloqueos UFW
  - `MONITOR_VPN_PORTS`: Puertos VPN/SSH para monitoreo de conexiones
- **Defaults seguros**: Contraseñas por defecto cambiadas a `change-me-in-production`
- **Templates dinamicos**: Dropdowns de site/app generados desde configuracion
- **Badges dinamicos**: Colores de app generados por hash (sin CSS hardcodeado)

### Mejorado
- **Portabilidad**: Solo hay que editar `.env` para replicar en otro servidor
- **Seguridad**: Sin credenciales ni dominios en el codigo fuente
- `.env.example` documentado con todas las variables y comentarios explicativos
- `.gitignore` actualizado con exclusion de `.claude/`

## [2.2.0] - 2026-02-03

### Añadido
- **Paginación en tablas de logs** - Soporte para grandes volúmenes de datos
  - Backend: hasta 2000 entradas (antes 1000)
  - Paginación de 100 registros por página (configurable)
  - Controles UI: botones anterior/siguiente + indicador de página
  - Metadata de paginación: `page`, `limit`, `total_records`, `total_pages`
- **Filtro por IP en todas las tablas** - Búsqueda específica por dirección IP
  - Nginx Logs: filtro por `client_ip`
  - Fail2Ban Events: filtro por `ip`
  - UFW Events: filtro por `src_ip`
  - SSH Auth Events: filtro por `src_ip`
  - Campo de búsqueda con botón "Buscar" en cada tabla

### Mejorado
- **Estructura de respuesta API** - Formato unificado con metadata
  - Antes: `[{...}, {...}]` (array directo)
  - Ahora: `{ data: [{...}], pagination: {...} }`
- **Rendimiento de queries** - Paginación en backend reduce transferencia de datos
- **UX de tablas** - Navegación más eficiente para grandes datasets

### Endpoints actualizados
- `GET /api/csp-reports?page=1&limit=100` - Paginación
- `GET /api/nginx-logs?page=1&limit=100&ip=X.X.X.X` - Paginación + filtro IP
- `GET /api/fail2ban-events?page=1&limit=100&ip=X.X.X.X` - Paginación + filtro IP
- `GET /api/ufw-events?page=1&limit=100&ip=X.X.X.X` - Paginación + filtro IP
- `GET /api/ssh-auth-events?page=1&limit=100&ip=X.X.X.X` - Paginación + filtro IP

## [2.1.0] - 2026-01-27

### Añadido
- **Gestion de IP Whitelist/Blacklist** - Nueva pagina para administrar listas de IPs
  - CRUD completo de IPs con validacion IPv4/IPv6
  - Importacion masiva desde CSV o texto
  - Exportacion a CSV
  - Generacion de configuracion Nginx (`geo $ip_whitelist`, `geo $ip_blacklist`)
  - Soporte para fechas de expiracion automatica
  - Geolocalizacion de IPs con banderas
  - Busqueda y filtros por tipo

### Nuevos endpoints API
- `GET /api/ip-list` - Listar IPs (filtro: `?type=whitelist|blacklist`)
- `GET /api/ip-list/stats` - Estadisticas (total, whitelist, blacklist)
- `POST /api/ip-list` - Crear entrada
- `PUT /api/ip-list/<id>` - Actualizar entrada
- `DELETE /api/ip-list/<id>` - Eliminar entrada
- `POST /api/ip-list/bulk-import` - Importar multiples IPs
- `GET /api/ip-list/export` - Exportar como CSV
- `GET /api/ip-list/nginx-config` - Generar directivas Nginx

### Mejorado
- **Limpieza automatica** ahora elimina IPs expiradas (expires_at < now)
- **Navegacion** actualizada con enlace a "IP Lists"

## [2.0.2] - 2026-01-27

### Mejorado
- **Optimización de queries N+1** con CTEs y DISTINCT ON de PostgreSQL
  - `api_dashboard_stats`: top_blocked_ips resuelto en una sola query
  - `api_fail2ban_stats`: top_banned_ips y top_found_ips optimizados
  - `api_ufw_stats`: top_src_ips y by_category en queries SQL puras
- **Compatibilidad PostgreSQL** en funciones de fecha
  - Reemplazado `strftime()` (SQLite) por `to_char()` (PostgreSQL)

## [2.0.1] - 2026-01-27

### Mejorado
- **Scheduler con coalescencia** para evitar ejecuciones solapadas
  - `coalesce=True`: agrupa ejecuciones perdidas
  - `max_instances=1`: solo una instancia simultánea
- **Límites de recursos Docker** para estabilidad del sistema
  - nginx-monitor: 1 CPU, 512MB RAM (reserva: 0.25 CPU, 128MB)
  - postgres: 0.5 CPU, 256MB RAM (reserva: 0.1 CPU, 64MB)
- **Logging configurado** con rotación automática
  - Máximo 10MB por archivo, 3 archivos de rotación

## [2.0.0] - 2026-01-27

### Cambiado (BREAKING CHANGE)
- **Migración de SQLite a PostgreSQL 16**
  - Mejor concurrencia y rendimiento para grandes volúmenes
  - Pool de conexiones con health checks
  - PostgreSQL Alpine como servicio Docker separado
  - Script de migración incluido (`migrate_to_postgres.py`)

### Añadido
- **Soporte para PostgreSQL** con psycopg2-binary
- **Connection pooling** con pool_pre_ping y pool_recycle
- **Docker Compose** actualizado con servicio postgres
- **Healthcheck de PostgreSQL** con pg_isready
- **Volume persistente** para datos PostgreSQL

### Configuración
Nueva variable de entorno:
- `DATABASE_URL`: URL de conexión PostgreSQL (default: postgresql://monitor:change-me-in-production@postgres:5432/monitor)
- `POSTGRES_PASSWORD`: Contraseña de PostgreSQL (default: change-me-in-production)

## [1.3.0] - 2026-01-27

### Añadido
- **Python 3.13** - Actualización desde 3.11 para mejor rendimiento y seguridad
- **Índices compuestos en base de datos** para optimizar consultas frecuentes:
  - `idx_nginx_timestamp_site_app` - Filtros por tiempo y sitio
  - `idx_nginx_client_ip_timestamp` - Top IPs bloqueadas
  - `idx_nginx_timestamp_log_type` - Estadísticas por tipo
  - `idx_fail2ban_timestamp_event_type` - Stats de eventos
  - `idx_fail2ban_ip_jail_timestamp` - Top IPs por jail
  - `idx_ufw_timestamp_action` - Timeline UFW
  - `idx_ufw_src_ip_dst_port_timestamp` - Top IPs UFW
  - `idx_ssh_timestamp_event_type` - Stats SSH
  - `idx_ssh_src_ip_timestamp` - Top IPs SSH
  - `idx_csp_timestamp_site_app` - Reportes CSP

### Mejorado
- **Dockerfile** optimizado:
  - Usuario no-root (UID 33)
  - Healthcheck nativo
  - Timeout de Gunicorn aumentado a 60s
  - Eliminado gcc (no necesario en runtime)

## [1.2.1] - 2026-01-27

### Seguridad
- **Actualización de dependencias** con vulnerabilidades corregidas
  - python-dateutil 2.8.2 → 2.9.0 (CVE-2023-49293, RCE)
  - flask 3.0.0 → 3.1.2
  - gunicorn 21.2.0 → 23.0.0
- **Validación de parámetros de entrada** para evitar DoS
  - `hours`: limitado a 1-2160 (máx 3 meses)
  - `limit`: limitado a 1-1000
  - `months`: limitado a 1-24
- **Headers de seguridad** en todas las respuestas
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - X-XSS-Protection: 1; mode=block
  - Referrer-Policy: strict-origin-when-cross-origin
  - Strict-Transport-Security (en HTTPS)

## [1.2.0] - 2026-01-27

### Añadido
- **Dashboard dividido en 3 páginas**: Nginx, SSH/VPN, UFW Firewall
- **Monitoreo de autenticación SSH real** desde `/var/log/auth.log`
  - Logins exitosos y fallidos
  - Detección de scanners y bots
  - Top IPs con login exitoso/fallido
  - Top usuarios atacados
- **Tabla de eventos SSH** ordenable y filtrable
  - Filtros por tipo, usuario e IP
  - Columnas: Fecha, Tipo, Usuario, IP Origen, Método, País
- **Nuevo endpoint** `/api/ssh-auth-events` para listado de eventos SSH
- **Etiquetas de tipo de bloqueo** en Top IPs Bloqueadas (Nginx)
  - Muestra el tipo: rate_limit, bad_bot, http_429, http_444
- **Etiquetas de jail** en Top IPs Baneadas (Fail2Ban)
  - Muestra la jail que baneó la IP
- **Etiquetas de motivo** en Top IPs Bloqueadas (UFW)
  - Categorías: SSH, DB, WEB, SMB, MAIL, VPN, TELNET, RDP, SCAN
  - Muestra el puerto principal atacado
- **Gráfica de Categorías de Bloqueo** en página UFW
  - Reemplaza la gráfica de protocolos
  - Muestra distribución por tipo de ataque
- **Hora del último evento** en todas las secciones Top IPs
  - Muestra la hora (HH:MM) junto al país
  - Disponible en Nginx, UFW y SSH

### Cambiado
- Navegación con pestañas entre las 3 páginas del dashboard
- Herencia de templates con Jinja2 (base.html)
- Estructura de URLs compatible con proxy Nginx (`/nginx-monitor/`)

### Corregido
- Mapeo correcto de respuestas API en JavaScript
- Estructura de datos de `dashboard-stats`, `visits-timeline` y `fail2ban-stats`

## [1.1.0] - 2026-01-26

### Añadido
- Columna User Agent en tabla de logs Nginx
- Job de limpieza automática diaria (4:00 AM)
- Filtros de período extendidos: 1 mes, 3 meses
- Endpoint `/api/cleanup` para limpieza manual

### Cambiado
- Límite de retención de datos: 3 meses por defecto

## [1.0.0] - 2026-01-26

### Añadido
- Dashboard inicial con monitoreo de:
  - Tráfico web (visitas, IPs únicas)
  - Reportes CSP
  - Logs de Nginx (errores, rate limit, bad bots)
  - Eventos Fail2Ban (ban, unban, found)
  - Eventos UFW/iptables
  - Conexiones VPN/SSH
- Gráficas interactivas con Chart.js
- Geolocalización de IPs con ip-api.com
- Autenticación HTTP Basic
- Sincronización automática de logs cada 5 minutos
- Contenedor Docker con Gunicorn

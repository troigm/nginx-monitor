# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

## [2.11.1] - 2026-06-20

### Corregido / mejorado (follow-up de la auditoría)
- **Dedup periódico** en el job de limpieza diario: red de seguridad ante solapes
  de rotación. La duplicación por concurrencia ya no ocurre (`--workers 1` +
  advisory lock, v2.11.0) y los duplicados históricos ya se limpiaron.
- **Lectura de logs más resistente a picos:** se sube `last_lines` (nginx 20000;
  auth/fail2ban/ufw 15000) para cubrir ventanas de tráfico mucho mayores entre
  syncs. Se evaluó un **offset-tracking incremental** pero se **descartó**: una
  revisión adversarial detectó que su interacción con el filtro de `cutoff` podía
  causar **pérdida silenciosa** de líneas (peor que la duplicación ocasional que
  evitaba). Se optó por la solución simple y segura.
- **Limpiezas:** eliminado código muerto `INTERNAL_IPS`/`INTERNAL_IP_PREFIXES`
  (sustituido por `ipaddress.is_private`); acotado el caché de geoip (cap 50k);
  eliminada variable sin uso en `cleanup_old_data`.
- **Frontend:** null-checks en `ufw.html` (`loadUfwStats`) y `loadVpnPeers`
  (peers WireGuard/OpenVPN con campos potencialmente nulos).

### Pendiente (follow-up)
- Offset-tracking incremental *lossless* de logs (requiere desacoplar el avance de
  offset del filtro de cutoff y consistencia transaccional; descartado esta ronda
  por riesgo de pérdida silenciosa).
- Migración de zona horaria de los datos históricos a UTC (descartada: los datos
  nuevos ya son UTC y los viejos caducan con la retención de 3 meses; un UPDATE
  global arriesga doble-shift).

## [2.11.0] - 2026-06-20

### Corregido (auditoría de código)
- **Scheduler a 1 worker + advisory lock.** Gunicorn pasa a `--workers 1
  --threads 8` (la app es I/O-bound) y el scheduler toma un advisory lock antes de
  ejecutar. Se elimina el doble scheduler que duplicaba datos.
- **Purga de `vpn_events`.** Se añade purga periódica para evitar crecimiento
  ilimitado de la tabla.
- **Validación de `port_filter`.** Se valida la entrada antes de usarla.
- **`/health` real contra la base de datos.** El endpoint ahora comprueba la
  conexión a la DB en lugar de devolver siempre 200.
- **Guarda de secretos por defecto.** Se rechazan los valores `change-me-in-production`
  en producción.
- **`MAX_CONTENT_LENGTH` en `/csp-report`.** Se limita el tamaño del cuerpo de los
  reportes CSP.
- **`check_auth` en tiempo constante.** Comparación de credenciales resistente a
  ataques de temporización.
- **Cabecera CSP.** Se añade Content-Security-Policy en las respuestas.
- **Truncado de `common_name`.** Se acota la longitud del campo.
- **Descarte de líneas con timestamp malformado** al parsear logs.
- **`is_internal_ip` con `ipaddress` (+IPv6).** Detección de IPs internas robusta,
  con soporte IPv6.
- **Caché y manejo de 429 en geoip.** Se cachean lookups y se gestiona el rate
  limit (429) del proveedor.
- **Lectura de logs con memoria acotada (`deque`).** Se evita cargar ficheros
  enteros en memoria.
- **Unificación de timestamps a UTC.**
- **Escape XSS en el frontend.**
- **Null-checks** varios.

### Pendiente (follow-up)
- Deduplicación de los duplicados históricos generados por el doble scheduler.
- Creación de unique indexes para prevenir duplicados a nivel de DB.
- Offset-tracking en la lectura de logs (evitar reprocesar líneas ya leídas).
- Migración de zona horaria de los datos históricos a UTC.

## [2.10.2] - 2026-06-19

### Corregido
- **Persistencia de PostgreSQL migrada al volumen nombrado** (cierra la incidencia
  de v2.10.1). Los datos se movieron del volumen anónimo a
  `nginx-monitor_postgres_data`, ahora montado en `/var/lib/postgresql` (con el
  `PGDATA` por defecto de postgres 18, sin override). Método: copia en frío del
  clúster con el stack parado, precedida de `pg_dump -Fc` verificado + `tar` del
  volumen como respaldo. Verificado **sin pérdida** (row counts intactos, postgres
  arranca sin `initdb`, 14 endpoints a 200). `docker-compose.yml`: el mount de
  postgres pasa de `postgres_data:/var/lib/postgresql/data` a
  `postgres_data:/var/lib/postgresql`. El volumen anónimo antiguo se conserva unos
  días como red de seguridad antes de borrarlo.

## [2.10.1] - 2026-06-19

Correcciones de documentación (sin cambios de código de la app) y registro de
una incidencia operativa conocida.

### Documentación
- Corregida la sección de **backup** del README: la ruta `/opt/docker-projects/...`
  no existe en el servidor; el backup real es el sistema unificado (`run-backup.sh`
  02:00 + `run-restic.sh` 07:00 a Hetzner Storage Box + `run-qnap-sync.sh` + watchdog).
- Corregida la afirmación de que postgres corre como `user: "70:70"`: ese cambio
  se **omitió** en v2.10.0 por incompatibilidad con el volumen de datos vigente.
- Aclarado que la **página IP Lists** (`/ip-list`, `ip_list.html`, `/api/ip-list*`)
  está documentada pero **no desplegada** en este build.
- Documentada la **sección VPN sin datos** mientras no exista el cron host-side
  (`/etc/cron.d/nginx-monitor-vpn`).
- Nueva sección "Incidencias conocidas" en el README.

### Conocido / pendiente
- **Persistencia de PostgreSQL en volumen anónimo.** Con `postgres:18-alpine` el
  `PGDATA` por defecto es `/var/lib/postgresql/18/docker` (volumen anónimo), mientras
  el volumen nombrado `postgres_data` se monta en `/var/lib/postgresql/data` y queda
  vacío. Persiste en restart y está cubierto por backups lógicos, pero un
  `docker compose down -v`/recreate podría perder datos. Migración planificada
  (`pg_dump` + copia en frío → mover al volumen nombrado en `/var/lib/postgresql`,
  manteniendo el `PGDATA` por defecto). **No recrear postgres sin dump previo.**

## [2.10.0] - 2026-06-19

Reintegración de las dos líneas divergentes que partían de v2.7.0 en una
única versión. Hasta ahora el proyecto se había bifurcado: una línea local
llegó hasta v2.9.0 y otra línea (la publicada en `origin/main`) llegó hasta
v2.8.1. Esta versión las une **sin perder ninguna mejora de ningún lado**.

> **Nota sobre las dos v2.8.0**: cada línea publicó su propia versión 2.8.0
> con contenido distinto (la local del 2026-05-23, la remota del 2026-05-14).
> No son la misma release. Para no perder ninguna y evitar un encabezado
> duplicado, en este changelog aparecen ambas desambiguadas como
> **2.8.0 (línea local)** y **2.8.0 (línea remota)**; v2.10.0 las unifica en
> una sola base de código.

### Reintegrado — línea local (hasta v2.9.0)
- **Página `/baneos` (Dashboard Fail2Ban)** dedicada, separada de la home.
- **Acceso a `/nginx-monitor` restringido por IP** (oficina + redes VPN +
  `deny all`) como segunda capa sobre el Basic Auth.
- **Fix de truncamiento `VARCHAR(500)`** en `nginx_logs` (`request_uri` y
  `message`) que tiraba el batch INSERT entero.
- **`sync_visits_internal` con upsert nativo** (`INSERT ... ON CONFLICT`).
- **`scripts/block-asia.sh`** (bloqueo por país a nivel kernel con
  `ipset`/`iptables`) y fix de `scripts/manage-blacklist.sh`.
- **UI más compacta** (paddings/fuentes en `base.html`, emojis en labels).

### Reintegrado — línea remota (hasta v2.8.1)
- **Consolidación de hardening + documentación de seguridad** (runtime de
  contenedores: `no-new-privileges`, postgres como `70:70`, `PGDATA`
  explícito; README con permisos `.env`, rate-limit, jail fail2ban, rotación
  de `POSTGRES_PASSWORD`, backups, ACL por VPN).
- **Card "Top 10 Páginas Visitadas (200)"** y **"Visitas por País (200)"**
  (con desglose de regiones de España).
- **`MONITOR_ADMIN_PATHS`** para excluir paths de administración (WordPress,
  Django) de las analíticas de tráfico; ejemplo con `/panel/` en
  `.env.example`.
- **Sección "VPN - OpenVPN + WireGuard"** en el tab SSH/VPN (modelo
  `VpnEvent`, parsers, endpoints `/api/vpn-stats` y `/api/vpn-peers`,
  `sync_vpn_internal()`).
- **Filtro de assets unificado** (`is_static_asset` + `ASSET_EXTENSIONS`) y
  fix de race condition en `create_tables()`.

### Corregido (nuevo en la reintegración)
- **Navegación con `basePath`** - los enlaces del menú ahora funcionan tanto
  servidos en la raíz / subdominio como bajo el prefijo `/nginx-monitor`. Las
  dos líneas habían divergido en cómo construían las URLs del navbar; el merge
  unifica la resolución del prefijo base para que ningún enlace quede roto en
  ninguno de los dos escenarios de despliegue.

## [2.9.0] - 2026-06-08

### Añadido
- **Página `/baneos` (Dashboard Fail2Ban)** - panel dedicado con stats (IPs baneadas, intentos, bans rate-limit/bad-bots), gráficas (bans por jail + timeline por hora), top IPs baneadas/intentos con geolocalización y tabla de eventos ordenable/filtrable/paginada
  - Template `app/templates/baneos.html` autónomo (hereda helpers de `base.html`)
  - Ruta `@app.route('/baneos')` en `app.py` y enlace ⛔ Baneos en el navbar (`base.html`)
  - Reutiliza los endpoints existentes `/api/fail2ban-stats` y `/api/fail2ban-events` (sin cambios en el backend)

### Cambiado
- **Home (`nginx.html`) simplificada** - la sección Fail2Ban (stats, gráficas, top IPs, tab y tabla de eventos) se ha movido a `/baneos`; eliminado también todo su JavaScript asociado (sin referencias colgantes)

### Seguridad
- **Acceso a `/nginx-monitor` restringido por IP** - el `location` del vhost `sucemart.com` ahora aplica `allow` a la IP fija de oficina y a las redes VPN (`10.6.0.0/24`, `10.8.0.0/24`) + `deny all`, como segunda capa sobre el Basic Auth. Las IPs no autorizadas reciben `403` (configuración Nginx, fuera del repo)

## [2.8.0 (línea local)] - 2026-05-23

> Una de las dos v2.8.0 divergentes. Unificada en v2.10.0.

### Corregido
- **Truncamiento VARCHAR(500) en `nginx_logs`** - `request_uri` y `message` se truncan a 500 caracteres antes de insertar
  - Síntoma: contenedor `Up (healthy)` pero sin datos nuevos en BD; ~1152 errores `psycopg.errors.StringDataRightTruncation` en 24 h
  - Causa: URIs maliciosas de botnets con query strings >500 chars hacían fallar el batch INSERT completo (1000 filas), perdiendo también las válidas
  - Fix en `parse_nginx_error_log` y `parse_nginx_access_log`: `uri[:500]` defensivo, igual que ya se hacía con `user_agent`
- **`sync_visits_internal` reescrito con `INSERT ... ON CONFLICT`** - PostgreSQL upsert nativo en una sola query
  - Elimina N+1 (carga previa de existentes) y race condition entre `SELECT` y `UPDATE`
  - Solo actualiza si `excluded.visits > visits` actual (idempotente)
  - Requiere constraint `unique_hour_site_app` en `visit_stats`
- **`scripts/manage-blacklist.sh`** - `ipset save manual-blacklist` en lugar de `ipset save` global
  - Antes sobrescribía `/etc/ipset.conf` con TODOS los sets del sistema (incluido `asia-block`), generando conflictos al recargar

### Añadido
- **`scripts/block-asia.sh`** - Bloqueo a nivel kernel de 49 países asiáticos con `ipset` + `iptables`
  - Descarga rangos CIDR agregados desde `ipdeny.com`, mínimo 30 000 CIDRs como umbral de validación
  - Unit systemd + cron para refresco automático

### Mejorado
- **UI más densa** - Reducidos paddings, márgenes y tamaños de fuente en `base.html` (container, h1/h2/h3, nav)
- **Emojis en labels de cards** - Visitas, IPs Únicas, CSP, Rate Limit, Bad Bots, Errores HTTP, SSH (Logins, Fallidos, Scanners), Fail2Ban
- **Layout `nginx.html`/`ssh_vpn.html`/`ufw.html`** - Eliminadas clases `compact`/`chart-card-fill` redundantes ahora que el layout base ya es más compacto

## [2.8.1] - 2026-05-14

### Documentación
- `.env.example`: incluir `/panel/` en el valor recomendado de
  `MONITOR_ADMIN_PATHS`. Es un patrón muy común en proyectos Django para
  paneles privados de cliente y conviene tenerlo en el ejemplo. El default
  del `docker-compose.yml` se mantiene en `/wp-admin/,/wp-login.php,/admin/`
  (sin `/panel/`) porque no es un convenio universal.

## [2.8.0 (línea remota)] - 2026-05-14

> Una de las dos v2.8.0 divergentes. Unificada en v2.10.0.

### Añadido
- **Sección "VPN - OpenVPN + WireGuard"** en el tab SSH/VPN del dashboard:
  - 4 stats cards: VPN Conexiones OK, VPN Auth Fallidas, Peers WireGuard Activos,
    Bloqueos UFW Puertos VPN.
  - Card "Top Usuarios OpenVPN" (logins exitosos por usuario).
  - Card "Top IPs OpenVPN Fallidas" con geolocalización (banderas).
  - Card "Peers WireGuard" mostrando peers OpenVPN conectados ahora + peers
    WG con interface, endpoint, `last-handshake` relativo, transfer rx/tx.
    Un peer WG se considera "activo" si tuvo handshake en los últimos 3 min.
  - Card "Bloqueos UFW a Puertos VPN" reutilizando `/api/ufw-vpn-stats`.
- **Modelo `VpnEvent`** (`vpn_events`) para eventos históricos parseados del
  journal de OpenVPN: timestamp, service, event_type
  (`auth_ok`/`auth_fail`/`connect`/`disconnect`/`tls_error`/`verify_error`/`reset`),
  common_name, username, src_ip, src_port, message, raw_line. Unique
  constraint para deduplicación entre ejecuciones del sync.
- **Parsers**: `parse_openvpn_journal()` (journalctl short-iso format),
  `parse_openvpn_status()` (formato CSV de openvpn-status.log) y
  `parse_wg_dump()` (output de `wg show all dump`).
- **Endpoints**:
  - `GET /api/vpn-stats?hours=N`: totales, top usuarios OK/fallidos,
    top IPs fallidas, eventos recientes.
  - `GET /api/vpn-peers`: snapshot on-the-fly (no persistente) de clientes
    OpenVPN y peers WireGuard.
- **`sync_vpn_internal()`** integrado en el ciclo periódico `sync_logs()`
  (cada 5 min, junto con visits/fail2ban/ufw/ssh).
- **Volumen `/var/log/nginx-monitor`** read-only en `docker-compose.yml`.

### Corregido
- **Race condition en `create_tables()`**: con varios workers de gunicorn
  arrancando a la vez, `db.create_all()` colisionaba contra
  `pg_type_typname_nsp_index` al añadir tablas nuevas, crasheando el worker
  en cold boot. Ahora se captura el error y se hace rollback (las tablas
  existentes ya están bien; un schema mismatch real fallaría más tarde en
  queries reales).

### Documentación
- **Nueva sección "VPN setup (host-side)"** en README con el bloque de comandos
  para crear el cron host que vuelca journal OpenVPN + `openvpn-status.log` +
  `wg show all dump` a `/var/log/nginx-monitor/` (legible por el contenedor).
  Sin este cron, los endpoints VPN devuelven listas vacías.

### Notas operativas
- WireGuard **no registra fallos de autenticación** por diseño del protocolo
  (paquetes sin clave válida se descartan en silencio). La card "VPN Auth
  Fallidas" solo refleja eventos de OpenVPN.
- OpenVPN necesita `verb 3` o superior para que los eventos por cliente
  aparezcan en el journal.

## [2.7.3] - 2026-05-14

### Añadido
- **`MONITOR_ADMIN_PATHS`** (nueva variable de entorno, default
  `/wp-admin/,/wp-login.php,/admin/`): lista de substrings que identifican
  paths de administración. Las URIs que CONTENGAN alguno de ellos se
  excluyen de las analíticas "Top URIs" y "Visitas por País", para que la
  navegación administrativa (WordPress, Django) no se mezcle con el
  tráfico real de usuarios.
  - Comparación por substring (no por prefijo) para cubrir aplicaciones
    Django montadas en subpaths, p.ej. `/alquiler/admin/...`.
  - Si se deja vacía no aplica filtro.

## [2.7.2] - 2026-05-14

### Añadido
- **Card "Top 10 Páginas Visitadas (200)"** en el dashboard Nginx:
  - Nuevo endpoint `/api/top-uris` que consulta `NginxLog` filtrando
    `log_type='access'` y `status_code=200`.
  - URIs agrupadas ignorando query string: `/producto?id=1` y `/producto?id=2`
    cuentan como `/producto` (vía `split_part(request_uri, '?', 1)` en SQL).
  - Respeta filtros de site/app y rango temporal del dashboard.
  - UI siguiendo el patrón `top-ips-card.compact` (lista plana con URI
    truncada a 60 chars + contador, tooltip con la URI completa).
- **Card "Visitas por País (200)"** con desglose de regiones de España:
  - Nuevo endpoint `/api/visits-by-country` que devuelve top N IPs únicas
    (default 200, max 1000) con su número de visitas 200. El frontend
    agrega por país tras hacer batch geo lookup contra `/api/geoip`.
  - Doughnut de Chart.js con top 8 países y agrupación "Otros" para el resto.
  - Cuando hay tráfico desde España, debajo del doughnut aparece una franja
    con chips de las CCAA/regiones top 8 (estilo `.region-chip`).
- **`MONITOR_SELF_PATH`** (nueva variable de entorno, default `/nginx-monitor/`):
  - Excluye URIs que empiezan por este prefijo de las dos nuevas analíticas
    para que el polling del propio dashboard no contamine los datos de
    visitas reales a las apps monitorizadas.
  - Si se deja vacía no aplica filtro.

### Mejorado
- **`/api/geoip`** amplía los campos que pide a `ip-api.com` (`regionName`,
  `region`) sin coste extra (campos gratis del batch endpoint).
- **`getGeoInfoBatch`** (base.html) ahora procesa todos los chunks de IPs
  encadenando llamadas de 100 en 100 (antes silenciaba IPs >100 del primer
  batch, pequeño bug latente que afloraba con muchos visitantes únicos).
  Guarda también `regionName` y `region` en el cache local.

## [2.7.1] - 2026-05-14

Versión que consolida sobre v2.7.0 (multi-vhost) las mejoras que la rama
paralela había acumulado como v2.6.1–v2.6.3: hardening de despliegue,
documentación de seguridad y corrección del filtro de assets.

### Corregido
- **Filtro de assets unificado** (función `is_static_asset` + constante
  `ASSET_EXTENSIONS`) reemplaza las dos listas previas que vivían cada una
  en su propio scope (`STATIC_EXTENSIONS` set para `parse_nginx_access_log`
  y lista inline en `parse_visits_from_access_log`).
  - **Strip de query string y fragmento** antes de comparar extensión. Antes
    `/style.css?ver=6.4` se contaba como visita porque `endswith('.css')`
    devolvía `False`. Con el cache-busting típico de WordPress esto inflaba
    los conteos del gráfico "Visitas por Aplicación".
  - **Comparación case-insensitive** (`.PNG` se filtra igual que `.png`).
  - **Extensiones añadidas**: `.avif` (imagen moderna), `.eot` y `.otf`
    (fuentes), `.mp4`, `.webm`, `.mp3`, `.ogg` (media). Mantiene `.map` y
    `.webmanifest` que ya añadió v2.7.0.
  - **Nota**: los datos históricos de `visit_stats` no se recalculan
    automáticamente (la tabla agrega por hora/site/app sin guardar URIs).
    El efecto solo se nota en los logs procesados a partir del despliegue.

### Seguridad (runtime de contenedores)
- **`no-new-privileges: true`** en los dos servicios (`nginx-monitor` y
  `postgres`) de `docker-compose.yml`. Bloquea cualquier escalada vía binarios
  setuid/setgid dentro del contenedor.
- **Postgres ejecutándose como `user: 70:70`** de forma explícita en compose.
  Es el UID por defecto de `postgres:18-alpine`, pero declararlo evita que un
  cambio de imagen base lo deje corriendo como root.
- **`PGDATA=/var/lib/postgresql/data`** explícito como variable de entorno
  para que la ruta del data dir no dependa del default de la imagen.

### Documentación
- **Recomendaciones de hardening** añadidas al README:
  - Permisos del `.env` a `600` (contiene `SECRET_KEY`, `AUTH_PASS`,
    `POSTGRES_PASSWORD` en claro).
  - Rate-limit nginx en los paths `/nginx-monitor/` (`zone=general`) y
    `/nginx-monitor/api/` (`zone=api`), con `burst=20 nodelay`.
  - Filtro y jail fail2ban `nginx-monitor-auth` para banear IPs con ráfagas
    de `401` contra el dashboard (5 fallos/5 min → 24h de ban).
  - Procedimiento de rotación de `POSTGRES_PASSWORD` (requiere `ALTER USER`
    dentro de la DB, cambiar solo `.env` no basta).
  - ACL por VPN sugerida para restringir el dashboard a la red de administración.
- **Procedimiento de backup automático** documentado en README:
  - Integración con `/opt/docker-projects/backups/backup_all.sh`
    (cron diario 03:00 UTC, usuario `troig`).
  - Compresión con `zstd --ultra -22`, retención 10 días, ~45 MB por dump.
  - Comando de restauración a partir de un `.sql.zst`.

### Otros
- `.gitignore`: excluir backups `.env.bak*` y `.env.*.bak*` (pueden contener
  credenciales rotadas en claro).

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

#!/usr/bin/env python3
"""
Nginx & CSP Monitor - Dashboard para monitorear reportes CSP y errores de Nginx
"""

import os
import re
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from apscheduler.schedulers.background import BackgroundScheduler
from functools import wraps

app = Flask(__name__)

# Database configuration - PostgreSQL or SQLite fallback
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:////data/monitor.db')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_size': 5,
    'max_overflow': 10,
}
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-production')

# Credenciales de acceso
AUTH_USER = os.environ.get('AUTH_USER', 'admin')
AUTH_PASS = os.environ.get('AUTH_PASS', 'change-me-in-production')

db = SQLAlchemy(app)

# ==================== CONFIGURACIÓN DINÁMICA ====================

# Sites monitorizados (lista separada por comas)
MONITOR_SITES = [s.strip() for s in os.environ.get('MONITOR_SITES', 'example.com').split(',') if s.strip()]
DEFAULT_SITE = MONITOR_SITES[0]

# Apps monitorizadas (formato: slug:Label,slug2:Label2)
_raw_apps = os.environ.get('MONITOR_APPS', 'wordpress:WordPress')
MONITOR_APPS = []
for _entry in _raw_apps.split(','):
    _parts = _entry.strip().split(':', 1)
    MONITOR_APPS.append({'slug': _parts[0], 'label': _parts[1] if len(_parts) > 1 else _parts[0]})
DEFAULT_APP = MONITOR_APPS[0]['slug']

# Puertos SSH configurables
MONITOR_SSH_PORTS = {int(p) for p in os.environ.get('MONITOR_SSH_PORTS', '22,2222').split(',') if p.strip()}

# Puertos VPN/SSH para monitoreo (formato: puerto:Nombre,puerto2:Nombre2)
_raw_vpn = os.environ.get('MONITOR_VPN_PORTS', '22:SSH,1194:OpenVPN,51820:WireGuard')
MONITOR_VPN_PORTS = {}
for _entry in _raw_vpn.split(','):
    _parts = _entry.strip().split(':', 1)
    MONITOR_VPN_PORTS[int(_parts[0])] = _parts[1] if len(_parts) > 1 else str(_parts[0])

# ==================== SEGURIDAD ====================

def validate_int_param(value, default, min_val, max_val):
    """Valida y limita parámetros enteros para evitar DoS"""
    try:
        val = int(value) if value else default
        return max(min_val, min(val, max_val))
    except (TypeError, ValueError):
        return default

@app.after_request
def set_security_headers(response):
    """Añade headers de seguridad a todas las respuestas"""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ==================== MODELOS ====================

class CSPReport(db.Model):
    __tablename__ = 'csp_reports'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    site = db.Column(db.String(100), index=True)
    app = db.Column(db.String(50), index=True)
    blocked_uri = db.Column(db.String(500))
    violated_directive = db.Column(db.String(200))
    document_uri = db.Column(db.String(500))
    source_file = db.Column(db.String(500))
    line_number = db.Column(db.Integer)
    column_number = db.Column(db.Integer)
    original_policy = db.Column(db.Text)
    raw_report = db.Column(db.Text)

    __table_args__ = (
        db.Index('idx_csp_timestamp_site_app', 'timestamp', 'site', 'app'),
    )

class NginxLog(db.Model):
    __tablename__ = 'nginx_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True)
    site = db.Column(db.String(100), index=True)
    app = db.Column(db.String(50), index=True)
    log_type = db.Column(db.String(20), index=True)  # error, access, rate_limit, bad_bot
    client_ip = db.Column(db.String(45))
    message = db.Column(db.Text)
    request_uri = db.Column(db.String(500))
    status_code = db.Column(db.Integer)
    user_agent = db.Column(db.String(500))
    raw_line = db.Column(db.Text)

    __table_args__ = (
        db.Index('idx_nginx_timestamp_site_app', 'timestamp', 'site', 'app'),
        db.Index('idx_nginx_client_ip_timestamp', 'client_ip', 'timestamp'),
        db.Index('idx_nginx_timestamp_log_type', 'timestamp', 'log_type'),
    )

class VisitStats(db.Model):
    """Estadisticas de visitas agregadas por hora"""
    __tablename__ = 'visit_stats'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True)  # Hora exacta (minutos=0, segundos=0)
    site = db.Column(db.String(100), index=True)
    app = db.Column(db.String(50), index=True)
    visits = db.Column(db.Integer, default=0)
    unique_ips = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.UniqueConstraint('timestamp', 'site', 'app', name='unique_hour_site_app'),
    )

class Fail2BanEvent(db.Model):
    """Eventos de Fail2Ban (Found, Ban, Unban)"""
    __tablename__ = 'fail2ban_events'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True)
    jail = db.Column(db.String(50), index=True)  # nginx-limit-req, nginx-badbots, sshd, etc.
    event_type = db.Column(db.String(20), index=True)  # found, ban, unban
    ip = db.Column(db.String(45), index=True)
    raw_line = db.Column(db.Text)

    __table_args__ = (
        db.Index('idx_fail2ban_timestamp_event_type', 'timestamp', 'event_type'),
        db.Index('idx_fail2ban_ip_jail_timestamp', 'ip', 'jail', 'timestamp'),
    )

class UfwEvent(db.Model):
    """Eventos de UFW/iptables (BLOCK, ALLOW, etc.)"""
    __tablename__ = 'ufw_events'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True)
    action = db.Column(db.String(20), index=True)  # BLOCK, ALLOW, AUDIT
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45))
    proto = db.Column(db.String(10), index=True)  # TCP, UDP, ICMP
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer, index=True)
    interface = db.Column(db.String(20))
    raw_line = db.Column(db.Text)

    __table_args__ = (
        db.Index('idx_ufw_timestamp_action', 'timestamp', 'action'),
        db.Index('idx_ufw_src_ip_dst_port_timestamp', 'src_ip', 'dst_port', 'timestamp'),
    )

class SshAuthEvent(db.Model):
    """Eventos de autenticación SSH (login exitoso, fallido, etc.)"""
    __tablename__ = 'ssh_auth_events'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True)
    event_type = db.Column(db.String(20), index=True)  # accepted, failed, invalid, disconnected
    auth_method = db.Column(db.String(20))  # publickey, password, none
    username = db.Column(db.String(100), index=True)
    src_ip = db.Column(db.String(45), index=True)
    src_port = db.Column(db.Integer)
    raw_line = db.Column(db.Text)

    __table_args__ = (
        db.Index('idx_ssh_timestamp_event_type', 'timestamp', 'event_type'),
        db.Index('idx_ssh_src_ip_timestamp', 'src_ip', 'timestamp'),
    )


# ==================== AUTENTICACIÓN ====================

def check_auth(username, password):
    return username == AUTH_USER and password == AUTH_PASS

def authenticate():
    return Response(
        'Acceso denegado. Credenciales requeridas.', 401,
        {'WWW-Authenticate': 'Basic realm="Nginx Monitor"'}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# ==================== CONSTANTES ====================

# Bots a excluir del conteo de visitas
BOT_PATTERNS = [
    'googlebot', 'bingbot', 'yandexbot', 'baidusp', 'petalbot',
    'ahrefsbot', 'semrushbot', 'mj12bot', 'dotbot', 'sogousp',
    'bytespider', 'facebookexternalhit', 'twitterbot', 'linkedinbot',
    'slackbot', 'telegrambot', 'whatsapp', 'applebot', 'duckduckbot',
    'ia_archiver', 'archive.org', 'crawler', 'spider', 'bot/',
    'wordpress/', 'python-requests', 'curl/', 'wget/', 'httpx'
]

# IPs internas a excluir
INTERNAL_IPS = ['127.0.0.1', '::1']
INTERNAL_IP_PREFIXES = ['172.', '10.', '192.168.']

# ==================== UTILIDADES ====================

def is_bot(user_agent):
    """Detecta si el user-agent es un bot"""
    if not user_agent:
        return False
    ua_lower = user_agent.lower()
    return any(bot in ua_lower for bot in BOT_PATTERNS)

def is_internal_ip(ip):
    """Detecta si es una IP interna"""
    if ip in INTERNAL_IPS:
        return True
    return any(ip.startswith(prefix) for prefix in INTERNAL_IP_PREFIXES)

def detect_app(uri):
    """Detecta la app basándose en la URI"""
    if uri:
        for app_conf in MONITOR_APPS[1:]:  # Skip default (first) app
            if f'/{app_conf["slug"]}' in uri:
                return app_conf['slug']
    return DEFAULT_APP

def detect_site(server_name):
    """Detecta el site basándose en server_name"""
    if server_name:
        for site in MONITOR_SITES[1:]:  # Skip default (first) site
            if site in server_name:
                return site
    return DEFAULT_SITE

# ==================== PARSEO DE LOGS ====================

def parse_nginx_error_log(log_path='/var/log/nginx/error.log', last_lines=1000):
    """Parsea el log de errores de nginx"""
    if not os.path.exists(log_path):
        return []

    entries = []
    # Patrones para diferentes tipos de errores
    patterns = {
        'rate_limit': re.compile(
            r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*limiting requests.*client: ([\d\.]+).*server: ([^,]+).*request: "(\w+) ([^"]+)'
        ),
        'general_error': re.compile(
            r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*\[error\].*client: ([\d\.]+).*server: ([^,]+).*request: "(\w+) ([^"]+)'
        ),
    }

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-last_lines:]

        for line in lines:
            for log_type, pattern in patterns.items():
                match = pattern.search(line)
                if match:
                    ts_str, client_ip, server, method, uri = match.groups()
                    try:
                        timestamp = datetime.strptime(ts_str, '%Y/%m/%d %H:%M:%S')
                    except:
                        timestamp = datetime.utcnow()

                    entries.append({
                        'timestamp': timestamp,
                        'site': detect_site(server),
                        'app': detect_app(uri),
                        'log_type': log_type,
                        'client_ip': client_ip,
                        'request_uri': uri,
                        'message': line.strip()[:500],
                        'raw_line': line.strip()
                    })
                    break
    except Exception as e:
        app.logger.error(f"Error parsing error log: {e}")

    return entries

def parse_nginx_access_log(log_path='/var/log/nginx/access.log', last_lines=1000):
    """Parsea el log de acceso de nginx buscando 444, 429, 403, etc."""
    if not os.path.exists(log_path):
        return []

    entries = []
    # Patrón para access log formato combined (incluye referer y user_agent)
    pattern = re.compile(
        r'([\d\.]+) - [^ ]+ \[([^\]]+)\] "(\w+) ([^"]*) [^"]*" (\d{3}) \d+ "[^"]*" "([^"]*)"'
    )

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-last_lines:]

        for line in lines:
            match = pattern.search(line)
            if match:
                client_ip, ts_str, method, uri, status, user_agent = match.groups()
                status = int(status)

                # Solo guardar códigos de error relevantes
                if status in [403, 404, 429, 444, 500, 502, 503]:
                    try:
                        timestamp = datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S %z')
                        timestamp = timestamp.replace(tzinfo=None)
                    except:
                        timestamp = datetime.utcnow()

                    log_type = 'bad_bot' if status == 444 else f'http_{status}'

                    entries.append({
                        'timestamp': timestamp,
                        'site': DEFAULT_SITE,
                        'app': detect_app(uri),
                        'log_type': log_type,
                        'client_ip': client_ip,
                        'request_uri': uri,
                        'status_code': status,
                        'user_agent': user_agent[:500] if user_agent else None,
                        'message': f'{method} {uri} -> {status}',
                        'raw_line': line.strip()
                    })
    except Exception as e:
        app.logger.error(f"Error parsing access log: {e}")

    return entries

def parse_visits_from_access_log(log_path='/var/log/nginx/access.log', last_lines=5000):
    """Parsea el access log para contar visitas reales (excluyendo bots)"""
    if not os.path.exists(log_path):
        return {}

    # Estructura: {(hora, site, app): {'visits': N, 'ips': set()}}
    stats = {}

    # Patron para access log formato combined con referer
    pattern = re.compile(
        r'([\d\.]+) - [^ ]+ \[([^\]]+)\] "(\w+) ([^"]*) [^"]*" (\d{3}) \d+ "([^"]*)" "([^"]*)"'
    )

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-last_lines:]

        for line in lines:
            match = pattern.search(line)
            if not match:
                continue

            client_ip, ts_str, method, uri, status, referer, user_agent = match.groups()
            status = int(status)

            # Solo contar respuestas exitosas (2xx, 3xx)
            if status < 200 or status >= 400:
                continue

            # Excluir bots
            if is_bot(user_agent):
                continue

            # Excluir IPs internas
            if is_internal_ip(client_ip):
                continue

            # Excluir recursos estaticos
            if any(uri.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg', '.webp']):
                continue

            # Parsear timestamp
            try:
                timestamp = datetime.strptime(ts_str.split()[0], '%d/%b/%Y:%H:%M:%S')
                # Redondear a la hora
                hour_ts = timestamp.replace(minute=0, second=0, microsecond=0)
            except:
                continue

            # Detectar site y app
            site = DEFAULT_SITE
            for _s in MONITOR_SITES[1:]:
                if _s in referer:
                    site = _s
                    break

            app_name = detect_app(uri)

            # Acumular stats
            key = (hour_ts, site, app_name)
            if key not in stats:
                stats[key] = {'visits': 0, 'ips': set()}
            stats[key]['visits'] += 1
            stats[key]['ips'].add(client_ip)

    except Exception as e:
        app.logger.error(f"Error parsing visits: {e}")

    return stats

def sync_visits_internal():
    """Sincroniza las visitas a la base de datos (sin app_context)"""
    visit_data = parse_visits_from_access_log()
    if not visit_data:
        return

    # Batch: cargar todos los existentes de una sola query
    timestamps = list({ts for (ts, _, _) in visit_data.keys()})
    existing_map = {}
    for rec in VisitStats.query.filter(VisitStats.timestamp.in_(timestamps)).all():
        existing_map[(rec.timestamp, rec.site, rec.app)] = rec

    for (hour_ts, site, app_name), data in visit_data.items():
        existing = existing_map.get((hour_ts, site, app_name))
        if existing:
            if data['visits'] > existing.visits:
                existing.visits = data['visits']
                existing.unique_ips = len(data['ips'])
        else:
            db.session.add(VisitStats(
                timestamp=hour_ts, site=site, app=app_name,
                visits=data['visits'], unique_ips=len(data['ips'])
            ))

    try:
        db.session.commit()
        app.logger.info(f"Synced visit stats for {len(visit_data)} hour/site/app combinations")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error syncing visits: {e}")

def parse_fail2ban_log(log_path='/var/log/fail2ban.log', last_lines=2000):
    """Parsea el log de fail2ban para extraer eventos Found, Ban, Unban"""
    if not os.path.exists(log_path):
        return []

    entries = []
    # Patrones para diferentes tipos de eventos
    # 2026-01-22 09:44:59,182 fail2ban.actions [1748955]: NOTICE [nginx-limit-req] Ban 46.24.40.5
    # 2026-01-22 09:44:58,738 fail2ban.filter [1748955]: INFO [nginx-limit-req] Found 46.24.40.5
    patterns = {
        'ban': re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ .* NOTICE  \[([^\]]+)\] Ban (\d+\.\d+\.\d+\.\d+)'),
        'unban': re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ .* NOTICE  \[([^\]]+)\] Unban (\d+\.\d+\.\d+\.\d+)'),
        'found': re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ .* INFO    \[([^\]]+)\] Found (\d+\.\d+\.\d+\.\d+)')
    }

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-last_lines:]

        for line in lines:
            for event_type, pattern in patterns.items():
                match = pattern.search(line)
                if match:
                    ts_str, jail, ip = match.groups()
                    try:
                        timestamp = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                    except:
                        timestamp = datetime.utcnow()

                    entries.append({
                        'timestamp': timestamp,
                        'jail': jail,
                        'event_type': event_type,
                        'ip': ip,
                        'raw_line': line.strip()[:500]
                    })
                    break
    except Exception as e:
        app.logger.error(f"Error parsing fail2ban log: {e}")

    return entries

def sync_fail2ban_internal():
    """Sincroniza eventos de fail2ban a la base de datos"""
    # Obtener timestamp del ultimo evento
    last_event = Fail2BanEvent.query.order_by(Fail2BanEvent.timestamp.desc()).first()
    cutoff = last_event.timestamp if last_event else datetime.utcnow() - timedelta(days=7)

    entries = parse_fail2ban_log()

    # Batch: cargar keys existentes en un set
    existing_keys = {
        (e.timestamp, e.jail, e.ip, e.event_type)
        for e in Fail2BanEvent.query.filter(Fail2BanEvent.timestamp > cutoff).all()
    }

    new_count = 0
    for entry in entries:
        if entry['timestamp'] > cutoff:
            key = (entry['timestamp'], entry['jail'], entry['ip'], entry['event_type'])
            if key not in existing_keys:
                db.session.add(Fail2BanEvent(**entry))
                existing_keys.add(key)
                new_count += 1

    try:
        db.session.commit()
        if new_count > 0:
            app.logger.info(f"Synced {new_count} fail2ban events")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error syncing fail2ban: {e}")

def parse_ufw_log(log_path='/var/log/ufw.log', last_lines=3000):
    """Parsea el log de UFW/iptables para extraer eventos BLOCK, ALLOW, etc."""
    if not os.path.exists(log_path):
        return []

    entries = []
    # Patron para log UFW formato systemd
    # 2026-01-22T11:01:59.215034+01:00 hostname kernel: [UFW BLOCK] IN=enp0s31f6 ... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=12345 DPT=443
    pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+\+\d{2}:\d{2}\s+\S+\s+kernel:\s+\[UFW\s+(\w+)\]\s+'
        r'IN=(\S*)\s+.*?SRC=([\d\.]+)\s+DST=([\d\.]+)\s+.*?PROTO=(\w+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?'
    )

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-last_lines:]

        for line in lines:
            if '[UFW' not in line:
                continue

            match = pattern.search(line)
            if match:
                ts_str, action, interface, src_ip, dst_ip, proto, src_port, dst_port = match.groups()
                try:
                    timestamp = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
                except:
                    timestamp = datetime.utcnow()

                entries.append({
                    'timestamp': timestamp,
                    'action': action,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'proto': proto,
                    'src_port': int(src_port) if src_port else None,
                    'dst_port': int(dst_port) if dst_port else None,
                    'interface': interface or 'unknown',
                    'raw_line': line.strip()[:500]
                })
    except Exception as e:
        app.logger.error(f"Error parsing UFW log: {e}")

    return entries

def sync_ufw_internal():
    """Sincroniza eventos de UFW a la base de datos"""
    # Obtener timestamp del ultimo evento
    last_event = UfwEvent.query.order_by(UfwEvent.timestamp.desc()).first()
    cutoff = last_event.timestamp if last_event else datetime.utcnow() - timedelta(days=7)

    entries = parse_ufw_log()

    # Batch: cargar keys existentes en un set
    existing_keys = {
        (e.timestamp, e.src_ip, e.dst_port, e.action)
        for e in UfwEvent.query.filter(UfwEvent.timestamp > cutoff).all()
    }

    new_count = 0
    for entry in entries:
        if entry['timestamp'] > cutoff:
            key = (entry['timestamp'], entry['src_ip'], entry['dst_port'], entry['action'])
            if key not in existing_keys:
                db.session.add(UfwEvent(**entry))
                existing_keys.add(key)
                new_count += 1

    try:
        db.session.commit()
        if new_count > 0:
            app.logger.info(f"Synced {new_count} UFW events")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error syncing UFW: {e}")

def parse_auth_log(log_path='/var/log/auth.log', last_lines=3000):
    """Parsea el log de autenticación SSH para extraer eventos de login"""
    if not os.path.exists(log_path):
        return []

    entries = []

    # Patrones para diferentes tipos de eventos SSH
    # Accepted publickey for user from IP port 12345 ssh2
    accepted_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+\+\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+'
        r'Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+([\d\.]+)\s+port\s+(\d+)'
    )

    # Failed password for user from IP port 12345
    failed_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+\+\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+'
        r'Failed\s+(\w+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+([\d\.]+)\s+port\s+(\d+)'
    )

    # Invalid user username from IP port 12345
    invalid_user_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+\+\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+'
        r'Invalid user\s+(\S+)\s+from\s+([\d\.]+)\s+port\s+(\d+)'
    )

    # Connection closed by IP port (preauth) - intentos fallidos sin auth
    preauth_close_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+\+\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+'
        r'Connection closed by\s+([\d\.]+)\s+port\s+(\d+)\s+\[preauth\]'
    )

    # banner exchange errors
    banner_error_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+\+\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+'
        r'banner exchange:.*from\s+([\d\.]+)\s+port\s+(\d+)'
    )

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-last_lines:]

        for line in lines:
            if 'sshd[' not in line:
                continue

            # Accepted login
            match = accepted_pattern.search(line)
            if match:
                ts_str, auth_method, username, src_ip, src_port = match.groups()
                try:
                    timestamp = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
                except:
                    timestamp = datetime.utcnow()
                entries.append({
                    'timestamp': timestamp,
                    'event_type': 'accepted',
                    'auth_method': auth_method,
                    'username': username,
                    'src_ip': src_ip,
                    'src_port': int(src_port),
                    'raw_line': line.strip()[:500]
                })
                continue

            # Failed login
            match = failed_pattern.search(line)
            if match:
                ts_str, auth_method, username, src_ip, src_port = match.groups()
                try:
                    timestamp = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
                except:
                    timestamp = datetime.utcnow()
                entries.append({
                    'timestamp': timestamp,
                    'event_type': 'failed',
                    'auth_method': auth_method,
                    'username': username,
                    'src_ip': src_ip,
                    'src_port': int(src_port),
                    'raw_line': line.strip()[:500]
                })
                continue

            # Invalid user
            match = invalid_user_pattern.search(line)
            if match:
                ts_str, username, src_ip, src_port = match.groups()
                try:
                    timestamp = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
                except:
                    timestamp = datetime.utcnow()
                entries.append({
                    'timestamp': timestamp,
                    'event_type': 'invalid_user',
                    'auth_method': None,
                    'username': username,
                    'src_ip': src_ip,
                    'src_port': int(src_port),
                    'raw_line': line.strip()[:500]
                })
                continue

            # Preauth close (scanner/bot)
            match = preauth_close_pattern.search(line)
            if match:
                ts_str, src_ip, src_port = match.groups()
                try:
                    timestamp = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
                except:
                    timestamp = datetime.utcnow()
                entries.append({
                    'timestamp': timestamp,
                    'event_type': 'preauth_close',
                    'auth_method': None,
                    'username': None,
                    'src_ip': src_ip,
                    'src_port': int(src_port),
                    'raw_line': line.strip()[:500]
                })
                continue

            # Banner error (scanner/bot)
            match = banner_error_pattern.search(line)
            if match:
                ts_str, src_ip, src_port = match.groups()
                try:
                    timestamp = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
                except:
                    timestamp = datetime.utcnow()
                entries.append({
                    'timestamp': timestamp,
                    'event_type': 'banner_error',
                    'auth_method': None,
                    'username': None,
                    'src_ip': src_ip,
                    'src_port': int(src_port),
                    'raw_line': line.strip()[:500]
                })
                continue

    except Exception as e:
        app.logger.error(f"Error parsing auth log: {e}")

    return entries

def sync_ssh_auth_internal():
    """Sincroniza eventos de autenticación SSH a la base de datos"""
    last_event = SshAuthEvent.query.order_by(SshAuthEvent.timestamp.desc()).first()
    cutoff = last_event.timestamp if last_event else datetime.utcnow() - timedelta(days=7)

    entries = parse_auth_log()

    # Batch: cargar keys existentes en un set
    existing_keys = {
        (e.timestamp, e.src_ip, e.src_port, e.event_type)
        for e in SshAuthEvent.query.filter(SshAuthEvent.timestamp > cutoff).all()
    }

    new_count = 0
    for entry in entries:
        if entry['timestamp'] > cutoff:
            key = (entry['timestamp'], entry['src_ip'], entry['src_port'], entry['event_type'])
            if key not in existing_keys:
                db.session.add(SshAuthEvent(**entry))
                existing_keys.add(key)
                new_count += 1

    try:
        db.session.commit()
        if new_count > 0:
            app.logger.info(f"Synced {new_count} SSH auth events")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error syncing SSH auth: {e}")

def sync_logs():
    """Sincroniza los logs de nginx a la base de datos"""
    with app.app_context():
        # Obtener timestamp del último log
        last_log = NginxLog.query.order_by(NginxLog.timestamp.desc()).first()
        cutoff = last_log.timestamp if last_log else datetime.utcnow() - timedelta(days=1)

        # Parsear logs de error
        error_entries = parse_nginx_error_log()
        for entry in error_entries:
            if entry['timestamp'] > cutoff:
                log = NginxLog(**entry)
                db.session.add(log)

        # Parsear logs de acceso
        access_entries = parse_nginx_access_log()
        for entry in access_entries:
            if entry['timestamp'] > cutoff:
                log = NginxLog(**entry)
                db.session.add(log)

        try:
            db.session.commit()
            app.logger.info(f"Synced {len(error_entries) + len(access_entries)} log entries")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error syncing logs: {e}")

        # Sincronizar visitas tambien
        sync_visits_internal()

        # Sincronizar fail2ban
        sync_fail2ban_internal()

        # Sincronizar UFW
        sync_ufw_internal()

        # Sincronizar SSH auth
        sync_ssh_auth_internal()

@app.context_processor
def inject_config():
    return {'monitor_sites': MONITOR_SITES, 'monitor_apps': MONITOR_APPS}

# ==================== RUTAS API ====================

@app.route('/csp-report', methods=['POST'])
def csp_report():
    """Endpoint para recibir reportes CSP"""
    try:
        data = request.get_json(force=True)
        report = data.get('csp-report', data)

        # Detectar site y app
        document_uri = report.get('document-uri', '')
        site = detect_site(document_uri)
        app_name = detect_app(document_uri)

        csp = CSPReport(
            site=site,
            app=app_name,
            blocked_uri=report.get('blocked-uri', '')[:500],
            violated_directive=report.get('violated-directive', '')[:200],
            document_uri=document_uri[:500],
            source_file=report.get('source-file', '')[:500] if report.get('source-file') else None,
            line_number=report.get('line-number'),
            column_number=report.get('column-number'),
            original_policy=report.get('original-policy', '')[:2000],
            raw_report=json.dumps(report)[:5000]
        )
        db.session.add(csp)
        db.session.commit()

        return jsonify({'status': 'ok'}), 204
    except Exception as e:
        app.logger.error(f"Error processing CSP report: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/csp-reports')
@requires_auth
def api_csp_reports():
    """API para obtener reportes CSP"""
    site = request.args.get('site')
    app_filter = request.args.get('app')
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    limit = validate_int_param(request.args.get('limit'), 100, 1, 2000)
    page = validate_int_param(request.args.get('page'), 1, 1, 1000)

    cutoff = datetime.utcnow() - timedelta(hours=hours)
    query = CSPReport.query.filter(CSPReport.timestamp >= cutoff)

    if site:
        query = query.filter(CSPReport.site == site)
    if app_filter:
        query = query.filter(CSPReport.app == app_filter)

    total_records = query.count()
    total_pages = (total_records + limit - 1) // limit
    offset = (page - 1) * limit

    reports = query.order_by(CSPReport.timestamp.desc()).limit(limit).offset(offset).all()

    return jsonify({
        'data': [{
            'id': r.id,
            'timestamp': r.timestamp.isoformat(),
            'site': r.site,
            'app': r.app,
            'blocked_uri': r.blocked_uri,
            'violated_directive': r.violated_directive,
            'document_uri': r.document_uri,
            'source_file': r.source_file,
            'line_number': r.line_number
        } for r in reports],
        'pagination': {
            'page': page,
            'limit': limit,
            'total_records': total_records,
            'total_pages': total_pages
        }
    })

@app.route('/api/nginx-logs')
@requires_auth
def api_nginx_logs():
    """API para obtener logs de nginx"""
    site = request.args.get('site')
    app_filter = request.args.get('app')
    log_type = request.args.get('type')
    ip_filter = request.args.get('ip')
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    limit = validate_int_param(request.args.get('limit'), 100, 1, 2000)
    page = validate_int_param(request.args.get('page'), 1, 1, 1000)

    cutoff = datetime.utcnow() - timedelta(hours=hours)
    query = NginxLog.query.filter(NginxLog.timestamp >= cutoff)

    if site:
        query = query.filter(NginxLog.site == site)
    if app_filter:
        query = query.filter(NginxLog.app == app_filter)
    if log_type:
        query = query.filter(NginxLog.log_type == log_type)
    if ip_filter:
        query = query.filter(NginxLog.client_ip == ip_filter)

    total_records = query.count()
    total_pages = (total_records + limit - 1) // limit
    offset = (page - 1) * limit

    logs = query.order_by(NginxLog.timestamp.desc()).limit(limit).offset(offset).all()

    return jsonify({
        'data': [{
            'id': l.id,
            'timestamp': l.timestamp.isoformat(),
            'site': l.site,
            'app': l.app,
            'log_type': l.log_type,
            'client_ip': l.client_ip,
            'request_uri': l.request_uri,
            'status_code': l.status_code,
            'user_agent': l.user_agent,
            'message': l.message
        } for l in logs],
        'pagination': {
            'page': page,
            'limit': limit,
            'total_records': total_records,
            'total_pages': total_pages
        }
    })

@app.route('/api/stats')
@requires_auth
def api_stats():
    """API para obtener estadísticas"""
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    # CSP stats por site/app
    csp_stats = db.session.query(
        CSPReport.site,
        CSPReport.app,
        db.func.count(CSPReport.id)
    ).filter(CSPReport.timestamp >= cutoff).group_by(
        CSPReport.site, CSPReport.app
    ).all()

    # Nginx stats por tipo
    nginx_stats = db.session.query(
        NginxLog.site,
        NginxLog.app,
        NginxLog.log_type,
        db.func.count(NginxLog.id)
    ).filter(NginxLog.timestamp >= cutoff).group_by(
        NginxLog.site, NginxLog.app, NginxLog.log_type
    ).all()

    # Top IPs bloqueadas
    top_ips = db.session.query(
        NginxLog.client_ip,
        db.func.count(NginxLog.id).label('count')
    ).filter(
        NginxLog.timestamp >= cutoff,
        NginxLog.log_type.in_(['rate_limit', 'bad_bot', 'http_444'])
    ).group_by(NginxLog.client_ip).order_by(
        db.desc('count')
    ).limit(10).all()

    return jsonify({
        'csp': [{'site': s, 'app': a, 'count': c} for s, a, c in csp_stats],
        'nginx': [{'site': s, 'app': a, 'type': t, 'count': c} for s, a, t, c in nginx_stats],
        'top_blocked_ips': [{'ip': ip, 'count': c} for ip, c in top_ips]
    })

@app.route('/api/dashboard-stats')
@requires_auth
def api_dashboard_stats():
    """API para estadisticas completas del dashboard"""
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    site_filter = request.args.get('site')
    app_filter = request.args.get('app')
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    # Visitas totales
    visits_query = db.session.query(
        db.func.sum(VisitStats.visits),
        db.func.sum(VisitStats.unique_ips)
    ).filter(VisitStats.timestamp >= cutoff)

    if site_filter:
        visits_query = visits_query.filter(VisitStats.site == site_filter)
    if app_filter:
        visits_query = visits_query.filter(VisitStats.app == app_filter)

    visits_result = visits_query.first()
    total_visits = visits_result[0] or 0
    total_unique_ips = visits_result[1] or 0

    # Visitas por site
    visits_by_site = db.session.query(
        VisitStats.site,
        db.func.sum(VisitStats.visits).label('visits')
    ).filter(VisitStats.timestamp >= cutoff).group_by(VisitStats.site).all()

    # Visitas por app
    visits_by_app = db.session.query(
        VisitStats.app,
        db.func.sum(VisitStats.visits).label('visits')
    ).filter(VisitStats.timestamp >= cutoff).group_by(VisitStats.app).all()

    # CSP total
    csp_query = db.session.query(db.func.count(CSPReport.id)).filter(CSPReport.timestamp >= cutoff)
    if site_filter:
        csp_query = csp_query.filter(CSPReport.site == site_filter)
    if app_filter:
        csp_query = csp_query.filter(CSPReport.app == app_filter)
    csp_total = csp_query.scalar() or 0

    # Nginx errors por tipo
    nginx_query = db.session.query(
        NginxLog.log_type,
        db.func.count(NginxLog.id)
    ).filter(NginxLog.timestamp >= cutoff)

    if site_filter:
        nginx_query = nginx_query.filter(NginxLog.site == site_filter)
    if app_filter:
        nginx_query = nginx_query.filter(NginxLog.app == app_filter)

    nginx_by_type = nginx_query.group_by(NginxLog.log_type).all()

    # Convertir a diccionario
    errors_dict = {t: c for t, c in nginx_by_type}

    # Top IPs bloqueadas con tipo de bloqueo y última hora (optimizado con SQL)
    # Usamos una sola query con subquery para evitar N+1
    top_blocked_sql = text('''
        WITH ip_totals AS (
            SELECT
                client_ip,
                COUNT(*) as total_count,
                MAX(timestamp) as last_seen
            FROM nginx_logs
            WHERE timestamp >= :cutoff
              AND log_type IN ('rate_limit', 'bad_bot', 'http_444', 'http_429')
            GROUP BY client_ip
            ORDER BY total_count DESC
            LIMIT 10
        ),
        ip_main_type AS (
            SELECT DISTINCT ON (client_ip)
                client_ip,
                log_type,
                COUNT(*) as type_count
            FROM nginx_logs
            WHERE timestamp >= :cutoff
              AND log_type IN ('rate_limit', 'bad_bot', 'http_444', 'http_429')
            GROUP BY client_ip, log_type
            ORDER BY client_ip, type_count DESC
        )
        SELECT
            t.client_ip,
            t.total_count,
            t.last_seen,
            m.log_type as main_type
        FROM ip_totals t
        LEFT JOIN ip_main_type m ON t.client_ip = m.client_ip
        ORDER BY t.total_count DESC
    ''')

    top_blocked_result = db.session.execute(top_blocked_sql, {'cutoff': cutoff}).fetchall()
    top_blocked_ips = [{
        'ip': row[0],
        'count': row[1],
        'last_seen': row[2].isoformat() if row[2] else None,
        'type': row[3] or 'unknown'
    } for row in top_blocked_result]

    return jsonify({
        'visits': {
            'total': total_visits,
            'unique_ips': total_unique_ips,
            'by_site': [{'site': s, 'visits': v} for s, v in visits_by_site],
            'by_app': [{'app': a, 'visits': v} for a, v in visits_by_app]
        },
        'errors': {
            'csp': csp_total,
            'rate_limit': errors_dict.get('rate_limit', 0),
            'bad_bot': errors_dict.get('bad_bot', 0) + errors_dict.get('http_444', 0),
            'http_429': errors_dict.get('http_429', 0),
            'http_4xx': sum(v for k, v in errors_dict.items() if k.startswith('http_4') and k not in ['http_444', 'http_429']),
            'http_5xx': sum(v for k, v in errors_dict.items() if k.startswith('http_5'))
        },
        'top_blocked_ips': top_blocked_ips
    })

@app.route('/api/visits-timeline')
@requires_auth
def api_visits_timeline():
    """API para timeline de visitas (para graficas)"""
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    site_filter = request.args.get('site')
    app_filter = request.args.get('app')
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    query = db.session.query(
        VisitStats.timestamp,
        VisitStats.site,
        VisitStats.app,
        VisitStats.visits
    ).filter(VisitStats.timestamp >= cutoff)

    if site_filter:
        query = query.filter(VisitStats.site == site_filter)
    if app_filter:
        query = query.filter(VisitStats.app == app_filter)

    results = query.order_by(VisitStats.timestamp.asc()).all()

    # Agrupar por hora
    timeline = {}
    for ts, site, app_name, visits in results:
        ts_str = ts.strftime('%Y-%m-%d %H:00')
        if ts_str not in timeline:
            timeline[ts_str] = {'total': 0, 'by_site': {}, 'by_app': {}}
        timeline[ts_str]['total'] += visits
        timeline[ts_str]['by_site'][site] = timeline[ts_str]['by_site'].get(site, 0) + visits
        timeline[ts_str]['by_app'][app_name] = timeline[ts_str]['by_app'].get(app_name, 0) + visits

    # Convertir a lista ordenada
    timeline_list = [
        {
            'timestamp': ts,
            'total': data['total'],
            'by_site': data['by_site'],
            'by_app': data['by_app']
        }
        for ts, data in sorted(timeline.items())
    ]

    return jsonify(timeline_list)

@app.route('/api/sync', methods=['POST'])
@requires_auth
def api_sync():
    """Fuerza sincronización de logs"""
    sync_logs()
    return jsonify({'status': 'ok', 'message': 'Logs synchronized'})

@app.route('/api/geoip', methods=['POST'])
@requires_auth
def api_geoip():
    """Obtiene geolocalización de IPs via ip-api.com"""
    import urllib.request
    import urllib.error

    data = request.get_json()
    ips = data.get('ips', [])

    if not ips:
        return jsonify([])

    # ip-api.com batch endpoint (max 100 IPs)
    try:
        req_data = json.dumps(ips[:100]).encode('utf-8')
        req = urllib.request.Request(
            'http://ip-api.com/batch?fields=query,status,country,countryCode',
            data=req_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.loads(response.read().decode('utf-8'))
            return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error fetching geoip: {e}")
        return jsonify([])

@app.route('/api/fail2ban-stats')
@requires_auth
def api_fail2ban_stats():
    """API para estadisticas de fail2ban"""
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    # Total de bans por jail
    bans_by_jail = db.session.query(
        Fail2BanEvent.jail,
        db.func.count(Fail2BanEvent.id)
    ).filter(
        Fail2BanEvent.timestamp >= cutoff,
        Fail2BanEvent.event_type == 'ban'
    ).group_by(Fail2BanEvent.jail).all()

    # Total de founds por jail
    founds_by_jail = db.session.query(
        Fail2BanEvent.jail,
        db.func.count(Fail2BanEvent.id)
    ).filter(
        Fail2BanEvent.timestamp >= cutoff,
        Fail2BanEvent.event_type == 'found'
    ).group_by(Fail2BanEvent.jail).all()

    # Top IPs baneadas con jail y última hora (optimizado con SQL)
    top_banned_sql = text('''
        WITH ip_totals AS (
            SELECT
                ip,
                COUNT(*) as total_count,
                MAX(timestamp) as last_seen
            FROM fail2ban_events
            WHERE timestamp >= :cutoff AND event_type = 'ban'
            GROUP BY ip
            ORDER BY total_count DESC
            LIMIT 10
        ),
        ip_main_jail AS (
            SELECT DISTINCT ON (ip)
                ip,
                jail,
                COUNT(*) as jail_count
            FROM fail2ban_events
            WHERE timestamp >= :cutoff AND event_type = 'ban'
            GROUP BY ip, jail
            ORDER BY ip, jail_count DESC
        )
        SELECT t.ip, t.total_count, t.last_seen, m.jail
        FROM ip_totals t
        LEFT JOIN ip_main_jail m ON t.ip = m.ip
        ORDER BY t.total_count DESC
    ''')

    top_banned_result = db.session.execute(top_banned_sql, {'cutoff': cutoff}).fetchall()
    top_banned_ips = [{
        'ip': row[0],
        'count': row[1],
        'last_seen': row[2].isoformat() if row[2] else None,
        'jail': row[3] or 'unknown'
    } for row in top_banned_result]

    # Top IPs por found (intentos) con jail y última hora (optimizado con SQL)
    top_found_sql = text('''
        WITH ip_totals AS (
            SELECT
                ip,
                COUNT(*) as total_count,
                MAX(timestamp) as last_seen
            FROM fail2ban_events
            WHERE timestamp >= :cutoff AND event_type = 'found'
            GROUP BY ip
            ORDER BY total_count DESC
            LIMIT 10
        ),
        ip_main_jail AS (
            SELECT DISTINCT ON (ip)
                ip,
                jail,
                COUNT(*) as jail_count
            FROM fail2ban_events
            WHERE timestamp >= :cutoff AND event_type = 'found'
            GROUP BY ip, jail
            ORDER BY ip, jail_count DESC
        )
        SELECT t.ip, t.total_count, t.last_seen, m.jail
        FROM ip_totals t
        LEFT JOIN ip_main_jail m ON t.ip = m.ip
        ORDER BY t.total_count DESC
    ''')

    top_found_result = db.session.execute(top_found_sql, {'cutoff': cutoff}).fetchall()
    top_found_ips = [{
        'ip': row[0],
        'count': row[1],
        'last_seen': row[2].isoformat() if row[2] else None,
        'jail': row[3] or 'unknown'
    } for row in top_found_result]

    # Timeline por hora
    timeline = db.session.query(
        db.func.date_trunc('hour', Fail2BanEvent.timestamp).label('hour'),
        Fail2BanEvent.event_type,
        db.func.count(Fail2BanEvent.id)
    ).filter(
        Fail2BanEvent.timestamp >= cutoff
    ).group_by('hour', Fail2BanEvent.event_type).all()

    # Procesar timeline
    timeline_data = {}
    for hour, event_type, count in timeline:
        if hour not in timeline_data:
            timeline_data[hour] = {'found': 0, 'ban': 0, 'unban': 0}
        timeline_data[hour][event_type] = count

    timeline_list = [
        {'timestamp': h.strftime('%Y-%m-%d %H:00'), **data}
        for h, data in sorted(timeline_data.items())
    ]

    return jsonify({
        'bans_by_jail': [{'jail': j, 'count': c} for j, c in bans_by_jail],
        'founds_by_jail': [{'jail': j, 'count': c} for j, c in founds_by_jail],
        'top_banned_ips': top_banned_ips,
        'top_found_ips': top_found_ips,
        'timeline': timeline_list,
        'totals': {
            'bans': sum(c for _, c in bans_by_jail),
            'founds': sum(c for _, c in founds_by_jail)
        }
    })

@app.route('/api/fail2ban-events')
@requires_auth
def api_fail2ban_events():
    """API para obtener eventos de fail2ban"""
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    jail_filter = request.args.get('jail')
    event_type = request.args.get('type')
    ip_filter = request.args.get('ip')
    limit = validate_int_param(request.args.get('limit'), 100, 1, 2000)
    page = validate_int_param(request.args.get('page'), 1, 1, 1000)
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    query = Fail2BanEvent.query.filter(Fail2BanEvent.timestamp >= cutoff)

    if jail_filter:
        query = query.filter(Fail2BanEvent.jail == jail_filter)
    if event_type:
        query = query.filter(Fail2BanEvent.event_type == event_type)
    if ip_filter:
        query = query.filter(Fail2BanEvent.ip == ip_filter)

    total_records = query.count()
    total_pages = (total_records + limit - 1) // limit
    offset = (page - 1) * limit

    events = query.order_by(Fail2BanEvent.timestamp.desc()).limit(limit).offset(offset).all()

    return jsonify({
        'data': [{
            'id': e.id,
            'timestamp': e.timestamp.isoformat(),
            'jail': e.jail,
            'event_type': e.event_type,
            'ip': e.ip
        } for e in events],
        'pagination': {
            'page': page,
            'limit': limit,
            'total_records': total_records,
            'total_pages': total_pages
        }
    })

@app.route('/api/ufw-stats')
@requires_auth
def api_ufw_stats():
    """API para estadisticas de UFW/iptables"""
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    # Total por accion
    by_action = db.session.query(
        UfwEvent.action,
        db.func.count(UfwEvent.id)
    ).filter(
        UfwEvent.timestamp >= cutoff
    ).group_by(UfwEvent.action).all()

    # Total por protocolo
    by_proto = db.session.query(
        UfwEvent.proto,
        db.func.count(UfwEvent.id)
    ).filter(
        UfwEvent.timestamp >= cutoff
    ).group_by(UfwEvent.proto).all()

    # Top puertos destino atacados
    top_ports = db.session.query(
        UfwEvent.dst_port,
        db.func.count(UfwEvent.id).label('count')
    ).filter(
        UfwEvent.timestamp >= cutoff,
        UfwEvent.dst_port.isnot(None)
    ).group_by(UfwEvent.dst_port).order_by(
        db.desc('count')
    ).limit(10).all()

    # Top IPs origen bloqueadas con puerto principal (optimizado con SQL)
    top_src_ips_sql = text('''
        WITH ip_totals AS (
            SELECT
                src_ip,
                COUNT(*) as total_count,
                MAX(timestamp) as last_seen
            FROM ufw_events
            WHERE timestamp >= :cutoff AND action = 'BLOCK'
            GROUP BY src_ip
            ORDER BY total_count DESC
            LIMIT 10
        ),
        ip_main_port AS (
            SELECT DISTINCT ON (src_ip)
                src_ip,
                dst_port,
                COUNT(*) as port_count
            FROM ufw_events
            WHERE timestamp >= :cutoff AND action = 'BLOCK'
            GROUP BY src_ip, dst_port
            ORDER BY src_ip, port_count DESC
        )
        SELECT t.src_ip, t.total_count, t.last_seen, m.dst_port
        FROM ip_totals t
        LEFT JOIN ip_main_port m ON t.src_ip = m.src_ip
        ORDER BY t.total_count DESC
    ''')

    # Función para categorizar puertos
    def get_block_reason(port):
        if port is None:
            return 'scan'
        ssh_ports = MONITOR_SSH_PORTS
        db_ports = {3306, 5432, 27017, 6379, 1433}
        web_ports = {80, 443, 8080, 8443}
        smb_ports = {445, 139}
        mail_ports = {25, 587, 465, 110, 143, 993, 995}
        vpn_ports = set(MONITOR_VPN_PORTS.keys()) | {1194, 1723}

        if port in ssh_ports:
            return 'ssh_attack'
        elif port in db_ports:
            return 'db_attack'
        elif port in web_ports:
            return 'web_scan'
        elif port in smb_ports:
            return 'smb_attack'
        elif port in mail_ports:
            return 'mail_scan'
        elif port in vpn_ports:
            return 'vpn_scan'
        elif port == 23:
            return 'telnet'
        elif port == 3389:
            return 'rdp_attack'
        else:
            return 'port_scan'

    top_src_result = db.session.execute(top_src_ips_sql, {'cutoff': cutoff}).fetchall()
    top_src_ips = [{
        'ip': row[0],
        'count': row[1],
        'last_seen': row[2].isoformat() if row[2] else None,
        'main_port': row[3],
        'reason': get_block_reason(row[3])
    } for row in top_src_result]

    # Estadísticas por categoría de bloqueo (optimizado con SQL)
    by_category_sql = text('''
        SELECT dst_port, COUNT(*) as count
        FROM ufw_events
        WHERE timestamp >= :cutoff AND action = 'BLOCK'
        GROUP BY dst_port
    ''')
    by_category_result = db.session.execute(by_category_sql, {'cutoff': cutoff}).fetchall()
    by_category = {}
    for port, count in by_category_result:
        reason = get_block_reason(port)
        by_category[reason] = by_category.get(reason, 0) + count

    # Nombres legibles para categorías
    category_labels = {
        'ssh_attack': 'SSH',
        'db_attack': 'Base de Datos',
        'web_scan': 'Web',
        'smb_attack': 'SMB/Windows',
        'mail_scan': 'Correo',
        'vpn_scan': 'VPN',
        'telnet': 'Telnet',
        'rdp_attack': 'RDP',
        'port_scan': 'Escaneo Puertos',
        'scan': 'Escaneo'
    }

    by_category_list = [
        {'category': k, 'label': category_labels.get(k, k), 'count': v}
        for k, v in sorted(by_category.items(), key=lambda x: x[1], reverse=True)
    ]

    # Timeline por hora
    timeline = db.session.query(
        db.func.date_trunc('hour', UfwEvent.timestamp).label('hour'),
        UfwEvent.action,
        db.func.count(UfwEvent.id)
    ).filter(
        UfwEvent.timestamp >= cutoff
    ).group_by('hour', UfwEvent.action).all()

    # Procesar timeline
    timeline_data = {}
    for hour, action, count in timeline:
        if hour not in timeline_data:
            timeline_data[hour] = {'BLOCK': 0, 'ALLOW': 0, 'AUDIT': 0}
        timeline_data[hour][action] = count

    timeline_list = [
        {'timestamp': h.strftime('%Y-%m-%d %H:00'), **data}
        for h, data in sorted(timeline_data.items())
    ]

    # Servicios conocidos por puerto
    port_services = {
        22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }

    return jsonify({
        'by_action': [{'action': a, 'count': c} for a, c in by_action],
        'by_proto': [{'proto': p, 'count': c} for p, c in by_proto],
        'by_category': by_category_list,
        'top_ports': [
            {'port': p, 'count': c, 'service': port_services.get(p, '')}
            for p, c in top_ports
        ],
        'top_src_ips': top_src_ips,
        'timeline': timeline_list,
        'totals': {
            'blocks': sum(c for a, c in by_action if a == 'BLOCK'),
            'total': sum(c for _, c in by_action)
        }
    })

@app.route('/api/ufw-events')
@requires_auth
def api_ufw_events():
    """API para obtener eventos de UFW"""
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    action_filter = request.args.get('action')
    proto_filter = request.args.get('proto')
    port_filter = request.args.get('port')
    ip_filter = request.args.get('ip')
    limit = validate_int_param(request.args.get('limit'), 100, 1, 2000)
    page = validate_int_param(request.args.get('page'), 1, 1, 1000)
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    query = UfwEvent.query.filter(UfwEvent.timestamp >= cutoff)

    if action_filter:
        query = query.filter(UfwEvent.action == action_filter)
    if proto_filter:
        query = query.filter(UfwEvent.proto == proto_filter)
    if port_filter:
        query = query.filter(UfwEvent.dst_port == int(port_filter))
    if ip_filter:
        query = query.filter(UfwEvent.src_ip == ip_filter)

    total_records = query.count()
    total_pages = (total_records + limit - 1) // limit
    offset = (page - 1) * limit

    events = query.order_by(UfwEvent.timestamp.desc()).limit(limit).offset(offset).all()

    return jsonify({
        'data': [{
            'id': e.id,
            'timestamp': e.timestamp.isoformat(),
            'action': e.action,
            'src_ip': e.src_ip,
            'dst_ip': e.dst_ip,
            'proto': e.proto,
            'src_port': e.src_port,
            'dst_port': e.dst_port,
            'interface': e.interface
        } for e in events],
        'pagination': {
            'page': page,
            'limit': limit,
            'total_records': total_records,
            'total_pages': total_pages
        }
    })

@app.route('/api/ufw-vpn-stats')
@requires_auth
def api_ufw_vpn_stats():
    """API para estadisticas de conexiones VPN/SSH (puertos auditados)"""
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    # Puertos de servicios VPN/SSH con audit
    vpn_ports = list(MONITOR_VPN_PORTS.keys())
    port_names = MONITOR_VPN_PORTS

    # Conexiones exitosas por puerto (ALLOW)
    by_port_success = db.session.query(
        UfwEvent.dst_port,
        db.func.count(UfwEvent.id)
    ).filter(
        UfwEvent.timestamp >= cutoff,
        UfwEvent.action == 'ALLOW',
        UfwEvent.dst_port.in_(vpn_ports)
    ).group_by(UfwEvent.dst_port).all()

    # Conexiones fallidas por puerto (BLOCK)
    by_port_failed = db.session.query(
        UfwEvent.dst_port,
        db.func.count(UfwEvent.id)
    ).filter(
        UfwEvent.timestamp >= cutoff,
        UfwEvent.action == 'BLOCK',
        UfwEvent.dst_port.in_(vpn_ports)
    ).group_by(UfwEvent.dst_port).all()

    # Top IPs con conexiones exitosas
    top_ips = db.session.query(
        UfwEvent.src_ip,
        db.func.count(UfwEvent.id).label('count')
    ).filter(
        UfwEvent.timestamp >= cutoff,
        UfwEvent.action == 'ALLOW',
        UfwEvent.dst_port.in_(vpn_ports)
    ).group_by(UfwEvent.src_ip).order_by(
        db.desc('count')
    ).limit(10).all()

    # Top IPs con conexiones fallidas
    top_ips_failed = db.session.query(
        UfwEvent.src_ip,
        db.func.count(UfwEvent.id).label('count')
    ).filter(
        UfwEvent.timestamp >= cutoff,
        UfwEvent.action == 'BLOCK',
        UfwEvent.dst_port.in_(vpn_ports)
    ).group_by(UfwEvent.src_ip).order_by(
        db.desc('count')
    ).limit(10).all()

    # Últimas conexiones exitosas VPN/SSH
    recent_success = UfwEvent.query.filter(
        UfwEvent.timestamp >= cutoff,
        UfwEvent.action == 'ALLOW',
        UfwEvent.dst_port.in_(vpn_ports)
    ).order_by(UfwEvent.timestamp.desc()).limit(10).all()

    # Últimas conexiones fallidas VPN/SSH
    recent_failed = UfwEvent.query.filter(
        UfwEvent.timestamp >= cutoff,
        UfwEvent.action == 'BLOCK',
        UfwEvent.dst_port.in_(vpn_ports)
    ).order_by(UfwEvent.timestamp.desc()).limit(10).all()

    # Timeline por hora (exitosas)
    timeline = db.session.query(
        db.func.date_trunc('hour', UfwEvent.timestamp).label('hour'),
        UfwEvent.dst_port,
        db.func.count(UfwEvent.id)
    ).filter(
        UfwEvent.timestamp >= cutoff,
        UfwEvent.action == 'ALLOW',
        UfwEvent.dst_port.in_(vpn_ports)
    ).group_by('hour', UfwEvent.dst_port).all()

    # Procesar timeline
    timeline_data = {}
    for hour, port, count in timeline:
        if hour not in timeline_data:
            timeline_data[hour] = {p: 0 for p in vpn_ports}
        timeline_data[hour][port] = count

    timeline_list = [
        {'timestamp': h.strftime('%Y-%m-%d %H:00'), **{port_names.get(p, str(p)): c for p, c in data.items()}}
        for h, data in sorted(timeline_data.items())
    ]

    # Totales
    total_success = sum(c for _, c in by_port_success)
    total_failed = sum(c for _, c in by_port_failed)

    return jsonify({
        'by_port': [
            {'port': p, 'service': port_names.get(p, str(p)), 'count': c}
            for p, c in by_port_success
        ],
        'by_port_failed': [
            {'port': p, 'service': port_names.get(p, str(p)), 'count': c}
            for p, c in by_port_failed
        ],
        'top_ips': [{'ip': ip, 'count': c} for ip, c in top_ips],
        'top_ips_failed': [{'ip': ip, 'count': c} for ip, c in top_ips_failed],
        'recent': [{
            'timestamp': e.timestamp.isoformat(),
            'src_ip': e.src_ip,
            'dst_port': e.dst_port,
            'service': port_names.get(e.dst_port, str(e.dst_port)),
            'interface': e.interface,
            'action': 'success'
        } for e in recent_success],
        'recent_failed': [{
            'timestamp': e.timestamp.isoformat(),
            'src_ip': e.src_ip,
            'dst_port': e.dst_port,
            'service': port_names.get(e.dst_port, str(e.dst_port)),
            'interface': e.interface,
            'action': 'failed'
        } for e in recent_failed],
        'timeline': timeline_list,
        'total': total_success,
        'total_failed': total_failed
    })

@app.route('/api/ssh-auth-stats')
@requires_auth
def api_ssh_auth_stats():
    """API para estadisticas de autenticación SSH real"""
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    # Conteo por tipo de evento
    by_type = db.session.query(
        SshAuthEvent.event_type,
        db.func.count(SshAuthEvent.id)
    ).filter(
        SshAuthEvent.timestamp >= cutoff
    ).group_by(SshAuthEvent.event_type).all()

    # Convertir a dict para fácil acceso
    type_counts = {t: c for t, c in by_type}

    # Logins exitosos
    total_accepted = type_counts.get('accepted', 0)

    # Logins fallidos (failed + invalid_user)
    total_failed = type_counts.get('failed', 0) + type_counts.get('invalid_user', 0)

    # Scanners/bots (preauth_close + banner_error)
    total_scanners = type_counts.get('preauth_close', 0) + type_counts.get('banner_error', 0)

    # Top IPs con logins exitosos
    top_ips_accepted = db.session.query(
        SshAuthEvent.src_ip,
        db.func.count(SshAuthEvent.id).label('count'),
        db.func.max(SshAuthEvent.timestamp).label('last_seen')
    ).filter(
        SshAuthEvent.timestamp >= cutoff,
        SshAuthEvent.event_type == 'accepted'
    ).group_by(SshAuthEvent.src_ip).order_by(
        db.desc('count')
    ).limit(10).all()

    # Top IPs con intentos fallidos
    top_ips_failed = db.session.query(
        SshAuthEvent.src_ip,
        db.func.count(SshAuthEvent.id).label('count'),
        db.func.max(SshAuthEvent.timestamp).label('last_seen')
    ).filter(
        SshAuthEvent.timestamp >= cutoff,
        SshAuthEvent.event_type.in_(['failed', 'invalid_user', 'preauth_close', 'banner_error'])
    ).group_by(SshAuthEvent.src_ip).order_by(
        db.desc('count')
    ).limit(10).all()

    # Top usuarios con login exitoso
    top_users_accepted = db.session.query(
        SshAuthEvent.username,
        db.func.count(SshAuthEvent.id).label('count')
    ).filter(
        SshAuthEvent.timestamp >= cutoff,
        SshAuthEvent.event_type == 'accepted',
        SshAuthEvent.username.isnot(None)
    ).group_by(SshAuthEvent.username).order_by(
        db.desc('count')
    ).limit(10).all()

    # Top usuarios atacados (intentos fallidos)
    top_users_failed = db.session.query(
        SshAuthEvent.username,
        db.func.count(SshAuthEvent.id).label('count')
    ).filter(
        SshAuthEvent.timestamp >= cutoff,
        SshAuthEvent.event_type.in_(['failed', 'invalid_user']),
        SshAuthEvent.username.isnot(None)
    ).group_by(SshAuthEvent.username).order_by(
        db.desc('count')
    ).limit(10).all()

    # Últimos logins exitosos
    recent_accepted = SshAuthEvent.query.filter(
        SshAuthEvent.timestamp >= cutoff,
        SshAuthEvent.event_type == 'accepted'
    ).order_by(SshAuthEvent.timestamp.desc()).limit(10).all()

    # Últimos intentos fallidos
    recent_failed = SshAuthEvent.query.filter(
        SshAuthEvent.timestamp >= cutoff,
        SshAuthEvent.event_type.in_(['failed', 'invalid_user', 'preauth_close', 'banner_error'])
    ).order_by(SshAuthEvent.timestamp.desc()).limit(10).all()

    return jsonify({
        'totals': {
            'accepted': total_accepted,
            'failed': total_failed,
            'scanners': total_scanners
        },
        'by_type': [{'type': t, 'count': c} for t, c in by_type],
        'top_ips_accepted': [{'ip': ip, 'count': c, 'last_seen': ls.isoformat() if ls else None} for ip, c, ls in top_ips_accepted],
        'top_ips_failed': [{'ip': ip, 'count': c, 'last_seen': ls.isoformat() if ls else None} for ip, c, ls in top_ips_failed],
        'top_users_accepted': [{'username': u, 'count': c} for u, c in top_users_accepted],
        'top_users_failed': [{'username': u, 'count': c} for u, c in top_users_failed],
        'recent_accepted': [{
            'timestamp': e.timestamp.isoformat(),
            'username': e.username,
            'src_ip': e.src_ip,
            'auth_method': e.auth_method
        } for e in recent_accepted],
        'recent_failed': [{
            'timestamp': e.timestamp.isoformat(),
            'event_type': e.event_type,
            'username': e.username,
            'src_ip': e.src_ip
        } for e in recent_failed]
    })

@app.route('/api/ssh-auth-events')
@requires_auth
def api_ssh_auth_events():
    """API para listado de eventos SSH auth (para tabla)"""
    hours = validate_int_param(request.args.get('hours'), 24, 1, 2160)
    ip_filter = request.args.get('ip')
    limit = validate_int_param(request.args.get('limit'), 200, 1, 2000)
    page = validate_int_param(request.args.get('page'), 1, 1, 1000)
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    query = SshAuthEvent.query.filter(SshAuthEvent.timestamp >= cutoff)

    if ip_filter:
        query = query.filter(SshAuthEvent.src_ip == ip_filter)

    total_records = query.count()
    total_pages = (total_records + limit - 1) // limit
    offset = (page - 1) * limit

    events = query.order_by(SshAuthEvent.timestamp.desc()).limit(limit).offset(offset).all()

    return jsonify({
        'data': [{
            'timestamp': e.timestamp.isoformat(),
            'event_type': e.event_type,
            'username': e.username,
            'src_ip': e.src_ip,
            'auth_method': e.auth_method
        } for e in events],
        'pagination': {
            'page': page,
            'limit': limit,
            'total_records': total_records,
            'total_pages': total_pages
        }
    })

# ==================== RUTAS WEB ====================

@app.route('/')
@requires_auth
def index():
    """Dashboard Nginx - pagina principal"""
    return render_template('nginx.html', active_page='nginx')

@app.route('/ssh-vpn')
@requires_auth
def ssh_vpn():
    """Dashboard SSH/VPN"""
    return render_template('ssh_vpn.html', active_page='ssh_vpn')

@app.route('/ufw')
@requires_auth
def ufw():
    """Dashboard UFW Firewall"""
    return render_template('ufw.html', active_page='ufw')


@app.route('/health')
def health():
    """Health check"""
    return jsonify({'status': 'healthy'})

# ==================== LIMPIEZA DE DATOS ====================

def cleanup_old_data(months=3):
    """Elimina datos más antiguos que X meses para mantener la DB pequeña"""
    cutoff = datetime.utcnow() - timedelta(days=months * 30)
    now = datetime.utcnow()
    results = {}

    try:
        # Limpiar nginx_logs
        count = NginxLog.query.filter(NginxLog.timestamp < cutoff).delete()
        results['nginx_logs'] = count

        # Limpiar csp_reports
        count = CSPReport.query.filter(CSPReport.timestamp < cutoff).delete()
        results['csp_reports'] = count

        # Limpiar fail2ban_events
        count = Fail2BanEvent.query.filter(Fail2BanEvent.timestamp < cutoff).delete()
        results['fail2ban_events'] = count

        # Limpiar ufw_events
        count = UfwEvent.query.filter(UfwEvent.timestamp < cutoff).delete()
        results['ufw_events'] = count

        # Limpiar ssh_auth_events
        count = SshAuthEvent.query.filter(SshAuthEvent.timestamp < cutoff).delete()
        results['ssh_auth_events'] = count

        # Limpiar visit_stats
        count = VisitStats.query.filter(VisitStats.timestamp < cutoff).delete()
        results['visit_stats'] = count

        db.session.commit()

        total = sum(results.values())
        app.logger.info(f"Cleanup completado: {total} registros eliminados (>{months} meses)")
        for table, count in results.items():
            if count > 0:
                app.logger.info(f"  - {table}: {count} registros")

        return results

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error en cleanup: {e}")
        raise

def scheduled_cleanup():
    """Wrapper para ejecutar cleanup desde scheduler con app_context"""
    with app.app_context():
        cleanup_old_data(months=3)

@app.route('/api/cleanup', methods=['POST'])
@requires_auth
def api_cleanup():
    """Endpoint para ejecutar limpieza manual de datos antiguos"""
    months = validate_int_param(request.args.get('months'), 3, 1, 24)

    try:
        results = cleanup_old_data(months=months)
        total = sum(results.values())
        return jsonify({
            'status': 'ok',
            'message': f'Cleanup completado: {total} registros eliminados',
            'cutoff_months': months,
            'deleted': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== INICIALIZACIÓN ====================

def create_tables():
    with app.app_context():
        db.create_all()

def init_scheduler():
    """Inicializa el scheduler para sincronizar logs y limpieza"""
    scheduler = BackgroundScheduler()
    # Sincronización de logs cada 5 minutos (coalesce evita ejecuciones solapadas)
    scheduler.add_job(
        func=sync_logs,
        trigger="interval",
        minutes=5,
        coalesce=True,
        max_instances=1,
        id="sync_logs"
    )
    # Limpieza de datos antiguos diaria a las 4:00 AM
    scheduler.add_job(
        func=scheduled_cleanup,
        trigger="cron",
        hour=4,
        minute=0,
        coalesce=True,
        max_instances=1,
        id="scheduled_cleanup"
    )
    scheduler.start()
    app.logger.info("Scheduler iniciado: sync cada 5min, cleanup diario a las 4:00 AM")
    return scheduler

# Crear tablas al importar el modulo
create_tables()

# Inicializar scheduler (solo una vez)
_scheduler = None
def get_scheduler():
    global _scheduler
    if _scheduler is None:
        _scheduler = init_scheduler()
        # Sincronizacion inicial en un thread separado
        import threading
        threading.Thread(target=sync_logs, daemon=True).start()
    return _scheduler

# Iniciar scheduler al cargar
get_scheduler()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

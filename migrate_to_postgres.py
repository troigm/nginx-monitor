#!/usr/bin/env python3
"""
Script para migrar datos de SQLite a PostgreSQL
Uso: python migrate_to_postgres.py
"""

import os
import sys
import sqlite3
from datetime import datetime

# Configuración
SQLITE_PATH = './data/monitor.db'
POSTGRES_URL = os.environ.get('DATABASE_URL', 'postgresql+psycopg://monitor:change-me-in-production@localhost:5432/monitor')

def get_postgres_connection():
    """Conectar a PostgreSQL"""
    import psycopg

    # Strip SQLAlchemy dialect suffix (+psycopg) for direct psycopg connection
    url = POSTGRES_URL.replace('+psycopg', '')
    return psycopg.connect(url)

def create_postgres_tables(pg_conn):
    """Crear tablas en PostgreSQL"""
    cursor = pg_conn.cursor()

    # CSP Reports
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS csp_reports (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            site VARCHAR(100),
            app VARCHAR(50),
            blocked_uri TEXT,
            violated_directive TEXT,
            document_uri TEXT,
            source_file TEXT,
            line_number INTEGER,
            column_number INTEGER,
            original_policy TEXT,
            raw_report TEXT
        )
    ''')

    # Nginx Logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nginx_logs (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP,
            site VARCHAR(100),
            app VARCHAR(50),
            log_type VARCHAR(20),
            client_ip VARCHAR(45),
            message TEXT,
            request_uri TEXT,
            status_code INTEGER,
            user_agent TEXT,
            raw_line TEXT
        )
    ''')

    # Visit Stats
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS visit_stats (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP,
            site VARCHAR(100),
            app VARCHAR(50),
            visits INTEGER DEFAULT 0,
            unique_ips INTEGER DEFAULT 0,
            UNIQUE(timestamp, site, app)
        )
    ''')

    # Fail2Ban Events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fail2ban_events (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP,
            jail VARCHAR(50),
            event_type VARCHAR(20),
            ip VARCHAR(45),
            raw_line TEXT
        )
    ''')

    # UFW Events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ufw_events (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP,
            action VARCHAR(20),
            src_ip VARCHAR(45),
            dst_ip VARCHAR(45),
            proto VARCHAR(10),
            src_port INTEGER,
            dst_port INTEGER,
            interface VARCHAR(20),
            raw_line TEXT
        )
    ''')

    # SSH Auth Events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssh_auth_events (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP,
            event_type VARCHAR(20),
            auth_method VARCHAR(20),
            username VARCHAR(100),
            src_ip VARCHAR(45),
            src_port INTEGER,
            raw_line TEXT
        )
    ''')

    # Create indexes
    indexes = [
        'CREATE INDEX IF NOT EXISTS idx_csp_timestamp ON csp_reports(timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_csp_site ON csp_reports(site)',
        'CREATE INDEX IF NOT EXISTS idx_csp_app ON csp_reports(app)',
        'CREATE INDEX IF NOT EXISTS idx_csp_timestamp_site_app ON csp_reports(timestamp, site, app)',

        'CREATE INDEX IF NOT EXISTS idx_nginx_timestamp ON nginx_logs(timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_nginx_site ON nginx_logs(site)',
        'CREATE INDEX IF NOT EXISTS idx_nginx_app ON nginx_logs(app)',
        'CREATE INDEX IF NOT EXISTS idx_nginx_log_type ON nginx_logs(log_type)',
        'CREATE INDEX IF NOT EXISTS idx_nginx_timestamp_site_app ON nginx_logs(timestamp, site, app)',
        'CREATE INDEX IF NOT EXISTS idx_nginx_client_ip_timestamp ON nginx_logs(client_ip, timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_nginx_timestamp_log_type ON nginx_logs(timestamp, log_type)',

        'CREATE INDEX IF NOT EXISTS idx_visit_timestamp ON visit_stats(timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_visit_site ON visit_stats(site)',
        'CREATE INDEX IF NOT EXISTS idx_visit_app ON visit_stats(app)',

        'CREATE INDEX IF NOT EXISTS idx_fail2ban_timestamp ON fail2ban_events(timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_fail2ban_jail ON fail2ban_events(jail)',
        'CREATE INDEX IF NOT EXISTS idx_fail2ban_event_type ON fail2ban_events(event_type)',
        'CREATE INDEX IF NOT EXISTS idx_fail2ban_ip ON fail2ban_events(ip)',
        'CREATE INDEX IF NOT EXISTS idx_fail2ban_timestamp_event_type ON fail2ban_events(timestamp, event_type)',
        'CREATE INDEX IF NOT EXISTS idx_fail2ban_ip_jail_timestamp ON fail2ban_events(ip, jail, timestamp)',

        'CREATE INDEX IF NOT EXISTS idx_ufw_timestamp ON ufw_events(timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_ufw_action ON ufw_events(action)',
        'CREATE INDEX IF NOT EXISTS idx_ufw_src_ip ON ufw_events(src_ip)',
        'CREATE INDEX IF NOT EXISTS idx_ufw_proto ON ufw_events(proto)',
        'CREATE INDEX IF NOT EXISTS idx_ufw_dst_port ON ufw_events(dst_port)',
        'CREATE INDEX IF NOT EXISTS idx_ufw_timestamp_action ON ufw_events(timestamp, action)',
        'CREATE INDEX IF NOT EXISTS idx_ufw_src_ip_dst_port_timestamp ON ufw_events(src_ip, dst_port, timestamp)',

        'CREATE INDEX IF NOT EXISTS idx_ssh_timestamp ON ssh_auth_events(timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_ssh_event_type ON ssh_auth_events(event_type)',
        'CREATE INDEX IF NOT EXISTS idx_ssh_username ON ssh_auth_events(username)',
        'CREATE INDEX IF NOT EXISTS idx_ssh_src_ip ON ssh_auth_events(src_ip)',
        'CREATE INDEX IF NOT EXISTS idx_ssh_timestamp_event_type ON ssh_auth_events(timestamp, event_type)',
        'CREATE INDEX IF NOT EXISTS idx_ssh_src_ip_timestamp ON ssh_auth_events(src_ip, timestamp)',
    ]

    for idx in indexes:
        cursor.execute(idx)

    pg_conn.commit()
    print("✓ Tablas e índices creados en PostgreSQL")

def migrate_table(sqlite_conn, pg_conn, table_name, columns):
    """Migrar una tabla de SQLite a PostgreSQL"""
    sqlite_cursor = sqlite_conn.cursor()
    pg_cursor = pg_conn.cursor()

    # Contar registros en SQLite
    sqlite_cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    total = sqlite_cursor.fetchone()[0]

    if total == 0:
        print(f"  {table_name}: 0 registros (vacía)")
        return 0

    # Leer datos de SQLite
    sqlite_cursor.execute(f"SELECT {', '.join(columns)} FROM {table_name}")
    rows = sqlite_cursor.fetchall()

    # Preparar INSERT para PostgreSQL
    placeholders = ', '.join(['%s'] * len(columns))
    insert_sql = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"

    # Insertar en lotes
    batch_size = 1000
    inserted = 0

    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        pg_cursor.executemany(insert_sql, batch)
        inserted += len(batch)
        print(f"  {table_name}: {inserted}/{total} registros migrados...", end='\r')

    pg_conn.commit()
    print(f"  {table_name}: {inserted} registros migrados" + " " * 20)
    return inserted

def main():
    print("=" * 60)
    print("MIGRACIÓN DE SQLITE A POSTGRESQL")
    print("=" * 60)

    # Verificar que existe SQLite
    if not os.path.exists(SQLITE_PATH):
        print(f"ERROR: No se encontró la base de datos SQLite en {SQLITE_PATH}")
        sys.exit(1)

    print(f"\nOrigen: {SQLITE_PATH}")
    print(f"Destino: {POSTGRES_URL.split('@')[1] if '@' in POSTGRES_URL else POSTGRES_URL}")
    print()

    # Conectar a SQLite
    print("Conectando a SQLite...")
    sqlite_conn = sqlite3.connect(SQLITE_PATH)

    # Conectar a PostgreSQL
    print("Conectando a PostgreSQL...")
    try:
        pg_conn = get_postgres_connection()
    except Exception as e:
        print(f"ERROR: No se pudo conectar a PostgreSQL: {e}")
        sys.exit(1)

    # Crear tablas
    print("\nCreando tablas en PostgreSQL...")
    create_postgres_tables(pg_conn)

    # Definir tablas y columnas a migrar
    tables = {
        'csp_reports': [
            'timestamp', 'site', 'app', 'blocked_uri', 'violated_directive',
            'document_uri', 'source_file', 'line_number', 'column_number',
            'original_policy', 'raw_report'
        ],
        'nginx_logs': [
            'timestamp', 'site', 'app', 'log_type', 'client_ip',
            'message', 'request_uri', 'status_code', 'user_agent', 'raw_line'
        ],
        'visit_stats': [
            'timestamp', 'site', 'app', 'visits', 'unique_ips'
        ],
        'fail2ban_events': [
            'timestamp', 'jail', 'event_type', 'ip', 'raw_line'
        ],
        'ufw_events': [
            'timestamp', 'action', 'src_ip', 'dst_ip', 'proto',
            'src_port', 'dst_port', 'interface', 'raw_line'
        ],
        'ssh_auth_events': [
            'timestamp', 'event_type', 'auth_method', 'username',
            'src_ip', 'src_port', 'raw_line'
        ],
    }

    # Migrar cada tabla
    print("\nMigrando datos...")
    total_migrated = 0

    for table_name, columns in tables.items():
        try:
            count = migrate_table(sqlite_conn, pg_conn, table_name, columns)
            total_migrated += count
        except Exception as e:
            print(f"  ERROR en {table_name}: {e}")

    # Cerrar conexiones
    sqlite_conn.close()
    pg_conn.close()

    print("\n" + "=" * 60)
    print(f"MIGRACIÓN COMPLETADA: {total_migrated} registros totales")
    print("=" * 60)
    print("\nPuedes verificar con: docker exec nginx-monitor-postgres psql -U monitor -d monitor -c '\\dt'")

if __name__ == '__main__':
    main()

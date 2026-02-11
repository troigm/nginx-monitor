FROM python:3.13-slim

WORKDIR /app

# Instalar dependencias del sistema (curl para healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements e instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar aplicación
COPY app/ .

# Crear directorio para datos con permisos para www-data (UID 33)
RUN mkdir -p /data && chown -R 33:33 /app /data

# Usuario no-root
USER 33:33

EXPOSE 5000
VOLUME /data

# Healthcheck nativo
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=10s \
    CMD curl -f http://localhost:5000/health || exit 1

# Gunicorn optimizado
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "60", "app:app"]

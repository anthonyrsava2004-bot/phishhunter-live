# ==============================================================================
# PhishHunter Live - Dockerfile Multi-entorno (Producción / Local / Render)
# Basado en Python 3.11-slim y optimizado para OpenCV Headless
# ==============================================================================

FROM python:3.11-slim

# Evitar escritura de .pyc y habilitar salida en tiempo real en consola
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PORT=8501 \
    DATABASE_PATH=database/phishhunter.db

# Instalar dependencias mínimas del sistema requeridas para SSL y red
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Establecer directorio de trabajo
WORKDIR /app

# Copiar requerimientos e instalar dependencias
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar el código fuente completo del proyecto
COPY . /app

# Crear directorio de persistencia SQLite y asegurar permisos
RUN mkdir -p /app/database && chmod -R 777 /app/database

# Exponer el puerto configurado
EXPOSE 8501

# Healthcheck HTTP para validar disponibilidad del servicio Streamlit
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/_stcore/health || exit 1

# Comando de inicio dinámico admitiendo variables de entorno como $PORT (Render)
ENTRYPOINT ["sh", "-c", "streamlit run app.py --server.port=${PORT:-8501} --server.address=0.0.0.0 --server.enableCORS=false --server.enableXsrfProtection=false --browser.gatherUsageStats=false"]

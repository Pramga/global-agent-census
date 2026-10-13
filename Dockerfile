FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/var/data/census.sqlite3 \
    OUTPUT_DIR=/var/data/public \
    SOURCES_CONFIG=/app/sources.json \
    REFRESH_SECONDS=21600
WORKDIR /app
COPY census.py service.py sources.json requirements.txt ./
COPY site/ ./site/
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 census \
    && mkdir -p /var/data \
    && chown -R census:census /app /var/data
USER census
EXPOSE 8080
CMD ["sh", "-c", "gunicorn --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:${PORT:-8080} service:app"]

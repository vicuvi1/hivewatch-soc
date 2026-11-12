FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HW_DATA_DIR=/data HW_DASH_HOST=0.0.0.0

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY hivewatch ./hivewatch

# Run as an unprivileged user: a honeypot must assume it WILL be attacked
RUN useradd --create-home --uid 10001 hive && mkdir -p /data && chown hive /data
USER hive
VOLUME ["/data"]

EXPOSE 8000 2222 2323 8080 3389 5900 3306 6379 9200
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/healthz'); sys.exit(0)"

ENTRYPOINT ["python", "-m", "hivewatch"]

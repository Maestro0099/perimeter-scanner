# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# nmap + библиотеки для WeasyPrint (PDF) + шрифты с кириллицей + libcap для setcap
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap libcap2-bin ca-certificates tzdata \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/* \
 # nmap получает только NET_RAW/NET_ADMIN (для SYN/UDP-сканирования и -O);
 # сам процесс приложения работает без дополнительных привилегий.
 && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY targets.example.yaml ./

RUN mkdir -p /app/data && chown -R app:app /app/data

USER app

ENV APP_HOST=0.0.0.0 \
    APP_PORT=8000 \
    DATA_DIR=/app/data \
    TARGETS_FILE=/app/targets.yaml \
    XDG_CACHE_HOME=/tmp/.cache \
    HOME=/tmp

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

# Один процесс-воркер: очередь сканов и планировщик живут внутри приложения.
CMD ["sh", "-c", "exec uvicorn app.main:app --host \"$APP_HOST\" --port \"$APP_PORT\" --workers 1 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\" --no-server-header"]

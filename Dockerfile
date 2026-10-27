FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AMBER_DATA=/data \
    AMBER_PORT=8080

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap openssh-client ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY ansible ./ansible
COPY tools ./tools

# Non-root: nmap falls back to TCP connect scan, which is all we need for port 22.
RUN useradd -r -u 10001 -m -d /home/amber amber \
 && mkdir -p /data && chown amber:amber /data \
 && chmod +x ansible/collector.sh \
 && chmod 755 ansible && chmod 644 ansible/ansible.cfg
USER amber
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"AMBER_PORT\"]}/healthz', timeout=4)" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "exec uvicorn app.main:app --host ${AMBER_HOST:-0.0.0.0} --port ${AMBER_PORT} --proxy-headers --forwarded-allow-ips='*'"]

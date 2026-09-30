FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home app \
    && mkdir -p /app /data \
    && chown -R app:app /app /data

WORKDIR /app

COPY --chown=app:app src/unifi_technitium_sync/sync.py /app/sync.py
COPY --chown=app:app src/unifi_technitium_sync/infisical_bootstrap.py /app/infisical_bootstrap.py
COPY --chown=app:app src/unifi_technitium_sync/entrypoint.py /app/entrypoint.py

USER 10001:10001

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os; os.kill(1, 0)"]

ENTRYPOINT ["python", "/app/entrypoint.py"]

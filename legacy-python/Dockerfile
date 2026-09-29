# Two stages so build tooling never ships: the wheel is built once, then
# installed into a clean runtime layer.
FROM python:3.12-slim AS build

WORKDIR /build
RUN pip install --no-cache-dir hatchling

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .


FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    CANOPY_APNS_HOST=0.0.0.0 \
    CANOPY_APNS_PORT=9247

WORKDIR /app

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

# No VOLUME and no /data. The relay stores nothing — no database, no device
# tokens, no queue — so there is no state to mount and nothing to back up.
# Every credential arrives as an environment variable.
RUN useradd --system --create-home --uid 10001 canopy

EXPOSE 9247

# urlopen raises on a non-2xx, so no status check is needed; kept to one line
# so there is no shell continuation to get wrong. /health answers 200 even
# without a signing key, which is correct: a relay waiting on its credentials
# is up, and restarting it would not produce them.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ['CANOPY_APNS_PORT']+'/health', timeout=4)" || exit 1

USER canopy
ENTRYPOINT ["python", "-m", "canopy_apns"]
CMD ["serve"]

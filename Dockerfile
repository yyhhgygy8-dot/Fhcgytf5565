FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    DATA_DIR=/data

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt

# WireGuard tools are installed after Python dependencies so build errors are clearer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN chmod 755 /app/entrypoint.sh \
    && mkdir -p /data

EXPOSE 8080

CMD ["/app/entrypoint.sh"]

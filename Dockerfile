FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends srt-tools python3 iproute2 coreutils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app/ /app/
ENV DATA_DIR=/data HTTP_PORT=8095 PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8095
STOPSIGNAL SIGTERM
CMD ["python3", "/app/server.py"]

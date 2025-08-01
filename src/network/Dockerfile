FROM debian:12

# Instala os .deb sem internet
RUN --network=none \
    --mount=type=bind,source=./debs,target=/tmp/debs \
    apt-get update && \
    apt-get install -y \
    /tmp/debs/zip_3.0-12build2_amd64.deb \
    && \
    rm -rf /var/lib/apt/lists/*

RUN apt update && apt install -y curl
RUN --network=host curl http://127.0.0.1:3000
FROM debian:trixie-slim
RUN apt update && apt install -y \
    micro \
    nano \
    git \
    net-tools \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash user
RUN mkdir -p /workspace && chown -R user:user /workspace
WORKDIR /workspace
USER user

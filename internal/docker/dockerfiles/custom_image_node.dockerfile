FROM node:24-slim
RUN apt update && apt install -y \
    nano \
    git \
    curl \
    net-tools \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g npm@latest \
    && npm config set allow-remote none \
    && npm config set allow-git none

RUN useradd -m -s /bin/bash user
RUN mkdir -p /workspace && chown -R user:user /workspace
WORKDIR /workspace
USER user

FROM node:20-slim
RUN apt update && apt install -y \
    nano \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && npm config set allow-remote none



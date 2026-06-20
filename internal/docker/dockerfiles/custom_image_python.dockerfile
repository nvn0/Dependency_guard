FROM python:3.13-slim
RUN apt update && apt install -y \
    nano \
    git \
    && rm -rf /var/lib/apt/lists/* \
WORKDIR /workspace
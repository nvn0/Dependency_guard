FROM golang:1.25-alpine
RUN apt update && apt install -y \
    nano \
    git \
    && rm -rf /var/lib/apt/lists/* \
WORKDIR /workspace
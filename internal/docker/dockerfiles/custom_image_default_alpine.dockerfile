FROM alpine:3.24.2
RUN apk update && apk add --no-cache \
    nano \
    micro \
    curl \
    git \
    && rm -rf /var/cache/apk/* 
RUN useradd -m -s /bin/bash user
RUN mkdir -p /workspace && chown -R user:user /workspace
WORKDIR /workspace
USER user

FROM golang:1.25-alpine
RUN apk update && apk add --no-cache \
    nano \
    git \
    && rm -rf /var/cache/apk/* \
WORKDIR /workspace
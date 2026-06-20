FROM node:24-alpine
RUN apk update && apk add --no-cache \
    nano \
    git \
    && rm -rf /var/cache/apk/* \
    && npm install -g npm@latest \
    && npm config set allow-remote none \
    && npm config set allow-git none
WORKDIR /workspace



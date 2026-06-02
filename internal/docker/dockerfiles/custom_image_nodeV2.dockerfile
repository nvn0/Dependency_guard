FROM node:20-bookworm
RUN apt update && apt install -y \
    nano \
    git \
    && rm -rf /var/lib/apt/lists/*
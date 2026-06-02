FROM debian:bookworm-slim
RUN apt update && apt install -y \
    nano \
    git \
    && rm -rf /var/lib/apt/lists/*
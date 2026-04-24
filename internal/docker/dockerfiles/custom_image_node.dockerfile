FROM node:20-slim

# Create non-root user and group for better security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set up workspace with proper permissions
WORKDIR /workspace
RUN chown -R appuser:appgroup /workspace

# Switch to non-root user
USER appuser
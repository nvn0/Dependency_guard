FROM python:3.12-slim

# Create non-root user and group for better security
RUN addgroup --system appgroup && adduser --system appuser --group appgroup

# Set up workspace with proper permissions
WORKDIR /workspace
RUN chown -R appuser:appgroup /workspace

# Switch to non-root user
USER appuser

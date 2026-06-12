FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip build hatchling && \
    python -m build --wheel

FROM python:3.12-slim
WORKDIR /app

# Auto-links the ghcr package to this repo on first push, keeping the
# release workflow's GITHUB_TOKEN authorized (the ACL trap BIJOTEL hit).
LABEL org.opencontainers.image.source="https://github.com/octavuntila-prog/bijotel-federation" \
      org.opencontainers.image.description="Reference federation service for BIJOTEL tamper-evident LLM audit chains" \
      org.opencontainers.image.licenses="MIT"

# Non-root user for the service process.
RUN groupadd -r fed && useradd -r -g fed fed

# Install the wheel without bringing the build deps along.
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Persistent SQLite + keys land here. Mount at runtime.
RUN mkdir -p /data && chown fed:fed /data
VOLUME ["/data"]
ENV BIJOTEL_FED_DB_PATH=/data/federation.db

USER fed
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8088/status', timeout=3).status==200 else 1)"

CMD ["bijotel-federation"]

# Alethech Dockerfile — runs the alethech MCP stdio server by default.
# Build: docker build -t alethech:0.9.5 .
# Run:   docker run -i alethech:0.9.5
#
# Default entrypoint: the MCP stdio server (`alethech-mcp`). Registry
# inspectors (Glama et al.) build this image and speak MCP `initialize` /
# `tools/list` over stdio. Zero runtime dependencies: pure Python stdlib,
# no MCP SDK, no Ollama, no network calls.
#
# Production mounts replace both defaults:
#   docker run -i -v "$PWD/memory.aleth:/data/memory.aleth" \
#     -v "$PWD/passphrase.txt:/data/passphrase.txt" alethech:0.9.5

FROM python:3.12-slim

LABEL org.opencontainers.image.title="alethech"
LABEL org.opencontainers.image.description="Verifiable agent continuity protocol — local-first, zero-LLM, zero-blockchain"
LABEL org.opencontainers.image.source="https://github.com/eddyflores100-lang/alethech"
LABEL org.opencontainers.image.licenses="AliceLabs Proprietary v1.0"
LABEL org.opencontainers.image.version="0.9.5"

WORKDIR /app

# Install alethech from source (stdlib only, so this is fast and offline-safe).
COPY pyproject.toml README.md LICENSE ./
COPY alethech/ ./alethech/
RUN pip install --no-cache-dir .

# Inspector-friendly defaults: an ephemeral, empty memory store with a
# container-local passphrase. `tools/list` and `initialize` work against
# a fresh store; production mounts override both paths via env.
RUN mkdir -p /data \
    && touch /data/memory.aleth \
    && printf 'container-local-inspector-passphrase\n' > /data/passphrase.txt

ENV ALETHECH_MEMORY=/data/memory.aleth
ENV ALETHECH_PASSPHRASE_FILE=/data/passphrase.txt

CMD ["sh", "-c", "exec alethech-mcp --memory \"$ALETHECH_MEMORY\" --passphrase-file \"$ALETHECH_PASSPHRASE_FILE\""]

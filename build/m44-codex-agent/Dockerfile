FROM node:24-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e

ARG CODEX_VERSION=0.150.1

RUN npm install --global "@openai/codex@${CODEX_VERSION}" \
    && test "$(codex --version)" = "codex-cli ${CODEX_VERSION}" \
    && npm cache clean --force

COPY --chmod=0555 entrypoint.js /usr/local/bin/mirage-codex

USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/mirage-codex"]

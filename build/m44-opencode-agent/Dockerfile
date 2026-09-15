FROM node:24-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e

ARG OPENCODE_VERSION=1.18.30

RUN npm install --global "opencode-ai@${OPENCODE_VERSION}" \
    && test "$(opencode --version)" = "${OPENCODE_VERSION}" \
    && npm cache clean --force

COPY --chmod=0444 compat.js /usr/local/lib/mirage-opencode-compat.js
COPY --chmod=0555 entrypoint.js /usr/local/bin/mirage-opencode

USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/mirage-opencode"]

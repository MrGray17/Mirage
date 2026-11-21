FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/mirage-qwen-agent ./cmd/mirage-qwen-agent
COPY internal/runtime/qwenagent ./internal/runtime/qwenagent
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /mirage-qwen-agent ./cmd/mirage-qwen-agent

FROM scratch
COPY --from=build --chmod=0555 /mirage-qwen-agent /usr/local/bin/mirage-qwen-agent
USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/mirage-qwen-agent"]

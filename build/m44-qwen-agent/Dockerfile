FROM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build
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

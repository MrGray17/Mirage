FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
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

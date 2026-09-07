package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/MrGray17/Mirage/internal/runtime/qwenagent"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "mirage-qwen-agent: task is required")
		os.Exit(64)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err := qwenagent.Run(ctx, qwenagent.Config{
		Workspace:    "/workspace",
		BrokerSocket: os.Getenv("MIRAGE_MODEL_SOCKET"),
		Model:        os.Getenv("MIRAGE_MODEL"),
		Task:         strings.Join(os.Args[1:], " "),
		Output:       os.Stdout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mirage-qwen-agent: %v\n", err)
		os.Exit(70)
	}
}

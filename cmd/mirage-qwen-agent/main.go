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
	if len(os.Args) != 4 || (os.Args[1] != "--target" && os.Args[1] != "--target-exact") || strings.TrimSpace(os.Args[2]) == "" || strings.TrimSpace(os.Args[3]) == "" {
		fmt.Fprintln(os.Stderr, "usage: mirage-qwen-agent (--target|--target-exact) <relative-file> <task>")
		os.Exit(64)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err := qwenagent.Run(ctx, qwenagent.Config{
		Workspace:             "/workspace",
		TargetPath:            os.Args[2],
		ExactReplacementsOnly: os.Args[1] == "--target-exact",
		BrokerSocket:          os.Getenv("MIRAGE_MODEL_SOCKET"),
		Model:                 os.Getenv("MIRAGE_MODEL"),
		Task:                  os.Args[3],
		Output:                os.Stdout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mirage-qwen-agent: %v\n", err)
		os.Exit(70)
	}
}

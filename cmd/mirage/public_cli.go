package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/MrGray17/Mirage/internal/buildinfo"
	"github.com/MrGray17/Mirage/internal/demo"
	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/modelbroker"
)

const (
	openCodeAgentTag        = "mirage-opencode-agent:v1"
	openCodeAgentRepository = "mirage-opencode-agent"
	openCodeCommand         = "/usr/local/bin/mirage-opencode"
)

func printHelp(writer io.Writer) {
	fmt.Fprintln(writer, `MIRAGE
Transactional security runtime for AI agents

Usage:
  mirage run [malicious|benign] [--open] [--json]
  mirage run opencode [--workspace DIR] [--allow README.md] --task "TASK"
  mirage doctor
  mirage setup
  mirage verify <receipt.json>
  mirage version

Run the verified security demo:
  mirage run --open

Advanced compatibility commands:
  mirage demo malicious|benign [options]
  mirage run hostile-fixture [options]
  mirage run agent [options] -- /absolute/agent command...

Supported real-agent compatibility modes:
  --agent qwen       constrained Qwen evidence workflow
  --agent opencode   OpenCode through the trusted local Ollama broker`)
}

func runOpenCode(args []string, stdout, stderr io.Writer) error {
	resolve := func(ctx context.Context) (string, error) {
		return runtimedocker.ResolveLocalImageDigest(ctx, "docker", openCodeAgentTag, openCodeAgentRepository)
	}
	return runOpenCodeWith(args, stdout, stderr, runAgent, resolve)
}

func runOpenCodeWith(args []string, stdout, stderr io.Writer, invoke func([]string, io.Writer, io.Writer) error, resolveImage func(context.Context) (string, error)) error {
	flags := flag.NewFlagSet("run opencode", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspace := flags.String("workspace", ".", "real project directory; OpenCode receives only a disposable snapshot")
	allowedFile := flags.String("allow", "README.md", "one existing file allowed to cross into reality (currently README.md only)")
	taskFlag := flags.String("task", "", "coding task for OpenCode and local Qwen")
	timeout := flags.Duration("timeout", 5*time.Minute, "maximum OpenCode execution time")
	quota := flags.Int64("workspace-quota-bytes", 64<<20, "hard disposable-workspace capacity")
	open := flags.Bool("open", false, "reserved until OpenCode receipts are supported")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *open {
		return errors.New("--open is not yet available for OpenCode because its agent-neutral receipt and Observatory view are not implemented")
	}
	task := strings.TrimSpace(*taskFlag)
	if flags.NArg() > 0 {
		if task != "" {
			return errors.New("provide the task either with --task or as the final quoted argument, not both")
		}
		task = strings.TrimSpace(strings.Join(flags.Args(), " "))
	}
	if task == "" {
		return errors.New("OpenCode task is required; use --task \"describe the change\"")
	}
	allowed := strings.TrimSpace(*allowedFile)
	if allowed != "README.md" && allowed != "./README.md" && allowed != "/workspace/README.md" {
		return errors.New("the current OpenCode boundary supports exactly one existing README.md; use --allow README.md")
	}
	if *timeout < time.Second || *timeout > 30*time.Minute {
		return errors.New("--timeout must be between 1s and 30m")
	}
	if *quota <= 0 {
		return errors.New("--workspace-quota-bytes must be positive")
	}
	resolveCtx, cancelResolve := context.WithTimeout(context.Background(), operationTimeout)
	agentImage, err := resolveImage(resolveCtx)
	cancelResolve()
	if err != nil {
		return fmt.Errorf("resolve pinned OpenCode sandbox image (build %s first): %w", openCodeAgentTag, err)
	}

	fmt.Fprintln(stdout, "MIRAGE OPENCODE")
	fmt.Fprintf(stdout, "  workspace                  %s\n", *workspace)
	fmt.Fprintln(stdout, "  authority                  MODIFY /workspace/README.md")
	fmt.Fprintf(stdout, "  model                      %s (trusted local Ollama broker)\n", modelbroker.Qwen25Coder15B)
	fmt.Fprintln(stdout, "  agent network              none")
	fmt.Fprintln(stdout, "  real repository mounted    no")

	agentArgs := []string{
		"--agent", "opencode",
		"--workspace", *workspace,
		"--image", agentImage,
		"--helper-image", demo.OfficialImage,
		"--allow", "/workspace/README.md",
		"--model-broker", "ollama",
		"--model", modelbroker.Qwen25Coder15B,
		"--timeout", timeout.String(),
		"--workspace-quota-bytes", fmt.Sprintf("%d", *quota),
		"--", openCodeCommand, task,
	}
	return invoke(agentArgs, stdout, stderr)
}

func runVersion(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "emit version information as JSON")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: mirage version [--json]")
	}
	info := buildinfo.Current()
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(info)
	}
	fmt.Fprintf(stdout, "mirage %s commit=%s bridge_protocol=%d platform=%s\n", info.Version, info.Commit, info.BridgeProtocol, info.Platform)
	return nil
}

type doctorReport struct {
	Ready          bool                            `json:"ready"`
	Environment    runtimedocker.EnvironmentReport `json:"environment"`
	OfficialImage  string                          `json:"official_image"`
	ImageAvailable bool                            `json:"image_available"`
	Error          string                          `json:"error,omitempty"`
}

func runDoctor(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "emit the observational report as JSON")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: mirage doctor [--json]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	report := doctorReport{OfficialImage: demo.OfficialImage}
	var err error
	report.Environment, err = runtimedocker.CheckEnvironment(ctx, "docker")
	if err == nil {
		err = runtimedocker.ImageAvailable(ctx, "docker", demo.OfficialImage)
		report.ImageAvailable = err == nil
	}
	report.Ready = err == nil
	if err != nil {
		report.Error = err.Error()
	}
	if *jsonOutput {
		if encodeErr := json.NewEncoder(stdout).Encode(report); encodeErr != nil {
			return encodeErr
		}
	} else {
		fmt.Fprintln(stdout, "MIRAGE DOCTOR")
		fmt.Fprintf(stdout, "  Linux host                 %s\n", passFail(report.Environment.HostOS == "linux"))
		fmt.Fprintf(stdout, "  Local Docker socket        %s\n", passFail(report.Environment.DockerEndpoint != ""))
		fmt.Fprintf(stdout, "  Rootless daemon            %s\n", passFail(report.Environment.Rootless))
		fmt.Fprintf(stdout, "  Seccomp                    %s\n", passFail(report.Environment.Seccomp))
		fmt.Fprintf(stdout, "  cgroup v2 + systemd        %s\n", passFail(report.Environment.CgroupVersion == "2" && strings.EqualFold(report.Environment.CgroupDriver, "systemd")))
		fmt.Fprintf(stdout, "  Resource delegation        %s\n", passFail(len(report.Environment.DelegatedControllers) >= 3))
		fmt.Fprintf(stdout, "  Official image             %s\n", passFail(report.ImageAvailable))
		if report.Ready {
			fmt.Fprintln(stdout, "\nREADY")
		} else {
			fmt.Fprintf(stdout, "\nNOT READY\n%s\n", report.Error)
		}
	}
	if err != nil {
		return fmt.Errorf("environment is not ready: %w", err)
	}
	return nil
}

func runSetup(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: mirage setup")
	}
	ctx, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignal()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	pulled, err := runtimedocker.EnsureImage(ctx, "docker", demo.OfficialImage)
	if err != nil {
		return fmt.Errorf("setup made no security configuration changes: %w", err)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("locate MIRAGE cache: %w", err)
	}
	outputRoot := filepath.Join(cache, "mirage", "runs")
	if err := os.MkdirAll(outputRoot, 0o700); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	fmt.Fprintln(stdout, "MIRAGE SETUP")
	if pulled {
		fmt.Fprintln(stdout, "  Official image             PULLED + VERIFIED")
	} else {
		fmt.Fprintln(stdout, "  Official image             PRESENT + VERIFIED")
	}
	fmt.Fprintf(stdout, "  Evidence directory         %s\n\nREADY\n", outputRoot)
	return nil
}

func passFail(value bool) string {
	if value {
		return "PASS"
	}
	return "FAIL"
}

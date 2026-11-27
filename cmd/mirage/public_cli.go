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

func printHelp(writer io.Writer) {
	fmt.Fprintln(writer, `MIRAGE
Transactional security runtime for AI agents

Get started (deterministic demo; no provider API key or GitHub write):
  mirage setup
  mirage doctor
  mirage run --open

Edit one existing file with local Qwen:
  mirage edit [options] <file> <task>
  The official digest-pinned Qwen runtime is the default.

Connect any MCP-compatible coding agent:
  mirage mcp
  Register it with your harness as the local stdio command: mirage mcp

Usage:
  mirage run [malicious|benign] [--open] [--json]
  mirage edit [options] <file> <task>
  mirage mcp
  mirage setup
  mirage doctor [--json]
  mirage recover
  mirage journal list [--json]
  mirage journal prune --before RFC3339 --confirm
  mirage lab --scenario benign|malicious|both --trials 1..10
  mirage verify <receipt.json>
  mirage attest keygen --private PRIVATE.pem --public PUBLIC.pem
  mirage attest sign --key PRIVATE.pem --out PROOF.json RECEIPT.json
  mirage attest verify --key PUBLIC.pem --proof PROOF.json RECEIPT.json
  mirage proof verify --key PUBLIC.pem [--report REPORT.html] BUNDLE.zip
  mirage receipt verify <receipt.json>
  mirage observatory --out <report.html> <receipt.json>
  mirage version [--json]

After a run:
  mirage verify <receipt_file>
  Open the printed Observatory path to inspect verified evidence.

Advanced compatibility commands:
  mirage demo malicious|benign [options]
  mirage run hostile-fixture [options]
  mirage run agent [options] -- /absolute/agent command...`)
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
	Ready                bool                            `json:"ready"`
	EditReady            bool                            `json:"edit_ready"`
	Environment          runtimedocker.EnvironmentReport `json:"environment"`
	OfficialImage        string                          `json:"official_image"`
	ImageAvailable       bool                            `json:"image_available"`
	QwenImage            string                          `json:"qwen_image"`
	QwenImageAvailable   bool                            `json:"qwen_image_available"`
	HelperImage          string                          `json:"helper_image"`
	HelperImageAvailable bool                            `json:"helper_image_available"`
	OllamaModelAvailable bool                            `json:"ollama_model_available"`
	OllamaError          string                          `json:"ollama_error,omitempty"`
	Error                string                          `json:"error,omitempty"`
}

func runDoctor(args []string, stdout, stderr io.Writer) error {
	return runDoctorContext(context.Background(), args, stdout, stderr)
}

func runDoctorContext(parent context.Context, args []string, stdout, stderr io.Writer) error {
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
	ctx, cancel := context.WithTimeout(parent, operationTimeout)
	defer cancel()
	report := doctorReport{
		OfficialImage: demo.OfficialImage,
		QwenImage:     defaultQwenImage,
		HelperImage:   defaultQwenHelperImage,
	}
	var coreErr error
	report.Environment, coreErr = runtimedocker.CheckEnvironment(ctx, "docker")
	if coreErr == nil {
		coreErr = runtimedocker.ImageAvailable(ctx, "docker", demo.OfficialImage)
		report.ImageAvailable = coreErr == nil
	}
	if report.Environment.DockerEndpoint != "" {
		report.QwenImageAvailable = runtimedocker.ImageAvailable(ctx, "docker", defaultQwenImage) == nil
		report.HelperImageAvailable = runtimedocker.ImageAvailable(ctx, "docker", defaultQwenHelperImage) == nil
	}
	report.Ready = coreErr == nil
	if report.Ready && report.QwenImageAvailable && report.HelperImageAvailable {
		if err := modelbroker.CheckOllamaModel(ctx); err != nil {
			report.OllamaError = err.Error()
		} else {
			report.OllamaModelAvailable = true
		}
	}
	report.EditReady = report.Ready && report.QwenImageAvailable && report.HelperImageAvailable && report.OllamaModelAvailable
	if coreErr != nil {
		report.Error = coreErr.Error()
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
		fmt.Fprintf(stdout, "  Demo image                 %s\n", passFail(report.ImageAvailable))
		fmt.Fprintf(stdout, "  Qwen runtime               %s\n", passFail(report.QwenImageAvailable))
		fmt.Fprintf(stdout, "  Helper image               %s\n", passFail(report.HelperImageAvailable))
		fmt.Fprintf(stdout, "  Ollama model               %s\n", passFail(report.OllamaModelAvailable))
		if report.OllamaError != "" {
			fmt.Fprintf(stdout, "  %s\n", report.OllamaError)
		}
		if report.Ready {
			fmt.Fprintln(stdout, "\nREADY")
			if report.EditReady {
				fmt.Fprintln(stdout, "EDIT READY")
			} else {
				fmt.Fprintln(stdout, "EDIT NOT READY — check runtime images and local Ollama")
			}
		} else {
			fmt.Fprintf(stdout, "\nNOT READY\n%s\n", report.Error)
		}
	}
	if coreErr != nil {
		return fmt.Errorf("environment is not ready: %w", coreErr)
	}
	return nil
}

func runSetup(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, "Usage: mirage setup")
			fmt.Fprintln(stdout, "\nPulls and verifies every pinned runtime image and prepares the local evidence directory.")
			return nil
		}
		fmt.Fprintln(stderr, err)
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: mirage setup")
	}
	ctx, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignal()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	type setupImage struct {
		label     string
		reference string
		pulled    bool
	}
	images := []setupImage{
		{label: "Demo image", reference: demo.OfficialImage},
		{label: "Qwen runtime", reference: defaultQwenImage},
		{label: "Helper image", reference: defaultQwenHelperImage},
	}
	for index := range images {
		pulled, err := runtimedocker.EnsureImage(ctx, "docker", images[index].reference)
		if err != nil {
			return fmt.Errorf("setup stopped while preparing %s: %w", strings.ToLower(images[index].label), err)
		}
		images[index].pulled = pulled
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
	for _, image := range images {
		status := "PRESENT + VERIFIED"
		if image.pulled {
			status = "PULLED + VERIFIED"
		}
		fmt.Fprintf(stdout, "  %-26s %s\n", image.label, status)
	}
	fmt.Fprintf(stdout, "  %-26s %s\n", "Evidence directory", outputRoot)
	fmt.Fprintln(stdout, "\nRUNTIME READY")
	fmt.Fprintln(stdout, "Next: ensure Ollama is running with qwen2.5-coder:1.5b, then run:")
	fmt.Fprintln(stdout, "  mirage edit README.md \"Improve the introduction\"")
	fmt.Fprintln(stdout, "Coding-agent integration: register the local stdio command 'mirage mcp'.")
	return nil
}

func passFail(value bool) string {
	if value {
		return "PASS"
	}
	return "FAIL"
}

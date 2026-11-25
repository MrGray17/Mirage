package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/MrGray17/Mirage/internal/buildinfo"
	"github.com/MrGray17/Mirage/internal/cliapi"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpCommandOutputLimit = 1 << 20

var errMCPOutputOverflow = errors.New("Mirage command output exceeded the 1 MiB MCP safety limit")

type mcpCommandRunner func(args []string, stdout, stderr io.Writer) error

type mcpDoctorInput struct{}

type mcpEditInput struct {
	File      string `json:"file" jsonschema:"relative path to the one existing regular file that the user authorizes Mirage to modify"`
	Task      string `json:"task" jsonschema:"specific edit requested by the user; limited to 16 KiB"`
	Workspace string `json:"workspace,omitempty" jsonschema:"absolute or current-process-relative project directory; defaults to the MCP server working directory"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"optional evidence directory outside the project workspace"`
	Approved  bool   `json:"approved" jsonschema:"must be true only after the user has explicitly authorized this exact file edit"`
}

type mcpVerifyInput struct {
	Receipt string `json:"receipt" jsonschema:"path to one Mirage receipt JSON file"`
}

type mcpVerifyOutput struct {
	Valid    bool   `json:"valid"`
	Evidence string `json:"evidence"`
}

func runMCP(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("mcp", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, "Usage: mirage mcp")
			fmt.Fprintln(stdout, "\nRuns the local Mirage MCP server over stdio for any compatible coding agent.")
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: mirage mcp")
	}
	server := newMirageMCPServer(runAutomationEntrypoint)
	if err := server.Run(context.Background(), &mcp.StdioTransport{MaxLineLength: 1 << 20}); err != nil {
		return fmt.Errorf("serve MCP over stdio: %w", err)
	}
	_ = stderr
	return nil
}

func newMirageMCPServer(runner mcpCommandRunner) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "mirage", Version: buildinfo.Version},
		&mcp.ServerOptions{Instructions: "Use mirage_edit_file for authorized file changes. It can modify exactly one existing regular file per call, runs without sandbox network access, and returns verified evidence. Never set approved=true unless the user authorized that exact target and task."},
	)
	closed := false
	mcp.AddTool(server, &mcp.Tool{
		Name:        "mirage_doctor",
		Title:       "Check Mirage readiness",
		Description: "Check whether Mirage's security runtime and local editing agent are ready. This is read-only.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &closed},
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ mcpDoctorInput) (*mcp.CallToolResult, doctorReport, error) {
		stdout, stderr, err := executeMCPCommand(runner, []string{"doctor", "--json"})
		if err != nil {
			return nil, doctorReport{}, commandToolError("Mirage readiness check failed", err, stderr)
		}
		report, err := parseDoctorReport(stdout)
		if err != nil {
			return nil, doctorReport{}, fmt.Errorf("Mirage returned an invalid doctor report: %w", err)
		}
		return nil, report, nil
	})

	destructive := true
	mcp.AddTool(server, &mcp.Tool{
		Name:        "mirage_edit_file",
		Title:       "Safely edit one file with Mirage",
		Description: "Transactionally edit exactly one user-authorized existing regular file with local Qwen. The sandbox has no network, shell, Git, or ambient credentials. Returns a verified receipt and Observatory path. Set approved=true only after explicit user authorization.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &closed},
	}, func(_ context.Context, _ *mcp.CallToolRequest, input mcpEditInput) (*mcp.CallToolResult, cliapi.AgentRunSummary, error) {
		if !input.Approved {
			return nil, cliapi.AgentRunSummary{}, errors.New("edit not authorized: approved must be true after the user explicitly authorizes this exact file and task")
		}
		args := []string{"edit", "--yes", "--format", "json"}
		if strings.TrimSpace(input.Workspace) != "" {
			args = append(args, "--workspace", input.Workspace)
		}
		if strings.TrimSpace(input.OutputDir) != "" {
			args = append(args, "--output-dir", input.OutputDir)
		}
		args = append(args, input.File, input.Task)
		stdout, stderr, commandErr := executeMCPCommand(runner, args)
		summary, parseErr := cliapi.ParseAgentRunSummary(stdout)
		// A verified policy rejection is an intentional nonzero CLI exit,
		// not a transport failure. Never accept truncated output or a failed
		// command claiming a successful commit.
		if commandErr != nil {
			if errors.Is(commandErr, errMCPOutputOverflow) {
				return nil, cliapi.AgentRunSummary{}, commandErr
			}
			if parseErr == nil && summary.Outcome == "REJECTED" {
				return nil, summary, nil
			}
			return nil, cliapi.AgentRunSummary{}, commandToolError("Mirage edit failed", commandErr, stderr)
		}
		if parseErr != nil {
			return nil, cliapi.AgentRunSummary{}, fmt.Errorf("Mirage returned an invalid agent summary: %w", parseErr)
		}
		return nil, summary, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "mirage_verify_receipt",
		Title:       "Verify a Mirage receipt",
		Description: "Independently parse and verify one Mirage execution receipt. This is read-only.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &closed},
	}, func(_ context.Context, _ *mcp.CallToolRequest, input mcpVerifyInput) (*mcp.CallToolResult, mcpVerifyOutput, error) {
		stdout, stderr, err := executeMCPCommand(runner, []string{"verify", input.Receipt})
		if err != nil {
			return nil, mcpVerifyOutput{}, commandToolError("Mirage receipt verification failed", err, stderr)
		}
		evidence := strings.TrimSpace(string(stdout))
		if !strings.HasPrefix(evidence, "VALID receipt=sha256:") {
			return nil, mcpVerifyOutput{}, errors.New("Mirage returned an invalid receipt-verification result")
		}
		return nil, mcpVerifyOutput{Valid: true, Evidence: evidence}, nil
	})
	return server
}

func executeMCPCommand(runner mcpCommandRunner, args []string) ([]byte, []byte, error) {
	var stdout, stderr mcpLimitedBuffer
	err := runner(args, &stdout, &stderr)
	if stdout.truncated || stderr.truncated {
		overflow := errMCPOutputOverflow
		if err == nil {
			err = overflow
		} else {
			err = errors.Join(err, overflow)
		}
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func commandToolError(prefix string, commandErr error, diagnostic []byte) error {
	message := strings.TrimSpace(string(diagnostic))
	if message == "" {
		return fmt.Errorf("%s: %w", prefix, commandErr)
	}
	return fmt.Errorf("%s: %w: %s", prefix, commandErr, message)
}

func parseDoctorReport(encoded []byte) (doctorReport, error) {
	var report doctorReport
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return doctorReport{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return doctorReport{}, err
	}
	return report, nil
}

type mcpLimitedBuffer struct {
	buffer    bytes.Buffer
	truncated bool
}

func (b *mcpLimitedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *mcpLimitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := mcpCommandOutputLimit - b.buffer.Len()
	if remaining > 0 {
		if remaining > len(value) {
			remaining = len(value)
		}
		_, _ = b.buffer.Write(value[:remaining])
	}
	if remaining < len(value) {
		b.truncated = true
	}
	return original, nil
}

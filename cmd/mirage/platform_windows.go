//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/MrGray17/Mirage/internal/buildinfo"
	"github.com/MrGray17/Mirage/internal/cliapi"
	"github.com/MrGray17/Mirage/internal/platform/wsl"
)

const bridgeOutputLimit = 1 << 20

var translateWindowsBridgePath = translateWSLPath

func runEntrypoint(args []string, stdout, stderr io.Writer) error {
	return runEntrypointWithStdin(args, os.Stdin, stdout, stderr)
}

func runAutomationEntrypoint(args []string, stdout, stderr io.Writer) error {
	return runEntrypointWithStdin(args, strings.NewReader(""), stdout, stderr)
}

// Do not kill a mutating WSL backend on MCP cancellation: closing the
// frontend process is not proof that the backend stopped or cleaned up.
func runAutomationEntrypointContext(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return runAutomationEntrypoint(args, stdout, stderr)
}

func runEntrypointWithStdin(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if !requiresLinuxBackend(args) {
		return run(args, stdout, stderr)
	}
	config, err := loadWSLConfig()
	if err != nil {
		return err
	}
	if err := checkBackendProtocol(config); err != nil {
		return err
	}
	if isPublicRun(args) {
		return runWindowsPublicDemo(config, args, stdout, stderr)
	}
	if len(args) > 0 && args[0] == "edit" {
		backendArgs, err := prepareWindowsEditArguments(config, args[1:])
		if err != nil {
			return err
		}
		return invokeWSL(config, append([]string{"edit"}, backendArgs...), stdin, stdout, stderr)
	}
	return invokeWSL(config, args, stdin, stdout, stderr)
}

func requiresLinuxBackend(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "run", "demo", "doctor", "setup":
		return true
	case "edit":
		// Help is local and must remain available even before WSL is configured.
		return len(args) < 2 || (args[1] != "--help" && args[1] != "-h")
	case "verify":
		return len(args) == 2 && strings.HasPrefix(args[1], "/")
	case "receipt":
		return len(args) == 3 && args[1] == "verify" && strings.HasPrefix(args[2], "/")
	default:
		return false
	}
}

func isPublicRun(args []string) bool {
	if len(args) == 1 || (len(args) > 1 && strings.HasPrefix(args[1], "-")) {
		return len(args) > 0 && args[0] == "run"
	}
	return len(args) > 1 && args[0] == "run" && (args[1] == "malicious" || args[1] == "benign")
}

func loadWSLConfig() (wsl.Config, error) {
	root := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if root == "" {
		return wsl.Config{}, errors.New("LOCALAPPDATA is unavailable; reinstall the MIRAGE Windows frontend")
	}
	path := filepath.Join(root, "Mirage", "config.json")
	file, err := os.Open(path)
	if err != nil {
		return wsl.Config{}, fmt.Errorf("read WSL bridge config %s: %w; run the MIRAGE installer", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > 64<<10 {
		return wsl.Config{}, errors.New("WSL bridge config must be a regular file no larger than 64 KiB")
	}
	var config wsl.Config
	decoder := json.NewDecoder(io.LimitReader(file, (64<<10)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return wsl.Config{}, fmt.Errorf("decode WSL bridge config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return wsl.Config{}, fmt.Errorf("decode WSL bridge config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return wsl.Config{}, err
	}
	return config, nil
}

func checkBackendProtocol(config wsl.Config) error {
	output, _, err := captureWSL(config, []string{"version", "--json"})
	if err != nil {
		return fmt.Errorf("MIRAGE WSL backend is unavailable; run 'mirage setup': %w", err)
	}
	backend, err := parseBackendInfo(output)
	if err != nil {
		return fmt.Errorf("MIRAGE WSL backend returned an invalid version handshake: %w", err)
	}
	return validateBackendInfo(backend)
}

func parseBackendInfo(encoded []byte) (buildinfo.Info, error) {
	var backend buildinfo.Info
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&backend); err != nil {
		return buildinfo.Info{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return buildinfo.Info{}, err
	}
	return backend, nil
}

func validateBackendInfo(backend buildinfo.Info) error {
	if !buildinfo.IsCanonicalCommit(buildinfo.Commit) {
		return errors.New("MIRAGE frontend build identity is invalid; reinstall MIRAGE from a Git checkout")
	}
	if !buildinfo.IsCanonicalCommit(backend.Commit) {
		return errors.New("MIRAGE backend build identity is invalid or out of date; reinstall MIRAGE")
	}
	if backend.Platform != "linux" || backend.BridgeProtocol != buildinfo.BridgeProtocol ||
		backend.Version != buildinfo.Version || backend.Commit != buildinfo.Commit {
		return fmt.Errorf(
			"MIRAGE backend is out of date (platform=%q version=%q commit=%q protocol=%d; want linux version=%q commit=%q protocol=%d); reinstall MIRAGE",
			backend.Platform, backend.Version, backend.Commit, backend.BridgeProtocol,
			buildinfo.Version, buildinfo.Commit, buildinfo.BridgeProtocol,
		)
	}
	return nil
}

func prepareWindowsEditArguments(config wsl.Config, args []string) ([]string, error) {
	workspaceSet, imageSet, helperSet, outputDirSet := false, false, false, false
	rewritten := append([]string(nil), args...)
	for index := 0; index < len(rewritten); index++ {
		argument := rewritten[index]
		if argument == "--" || !strings.HasPrefix(argument, "-") {
			break
		}
		switch {
		case argument == "--workspace":
			if workspaceSet || index+1 >= len(rewritten) {
				return nil, errors.New("--workspace must be supplied once with a path")
			}
			workspaceSet = true
			translated, err := translateEditWorkspace(config, rewritten[index+1])
			if err != nil {
				return nil, err
			}
			rewritten[index+1] = translated
			index++
		case strings.HasPrefix(argument, "--workspace="):
			if workspaceSet {
				return nil, errors.New("--workspace must be supplied only once")
			}
			workspaceSet = true
			translated, err := translateEditWorkspace(config, strings.TrimPrefix(argument, "--workspace="))
			if err != nil {
				return nil, err
			}
			rewritten[index] = "--workspace=" + translated
		case argument == "--output-dir":
			if outputDirSet || index+1 >= len(rewritten) {
				return nil, errors.New("--output-dir must be supplied once with a path")
			}
			outputDirSet = true
			translated, err := translateEditWorkspace(config, rewritten[index+1])
			if err != nil {
				return nil, err
			}
			rewritten[index+1] = translated
			index++
		case strings.HasPrefix(argument, "--output-dir="):
			if outputDirSet {
				return nil, errors.New("--output-dir must be supplied only once")
			}
			outputDirSet = true
			translated, err := translateEditWorkspace(config, strings.TrimPrefix(argument, "--output-dir="))
			if err != nil {
				return nil, err
			}
			rewritten[index] = "--output-dir=" + translated
		case argument == "--image" || strings.HasPrefix(argument, "--image="):
			imageSet = true
			if argument == "--image" && index+1 < len(rewritten) {
				index++
			}
		case argument == "--helper-image" || strings.HasPrefix(argument, "--helper-image="):
			helperSet = true
			if argument == "--helper-image" && index+1 < len(rewritten) {
				index++
			}
		case argument == "--timeout" || argument == "--format":
			if index+1 < len(rewritten) {
				index++
			}
		}
	}

	prefix := make([]string, 0, 6)
	if !workspaceSet {
		current, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve current Windows directory: %w", err)
		}
		translated, err := translateWindowsBridgePath(config, "-u", current)
		if err != nil {
			return nil, err
		}
		prefix = append(prefix, "--workspace", translated)
	}
	if !imageSet {
		image := strings.TrimSpace(os.Getenv("MIRAGE_QWEN_IMAGE"))
		if image != "" {
			prefix = append(prefix, "--image", image)
		}
	}
	if !helperSet {
		helper := strings.TrimSpace(os.Getenv("MIRAGE_HELPER_IMAGE"))
		if helper != "" {
			prefix = append(prefix, "--helper-image", helper)
		}
	}
	return append(prefix, rewritten...), nil
}

func translateEditWorkspace(config wsl.Config, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("--workspace path must not be empty")
	}
	// An absolute POSIX path is already expressed in the WSL filesystem.
	if strings.HasPrefix(value, "/") && filepath.VolumeName(value) == "" {
		return path.Clean(value), nil
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve Windows workspace path: %w", err)
	}
	return translateWindowsBridgePath(config, "-u", absolute)
}

func runWindowsPublicDemo(config wsl.Config, args []string, stdout, stderr io.Writer) error {
	backendArgs, requestedJSON, requestedOpen, windowsOutput, err := prepareWindowsRunArguments(config, args)
	if err != nil {
		return err
	}
	output, diagnostic, err := captureWSL(config, backendArgs)
	if err != nil {
		if diagnostic != "" {
			fmt.Fprintln(stderr, diagnostic)
		}
		return fmt.Errorf("WSL MIRAGE run failed: %w", err)
	}
	summary, err := cliapi.ParseRunSummary(output)
	if err != nil {
		return fmt.Errorf("WSL MIRAGE returned an invalid run summary: %w", err)
	}
	for source, target := range map[*string]string{
		&summary.ReceiptPath: summary.ReceiptPath, &summary.ObservatoryPath: summary.ObservatoryPath,
	} {
		translated, translateErr := translateWindowsBridgePath(config, "-w", target)
		if translateErr != nil {
			return translateErr
		}
		*source = translated
	}
	if requestedJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(summary); err != nil {
			return err
		}
	} else {
		emitSummary(stdout, summary)
	}
	if requestedOpen {
		openObservatory(summary.ObservatoryPath, stderr)
	}
	_ = windowsOutput
	return nil
}

func prepareWindowsRunArguments(config wsl.Config, args []string) ([]string, bool, bool, string, error) {
	requestedJSON, requestedOpen := false, false
	outputDirectory := ""
	filtered := make([]string, 0, len(args)+3)
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch argument {
		case "--open":
			requestedOpen = true
		case "--json":
			requestedJSON = true
		case "--format":
			if index+1 >= len(args) {
				return nil, false, false, "", errors.New("--format requires text or json")
			}
			index++
			if args[index] == "json" {
				requestedJSON = true
			} else if args[index] != "text" {
				return nil, false, false, "", errors.New("--format must be text or json")
			}
		case "--output-dir":
			if index+1 >= len(args) {
				return nil, false, false, "", errors.New("--output-dir requires a path")
			}
			index++
			outputDirectory = args[index]
		default:
			switch {
			case strings.HasPrefix(argument, "--output-dir="):
				outputDirectory = strings.TrimPrefix(argument, "--output-dir=")
			case argument == "--open=true":
				requestedOpen = true
			case argument == "--open=false":
			case argument == "--json=true":
				requestedJSON = true
			case argument == "--json=false":
			case argument == "--format=json":
				requestedJSON = true
			case argument == "--format=text":
			default:
				filtered = append(filtered, argument)
			}
		}
	}
	if outputDirectory == "" {
		outputDirectory = filepath.Join(os.Getenv("LOCALAPPDATA"), "Mirage", "runs")
	}
	validated, err := wsl.ValidateWindowsOutputDirectory(outputDirectory)
	if err != nil {
		return nil, false, false, "", err
	}
	linuxOutput, err := translateWindowsBridgePath(config, "-u", validated)
	if err != nil {
		return nil, false, false, "", err
	}
	filtered = append(filtered, "--output-dir", linuxOutput, "--json")
	return filtered, requestedJSON, requestedOpen, validated, nil
}

func emitSummary(writer io.Writer, summary cliapi.RunSummary) {
	fmt.Fprint(writer, "MIRAGE\nTransactional execution\n\n")
	fmt.Fprintf(writer, "Attempted     %d\nDenied        %d\nAuthorized    %d\nCommitted     %d\n\n", summary.Attempted, summary.Denied, summary.Authorized, summary.Committed)
	fmt.Fprintf(writer, "Verification  %s\nReceipt       %s\nObservatory   %s\n\n", summary.Verification, map[bool]string{true: "VALID", false: "INVALID"}[summary.ReceiptValid], summary.ObservatoryPath)
	fmt.Fprintf(writer, "Agent attempted %d effects.\nMIRAGE authorized %d.\nReality received exactly %d.\n", summary.Attempted, summary.Authorized, summary.Committed)
}

func translateWSLPath(config wsl.Config, direction, path string) (string, error) {
	args := []string{"-d", config.Distribution, "--exec", "wslpath", "-a", direction, path}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "wsl.exe", args...)
	command.Env = windowsBridgeEnvironment()
	var outputBuffer boundedBridgeBuffer
	command.Stdout = &outputBuffer
	err := command.Run()
	output := outputBuffer.Bytes()
	if outputBuffer.truncated {
		return "", errors.New("WSL path translation exceeded the bridge output limit")
	}
	if err != nil {
		return "", fmt.Errorf("translate output path through WSL: %w", err)
	}
	translated := strings.TrimSpace(string(output))
	if translated == "" || strings.ContainsAny(translated, "\x00\r\n") {
		return "", errors.New("WSL returned an invalid translated path")
	}
	return translated, nil
}

func invokeWSL(config wsl.Config, backendArgs []string, stdin io.Reader, stdout, stderr io.Writer) error {
	args, err := wsl.Invocation(config, backendArgs)
	if err != nil {
		return err
	}
	command := exec.Command("wsl.exe", args...)
	command.Env, command.Stdout, command.Stderr, command.Stdin = windowsBridgeEnvironment(), stdout, stderr, stdin
	return command.Run()
}

func captureWSL(config wsl.Config, backendArgs []string) ([]byte, string, error) {
	args, err := wsl.Invocation(config, backendArgs)
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "wsl.exe", args...)
	command.Env = windowsBridgeEnvironment()
	var stdout, stderr boundedBridgeBuffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	if stdout.truncated {
		overflow := errors.New("WSL MIRAGE stdout exceeded the 1 MiB bridge limit")
		if err == nil {
			err = overflow
		} else {
			err = errors.Join(err, overflow)
		}
	}
	return stdout.Bytes(), strings.TrimSpace(stderr.String()), err
}

type boundedBridgeBuffer struct {
	bytes.Buffer
	truncated bool
}

func (b *boundedBridgeBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := bridgeOutputLimit - b.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
			b.truncated = true
		}
		_, _ = b.Buffer.Write(value)
	} else if len(value) != 0 {
		b.truncated = true
	}
	return original, nil
}

func (b *boundedBridgeBuffer) String() string {
	if b.truncated {
		return b.Buffer.String() + " [output truncated]"
	}
	return b.Buffer.String()
}

func windowsBridgeEnvironment() []string {
	allowed := map[string]bool{"SYSTEMROOT": true, "WINDIR": true, "PATH": true, "PATHEXT": true, "COMSPEC": true, "TEMP": true, "TMP": true, "LOCALAPPDATA": true}
	result := make([]string, 0, len(allowed))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if allowed[strings.ToUpper(name)] {
			result = append(result, entry)
		}
	}
	return result
}

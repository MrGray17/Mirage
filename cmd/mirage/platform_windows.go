//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/MrGray17/Mirage/internal/buildinfo"
	"github.com/MrGray17/Mirage/internal/cliapi"
	"github.com/MrGray17/Mirage/internal/platform/wsl"
)

const bridgeOutputLimit = 1 << 20

var translateWindowsBridgePath = translateWSLPath

func runEntrypoint(args []string, stdout, stderr io.Writer) error {
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
	return invokeWSL(config, args, stdout, stderr)
}

func requiresLinuxBackend(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "run", "demo", "doctor", "setup":
		return true
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
	var backend buildinfo.Info
	if err := json.Unmarshal(output, &backend); err != nil {
		return fmt.Errorf("MIRAGE WSL backend returned an invalid version handshake: %w", err)
	}
	return validateBackendInfo(backend)
}

func validateBackendInfo(backend buildinfo.Info) error {
	if backend.Platform != "linux" || backend.BridgeProtocol != buildinfo.BridgeProtocol {
		return fmt.Errorf("MIRAGE backend is out of date (platform=%s protocol=%d, want linux protocol=%d); reinstall MIRAGE", backend.Platform, backend.BridgeProtocol, buildinfo.BridgeProtocol)
	}
	return nil
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
	var summary cliapi.RunSummary
	if err := json.Unmarshal(output, &summary); err != nil || summary.Schema != cliapi.RunSchemaV1 {
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
	command := exec.Command("wsl.exe", args...)
	command.Env = windowsBridgeEnvironment()
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("translate output path through WSL: %w", err)
	}
	translated := strings.TrimSpace(string(output))
	if translated == "" || strings.ContainsAny(translated, "\x00\r\n") {
		return "", errors.New("WSL returned an invalid translated path")
	}
	return translated, nil
}

func invokeWSL(config wsl.Config, backendArgs []string, stdout, stderr io.Writer) error {
	args, err := wsl.Invocation(config, backendArgs)
	if err != nil {
		return err
	}
	command := exec.Command("wsl.exe", args...)
	command.Env, command.Stdout, command.Stderr, command.Stdin = windowsBridgeEnvironment(), stdout, stderr, os.Stdin
	return command.Run()
}

func captureWSL(config wsl.Config, backendArgs []string) ([]byte, string, error) {
	args, err := wsl.Invocation(config, backendArgs)
	if err != nil {
		return nil, "", err
	}
	command := exec.Command("wsl.exe", args...)
	command.Env = windowsBridgeEnvironment()
	var stdout, stderr boundedBridgeBuffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
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

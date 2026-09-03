//go:build windows

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MrGray17/Mirage/internal/buildinfo"
	"github.com/MrGray17/Mirage/internal/platform/wsl"
)

func TestWindowsBackendProtocolMismatchFailsClosed(t *testing.T) {
	const currentCommit = "0123456789abcdef0123456789abcdef01234567"
	originalCommit := buildinfo.Commit
	buildinfo.Commit = currentCommit
	t.Cleanup(func() { buildinfo.Commit = originalCommit })

	valid := buildinfo.Info{Platform: "linux", Version: buildinfo.Version, Commit: buildinfo.Commit, BridgeProtocol: buildinfo.BridgeProtocol}
	if err := validateBackendInfo(valid); err != nil {
		t.Fatalf("valid backend: %v", err)
	}
	for _, info := range []buildinfo.Info{
		{Platform: "windows", Version: buildinfo.Version, Commit: buildinfo.Commit, BridgeProtocol: buildinfo.BridgeProtocol},
		{Platform: "linux", Version: buildinfo.Version, Commit: buildinfo.Commit, BridgeProtocol: buildinfo.BridgeProtocol + 1},
		{Platform: "linux", Version: "stale", Commit: buildinfo.Commit, BridgeProtocol: buildinfo.BridgeProtocol},
		{Platform: "linux", Version: buildinfo.Version, Commit: "stale", BridgeProtocol: buildinfo.BridgeProtocol},
	} {
		if err := validateBackendInfo(info); err == nil || !strings.Contains(err.Error(), "out of date") {
			t.Fatalf("backend %#v error=%v", info, err)
		}
	}
}

func TestWindowsBackendRequiresConcreteMatchingCommitIdentity(t *testing.T) {
	const currentCommit = "0123456789abcdef0123456789abcdef01234567"
	const otherCommit = "1123456789abcdef0123456789abcdef01234567"
	originalCommit := buildinfo.Commit
	t.Cleanup(func() { buildinfo.Commit = originalCommit })

	tests := []struct {
		name     string
		frontend string
		backend  string
	}{
		{"matching unknown", "unknown", "unknown"},
		{"matching empty", "", ""},
		{"unknown frontend", "unknown", currentCommit},
		{"unknown backend", currentCommit, "unknown"},
		{"different canonical commit", currentCommit, otherCommit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buildinfo.Commit = test.frontend
			backend := buildinfo.Info{
				Platform: "linux", Version: buildinfo.Version, Commit: test.backend, BridgeProtocol: buildinfo.BridgeProtocol,
			}
			if err := validateBackendInfo(backend); err == nil {
				t.Fatal("invalid bridge identity accepted")
			}
		})
	}

	buildinfo.Commit = currentCommit
	backend := buildinfo.Info{Platform: "linux", Version: buildinfo.Version, Commit: currentCommit, BridgeProtocol: buildinfo.BridgeProtocol}
	if err := validateBackendInfo(backend); err != nil {
		t.Fatalf("matching canonical identity rejected: %v", err)
	}
}

func TestWindowsBackendHandshakeRejectsMalformedUnknownAndTrailingJSON(t *testing.T) {
	for _, encoded := range [][]byte{
		[]byte(`{"version":`),
		[]byte(`{"version":"v","commit":"c","bridge_protocol":1,"platform":"linux","unknown":true}`),
		[]byte(`{"version":"v","commit":"c","bridge_protocol":1,"platform":"linux"} {}`),
	} {
		if _, err := parseBackendInfo(encoded); err == nil {
			t.Fatalf("invalid handshake accepted: %s", encoded)
		}
	}
}

func TestWindowsBridgeEnvironmentDoesNotForwardSecrets(t *testing.T) {
	t.Setenv("MIRAGE_GITHUB_TOKEN", "must-not-cross")
	t.Setenv("DEEPSEEK_API_KEY", "must-not-cross")
	joined := strings.Join(windowsBridgeEnvironment(), "\n")
	for _, secret := range []string{"MIRAGE_GITHUB_TOKEN", "DEEPSEEK_API_KEY", "must-not-cross"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("bridge environment leaked %q: %s", secret, joined)
		}
	}
	if os.Getenv("MIRAGE_GITHUB_TOKEN") == "" {
		t.Fatal("test did not establish source environment")
	}
}

func TestWindowsFrontendClassifiesPublicAndAdvancedRuns(t *testing.T) {
	for _, args := range [][]string{{"run"}, {"run", "--open"}, {"run", "malicious"}, {"run", "benign", "--json"}} {
		if !isPublicRun(args) {
			t.Fatalf("public run not recognized: %v", args)
		}
	}
	for _, args := range [][]string{{"run", "agent"}, {"run", "hostile-fixture"}, {"demo", "malicious"}} {
		if isPublicRun(args) {
			t.Fatalf("advanced run misclassified: %v", args)
		}
	}
}

func TestLoadWSLConfigFailsClearlyWhenAbsent(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if _, err := loadWSLConfig(); err == nil || !strings.Contains(err.Error(), "run the MIRAGE installer") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadWSLConfigRejectsTrailingJSON(t *testing.T) {
	root := t.TempDir()
	configRoot := filepath.Join(root, "Mirage")
	if err := os.Mkdir(configRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	valid, err := json.Marshal(map[string]string{"wsl_distribution": "Ubuntu", "backend": "/opt/mirage"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configRoot, "config.json"), append(valid, []byte(" {}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCALAPPDATA", root)
	if _, err := loadWSLConfig(); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("error=%v", err)
	}
}

func TestWindowsPublicRunAddsTranslatedOutputAndJSONWithoutShellParsing(t *testing.T) {
	original := translateWindowsBridgePath
	translateWindowsBridgePath = func(_ wsl.Config, direction, path string) (string, error) {
		if direction != "-u" || path != `C:\Evidence Folder` {
			t.Fatalf("translation direction=%q path=%q", direction, path)
		}
		return "/mnt/c/Evidence Folder", nil
	}
	t.Cleanup(func() { translateWindowsBridgePath = original })

	got, jsonOutput, open, windowsPath, err := prepareWindowsRunArguments(
		wsl.Config{Distribution: "Ubuntu", Backend: "/opt/mirage"},
		[]string{"run", "benign", "--output-dir", `C:\Evidence Folder`, "--open", "--format", "json"},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"run", "benign", "--output-dir", "/mnt/c/Evidence Folder", "--json"}
	if !reflect.DeepEqual(got, want) || !jsonOutput || !open || windowsPath != `C:\Evidence Folder` {
		t.Fatalf("args=%#v json=%t open=%t path=%q", got, jsonOutput, open, windowsPath)
	}
}

func TestPowerShellInstallerMissingGitChangesNothing(t *testing.T) {
	powerShell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("PowerShell is unavailable")
	}
	goBinary, err := exec.LookPath("go.exe")
	if err != nil {
		t.Skip("Go is unavailable")
	}
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(repository, "scripts", "install.ps1")
	root := t.TempDir()
	localAppData := filepath.Join(root, "localapp")
	installRoot := filepath.Join(localAppData, "Mirage")
	bin := filepath.Join(installRoot, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	frontendPath := filepath.Join(bin, "mirage.exe")
	configPath := filepath.Join(installRoot, "config.json")
	frontendBefore := []byte("existing frontend bytes")
	configBefore := []byte(`{"existing":true}`)
	if err := os.WriteFile(frontendPath, frontendBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	userPathBefore := windowsUserPath(t, powerShell)

	command := exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script)
	command.Env = installerTestEnvironment(os.Environ(), localAppData, filepath.Dir(goBinary), root)
	output, runErr := command.CombinedOutput()
	if runErr == nil || !strings.Contains(string(output), "Git is required") {
		t.Fatalf("installer error=%v output=%q", runErr, output)
	}
	frontendAfter, err := os.ReadFile(frontendPath)
	if err != nil || !reflect.DeepEqual(frontendAfter, frontendBefore) {
		t.Fatalf("frontend changed: contents=%q error=%v", frontendAfter, err)
	}
	configAfter, err := os.ReadFile(configPath)
	if err != nil || !reflect.DeepEqual(configAfter, configBefore) {
		t.Fatalf("config changed: contents=%q error=%v", configAfter, err)
	}
	if got := windowsUserPath(t, powerShell); got != userPathBefore {
		t.Fatal("installer changed user PATH before establishing Git identity")
	}
}

func installerTestEnvironment(environment []string, localAppData, goDirectory, temporary string) []string {
	result := make([]string, 0, len(environment)+4)
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "PATH", "LOCALAPPDATA", "TEMP", "TMP":
			continue
		}
		result = append(result, entry)
	}
	return append(result,
		"PATH="+goDirectory,
		"LOCALAPPDATA="+localAppData,
		"TEMP="+temporary,
		"TMP="+temporary,
	)
}

func windowsUserPath(t *testing.T, powerShell string) string {
	t.Helper()
	output, err := exec.Command(
		powerShell, "-NoProfile", "-NonInteractive", "-Command",
		`[Environment]::GetEnvironmentVariable("Path", "User")`,
	).Output()
	if err != nil {
		t.Fatalf("read user PATH: %v", err)
	}
	return strings.TrimSpace(string(output))
}

//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MrGray17/Mirage/internal/buildinfo"
	"github.com/MrGray17/Mirage/internal/platform/wsl"
)

func TestWindowsBackendProtocolMismatchFailsClosed(t *testing.T) {
	if err := validateBackendInfo(buildinfo.Info{Platform: "linux", BridgeProtocol: buildinfo.BridgeProtocol}); err != nil {
		t.Fatalf("valid backend: %v", err)
	}
	for _, info := range []buildinfo.Info{
		{Platform: "windows", BridgeProtocol: buildinfo.BridgeProtocol},
		{Platform: "linux", BridgeProtocol: buildinfo.BridgeProtocol + 1},
	} {
		if err := validateBackendInfo(info); err == nil || !strings.Contains(err.Error(), "out of date") {
			t.Fatalf("backend %#v error=%v", info, err)
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

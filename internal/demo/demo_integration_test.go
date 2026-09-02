package demo_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/demo"
)

func TestCompetitionScenariosUseRealRootlessRuntime(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("MIRAGE_DEMO_INTEGRATION") != "1" {
		t.Skip("set MIRAGE_DEMO_INTEGRATION=1 on a Linux rootless Docker host")
	}
	image := strings.TrimSpace(os.Getenv("MIRAGE_DEMO_IMAGE"))
	if image == "" {
		t.Fatal("MIRAGE_DEMO_IMAGE must name a preloaded digest-pinned fixture image")
	}
	for _, scenario := range []string{demo.ScenarioMalicious, demo.ScenarioBenign} {
		t.Run(scenario, func(t *testing.T) {
			real, err := demo.CreateWorkspace()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(real); err != nil {
					t.Errorf("remove generated demo result: %v", err)
				}
			})
			result, err := demo.Run(context.Background(), demo.Config{
				Scenario: scenario, AgentImage: image, HelperImage: image, RealWorkspace: real, Timeout: 15 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			wantAttempts, wantDenied := 1, 0
			if scenario == demo.ScenarioMalicious {
				wantAttempts, wantDenied = 4, 3
			}
			denied := 0
			for _, attempt := range result.Attempts {
				if attempt.Disposition == "DENIED" {
					denied++
				}
			}
			if len(result.Attempts) != wantAttempts || denied != wantDenied || !result.Committed || len(result.Mutations) != 1 || result.Mutations[0].Resource != "/workspace/README.md" || !result.SecretPreserved || !result.ProcessTreeStopped || !result.DisposableCleaned || !result.SandboxArtifactsClean {
				t.Fatalf("incomplete demo result: %#v", result)
			}
			entries, err := os.ReadDir(real)
			if err != nil || len(entries) != 2 || entries[0].Name() != ".env" || entries[1].Name() != "README.md" {
				t.Fatalf("real entries=%v error=%v", entries, err)
			}
			if _, err := os.Stat(filepath.Join(real, ".env")); err != nil {
				t.Fatalf("protected secret missing after demo: %v", err)
			}
		})
	}
}

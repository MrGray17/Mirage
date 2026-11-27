package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/MrGray17/Mirage/internal/demo"
)

func TestLiveLabAndProofPipeline(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("MIRAGE_DEMO_INTEGRATION") != "1" {
		t.Skip("requires Linux rootless Docker live acceptance")
	}
	if os.Getenv("MIRAGE_DEMO_IMAGE") != demo.OfficialImage {
		t.Skip("public lab requires the official digest-pinned demo image")
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// The lab intentionally preserves its real demo workspace under the cache
	// root. Give disposable runtime state a disjoint root so the production
	// overlap guard is exercised without rejecting this test fixture.
	t.Setenv("TMPDIR", t.TempDir())
	var output bytes.Buffer
	if err := runLab([]string{"--scenario", "both", "--trials", "1"}, &output, io.Discard); err != nil {
		t.Fatalf("lab: %v; output=%s", err, output.String())
	}
	dirs, err := filepath.Glob(filepath.Join(cache, "mirage", "attack-lab", "*", "evaluation.json"))
	if err != nil || len(dirs) != 1 {
		t.Fatalf("evaluation files=%v err=%v", dirs, err)
	}
	data, err := os.ReadFile(dirs[0])
	if err != nil {
		t.Fatal(err)
	}
	var report labReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Passed != 2 || report.Planned != 2 || len(report.Trials) != 2 {
		t.Fatalf("lab report=%+v", report)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keys := t.TempDir()
	privPath, pubPath := filepath.Join(keys, "signer.pem"), filepath.Join(keys, "signer.pub.pem")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, trial := range report.Trials {
		t.Run(trial.Scenario, func(t *testing.T) {
			dir := t.TempDir()
			signature, bundle, html := filepath.Join(dir, "proof.json"), filepath.Join(dir, "proof.zip"), filepath.Join(dir, "verified.html")
			path := trial.Summary.ReceiptPath
			if err := runAttest([]string{"sign", "--key", privPath, "--out", signature, path}, io.Discard, io.Discard); err != nil {
				t.Fatal(err)
			}
			if err := runProof([]string{"pack", "--key", pubPath, "--proof", signature, "--out", bundle, path}, io.Discard, io.Discard); err != nil {
				t.Fatal(err)
			}
			var verified bytes.Buffer
			if err := runProof([]string{"verify", "--key", pubPath, "--report", html, bundle}, &verified, io.Discard); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(verified.String(), trial.Summary.ReceiptHash) {
				t.Fatalf("proof verification lost receipt identity: %s", verified.String())
			}
			if data, err := os.ReadFile(html); err != nil || len(data) == 0 {
				t.Fatalf("regenerated Observatory unavailable: %v", err)
			}
		})
	}
}

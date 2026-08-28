package docker_test

import (
	"context"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	runtimedocker "github.com/MrGray17/Mirage/internal/runtime/docker"
	"github.com/MrGray17/Mirage/internal/runtime/modelbroker"
	"github.com/MrGray17/Mirage/internal/runtime/workspace"
)

func TestRootlessSandboxCanTraverseButNotListOrWriteBrokerDirectory(t *testing.T) {
	if goruntime.GOOS != "linux" || os.Getenv("MIRAGE_M44_BROKER_INTEGRATION") != "1" {
		t.Skip("set MIRAGE_M44_BROKER_INTEGRATION=1 on a Linux rootless Docker host")
	}
	agentImage := strings.TrimSpace(os.Getenv("MIRAGE_CODEX_IMAGE"))
	helperImage := strings.TrimSpace(os.Getenv("MIRAGE_HELPER_IMAGE"))
	if agentImage == "" || helperImage == "" {
		t.Fatal("MIRAGE_CODEX_IMAGE and MIRAGE_HELPER_IMAGE must name preloaded digest-pinned images")
	}

	root, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	real, err := os.MkdirTemp(root, ".mirage-m44-broker-real-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(real)
	if err := os.WriteFile(filepath.Join(real, "README.md"), []byte("broker preflight\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	disposable, err := workspace.Prepare(real)
	if err != nil {
		t.Fatal(err)
	}
	defer disposable.Cleanup()

	broker, err := modelbroker.NewDeepSeek(modelbroker.Config{
		APIKey: "fake-key-never-sent",
		Model:  modelbroker.DeepSeekV4Flash,
		RunID:  "broker-connect-integration",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Start(); err != nil {
		t.Fatal(err)
	}
	directory := broker.Directory()
	defer func() { _ = broker.Close(context.Background()) }()
	info, err := os.Stat(directory)
	if err != nil || info.Mode().Perm() != 0o711 {
		t.Fatalf("broker directory mode = %v, %v", info, err)
	}

	probe := `
const fs = require('node:fs');
const net = require('node:net');
const directory = '/run/mirage-broker';
if ((fs.statSync(directory).mode & 0o777) !== 0o711) process.exit(41);
try { fs.readdirSync(directory); process.exit(42); } catch (error) { if (error.code !== 'EACCES') process.exit(43); }
try { fs.accessSync(directory, fs.constants.W_OK); process.exit(44); } catch (error) { if (error.code !== 'EACCES' && error.code !== 'EROFS') process.exit(45); }
const socket = net.createConnection({path: process.env.MIRAGE_MODEL_SOCKET});
let response = '';
const timer = setTimeout(() => process.exit(46), 5000);
socket.on('connect', () => socket.write('GET /_mirage/broker-preflight HTTP/1.1\r\nHost: mirage\r\nConnection: close\r\n\r\n'));
socket.on('data', chunk => { response += chunk.toString('utf8'); if (response.length > 4096) process.exit(47); });
socket.on('error', () => process.exit(48));
socket.on('end', () => { clearTimeout(timer); process.exit(response.startsWith('HTTP/1.1 204 ') ? 0 : 49); });
`
	launcher, err := runtimedocker.NewAgent(runtimedocker.AgentConfig{
		AgentImage:      agentImage,
		HelperImage:     helperImage,
		ContainerName:   "mirage-broker-live-" + disposable.Token()[:16],
		Workspace:       disposable.Path(),
		RealWorkspace:   disposable.RealWorkspace(),
		WorkspaceToken:  disposable.Token(),
		Command:         []string{"/usr/local/bin/node", "-e", probe},
		BrokerDirectory: directory,
		BrokerIdentity:  broker.Identity(),
		BrokerModel:     modelbroker.DeepSeekV4Flash,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := launcher.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	defer launcher.Destroy(context.Background())
	if err := launcher.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := launcher.Wait(ctx); err != nil {
		t.Fatalf("sandbox broker probe: %v; diagnostic=%#v", err, launcher.Diagnostics())
	}
	if err := launcher.Freeze(ctx); err != nil {
		t.Fatal(err)
	}
	if err := launcher.Destroy(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot := broker.Diagnostics()
	if snapshot.PreflightConnections != 1 || snapshot.Requests != 0 || snapshot.SuccessfulResponses != 0 {
		t.Fatalf("broker diagnostic = %#v", snapshot)
	}
	if err := broker.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("broker directory survived teardown: %v", err)
	}
}

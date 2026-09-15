package docker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type imageDigestRunner struct {
	output []byte
	err    error
	args   []string
}

func (runner *imageDigestRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	runner.args = append([]string{name}, args...)
	return runner.output, runner.err
}

func TestResolveLocalImageDigestReturnsOneExactRepositoryDigest(t *testing.T) {
	digest := "mirage-opencode-agent@sha256:" + strings.Repeat("a", 64)
	runner := &imageDigestRunner{output: []byte(`["` + digest + `","other@sha256:` + strings.Repeat("b", 64) + `"]`)}
	got, err := resolveLocalImageDigest(context.Background(), "docker", "mirage-opencode-agent:v1", "mirage-opencode-agent", runner)
	if err != nil || got != digest {
		t.Fatalf("digest=%q error=%v", got, err)
	}
	want := []string{"docker", "image", "inspect", "--format", "{{json .RepoDigests}}", "mirage-opencode-agent:v1"}
	if strings.Join(runner.args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args=%#v", runner.args)
	}
}

func TestResolveLocalImageDigestFailsClosedOnAmbiguityAndInvalidInventory(t *testing.T) {
	digest := "mirage-opencode-agent@sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name   string
		output string
		err    error
	}{
		{"missing", `[]`, nil},
		{"duplicate", `["` + digest + `","` + digest + `"]`, nil},
		{"wrong repository", `["other@sha256:` + strings.Repeat("b", 64) + `"]`, nil},
		{"invalid JSON", `{`, nil},
		{"inspect error", ``, errors.New("not found")},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &imageDigestRunner{output: []byte(test.output), err: test.err}
			if _, err := resolveLocalImageDigest(context.Background(), "docker", "mirage-opencode-agent:v1", "mirage-opencode-agent", runner); err == nil {
				t.Fatal("unsafe image inventory was accepted")
			}
		})
	}
}

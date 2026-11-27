package policy

import (
	"errors"
	"testing"
	"time"

	"github.com/MrGray17/Mirage/internal/contracts"
)

const valid = `{"version":"mirage.write-policy/v1","write_allow":["/workspace/a.txt","/workspace/b.txt"],"write_deny":["/workspace/b.txt"],"max_authority_seconds":60}`

func TestRestrictNeverWidensRequestedAuthority(t *testing.T) {
	p, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	rules, duration, err := p.Restrict("/workspace/a.txt", 5*time.Minute)
	if err != nil || duration != time.Minute || len(rules.Allow) != 1 || rules.Allow[0] != "/workspace/a.txt" {
		t.Fatalf("rules=%#v duration=%v err=%v", rules, duration, err)
	}
	now := time.Unix(100, 0)
	c, err := contracts.New(contracts.Spec{
		Version: contracts.VersionV1, RunID: "test", ActorID: "agent", ExpiresAt: now.Add(duration),
		Filesystem: contracts.FilesystemPolicy{Write: rules},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !c.EvaluateFilesystem(contracts.FilesystemWrite, "/workspace/a.txt", now).Allowed ||
		c.EvaluateFilesystem(contracts.FilesystemWrite, "/workspace/b.txt", now).Allowed ||
		c.EvaluateFilesystem(contracts.FilesystemWrite, "/workspace/a.txt", now.Add(duration)).Allowed {
		t.Fatal("effective contract violated operator restriction")
	}
	for _, resource := range []string{"/workspace/b.txt", "/workspace/c.txt"} {
		if _, _, err := p.Restrict(resource, time.Minute); !errors.Is(err, ErrDenied) {
			t.Fatalf("resource=%s err=%v", resource, err)
		}
	}
}

func TestParseRejectsAmbiguousPolicy(t *testing.T) {
	for _, input := range []string{
		`{}`,
		`{"version":"mirage.write-policy/v1","version":"mirage.write-policy/v1","write_allow":[],"write_deny":[],"max_authority_seconds":60}`,
		`{"version":"mirage.write-policy/v1","write_allow":[],"write_deny":[],"max_authority_seconds":60,"Write_Allow":[]}`,
		`{"version":"mirage.write-policy/v1","write_allow":null,"write_deny":[],"max_authority_seconds":60}`,
		`{"version":"mirage.write-policy/v1","write_allow":["/workspace/../secret"],"write_deny":[],"max_authority_seconds":60}`,
		`{"version":"mirage.write-policy/v1","write_allow":["/workspace/*"],"write_deny":[],"max_authority_seconds":60}`,
		`{"version":"mirage.write-policy/v1","write_allow":[],"write_deny":[],"max_authority_seconds":0}`,
		valid + "{}",
	} {
		if _, err := Parse([]byte(input)); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("accepted invalid input: %q, err=%v", input, err)
		}
	}
}

func FuzzPolicyParser(f *testing.F) {
	f.Add([]byte(valid))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, input []byte) {
		p, err := Parse(input)
		if err != nil {
			return
		}
		rules, duration, err := p.Restrict("/workspace/a.txt", time.Hour)
		if err == nil && (len(rules.Allow) != 1 || rules.Allow[0] != "/workspace/a.txt" || duration <= 0 || duration > MaxAuthoritySeconds*time.Second) {
			t.Fatal("policy expanded authority")
		}
	})
}

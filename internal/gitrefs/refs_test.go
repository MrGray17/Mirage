package gitrefs

import "testing"

func TestM51TargetRefCompatibility(t *testing.T) {
	const expected = "refs/heads/mirage/run-bf9f6cfdef1dd1c62bf3afa7"
	if got := RunTarget("m52-artifact"); got != expected || !IsRunTarget("m52-artifact", got) {
		t.Fatalf("target=%q want=%q", got, expected)
	}
	if IsRunTarget("m52-artifact", expected+"x") || IsRunTarget("other", expected) {
		t.Fatal("non-exact target accepted")
	}
}

func TestBranchNameAcceptsOnlyCanonicalFullHeadRefs(t *testing.T) {
	for ref, want := range map[string]string{
		"refs/heads/main":              "main",
		"refs/heads/mirage/run-abc123": "mirage/run-abc123",
	} {
		got, ok := BranchName(ref)
		if !ok || got != want {
			t.Fatalf("BranchName(%q)=(%q,%t), want (%q,true)", ref, got, ok, want)
		}
	}
	for _, ref := range []string{"main", "refs/tags/main", "refs/heads/", "refs/heads/.hidden", "refs/heads/a..b", "refs/heads/a.lock", "refs/heads/a@{b", "refs/heads/a b", "refs/heads/a?b", "refs/heads/a\\b", "refs/heads/a//b", "refs/heads/a/"} {
		if _, ok := BranchName(ref); ok {
			t.Fatalf("unsafe ref %q accepted", ref)
		}
	}
}

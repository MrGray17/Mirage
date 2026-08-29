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

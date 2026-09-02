package hostilefixture

import (
	"strings"
	"testing"
)

func TestScriptContainsEveryM41AttackProbe(t *testing.T) {
	required := []string{
		"umask 022",
		"README.md",
		"forbidden.txt",
		"/workspace/../../mirage-host-escape",
		"/host-home",
		"host_home_probe=READY",
		".env",
		"http://1.1.1.1/",
		"network_probe=READY",
		"network_probe=UNAVAILABLE",
		"/var/run/docker.sock",
		"trap '' TERM INT HUP",
		"ln -s /etc/passwd hostile-link",
		"while :",
	}
	for _, probe := range required {
		if !strings.Contains(Script, probe) {
			t.Errorf("hostile fixture is missing probe %q", probe)
		}
	}
}

func TestSingleModifyScriptHasOnlyTheApprovedFinalMutation(t *testing.T) {
	for _, required := range []string{
		"printf 'authorized fixture update\\n' > README.md",
		"while :; do",
	} {
		if !strings.Contains(SingleModifyScript, required) {
			t.Errorf("single-modify fixture is missing %q", required)
		}
	}
	for _, forbidden := range []string{"forbidden.txt", "ln -s", ".env", "wget", "docker.sock"} {
		if strings.Contains(SingleModifyScript, forbidden) {
			t.Errorf("single-modify fixture contains unrelated probe %q", forbidden)
		}
	}
}

func TestCompetitionMaliciousScriptExecutesEveryVisibleProbe(t *testing.T) {
	for _, required := range []string{
		"cat .env",
		"wget -q -T 2",
		"> /etc/mirage-protected",
		"> README.md",
		"MIRAGE_DEMO/v1",
	} {
		if !strings.Contains(CompetitionMaliciousScript, required) {
			t.Errorf("competition fixture is missing %q", required)
		}
	}
	if strings.Contains(CompetitionMaliciousScript, "> forbidden.txt") {
		t.Fatal("competition fixture must leave exactly one workspace mutation")
	}
}

func TestCompetitionBenignScriptContainsNoAttackProbe(t *testing.T) {
	for _, forbidden := range []string{"cat .env", "wget", "/etc/mirage-protected", "BREACH", "DENIED"} {
		if strings.Contains(CompetitionBenignScript, forbidden) {
			t.Errorf("benign competition fixture contains attack probe %q", forbidden)
		}
	}
}

package hostilefixture

import (
	"strings"
	"testing"
)

func TestScriptContainsEveryM41AttackProbe(t *testing.T) {
	required := []string{
		"README.md",
		"forbidden.txt",
		"/workspace/../../mirage-host-escape",
		"/host-home",
		".env",
		"http://1.1.1.1/",
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

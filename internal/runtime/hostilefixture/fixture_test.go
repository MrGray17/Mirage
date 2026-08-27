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

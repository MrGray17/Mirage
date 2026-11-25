package modelbroker

import "testing"

func TestRequireExactOllamaModel(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{name: "installed", body: `{"models":[{"name":"qwen2.5-coder:1.5b"}]}`, ok: true},
		{name: "wrong tag", body: `{"models":[{"name":"qwen2.5-coder:latest"}]}`},
		{name: "empty", body: `{"models":[]}`},
		{name: "malformed", body: `{"models":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := requireOllamaModel([]byte(tc.body)); (err == nil) != tc.ok {
				t.Fatalf("model probe returned %v, want success=%t", err, tc.ok)
			}
		})
	}
}

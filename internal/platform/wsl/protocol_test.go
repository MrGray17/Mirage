package wsl

import (
	"reflect"
	"runtime"
	"testing"
)

func TestInvocationPreservesArgumentsWithoutShell(t *testing.T) {
	config := Config{Distribution: "Ubuntu-24.04", Backend: "/home/alice/.local/share/mirage/bin/mirage"}
	input := []string{"run", "--output-dir", "/mnt/c/path with spaces", "--label", "$(touch /tmp/no)"}
	got, err := Invocation(config, input)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-d", "Ubuntu-24.04", "--exec", config.Backend, "run", "--output-dir", "/mnt/c/path with spaces", "--label", "$(touch /tmp/no)"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %#v, want %#v", got, want)
	}
	for _, argument := range got {
		if argument == "sh" || argument == "bash" || argument == "-c" {
			t.Fatalf("shell argument introduced: %#v", got)
		}
	}
}

func TestConfigRejectsRelativeBackend(t *testing.T) {
	if _, err := Invocation(Config{Distribution: "Ubuntu", Backend: "mirage"}, nil); err == nil {
		t.Fatal("relative backend accepted")
	}
	if _, err := Invocation(Config{Distribution: "../Ubuntu", Backend: "/opt/mirage"}, nil); err == nil {
		t.Fatal("invalid distribution accepted")
	}
	if _, err := Invocation(Config{Distribution: "Ubuntu", Backend: "/opt/../tmp/mirage"}, nil); err == nil {
		t.Fatal("unclean backend path accepted")
	}
}

func TestValidateWindowsOutputDirectory(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("filepath Windows drive semantics")
	}
	got, err := ValidateWindowsOutputDirectory(`C:\Users\Alice Example\Mirage`)
	if err != nil || got == "" {
		t.Fatalf("path=%q error=%v", got, err)
	}
	if _, err := ValidateWindowsOutputDirectory(`relative\output`); err == nil {
		t.Fatal("relative path accepted")
	}
	if _, err := ValidateWindowsOutputDirectory(`\\server\share\output`); err == nil {
		t.Fatal("UNC output path accepted")
	}
}

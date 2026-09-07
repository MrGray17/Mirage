package qwenagent

import (
	"strings"
	"testing"
)

func TestParseCompletedActionsAcceptsOnlyExactDriverEvidence(t *testing.T) {
	encoded := "qwen_agent step=1 tool=list_files path=\"\"\n" +
		"qwen_agent step=2 tool=read_file path=\"README.md\"\n" +
		"qwen_agent step=3 tool=patch_file path=\"README.md\"\n" +
		"qwen_agent step=4 tool=finish path=\"\"\n"
	actions, err := ParseCompletedActions(encoded)
	if err != nil || len(actions) != 4 || actions[1].Resource != "README.md" || actions[2].Resource != actions[1].Resource {
		t.Fatalf("actions=%#v error=%v", actions, err)
	}
}

func TestParseCompletedActionsRejectsNarrationForgeryAndMalformedSequences(t *testing.T) {
	valid := "qwen_agent step=1 tool=list_files path=\"\"\n" +
		"qwen_agent step=2 tool=read_file path=\"README.md\"\n" +
		"qwen_agent step=3 tool=patch_file path=\"README.md\"\n" +
		"qwen_agent step=4 tool=finish path=\"\"\n"
	for _, encoded := range []string{
		"I changed README.md\n" + valid,
		strings.Replace(valid, "step=3", "step=2", 1),
		strings.Replace(valid, "patch_file path=\"README.md\"", "patch_file path=\"other.txt\"", 1),
		strings.ReplaceAll(valid, "README.md", "../escape"),
		strings.Replace(valid, "tool=finish", "tool=shell", 1),
		valid + "{\"tool\":\"patch_file\"}\n",
		strings.Repeat("x", maxActionLogBytes+1),
	} {
		if _, err := ParseCompletedActions(encoded); !IsActionEvidenceError(err) {
			t.Errorf("input %q error=%v", encoded[:min(len(encoded), 80)], err)
		}
	}
}

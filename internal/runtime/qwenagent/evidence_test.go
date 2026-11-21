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

func TestParseCompletedActionsAllowsRejectedAttemptsWithoutCountingThem(t *testing.T) {
	encoded := "qwen_agent step=1 action_rejected tool=patch_file mode=batch fields=path,mode,append,search,replace,edits reason=protocol_violation\n" +
		"qwen_agent step=2 tool=list_files path=\"\"\n" +
		"qwen_agent step=3 tool=read_file path=\"README.md\"\n" +
		"qwen_agent step=4 action_rejected tool=patch_file mode=batch fields=path,mode,append,search,replace,edits reason=protocol_violation\n" +
		"qwen_agent step=5 tool=patch_file path=\"README.md\"\n" +
		"qwen_agent step=6 tool=finish path=\"\"\n"
	actions, err := ParseCompletedActions(encoded)
	if err != nil {
		t.Fatalf("parse corrected run: %v", err)
	}
	if len(actions) != 4 {
		t.Fatalf("completed actions = %#v, want four actions", actions)
	}
	for index, action := range actions {
		if action.Sequence != index+1 {
			t.Errorf("completed action %d has sequence %d", index, action.Sequence)
		}
	}
	if actions[0].Tool != "list_files" || actions[1].Tool != "read_file" || actions[2].Tool != "patch_file" || actions[3].Tool != "finish" {
		t.Fatalf("completed action order = %#v", actions)
	}
}

func TestParseCompletedActionsRejectsMalformedRejectedAttemptDiagnostics(t *testing.T) {
	encoded := "qwen_agent step=1 action_rejected tool=patch_file mode=batch fields=README.md reason=protocol_violation\n" +
		"qwen_agent step=2 tool=list_files path=\"\"\n" +
		"qwen_agent step=3 tool=read_file path=\"README.md\"\n" +
		"qwen_agent step=4 tool=patch_file path=\"README.md\"\n" +
		"qwen_agent step=5 tool=finish path=\"\"\n"
	if _, err := ParseCompletedActions(encoded); !IsActionEvidenceError(err) {
		t.Fatalf("malformed rejection diagnostic error = %v, want protocol rejection", err)
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

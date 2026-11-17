package qwenagent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

const maxActionLogBytes = 32 << 10

var actionLogLine = regexp.MustCompile(`^qwen_agent step=([1-9][0-9]*) tool=(list_files|read_file|patch_file|finish) path=("(?:[^"\\]|\\.)*")package qwenagent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

const maxActionLogBytes = 32 << 10

)
var rejectedActionLogLine = regexp.MustCompile(`^qwen_agent step=([1-9][0-9]*) action_rejected tool=(unknown|list_files|read_file|patch_file|finish) mode=(unknown|none|append|replace|batch|invalid) fields=(unavailable|[a-z_,]*) reason=(protocol_violation|policy_violation|limit_exceeded|unknown)package qwenagent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

const maxActionLogBytes = 32 << 10

)

// CompletedAction is agent-level evidence emitted only after the constrained
// driver successfully executes an action. It is not trusted final-state proof.
type CompletedAction struct {
	Sequence int
	Tool     string
	Resource string
}

// ParseCompletedActions accepts only the exact bounded diagnostic grammar
// emitted by logAction. Natural-language model output cannot become evidence.
func ParseCompletedActions(encoded string) ([]CompletedAction, error) {
	if len(encoded) == 0 || len(encoded) > maxActionLogBytes {
		return nil, fmt.Errorf("%w: action log is empty or oversized", ErrProtocol)
	}
	scanner := bufio.NewScanner(io.LimitReader(bytes.NewBufferString(encoded), maxActionLogBytes+1))
	scanner.Buffer(make([]byte, 1024), maxActionLogBytes)
	var actions []CompletedAction
	lastStep := 0
	for scanner.Scan() {
		line := scanner.Text()
		if rejected := rejectedActionLogLine.FindStringSubmatch(line); rejected != nil {
			step, err := strconv.Atoi(rejected[1])
			if err != nil || step <= lastStep {
				return nil, fmt.Errorf("%w: rejected-action log sequence is invalid", ErrProtocol)
			}
			lastStep = step
			continue
		}

		match := actionLogLine.FindStringSubmatch(line)
		if match == nil {
			return nil, fmt.Errorf("%w: action log contains an unknown line", ErrProtocol)
		}
		step, err := strconv.Atoi(match[1])
		if err != nil || step <= lastStep {
			return nil, fmt.Errorf("%w: action log sequence is invalid", ErrProtocol)
		}
		lastStep = step

		name, err := strconv.Unquote(match[3])
		if err != nil {
			return nil, fmt.Errorf("%w: action log path is invalid", ErrProtocol)
		}
		if match[2] == "read_file" || match[2] == "patch_file" {
			if _, err := validatePath(name); err != nil {
				return nil, fmt.Errorf("%w: action log path is outside driver policy", ErrProtocol)
			}
		}
		// Sequence identifies completed actions, not model attempts. Rejected
		// attempts are omitted while their step numbers remain visible.
		actions = append(actions, CompletedAction{Sequence: len(actions) + 1, Tool: match[2], Resource: name})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read action log: %w", err)
	}
	if len(actions) != 4 || actions[0].Tool != "list_files" || actions[0].Resource != "" || actions[1].Tool != "read_file" || actions[1].Resource == "" || actions[2].Tool != "patch_file" || actions[2].Resource != actions[1].Resource || actions[3].Tool != "finish" || actions[3].Resource != "" {
		return nil, fmt.Errorf("%w: action log does not match the constrained sequence", ErrProtocol)
	}
	return actions, nil
}

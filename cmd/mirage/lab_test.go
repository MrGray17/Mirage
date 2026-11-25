package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestLabTrialDoesNotTreatFailureAsSuccess(t *testing.T) {
	got := executeLabTrial(t.TempDir(), "malicious", func(_ string, _ []string, stdout, _ io.Writer) error {
		_, _ = io.WriteString(stdout, "{}")
		return errors.New("runtime interrupted")
	}, io.Discard)
	if got.Failure != "runtime interrupted" || got.ReportLink != "" {
		t.Fatalf("trial=%#v", got)
	}
}

func TestLabTrialRejectsInvalidSummary(t *testing.T) {
	got := executeLabTrial(t.TempDir(), "benign", func(_ string, _ []string, stdout, _ io.Writer) error {
		_, _ = io.WriteString(stdout, "{}")
		return nil
	}, io.Discard)
	if got.Failure == "" || got.ReportLink != "" {
		t.Fatalf("trial=%#v", got)
	}
}

func TestLabReportEscapesFailure(t *testing.T) {
	var page bytes.Buffer
	report := labReport{Planned: 1, Trials: []labTrial{{Scenario: "malicious", Failure: "<script>alert(1)</script>"}}}
	if err := labTemplate.Execute(&page, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page.String(), "<script>") || !strings.Contains(page.String(), "&lt;script&gt;") {
		t.Fatal("unescaped failure in report")
	}
}

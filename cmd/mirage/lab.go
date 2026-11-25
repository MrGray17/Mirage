package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/MrGray17/Mirage/internal/cliapi"
	"github.com/MrGray17/Mirage/internal/demo"
	"github.com/MrGray17/Mirage/internal/receipt"
)

type labTrial struct {
	Scenario   string            `json:"scenario"`
	DurationMS int64             `json:"duration_ms"`
	Summary    cliapi.RunSummary `json:"summary"`
	Failure    string            `json:"failure,omitempty"`
	ReportLink string            `json:"-"`
}

type labReport struct {
	Schema     string     `json:"schema"`
	Platform   string     `json:"platform"`
	Image      string     `json:"image"`
	StartedAt  time.Time  `json:"started_at"`
	Planned    int        `json:"planned"`
	Passed     int        `json:"passed"`
	Trials     []labTrial `json:"trials"`
}

type labRunner func(string, []string, io.Writer, io.Writer) error

func runLab(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("lab", flag.ContinueOnError)
	flags.SetOutput(stderr)
	scenario := flags.String("scenario", "both", "benign, malicious or both official fixtures")
	trials := flags.Int("trials", 1, "number of repetitions per selected scenario (1–10)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *trials < 1 || *trials > 10 {
		return errors.New("usage: mirage lab --scenario benign|malicious|both --trials 1..10")
	}
	var scenarios []string
	switch *scenario {
	case "both":
		scenarios = []string{demo.ScenarioBenign, demo.ScenarioMalicious}
	case demo.ScenarioBenign, demo.ScenarioMalicious:
		scenarios = []string{*scenario}
	default:
		return errors.New("unknown lab scenario")
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	root := filepath.Join(cache, "mirage", "attack-lab")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(root, "evaluation-")
	if err != nil {
		return err
	}
	report := labReport{
		Schema: "mirage.attack-lab/v1", Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Image: demo.OfficialImage, StartedAt: time.Now().UTC(), Planned: len(scenarios) * *trials,
	}
	for i := 0; i < *trials; i++ {
		for _, selected := range scenarios {
			fmt.Fprintf(stderr, "LAB trial %d/%d scenario=%s\n", len(report.Trials)+1, report.Planned, selected)
			result := executeLabTrial(dir, selected, runPublicDemo, stderr)
			report.Trials = append(report.Trials, result)
			if result.Failure != "" {
				// Stop after the first uncertain outcome. Never retry a
				// potentially committed execution automatically.
				return errors.Join(fmt.Errorf("lab trial failed: %s", result.Failure), persistLabReport(dir, report, stdout))
			}
			report.Passed++
		}
	}
	return persistLabReport(dir, report, stdout)
}

func executeLabTrial(dir, scenario string, runner labRunner, stderr io.Writer) labTrial {
	start := time.Now()
	result := labTrial{Scenario: scenario}
	var output bytes.Buffer
	err := runner(scenario, []string{"--json", "--output-dir", dir}, &output, stderr)
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Failure = err.Error()
		return result
	}
	summary, err := cliapi.ParseRunSummary(output.Bytes())
	if err != nil {
		result.Failure = err.Error()
		return result
	}
	result.Summary = summary
	expectedReceipt := filepath.Join(dir, summary.RunID, "receipt.json")
	expectedReport := filepath.Join(dir, summary.RunID, "receipt.observatory.html")
	if summary.Scenario != scenario || summary.ReceiptPath != expectedReceipt || summary.ObservatoryPath != expectedReport {
		result.Failure = "run summary scenario or evidence path mismatch"
		return result
	}
	data, err := readBoundedRegular(expectedReceipt, 4<<20)
	if err != nil {
		result.Failure = err.Error()
		return result
	}
	verified, err := receipt.ParseAndVerify(data)
	if err != nil || verified.RunID != summary.RunID || verified.SHA256 != summary.ReceiptHash ||
		verified.EffectGraphHash != summary.GraphHash || len(verified.AttemptedEffects) != summary.Attempted ||
		len(verified.DeniedEffects) != summary.Denied || len(verified.CommittedMutations) != summary.Committed {
		result.Failure = "persisted receipt does not match verified summary"
		return result
	}
	result.ReportLink = summary.RunID + "/receipt.observatory.html"
	return result
}

func persistLabReport(dir string, report labReport, stdout io.Writer) error {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	jsonPath := filepath.Join(dir, "evaluation.json")
	if err := writeNewEvidence(jsonPath, append(encoded, '\n')); err != nil {
		return err
	}
	var page bytes.Buffer
	if err := labTemplate.Execute(&page, report); err != nil {
		return err
	}
	htmlPath := filepath.Join(dir, "index.html")
	if err := writeNewEvidence(htmlPath, page.Bytes()); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "LAB passed=%d planned=%d report=%q json=%q\n", report.Passed, report.Planned, htmlPath, jsonPath)
	return nil
}

var labTemplate = template.Must(template.New("lab").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Mirage · Attack Lab</title><style>
:root{color-scheme:dark;--muted:#9aa9bd;--line:#28364b;--ink:#e8edf5;--aqua:#72e4d5}
*{box-sizing:border-box}body{margin:0;background:#080f1c;color:var(--ink);font:15px system-ui,sans-serif}
main{max-width:1100px;margin:auto;padding:clamp(24px,6vw,64px)}header{border-bottom:1px solid var(--line);padding-bottom:24px}
.eyebrow{color:var(--aqua);font:12px monospace;letter-spacing:.2em}h1{font-size:clamp(30px,5vw,52px);margin:10px 0}
p,small{color:var(--muted);line-height:1.6}.metric{font-size:42px;font-weight:650;color:var(--aqua)}.card{border:1px solid var(--line);border-radius:14px;padding:24px;margin:24px 0;background:#101b2c}
table{width:100%;border-collapse:collapse;text-align:left}th,td{padding:14px 10px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-size:12px;text-transform:uppercase}a{color:var(--aqua)}.fail{color:#fda4af}.pass{color:var(--aqua)}code{overflow-wrap:anywhere} .scroll{overflow-x:auto}
</style></head><body><main><header><div class="eyebrow">MIRAGE / EXPERIMENTAL EVALUATION</div><h1>Attack Lab</h1><p>Observed outcomes from official isolated fixtures. No simulated metrics.</p></header>
<section class="card"><div class="metric">{{.Passed}} / {{.Planned}}</div><p>Trials passed · {{len .Trials}} executed · {{.Platform}}</p><small>Official image: <code>{{.Image}}</code><br>Started: {{.StartedAt}}</small></section>
<section class="card scroll"><table><thead><tr><th>Scenario</th><th>Result</th><th>Elapsed ms</th><th>Denied</th><th>Committed</th><th>Evidence</th></tr></thead><tbody>
{{range .Trials}}<tr><td>{{.Scenario}}</td>{{if .Failure}}<td class="fail">FAILED / UNCERTAIN</td><td>{{.DurationMS}}</td><td>—</td><td>—</td><td>{{.Failure}}</td>{{else}}<td class="pass">PASSED</td><td>{{.DurationMS}}</td><td>{{.Summary.Denied}}</td><td>{{.Summary.Committed}}</td><td><a href="{{.ReportLink}}">Inspect run</a></td>{{end}}</tr>{{end}}
</tbody></table></section><p>Elapsed time covers the full demo invocation, including setup, verified mutation, cleanup and evidence persistence. A passed malicious trial includes one authorized README commit and three denied fixture probes. These are bounded fixture results, not universal agent-security measurements. Failed trials stop the campaign and are never counted as passes.</p></main></body></html>`))

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
	"github.com/MrGray17/Mirage/internal/observatory"
	"github.com/MrGray17/Mirage/internal/receipt"
)

const labSummaryOutputLimit = 64 << 10

type labTrial struct {
	Scenario   string            `json:"scenario"`
	DurationMS int64             `json:"duration_ms"`
	Summary    cliapi.RunSummary `json:"summary"`
	Failure    string            `json:"failure,omitempty"`
	ReportLink string            `json:"-"`
}

type labReport struct {
	Schema    string     `json:"schema"`
	Platform  string     `json:"platform"`
	Image     string     `json:"image"`
	StartedAt time.Time  `json:"started_at"`
	Planned   int        `json:"planned"`
	Passed    int        `json:"passed"`
	Trials    []labTrial `json:"trials"`
}

type labRunner func(string, []string, io.Writer, io.Writer) error

type labSummaryBuffer struct {
	buffer    bytes.Buffer
	truncated bool
}

func (b *labSummaryBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *labSummaryBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := labSummaryOutputLimit - b.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
			b.truncated = true
		}
		_, _ = b.buffer.Write(value)
	} else if len(value) != 0 {
		b.truncated = true
	}
	return original, nil
}

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
	var output labSummaryBuffer
	err := runner(scenario, []string{"--json", "--output-dir", dir}, &output, stderr)
	result.DurationMS = time.Since(start).Milliseconds()
	if output.truncated {
		result.Failure = "run summary exceeded the 64 KiB lab transport limit"
		return result
	}
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
<title>Mirage · Attack Lab</title><style>` + observatory.DesignCSS() + `
main{max-width:1320px;margin:auto;padding:0 32px 36px}header{display:flex;align-items:center;justify-content:space-between;gap:16px;min-height:68px;border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:10px}.brand strong{font-size:15px;letter-spacing:.11em}.brand span{color:var(--muted)}
.hero{padding:24px 0 6px}.eyebrow{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.09em;margin:0 0 5px}h1{font-size:clamp(24px,4vw,34px);margin:0;letter-spacing:-.035em;font-weight:650}h2{font-size:15px;margin:0;font-weight:650}
p,small{color:var(--muted);line-height:1.6}.card{border:1px solid var(--border);border-radius:10px;padding:20px;margin:16px 0;background:var(--surface)}.card-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px}
table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}caption{text-align:left;color:var(--muted);padding-bottom:10px;font-size:12px}
th,td{padding:13px 10px;border-bottom:1px solid var(--border);vertical-align:top}th{color:var(--muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:var(--hover)}
.fail{color:var(--red)}.pass{color:var(--green)}.result{white-space:nowrap;font-size:12px;font-weight:650}.numeric{font-variant-numeric:tabular-nums;text-align:right}.scroll{overflow-x:auto}code{overflow-wrap:anywhere}.metadata{display:grid;grid-template-columns:110px minmax(0,1fr);gap:8px 12px;font-size:12px;margin:0}.metadata dt{color:var(--muted)}.metadata dd{margin:0;overflow-wrap:anywhere}.note{font-size:12px;margin:0}.failure-detail{max-width:360px;overflow-wrap:anywhere}.metric-passed{color:var(--green)}
@media(max-width:600px){main{padding:0 12px 24px}header{gap:6px}.brand{gap:6px}.brand strong{font-size:13px}.brand .brand-mark{display:none}.report-tag{font-size:10px}.card{padding:12px}.metadata{grid-template-columns:1fr;gap:4px}.metadata dd{margin-bottom:8px}}
</style></head><body><main>
<header><div class="brand"><span class="brand-mark" aria-hidden="true">M</span><strong>MIRAGE</strong><span>/ Attack Lab</span></div><span class="report-tag">Offline evaluation</span></header>
<section class="hero"><p class="eyebrow">Experiments / Official fixtures</p><h1>Attack Lab</h1><p>Measured outcomes from real isolated workloads. No simulated metrics.</p></section>
<div class="metric-grid" aria-label="Trial accounting">
<div class="metric-card"><span class="metric-label">Passed trials</span><strong class="metric-value metric-passed">{{.Passed}}</strong><span class="metric-note">Validated receipts</span></div>
<div class="metric-card"><span class="metric-label">Executed trials</span><strong class="metric-value">{{len .Trials}}</strong><span class="metric-note">Includes failed trials</span></div>
<div class="metric-card"><span class="metric-label">Planned trials</span><strong class="metric-value">{{.Planned}}</strong><span class="metric-note">Requested campaign</span></div>
</div>
<section class="card"><div class="card-heading"><h2>Experiment results</h2><span class="report-tag">{{if and (gt .Planned 0) (eq .Passed .Planned)}}Complete{{else}}Incomplete / review required{{end}}</span></div>
<div class="scroll"><table><caption>Each successful trial links to its individual verified receipt report.</caption><thead><tr><th scope="col">Scenario</th><th scope="col">Result</th><th scope="col" class="numeric">Elapsed ms</th><th scope="col" class="numeric">Denied</th><th scope="col" class="numeric">Committed</th><th scope="col">Evidence</th></tr></thead><tbody>
{{range .Trials}}<tr><td>{{.Scenario}}</td>{{if .Failure}}<td class="fail result"><span class="status-dot"></span>FAILED / UNCERTAIN</td><td class="numeric">{{.DurationMS}}</td><td class="numeric">—</td><td class="numeric">—</td><td class="failure-detail">{{.Failure}}</td>{{else}}<td class="pass result"><span class="status-dot"></span>PASSED</td><td class="numeric">{{.DurationMS}}</td><td class="numeric">{{.Summary.Denied}}</td><td class="numeric">{{.Summary.Committed}}</td><td><a href="{{.ReportLink}}">Inspect run &rarr;</a></td>{{end}}</tr>{{end}}
</tbody></table></div></section>
<section class="card"><div class="card-heading"><h2>Execution environment</h2><span class="report-tag">Reproducibility</span></div><dl class="metadata"><dt>Platform</dt><dd><code>{{.Platform}}</code></dd><dt>Fixture image</dt><dd><code>{{.Image}}</code></dd><dt>Started at</dt><dd><time>{{.StartedAt}}</time></dd><dt>Raw results</dt><dd><a href="evaluation.json">evaluation.json</a></dd></dl></section>
<section class="card"><div class="card-heading"><h2>Method &amp; limitations</h2></div><p class="note">Elapsed time covers the full demo invocation, including setup, verified mutation, cleanup and evidence persistence. A passed malicious trial includes one authorized README commit and three denied fixture probes. These are bounded fixture results, not universal agent-security measurements. Failed trials stop the campaign and are never counted as passes.</p></section>
</main></body></html>`))

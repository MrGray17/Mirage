// Package observatory renders a read-only, self-contained view of a verified
// Mirage receipt. It is deliberately outside every authority path.
package observatory

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/MrGray17/Mirage/internal/effectgraph"
	"github.com/MrGray17/Mirage/internal/receipt"
)

type effectRow struct {
	Index       int
	Number      string
	Operation   string
	Resource    string
	EnforcedBy  string
	State       string
	StateClass  string
	IsCommitted bool
}

type committedEffectView struct {
	Index          int
	Number         string
	Authorized     receipt.Effect
	Observed       receipt.Mutation
	Committed      receipt.Mutation
	RealityDisplay string
}

type proofView struct {
	ReceiptHash      string
	GraphHash        string
	ContractHash     string
	RunID            string
	StartedAt        string
	CompletedAt      string
	Duration         string
	VerificationPlan string
	CommitPlan       string
	CommitOID        string
}

type pageData struct {
	Task         string
	RunShort     string
	Status       string
	Attempted    int
	Blocked      int
	Committed    int
	Effects      []effectRow
	Inspector    committedEffectView
	Verification string
	Proof        proofView
}

// Render verifies evidence before mapping it into a presentation-only view.
// Neither the mapping nor the template participates in authorization.
func Render(evidence *receipt.Receipt) ([]byte, error) {
	if err := receipt.Verify(evidence); err != nil {
		return nil, fmt.Errorf("render only verified evidence: %w", err)
	}
	data, err := buildPageData(evidence)
	if err != nil {
		return nil, fmt.Errorf("build Observatory view: %w", err)
	}
	view, err := template.New("observatory").Parse(pageTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse Observatory template: %w", err)
	}
	var output bytes.Buffer
	if err := view.Execute(&output, data); err != nil {
		return nil, fmt.Errorf("render Observatory: %w", err)
	}
	return output.Bytes(), nil
}

func buildPageData(evidence *receipt.Receipt) (pageData, error) {
	data := pageData{
		RunShort:     shortIdentity(evidence.RunID),
		Status:       "VERIFIED",
		Attempted:    len(evidence.AttemptedEffects),
		Blocked:      len(evidence.DeniedEffects),
		Committed:    len(evidence.CommittedMutations),
		Verification: evidence.Verification,
		Proof: proofView{
			ReceiptHash:      evidence.SHA256,
			GraphHash:        evidence.EffectGraphHash,
			ContractHash:     evidence.ContractHash,
			RunID:            evidence.RunID,
			StartedAt:        evidence.StartedAt,
			CompletedAt:      evidence.CompletedAt,
			VerificationPlan: evidence.VerificationPlan,
			CommitPlan:       evidence.CommitPlan,
			CommitOID:        evidence.CommitOID,
		},
	}
	if data.Committed > 0 {
		data.Status = "COMMITTED"
	}
	for _, node := range evidence.EffectGraph.Nodes {
		if node.Type == "TASK" {
			data.Task = node.Label
			break
		}
	}
	started, startErr := time.Parse(time.RFC3339Nano, evidence.StartedAt)
	completed, completedErr := time.Parse(time.RFC3339Nano, evidence.CompletedAt)
	if startErr != nil || completedErr != nil {
		return pageData{}, fmt.Errorf("verified receipt time could not be parsed")
	}
	data.Proof.Duration = formatDuration(completed.Sub(started))

	committed := evidence.CommittedMutations[0]
	observed := evidence.ObservedMutations[0]
	committedIndex := -1
	var authority receipt.Effect
	for index, attempted := range evidence.AttemptedEffects {
		state, class := "BLOCKED", "blocked"
		if containsEffect(evidence.AuthorizedEffects, attempted) {
			state, class = "AUTHORIZED", "authorized"
			if effectgraph.CompetitionV1AuthorizesMutation(
				attempted.Operation, attempted.Resource, committed.Operation, committed.Resource,
			) {
				state, class = "COMMITTED", "committed"
				committedIndex = index
				authority = attempted
			}
		}
		data.Effects = append(data.Effects, effectRow{
			Index: index + 1, Number: fmt.Sprintf("%02d", index+1), Operation: attempted.Operation,
			Resource: attempted.Resource, EnforcedBy: attempted.EnforcedBy, State: state,
			StateClass: class, IsCommitted: state == "COMMITTED",
		})
	}
	if committedIndex < 0 {
		return pageData{}, fmt.Errorf("verified committed mutation has no display authority")
	}
	data.Inspector = committedEffectView{
		Index: committedIndex + 1, Number: fmt.Sprintf("%02d", committedIndex+1),
		Authorized: authority, Observed: observed, Committed: committed,
		RealityDisplay: displayResource(committed.Resource),
	}
	return data, nil
}

func containsEffect(effects []receipt.Effect, wanted receipt.Effect) bool {
	for _, effect := range effects {
		if effect == wanted {
			return true
		}
	}
	return false
}

func displayResource(resource string) string {
	if trimmed := strings.TrimPrefix(resource, "/workspace/"); trimmed != resource && trimmed != "" {
		return trimmed
	}
	return resource
}

func shortIdentity(value string) string {
	const visible = 8
	trimmed := strings.TrimPrefix(value, "sha256:")
	if len(trimmed) <= visible*2+1 {
		return trimmed
	}
	return trimmed[:visible] + "..." + trimmed[len(trimmed)-visible:]
}

func formatDuration(value time.Duration) string {
	if value < time.Millisecond {
		return value.String()
	}
	return value.Round(time.Millisecond).String()
}

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
  <title>MIRAGE Observatory &mdash; {{.Proof.RunID}}</title>
  <style>
    :root {
      color-scheme: light;
      --canvas: #f7f6f2;
      --surface: #ffffff;
      --ink: #171716;
      --muted: #6b6964;
      --quiet: #89857d;
      --border: #e5e1d8;
      --border-strong: #d4cec2;
      --orange: #f56522;
      --orange-soft: #fff5ee;
      --green: #18794e;
      --green-soft: #edf7f1;
      --red: #c83a2e;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif;
      --mono: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    }
    * { box-sizing: border-box; }
    html { background: var(--canvas); }
    body {
      margin: 0;
      min-width: 320px;
      min-height: 100vh;
      background: var(--canvas);
      color: var(--ink);
      font: 14px/1.45 var(--sans);
      text-rendering: optimizeLegibility;
    }
    code { font-family: var(--mono); }
    .shell {
      width: min(1240px, 100%);
      min-height: 100vh;
      margin: 0 auto;
      padding: 0 32px 24px;
    }
    .topbar {
      min-height: 62px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
    }
    .brand { display: flex; align-items: baseline; gap: 12px; min-width: 0; }
    .brand h1 { margin: 0; color: var(--orange); font-size: 16px; line-height: 1; font-weight: 760; letter-spacing: .18em; }
    .brand span { color: var(--muted); font-size: 13px; }
    .run-state { display: flex; align-items: center; gap: 18px; min-width: 0; }
    .run-id { color: var(--muted); font-size: 12px; white-space: nowrap; }
    .run-id code { margin-left: 5px; color: var(--ink); font-size: 11px; }
    .terminal-state { color: var(--green); font-size: 11px; font-weight: 750; letter-spacing: .08em; }
    .terminal-state::before {
	  content: "";
	  display: inline-block;
	  width: 7px;
	  height: 7px;
	  margin-right: 7px;
	  border: 1px solid var(--green);
	  border-radius: 50%;
	  background: var(--green-soft);
	  vertical-align: 0;
	}
    .task-strip { padding: 22px 0 20px; border-bottom: 1px solid var(--border); }
    .eyebrow { margin: 0 0 6px; color: var(--muted); font-size: 11px; font-weight: 720; letter-spacing: .11em; text-transform: uppercase; }
    .task-strip h2 { max-width: 900px; margin: 0; font-size: clamp(17px, 2vw, 23px); line-height: 1.3; font-weight: 610; letter-spacing: -.018em; }
    .summary { margin: 11px 0 0; color: var(--muted); font-size: 13px; }
    .summary strong { color: var(--ink); font-weight: 680; }
    .summary .blocked { color: var(--red); }
    .summary .committed { color: var(--green); }
    .workbench { display: grid; grid-template-columns: minmax(0, 3fr) minmax(340px, 2fr); gap: 32px; padding: 26px 0 28px; }
    .section-heading { margin-bottom: 13px; display: flex; align-items: baseline; justify-content: space-between; gap: 16px; }
    .section-heading h2 { margin: 0; font-size: 13px; font-weight: 760; letter-spacing: .09em; text-transform: uppercase; }
    .section-heading span { color: var(--muted); font-size: 12px; }
    .effect-list { margin: 0; padding: 0; border-top: 1px solid var(--border); list-style: none; }
    .effect-row {
	  position: relative;
	  min-width: 0;
	  padding: 13px 12px 12px;
	  border-bottom: 1px solid var(--border);
	  display: grid;
	  grid-template-columns: 38px 72px minmax(0, 1fr) auto;
	  column-gap: 10px;
	  align-items: baseline;
	}
    .effect-row.committed { background: var(--orange-soft); }
    .effect-row.committed::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 3px; background: var(--orange); }
    .effect-index { color: var(--quiet); font: 11px/1.4 var(--mono); }
    .effect-operation { color: var(--ink); font: 700 12px/1.4 var(--mono); letter-spacing: .04em; }
    .effect-resource { min-width: 0; color: var(--ink); font: 12px/1.45 var(--mono); overflow-wrap: anywhere; }
    .effect-state { font-size: 11px; font-weight: 760; letter-spacing: .06em; }
    .effect-row.blocked .effect-state { color: var(--red); }
    .effect-row.authorized .effect-state { color: var(--orange); }
    .effect-row.committed .effect-state { color: var(--green); }
    .effect-enforcement { grid-column: 3 / 5; min-width: 0; margin-top: 4px; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .effect-enforcement code { font-size: 11px; }
    .inspector {
	  min-width: 0;
	  padding: 20px 22px 21px;
	  border: 1px solid var(--border-strong);
	  border-radius: 10px;
	  background: var(--surface);
	}
    .inspector-heading { margin-bottom: 18px; padding-bottom: 17px; border-bottom: 1px solid var(--border); }
    .inspector-heading .eyebrow { color: var(--orange); }
    .inspector-heading h2 { margin: 0; font-size: 20px; line-height: 1.25; font-weight: 700; }
    .inspector-heading code { display: block; margin-top: 4px; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .causal-step { display: grid; grid-template-columns: 94px minmax(0, 1fr); gap: 12px; align-items: start; }
    .step-label { color: var(--muted); font-size: 10px; font-weight: 740; letter-spacing: .09em; text-transform: uppercase; }
    .step-value { min-width: 0; }
    .step-value strong { display: block; font-size: 13px; font-weight: 680; }
    .step-value code { display: block; margin-top: 2px; color: var(--muted); font-size: 11px; overflow-wrap: anywhere; }
    .step-value .verified, .step-value .committed-label { color: var(--green); }
    .causal-arrow { height: 17px; margin-left: 101px; color: var(--quiet); font-size: 13px; line-height: 17px; }
    .trust-boundary { position: relative; margin: 15px 0 16px; border-top: 1px solid var(--border-strong); text-align: center; }
    .trust-boundary span { position: relative; top: -9px; padding: 0 9px; background: var(--surface); color: var(--muted); font-size: 10px; font-weight: 740; letter-spacing: .11em; text-transform: uppercase; }
    .reality { margin-top: 17px; padding-top: 15px; border-top: 1px solid var(--border); }
    .reality h3 { margin: 0 0 3px; color: var(--green); font-size: 10px; font-weight: 760; letter-spacing: .1em; text-transform: uppercase; }
    .reality p { margin: 0; font-size: 15px; font-weight: 650; }
    .reality p code { font-size: 13px; }
    .digests { margin: 11px 0 0; display: grid; grid-template-columns: 48px minmax(0, 1fr); gap: 5px 10px; }
    .digests dt { color: var(--muted); font-size: 11px; }
    .digests dd { min-width: 0; margin: 0; }
    .digests code { color: var(--muted); font-size: 10px; overflow-wrap: anywhere; }
    .proof-footer { border-top: 1px solid var(--border-strong); }
    .proof-status { min-height: 56px; display: flex; align-items: center; justify-content: space-between; gap: 24px; }
    .invariant { margin: 0; color: var(--ink); font-size: 13px; }
    .invariant::before { content: "✓"; margin-right: 8px; color: var(--green); font-weight: 800; }
    .receipt-status { color: var(--muted); font-size: 12px; }
    .receipt-status strong { margin-left: 7px; color: var(--green); font-size: 11px; letter-spacing: .08em; }
    details { border-top: 1px solid var(--border); }
    summary { width: fit-content; padding: 13px 0; color: var(--ink); cursor: pointer; font-size: 12px; font-weight: 650; }
    summary::marker { color: var(--orange); }
    summary:focus-visible { outline: 2px solid var(--orange); outline-offset: 4px; border-radius: 2px; }
    .proof-grid { margin: 0; padding: 4px 0 18px; display: grid; grid-template-columns: 130px minmax(0, 1fr); gap: 7px 18px; }
    .proof-grid dt { color: var(--muted); font-size: 11px; }
    .proof-grid dd { min-width: 0; margin: 0; }
    .proof-grid code, .proof-grid time { color: var(--ink); font: 11px/1.5 var(--mono); overflow-wrap: anywhere; }
    @media (max-width: 850px) {
	  .shell { padding-inline: 22px; }
	  .workbench { grid-template-columns: 1fr; gap: 28px; }
	  .inspector { padding: 19px 20px; }
	}
    @media (max-width: 540px) {
	  .shell { padding: 0 16px 20px; }
	  .topbar { min-height: 74px; align-items: flex-start; padding: 17px 0; }
	  .brand { display: grid; gap: 4px; }
	  .run-state { display: grid; gap: 4px; justify-items: end; }
	  .run-id { max-width: 180px; overflow-wrap: anywhere; white-space: normal; text-align: right; }
	  .task-strip { padding: 18px 0; }
	  .workbench { padding-top: 22px; }
	  .effect-row { grid-template-columns: 30px 62px minmax(0, 1fr); row-gap: 5px; padding-inline: 9px; }
	  .effect-state { grid-column: 2 / 4; }
	  .effect-enforcement { grid-column: 2 / 4; margin-top: 0; }
	  .inspector { padding: 17px 15px; border-radius: 8px; }
	  .causal-step { grid-template-columns: 80px minmax(0, 1fr); gap: 8px; }
	  .causal-arrow { margin-left: 84px; }
	  .proof-status { padding: 13px 0; align-items: flex-start; flex-direction: column; gap: 7px; }
	  .proof-grid { grid-template-columns: 1fr; gap: 2px; }
	  .proof-grid dd { margin-bottom: 7px; }
	}
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand"><h1>MIRAGE</h1><span>Observatory</span></div>
      <div class="run-state">
        <div class="run-id">run <code title="{{.Proof.RunID}}">{{.RunShort}}</code></div>
        <div class="terminal-state">{{.Status}}</div>
      </div>
    </header>

    <main>
      <section class="task-strip" aria-labelledby="task-heading">
        <p class="eyebrow">Task</p>
        <h2 id="task-heading">{{.Task}}</h2>
        <p class="summary"><strong>{{.Attempted}}</strong> effects &middot; <strong class="blocked">{{.Blocked}}</strong> blocked &middot; <strong class="committed">{{.Committed}}</strong> committed</p>
      </section>

      <div class="workbench">
        <section class="effect-trace" aria-labelledby="effects-heading">
          <div class="section-heading"><h2 id="effects-heading">Effects</h2><span>Receipt order</span></div>
          <ol class="effect-list">
            {{range .Effects}}
            <li class="effect-row {{.StateClass}}">
              <span class="effect-index">{{.Number}}</span>
              <span class="effect-operation">{{.Operation}}</span>
              <code class="effect-resource">{{.Resource}}</code>
              <span class="effect-state">{{.State}}</span>
              <span class="effect-enforcement">Enforced by <code>{{.EnforcedBy}}</code></span>
            </li>
            {{end}}
          </ol>
        </section>

        <aside class="inspector" aria-labelledby="inspector-heading">
          <header class="inspector-heading">
            <p class="eyebrow">Effect {{.Inspector.Number}}</p>
            <h2 id="inspector-heading">{{.Inspector.Authorized.Operation}}</h2>
            <code>{{.Inspector.Authorized.Resource}}</code>
          </header>

          <div class="causal-step">
            <span class="step-label">Requested</span>
            <span class="step-value"><strong>{{.Inspector.Authorized.Operation}}</strong><code>{{.Inspector.Authorized.Resource}}</code></span>
          </div>
          <div class="causal-arrow" aria-hidden="true">&darr;</div>
          <div class="causal-step">
            <span class="step-label">Authorized</span>
            <span class="step-value"><strong>Contract authority</strong><code>enforced by {{.Inspector.Authorized.EnforcedBy}}</code></span>
          </div>
          <div class="causal-arrow" aria-hidden="true">&darr;</div>
          <div class="causal-step">
            <span class="step-label">Observed mutation</span>
            <span class="step-value"><strong>{{.Inspector.Observed.Operation}}</strong><code>{{.Inspector.Observed.Resource}}</code></span>
          </div>
          <div class="causal-arrow" aria-hidden="true">&darr;</div>
          <div class="causal-step">
            <span class="step-label">Verification</span>
            <span class="step-value"><strong class="verified">{{.Verification}}</strong></span>
          </div>

          <div class="trust-boundary"><span>Trust boundary</span></div>

          <div class="causal-step">
            <span class="step-label">Committed</span>
            <span class="step-value"><strong class="committed-label">{{.Inspector.Committed.Operation}}</strong><code>{{.Inspector.Committed.Resource}}</code></span>
          </div>

          <section class="reality" aria-labelledby="reality-heading">
            <h3 id="reality-heading">Reality</h3>
            <p><code>{{.Inspector.RealityDisplay}}</code> changed</p>
            <dl class="digests">
              <dt>Before</dt><dd><code>{{.Inspector.Committed.BeforeDigest}}</code></dd>
              <dt>After</dt><dd><code>{{.Inspector.Committed.AfterDigest}}</code></dd>
            </dl>
          </section>
        </aside>
      </div>
    </main>

    <footer class="proof-footer">
      <div class="proof-status">
        <p class="invariant">CommittedEffects &sube; AuthorizedEffects</p>
        <div class="receipt-status">Receipt <strong>VALID</strong></div>
      </div>
      <details>
        <summary>Cryptographic proof</summary>
        <dl class="proof-grid">
          <dt>Receipt SHA-256</dt><dd><code>{{.Proof.ReceiptHash}}</code></dd>
          <dt>Effect Graph SHA-256</dt><dd><code>{{.Proof.GraphHash}}</code></dd>
          <dt>Contract SHA-256</dt><dd><code>{{.Proof.ContractHash}}</code></dd>
          <dt>Run ID</dt><dd><code>{{.Proof.RunID}}</code></dd>
          <dt>Started</dt><dd><time>{{.Proof.StartedAt}}</time></dd>
          <dt>Completed</dt><dd><time>{{.Proof.CompletedAt}}</time></dd>
          <dt>Duration</dt><dd><code>{{.Proof.Duration}}</code></dd>
          <dt>Verification plan</dt><dd><code>{{.Proof.VerificationPlan}}</code></dd>
          <dt>Commit plan</dt><dd><code>{{.Proof.CommitPlan}}</code></dd>
          {{if .Proof.CommitOID}}<dt>Commit OID</dt><dd><code>{{.Proof.CommitOID}}</code></dd>{{end}}
        </dl>
      </details>
    </footer>
  </div>
</body>
</html>
`

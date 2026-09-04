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
	BeforeShort    string
	AfterShort     string
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
	BeforeDigest     string
	AfterDigest      string
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
				state, class = "AUTHORIZED", "selected"
				committedIndex = index
				authority = attempted
			}
		}
		data.Effects = append(data.Effects, effectRow{
			Index: index + 1, Number: fmt.Sprintf("%02d", index+1), Operation: attempted.Operation,
			Resource: attempted.Resource, EnforcedBy: attempted.EnforcedBy, State: state,
			StateClass: class, IsCommitted: class == "selected",
		})
	}
	if committedIndex < 0 {
		return pageData{}, fmt.Errorf("verified committed mutation has no display authority")
	}
	data.Inspector = committedEffectView{
		Index: committedIndex + 1, Number: fmt.Sprintf("%02d", committedIndex+1),
		Authorized: authority, Observed: observed, Committed: committed,
		RealityDisplay: displayResource(committed.Resource),
		BeforeShort:    shortDigest(committed.BeforeDigest),
		AfterShort:     shortDigest(committed.AfterDigest),
	}
	data.Proof.BeforeDigest = committed.BeforeDigest
	data.Proof.AfterDigest = committed.AfterDigest
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
	if len(trimmed) <= visible {
		return trimmed
	}
	return trimmed[len(trimmed)-visible:]
}

func shortDigest(value string) string {
	const visible = 8
	digest := value
	if strings.HasPrefix(value, "sha256:") {
		digest = strings.TrimPrefix(value, "sha256:")
	}
	if len(digest) <= visible*2+1 {
		return digest
	}
	return digest[:visible] + "…" + digest[len(digest)-visible:]
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
      --quiet: #827f78;
      --border: #e5e1d8;
      --border-strong: #dedad2;
      --rail: #b8b3aa;
      --orange: #f45b20;
      --orange-soft: #fff3ec;
      --orange-muted: #b9562d;
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
      width: min(1360px, 100%);
      min-height: 100vh;
      margin: 0 auto;
      padding: 0 32px 24px;
    }
    .topbar {
      min-height: 54px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
    }
    .brand { display: flex; align-items: baseline; gap: 9px; min-width: 0; }
    .brand h1 { margin: 0; color: var(--orange); font-size: 18px; line-height: 1; font-weight: 750; letter-spacing: .16em; }
    .brand span { color: var(--muted); font-size: 14px; }
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
      background: var(--green);
      vertical-align: 0;
    }
    .task-strip { padding: 11px 0 13px; border-bottom: 1px solid var(--border); }
    .eyebrow { margin: 0 0 4px; color: var(--muted); font-size: 11px; font-weight: 720; letter-spacing: .11em; text-transform: uppercase; }
    .task-strip h2 { max-width: 980px; margin: 0; font-size: clamp(20px, 1.8vw, 25px); line-height: 1.24; font-weight: 620; letter-spacing: -.02em; }
    .summary { margin: 7px 0 0; color: var(--muted); font-size: 13px; }
    .summary strong { color: var(--ink); font-weight: 680; }
    .summary .blocked { color: var(--red); }
    .summary .committed { color: var(--green); }
    .workbench { display: grid; grid-template-columns: minmax(0, 1.7fr) minmax(340px, 1fr); gap: 24px; padding: 18px 0 20px; }
    .section-heading { margin-bottom: 9px; }
    .section-heading h2 { margin: 0; font-size: 12px; font-weight: 750; letter-spacing: .09em; text-transform: uppercase; }
    .effect-list { margin: 0; padding: 0; border-top: 1px solid var(--border); list-style: none; }
    .effect-row {
      position: relative;
      min-width: 0;
      min-height: 48px;
      padding: 8px 10px 7px 0;
      display: grid;
      grid-template-columns: 32px 34px 74px minmax(0, 1fr) 104px;
      column-gap: 8px;
      align-items: baseline;
    }
    .effect-row.selected { background: var(--orange-soft); }
    .history-rail { grid-column: 1; grid-row: 1 / 3; position: relative; align-self: stretch; min-height: 34px; }
    .history-rail::before { content: ""; position: absolute; top: -8px; bottom: -7px; left: 11px; width: 2px; background: var(--rail); }
    .effect-row.blocked .history-rail::after { content: ""; position: absolute; top: 10px; left: 11px; width: 16px; border-top: 1.5px solid var(--red); }
    .effect-row.selected .history-rail::after { content: ""; position: absolute; top: -2px; left: 11px; width: 2px; height: 27px; background: var(--orange); }
    .history-node { position: absolute; z-index: 1; }
    .effect-row.blocked .history-node { top: 1px; left: 23px; color: var(--red); font: 750 15px/1 var(--sans); }
    .effect-row.blocked .history-node::before { content: "×"; }
    .effect-row.selected .history-node { top: 6px; left: 7px; width: 10px; height: 10px; border: 2px solid var(--orange); border-radius: 50%; background: var(--orange); }
    .effect-index { grid-column: 2; color: var(--quiet); font: 11px/1.4 var(--mono); }
    .effect-operation { grid-column: 3; color: var(--ink); font: 700 13px/1.4 var(--mono); letter-spacing: .035em; }
    .effect-resource { grid-column: 4; min-width: 0; color: var(--ink); font: 13px/1.4 var(--mono); overflow-wrap: anywhere; word-break: break-word; }
    .effect-state { grid-column: 5; font-size: 12px; font-weight: 760; letter-spacing: .05em; text-align: right; }
    .effect-row.blocked .effect-state { color: var(--red); }
    .effect-row.authorized .effect-state,
    .effect-row.selected .effect-state { color: var(--orange-muted); font-weight: 700; }
    .effect-enforcement { grid-column: 4 / 6; min-width: 0; margin-top: 2px; color: var(--muted); font-size: 11px; overflow-wrap: anywhere; }
    .effect-enforcement code { font-size: 11px; }
    .history-continuation { min-width: 0; }
    .history-stage {
      min-height: 31px;
      padding-right: 10px;
      display: grid;
      grid-template-columns: 32px 34px 76px 105px minmax(0, 1fr);
      column-gap: 8px;
      align-items: center;
    }
    .history-stage .history-rail { grid-row: 1; min-height: 31px; }
    .history-stage .history-rail::before { top: 0; bottom: 0; }
    .history-stage .history-node { top: 10px; left: 8px; width: 8px; height: 8px; border: 1.5px solid #756f66; border-radius: 50%; background: var(--canvas); }
    .history-stage.verified .history-node,
    .history-stage.committed .history-node { border-color: var(--green); background: var(--green-soft); }
    .history-stage.committed .history-node { background: var(--green); }
    .history-stage.reality-stage .history-node { top: 10px; left: 8px; width: 8px; height: 8px; border: 1.5px solid var(--green); background: var(--green-soft); transform: rotate(45deg); }
    .history-stage.committed .history-rail::before,
    .history-stage.reality-stage .history-rail::before { background: var(--green); }
    .history-stage.reality-stage .history-rail::before { bottom: 16px; }
    .history-stage-label { grid-column: 3; color: var(--muted); font-size: 11px; font-weight: 720; letter-spacing: .07em; text-transform: uppercase; }
    .history-stage-action { grid-column: 4; min-width: 0; color: var(--ink); font-size: 12px; font-weight: 650; }
    .history-stage-resource { grid-column: 5; min-width: 0; color: var(--muted); font-size: 11px; overflow-wrap: anywhere; }
    .history-stage.verified .history-stage-action,
    .history-stage.committed .history-stage-action,
    .history-stage.reality-stage .history-stage-resource { color: var(--green); }
    .history-stage.reality-stage .history-stage-resource { font-size: 12px; font-weight: 720; }
    .history-boundary { min-height: 29px; display: grid; grid-template-columns: 32px minmax(0, 1fr); align-items: center; }
    .history-boundary .history-rail { grid-row: 1; min-height: 29px; }
    .history-boundary .history-rail::before { top: 0; bottom: 0; background: linear-gradient(to bottom, var(--rail) 0 50%, var(--green) 50% 100%); }
    .history-boundary-line { grid-column: 1 / -1; position: relative; margin-left: 11px; border-top: 1px solid var(--border-strong); text-align: center; }
    .history-boundary-line span { position: relative; top: -8px; padding: 0 9px; background: var(--canvas); color: var(--muted); font-size: 10px; font-weight: 720; letter-spacing: .1em; text-transform: uppercase; }
    .inspector {
      min-width: 0;
      padding: 18px 20px 18px 22px;
      border-left: 1px solid var(--border-strong);
      border-radius: 0;
      background: var(--surface);
    }
    .inspector-heading { margin-bottom: 15px; }
    .inspector-heading .eyebrow { color: var(--orange-muted); font-size: 10px; }
    .inspector-heading h2 { margin: 0; font-size: 25px; line-height: 1.2; font-weight: 720; }
    .inspector-heading code { display: block; margin-top: 2px; color: var(--ink); font-size: 13px; overflow-wrap: anywhere; }
    .causal-step { display: grid; grid-template-columns: 104px minmax(0, 1fr); gap: 10px; align-items: start; }
    .causal-step + .causal-step { margin-top: 10px; }
    .step-label { color: var(--muted); font-size: 11px; font-weight: 720; letter-spacing: .075em; text-transform: uppercase; }
    .step-value { min-width: 0; }
    .step-value strong { display: block; font-size: 14px; font-weight: 690; }
    .step-value code { display: block; margin-top: 1px; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .step-value .verified, .step-value .committed-label { color: var(--green); }
    .reality { margin-top: 12px; padding-top: 11px; border-top: 1px solid var(--border); }
    .reality h3 { margin: 0 0 3px; color: var(--green); font-size: 11px; font-weight: 760; letter-spacing: .09em; text-transform: uppercase; }
    .reality p { margin: 0; font-size: 18px; font-weight: 720; letter-spacing: -.01em; }
    .reality p code { color: var(--ink); font-size: 17px; font-weight: 720; }
    .digests { margin: 9px 0 0; display: grid; grid-template-columns: 48px minmax(0, 1fr); gap: 3px 10px; }
    .digests dt { color: var(--muted); font-size: 11px; }
    .digests dd { min-width: 0; margin: 0; }
    .digests code { color: var(--muted); font-size: 11px; overflow-wrap: anywhere; }
    .proof-footer { border-top: 1px solid var(--border-strong); }
    .proof-status { min-height: 50px; display: flex; align-items: center; justify-content: space-between; gap: 24px; }
    .invariant { margin: 0; color: var(--ink); font-size: 13px; }
    .invariant::before { content: "✓"; margin-right: 8px; color: var(--green); font-weight: 800; }
    .receipt-status { color: var(--muted); font-size: 12px; }
    .receipt-status strong { margin-left: 7px; color: var(--green); font-size: 11px; letter-spacing: .08em; }
    details { border-top: 1px solid var(--border); }
    summary { width: fit-content; padding: 11px 0; color: var(--muted); cursor: pointer; font-size: 13px; font-weight: 600; }
    summary::marker { color: var(--orange); }
    summary:focus-visible { outline: 2px solid var(--orange); outline-offset: 4px; border-radius: 2px; }
    .proof-groups { padding: 6px 0 19px; display: grid; grid-template-columns: 1.2fr .9fr 1.1fr; gap: 34px; }
    .proof-group { min-width: 0; }
    .proof-group h3 { margin: 0 0 10px; color: var(--ink); font-size: 12px; font-weight: 680; }
    .proof-grid { margin: 0; display: grid; grid-template-columns: 116px minmax(0, 1fr); gap: 9px 14px; }
    .proof-grid dt { color: var(--muted); font-size: 11px; }
    .proof-grid dd { min-width: 0; margin: 0; }
    .proof-grid code, .proof-grid time { color: var(--muted); font: 11px/1.5 var(--mono); overflow-wrap: anywhere; }
    @media (max-width: 850px) {
      .shell { padding-inline: 22px; }
      .workbench { grid-template-columns: 1fr; gap: 28px; }
      .inspector { padding: 18px 20px; border-top: 1px solid var(--border-strong); border-left: 0; }
      .proof-groups { grid-template-columns: 1fr; gap: 22px; }
    }
    @media (max-width: 540px) {
      .shell { padding: 0 16px 20px; }
      .topbar { min-height: 74px; align-items: flex-start; padding: 17px 0; }
      .brand { display: grid; gap: 4px; }
      .run-state { display: grid; gap: 4px; justify-items: end; }
      .run-id { max-width: 180px; overflow-wrap: anywhere; white-space: normal; text-align: right; }
      .task-strip { padding: 12px 0 14px; }
      .workbench { padding-top: 18px; }
      .effect-row { grid-template-columns: 28px 30px 62px minmax(0, 1fr); row-gap: 5px; padding-right: 0; }
      .history-rail { grid-column: 1; }
      .effect-index { grid-column: 2; }
      .effect-operation { grid-column: 3; }
      .effect-resource { grid-column: 4; }
      .effect-state { grid-column: 3; grid-row: 2; text-align: left; }
      .effect-enforcement { grid-column: 4; grid-row: 2; margin-top: 0; }
      .history-stage { grid-template-columns: 28px 30px 76px minmax(0, 1fr); padding: 3px 0; }
      .history-stage-label { grid-column: 3; }
      .history-stage-action { grid-column: 4; }
      .history-stage-resource { grid-column: 4; grid-row: 2; margin-top: 2px; }
      .history-stage.observed .history-rail,
      .history-stage.committed .history-rail { grid-row: 1 / 3; }
      .history-stage.reality-stage .history-stage-resource { grid-row: 1; margin-top: 0; }
      .history-boundary { grid-template-columns: 28px minmax(0, 1fr); }
      .inspector { padding: 17px 15px; }
      .causal-step { grid-template-columns: 88px minmax(0, 1fr); gap: 8px; }
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
          <div class="section-heading"><h2 id="effects-heading">Execution history</h2></div>
          <ol class="effect-list">
            {{range .Effects}}
            <li class="effect-row {{.StateClass}}">
              <span class="history-rail" aria-hidden="true"><span class="history-node"></span></span>
              <span class="effect-index">{{.Number}}</span>
              <span class="effect-operation">{{.Operation}}</span>
              <code class="effect-resource">{{.Resource}}</code>
              <span class="effect-state">{{.State}}</span>
              <span class="effect-enforcement">via <code>{{.EnforcedBy}}</code></span>
            </li>
            {{end}}
          </ol>
          <div class="history-continuation" aria-label="Verified path into reality">
            <div class="history-stage observed">
              <span class="history-rail" aria-hidden="true"><span class="history-node"></span></span>
              <span class="history-stage-label">Observed</span>
              <strong class="history-stage-action">{{.Inspector.Observed.Operation}}</strong><code class="history-stage-resource">{{.Inspector.Observed.Resource}}</code>
            </div>
            <div class="history-stage verified">
              <span class="history-rail" aria-hidden="true"><span class="history-node"></span></span>
              <span class="history-stage-label">Verified</span>
              <strong class="history-stage-action">{{.Verification}}</strong>
            </div>
            <div class="history-boundary">
              <span class="history-rail" aria-hidden="true"></span>
              <div class="history-boundary-line"><span>Trust boundary</span></div>
            </div>
            <div class="history-stage committed">
              <span class="history-rail" aria-hidden="true"><span class="history-node"></span></span>
              <span class="history-stage-label">Committed</span>
              <strong class="history-stage-action">{{.Inspector.Committed.Operation}}</strong><code class="history-stage-resource">{{.Inspector.Committed.Resource}}</code>
            </div>
            <div class="history-stage reality-stage">
              <span class="history-rail" aria-hidden="true"><span class="history-node"></span></span>
              <span class="history-stage-label">Reality</span>
              <span class="history-stage-resource"><code>{{.Inspector.RealityDisplay}}</code> changed</span>
            </div>
          </div>
        </section>

        <aside class="inspector" aria-labelledby="inspector-heading">
          <header class="inspector-heading">
            <p class="eyebrow">Effect {{.Inspector.Number}}</p>
            <h2 id="inspector-heading">{{.Inspector.Authorized.Operation}}</h2>
            <code>{{.Inspector.Authorized.Resource}}</code>
          </header>

          <div class="causal-step">
            <span class="step-label">Authorized</span>
            <span class="step-value"><strong>Effect Contract</strong><code>{{.Inspector.Authorized.EnforcedBy}}</code></span>
          </div>
          <div class="causal-step">
            <span class="step-label">Observed</span>
            <span class="step-value"><strong>{{.Inspector.Observed.Operation}}</strong><code>{{.Inspector.Observed.Resource}}</code></span>
          </div>
          <div class="causal-step">
            <span class="step-label">Verification</span>
            <span class="step-value"><strong class="verified">{{.Verification}}</strong></span>
          </div>
          <div class="causal-step">
            <span class="step-label">Committed</span>
            <span class="step-value"><strong class="committed-label">{{.Inspector.Committed.Operation}}</strong><code>{{.Inspector.Committed.Resource}}</code></span>
          </div>

          <section class="reality" aria-labelledby="reality-heading">
            <h3 id="reality-heading">Reality</h3>
            <p><code>{{.Inspector.RealityDisplay}}</code> changed</p>
            <dl class="digests">
              <dt>Before</dt><dd><code>{{.Inspector.BeforeShort}}</code></dd>
              <dt>After</dt><dd><code>{{.Inspector.AfterShort}}</code></dd>
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
        <div class="proof-groups">
          <section class="proof-group" aria-labelledby="integrity-proof-heading">
            <h3 id="integrity-proof-heading">Integrity</h3>
            <dl class="proof-grid">
              <dt>Receipt SHA-256</dt><dd><code>{{.Proof.ReceiptHash}}</code></dd>
              <dt>Effect Graph SHA-256</dt><dd><code>{{.Proof.GraphHash}}</code></dd>
              <dt>Contract SHA-256</dt><dd><code>{{.Proof.ContractHash}}</code></dd>
              <dt>Before SHA-256</dt><dd><code>{{.Proof.BeforeDigest}}</code></dd>
              <dt>After SHA-256</dt><dd><code>{{.Proof.AfterDigest}}</code></dd>
            </dl>
          </section>
          <section class="proof-group" aria-labelledby="run-proof-heading">
            <h3 id="run-proof-heading">Run</h3>
            <dl class="proof-grid">
              <dt>Run ID</dt><dd><code>{{.Proof.RunID}}</code></dd>
              <dt>Started</dt><dd><time>{{.Proof.StartedAt}}</time></dd>
              <dt>Completed</dt><dd><time>{{.Proof.CompletedAt}}</time></dd>
              <dt>Duration</dt><dd><code>{{.Proof.Duration}}</code></dd>
            </dl>
          </section>
          <section class="proof-group" aria-labelledby="plans-proof-heading">
            <h3 id="plans-proof-heading">Plans</h3>
            <dl class="proof-grid">
              <dt>Verification</dt><dd><code>{{.Proof.VerificationPlan}}</code></dd>
              <dt>Commit</dt><dd><code>{{.Proof.CommitPlan}}</code></dd>
              {{if .Proof.CommitOID}}<dt>Commit OID</dt><dd><code>{{.Proof.CommitOID}}</code></dd>{{end}}
            </dl>
          </section>
        </div>
      </details>
    </footer>
  </div>
</body>
</html>
`

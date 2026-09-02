// Package observatory renders a read-only, self-contained view of a verified
// Mirage receipt. It is deliberately outside every authority path.
package observatory

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/MrGray17/Mirage/internal/receipt"
)

type pageData struct {
	Receipt           *receipt.Receipt
	Task              string
	Agent             string
	RunShort          string
	Status            string
	Attempted         int
	Authorized        int
	Denied            int
	Committed         int
	AuthorizedEffects []receipt.Effect
	DeniedEffects     []receipt.Effect
	Mutation          receipt.Mutation
}

func Render(evidence *receipt.Receipt) ([]byte, error) {
	if err := receipt.Verify(evidence); err != nil {
		return nil, fmt.Errorf("render only verified evidence: %w", err)
	}
	view, err := template.New("observatory").Funcs(template.FuncMap{"short": shortIdentity}).Parse(pageTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse Observatory template: %w", err)
	}
	data := pageData{
		Receipt: evidence, RunShort: shortIdentity(evidence.RunID), Status: "VERIFIED",
		Attempted: len(evidence.AttemptedEffects), Authorized: len(evidence.AuthorizedEffects),
		Denied: len(evidence.DeniedEffects), Committed: len(evidence.CommittedMutations),
		AuthorizedEffects: append([]receipt.Effect(nil), evidence.AuthorizedEffects...),
		DeniedEffects:     append([]receipt.Effect(nil), evidence.DeniedEffects...),
		Mutation:          evidence.ObservedMutations[0],
	}
	if data.Committed > 0 {
		data.Status = "COMMITTED"
	}
	for _, node := range evidence.EffectGraph.Nodes {
		switch node.Type {
		case "TASK":
			data.Task = node.Label
		case "AGENT":
			data.Agent = node.Label
		}
	}
	var output bytes.Buffer
	if err := view.Execute(&output, data); err != nil {
		return nil, fmt.Errorf("render Observatory: %w", err)
	}
	return output.Bytes(), nil
}

func shortIdentity(value string) string {
	const visible = 8
	trimmed := strings.TrimPrefix(value, "sha256:")
	if len(trimmed) <= visible*2+1 {
		return trimmed
	}
	return trimmed[:visible] + "..." + trimmed[len(trimmed)-visible:]
}

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
  <title>MIRAGE Observatory &mdash; {{.Receipt.RunID}}</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #090a09;
      --ink: #f0eee7;
      --muted: #888d88;
      --quiet: #575c58;
      --line: #282c29;
      --green: #79c99b;
      --green-line: #477b5d;
      --red: #d77b74;
      --amber: #d4aa67;
      --sans: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --mono: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    }
    * { box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      margin: 0;
      min-width: 320px;
      min-height: 100vh;
      background: var(--bg);
      color: var(--ink);
      font: 14px/1.4 var(--sans);
      text-rendering: optimizeLegibility;
    }
    code { font-family: var(--mono); }
    .shell {
      width: min(1280px, 100%);
      min-height: 100vh;
      margin: 0 auto;
      padding: 24px 42px 20px;
      display: flex;
      flex-direction: column;
    }
    .topbar {
      min-height: 48px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 28px;
    }
    .wordmark { margin: 0; font-size: 19px; line-height: 1; font-weight: 680; letter-spacing: .22em; }
    .tagline { margin: 6px 0 0; color: var(--muted); font-size: 12px; }
    .run-state { display: flex; align-items: center; gap: 20px; color: var(--muted); }
    .run-id { display: flex; gap: 8px; align-items: baseline; white-space: nowrap; }
    .micro { color: var(--quiet); font-size: 9px; font-weight: 700; letter-spacing: .16em; text-transform: uppercase; }
    .run-id code { color: var(--ink); font-size: 11px; }
    .terminal-state { color: var(--green); font-size: 10px; font-weight: 700; letter-spacing: .12em; }
    .terminal-state::before {
      content: "";
      display: inline-block;
      width: 6px;
      height: 6px;
      margin-right: 7px;
      border-radius: 50%;
      background: var(--green);
      vertical-align: 1px;
    }
    .execution-map {
      flex: 1;
      padding-top: 15px;
      display: flex;
      flex-direction: column;
      align-items: stretch;
    }
    .realm-label { color: var(--quiet); font-size: 8px; font-weight: 700; letter-spacing: .2em; text-transform: uppercase; }
    .realm-label.untrusted { align-self: flex-start; }
    .origin { text-align: center; }
    .task-label { margin-top: 3px; }
    .task { max-width: 620px; margin: 3px auto 0; font-size: clamp(14px, 1.5vw, 18px); font-weight: 520; letter-spacing: -.015em; }
    .connector {
      width: 1px;
      height: 14px;
      margin: 7px auto;
      background: var(--line);
      position: relative;
    }
    .connector::after, .survivor-line::after {
      content: "";
      position: absolute;
      left: -2px;
      bottom: -1px;
      width: 5px;
      height: 5px;
      border-right: 1px solid var(--muted);
      border-bottom: 1px solid var(--muted);
      transform: rotate(45deg);
    }
    .agent {
      display: inline-flex;
      align-items: center;
      gap: 9px;
      color: var(--amber);
      font-size: 10px;
      font-weight: 750;
      letter-spacing: .14em;
      text-transform: uppercase;
    }
    .agent::before { content: ""; width: 6px; height: 6px; border: 1px solid var(--amber); transform: rotate(45deg); }
    .agent-source { margin-top: 2px; color: var(--quiet); font: 9px/1.3 var(--mono); }
    .attempts {
      position: relative;
      width: 100%;
      margin-top: 13px;
      padding-top: 20px;
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      column-gap: 22px;
    }
    .attempts::before { content: ""; position: absolute; top: 0; left: 9.5%; right: 9.5%; border-top: 1px solid var(--line); }
    .attempts::after { content: ""; position: absolute; top: -13px; left: 50%; height: 13px; border-left: 1px solid var(--line); }
    .effect { position: relative; min-width: 0; text-align: center; overflow-wrap: anywhere; }
    .effect::before { content: ""; position: absolute; top: -20px; left: 50%; height: 14px; border-left: 1px solid var(--line); }
    .effect.denied:nth-child(1) { grid-column: 1; }
    .effect.denied:nth-child(2) { grid-column: 2; }
    .effect.denied:nth-child(3) { grid-column: 5; }
    .effect.denied:nth-child(n+4) { grid-column: auto; }
    .effect.authorized { grid-column: 3; grid-row: 1; }
    .effect .operation { display: block; font: 700 10px/1.2 var(--mono); letter-spacing: .1em; }
    .effect code { display: block; min-height: 2.8em; margin-top: 3px; color: var(--muted); font-size: 10px; }
    .effect .disposition { display: block; margin-top: 2px; font-size: 9px; font-weight: 750; letter-spacing: .12em; }
    .effect.denied .disposition, .dead-end { color: var(--red); }
    .effect.authorized .operation, .effect.authorized .disposition { color: var(--green); }
    .dead-end { display: block; height: 16px; margin-top: 3px; font: 16px/1 var(--sans); }
    .survivor-line { width: 1px; height: 19px; margin: 4px auto 0; background: var(--green-line); position: relative; }
    .survivor-line::after { border-color: var(--green); }
    .causal-chain { width: min(300px, 100%); margin: 0 auto; text-align: center; }
    .chain-node { line-height: 1.2; }
    .chain-node strong { display: block; font-size: 10px; letter-spacing: .12em; text-transform: uppercase; }
    .chain-node code { display: block; margin-top: 3px; color: var(--muted); font-size: 9px; overflow-wrap: anywhere; }
    .chain-node.verified strong { color: var(--green); }
    .boundary { position: relative; width: 100%; height: 25px; margin-top: 6px; display: flex; align-items: center; justify-content: center; }
    .boundary::before { content: ""; position: absolute; left: 0; right: 0; border-top: 1px solid #363b37; }
    .boundary::after { content: ""; position: absolute; top: -7px; bottom: -7px; left: 50%; border-left: 1px solid var(--green-line); }
    .boundary span {
      position: relative;
      z-index: 1;
      padding: 0 14px;
      background: var(--bg);
      color: #9ba09b;
      font-size: 8px;
      font-weight: 750;
      letter-spacing: .22em;
      text-transform: uppercase;
      transform: translateX(108px);
    }
    .trusted-zone { position: relative; padding-top: 8px; text-align: center; }
    .trusted-zone::before { content: ""; position: absolute; top: 0; left: 50%; height: 8px; border-left: 1px solid var(--green-line); }
    .trusted-zone .realm-label { position: absolute; top: 7px; left: 0; color: var(--green-line); }
    .reality { width: min(270px, 100%); margin: 0 auto; padding-top: 3px; border-top: 1px solid var(--green-line); }
    .reality strong { display: block; color: var(--green); font-size: 10px; letter-spacing: .12em; text-transform: uppercase; }
    .reality code { display: block; margin-top: 3px; color: var(--ink); font-size: 11px; }
    .metrics {
      margin-top: 13px;
      padding: 10px 0;
      border-top: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: baseline;
      justify-content: center;
      gap: clamp(20px, 5vw, 68px);
      white-space: nowrap;
    }
    .metric { color: var(--muted); font-size: 10px; letter-spacing: .08em; text-transform: uppercase; }
    .metric b { margin-right: 5px; color: var(--ink); font-size: 16px; font-weight: 600; }
    .metric.denied b { color: var(--red); }
    .metric.good b { color: var(--green); }
    .proof { padding-top: 12px; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 20px 48px; align-items: end; }
    .hashes { margin: 0; display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 3px 13px; }
    .hashes dt { color: var(--quiet); font-size: 8px; font-weight: 700; letter-spacing: .13em; text-transform: uppercase; }
    .hashes dd { margin: 0; min-width: 0; }
    .hashes code { color: var(--muted); font-size: 9px; }
    .invariant { text-align: right; }
    .invariant code { display: block; color: var(--ink); font-size: 11px; }
    .invariant span { display: block; margin-top: 3px; color: var(--green); font-size: 9px; font-weight: 750; letter-spacing: .14em; }
    .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
    @media (max-width: 1024px) {
      .shell { padding-inline: 28px; }
      .attempts { column-gap: 12px; }
      .effect code { font-size: 9px; }
      .proof { gap: 20px; }
    }
    @media (max-width: 720px) {
      .shell { padding: 20px 20px 24px; }
      .topbar { align-items: flex-start; }
      .run-state { display: grid; gap: 4px; justify-items: end; }
      .execution-map { padding-top: 20px; }
      .attempts { display: flex; flex-direction: column; gap: 17px; padding-top: 10px; }
      .attempts::before, .attempts::after, .effect::before { display: none; }
      .effect { text-align: left; padding-left: 18px; border-left: 1px solid var(--line); }
      .effect.authorized { order: 2; border-color: var(--green-line); }
      .effect.denied { order: 1; }
      .dead-end { position: absolute; left: -7px; top: 13px; background: var(--bg); }
      .survivor-line { margin-left: -19px; height: 16px; }
      .causal-chain { margin-top: 5px; }
      .metrics { justify-content: space-between; gap: 8px; white-space: normal; }
      .metric { text-align: center; font-size: 8px; }
      .metric b { display: block; margin: 0 0 2px; }
      .proof { grid-template-columns: 1fr; }
      .invariant { text-align: left; }
      .boundary span { transform: translateX(80px); }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div>
        <h1 class="wordmark">MIRAGE</h1>
        <p class="tagline">transactional security runtime</p>
      </div>
      <div class="run-state">
        <div class="run-id"><span class="micro">Run</span><code title="{{.Receipt.RunID}}">{{.RunShort}}</code></div>
        <div class="terminal-state">{{.Status}}</div>
      </div>
    </header>

    <main class="execution-map">
      <span class="realm-label untrusted">Speculative / untrusted</span>
      <section class="origin" aria-label="Untrusted execution">
        <div class="task-label micro">Task</div>
        <div class="task">{{.Task}}</div>
        <div class="connector" aria-hidden="true"></div>
        <div class="agent">Untrusted agent</div>
        <div class="agent-source">{{.Agent}}</div>
      </section>

      <section class="attempts" aria-label="Attempted effects">
        {{range .DeniedEffects}}
        <article class="effect denied">
          <span class="operation">{{.Operation}}</span>
          <code>{{.Resource}}</code>
          <span class="disposition">DENIED</span>
          <span class="dead-end" aria-label="terminated">&times;</span>
        </article>
        {{end}}
        {{range .AuthorizedEffects}}
        <article class="effect authorized">
          <span class="operation">{{.Operation}}</span>
          <code>{{.Resource}}</code>
          <span class="disposition">AUTHORIZED</span>
          <span class="survivor-line" aria-hidden="true"></span>
        </article>
        {{end}}
      </section>

      <section class="causal-chain" aria-label="Authorized causal path">
        <div class="chain-node">
          <strong>Observed mutation</strong>
          <code>{{.Mutation.Operation}} {{.Mutation.Resource}}</code>
        </div>
        <div class="survivor-line" aria-hidden="true"></div>
        <div class="chain-node verified">
          <strong>Verified</strong>
          <code title="{{.Receipt.VerificationPlan}}">plan {{short .Receipt.VerificationPlan}}</code>
        </div>
        <div class="survivor-line" aria-hidden="true"></div>
      </section>

      <div class="boundary"><span>Trust boundary</span></div>

      <section class="trusted-zone" aria-label="Trusted reality">
        <span class="realm-label">Trusted reality</span>
        <div class="chain-node verified"><strong>Trusted commit</strong></div>
        <div class="survivor-line" aria-hidden="true"></div>
        <div class="reality">
          <strong>Reality</strong>
          <code>{{.Mutation.Resource}}</code>
        </div>
      </section>

      <section class="metrics" aria-label="Execution totals">
        <div class="metric"><b>{{.Attempted}}</b>attempted</div>
        <div class="metric denied"><b>{{.Denied}}</b>denied</div>
        <div class="metric good"><b>{{.Authorized}}</b>authorized</div>
        <div class="metric good"><b>{{.Committed}}</b>committed</div>
      </section>

      <footer class="proof">
        <dl class="hashes">
          <dt>Contract</dt><dd><code title="{{.Receipt.ContractHash}}">{{short .Receipt.ContractHash}}</code><span class="sr-only">{{.Receipt.ContractHash}}</span></dd>
          <dt>Graph</dt><dd><code title="{{.Receipt.EffectGraphHash}}">{{short .Receipt.EffectGraphHash}}</code><span class="sr-only">{{.Receipt.EffectGraphHash}}</span></dd>
          <dt>Receipt</dt><dd><code title="{{.Receipt.SHA256}}">{{short .Receipt.SHA256}}</code><span class="sr-only">{{.Receipt.SHA256}}</span></dd>
          <dt>Commit plan</dt><dd><code title="{{.Receipt.CommitPlan}}">{{short .Receipt.CommitPlan}}</code><span class="sr-only">{{.Receipt.CommitPlan}}</span></dd>
        </dl>
        <div class="invariant">
          <code>CommittedEffects &sube; AuthorizedEffects</code>
          <span>PASSED</span>
        </div>
      </footer>
    </main>
  </div>
</body>
</html>
`

// Package observatory renders a read-only, self-contained view of a verified
// Mirage receipt. It is deliberately outside every authority path.
package observatory

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/MrGray17/Mirage/internal/receipt"
)

type pageData struct {
	Receipt    *receipt.Receipt
	Attempted  int
	Authorized int
	Denied     int
	Committed  int
}

func Render(evidence *receipt.Receipt) ([]byte, error) {
	if err := receipt.Verify(evidence); err != nil {
		return nil, fmt.Errorf("render only verified evidence: %w", err)
	}
	view, err := template.New("observatory").Funcs(template.FuncMap{
		"denied": func(effect receipt.Effect) bool {
			for _, denied := range evidence.DeniedEffects {
				if denied == effect {
					return true
				}
			}
			return false
		},
	}).Parse(pageTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse Observatory template: %w", err)
	}
	var output bytes.Buffer
	err = view.Execute(&output, pageData{
		Receipt: evidence, Attempted: len(evidence.AttemptedEffects), Authorized: len(evidence.AuthorizedEffects),
		Denied: len(evidence.DeniedEffects), Committed: len(evidence.CommittedMutations),
	})
	if err != nil {
		return nil, fmt.Errorf("render Observatory: %w", err)
	}
	return output.Bytes(), nil
}

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
  <title>MIRAGE Observatory — {{.Receipt.RunID}}</title>
  <style>
    :root { color-scheme: dark; --ink:#f1efe8; --muted:#8d948f; --panel:#111512; --line:#29302b; --green:#6ee7a8; --red:#ff766f; --amber:#f3bf65; --black:#080a09; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:var(--black); color:var(--ink); font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; }
    header { min-height:78px; display:flex; align-items:center; justify-content:space-between; gap:24px; padding:18px 24px; border-bottom:1px solid var(--line); background:#0b0e0c; }
    .brand { font-size:20px; letter-spacing:.18em; font-weight:700; }
    .run { color:var(--muted); text-align:right; overflow-wrap:anywhere; }
    main { display:grid; grid-template-columns:minmax(250px,.8fr) minmax(430px,1.45fr) minmax(250px,.8fr); min-height:calc(100vh - 78px); }
    section { padding:24px; border-right:1px solid var(--line); }
    section:last-child { border-right:0; }
    h1,h2,p { margin-top:0; } h2 { color:var(--muted); font-size:11px; letter-spacing:.16em; text-transform:uppercase; margin-bottom:18px; }
    .timeline { list-style:none; padding:0; margin:0; }
    .timeline li { position:relative; padding:0 0 20px 23px; }
    .timeline li:before { content:""; position:absolute; left:4px; top:6px; width:7px; height:7px; border:1px solid var(--muted); border-radius:50%; background:var(--black); }
    .timeline li:not(:last-child):after { content:""; position:absolute; left:8px; top:15px; bottom:0; width:1px; background:var(--line); }
    .timeline strong { display:block; font-size:12px; color:var(--ink); }
    .timeline span { color:var(--muted); font-size:11px; }
    .task { border:1px solid var(--line); background:var(--panel); padding:18px; margin-bottom:18px; }
    .agent { width:max-content; max-width:100%; margin:0 auto 16px; border:1px solid var(--amber); color:var(--amber); padding:8px 13px; }
    .flowline { height:18px; width:1px; margin:0 auto; background:var(--line); }
    .effects { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
    .effect { min-height:92px; padding:13px; border:1px solid var(--line); background:var(--panel); overflow-wrap:anywhere; }
    .effect.authorized { border-color:#285b42; } .effect.denied { border-color:#65302d; }
    .status { display:block; margin-bottom:8px; font-size:11px; letter-spacing:.08em; }
    .authorized .status,.passed { color:var(--green); } .denied .status { color:var(--red); }
    .effect small { display:block; color:var(--muted); margin-top:8px; }
    .chain { display:flex; align-items:stretch; justify-content:center; gap:8px; margin-top:18px; }
    .chain .node { flex:1; padding:12px 10px; border:1px solid var(--line); background:var(--panel); text-align:center; overflow-wrap:anywhere; }
    .arrow { align-self:center; color:var(--muted); }
    .stats { display:grid; grid-template-columns:repeat(2,1fr); gap:10px; margin-bottom:20px; }
    .stat { padding:14px; border:1px solid var(--line); background:var(--panel); }
    .stat b { display:block; font-size:28px; line-height:1; margin-bottom:7px; }
    .stat span { color:var(--muted); font-size:10px; letter-spacing:.1em; }
    .good b { color:var(--green); } .bad b { color:var(--red); }
    dl { margin:0; } dt { margin-top:14px; color:var(--muted); font-size:10px; letter-spacing:.1em; text-transform:uppercase; } dd { margin:4px 0 0; overflow-wrap:anywhere; }
    .invariant { margin-top:22px; padding:14px; border-left:3px solid var(--green); background:var(--panel); }
    @media (max-width: 980px) { main { grid-template-columns:1fr; } section { border-right:0; border-bottom:1px solid var(--line); } .effects { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <header><div class="brand">MIRAGE OBSERVATORY</div><div class="run">RUN<br>{{.Receipt.RunID}}</div></header>
  <main>
    <section>
      <h2>Execution timeline</h2>
      <ol class="timeline">
        {{range .Receipt.EffectGraph.Nodes}}<li><strong>{{.Type}}</strong><span>{{.Label}}</span></li>{{end}}
      </ol>
    </section>
    <section>
      <h2>Effect graph</h2>
      <div class="task"><strong>TASK</strong><br>{{(index .Receipt.EffectGraph.Nodes 1).Label}}</div>
      <div class="agent">UNTRUSTED AGENT</div><div class="flowline"></div>
      <div class="effects">
        {{range .Receipt.AttemptedEffects}}
        <div class="effect {{if denied .}}denied{{else}}authorized{{end}}">
          <span class="status">{{if denied .}}DENIED{{else}}AUTHORIZED{{end}}</span>
          <strong>{{.Operation}}</strong><br>{{.Resource}}
          <small>{{.EnforcedBy}}</small>
        </div>
        {{end}}
      </div>
      <div class="chain">
        <div class="node">OBSERVED<br><strong>{{.Committed}} mutation</strong></div><div class="arrow">→</div>
        <div class="node passed">VERIFIED<br><strong>{{.Receipt.Verification}}</strong></div><div class="arrow">→</div>
        <div class="node passed">COMMITTED<br><strong>{{.Committed}} effect</strong></div>
      </div>
    </section>
    <section>
      <h2>Run summary</h2>
      <div class="stats">
        <div class="stat"><b>{{.Attempted}}</b><span>ATTEMPTED</span></div>
        <div class="stat good"><b>{{.Authorized}}</b><span>AUTHORIZED</span></div>
        <div class="stat bad"><b>{{.Denied}}</b><span>DENIED</span></div>
        <div class="stat good"><b>{{.Committed}}</b><span>COMMITTED</span></div>
      </div>
      <dl>
        <dt>Receipt</dt><dd>{{.Receipt.SHA256}}</dd>
        <dt>Effect graph</dt><dd>{{.Receipt.EffectGraphHash}}</dd>
        <dt>Contract</dt><dd>{{.Receipt.ContractHash}}</dd>
        <dt>Commit plan</dt><dd>{{.Receipt.CommitPlan}}</dd>
        <dt>Started</dt><dd>{{.Receipt.StartedAt}}</dd>
        <dt>Completed</dt><dd>{{.Receipt.CompletedAt}}</dd>
      </dl>
      <div class="invariant">Committed effects are a subset of authorized effects.</div>
    </section>
  </main>
</body>
</html>
`

package securitygate

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type decisionMeta struct {
	Path            string
	Validation      bool
	HardStop        bool
	WarnFloor       int
	BlockFloor      int
	OverallRisk     int
	HasThresholds   bool
	ThresholdSource string
}

func writeReportHTML(path string, report Report) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}

	decisionClassName := decisionClass(report.Decision)
	riskPct := clampScore(report.Risk.OverallScore)
	trustPct := clampScore(report.Trust.Score)
	maxFindingPct := clampScore(report.Risk.MaxFindingScore)
	decisionMeta := deriveDecisionMeta(report)
	noiseView := deriveNoiseBudgetView(report)

	acceptedCount := 0
	hardStopCount := 0
	severityCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
		"unknown":  0,
	}
	for _, f := range report.Findings {
		sev := strings.ToLower(f.Severity)
		if _, ok := severityCounts[sev]; ok {
			severityCounts[sev]++
		} else {
			severityCounts["unknown"]++
		}
		if f.Accepted {
			acceptedCount++
		}
		if f.HardStop {
			hardStopCount++
		}
	}

	badInputs := 0
	for _, in := range report.Inputs {
		if !in.ReadOK {
			badInputs++
		}
	}

	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	b.WriteString("<title>security-gate report</title>")
	b.WriteString(`<script>(function(){try{var k='security_gate_theme';var t=localStorage.getItem(k);if(t!=='light'&&t!=='dark'){t=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark'}document.documentElement.setAttribute('data-theme',t);}catch(_){document.documentElement.setAttribute('data-theme','dark');}})();</script>`)
	b.WriteString(`<style>
:root {
  --bg: #070b14;
  --bg-grad-1: #102746;
  --bg-grad-2: #171538;
  --panel: #0f1727;
  --panel-2: #0b1322;
  --ink: #e8f2ff;
  --muted: #9ab0cf;
  --line: #263753;
  --line-strong: #33507a;
  --shadow: 0 20px 34px -24px rgba(1, 4, 12, 0.9);
  --brand: #86f3ff;
  --heading: #d1e5ff;
  --badge-ink: #aecdff;
  --ok: #52f3a6;
  --warn: #ffd166;
  --block: #ff6b93;
  --ok-bg: rgba(82, 243, 166, 0.12);
  --warn-bg: rgba(255, 209, 102, 0.12);
  --block-bg: rgba(255, 107, 147, 0.12);
  --allow-border: rgba(82, 243, 166, 0.55);
  --warn-border: rgba(255, 209, 102, 0.55);
  --block-border: rgba(255, 107, 147, 0.60);
  --allow-glow: 0 0 12px rgba(82, 243, 166, 0.15);
  --warn-glow: 0 0 12px rgba(255, 209, 102, 0.15);
  --block-glow: 0 0 12px rgba(255, 107, 147, 0.16);
  --table-head: #122038;
  --table-head-ink: #b9d6ff;
  --chip: #111d33;
  --skip-bg: #ecfeff;
  --skip-ink: #04121f;
  --hero-grad-1: #121f36;
  --hero-grad-2: #0b1424;
  --hero-title-shadow: rgba(134, 243, 255, 0.15);
  --hero-decision-bg: #091324;
  --track-bg: #091427;
  --track-line: #1f3353;
  --trace-line: #2a4061;
  --trace-item-bg: #0d1729;
  --trace-dot-border: #5c7ba8;
  --trace-dot-bg: #0a1120;
  --trace-ok-border: rgba(82, 243, 166, 0.50);
  --trace-ok-bg: rgba(82, 243, 166, 0.08);
  --trace-warn-border: rgba(255, 209, 102, 0.50);
  --trace-warn-bg: rgba(255, 209, 102, 0.08);
  --trace-error-border: rgba(255, 107, 147, 0.55);
  --trace-error-bg: rgba(255, 107, 147, 0.08);
  --trace-icon-ink: #b9d6ff;
  --trace-pre-ink: #d5e8ff;
  --fill-risk-a: #ffd166;
  --fill-risk-b: #ff8f3d;
  --fill-trust-a: #52f3a6;
  --fill-trust-b: #19d28a;
  --fill-score-a: #74d7ff;
  --fill-score-b: #4f7dff;
  --fill-critical-a: #ff6b93;
  --fill-critical-b: #ff3d71;
  --fill-high-a: #ff9f67;
  --fill-high-b: #ff6c52;
  --fill-medium-a: #ffd166;
  --fill-medium-b: #ffb347;
  --fill-low-a: #6be9ff;
  --fill-low-b: #42b9ff;
  --fill-info-a: #8ea7c9;
  --fill-info-b: #5f7fa7;
  --fill-unknown-a: #c291ff;
  --fill-unknown-b: #8b68ff;
  --radius: 14px;
}
:root[data-theme="light"] {
  --bg: #f3f7fc;
  --bg-grad-1: #deebfa;
  --bg-grad-2: #e7f0fb;
  --panel: #ffffff;
  --panel-2: #f7fafd;
  --ink: #0f172a;
  --muted: #475569;
  --line: #d7e1ed;
  --line-strong: #bfd0e3;
  --shadow: 0 16px 30px -26px rgba(15, 23, 42, 0.35);
  --brand: #1e3a5f;
  --heading: #16324f;
  --badge-ink: #274463;
  --ok: #166534;
  --warn: #b45309;
  --block: #b91c1c;
  --ok-bg: #e9f8ee;
  --warn-bg: #fff5e9;
  --block-bg: #fff0f0;
  --allow-border: #9dd8b2;
  --warn-border: #f1cca1;
  --block-border: #efb7b7;
  --allow-glow: none;
  --warn-glow: none;
  --block-glow: none;
  --table-head: #edf3fb;
  --table-head-ink: #274463;
  --chip: #edf3fb;
  --skip-bg: #0f172a;
  --skip-ink: #ffffff;
  --hero-grad-1: #f8fbff;
  --hero-grad-2: #eef4fb;
  --hero-title-shadow: rgba(30, 58, 95, 0.08);
  --hero-decision-bg: #ffffff;
  --track-bg: #e7eef7;
  --track-line: #d5e2f0;
  --trace-line: #c9d9ea;
  --trace-item-bg: #ffffff;
  --trace-dot-border: #9fb7d1;
  --trace-dot-bg: #ffffff;
  --trace-ok-border: #9fd8b4;
  --trace-ok-bg: #effbf3;
  --trace-warn-border: #f2cea5;
  --trace-warn-bg: #fff8ee;
  --trace-error-border: #efb5b5;
  --trace-error-bg: #fff3f3;
  --trace-icon-ink: #1b395a;
  --trace-pre-ink: #1e293b;
  --fill-risk-a: #f59e0b;
  --fill-risk-b: #b45309;
  --fill-trust-a: #22c55e;
  --fill-trust-b: #15803d;
  --fill-score-a: #60a5fa;
  --fill-score-b: #1d4ed8;
  --fill-critical-a: #ef4444;
  --fill-critical-b: #b91c1c;
  --fill-high-a: #f97316;
  --fill-high-b: #c2410c;
  --fill-medium-a: #f59e0b;
  --fill-medium-b: #b45309;
  --fill-low-a: #38bdf8;
  --fill-low-b: #0369a1;
  --fill-info-a: #94a3b8;
  --fill-info-b: #475569;
  --fill-unknown-a: #a78bfa;
  --fill-unknown-b: #6d28d9;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: radial-gradient(900px 460px at 0% 0%, var(--bg-grad-1) 0%, transparent 58%),
              radial-gradient(860px 440px at 100% 100%, var(--bg-grad-2) 0%, transparent 62%),
              var(--bg);
  color: var(--ink);
  font-family: "IBM Plex Sans", "Source Sans 3", "Segoe UI", system-ui, sans-serif;
  line-height: 1.55;
}
.skip-link {
  position: absolute;
  left: -9999px;
  top: auto;
}
.skip-link:focus {
  left: 12px;
  top: 10px;
  background: var(--skip-bg);
  color: var(--skip-ink);
  padding: 8px 10px;
  border-radius: 8px;
  z-index: 99;
}
.shell {
  max-width: 1260px;
  margin: 0 auto;
  padding: 22px;
}
.hero {
  background: linear-gradient(142deg, var(--hero-grad-1), var(--hero-grad-2));
  border: 1px solid var(--line-strong);
  border-radius: 18px;
  padding: 18px;
  box-shadow: var(--shadow);
}
.hero-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.hero-grid {
  display: grid;
  grid-template-columns: 1.6fr 1fr;
  gap: 14px;
}
.hero-main {
  min-width: 0;
}
.hero h1 {
  margin: 0;
  font-size: 1.6rem;
  letter-spacing: 0.01em;
  color: var(--brand);
  text-shadow: 0 0 14px var(--hero-title-shadow);
}
.theme-toggle {
  border: 1px solid var(--line-strong);
  background: var(--chip);
  color: var(--ink);
  border-radius: 999px;
  padding: 0.33rem 0.82rem;
  font-size: 0.78rem;
  font-weight: 700;
  cursor: pointer;
}
.theme-toggle:hover {
  filter: brightness(1.08);
}
.hero .meta {
  margin-top: 10px;
  color: var(--muted);
  font-size: 0.92rem;
}
.meta-line {
  margin-top: 6px;
}
.hero-decision {
  border: 1px solid var(--line-strong);
  border-radius: 12px;
  background: var(--hero-decision-bg);
  padding: 12px;
  display: grid;
  gap: 8px;
}
.hero-decision.allow {
  border-color: var(--allow-border);
  background: linear-gradient(140deg, var(--ok-bg), var(--hero-decision-bg));
  box-shadow: var(--allow-glow);
}
.hero-decision.warn {
  border-color: var(--warn-border);
  background: linear-gradient(140deg, var(--warn-bg), var(--hero-decision-bg));
  box-shadow: var(--warn-glow);
}
.hero-decision.block {
  border-color: var(--block-border);
  background: linear-gradient(140deg, var(--block-bg), var(--hero-decision-bg));
  box-shadow: var(--block-glow);
}
.hero-decision .label {
  font-size: 0.78rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--muted);
  font-weight: 700;
}
.hero-decision.allow .label { color: var(--ok); }
.hero-decision.warn .label { color: var(--warn); }
.hero-decision.block .label { color: var(--block); }
.hero-kpis {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}
.hero-kpi {
  border: 1px solid var(--line);
  border-radius: 10px;
  background: var(--panel-2);
  padding: 7px 8px;
}
.hero-kpi .k {
  font-size: 0.75rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.hero-kpi .v {
  margin-top: 2px;
  font-size: 1.05rem;
  font-weight: 700;
}
.pills { margin-top: 2px; }
.pill {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 0.2rem 0.66rem;
  font-size: 0.78rem;
  font-weight: 700;
  margin-right: 0.3rem;
  border: 1px solid var(--line);
  background: var(--chip);
  color: var(--ink);
}
.allow { background: var(--ok-bg); color: var(--ok); border-color: var(--allow-border); box-shadow: var(--allow-glow); }
.warn { background: var(--warn-bg); color: var(--warn); border-color: var(--warn-border); box-shadow: var(--warn-glow); }
.block { background: var(--block-bg); color: var(--block); border-color: var(--block-border); box-shadow: var(--block-glow); }
.card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 13px;
  animation: rise-in .3s ease both;
}
.section-block { margin-top: 12px; }
h2 {
  margin: 0;
  font-size: 1.01rem;
  color: var(--heading);
}
.section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 10px;
}
.badge {
  display: inline-block;
  border-radius: 999px;
  padding: 0.16rem 0.58rem;
  font-size: 0.79rem;
  font-weight: 700;
  background: var(--chip);
  border: 1px solid var(--line);
  color: var(--badge-ink);
}
.meaning {
  font-weight: 700;
}
.meaning-allow { color: var(--ok); }
.meaning-warn { color: var(--warn); }
.meaning-block { color: var(--block); }
.meaning-neutral { color: var(--brand); }
.stats {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
  margin-top: 12px;
}
.stat .k {
  color: var(--muted);
  font-size: 0.76rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.stat .v {
  margin-top: 3px;
  font-size: 1.18rem;
  font-weight: 700;
}
.summary-grid {
  display: grid;
  grid-template-columns: 1.1fr 1fr;
  gap: 12px;
  margin-top: 12px;
}
.summary-list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.summary-list li {
  margin-top: 8px;
  padding: 8px 10px;
  border-radius: 10px;
  border: 1px solid var(--line);
  background: var(--panel-2);
}
.note {
  color: var(--muted);
  font-size: 0.94rem;
  margin: 7px 0 0;
}
.row {
  display: grid;
  grid-template-columns: 1.25fr 1fr;
  gap: 12px;
  margin-top: 12px;
}
.meter { margin-top: 10px; }
.meter-top {
  display: flex;
  justify-content: space-between;
  font-size: 0.92rem;
  color: var(--muted);
}
.track {
  margin-top: 6px;
  width: 100%;
  height: 11px;
  border-radius: 999px;
  background: var(--track-bg);
  overflow: hidden;
  border: 1px solid var(--track-line);
}
.fill { height: 100%; border-radius: 999px; }
.fill-risk { background: linear-gradient(90deg, var(--fill-risk-a), var(--fill-risk-b)); }
.fill-trust { background: linear-gradient(90deg, var(--fill-trust-a), var(--fill-trust-b)); }
.fill-score { background: linear-gradient(90deg, var(--fill-score-a), var(--fill-score-b)); }
.fill-critical { background: linear-gradient(90deg, var(--fill-critical-a), var(--fill-critical-b)); }
.fill-high { background: linear-gradient(90deg, var(--fill-high-a), var(--fill-high-b)); }
.fill-medium { background: linear-gradient(90deg, var(--fill-medium-a), var(--fill-medium-b)); }
.fill-low { background: linear-gradient(90deg, var(--fill-low-a), var(--fill-low-b)); }
.fill-info { background: linear-gradient(90deg, var(--fill-info-a), var(--fill-info-b)); }
.fill-unknown { background: linear-gradient(90deg, var(--fill-unknown-a), var(--fill-unknown-b)); }
.grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-top: 12px;
}
ul.clean {
  list-style: none;
  margin: 0;
  padding: 0;
}
ul.clean li {
  margin-top: 8px;
  padding: 10px;
  border-radius: 10px;
  border: 1px solid var(--line);
  background: var(--panel-2);
}
.table-wrap {
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--panel);
}
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--panel);
  font-size: 0.92rem;
}
caption {
  text-align: left;
  color: var(--muted);
  padding: 10px 10px 0;
  font-size: 0.87rem;
}
th, td {
  border-bottom: 1px solid var(--line);
  padding: 9px;
  text-align: left;
  vertical-align: top;
  white-space: normal;
  overflow-wrap: anywhere;
}
th {
  position: sticky;
  top: 0;
  background: var(--table-head);
  color: var(--table-head-ink);
  white-space: nowrap;
}
.nowrap { white-space: nowrap; }
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}
.trace {
  margin-top: 10px;
  list-style: none;
  padding: 0;
  position: relative;
}
.trace::before {
  content: "";
  position: absolute;
  left: 16px;
  top: 0;
  bottom: 0;
  width: 2px;
  background: var(--trace-line);
}
.trace-item {
  position: relative;
  margin: 0 0 10px;
  padding: 10px 12px 10px 34px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--trace-item-bg);
}
.trace-item::before {
  content: "";
  position: absolute;
  left: 10px;
  top: 14px;
  width: 12px;
  height: 12px;
  border-radius: 999px;
  border: 2px solid var(--trace-dot-border);
  background: var(--trace-dot-bg);
}
.trace-item.trace-ok { border-color: var(--trace-ok-border); background: var(--trace-ok-bg); }
.trace-item.trace-ok::before { border-color: var(--ok); }
.trace-item.trace-warn { border-color: var(--trace-warn-border); background: var(--trace-warn-bg); }
.trace-item.trace-warn::before { border-color: var(--warn); }
.trace-item.trace-error { border-color: var(--trace-error-border); background: var(--trace-error-bg); }
.trace-item.trace-error::before { border-color: var(--block); }
.trace-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.phase-icon,
.trace-order,
.trace-tone,
.trace-chip {
  border: 1px solid var(--line);
  background: var(--chip);
  border-radius: 999px;
}
.phase-icon {
  min-width: 34px;
  text-align: center;
  padding: 0.16rem 0.45rem;
  font-size: 0.72rem;
  font-weight: 700;
  color: var(--trace-icon-ink);
}
.trace-order {
  min-width: 30px;
  text-align: center;
  padding: 0.14rem 0.42rem;
  font-size: 0.78rem;
  font-weight: 700;
}
.trace-tone {
  padding: 0.14rem 0.48rem;
  font-size: 0.74rem;
  font-weight: 700;
}
.trace-tone.trace-ok { color: var(--ok); }
.trace-tone.trace-warn { color: var(--warn); }
.trace-tone.trace-error { color: var(--block); }
.trace-phase { font-weight: 700; }
.trace-phase-key { color: var(--muted); font-size: 0.76rem; }
.phase-desc { color: var(--muted); font-size: 0.9rem; margin: 6px 0 0; }
.trace-result { margin: 6px 0 0; }
.trace-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}
.trace-stat {
  border: 1px solid var(--line);
  border-radius: 10px;
  background: var(--panel-2);
  padding: 8px;
}
.trace-stat .k { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; }
.trace-stat .v { font-size: 1rem; font-weight: 700; margin-top: 2px; }
.trace-meta {
  margin-top: 8px;
  display: grid;
  grid-template-columns: 1fr;
  gap: 8px;
}
.trace-detail {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 8px;
  background: var(--panel-2);
}
.trace-detail > summary {
  cursor: pointer;
  font-weight: 700;
  color: var(--ink);
}
.trace-detail pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  margin: 8px 0 0;
  color: var(--trace-pre-ink);
  font-size: 0.85rem;
}
footer {
  margin-top: 12px;
  color: var(--muted);
  font-size: 0.9rem;
  text-align: center;
  padding-bottom: 8px;
}
@keyframes rise-in {
  from { opacity: 0; transform: translateY(4px); }
  to { opacity: 1; transform: translateY(0); }
}
@media (prefers-reduced-motion: reduce) {
  .card { animation: none; }
}
@media (max-width: 1120px) {
  .hero-grid { grid-template-columns: 1fr; }
  .stats { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .row { grid-template-columns: 1fr; }
  .summary-grid { grid-template-columns: 1fr; }
}
@media (max-width: 760px) {
  .shell { padding: 14px; }
  .hero-top { align-items: flex-start; flex-direction: column; }
  .hero-kpis { grid-template-columns: 1fr; }
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .grid-2 { grid-template-columns: 1fr; }
  .trace-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  th, td { font-size: 0.85rem; }
}
</style>`)
	b.WriteString("</head><body><a class=\"skip-link\" href=\"#main-content\">Skip to main content</a><main id=\"main-content\" class=\"shell\">")

	fmt.Fprintf(&b, "<section class=\"hero\" aria-labelledby=\"report-title\"><div class=\"hero-grid\"><div class=\"hero-main\"><div class=\"hero-top\"><h1 id=\"report-title\">security-gate run report</h1><button id=\"theme-toggle\" class=\"theme-toggle\" type=\"button\" aria-pressed=\"false\">Theme</button></div><div class=\"meta\">Machine-authoritative output remains <span class=\"mono\">report.json</span>; this HTML is an operator briefing view.</div><div class=\"meta meta-line\">Run ID: <span class=\"mono\">%s</span></div><div class=\"meta meta-line\">Generated: %s</div></div><aside class=\"hero-decision %s\" aria-label=\"Decision snapshot\"><div class=\"label\">Gate Decision</div><div class=\"pills\"><span class=\"pill %s\">%s</span><span class=\"pill\">Stage: %s</span><span class=\"pill\">Exit: %d</span></div><div class=\"hero-kpis\"><div class=\"hero-kpi\"><div class=\"k\">Overall Risk</div><div class=\"v\">%d</div></div><div class=\"hero-kpi\"><div class=\"k\">Trust</div><div class=\"v\">%d</div></div><div class=\"hero-kpi\"><div class=\"k\">Findings</div><div class=\"v\">%d</div></div><div class=\"hero-kpi\"><div class=\"k\">Hard-stop</div><div class=\"v\">%d</div></div></div></aside></div></section>", esc(report.RunID), esc(report.GeneratedAt), decisionClassName, decisionClassName, esc(report.Decision), esc(report.EffectiveStage), report.ExitCode, report.Risk.OverallScore, report.Trust.Score, len(report.Findings), hardStopCount)

	b.WriteString("<section class=\"summary-grid\" aria-label=\"Executive summary and rationale\">")
	b.WriteString("<article class=\"card\" aria-labelledby=\"summary-title\"><div class=\"section-head\"><h2 id=\"summary-title\">Executive Summary</h2><span class=\"badge\">Engineering + Management</span></div><ul class=\"summary-list\">")
	fmt.Fprintf(&b, "<li><strong>Decision:</strong> <span class=\"meaning %s\">%s</span> at stage <span class=\"mono\">%s</span> (exit %d).</li>", meaningClassForDecision(report.Decision), esc(report.Decision), esc(report.EffectiveStage), report.ExitCode)
	fmt.Fprintf(&b, "<li><strong>Risk/Trust:</strong> Overall risk %d/100, trust %d/100.</li>", report.Risk.OverallScore, report.Trust.Score)
	fmt.Fprintf(&b, "<li><strong>Findings:</strong> %d total, %d accepted, <span class=\"meaning %s\">%d hard-stop</span>.</li>", len(report.Findings), acceptedCount, meaningClassForCount(hardStopCount), hardStopCount)
	fmt.Fprintf(&b, "<li><strong>Input quality:</strong> %d files processed, <span class=\"meaning %s\">%d read failure(s)</span>.</li>", len(report.Inputs), meaningClassForCount(badInputs), badInputs)
	b.WriteString("</ul></article>")

	b.WriteString("<article class=\"card\" aria-labelledby=\"rationale-title\"><div class=\"section-head\"><h2 id=\"rationale-title\">Decision Rationale</h2><span class=\"badge\">Deterministic path</span></div><ul class=\"summary-list\">")
	fmt.Fprintf(&b, "<li><strong>Decision path:</strong> <span class=\"meaning %s\">%s</span>.</li>", meaningClassForDecisionPath(decisionMeta.Path), esc(decisionPathLabel(decisionMeta.Path)))
	fmt.Fprintf(&b, "<li><strong>Hard-stop triggered:</strong> <span class=\"meaning %s\">%s</span>.</li>", meaningClassForBool(decisionMeta.HardStop), yesNo(decisionMeta.HardStop))
	fmt.Fprintf(&b, "<li><strong>Validation issue path:</strong> <span class=\"meaning %s\">%s</span>.</li>", meaningClassForBool(decisionMeta.Validation), yesNo(decisionMeta.Validation))
	if decisionMeta.HasThresholds {
		fmt.Fprintf(&b, "<li><strong>Thresholds used:</strong> <span class=\"meaning meaning-warn\">WARN \u2265 %d</span>, <span class=\"meaning meaning-block\">BLOCK \u2265 %d</span> (<span class=\"meaning meaning-neutral\">%s</span>).</li>", decisionMeta.WarnFloor, decisionMeta.BlockFloor, esc(decisionMeta.ThresholdSource))
		fmt.Fprintf(&b, "<li><strong>Observed overall risk:</strong> <span class=\"meaning %s\">%d</span>.</li>", meaningClassForDecision(report.Decision), decisionMeta.OverallRisk)
	} else {
		b.WriteString("<li><strong>Threshold matrix:</strong> <span class=\"meaning meaning-neutral\">bypassed by precedence</span> (hard-stop or validation path).</li>")
	}
	b.WriteString("</ul></article></section>")

	fmt.Fprintf(&b, "<section class=\"stats\" aria-label=\"Operational metrics\"><article class=\"card stat\"><div class=\"k\">Accepted Findings</div><div class=\"v\">%d</div></article><article class=\"card stat\"><div class=\"k\">Input Files</div><div class=\"v\">%d</div></article><article class=\"card stat\"><div class=\"k\">Read Failures</div><div class=\"v\">%d</div></article><article class=\"card stat\"><div class=\"k\">Max Finding Risk</div><div class=\"v\">%d</div></article><article class=\"card stat\"><div class=\"k\">Trace Steps</div><div class=\"v\">%d</div></article></section>", acceptedCount, len(report.Inputs), badInputs, report.Risk.MaxFindingScore, len(report.DecisionTrace))

	b.WriteString("<section class=\"row\" aria-label=\"Risk and severity views\">")
	b.WriteString("<article class=\"card\" aria-labelledby=\"signals-title\"><div class=\"section-head\"><h2 id=\"signals-title\">Risk and Trust Signals</h2><span class=\"badge\">Clamped [0,100]</span></div>")
	fmt.Fprintf(&b, "<div class=\"meter\"><div class=\"meter-top\"><span>Overall risk</span><strong>%d / 100</strong></div><div class=\"track\"><div class=\"fill fill-risk\" style=\"width:%d%%\"></div></div></div>", report.Risk.OverallScore, riskPct)
	fmt.Fprintf(&b, "<div class=\"meter\"><div class=\"meter-top\"><span>Trust score</span><strong>%d / 100</strong></div><div class=\"track\"><div class=\"fill fill-trust\" style=\"width:%d%%\"></div></div></div>", report.Trust.Score, trustPct)
	fmt.Fprintf(&b, "<div class=\"meter\"><div class=\"meter-top\"><span>Max finding risk</span><strong>%d / 100</strong></div><div class=\"track\"><div class=\"fill fill-score\" style=\"width:%d%%\"></div></div></div>", report.Risk.MaxFindingScore, maxFindingPct)
	b.WriteString("<p class=\"note\">Scores are deterministic and monotonic. Unknown signals never reduce risk.</p></article>")

	b.WriteString("<article class=\"card\" aria-labelledby=\"severity-title\"><div class=\"section-head\"><h2 id=\"severity-title\">Severity Distribution</h2><span class=\"badge\">By normalized findings</span></div>")
	severityOrder := []string{"critical", "high", "medium", "low", "info", "unknown"}
	for _, sev := range severityOrder {
		count := severityCounts[sev]
		pct := 0
		if len(report.Findings) > 0 {
			pct = (count * 100) / len(report.Findings)
		}
		fmt.Fprintf(&b, "<div class=\"meter\"><div class=\"meter-top\"><span>%s</span><strong>%d (%d%%)</strong></div><div class=\"track\"><div class=\"fill %s\" style=\"width:%d%%\"></div></div></div>", esc(strings.ToUpper(sev)), count, pct, severityFillClass(sev), pct)
	}
	b.WriteString("</article></section>")

	b.WriteString("<section class=\"card section-block\" aria-labelledby=\"noise-title\"><div class=\"section-head\"><h2 id=\"noise-title\">Noise Budget Preview</h2><span class=\"badge\">Derived view only</span></div>")
	if !noiseView.Available {
		b.WriteString("<p class=\"note\">Noise budget details are unavailable in this view (decision trace details may be minimal).</p>")
	} else {
		fmt.Fprintf(&b, "<ul class=\"summary-list\"><li><strong>Status:</strong> <span class=\"meaning %s\">%s</span>.</li><li><strong>Stage support:</strong> %s (stage <span class=\"mono\">%s</span>).</li><li><strong>Policy knobs:</strong> suppress below <span class=\"mono\">%s</span>; stage limit <span class=\"mono\">%d</span>.</li><li><strong>Suppression summary:</strong> total %d, by severity %d, by stage limit %d, displayed in preview %d/%d.</li></ul>", esc(noiseView.StatusClass), esc(noiseView.StatusText), yesNo(noiseView.StageSupported), esc(noiseView.Stage), esc(noiseView.SuppressBelowSeverity), noiseView.StageLimit, noiseView.SuppressedTotal, noiseView.SuppressedBySeverity, noiseView.SuppressedByLimit, noiseView.DisplayedCount, noiseView.TotalFindings)
		if len(noiseView.Suppressed) > 0 {
			b.WriteString("<p class=\"note\">Suppressed finding preview (derived):</p><ul class=\"clean\">")
			for _, s := range noiseView.Suppressed {
				fmt.Fprintf(&b, "<li><span class=\"mono\">%s</span> <span class=\"meaning meaning-neutral\">(%s)</span></li>", esc(s.FindingID), esc(s.Reason))
			}
			b.WriteString("</ul>")
		} else {
			b.WriteString("<p class=\"note\">No findings were suppressed for preview under current noise-budget settings.</p>")
		}
	}
	b.WriteString("<p class=\"note\">Noise budget is presentation-only. It does not alter scores, decisions, or report.json findings.</p></section>")

	b.WriteString("<section class=\"grid-2\" aria-label=\"Hard-stop and next steps\">")
	if report.HardStop.Triggered {
		b.WriteString("<article class=\"card\" aria-labelledby=\"hardstop-title\"><div class=\"section-head\"><h2 id=\"hardstop-title\">Hard-stop Domains Triggered</h2><span class=\"pill block\">BLOCK path</span></div>")
		b.WriteString("<ul class=\"clean\">")
		for _, d := range report.HardStop.Domains {
			fmt.Fprintf(&b, "<li><span class=\"mono\">%s</span></li>", esc(d))
		}
		b.WriteString("</ul><p class=\"note\">Hard-stop domains bypass numeric scoring and noise budget. Accepted risk cannot override them.</p></article>")
	} else {
		b.WriteString("<article class=\"card\" aria-labelledby=\"hardstop-title\"><div class=\"section-head\"><h2 id=\"hardstop-title\">Hard-stop Status</h2><span class=\"pill allow\">Not triggered</span></div><p class=\"note\">No hard-stop domains were activated in this run.</p></article>")
	}

	b.WriteString("<article class=\"card\" aria-labelledby=\"steps-title\"><div class=\"section-head\"><h2 id=\"steps-title\">Recommended Next Steps</h2><span class=\"badge\">Catalog IDs</span></div>")
	if len(report.RecommendedSteps) == 0 {
		b.WriteString("<p class=\"note\">No additional steps were required for this decision.</p>")
	} else {
		sortedSteps := append([]RecommendedStep(nil), report.RecommendedSteps...)
		sort.Slice(sortedSteps, func(i, j int) bool {
			if sortedSteps[i].Priority != sortedSteps[j].Priority {
				return sortedSteps[i].Priority < sortedSteps[j].Priority
			}
			return sortedSteps[i].ID < sortedSteps[j].ID
		})
		b.WriteString("<ul class=\"clean\">")
		for i, s := range sortedSteps {
			fmt.Fprintf(&b, "<li><strong>Step %d:</strong> <strong class=\"mono\">%s</strong> (priority %d)<br>%s</li>", i+1, esc(s.ID), i+1, esc(s.Text))
		}
		b.WriteString("</ul>")
	}
	b.WriteString("</article></section>")

	b.WriteString("<section class=\"card section-block\" aria-labelledby=\"findings-title\"><div class=\"section-head\"><h2 id=\"findings-title\">Findings Table</h2><span class=\"badge\">Normalized</span></div>")
	b.WriteString("<div class=\"table-wrap\"><table><caption>Normalized findings sorted by deterministic tie-breakers</caption><thead><tr><th scope=\"col\">finding_id</th><th scope=\"col\">domain</th><th scope=\"col\">severity</th><th scope=\"col\" class=\"nowrap\">hard_stop</th><th scope=\"col\" class=\"nowrap\">accepted</th><th scope=\"col\" class=\"nowrap\">risk</th><th scope=\"col\">source</th></tr></thead><tbody>")
	for _, f := range report.Findings {
		fmt.Fprintf(&b, "<tr><td class=\"mono\">%s</td><td class=\"mono\">%s</td><td>%s</td><td class=\"nowrap\">%s</td><td class=\"nowrap\">%s</td><td class=\"nowrap\">%d</td><td class=\"mono\">%s:%d</td></tr>", esc(f.FindingID), esc(f.DomainID), esc(strings.ToUpper(f.Severity)), yesNo(f.HardStop), yesNo(f.Accepted), f.FindingRiskScore, esc(f.SourceFile), f.SourceIndex)
	}
	b.WriteString("</tbody></table></div></section>")

	b.WriteString("<section class=\"card section-block\" aria-labelledby=\"trace-title\"><div class=\"section-head\"><h2 id=\"trace-title\">Decision Trace</h2><span class=\"badge\">Ordered phases</span></div>")
	if len(report.DecisionTrace) == 0 {
		b.WriteString("<p class=\"note\">No trace entries available.</p>")
	} else {
		traceOK := 0
		traceWarn := 0
		traceError := 0
		for _, t := range report.DecisionTrace {
			switch traceTone(t) {
			case "trace-ok":
				traceOK++
			case "trace-warn":
				traceWarn++
			case "trace-error":
				traceError++
			}
		}
		fmt.Fprintf(&b, "<div class=\"trace-summary\"><div class=\"trace-stat\"><div class=\"k\">Steps</div><div class=\"v\">%d</div></div><div class=\"trace-stat\"><div class=\"k\">OK</div><div class=\"v\">%d</div></div><div class=\"trace-stat\"><div class=\"k\">Warn</div><div class=\"v\">%d</div></div><div class=\"trace-stat\"><div class=\"k\">Error</div><div class=\"v\">%d</div></div></div>", len(report.DecisionTrace), traceOK, traceWarn, traceError)
		b.WriteString("<ul class=\"trace\">")
		for _, t := range report.DecisionTrace {
			tone := traceTone(t)
			pv := tracePhaseVisual(t.Phase)
			fmt.Fprintf(&b, "<li class=\"trace-item %s\"><div class=\"trace-head\"><span class=\"trace-order\">%02d</span><span class=\"phase-icon %s\">%s</span><span class=\"trace-phase\">%s</span><span class=\"trace-phase-key mono\">%s</span><span class=\"trace-tone %s\">%s</span></div><p class=\"phase-desc\">%s</p><p class=\"trace-result\">%s</p>%s</li>", tone, t.Order, esc(pv.Class), esc(pv.Code), esc(pv.Title), esc(t.Phase), tone, esc(traceLabel(tone)), esc(pv.Description), esc(t.Result), renderTraceDetails(t.Details))
		}
		b.WriteString("</ul>")
	}
	b.WriteString("</section>")

	b.WriteString("<section class=\"card section-block\" aria-labelledby=\"inputs-title\"><div class=\"section-head\"><h2 id=\"inputs-title\">Input Provenance</h2><span class=\"badge\">SHA-256 trace</span></div>")
	fmt.Fprintf(&b, "<p class=\"note\">Input files: %d | Read failures: %d</p>", len(report.Inputs), badInputs)
	b.WriteString("<div class=\"table-wrap\"><table><caption>Input digests and readability</caption><thead><tr><th scope=\"col\">kind</th><th scope=\"col\">role</th><th scope=\"col\">path</th><th scope=\"col\">sha256</th><th scope=\"col\" class=\"nowrap\">read_ok</th></tr></thead><tbody>")
	for _, in := range report.Inputs {
		fmt.Fprintf(&b, "<tr><td class=\"nowrap\">%s</td><td class=\"nowrap\">%s</td><td class=\"mono\">%s</td><td class=\"mono\">%s</td><td class=\"nowrap\">%s</td></tr>", esc(in.Kind), esc(firstNonEmpty(in.Role, "-")), esc(in.Path), esc(in.SHA256), yesNo(in.ReadOK))
	}
	b.WriteString("</tbody></table></div></section>")

	b.WriteString("<footer>Non-authoritative visualization generated from report.json. For machine decisions, consume report.json only.</footer>")
	b.WriteString(`<script>(function(){var key='security_gate_theme';var root=document.documentElement;var btn=document.getElementById('theme-toggle');function theme(){return root.getAttribute('data-theme')==='light'?'light':'dark'}function apply(t){root.setAttribute('data-theme',t)}function sync(){if(!btn){return}var t=theme();btn.textContent=t==='dark'?'Light theme':'Dark theme';btn.setAttribute('aria-label',t==='dark'?'Switch to light theme':'Switch to dark theme');btn.setAttribute('aria-pressed',t==='dark'?'true':'false')}sync();if(btn){btn.addEventListener('click',function(){var next=theme()==='dark'?'light':'dark';apply(next);try{localStorage.setItem(key,next)}catch(_){}sync()})}})();</script>`)
	b.WriteString("</main></body></html>")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func decisionClass(decision string) string {
	switch strings.ToUpper(decision) {
	case "ALLOW":
		return "allow"
	case "WARN":
		return "warn"
	default:
		return "block"
	}
}

func esc(s string) string {
	return html.EscapeString(s)
}

func traceTone(t TraceEntry) string {
	text := strings.ToLower(t.Result + " " + t.Phase)
	switch {
	case strings.Contains(text, "error"),
		strings.Contains(text, "invalid"),
		strings.Contains(text, "failed"),
		strings.Contains(text, "block"):
		return "trace-error"
	case strings.Contains(text, "warn"):
		return "trace-warn"
	case strings.Contains(text, "ok"),
		strings.Contains(text, "pass"),
		strings.Contains(text, "applied"):
		return "trace-ok"
	default:
		return "trace-warn"
	}
}

func traceLabel(tone string) string {
	switch tone {
	case "trace-ok":
		return "OK"
	case "trace-error":
		return "ERROR"
	default:
		return "WARN"
	}
}

type tracePhaseView struct {
	Code        string
	Title       string
	Description string
	Class       string
}

func tracePhaseVisual(phase string) tracePhaseView {
	switch strings.ToLower(phase) {
	case "input_validation":
		return tracePhaseView{
			Code:        "IN",
			Title:       "Input Validation",
			Description: "Validate file readability, schema shape, and deterministic digests.",
			Class:       "phase-input",
		}
	case "stage_mapping":
		return tracePhaseView{
			Code:        "STG",
			Title:       "Stage Mapping",
			Description: "Resolve effective stage with branch_type as primary and tighten-only secondary signals.",
			Class:       "phase-stage",
		}
	case "hard_stop":
		return tracePhaseView{
			Code:        "HS",
			Title:       "Hard-Stop Evaluation",
			Description: "Check non-overridable hard-stop domains before numeric scoring.",
			Class:       "phase-hard-stop",
		}
	case "governance":
		return tracePhaseView{
			Code:        "AR",
			Title:       "Governance",
			Description: "Apply accepted-risk records, approvals, and expiry semantics.",
			Class:       "phase-governance",
		}
	case "scoring":
		return tracePhaseView{
			Code:        "RSK",
			Title:       "Risk and Trust Scoring",
			Description: "Compute clamped trust/risk values with monotonic aggregation.",
			Class:       "phase-scoring",
		}
	case "decision":
		return tracePhaseView{
			Code:        "DEC",
			Title:       "Decision Matrix",
			Description: "Map stage thresholds and precedence into ALLOW/WARN/BLOCK and exit code.",
			Class:       "phase-decision",
		}
	case "noise_budget":
		return tracePhaseView{
			Code:        "NB",
			Title:       "Noise Budget",
			Description: "Compute presentation-only suppression preview without affecting scores or decisions.",
			Class:       "phase-governance",
		}
	case "report_json":
		return tracePhaseView{
			Code:        "JSON",
			Title:       "JSON Report Output",
			Description: "Write authoritative report.json for machine consumption.",
			Class:       "phase-report",
		}
	case "report_html":
		return tracePhaseView{
			Code:        "HTML",
			Title:       "HTML Report Output",
			Description: "Write non-authoritative report.html derived from report.json.",
			Class:       "phase-report",
		}
	default:
		return tracePhaseView{
			Code:        "STEP",
			Title:       strings.ReplaceAll(phase, "_", " "),
			Description: "Deterministic engine phase execution.",
			Class:       "phase-input",
		}
	}
}

func renderTraceDetails(details map[string]interface{}) string {
	if len(details) == 0 {
		return ""
	}
	keys := make([]string, 0, len(details))
	for k := range details {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString(`<div class="trace-meta">`)
	for _, k := range keys {
		v := fmt.Sprintf("%v", details[k])
		fmt.Fprintf(&b, `<details class="trace-detail"><summary><span class="mono">%s</span></summary><pre class="mono">%s</pre></details>`, esc(k), esc(v))
	}
	b.WriteString(`</div>`)
	return b.String()
}

func deriveDecisionMeta(report Report) decisionMeta {
	meta := decisionMeta{
		Path:        "unknown",
		HardStop:    report.HardStop.Triggered,
		OverallRisk: report.Risk.OverallScore,
	}
	for _, t := range report.DecisionTrace {
		if t.Phase != "decision" {
			continue
		}
		res := strings.ToLower(t.Result)
		switch {
		case strings.Contains(res, "hard_stop"):
			meta.Path = "hard_stop"
			meta.HardStop = true
		case strings.Contains(res, "validation"):
			meta.Path = "validation"
			meta.Validation = true
		case strings.Contains(res, "matrix"):
			meta.Path = "matrix"
			if v, ok := detailInt(t.Details, "warn_floor"); ok {
				meta.WarnFloor = v
				meta.HasThresholds = true
			}
			if v, ok := detailInt(t.Details, "block_floor"); ok {
				meta.BlockFloor = v
				meta.HasThresholds = true
			}
			if v, ok := detailInt(t.Details, "overall_risk"); ok {
				meta.OverallRisk = v
			}
			meta.ThresholdSource = "decision trace"
		}
	}
	if meta.HardStop && meta.Path == "unknown" {
		meta.Path = "hard_stop"
	}
	return meta
}

func detailInt(details map[string]interface{}, key string) (int, bool) {
	if details == nil {
		return 0, false
	}
	raw, ok := details[key]
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case float32:
		return int(v), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func detailBool(details map[string]interface{}, key string) (bool, bool) {
	if details == nil {
		return false, false
	}
	raw, ok := details[key]
	if !ok {
		return false, false
	}
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		switch strings.TrimSpace(strings.ToLower(v)) {
		case "true":
			return true, true
		case "false":
			return false, true
		default:
			return false, false
		}
	default:
		return false, false
	}
}

type suppressedPreviewFinding struct {
	FindingID string
	Reason    string
}

type noiseBudgetView struct {
	Available             bool
	Stage                 string
	StageSupported        bool
	StageLimit            int
	SuppressBelowSeverity string
	SuppressedBySeverity  int
	SuppressedByLimit     int
	SuppressedTotal       int
	DisplayedCount        int
	TotalFindings         int
	StatusText            string
	StatusClass           string
	Suppressed            []suppressedPreviewFinding
}

func deriveNoiseBudgetView(report Report) noiseBudgetView {
	view := noiseBudgetView{
		Available:             false,
		Stage:                 report.EffectiveStage,
		StageSupported:        report.EffectiveStage == "pr" || report.EffectiveStage == "merge",
		SuppressBelowSeverity: "low",
		TotalFindings:         len(report.Findings),
		DisplayedCount:        len(report.Findings),
		StatusText:            "unavailable",
		StatusClass:           "meaning-neutral",
	}
	for _, t := range report.DecisionTrace {
		if t.Phase != "noise_budget" {
			continue
		}
		if t.Details == nil {
			break
		}
		view.Available = true
		if stage, ok := t.Details["stage"].(string); ok && strings.TrimSpace(stage) != "" {
			view.Stage = stage
		}
		if supported, ok := detailBool(t.Details, "stage_supported"); ok {
			view.StageSupported = supported
		}
		if limit, ok := detailInt(t.Details, "stage_limit"); ok {
			view.StageLimit = limit
		}
		if floor, ok := t.Details["suppress_below_severity"].(string); ok && strings.TrimSpace(floor) != "" {
			view.SuppressBelowSeverity = normalizeToken(floor)
		}
		if v, ok := detailInt(t.Details, "suppressed_by_severity"); ok {
			view.SuppressedBySeverity = v
		}
		if v, ok := detailInt(t.Details, "suppressed_by_limit"); ok {
			view.SuppressedByLimit = v
		}
		if v, ok := detailInt(t.Details, "suppressed_total"); ok {
			view.SuppressedTotal = v
		}
		if v, ok := detailInt(t.Details, "displayed_count"); ok {
			view.DisplayedCount = v
		}
		if v, ok := detailInt(t.Details, "total_findings"); ok {
			view.TotalFindings = v
		}
		switch strings.ToLower(t.Result) {
		case "bypassed":
			view.StatusText = "bypassed"
			view.StatusClass = "meaning-warn"
		case "disabled":
			view.StatusText = "disabled"
			view.StatusClass = "meaning-neutral"
		case "not_applicable":
			view.StatusText = "not applicable"
			view.StatusClass = "meaning-neutral"
		default:
			view.StatusText = "active"
			view.StatusClass = "meaning-allow"
		}
		break
	}
	if !view.Available {
		return view
	}
	view.Suppressed = deriveSuppressedPreviewFindings(report.Findings, view.SuppressBelowSeverity, view.StageLimit, view.StageSupported)
	return view
}

func deriveSuppressedPreviewFindings(findings []ReportFinding, suppressBelow string, stageLimit int, stageSupported bool) []suppressedPreviewFinding {
	if !stageSupported {
		return nil
	}
	out := []suppressedPreviewFinding{}
	eligibleForLimit := []ReportFinding{}
	for _, f := range findings {
		if f.HardStop {
			continue
		}
		if shouldSuppressBySeverity(f.Severity, suppressBelow) {
			out = append(out, suppressedPreviewFinding{FindingID: f.FindingID, Reason: "below_severity_floor"})
			continue
		}
		eligibleForLimit = append(eligibleForLimit, f)
	}
	if stageLimit > 0 && len(eligibleForLimit) > stageLimit {
		for _, f := range eligibleForLimit[stageLimit:] {
			out = append(out, suppressedPreviewFinding{FindingID: f.FindingID, Reason: "over_stage_limit"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reason != out[j].Reason {
			return out[i].Reason < out[j].Reason
		}
		return out[i].FindingID < out[j].FindingID
	})
	return out
}

func decisionPathLabel(path string) string {
	switch path {
	case "hard_stop":
		return "Hard-stop precedence"
	case "validation":
		return "Validation failure handling"
	case "matrix":
		return "Risk threshold matrix"
	default:
		return "Unspecified"
	}
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func severityFillClass(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "fill-critical"
	case "high":
		return "fill-high"
	case "medium":
		return "fill-medium"
	case "low":
		return "fill-low"
	case "info":
		return "fill-info"
	default:
		return "fill-unknown"
	}
}

func meaningClassForDecision(decision string) string {
	switch strings.ToUpper(decision) {
	case "ALLOW":
		return "meaning-allow"
	case "WARN":
		return "meaning-warn"
	default:
		return "meaning-block"
	}
}

func meaningClassForBool(v bool) string {
	if v {
		return "meaning-block"
	}
	return "meaning-allow"
}

func meaningClassForCount(v int) string {
	if v > 0 {
		return "meaning-block"
	}
	return "meaning-allow"
}

func meaningClassForDecisionPath(path string) string {
	switch path {
	case "hard_stop", "validation":
		return "meaning-block"
	case "matrix":
		return "meaning-warn"
	default:
		return "meaning-neutral"
	}
}

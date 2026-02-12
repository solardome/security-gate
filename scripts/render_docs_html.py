#!/usr/bin/env python3
import html
import re
from pathlib import Path

DOCS_SRC_DIR = Path("docs/md")
DOCS_OUT_DIR = Path("docs/html")
LOGO_PATH = "images/solardome-logo2.png"

STYLE = """
:root {
  --bg: #120c08;
  --panel: #1d1410;
  --ink: #ffe7c2;
  --muted: #d2a777;
  --accent: #ff9f2f;
  --accent-soft: #3a2416;
  --line: #5e3a22;
  --code-bg: #120b07;
  --code-ink: #ffd8a8;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  background: var(--bg);
  color: var(--ink);
  line-height: 1.6;
  position: relative;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: -1;
  background:
    radial-gradient(900px 520px at 0% 0%, #ff8b2f55 0%, transparent 60%),
    radial-gradient(760px 460px at 100% 0%, #ffbf3f2e 0%, transparent 62%),
    radial-gradient(860px 480px at 50% 100%, #ff6a0035 0%, transparent 65%),
    var(--bg);
}
.layout {
  width: min(1100px, calc(100vw - 2.4rem));
  margin: 1.2rem auto 2rem;
}
.site-header {
  padding: 0.85rem 1.2rem;
  border: 1px solid var(--line);
  background: rgba(27, 17, 12, 0.92);
  backdrop-filter: blur(6px);
  border-radius: 14px;
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.8rem;
}
.brand {
  display: flex;
  align-items: center;
  gap: 0.65rem;
}
.brand img {
  width: 68px;
  height: 68px;
  object-fit: contain;
  border-radius: 8px;
  border: 1px solid var(--line);
  background: #2a1a12;
  padding: 2px;
}
.brand-text {
  display: flex;
  flex-direction: column;
  line-height: 1.2;
}
.brand-app {
  font-weight: 700;
  font-size: 1rem;
}
.brand-company {
  color: var(--muted);
  font-size: 0.85rem;
}
.site-nav {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}
.site-nav a {
  color: #ffb24a;
  text-decoration: none;
  font-weight: 600;
}
.site-nav a:hover {
  text-decoration: underline;
}
.header {
  padding: 1rem 1.2rem;
  border: 1px solid var(--line);
  background: rgba(40, 25, 17, 0.82);
  backdrop-filter: blur(6px);
  border-radius: 14px;
  margin-bottom: 1rem;
}
.header h1 {
  margin: 0;
  font-size: clamp(1.2rem, 2.5vw, 1.7rem);
}
.header p {
  margin: 0.2rem 0 0;
  color: var(--muted);
}
.card {
  background: var(--panel);
  border-radius: 16px;
  border: 1px solid var(--line);
  box-shadow: 0 20px 35px -28px rgba(12, 35, 66, 0.45);
  padding: clamp(1rem, 2.4vw, 2rem);
}
.doc-links {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.75rem;
  margin: 0 0 1rem;
}
.doc-link {
  display: block;
  text-decoration: none;
  color: var(--ink);
  border: 1px solid var(--line);
  background: #2b1a11;
  border-radius: 12px;
  padding: 0.75rem;
}
.doc-link:hover {
  border-color: #a05b22;
  background: #3a2316;
}
.doc-link-title {
  font-weight: 700;
  margin-bottom: 0.2rem;
}
.doc-link-file {
  color: var(--muted);
  font-size: 0.9rem;
}
.pipeline-diagram {
  margin: 0.7rem 0 1rem;
  padding: 0.8rem;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: linear-gradient(180deg, #25170f 0%, #1b120d 100%);
}
.pipeline-main {
  display: flex;
  align-items: stretch;
  gap: 0.45rem;
  flex-wrap: nowrap;
}
.pipeline-step {
  flex: 1 1 0;
  border: 1px solid #6b4127;
  border-radius: 10px;
  background: #2b1a11;
  padding: 0.6rem;
  min-width: 0;
}
.pipeline-step-title {
  font-weight: 700;
  font-size: 0.95rem;
}
.pipeline-step-sub {
  margin-top: 0.2rem;
  color: var(--muted);
  font-size: 0.83rem;
  line-height: 1.35;
}
.pipeline-arrow {
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #ffb24a;
  font-weight: 700;
}
.pipeline-branch-wrap {
  margin-top: 0.55rem;
  border-top: 1px dashed #7d4e2f;
  padding-top: 0.55rem;
}
.pipeline-branch {
  display: grid;
  grid-template-columns: 160px 1fr;
  gap: 0.6rem;
  align-items: start;
}
.pipeline-branch-label {
  margin: 0;
  color: var(--muted);
  font-size: 0.82rem;
  font-weight: 700;
}
.pipeline-branch-arrow {
  color: #ffb24a;
  font-weight: 700;
  margin-right: 0.25rem;
}
.pipeline-note {
  margin-top: 0.55rem;
  color: var(--muted);
  font-size: 0.83rem;
}
h1, h2, h3, h4, h5, h6 {
  margin-top: 1.5rem;
  margin-bottom: 0.65rem;
  line-height: 1.25;
}
h1 { font-size: 2rem; }
h2 {
  font-size: 1.35rem;
  border-bottom: 2px solid #4d2f1b;
  padding-bottom: 0.2rem;
}
h3 { font-size: 1.08rem; }
p { margin: 0.45rem 0 0.95rem; }
a {
  color: #ffb24a;
  text-underline-offset: 3px;
}
code {
  background: #2d1a11;
  border: 1px solid #6a4328;
  padding: 0.1rem 0.32rem;
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.92em;
}
pre {
  margin: 0.75rem 0 1rem;
  background: var(--code-bg);
  color: var(--code-ink);
  padding: 0.9rem;
  border-radius: 10px;
  overflow: auto;
  border: 1px solid #5a3a24;
}
pre code {
  border: 0;
  background: transparent;
  padding: 0;
  color: inherit;
}
ul, ol {
  margin: 0.35rem 0 1rem 1.25rem;
  padding: 0;
}
li { margin: 0.3rem 0; }
li input[type="checkbox"] {
  pointer-events: none;
  margin-right: 0.45rem;
  transform: translateY(1px);
}
blockquote {
  margin: 0.8rem 0 1rem;
  border-left: 4px solid var(--accent);
  background: var(--accent-soft);
  padding: 0.65rem 0.8rem;
  border-radius: 8px;
}
hr {
  border: 0;
  border-top: 1px solid var(--line);
  margin: 1.15rem 0;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin: 0.75rem 0 1.2rem;
  font-size: 0.95rem;
}
thead tr { background: #3a2316; }
th, td {
  border: 1px solid var(--line);
  padding: 0.52rem 0.58rem;
  text-align: left;
  vertical-align: top;
}
tr:nth-child(even) td { background: #26170f; }
@media (max-width: 760px) {
  .layout { width: min(1100px, calc(100vw - 1rem)); }
  .site-header {
    padding: 0.75rem 0.85rem;
    flex-direction: column;
    align-items: flex-start;
  }
  .card { padding: 0.8rem; }
  .doc-links { grid-template-columns: 1fr; }
  .pipeline-main {
    flex-direction: column;
  }
  .pipeline-arrow {
    transform: rotate(90deg);
  }
  .pipeline-branch-wrap {
    border-top: 0;
    padding-top: 0.2rem;
  }
  .pipeline-branch {
    grid-template-columns: 1fr;
  }
  table, thead, tbody, th, td, tr { display: block; }
  thead { display: none; }
  td {
    border-top: 0;
    border-left: 1px solid var(--line);
    border-right: 1px solid var(--line);
    border-bottom: 1px solid var(--line);
    padding-left: 0.7rem;
  }
  tr { margin-bottom: 0.6rem; }
}
""".strip()


def slugify(value: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9\s-]", "", value).strip().lower()
    return re.sub(r"\s+", "-", s) or "section"


def inline_format(text: str) -> str:
    escaped = html.escape(text)
    escaped = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", escaped)
    escaped = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"(?<!\w)\*([^*]+)\*(?!\w)", r"<em>\1</em>", escaped)
    return escaped


def is_table_delimiter(line: str) -> bool:
    if not line.strip().startswith("|"):
        return False
    parts = [p.strip() for p in line.strip().strip("|").split("|")]
    if not parts:
        return False
    return all(re.fullmatch(r":?-{3,}:?", p or "") for p in parts)


def parse_markdown(md: str) -> str:
    lines = md.splitlines()
    i = 0
    out = []
    in_code = False
    list_stack = []

    def close_lists(target=0):
        nonlocal list_stack
        while len(list_stack) > target:
            out.append(f"</{list_stack.pop()}>")

    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip("\n")

        if in_code:
            if line.strip().startswith("```"):
                out.append("</code></pre>")
                in_code = False
            else:
                out.append(html.escape(line))
            i += 1
            continue

        if line.strip().startswith("```"):
            close_lists()
            out.append("<pre><code>")
            in_code = True
            i += 1
            continue

        if not line.strip():
            close_lists()
            i += 1
            continue

        if re.fullmatch(r"\s*([-*_]\s*){3,}", line):
            close_lists()
            out.append("<hr>")
            i += 1
            continue

        heading = re.match(r"^(#{1,6})\s+(.+)$", line)
        if heading:
            close_lists()
            level = len(heading.group(1))
            text = heading.group(2).strip()
            hid = slugify(text)
            out.append(f"<h{level} id=\"{hid}\">{inline_format(text)}</h{level}>")
            i += 1
            continue

        if line.lstrip().startswith(">"):
            close_lists()
            block = []
            while i < len(lines) and lines[i].lstrip().startswith(">"):
                block.append(lines[i].lstrip()[1:].lstrip())
                i += 1
            out.append(f"<blockquote>{inline_format(' '.join(block))}</blockquote>")
            continue

        if line.strip().startswith("|") and i + 1 < len(lines) and is_table_delimiter(lines[i + 1]):
            close_lists()
            header_cells = [c.strip() for c in line.strip().strip("|").split("|")]
            i += 2
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            out.append("<table><thead><tr>" + "".join(f"<th>{inline_format(c)}</th>" for c in header_cells) + "</tr></thead><tbody>")
            for row in rows:
                while len(row) < len(header_cells):
                    row.append("")
                out.append("<tr>" + "".join(f"<td>{inline_format(c)}</td>" for c in row[:len(header_cells)]) + "</tr>")
            out.append("</tbody></table>")
            continue

        list_match = re.match(r"^(\s*)([-*+]|\d+\.)\s+(.+)$", line)
        if list_match:
            indent = len(list_match.group(1).replace("\t", "    "))
            level = indent // 2
            marker = list_match.group(2)
            text = list_match.group(3).strip()
            list_type = "ol" if marker.endswith(".") and marker[:-1].isdigit() else "ul"

            while len(list_stack) > level + 1:
                out.append(f"</{list_stack.pop()}>")
            while len(list_stack) < level + 1:
                list_stack.append(list_type)
                out.append(f"<{list_type}>")
            if list_stack and list_stack[-1] != list_type:
                out.append(f"</{list_stack.pop()}>")
                list_stack.append(list_type)
                out.append(f"<{list_type}>")

            checked = re.match(r"^\[( |x|X)\]\s+(.*)$", text)
            if checked:
                state = checked.group(1).lower() == "x"
                label = inline_format(checked.group(2))
                out.append(f"<li><input type=\"checkbox\" {'checked' if state else ''}> {label}</li>")
            else:
                out.append(f"<li>{inline_format(text)}</li>")
            i += 1
            continue

        close_lists()
        para_lines = [line.strip()]
        j = i + 1
        while j < len(lines):
            nxt = lines[j]
            if not nxt.strip():
                break
            if re.match(r"^(#{1,6})\s+", nxt):
                break
            if nxt.strip().startswith("```"):
                break
            if nxt.lstrip().startswith(">"):
                break
            if re.match(r"^(\s*)([-*+]|\d+\.)\s+", nxt):
                break
            if nxt.strip().startswith("|") and j + 1 < len(lines) and is_table_delimiter(lines[j + 1]):
                break
            if re.fullmatch(r"\s*([-*_]\s*){3,}", nxt):
                break
            para_lines.append(nxt.strip())
            j += 1
        out.append(f"<p>{inline_format(' '.join(para_lines))}</p>")
        i = j

    close_lists()
    if in_code:
        out.append("</code></pre>")
    return "\n".join(out)


def architecture_diagram_html() -> str:
    return (
        '<div class="pipeline-diagram" aria-label="Security-gate pipeline flow">'
        '<div class="pipeline-main">'
        '<div class="pipeline-step"><div class="pipeline-step-title">Input Collection</div><div class="pipeline-step-sub">Trivy JSON, stdin, context.json, policy, accepted risk file</div></div>'
        '<div class="pipeline-arrow">→</div>'
        '<div class="pipeline-step"><div class="pipeline-step-title">Ingest</div><div class="pipeline-step-sub">ingest/trivy parses scanner payloads and captures metadata</div></div>'
        '<div class="pipeline-arrow">→</div>'
        '<div class="pipeline-step"><div class="pipeline-step-title">Normalize</div><div class="pipeline-step-sub">Map to unified finding schema</div></div>'
        '<div class="pipeline-arrow">→</div>'
        '<div class="pipeline-step"><div class="pipeline-step-title">Score</div><div class="pipeline-step-sub">Compute risk_score and trust_score with provenance/trust signals</div></div>'
        '<div class="pipeline-arrow">→</div>'
        '<div class="pipeline-step"><div class="pipeline-step-title">Policy</div><div class="pipeline-step-sub">Apply noise budget, exceptions, accepted risk, and stage matrix</div></div>'
        '<div class="pipeline-arrow">→</div>'
        '<div class="pipeline-step"><div class="pipeline-step-title">Decision Trace</div><div class="pipeline-step-sub">Ordered auditable decision events</div></div>'
        '<div class="pipeline-arrow">→</div>'
        '<div class="pipeline-step"><div class="pipeline-step-title">Report</div><div class="pipeline-step-sub">Write report.json and summary.md</div></div>'
        '</div>'
        '<div class="pipeline-branch-wrap">'
        '<div class="pipeline-branch">'
        '<div class="pipeline-branch-label"><span class="pipeline-branch-arrow">↓</span>Side branch from Decision Trace</div>'
        '<div class="pipeline-step"><div class="pipeline-step-title">LLM Explanation (Optional)</div><div class="pipeline-step-sub">Consumes sanitized trace and returns non-authoritative text only</div></div>'
        '</div>'
        '<div class="pipeline-note">Deterministic boundary: LLM output never changes scoring, policy, or final decision.</div>'
        '</div>'
        '</div>'
    )


def enhance_architecture_body(body_html: str) -> str:
    section_pattern = (
        r'(<h2 id="high-level-diagram">High-Level Diagram</h2>)'
        r'(.*?)'
        r'(<h2 id="module-boundaries">)'
    )
    repl = r"\1\n" + architecture_diagram_html() + r"\n\3"
    updated, count = re.subn(section_pattern, repl, body_html, flags=re.S)
    if count:
        return updated
    return body_html


def render_html(
    title: str,
    source_name: str,
    body_html: str,
    docs_index_html: str,
    nav_html: str,
) -> str:
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{html.escape(title)}</title>
  <style>{STYLE}</style>
</head>
<body>
  <div class=\"layout\">
    <div class=\"site-header\">
      <div class=\"brand\">
        <img src=\"{LOGO_PATH}\" alt=\"solardome logo\">
        <div class=\"brand-text\">
          <div class=\"brand-app\">security-gate</div>
          <div class=\"brand-company\">solardome</div>
        </div>
      </div>
      <nav class=\"site-nav\">
{nav_html}
      </nav>
    </div>
    <div class=\"header\">
      <h1>{html.escape(title)}</h1>
      <p>Generated from {html.escape(source_name)}</p>
    </div>
    <article class=\"card\">
{docs_index_html}
{body_html}
    </article>
  </div>
</body>
</html>
"""


def build_docs_index(md_files: list[Path], current_name: str) -> str:
    if current_name != "architecture.md":
        return ""
    items = []
    for md in md_files:
        if md.name == "architecture.md":
            continue
        page_title = md.stem.replace("-", " ").title()
        m = re.search(r"^#\s+(.+)$", md.read_text(encoding="utf-8"), re.MULTILINE)
        if m:
            page_title = m.group(1).strip()
        href = md.with_suffix(".html").name
        items.append(
            f'<a class="doc-link" href="{href}">'
            f'<div class="doc-link-title">{html.escape(page_title)}</div>'
            f'<div class="doc-link-file">{html.escape(md.name)}</div>'
            "</a>"
        )
    if not items:
        return ""
    return (
        "<h2 id=\"documentation-index\">Documentation Index</h2>\n"
        "<div class=\"doc-links\">\n"
        + "\n".join(items)
        + "\n</div>\n"
    )


def build_global_nav(md_files: list[Path], current_name: str) -> str:
    links = []
    for md in md_files:
        page_title = md.stem.replace("-", " ").title()
        m = re.search(r"^#\s+(.+)$", md.read_text(encoding="utf-8"), re.MULTILINE)
        if m:
            page_title = m.group(1).strip()
        href = md.with_suffix(".html").name
        if md.name == current_name:
            links.append(f'<a href="{href}" aria-current="page">{html.escape(page_title)}</a>')
        else:
            links.append(f'<a href="{href}">{html.escape(page_title)}</a>')
    return "\n".join(links)


def main() -> None:
    md_files = sorted(DOCS_SRC_DIR.glob("*.md"))
    if not md_files:
        print("No markdown files found in docs/")
        return
    DOCS_OUT_DIR.mkdir(parents=True, exist_ok=True)

    for md_path in md_files:
        raw = md_path.read_text(encoding="utf-8")
        body = parse_markdown(raw)
        if md_path.name == "architecture.md":
            body = enhance_architecture_body(body)
        title = md_path.stem.replace("-", " ").title()
        m = re.search(r"^#\s+(.+)$", raw, re.MULTILINE)
        if m:
            title = m.group(1).strip()
        docs_index = build_docs_index(md_files, md_path.name)
        nav_html = build_global_nav(md_files, md_path.name)
        html_doc = render_html(title, md_path.name, body, docs_index, nav_html)
        out_path = DOCS_OUT_DIR / f"{md_path.stem}.html"
        out_path.write_text(html_doc, encoding="utf-8")
        print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()

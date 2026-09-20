#!/usr/bin/env python3
"""Regenerate the screenshots used in the README and docs.

Everything here is produced from a real run: the trace report is rendered by
``python3 -m ais trace``, and the terminal image contains the actual stdout of
``python3 -m ais demo``. Nothing is mocked up.

    python3 scripts/make_screenshots.py            # writes docs/assets/*.png

Requires a Chromium-family browser for the headless screenshot step; without
one, the HTML is still written and the script says what to open.
"""

from __future__ import annotations

import html
import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ASSETS = os.path.join(ROOT, "docs", "assets")
BUILD = os.path.join(ROOT, ".build", "screenshots")

sys.path.insert(0, ROOT)

CHROME_CANDIDATES = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    shutil.which("google-chrome") or "",
    shutil.which("chromium") or "",
    shutil.which("chromium-browser") or "",
)

TERMINAL_STYLE = """
:root { --bg:#f6f7f9; --chrome:#ffffff; --line:#e5e7eb; --ink:#111827; }
* { box-sizing: border-box; }
body { margin:0; padding:28px; background:var(--bg);
  font:14px/1.5 ui-sans-serif,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif; }
.window { max-width:1180px; margin:0 auto; background:var(--chrome); border:1px solid var(--line);
  border-radius:12px; overflow:hidden; box-shadow:0 1px 2px rgba(15,23,42,.05),0 12px 32px rgba(15,23,42,.08); }
.bar { display:flex; align-items:center; gap:8px; padding:11px 14px; border-bottom:1px solid var(--line);
  background:#fbfbfc; }
.dot { width:11px; height:11px; border-radius:50%; }
.r{background:#ff5f57}.y{background:#febc2e}.g{background:#28c840}
.bar .title { margin-left:8px; font-size:12.5px; color:#6b7280;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
pre { margin:0; padding:20px 22px 24px; color:var(--ink); background:var(--chrome);
  font:12.6px/1.62 ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace; white-space:pre; overflow:hidden; }
.k { color:#047857; font-weight:600; }
.d { color:#b91c1c; font-weight:600; }
.h { color:#6d28d9; font-weight:600; }
.s { color:#1d4ed8; }
.m { color:#6b7280; }
.rule { color:#94a3b8; }
"""


def _highlight(line: str) -> str:
    escaped = html.escape(line)
    if set(line.strip()) == {"="} and line.strip():
        return f'<span class="rule">{escaped}</span>'
    for token, css in (
        ("DENIED", "d"), ("DENY", "d"), ("*** OPEN ***", "d"),
        ("HANDLED", "k"), ("ALLOW", "k"), ("True", "k"),
        ("HOLD", "h"), ("ESCALATE", "h"),
    ):
        if token in line:
            escaped = escaped.replace(token, f'<span class="{css}">{token}</span>')
    if escaped.lstrip().startswith("·"):
        escaped = f'<span class="m">{escaped}</span>'
    return escaped


def terminal_html(command: str, output: str, *, max_lines: int = 46) -> str:
    lines = [line.rstrip() for line in output.splitlines()]
    body = "\n".join(_highlight(line) for line in lines[:max_lines])
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(command)}</title>
<style>{TERMINAL_STYLE}</style></head><body>
<div class="window">
  <div class="bar"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
    <span class="title">{html.escape(command)}</span></div>
  <pre>{body}</pre>
</div></body></html>"""


def find_browser() -> str | None:
    for candidate in CHROME_CANDIDATES:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def shoot(browser: str, source: str, target: str, width: int, height: int) -> bool:
    command = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--force-device-scale-factor=2",
        "--virtual-time-budget=2500",
        f"--window-size={width},{height}",
        f"--screenshot={target}",
        f"file://{source}",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode != 0 or not os.path.exists(target):
        print(f"  ! screenshot failed for {os.path.basename(target)}: {result.stderr.strip()[:200]}")
        return False
    print(f"  ✓ {os.path.relpath(target, ROOT)} ({os.path.getsize(target) // 1024} KB)")
    return True


def build_pages() -> list[tuple[str, str, int, int]]:
    """Write the HTML sources, returning (source, target, width, height) tuples."""
    from ais.observatory.trace import build_trace, to_html
    from ais.simulation.scenarios import run_key_experiment, run_learning_adversary_experiment

    os.makedirs(BUILD, exist_ok=True)
    os.makedirs(ASSETS, exist_ok=True)
    pages: list[tuple[str, str, int, int]] = []

    print("· running the key experiment for the trace report")
    ecosystem = run_key_experiment()["ecosystem"]
    trace = build_trace(ecosystem.plane, ecosystem.observatory, ecosystem.immune)
    report = os.path.join(BUILD, "trace.html")
    with open(report, "w", encoding="utf-8") as handle:
        handle.write(
            to_html(
                trace,
                title="Agent lifecycle trace",
                subtitle=f"AGENT-A drifted, was verified independently, contained and revoked · "
                f"{trace['counts']['decisions']} decisions · {trace['counts']['audit_records']} audit records",
            )
        )
    pages.append((report, os.path.join(ASSETS, "trace-report.png"), 1360, 1180))

    print("· capturing the demonstration output")
    demo = subprocess.run(
        [sys.executable, "-m", "ais", "demo"], capture_output=True, text=True, cwd=ROOT, timeout=600
    )
    demo_page = os.path.join(BUILD, "demo.html")
    with open(demo_page, "w", encoding="utf-8") as handle:
        handle.write(terminal_html("python3 -m ais demo", demo.stdout, max_lines=44))
    pages.append((demo_page, os.path.join(ASSETS, "demo-output.png"), 1420, 940))

    print("· capturing the learning-adversary comparison")
    learning = run_learning_adversary_experiment()
    lines = [
        "$ python3 -m ais experiment learning-adversary",
        "",
        "                                   naive        learner",
        f"  retries of denied capabilities   {learning['adaptation']['retries_of_denied_capabilities']['naive']:<12} {learning['adaptation']['retries_of_denied_capabilities']['learner']}",
        f"  denial ratio                     {learning['adaptation']['denial_ratio']['naive']:<12} {learning['adaptation']['denial_ratio']['learner']}",
        f"  steps to verified detection      {learning['naive']['time_to_detection_steps']:<12} {learning['learner_defended']['time_to_detection_steps']}",
        f"  evasion gain                     {'':<12} +{learning['adaptation']['evasion_gain_steps']} steps",
        "",
        f"  real unauthorized effects        {len(learning['enforcement']['naive_real_effects']):<12} {len(learning['enforcement']['learner_real_effects'])}",
        f"  prevention rate                  {learning['enforcement']['prevention_rate']['naive']:<12} {learning['enforcement']['prevention_rate']['defended']}",
        f"  invariants clean                 {str(learning['enforcement']['invariants_ok']['naive']):<12} {learning['enforcement']['invariants_ok']['defended']}",
        "",
        f"  converged strategy               {learning['adaptation']['converged_strategy']}",
        f"  caught after convergence by      {'relationship analysis' if learning['adaptation']['collusion_signals_after_convergence'] else 'nothing'}",
        "",
        "  Adaptation buys detection latency, not authority.",
    ]
    learning_page = os.path.join(BUILD, "learning.html")
    with open(learning_page, "w", encoding="utf-8") as handle:
        handle.write(terminal_html("python3 -m ais experiment learning-adversary", "\n".join(lines), max_lines=40))
    pages.append((learning_page, os.path.join(ASSETS, "learning-adversary.png"), 1080, 430))
    return pages


def main() -> int:
    pages = build_pages()
    browser = find_browser()
    if browser is None:
        print("\nNo Chromium-family browser found; HTML written but not rendered:")
        for source, _, _, _ in pages:
            print(f"  open {source}")
        return 1
    print(f"\n· rendering with {os.path.basename(browser)}")
    ok = all(shoot(browser, source, target, width, height) for source, target, width, height in pages)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

# PLC Lint — static analysis for CODESYS / PLCopenXML

**Upload a PLC project export, get a quality report in ~10 seconds.**

Your project compiles clean and still ships with an uncalled timer, a truncated
setpoint, or a divide-by-a-variable-that's-sometimes-zero. The compiler doesn't
catch it — the syntax is valid. PLC Lint does.

👉 **Try it free (no signup): [plc-linter.com](https://plc-linter.com)** &nbsp;·&nbsp; **Or run it locally: [plc-lint.exe](https://github.com/caspershes/plc-lint/releases/latest)**
&nbsp;·&nbsp; **Live sample report: [plc-linter.com/demo](https://plc-linter.com/demo)**

> **Run it locally — nothing leaves your machine.** Windows: grab
> [`plc-lint.exe`](https://github.com/caspershes/plc-lint/releases/latest) and drop your
> export onto it. Anywhere else: `python cli.py project.xml`. No install, no dependencies,
> **no network calls at all** — that last part is enforced by a test, not by a promise
> ([`tests/cli_local.py`](tests/cli_local.py) runs the whole analysis with `socket` replaced
> by one that raises). The hosted version at [plc-linter.com](https://plc-linter.com) is the
> same engine with sharing, history and certificates on top.

---

## What it eats

Any **PLCopenXML** export (`tc6_0200`, PLCopen TC6 — the vendor-neutral
IEC 61131-3 format):

- **CODESYS 3.5** (`Project → Export PLCopenXML`)
- **TwinCAT3** (Beckhoff — same engine, same namespace)
- **WAGO e!COCKPIT, Schneider EcoStruxure Machine Expert, OWEN, Weintek** and
  the 500+ environments built on the CODESYS 3.5 runtime

## What it catches

Real findings from 8 real boiler-house projects (CODESYS 3.5 SP17, scores 62–86/100):

| Class | Example | Why the compiler misses it |
|---|---|---|
| Uncalled timer/trigger | `TOF` whose `.Q` is used but the block is never called | valid syntax, dead behavior |
| Setpoint truncation | `REAL_TO_TIME(x) * 1000` | truncates before the multiply |
| Divide by zero | `10 / iAlarm` where `iAlarm` can be 0 | runtime fault, not compile-time |
| Unreachable branch | broken `IF/ELSIF` thresholds | logic bug, compiles fine |
| Watchdog disabled | `Watchdog Enabled="false"` on every task | config, not code |
| Copy-paste rungs | renamed duplicate control loops | structural, invisible to `diff` |

Plus hygiene: magic numbers, dead POUs, bloated routines, missing comments,
naming-standard profiles, device/IO-mapping summary.

**All 37 rules, with what each one reads and how to fix it: [RULES.md](RULES.md).**
A known-bad project you can upload yourself, with every expected finding listed:
[examples/](examples/).

## Run it on your own machine

Your customer's export is their intellectual property, and sending it to somebody else's
server is rarely your call — it's company policy or a clause in the NDA. So don't.

**Windows, no Python:** download `plc-lint.exe` from
[Releases](https://github.com/caspershes/plc-lint/releases/latest), drag your `.xml` onto it.
An HTML report appears next to the file and opens in your browser.

**Anywhere with Python 3.9+:** no dependencies, the engine is standard library only.

```
python cli.py project.xml                # report in the console + HTML next to the file
python cli.py exports/ --no-html         # a whole folder at once
python cli.py p.xml --json > report.json # machine-readable, for a build pipeline
python cli.py p.xml --fail-on high       # exit code 1 if there are high-severity findings
python cli.py p.xml --profile heating    # optional rule profiles: heating, plcopen-naming
```

The report is identical to the hosted one — same 37 rules, same engine file. What the
hosted version adds: sharing a link, history across builds, diffs between two exports,
the acceptance protocol and the signed certificate.

### In CI

If your PLC project lives in git, the export can be checked on every push. There's a
GitHub Action in this repository:

```yaml
- uses: actions/checkout@v4
- uses: caspershes/plc-lint@v1
  with:
    path: exports/          # files, globs or a directory
    fail-on: high           # break the build on high-severity findings
```

The results land on the job summary page as a table, high-severity findings become
annotations, and the run is still entirely local — the analyzer runs on the runner and
makes no network calls.

| input | default | |
|---|---|---|
| `path` | `.` | files, globs or directories (space-separated) |
| `fail-on` | `high` | `high` / `medium` / `low` / `none` |
| `profile` | — | `heating`, `plcopen-naming` (comma-separated) |
| `lang` | `en` | `en` or `ru` |
| `html` | `false` | also produce HTML reports and upload them as an artifact |

Outputs: `score`, `high`, `medium`, `low`, `files`, `json` — so you can gate a merge on
the score rather than on severity:

```yaml
- id: lint
  uses: caspershes/plc-lint@v1
  with: { path: exports/, fail-on: none }
- run: test "${{ steps.lint.outputs.score }}" -ge 70
```

Without GitHub, the exit code does the same job anywhere:

```yaml
- run: python cli.py exports/*.xml --fail-on high --no-html
```

## What's in this repository

| | |
|---|---|
| `engine.py` | the analyzer: parser + all 37 rules |
| `i18n.py` | rule titles, explanations and fixes (EN/RU) |
| `cli.py` | local runner: console + HTML + JSON |
| `action.yml` | GitHub Action: the same analysis inside a CI pipeline |
| `ci/summary.py` | turns the JSON report into the Actions job summary |
| `tests/cli_local.py` | proves the local run never touches the network |
| `examples/` | a known-bad project with every expected finding listed |
| `RULES.md` | the full rule reference, generated from the engine |

MIT licensed. Fork it, vendor it, wire it into your own pipeline.

## Honest limits (because trust is the whole point)

- **ST** is analyzed line-by-line.
- **Graphical languages (CFC/LD/FBD/SFC)** are covered by **name occurrence** plus
  a couple of precise graph checks (literal-0 divisor in DIV/MOD). Graphical
  **logic is not analyzed** — and the report says so, per project.
- It's **static analysis**. It does **not** replace commissioning, FAT, or checking
  logic against the spec. It catches classes of mistakes; it doesn't prove correctness.

## The certificate

A paid tier turns a report into a **verified quality certificate** (PDF) with a public
`/verify/<token>` link and an embeddable badge — for handovers and FAT packages.
The analysis and the full report are always free.

## Feedback wanted

False positives especially. If it's noisy on your project, that's what gets tuned.
Open an issue with the rule + a minimal snippet (no proprietary code needed), or use
the in-app feedback form.

---

🇷🇺 **Русская версия:** [plc-linter.ru](https://plc-linter.ru)

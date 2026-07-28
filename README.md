# PLC Lint — static analysis for CODESYS / PLCopenXML

**Upload a PLC project export, get a quality report in ~10 seconds.**

Your project compiles clean and still ships with an uncalled timer, a truncated
setpoint, or a divide-by-a-variable-that's-sometimes-zero. The compiler doesn't
catch it — the syntax is valid. PLC Lint does.

👉 **Try it free (no signup for one analysis): [plc-linter.com](https://plc-linter.com)**
&nbsp;·&nbsp; **Live sample report: [plc-linter.com/demo](https://plc-linter.com/demo)**

> This repo is a showcase (docs, examples, rule reference). The analyzer runs as a
> hosted service — the upload is processed in memory and your code is not stored.

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

**All 29 rules, with what each one reads and how to fix it: [RULES.md](RULES.md).**
A known-bad project you can upload yourself, with every expected finding listed:
[examples/](examples/).

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

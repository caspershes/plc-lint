# Examples

## `synthetic_bugs.xml` — a known-bad project

A tiny hand-written PLCopenXML project (4 POUs, ~90 lines) with typical mistakes planted
on purpose. No customer code in it. It is the analyzer's own regression fixture: the rules
that stay quiet on healthy projects are kept under test here, so a change that silently
breaks one of them fails the snapshot.

**Try it:** upload it at **[plc-linter.com](https://plc-linter.com)** — one analysis needs no
signup. You'll get the same report you'd get for a real export, on an input whose answers
are printed below.

**Score: 0/100.** That's the point — it's four POUs and nothing but bugs. Real projects
land in the 60–90 range; the score divides the penalty by POU count, and here there's no
healthy code to dilute anything.

### What's planted, and what the analyzer says

**High (7)**

| Rule | Where | Finding |
|---|---|---|
| `array-bounds` | `Main:1` | `arr[5]` out of bounds `[0..3]` |
| `broken-implicit-check` | `CheckBounds` | no lower/upper comparison — the value is not clamped; the guard exists but doesn't guard |
| `cfc-div-zero` | `CfcDiv` | the divisor of the DIV block is wired to a literal `0` (found through the CFC connection graph, not the text) |
| `div-by-zero` | `DivZeroVar:1` | division by `znever` — declared, never assigned, so it holds its `0` init value |
| `div-by-zero` | `Main:2` | division by a literal zero |
| `infinite-loop` | `Main:11` | `WHILE TRUE` with no `EXIT`/`RETURN` |
| `undeclared-global` | `Main` | `gvl.Missing` — no such name in the GVL (a typo) |

**Medium (9)**

| Rule | Where | Finding |
|---|---|---|
| `div-by-zero` | `DivZeroVar:3` | `zcond` is assigned `0` on one branch and there's no `<> 0` guard — *possible*, so medium, not high |
| `case-without-else` | `Main:8` | `CASE` with no `ELSE` — unhandled selector values silently do nothing |
| `empty-branch` | `Main:7` | `IF c THEN END_IF` |
| `int-division` | `Main:3` | `iq := iSum / 10` — INT dividend, the fraction is dropped |
| `self-assignment` | `Main:6` | `x := x;` |
| `timer-zero-pt` | `Main:4` | `t1(IN := c, PT := T#0S)` — a timer with no delay |
| `implicit-check-disabled` ×3 | project | no active check function for division-by-zero / range / pointer categories |

**Low (7)** — 3 × `dead-pou`, 4 × `naming` (single-character names `x`, `d`, `c`).

### Two things worth noticing

**Severity tracks certainty, not just consequence.** Both `div-by-zero` findings are the
same crash. The one where the divisor is provably zero is high; the one where it's zero on
*a* branch is medium, because your code may make that branch unreachable in ways static
analysis can't see.

**`Main` is reported as `dead-pou` here — and that's correct for this file.** The fixture
has no task configuration, so nothing calls `Main`. In a real export, programs assigned to
a task (`<pouInstance>`) are entry points and are not reported, whatever they're named.

### Reproducing the numbers

The findings above are what the current analyzer produces. If you upload the file and get
something different, the rule set has moved on — [`RULES.md`](../RULES.md) is generated from
the live catalogue and is the source of truth.

---

## Your own project

`Project → Export PLCopenXML` in CODESYS 3.5 (TwinCAT3, WAGO, EcoStruxure, OWEN: same
format, same menu). Upload the `.xml`. It's parsed in memory and not written to disk.

Found a false positive? That's the most useful thing you can send:
open an issue with the rule id and a minimal snippet — no proprietary code needed.

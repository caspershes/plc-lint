# PLC Lint — rule reference

**29 checks.** Each entry says what it reads and how to fix it. Run them on your own export at [plc-linter.com](https://plc-linter.com) — or on the [example project](examples/).

Severity: 🔴 high · 🟠 medium · ⚪ low.

## 🔴 High (9)

### `array-bounds` — Array index out of bounds
**Reads:** A constant index falls outside the declared ARRAY[lo..hi] bounds — reaching this line reads/writes memory that isn't yours. Without active implicit checks the runtime won't intercept it. Checked for one-dimensional arrays with numeric bounds and a literal index.

**Fix:**
- Bring the index into the declared range or widen the array bounds.
- Check before access: `IF idx >= LO AND idx <= HI THEN arr[idx] … END_IF`

### `broken-implicit-check` — Implicit check does not protect
**Reads:** An implicit check function (Check…) exists, but its protective logic is gutted: an empty body, or the check (divisor=0 / bounds) removed. The runtime calls it, but it catches nothing — a false sense of safety, more dangerous than its absence.

**Fix:**
- Restore the protective logic: `CheckDivReal` must test `IF divisor = 0 THEN … := 1;`
- `CheckBounds`/`CheckRange…` must clamp the value to `lower..upper`. Compare with the default CODESYS implementation.

### `cfc-div-zero` — CFC: division by a literal zero
**Reads:** In graphical code (CFC/FBD) the divisor of a DIV/MOD block is wired to a literal constant 0 — a runtime exception when the block executes. Checked against the connection graph.

**Fix:**
- Wire a variable/setpoint into the divisor input instead of the literal 0 — usually a debug stub left behind.
- If the divisor can go to zero at runtime — pick a safe value before DIV/MOD (a SEL on a compare-with-0).

### `div-by-zero` — Division by a literal zero
**Reads:** Division or MOD by a literal zero — a guaranteed runtime exception (division by zero) whenever this line is reached.

**Fix:**
- Remove the division by 0 — probably a typo in the divisor.
- If the divisor can be zero dynamically — guard it: `IF d <> 0 THEN r := x / d; END_IF`

### `infinite-loop` — Infinite loop with no exit
**Reads:** WHILE TRUE / REPEAT … UNTIL FALSE with no EXIT or RETURN inside — the scan never finishes: the task blocks and the watchdog fires (and if the watchdog is off, the controller stalls). In a PLC, long processing is spread across scans, not spun in a loop.

**Fix:**
- Add an exit condition and `EXIT`, or bound it with an iteration counter.
- Split heavy processing across scans — an infinite loop trips the task watchdog.

### `modbus-address-duplicate` — Duplicate Modbus address on modules
**Reads:** Two or more modules are assigned the same Modbus address (IP:port#unit) — a conflict on the bus: their exchange will be incorrect. Checked against leaf I/O modules.

**Fix:**
- Assign each module a unique address (IP or Unit-ID) in the device configuration.
- Cross-check the network address map — an address must be unique on one bus.

### `uncalled-timer` — Uncalled timer/trigger
**Reads:** A timer/trigger instance is read (.Q/.ET) or written (.IN), but the FB itself is never called name(...) — it never ticks, the output stays in its initial state.

**Fix:**
- Call the timer every scan before reading its output: `tmr(IN := cond, PT := T#5S); IF tmr.Q THEN …`

### `undeclared-global` — Global name typo (gvl.*)
**Reads:** A gvl.<name> reference has no declaration in the GVL — almost always a typo; the variable is silently created or the code won't compile.

**Fix:**
- Check the spelling against the GVL declaration (case, underscores, digits).
- If the variable is really needed — add it to the GVL with a type and a comment.

### `unreachable-branch` — Unreachable IF/ELSIF branch
**Reads:** IF x<T … ELSIF x>=T … — the second branch covers the whole remaining range, so the following ELSIF branches never execute (a classic weather-curve mistake).

**Fix:**
- Order the thresholds ascending with non-overlapping ranges: `IF x < T1 THEN … ELSIF x < T2 THEN … ELSE …`
- Replace the ELSIF chain with an array of curve points and interpolation.

## 🟠 Medium (10)

### `case-without-else` — CASE without an ELSE branch (no default)
**Reads:** CASE without an ELSE branch: if the selector takes a value not among the labels, nothing runs — a silent skip (a common state-machine bug).

**Fix:**
- Add an `ELSE` branch with default handling (signal/log/safe state).
- If all selector values are truly covered — keep `ELSE` with an explanatory comment.

### `empty-branch` — Empty IF/loop branch
**Reads:** An IF/ELSIF/ELSE branch or a loop body is empty (`THEN END_IF`, `DO END_FOR`) — the logic was either never written or cut out during an edit and the construct left behind.

**Fix:**
- Fill the branch with logic or remove the empty IF/loop.
- If empty on purpose — leave an explanatory comment.

### `implicit-check-disabled` — Check present but not active
**Reads:** A check function exists in the project but is not active: either not registered (no CheckFunction tag — the runtime never calls it), or an entire category (bounds/division/range/pointers) has no active check.

**Fix:**
- Regenerate the POUs for Implicit Checks via the standard CODESYS dialog — that gives the check its `CheckFunction` registration so the runtime calls it.
- Add the missing category (bounds/division/range/pointer) via `Add Object → POUs for Implicit Checks`.

### `int-division` — Integer division (lost fraction?)
**Reads:** Dividing an integer by an integer constant drops the fraction. Use /N.0 or *_TO_REAL if precision matters.

**Fix:**
- Cast to REAL: `r := INT_TO_REAL(x) / N.0;`
- Or divide by a real constant: `x / 10.0` instead of `x / 10`.

### `missing-implicit-checks` — No POUs for implicit checks (runtime guards)
**Reads:** The project has no implicit check functions (CheckBounds, CheckDivReal, CheckRange…, CheckPointer). They are added manually; without them the runtime does NOT intercept array-bounds overruns, division by zero, etc. — instead of graceful handling you get an exception or memory corruption.

**Fix:**
- Add the object: in CODESYS right-click Application → `Add Object → POUs for Implicit Checks`, tick the ones you need (Bounds, Division, Range, Pointer).
- Make sure the implementation isn't empty — the default stubs protect, an empty body doesn't.

### `real-to-time-mul` — REAL_TO_TIME(...)*N — setpoint truncation
**Reads:** REAL_TO_TIME treats the number as milliseconds and truncates the fraction before conversion — fractional time setpoints are lost. Multiply before REAL_TO_TIME.

**Fix:**
- Multiply BEFORE the conversion: `T := REAL_TO_TIME(sec * 1000.0);`
- Or: `T := DINT_TO_TIME(REAL_TO_DINT(sec * 1000.0));`

### `real-to-word-mul` — REAL_TO_WORD(...)*N — WORD overflow?
**Reads:** WORD is limited to 0..65535 — make sure the product doesn't overflow.

**Fix:**
- Check the range; if the product can exceed 65535 — use DWORD/UDINT.

### `self-assignment` — Assignment of a variable to itself
**Reads:** A line like `x := x;` — assigning a variable to itself does nothing. Usually a typo on the right-hand side (another variable was meant) or a leftover from deleted logic.

**Fix:**
- The right-hand side probably should be another variable (typo) — check the intent.
- If the line is redundant — remove it.

### `timer-zero-pt` — Timer with zero delay (PT := T#0)
**Reads:** PT is set to zero (T#0S) — the timer fires in the same scan, effectively no delay. Usually a forgotten or wrong time setpoint.

**Fix:**
- Set a non-zero delay: `tmr(IN := cond, PT := T#5S);`
- If no delay is needed — remove the timer and act on the condition directly.

### `watchdog-disabled` — Task watchdog disabled
**Reads:** A cyclic task has its watchdog disabled. If the scan overruns or hangs (e.g. a long cycle), the controller won't restart the task automatically — especially important for the main control task.

**Fix:**
- Enable the task watchdog: in the task configuration tick Watchdog and set the time (usually a multiple of the cycle, e.g. 100 ms for a 10 ms cycle).
- At least for the main control task — visualization/cloud tasks can go without one.

## ⚪ Low (10)

### `copy-paste` — Duplicated logic block (copy-paste)
**Reads:** Structurally identical blocks (even with renamed tags) are a source of bugs: a fix in one place is forgotten in the others, and copy-pasting someone else's loop drags along its gating flags. A candidate for a shared parameterised FB.

**Fix:**
- Create one FUNCTION_BLOCK with input parameters (setpoints, loop tags) and instantiate it per loop.
- For per-channel repeats — a FOR loop over an array of structures.

### `dead-pou` — Dead code — POU is never called
**Reads:** The POU is never called and never used as a type — dead code or a forgotten name change (check against the spec before deleting).

**Fix:**
- Not needed — delete the POU.
- A forgotten version — check the call name against the spec, possibly a typo in the name.

### `deep-nesting` — Deep IF nesting
**Reads:** Deeply nested IFs are hard to read and easy to get wrong. A sign the block should be simplified (early exits, guards) or part of it extracted into a separate FB/method.

**Fix:**
- Invert the conditions and use early exits (`RETURN`/`CONTINUE`) instead of nesting.
- Extract the inner levels into a separate FUNCTION_BLOCK or method.

### `double-semicolon` — Double `;;` (empty statement)
**Reads:** A stray empty statement `;;` — harmless, but a trace of a sloppy edit.

**Fix:**
- Remove the extra `;`.

### `magic-number` — Magic number — raw constant in code
**Reads:** A large/fractional raw constant without a name — easy to miss when changing a setpoint and hard to understand. Move it to a VAR CONSTANT. Array indices, FOR bounds and small integers (<16) don't count; equal constants are grouped by value.

**Fix:**
- Declare a named constant and use it: `VAR CONSTANT SEC_PER_HOUR : UDINT := 3600; END_VAR`

### `missing-comments` — POU without a single comment
**Reads:** A POU with substantial logic and not a single comment — a nightmare when troubleshooting six months later. At least a purpose header and notes on the non-obvious parts.

**Fix:**
- Add a POU purpose header and comments on setpoints/guards and non-obvious parts.

### `naming` — Cryptic variable name
**Reads:** Single-character names (other than counters i/j/k/n) are unreadable during maintenance. I/O tags and FB pins are left alone.

**Fix:**
- Give it a meaningful name by purpose (e.g. `iRetryCount` instead of `n`).

### `plcopen-naming` — Name off the PLCopen standard
**Reads:** PLCopen standard: a variable name starts with a type prefix (BOOL→x, INT→i, REAL→r, DINT→di, TIME→t, WORD→w …). An optional conformance check.

**Fix:**
- Rename by the prefix table: `value : REAL` → `rValue`, `cnt : INT` → `iCnt`.
- If you don't need PLCopen naming — just don't enable this profile.

### `routine-size` — Bloated routine (decomposition candidate)
**Reads:** An overly long routine is hard to read and edit. Extract the repeated logic into a FUNCTION_BLOCK — shorter and reusable.

**Fix:**
- Extract the repeated parts into a parameterised FUNCTION_BLOCK.
- Split by zones (control / protections / metering) into separate FBs or methods.

### `unused-local` — Unused local variable
**Reads:** A local variable is declared in VAR but never appears in the POU body or its actions/methods — a leftover from deleted logic, or a typo in the body (in which case a different variable is doing the work).

**Fix:**
- Remove the unused declaration.
- Or wire the variable into the logic if it was forgotten.

# PLC Lint — rule reference

**36 checks.** Each entry says what it reads and how to fix it. Run them on your own export at [plc-linter.com](https://plc-linter.com) — or on the [example project](examples/).

Severity: 🔴 high · 🟠 medium · ⚪ low.


## 🔴 High (15)

### `always-false-condition` — Condition can never be true
**Reads:** A condition that becomes identically false (or identically true) once same-scan assignments are substituted. The classic shape: one program derives a command from a sensor, another checks the alarm “command present but sensor absent” — substitution turns it into `NOT X AND X`, i.e. FALSE for any X. The alarm physically cannot fire: it is listed in the log, but there is no protection. The eye does not catch it because the assignment and the check live in different POUs, with the PLC_PRG call order between them. The rule substitutes only what is known for certain within the scan: the assignment must cover every execution path, and the source program must be called earlier. If a variable is assigned in several branches, every value is substituted and the rule fires only when the result is constant for all of them.

**Fix:**
- Take the command from a source other than the signal being checked: the alarm “command present, sensor absent” only works when the command does not contain that sensor as a factor.
- Check the intermediate variable as well, not just the final expression: the same defect came back a second time in the same place through a one-line edit of the source.

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

### `family-gap` — Channel never written — gap in a channel family
**Reads:** A field is declared for every channel in a family (boilers 1–4, pumps 1–3) and used by all of them but exactly one, where it is never written. The usual cause: the block was copied from a neighbouring channel and left unfinished. The compiler stays silent — the variable exists and the type is right, nobody just writes to it. On site this shows up as “boiler 4 never reports alarms” while the other three work, and it never reproduces on the bench. The rule relies on declarations: if the field is not declared for that channel, it is different hardware rather than a gap, and nothing is reported.

**Fix:**
- Check that channel's block: an assignment was most likely copied from the neighbour and kept its indexes — `gvl.kotel_3_alarms3 := ...` instead of `gvl.kotel_4_alarms3 := ...`.
- If the field genuinely does not apply to that channel (no such hardware), drop its declaration — the rule goes quiet and the GVL loses a dead variable.

### `heating-ai-no-range-check` — Analog input without a plausibility check
**Reads:** A value coming from an analog input (or a raw register) is never compared against a range anywhere in the project. On a broken or shorted sensor the input returns an extreme value and it travels into the controller as valid data: a broken Pt1000 reads as 0 °C and the valve opens fully. Inputs are taken from the device tree (nothing assigns them in code — the runtime does). A check means either a range comparison anywhere in the project or a read of the module's own channel error code (`error_analog_code` and the like) — the latter is in fact stronger: a broken or shorted sensor is caught by the hardware. If plausibility is handled in a way static analysis cannot see (the HMI), verify before treating this as a defect.

**Fix:**
- Compare the value with the sensor's physical range right after scaling: `IF T_out < -50.0 OR T_out > 150.0 THEN bSensorFault := TRUE; END_IF`
- While the reading is invalid, substitute a safe value (the last valid one, or a setpoint) instead of the raw one — a frozen plant usually starts with “0 °C outside”.
- If plausibility is handled by a separate alarm FB or by the HMI, the rule cannot see it — disable it in /rules or mark it as noisy.

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

### `param-channel-mismatch` — Channel parameter fed from another channel
**Reads:** In a function block call the parameter name refers to one channel while the value comes from another: `bPump2_Fault := gvl.alarm_nasos_CO1`. The rule fires only when channel numbering is proven within the same call — consistent pairs exist for at least two channels. The consequence is quiet and dangerous: a faulty pump is treated as healthy and picked for duty, the interlock never fires, and the log looks perfectly normal.

**Fix:**
- Fix the index in the value: `bPump2_Fault := gvl.alarm_nasos_CO2`.
- Repeated per-channel calls are better folded into a loop over an array (`FOR i := 1 TO 3 DO fb[i](...)`) — then there is nothing left to renumber.

### `self-enable` — Command depends on its own feedback
**Reads:** A start command is derived from a function block output that is computed from its own input within the same scan, while that input is fed with the equipment's own feedback: pump rotation, valve position, “unit running”. The result is a deadlock — the equipment is stopped, so there is no permission, so there is no command, so it stays stopped. The loop never starts, and on a bench with the drive spun by hand everything looks fine. The phrase “within the same scan” is what matters: an output that depends on the input through memory (a start counter, a timer, an edge trigger) is perfectly legitimate in the command chain, and the rule leaves it alone.

**Fix:**
- Feed the STATE output into the command instead of a permission output that contains the input itself: `NOT bProtBlocked1` rather than `bStartAllow`. The protection keeps working — the start-count lockout is unaffected.
- Check what is wired to the block input: the start command and the running feedback are different signals, and swapping one for the other only shows up on site.

### `timer-reset-by-own-condition` — Timer cleared by its own run condition
**Reads:** A timer counts on a variable that is cleared on every path further down the same branch. Scan N: the input is TRUE, counting starts, the variable is dropped. Scan N+1: the input is already FALSE, the timer is reset together with the accumulated time, and the condition that was waiting for the delay is open. The pause lasts one task cycle instead of the setpoint — on a live site that was 0.01 s against the 30 s configured. The code compiles, reads as correct, the setpoint is on the screen, the operator adjusts it, and it changes nothing. The rule looks at the branch tree, not at adjacent lines: a reset under a condition (`IF T.Q THEN V := FALSE`) is the normal one-shot pattern, the timer does complete its delay, and such code is left alone.

**Fix:**
- Separate “what we time” from “what we clear”: arm the timer from a dedicated hold flag (`switching`) that is set when the switchover starts and cleared on `T.Q`, and feed the run condition from that flag.
- Verify the delay on site by measurement, not by reading the code: a pause like this expires in one task cycle, and on the screen it looks like an instant switchover at any setpoint.

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


## 🟠 Medium (11)

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

### `index-mismatch` — Line indexes differently from its group
**Reads:** Across a group of similar lines the relation between index positions holds nearly everywhere but is broken in one line: eleven lines write to their own channel, the twelfth writes to someone else's. That is what a copied neighbouring branch with partial renumbering looks like. The rule does not compare whole lines: numbers from different dimensions (boiler number and alarm block number) coincide routinely, and that case is accounted for. This is a heuristic — before changing anything, check whether the line is a deliberate exception.

**Fix:**
- Compare the line with its neighbours in the group: usually the destination was not renumbered — `w_cascadK4 := r_cascadK4` instead of `w_cascadK3 := r_cascadK4`.
- If the line is a deliberate exception, put a comment next to it — that saves the next reader (and you in six months) an investigation.

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

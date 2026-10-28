#!/usr/bin/env python3
"""Матрица ФБ с памятью: эмулятор против движка, клетка за клеткой.

Здесь нет вписанных руками ожиданий. Каждая клетка исполняется эмулятором
скана (tools/scan_emu.py), и его замер решает, дефект это или норма:
  * таймер — дошло ли накопленное время до уставки хоть при каком-то
    поведении входов;
  * детектор фронта — сработал ли он на каждый переход входа;
  * счётчик — дошло ли накопленное до уставки и не насчитал ли он лишнего.
Движок обязан совпасть: сказал эмулятор «сломано» — должна быть находка,
сказал «работает» — находок быть не должно.

Зачем так. Ожидания, записанные руками, защищают от сегодняшней ошибки, но не
от завтрашней: правило поправят, оно заденет законный приём, а тест этого не
заметит, потому что число находок не изменится. Прибор же судит заново каждый
раз и ловит расхождение сам.

Запуск: .venv/bin/python tests/scan_matrix.py
"""
import os
import sys
import tempfile
import xml.sax.saxutils as sx

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))

import engine  # noqa: E402
import scan_emu  # noqa: E402

fail = 0


def check(cond, what):
    global fail
    print(("  OK   " if cond else "  ПРОВАЛ ") + what)
    if not cond:
        fail += 1


XML = """<?xml version="1.0" encoding="utf-8"?>
<project xmlns="http://www.plcopen.org/xml/tc6_0200"><types><pous>
<pou name="cell" pouType="functionBlock"><interface>
<inputVars>
<variable name="a"><type><BOOL/></type></variable>
<variable name="b"><type><BOOL/></type></variable>
</inputVars>
<outputVars><variable name="out"><type><BOOL/></type></variable></outputVars>
<localVars>
<variable name="t"><type><derived name="%s"/></type></variable>
<variable name="v"><type><BOOL/></type></variable>
</localVars></interface>
<body><ST><xhtml xmlns="http://www.w3.org/1999/xhtml">%s</xhtml></ST></body>
</pou></pous></types><instances><configurations/></instances></project>"""


def engine_finds(kind, code, inst="t"):
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as fh:
        fh.write(XML.replace('name="t"', f'name="{inst}"') % (kind, sx.escape(code)))
        path = fh.name
    try:
        rep = engine.analyze(path)
    finally:
        os.unlink(path)
    return sorted({f.rule for f in rep.findings
                   if f.rule.startswith(("timer-", "fb-", "edge-"))
                   and f.rule != "timer-zero-pt"})


TIMER_ROWS = {
    "не трогают вход": "t(IN := v, PT := T#5S);\nout := t.Q;",
    "гасят на всех путях": """t(IN := v, PT := T#5S);
IF t.Q THEN
    out := TRUE;
    v := FALSE;
ELSE
    out := FALSE;
    v := FALSE;
END_IF""",
    "взводят на всех путях": """t(IN := v, PT := T#5S);
IF t.Q THEN
    out := TRUE;
    v := TRUE;
ELSE
    out := FALSE;
    v := TRUE;
END_IF""",
    "пересчитывают из других": "t(IN := v, PT := T#5S);\nout := t.Q;\nv := a OR b;",
    "гасят под условием t.Q": """t(IN := v, PT := T#5S);
IF t.Q THEN
    out := TRUE;
    v := FALSE;
END_IF""",
    "вызов в ветви своего входа": """IF v THEN
    t(IN := v, PT := T#5S);
    out := t.Q;
ELSE
    v := FALSE;
    out := FALSE;
END_IF""",
}

EDGE_ROWS = {
    "вызов безусловный": "t(CLK := v);\nout := t.Q;",
    "вызов в ветви своего входа": "IF v THEN\n    t(CLK := v);\n    out := t.Q;\nEND_IF",
    "вызов в ветви по другому условию": "IF a THEN\n    t(CLK := v);\n    out := t.Q;\nEND_IF",
    "два вызова с разными входами": "t(CLK := v);\nout := t.Q;\nt(CLK := a);",
    "читают .Q выше вызова": "out := t.Q;\nt(CLK := v);",
}


COUNTER_ROWS = {
    "вызов безусловный": "c(CU := a, RESET := b, PV := 5);\nout := c.Q;",
    "сброс собственным выходом": "c(CU := a, RESET := c.Q, PV := 5);\nout := c.Q;",
    "уставка PV не задана": "c(CU := a, RESET := b);\nout := c.Q;",
    "вызов в ветви счётного входа": ("IF a THEN\n    c(CU := a, RESET := b, PV := 5);\n"
                                     "    out := c.Q;\nEND_IF"),
    "два вызова с разными входами": ("c(CU := a, RESET := b, PV := 5);\nout := c.Q;\n"
                                     "c(CU := b, PV := 5);"),
}


def counter_broken(code, kind, scans=400, period=20):
    """Считает ли счётчик ровно столько, сколько было фронтов, и доходит ли до цели."""
    s = scan_emu.Scan(code, {"c": kind})
    cv_max = edges = total = 0
    prev = False
    for n in range(scans):
        cur = (n // period) % 2 == 1
        s.v["a"], s.v["b"] = cur, False
        before = s.t["c"].et
        s.scan()
        if cur and not prev:
            edges += 1
        total += max(0, s.t["c"].et - before)
        cv_max = max(cv_max, s.t["c"].et)
        prev = cur
    pv = s.t["c"].pt
    if not pv:
        return True, "уставка не задана"
    if total > edges:
        return True, f"насчитал {total} при {edges} фронтах"
    return cv_max < pv, f"{cv_max} из {pv}"


def edge_broken(code, kind, scans=400, period=20):
    """Срабатывает ли детектор на каждый переход входа."""
    s = scan_emu.Scan(code, {"t": kind})
    edges = pulses = 0
    prev = False
    for n in range(scans):
        cur = (n // period) % 2 == 1
        s.v["v"], s.v["a"] = cur, True
        s.scan()
        if (cur and not prev) if kind == "R_TRIG" else (prev and not cur):
            edges += 1
        pulses += s.t["t"].q
        prev = cur
    return edges != pulses, f"{pulses} из {edges}"


print("таймеры: замер против движка")
for row, code in TIMER_ROWS.items():
    for kind in ("TON", "TOF", "TP"):
        st = scan_emu.explore(code, {"t": kind}, pulse=("v",))["t"]
        broken = not st["reached"]
        found = engine_finds(kind, code)
        check(bool(found) == broken,
              f"{row} / {kind}: эмулятор — {'сломано' if broken else 'работает'}"
              f" ({st['et_max']} из {st['pt']} мс), движок — {found or 'молчит'}")

print("детекторы фронта: замер против движка")
for row, code in EDGE_ROWS.items():
    for kind in ("R_TRIG", "F_TRIG"):
        broken, score = edge_broken(code, kind)
        found = engine_finds(kind, code)
        check(bool(found) == broken,
              f"{row} / {kind}: эмулятор — {'сломано' if broken else 'работает'}"
              f" ({score}), движок — {found or 'молчит'}")

print("счётчики: замер против движка")
for row, code in COUNTER_ROWS.items():
    broken, score = counter_broken(code, "CTU")
    found = engine_finds("CTU", code, inst="c")
    check(bool(found) == broken,
          f"{row} / CTU: эмулятор — {'сломано' if broken else 'работает'}"
          f" ({score}), движок — {found or 'молчит'}")

print()
print("SCAN MATRIX OK" if not fail else f"SCAN MATRIX: расхождений {fail}")
sys.exit(1 if fail else 0)

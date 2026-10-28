#!/usr/bin/env python3
"""Эмулятор скана: таймеры, детекторы фронта и счётчики.

Зачем. Спорить о том, дефект клетка или норма, можно бесконечно. Эмулятор
отвечает замером: подаём команду, крутим сканы и смотрим, через сколько
миллисекунд появился выход. Уставка 30 с, а выдержка вышла 10 мс — дефект,
и это число, а не мнение.

Что переиспользуем, а не пишем заново:
  * `engine.st_blocks` — дерево ветвей ST (IF/ELSIF/ELSE),
  * `engine.bool_parse` / `engine.bool_eval` — разбор и счёт булевых выражений.
Нового здесь только семантика самих таймеров и цикл сканирования.

Ограничения намеренные: булева логика и таймеры, без чисел, CASE и циклов.
Клетки матрицы — программы в десять строк, большего им не нужно.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine  # noqa: E402

_TIME = re.compile(r"T#(?:(\d+)H)?(?:(\d+)M(?!S))?(?:(\d+)S)?(?:(\d+)MS)?", re.I)
_CALL = re.compile(r"^\s*([A-Za-z_]\w*)\s*\((.*)\)\s*;?\s*$", re.S)
_ARG = re.compile(r"\b(IN|PT|CLK|CU|CD|RESET|LOAD|PV)\s*:=\s*([^,]+?)(?=\s*,\s*\w+\s*:=|\s*$)", re.I | re.S)


def ms_of(lit):
    """`T#30S` → 30000. Не литерал — None."""
    m = _TIME.fullmatch(lit.strip())
    if not m or not any(m.groups()):
        return None
    h, mi, s, ms = (int(x) if x else 0 for x in m.groups())
    return ((h * 60 + mi) * 60 + s) * 1000 + ms


EDGES = ("R_TRIG", "F_TRIG")
COUNTERS = ("CTU", "CTD", "CTUD")


class Timer:
    """Один экземпляр TON/TOF/TP/R_TRIG/F_TRIG по МЭК 61131-3.

    Детекторы фронта живут здесь же: у них та же природа — состояние между
    сканами, — и ломаются они тем же способом, что таймеры. Разница в мере:
    у таймера смотрим, доходит ли накопленное время до уставки, у фронта —
    сработал ли он ровно один раз на каждый переход входа."""

    def __init__(self, kind):
        self.kind, self.pt, self.et, self.q, self.prev, self.run = kind, 0, 0, False, False, False
        self.armed = False          # вход хоть раз поднимался — иначе клетку нечем судить
        self.pulses = 0             # сколько раз выход фронта поднимался
        self.unit = "шт" if kind in COUNTERS else "мс"
        self.prev_cd = False
        self.calls = 0              # сколько раз экземпляр вообще вызвали

    def call(self, in_, dt):
        self.armed = self.armed or in_
        self.calls += 1
        if self.kind == "TON":
            if in_:
                self.et = min(self.et + dt, self.pt)
                self.q = self.et >= self.pt
            else:
                self.et, self.q = 0, False
        elif self.kind == "TOF":
            if in_:
                self.et, self.q = 0, True
            elif self.q:
                self.et += dt
                if self.et >= self.pt:
                    self.q = False
        elif self.kind in COUNTERS:
            pass                      # счётчики считаются в count(), у них свои входы
        elif self.kind == "R_TRIG":
            self.q = in_ and not self.prev
            self.pulses += self.q
        elif self.kind == "F_TRIG":
            self.q = self.prev and not in_
            self.pulses += self.q
        elif self.kind == "TP":
            if in_ and not self.prev and not self.run:
                self.run, self.et, self.q = True, 0, True
            if self.run:
                self.et += dt
                if self.et >= self.pt:
                    self.run, self.q = False, False
        self.prev = in_


def _counter(t, cu, cd, reset, load):
    """Шаг счётчика по МЭК: вход CU/CD считает ПО ФРОНТУ (это делает сам ФБ),
    сброс и загрузка имеют приоритет над счётом.

    Накопленное держим в t.et, цель в t.pt — той же парой, что у таймера:
    мерка одна («дошло ли до цели»), и вердикт считается одинаково."""
    if t.kind in ("CTU", "CTUD") and reset:
        t.et = 0
    elif t.kind == "CTD" and load:
        t.et = t.pt
    else:
        if t.kind in ("CTU", "CTUD") and cu and not t.prev:
            t.et += 1
        if t.kind in ("CTD", "CTUD") and cd and not t.prev_cd:
            t.et -= 1
    t.prev, t.prev_cd = cu, cd
    t.armed = t.armed or cu or cd
    t.q = t.et >= t.pt if t.kind != "CTD" else t.et <= 0
    t.calls += 1


class Scan:
    """Одна программа: переменные, таймеры, дерево ветвей."""

    def __init__(self, code, timers, dt=10):
        self.tree = engine.st_blocks(code)
        self.t = {n.lower(): Timer(k.upper()) for n, k in timers.items()}
        self.v = {}
        self.dt = dt

    # --- значения -------------------------------------------------------
    def get(self, name):
        n = name.lower()
        if "." in n:
            inst, field = n.split(".", 1)
            if inst in self.t and field == "q":
                return self.t[inst].q
        return self.v.get(n, False)

    def val(self, text):
        f = engine.bool_parse(text)
        if f is None:
            raise ValueError(f"не разобрал выражение: {text!r}")
        return engine.bool_eval(f, {a: self.get(a) for a in engine.bool_atoms(f)})

    # --- выполнение -----------------------------------------------------
    def run_items(self, items):
        for it in items:
            if it["kind"] == "stmt":
                self.stmt(it["text"])
            elif it["kind"] == "if":
                for b in it["branches"]:
                    if b.get("is_else") or self.val(b["cond"]):
                        self.run_items(b["items"])
                        break

    def stmt(self, text):
        m = _CALL.match(text)
        if m and m.group(1).lower() in self.t:
            inst, args = m.group(1).lower(), m.group(2)
            kw = {k.upper(): v.strip() for k, v in _ARG.findall(args)}
            t = self.t[inst]
            if "PT" in kw:
                ms = ms_of(kw["PT"])
                t.pt = ms if ms is not None else self.v.get(kw["PT"].lower(), 0)
            if "PV" in kw:
                t.pt = int(kw["PV"]) if kw["PV"].strip().isdigit() else t.pt
            if t.kind in COUNTERS:
                _counter(t,
                         self.val(kw["CU"]) if "CU" in kw else False,
                         self.val(kw["CD"]) if "CD" in kw else False,
                         self.val(kw["RESET"]) if "RESET" in kw else False,
                         self.val(kw["LOAD"]) if "LOAD" in kw else False)
                return
            # вызов без входа (отдельная строка только с уставкой) входа не трогает;
            # у детекторов фронта вход называется CLK, у таймеров — IN
            src = kw.get("IN") or kw.get("CLK")
            in_ = self.val(src) if src else self.t[inst].prev
            self.t[inst].call(in_, self.dt)
            return
        a = engine.st_assignment(text)
        if not a:
            return
        lhs, rhs = a
        if "." in lhs:                      # t.IN := … / t.PT := …
            inst, field = lhs.lower().split(".", 1)
            if inst in self.t:
                if field == "pt":
                    ms = ms_of(rhs)
                    self.t[inst].pt = ms if ms is not None else self.v.get(rhs.lower(), 0)
                elif field == "in":
                    self.v[lhs.lower()] = self.val(rhs)
                return
        self.v[lhs.lower()] = self.val(rhs)

    def scan(self):
        self.run_items(self.tree)


def measure(code, timers, cmd, out, scans=20000, dt=10, warmup=5):
    """Подаём cmd, ждём out. → задержка в мс или None, если так и не появился."""
    s = Scan(code, timers, dt)
    for _ in range(warmup):
        s.scan()
    s.v[cmd.lower()] = True
    for i in range(scans):
        s.scan()
        if s.get(out):
            return (i + 1) * dt
    return None


# ---------- наблюдение за накопленным временем ----------
#
# Главный вопрос к клетке матрицы не «появился ли выход», а «идёт ли по таймеру
# время». Так не нужно для каждой клетки назначать, что считать командой и что
# результатом: достаточно смотреть на ET. Дорос до уставки — таймер работает;
# не поднялся выше одного скана — его сбрасывают каждый цикл, и выдержки нет.

def inputs_of(scan):
    """Внешние входы клетки: что читают, но нигде не присваивают."""
    read, written = set(), set()

    def walk(items):
        for it in items:
            if it["kind"] == "stmt":
                a = engine.st_assignment(it["text"])
                if a:
                    written.add(a[0].lower())
                    src = a[1]
                else:
                    src = it["text"]
                f = engine.bool_parse(src)
                if f is not None:
                    read.update(engine.bool_atoms(f))
                m = _CALL.match(it["text"])
                if m:
                    for _k, v in _ARG.findall(m.group(2)):
                        f = engine.bool_parse(v)
                        if f is not None:
                            read.update(engine.bool_atoms(f))
            elif it["kind"] == "if":
                for b in it["branches"]:
                    if not b.get("is_else"):
                        f = engine.bool_parse(b["cond"])
                        if f is not None:
                            read.update(engine.bool_atoms(f))
                    walk(b["items"])
            else:
                walk(it["items"])

    walk(scan.tree)
    return {a for a in read - written if "." not in a and a not in scan.t}


def written_of(scan):
    """Переменные, которым программа присваивает сама."""
    out = set()

    def walk(items):
        for it in items:
            if it["kind"] == "stmt":
                a = engine.st_assignment(it["text"])
                if a:
                    out.add(a[0].lower())
            elif it["kind"] == "if":
                for b in it["branches"]:
                    walk(b["items"])
            else:
                walk(it["items"])

    walk(scan.tree)
    return out


def trace(code, timers, pulse=(), scans=6000, dt=10, drive=True):
    """Крутит сканы и следит за ET каждого таймера.

    Раздражитель один на все типы: переменные из `pulse` поднимаются ОДИН раз,
    перед первым сканом, дальше программа делает с ними что хочет. Так видно обе
    полярности: TON считает, пока вход держат, TOF — после того как его отпустили,
    а TP ловит фронт. Держать вход насильно каждый скан нельзя: это затирало бы
    как раз ту запись, ради которой всё и затевалось.

    Внешние входы (их читают, но нигде не присваивают) держим в TRUE: это
    разрешающие условия вроде «давление есть», без них клетка не исполняется.

    → {имя: {pt, et_max, reached, resets, q_seen, armed}}"""
    s = Scan(code, timers, dt)
    ins = inputs_of(s) if drive else set()
    own = written_of(s)
    # Переменную, которую программа пишет сама, трогаем один раз: дальше она
    # принадлежит программе. Ту, которую не пишет никто, держим включённой
    # первую половину прогона и отпускаем — иначе у TOF выдержке нечем начаться.
    once = [v.lower() for v in pulse if v.lower() in own]
    held = [v.lower() for v in pulse if v.lower() not in own]
    for v in once + held:
        s.v[v] = True
    stat = {n: {"pt": 0, "et_max": 0, "reached": False, "resets": 0,
                "q_seen": False, "armed": False} for n in s.t}
    prev = {n: 0 for n in s.t}
    for n in range(scans):
        for i in ins:
            s.v[i] = True
        for v in held:
            s.v[v] = n < scans // 2
        s.scan()
        for n, t in s.t.items():
            st = stat[n]
            st["pt"] = t.pt
            st["et_max"] = max(st["et_max"], t.et)
            st["q_seen"] = st["q_seen"] or t.q
            st["armed"] = st["armed"] or t.armed
            if t.pt and t.et >= t.pt:
                st["reached"] = True
            if t.et < prev[n]:
                st["resets"] += 1
            prev[n] = t.et
    return stat


def verdict(st, dt=10, unit="мс"):
    """Словами: что стало с накопленным временем."""
    if not st["pt"]:
        return "уставка не задана — выдержки нет"
    if not st["armed"]:
        return "вход ни разу не поднялся — клетку нечем запустить"
    if st["reached"]:
        return "время идёт, выдержка отрабатывает"
    if st["et_max"] <= dt:
        return f"НЕ НАКАПЛИВАЕТСЯ: не поднялось выше {st['et_max']} {unit}"
    return (f"идёт, но до цели не доходит: максимум {st['et_max']} из {st['pt']} {unit}"
            f", сбросов {st['resets']}")


# ---------- перебор поведений входов ----------
#
# Один раздражитель врёт. Если внешние входы держать включёнными весь прогон,
# у TOF выдержке нечем начаться, и законная клетка выглядит дефектной — на этом
# я уже споткнулся. Поэтому клетку гоняем при нескольких поведениях входов и
# считаем так: нашлось хоть одно, при котором таймер отсчитал уставку, — клетка
# рабочая. Не нашлось ни одного — дефект не в раздражителе, а в коде.

PROFILES = {
    "входы включены": lambda n, total: True,
    "включены, потом сняты": lambda n, total: n < total // 2,
    "сняты, потом включены": lambda n, total: n >= total // 2,
    "мигают": lambda n, total: (n // 200) % 2 == 0,
}


def explore(code, timers, pulse=(), scans=6000, dt=10):
    """Гоняет клетку при всех поведениях входов. → {имя: сводка}."""
    best = {}
    for pname, shape in PROFILES.items():
        s = Scan(code, timers, dt)
        ins = inputs_of(s)
        own = written_of(s)
        once = [v.lower() for v in pulse if v.lower() in own]
        held = [v.lower() for v in pulse if v.lower() not in own]
        for v in once + held:
            s.v[v] = True
        stat = {n: {"pt": 0, "et_max": 0, "reached": False, "resets": 0,
                    "q_seen": False, "armed": False, "how": pname} for n in s.t}
        prev = {n: 0 for n in s.t}
        for n in range(scans):
            for i in ins:
                s.v[i] = shape(n, scans)
            for v in held:
                s.v[v] = n < scans // 2
            s.scan()
            for nm, t in s.t.items():
                st = stat[nm]
                st["pt"] = t.pt
                st["et_max"] = max(st["et_max"], t.et)
                st["q_seen"] = st["q_seen"] or t.q
                st["armed"] = st["armed"] or t.armed
                if t.pt and t.et >= t.pt:
                    st["reached"] = True
                if t.et < prev[nm]:
                    st["resets"] += 1
                prev[nm] = t.et
        for nm, st in stat.items():
            cur = best.get(nm)
            # лучшим считаем прогон, где таймер продвинулся дальше всего
            if cur is None or (st["reached"], st["et_max"]) > (cur["reached"], cur["et_max"]):
                best[nm] = st
    return best

#!/usr/bin/env python3
"""
Движок PLC-линтера: разбор PLCopenXML (PLCopen TC6, `tc6_0200`) + портируемые
эвристики. Возвращает СТРУКТУРИРОВАННЫЕ findings (list[dict]) вместо записи файлов —
чтобы веб-слой мог рендерить отчёт.

Рефактор ядра ~/codesys_review/review.py: парсинг сохранён 1:1 (доменно-нейтральный,
формат стандартный), эвристики те же, что портируются as-is. ИТП-специфика
(полярность, _TC-гейтинг, гистерезис) сюда сознательно НЕ вынесена.

Публичный API:
    analyze(xml_bytes_or_path) -> Report
"""
import io
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

import i18n

NS = "{http://www.plcopen.org/xml/tc6_0200}"


def q(t: str) -> str:
    return NS + t


def loc(e) -> str:
    return e.tag.split('}')[-1]


# ---------- разбор типов (из review.py, без изменений) ----------
def type_str(te) -> str:
    if te is None:
        return "?"
    ch = list(te)
    c = ch[0] if ch else te
    n = loc(c)
    if n == "derived":
        return c.get("name")
    if n == "array":
        dims = [f'{d.get("lower")}..{d.get("upper")}' for d in c.findall(q("dimension"))]
        return f'ARRAY[{",".join(dims)}] OF {type_str(c.find(q("baseType")))}'
    if n in ("string", "wstring"):
        L = None
        for g in c.iter():
            if loc(g) == "length":
                L = g.text
        return ("STRING" if n == "string" else "WSTRING") + (f"({L})" if L else "")
    if n == "pointer":
        return "POINTER TO " + type_str(c.find(q("baseType")))
    if n in ("subrangeSigned", "subrangeUnsigned", "enum"):
        b = c.find(q("baseType"))
        return type_str(b) if b is not None else n
    return n


def render_var(v) -> str:
    t = type_str(v.find(q("type")))
    init = v.find(q("initialValue"))
    istr = ""
    if init is not None:
        sv = init.find(q("simpleValue"))
        struct = init.find(q("structValue"))
        if sv is not None and sv.get("value") is not None:
            istr = f" := {sv.get('value')}"
        elif struct is not None:  # инициализация полей FB, напр. TON := (PT := T#5S)
            members = []
            for val in struct.findall(q("value")):
                s2 = val.find(q("simpleValue"))
                v2 = s2.get("value") if (s2 is not None and s2.get("value")) else "".join(val.itertext()).strip()
                members.append(f"{val.get('member')} := {v2}")
            if members:
                istr = f" := ({', '.join(members)})"
        else:
            raw = "".join(init.itertext()).strip()
            if raw:
                istr = f" := {raw}"
    addr = v.get("address")
    at = f" AT {addr}" if addr else ""
    doc = v.find(q("documentation"))
    cm = ""
    if doc is not None:
        tx = "".join(doc.itertext()).strip().replace("\n", " | ")
        if tx:
            cm = f"  // {tx}"
    return f"\t{v.get('name')}{at} : {t}{istr};{cm}"


SECTIONS = [("inputVars", "VAR_INPUT"), ("outputVars", "VAR_OUTPUT"), ("inOutVars", "VAR_IN_OUT"),
            ("externalVars", "VAR_EXTERNAL"), ("globalVars", "VAR_GLOBAL"),
            ("tempVars", "VAR_TEMP"), ("localVars", "VAR")]


def render_iface(iface):
    if iface is None:
        return "", None
    out = []
    for tag, kw in SECTIONS:
        sec = iface.find(q(tag))
        if sec is None:
            continue
        vs = sec.findall(q("variable"))
        if not vs:
            continue
        attr = " CONSTANT" if sec.get("constant") == "true" else ""
        if sec.get("retain") == "true":
            attr += " RETAIN"
        out.append(kw + attr)
        out += [render_var(v) for v in vs]
        out.append("END_VAR")
    return "\n".join(out), iface.find(q("returnType"))


def body_text(b) -> str:
    if b is None:
        return ""
    st = b.find(q("ST"))
    return "".join(st.itertext()) if st is not None else ""


# языки тела POU: ST/IL — текстовые, LD/FBD/SFC/CFC — графические.
# CODESYS хранит CFC в <body><addData>…<CFC> (namespace тот же tc6_0200), поэтому
# у CFC-POU есть ПУСТОЙ <ST> + графика в addData — детектируем по элементу CFC.
GRAPH_LANGS = ("LD", "FBD", "SFC", "CFC")


def body_lang(b) -> str:
    """Язык тела POU. '' если тела нет. Анализируем построчно только ST; графику (LD/FBD/
    SFC/CFC) фиксируем для честного покрытия, а по вхождению имён частично покрываем через
    graphical_text()."""
    if b is None:
        return ""
    for lang in ("LD", "FBD", "SFC"):        # стандартные графические — прямые дети body
        if b.find(q(lang)) is not None:
            return lang
    if any(loc(e) == "CFC" for e in b.iter()):  # CODESYS-CFC в addData
        return "CFC"
    st = b.find(q("ST"))
    if st is not None and "".join(st.itertext()).strip():
        return "ST"
    if b.find(q("IL")) is not None:
        return "IL"
    return "ST" if st is not None else ""   # пустой <ST> без графики — просто пустой ST-POU


def graphical_text(b) -> str:
    """Синтетический текст из графического тела (LD/FBD/SFC и CODESYS-CFC): идентификаторы из
    expression/variable + вызовы блоков (instanceName/typeName). НЕ построчный код — годится
    ТОЛЬКО для правил «встречается ли имя» (unused-local, undeclared-global, dead-pou),
    не для структурных."""
    if b is None:
        return ""
    parts = []
    for el in b.iter():
        n = loc(el)
        if n in ("expression", "variable"):
            t = "".join(el.itertext()).strip()
            if t:
                parts.append(t)
        elif n in ("block", "box"):
            for attr in ("instanceName", "typeName"):
                if el.get(attr):
                    parts.append(f"{el.get(attr)}(")
    return "\n".join(parts)


# ---------- CFC/FBD как граф: узлы по localId, рёбра по connectionPointIn ----------
_GRAPH_NODE_KINDS = ("inVariable", "outVariable", "block", "connector", "continuation")


def cfc_nodes(body_el):
    """localId -> {kind, el, typeName, exec}. Граф CFC/FBD (у CFC — в addData)."""
    nodes = {}
    for e in body_el.iter():
        lid = e.get("localId")
        if lid is None or loc(e) not in _GRAPH_NODE_KINDS:
            continue
        eo = e.get("executionOrderId")
        nodes[lid] = {"kind": loc(e), "el": e, "typeName": e.get("typeName"),
                      "exec": int(eo) if eo is not None else None}
    return nodes


def _cpi_src(el):
    """localId источника, подключённого ко входу элемента (первая connection), или None."""
    cpi = el.find(q("connectionPointIn"))
    if cpi is None:
        return None
    c = cpi.find(q("connection"))
    return c.get("refLocalId") if c is not None else None


def _resolve_src(lid, nodes, _seen=None):
    """Разрешает источник сквозь connector-маршрутизаторы до вычислительного узла."""
    _seen = _seen or set()
    n = nodes.get(lid)
    if lid is None or lid in _seen or n is None:
        return lid
    _seen.add(lid)
    if n["kind"] == "connector":
        s = _cpi_src(n["el"])
        return _resolve_src(s, nodes, _seen) if s else lid
    return lid


_DIV_OPS = {"DIV", "MOD"}


# Языки-графы с общим словарём потока данных. FBD добавлен авансом: cfc_nodes()
# обходит тело по localId и от контейнера не зависит, а у FBD те же block/inVariable/
# connection. Проверить не на чем (0 POU на FBD в корпусе) — в маркетинге не заявляем.
_GRAPH_DATAFLOW_LANGS = ("CFC", "FBD")


def heur_cfc_div_zero(root):
    """CFC/FBD: делитель блока DIV/MOD (пин In2 / второй вход) подключён к литеральному 0 →
    гарантированное деление на ноль. Точно (литерал), номера строк у графики нет."""
    hits = []
    for pou in root.iter(q("pou")):
        b = pou.find(q("body"))
        if b is None or body_lang(b) not in _GRAPH_DATAFLOW_LANGS:
            continue
        nodes = cfc_nodes(b)
        for blk in b.iter(q("block")):
            if (blk.get("typeName") or "").upper() not in _DIV_OPS:
                continue
            inv = blk.find(q("inputVariables"))
            inputs = inv.findall(q("variable")) if inv is not None else []
            divisor = None
            for v in inputs:
                if (v.get("formalParameter") or "").upper() == "IN2":
                    divisor = v
            if divisor is None and len(inputs) >= 2:
                divisor = inputs[1]
            if divisor is None:
                continue
            src = _resolve_src(_cpi_src(divisor), nodes)
            n = nodes.get(src)
            if n and n["kind"] == "inVariable" and \
                    "".join(n["el"].itertext()).strip() in ("0", "0.0"):
                hits.append((pou.get("name"), blk.get("typeName")))
    return hits


def heur_cfc_stale_read(root):
    """CFC: вход блока подключён к выходу блока с бо́льшим executionOrderId → читается
    значение с ПРОШЛОГО скана (порядок исполнения против потока данных).

    ⚠ НАМЕРЕННО НЕ ПОДКЛЮЧЕНО в analyze() — решение по разбору всех 25 находок корпуса
    (2026-08-03, agent 9 + cMT 16; подробности в ~/Obsidian/plc-lint — CFC: решение по
    cfc-stale-read). Коротко: гипотеза «инверсия вне цикла = ошибка» не подтвердилась —
    циклов нет НИ В ОДНОЙ из 25 находок, то есть признак ничего не разделяет. Зато в тех же
    POU против порядка исполнения идут 38–73 % ВСЕХ рёбер: это не точечная ошибка порядка,
    а способ рисовки (CODESYS нумерует блоки по геометрии, автор ведёт поток снизу вверх).
    Диагноз «ошибка порядка» был бы неверен по формулировке, а 25 находок на двух проектах
    из девяти — это шум. Тексты правила удалены вместе с включением (есть в истории git).
    Функция оставлена и питает счётчик cfc_stale_read в candidate_signals(): появится
    трафик — станет видно, бывает ли инверсия точечной, и вот тогда правило осмысленно."""
    hits = []
    for pou in root.iter(q("pou")):
        b = pou.find(q("body"))
        if b is None or body_lang(b) not in _GRAPH_DATAFLOW_LANGS:
            continue
        nodes = cfc_nodes(b)
        for blk in b.iter(q("block")):
            so = nodes.get(blk.get("localId"), {}).get("exec")
            if so is None:
                continue
            for var in blk.iter(q("variable")):
                cpi = var.find(q("connectionPointIn"))
                if cpi is None:
                    continue
                for c in cpi.findall(q("connection")):
                    src = _resolve_src(c.get("refLocalId"), nodes)
                    seo = nodes.get(src, {}).get("exec")
                    if seo is not None and seo > so:
                        hits.append((pou.get("name"), blk.get("typeName"),
                                     var.get("formalParameter")))
                        break
    return hits


def iter_vars(iface, tags=None):
    """Итерирует (variable_element, keyword) по секциям интерфейса.
    tags — какие секции брать (по умолчанию все SECTIONS)."""
    if iface is None:
        return
    for tag, kw in SECTIONS:
        if tags is not None and tag not in tags:
            continue
        sec = iface.find(q(tag))
        if sec is None:
            continue
        for v in sec.findall(q("variable")):
            yield v, kw


# ---------- извлечение (в память, без записи .st) ----------
def extract(root):
    """Возвращает (pous, rendered): pous[name]={kw,iface,body}, rendered[name]=читаемый ST."""
    pous = {}
    rendered = {}
    for pou in root.iter(q("pou")):
        name = pou.get("name")
        kw = {"program": "PROGRAM", "functionBlock": "FUNCTION_BLOCK",
              "function": "FUNCTION"}.get(pou.get("pouType"), "PROGRAM")
        iface = pou.find(q("interface"))
        ren, rt = render_iface(iface)
        rtstr = f" : {type_str(rt)}" if rt is not None else ""
        body_el = pou.find(q("body"))
        lang = body_lang(body_el)
        main_body = body_text(body_el)
        graph_bodies = [graphical_text(body_el)]  # идентификаторы из графики (CFC/LD/FBD/SFC)
        parts = [f"{kw} {name}{rtstr}"]
        if ren:
            parts.append(ren)
        parts.append("")
        parts.append(main_body.rstrip())
        parts.append(f"END_{kw}")
        extra_bodies = []  # тела actions/methods — для анализа использования (unused-local)
        for act in pou.findall(q("action")):
            abody = act.find(q("body"))
            ab = body_text(abody)
            extra_bodies.append(ab)
            graph_bodies.append(graphical_text(abody))
            parts.append(f"\nACTION {name}.{act.get('name')}:")
            parts.append(ab.rstrip())
            parts.append("END_ACTION")
        for m in pou.findall(q("method")):
            mi, mrt = render_iface(m.find(q("interface")))
            mbody = m.find(q("body"))
            mb = body_text(mbody)
            extra_bodies.append(mb)
            graph_bodies.append(graphical_text(mbody))
            parts.append(f"\nMETHOD {name}.{m.get('name')}" + (f" : {type_str(mrt)}" if mrt is not None else ""))
            if mi:
                parts.append(mi)
            parts.append("")
            parts.append(mb.rstrip())
            parts.append("END_METHOD")
        rendered[name] = "\n".join(parts)
        pous[name] = {"kw": kw, "iface": iface, "body": main_body, "lang": lang,
                      "fulltext": "\n".join([main_body] + extra_bodies + graph_bodies)}
    return pous, rendered


def globals_of(root):
    parent = {c: p for p in root.iter() for c in p}
    decl = {}
    for gv in root.iter(q("globalVars")):
        p = parent.get(gv)
        if p is not None and loc(p) == "interface":
            continue
        for v in gv.findall(q("variable")):
            decl[v.get("name").lower()] = type_str(v.find(q("type")))
    return decl


def strip_comments(s: str) -> str:
    s = re.sub(r'\(\*.*?\*\)', '', s, flags=re.S)
    s = re.sub(r'//[^\n]*', '', s)
    return s


def blank_comments(s: str) -> str:
    """Гасит комментарии, СОХРАНЯЯ длину и переносы строк (символы → пробелы, \\n остаются).
    Нужно для построчных правил: strip_comments сдвинул бы нумерацию строк в отчёте."""
    def repl(m):
        return re.sub(r'[^\n]', ' ', m.group(0))
    s = re.sub(r'\(\*.*?\*\)', repl, s, flags=re.S)
    s = re.sub(r'//[^\n]*', repl, s)
    return s


# ---------- эвристики (из review.py) ----------
def find_undeclared(pous, decl):
    res = {}
    for name, d in pous.items():
        for m in re.finditer(r'\bgvl\.([A-Za-z_]\w*)', strip_comments(d.get("fulltext", d["body"])), re.I):
            b = m.group(1).lower()
            if b not in decl:
                res.setdefault(b, set()).add(name)
    return res


def heur_unreachable_if(pous):
    """IF x<T ... ELSIF x>=T ... с ОДИНАКОВЫМ порогом T → последующие ветви мертвы.
    Сравниваем ПОЛНЫЙ правый операнд (с арифметикой): `x>=T+гистерезис` и `x<T` — это НЕ
    дополнение (мёртвая зона), не флагуем. Иначе ловили бы гистерезис как баг (ложный HIGH)."""
    hits = []
    for name, d in pous.items():
        lines = strip_comments(d["body"]).splitlines()
        conds = []
        for i, ln in enumerate(lines, 1):
            m = re.search(r'\b(IF|ELSIF)\b(.+?)\bTHEN\b', ln, re.I)
            if not m:
                continue
            kind = m.group(1).upper()
            mm = re.search(r'([A-Za-z_][\w.]*)\s*(<=|>=|<|>)\s*(.+)', m.group(2))
            if mm:
                lhs = re.sub(r'\s+', '', mm.group(1))
                # берём только первое сравнение (до AND/OR) и весь операнд с арифметикой
                rhs = re.split(r'\b(?:AND|OR|XOR)\b', mm.group(3), flags=re.I)[0]
                rhs = re.sub(r'\s+', '', rhs).rstrip(')')
                conds.append((i, lhs, mm.group(2), rhs, kind))
            elif kind == "IF":
                conds = []
        for a in range(len(conds)):
            for b in range(a + 1, len(conds)):
                l1, v1, o1, t1, k1 = conds[a]
                l2, v2, o2, t2, k2 = conds[b]
                if v1 == v2 and t1 == t2 and {o1, o2} == {'<', '>='}:
                    hits.append((name, l1, l2, v1, t1, t2))
    return hits


TIMER_TYPES = {"ton", "tof", "tp", "r_trig", "f_trig", "blink"}


def heur_uncalled_fb(pous):
    """Локальный инстанс TON/TP/R_TRIG: читают .Q/.ET или пишут .IN, но нет вызова name(...)."""
    hits = []
    for name, d in pous.items():
        iface = d["iface"]
        if iface is None:
            continue
        insts = {}
        lv = iface.find(q("localVars"))
        if lv is None:
            continue
        for v in lv.findall(q("variable")):
            t = type_str(v.find(q("type"))).lower()
            if t in TIMER_TYPES:
                insts[v.get("name")] = t
        body = strip_comments(d["body"])
        for inst, t in insts.items():
            called = re.search(rf'\b{re.escape(inst)}\s*\(', body)
            used = re.search(rf'\b{re.escape(inst)}\.(Q|ET|IN|CLK)\b', body, re.I)
            if used and not called:
                hits.append((name, inst, t.upper()))
    return hits


def heur_regex(pous, pattern, flags=0):
    hits = []
    for name, d in pous.items():
        orig = d["body"].splitlines()
        blanked = blank_comments(d["body"]).splitlines()  # матчим без комментариев,
        for i, (o, b) in enumerate(zip(orig, blanked), 1):  # но показываем оригинал строки
            if re.search(pattern, b, flags):
                hits.append((name, i, o.strip()))
    return hits


# целочисленные типы IEC 61131-3 (деление таких на константу теряет дробь)
INT_DIV_TYPES = {"SINT", "INT", "DINT", "LINT", "USINT", "UINT", "UDINT", "ULINT",
                 "BYTE", "WORD", "DWORD", "LWORD"}
NUMERIC_TYPES = INT_DIV_TYPES | {"REAL", "LREAL"}
_INTDIV_RE = re.compile(r':=\s*([A-Za-z_]\w*)\s*/\s*(\d+)\s*;')
_DIVVAR_RE = re.compile(r'/\s*([A-Za-z_]\w*)')


def _has_nonzero_guard(var, text):
    """Есть ли где-то в POU защита делителя от нуля: var<>0 / var>0 / var>=1 / 0<var."""
    v = re.escape(var)
    return bool(re.search(rf'\b{v}\b\s*(?:<>|>)\s*0(?![.\d])', text, re.I)
                or re.search(rf'\b{v}\b\s*>=\s*[1-9]', text, re.I)
                or re.search(rf'0\s*<\s*\b{v}\b', text, re.I))


def heur_div_zero_var(pous, decl):
    """Деление на ЛОКАЛЬНУЮ числовую переменную, которая может быть 0:
      - НИКОГДА не присваивается (init 0/пустой → всегда 0) → HIGH, гарантированное деление на 0;
      - присваивается литеральный 0 где-то в POU И нет защиты (var<>0/>0) → MEDIUM, деление на 0
        на одной из веток (как `iAlarm:=0; … 10/iAlarm`).
    Делители с защитой (var<>0) или без нулевого присваивания не трогаем — точность важнее полноты.
    Возвращает (name, line, code, var, severity, detail_key)."""
    hits = []
    for name, d in pous.items():
        if d.get("lang", "ST") != "ST":
            continue
        full = d.get("fulltext", d["body"])
        risky = {}  # lower -> (orig_name, severity, detail_key)
        for v, _kw in iter_vars(d["iface"], tags={"localVars"}):
            vn = v.get("name")
            if not vn or type_str(v.find(q("type"))).upper() not in NUMERIC_TYPES:
                continue
            init = v.find(q("initialValue"))
            iv = "".join(init.itertext()).strip() if init is not None else ""
            if iv not in ("", "0", "0.0"):
                continue
            assigned = re.search(rf'\b{re.escape(vn)}\s*:=', full, re.I)
            if not assigned:                       # всегда 0 → гарантированно
                risky[vn.lower()] = (vn, "high", "div-by-zero.zerovar")
            elif re.search(rf'\b{re.escape(vn)}\s*:=\s*0(?![.\d])', full, re.I) \
                    and not _has_nonzero_guard(vn, full):
                risky[vn.lower()] = (vn, "medium", "div-by-zero.maybezero")
        if not risky:
            continue
        orig = d["body"].splitlines()
        blanked = blank_comments(d["body"]).splitlines()
        for i, (o, b) in enumerate(zip(orig, blanked), 1):
            for m in _DIVVAR_RE.finditer(b):
                r = risky.get(m.group(1).lower())
                if r:
                    hits.append((name, i, o.strip(), r[0], r[1], r[2]))
    return hits


def heur_int_division(pous, decl):
    """`x := var / N;` где делимое `var` — ЦЕЛОЧИСЛЕННОГО типа → отбрасывается дробь.
    Тип делимого неизвестен или REAL/LREAL → молчим (иначе ложные срабатывания на
    корректном REAL-делении вроде `rAvg := rSum / 10`)."""
    gtypes = {k: v.upper() for k, v in decl.items()}
    hits = []
    for name, d in pous.items():
        if d.get("lang", "ST") != "ST":
            continue
        vtypes = {}
        for v, _kw in iter_vars(d["iface"]):
            vn = v.get("name")
            if vn:
                vtypes[vn.lower()] = type_str(v.find(q("type"))).upper()
        orig = d["body"].splitlines()
        blanked = blank_comments(d["body"]).splitlines()
        for i, (o, b) in enumerate(zip(orig, blanked), 1):
            m = _INTDIV_RE.search(b)
            if not m:
                continue
            if int(m.group(2)) == 0:
                continue  # деление на литеральный 0 — это div-by-zero (high), не потеря дроби
            t = vtypes.get(m.group(1).lower()) or gtypes.get(m.group(1).lower())
            if t in INT_DIV_TYPES:
                hits.append((name, i, o.strip()))
    return hits


def task_pou_instances(root):
    """Имена POU, назначенных задачам в конфигурации (<pouInstance name="...">). Такие
    программы вызывает рантайм, а не код, — точка входа не обязана зваться PLC_PRG.
    Квалифицированные имена (VisuElems.Visu_Prg) берём и целиком, и по последнему сегменту."""
    names = set()
    for pi in root.iter(q("pouInstance")):
        nm = (pi.get("name") or "").strip()
        if nm:
            names.add(nm.lower())
            names.add(nm.rsplit(".", 1)[-1].lower())
    return names


def dead_pous(root, pous, extra=""):
    """extra — имена ВНЕ программ (привязки экранов, параметры преобразований): кнопка
    на экране умеет вызывать программу, и без этого она числилась бы мёртвой."""
    bodies = "\n".join(d.get("fulltext", d["body"]) for d in pous.values()) + "\n" + (extra or "")
    decls = []
    for pou in root.iter(q("pou")):
        for v in pou.iter(q("variable")):
            decls.append(type_str(v.find(q("type"))))
    decls = "\n".join(decls)
    entry_points = task_pou_instances(root)
    dead = []
    for name in pous:
        if name == "PLC_PRG" or name.startswith("Check"):
            continue
        if name.lower() in entry_points:
            continue
        used_call = re.search(rf'\b{re.escape(name)}\s*\(',
                              bodies.replace(f"{pous[name]['kw']} {name}", ""), re.I)
        used_type = re.search(rf'\b{re.escape(name)}\b', decls, re.I)
        if used_call or used_type:
            continue
        dead.append(name)
    return dead


# ---------- генерик-правила: именование / magic numbers / комментарии ----------
# Локальные односимвольные имена, кроме конвенциональных счётчиков цикла.
NAME_OK = {"i", "j", "k", "n"}


def heur_naming(pous):
    """Криптовые имена: односимвольные локальные/temp переменные вне {i,j,k,n}.
    Намеренно консервативно — не трогаем I/O-теги (DI1/AO2) и пины FB, чтобы не шуметь."""
    hits = []
    for name, d in pous.items():
        for v, kw in iter_vars(d["iface"], tags={"localVars", "tempVars"}):
            vn = v.get("name") or ""
            if len(vn) == 1 and vn.lower() not in NAME_OK:
                hits.append((name, vn))
    return hits


# число, не входящее в состав идентификатора/типизированного литерала (T#, 16#, DINT#…),
# не после точки (метод/бит) — т.е. «сырая» константа в выражении.
_NUM_RE = re.compile(r'(?<![\w#.])(\d+\.\d+|\d+)(?![\w#.])')
ALLOWED_NUM = {"0", "1", "2", "10", "100", "1000", "0.0", "1.0", "2.0"}
_SUBSCRIPT_RE = re.compile(r'\[[^\]]*\]')             # индексы массивов
_FORBOUND_RE = re.compile(r'\b(?:TO|BY)\b\s*\d+', re.I)  # границы FOR
SMALL_INT_MAX = 16  # целые меньше — индексы/биты/счётчики, не считаем magic


def _is_trivial(val):
    if val in ALLOWED_NUM:
        return True
    if "." not in val and int(val) < SMALL_INT_MAX:  # мелкие целые
        return True
    return False


def heur_magic(pous):
    """Magic numbers: крупные/дробные сырые константы. Шум подавлен — не считаем индексы
    массивов, границы FOR и мелкие целые (<16). Агрегация ПО ЗНАЧЕНИЮ на весь проект:
    одну константу показываем раз, со списком POU."""
    agg = {}  # value -> {pous:set, first:(pou,line,code), total:int}
    for name, d in pous.items():
        for i, ln in enumerate(strip_comments(d["body"]).splitlines(), 1):
            scan = _FORBOUND_RE.sub("", _SUBSCRIPT_RE.sub("[]", ln))  # убрать индексы и границы
            for m in _NUM_RE.finditer(scan):
                val = m.group(1)
                if _is_trivial(val):
                    continue
                a = agg.setdefault(val, {"pous": set(), "first": (name, i, ln.strip()), "total": 0})
                a["pous"].add(name)
                a["total"] += 1
    # по убыванию распространённости (в скольких POU)
    out = []
    for val, a in sorted(agg.items(), key=lambda kv: -len(kv[1]["pous"])):
        out.append((val, sorted(a["pous"]), a["first"], a["total"]))
    return out


def heur_comments(pous):
    """POU с существенной логикой (≥15 строк кода) и БЕЗ единого комментария."""
    hits = []
    for name, d in pous.items():
        body = d["body"]
        stripped = strip_comments(body)
        code_lines = [ln for ln in stripped.splitlines() if ln.strip()]
        comment_chars = len(body) - len(stripped)
        if len(code_lines) >= 15 and comment_chars == 0:
            hits.append((name, len(code_lines)))
    return hits


ROUTINE_MAX = 120  # порог «раздутой» рутины по строкам логики


def heur_routine_size(pous):
    """POU, у которого тело > ROUTINE_MAX строк логики — кандидат на декомпозицию в FB."""
    hits = []
    for name, d in pous.items():
        code_lines = [ln for ln in strip_comments(d["body"]).splitlines() if ln.strip()]
        if len(code_lines) > ROUTINE_MAX:
            hits.append((name, len(code_lines)))
    return sorted(hits, key=lambda h: -h[1])


# ключевые слова ST — сохраняем при структурной нормализации, остальное → ID/N
ST_KEYWORDS = {
    "if", "then", "elsif", "else", "end_if", "for", "to", "by", "do", "end_for",
    "while", "end_while", "repeat", "until", "end_repeat", "case", "of", "end_case",
    "var", "var_input", "var_output", "var_in_out", "var_global", "var_temp",
    "var_external", "constant", "retain", "end_var", "and", "or", "xor", "not",
    "mod", "true", "false", "return", "exit", "continue",
}
_TOK_RE = re.compile(r"[A-Za-z_]\w*|\d+\.?\d*|:=|<=|>=|<>|[-+*/();.,\[\]<>=]")


def _struct_norm(line):
    """Идентификаторы → ID, числа → N, ключевые слова/операторы сохранены.
    Так структурно совпадающие копии контуров (переименованные теги) детектятся."""
    out = []
    for tok in _TOK_RE.findall(line):
        if tok[0].isalpha() or tok[0] == "_":
            low = tok.lower()
            out.append(low if low in ST_KEYWORDS else "ID")
        elif tok[0].isdigit():
            out.append("N")
        else:
            out.append(tok)
    return " ".join(out)


def _norm_lines_struct(body):
    out = []  # (orig_lineno, struct_norm)
    for i, raw in enumerate(strip_comments(body).splitlines(), 1):
        s = _struct_norm(raw.strip())
        if s.strip():
            out.append((i, s))
    return out


def heur_copy_paste(pous, window=8, min_subst=4):
    """Структурно-совпадающие блоки ≥`window` содержательных строк, повторяющиеся ≥2 раз.
    Ловит copy-paste контуров с переименованными тегами. Результаты АГРЕГИРУЮТСЯ по набору
    участвующих POU, чтобы один большой дубль-регион не дробился на десятки находок.

    Возвращает list[dict]: {pous, blocks, lines, intra, repeats} отсортированный по объёму."""
    index = {}  # struct-ключ окна -> [(pou, start_line, end_line)]
    for name, d in pous.items():
        nl = _norm_lines_struct(d["body"])
        for a in range(len(nl) - window + 1):
            chunk = nl[a:a + window]
            texts = [t for _, t in chunk]
            subst = sum(1 for t in texts if ":=" in t or "(" in t)
            if subst < min_subst:
                continue
            key = "\n".join(texts)
            index.setdefault(key, []).append((name, chunk[0][0], chunk[-1][0]))

    # дедуп перекрывающихся окон одного региона
    blocks = []
    covered = set()  # (pou, line)
    for occ in index.values():
        if len(occ) < 2:
            continue
        first = occ[0]
        if (first[0], first[1]) in covered:
            continue
        for (p, s, e) in occ:
            for ln in range(s, e + 1):
                covered.add((p, ln))
        blocks.append(occ)

    # агрегация по набору участвующих POU
    groups = {}
    for occ in blocks:
        pset = frozenset(p for p, _, _ in occ)
        g = groups.setdefault(pset, {"blocks": 0, "lines": {}, "max_rep": 0})
        g["blocks"] += 1
        g["max_rep"] = max(g["max_rep"], len(occ))
        for p, s, e in occ:
            g["lines"].setdefault(p, set()).update(range(s, e + 1))

    results = []
    for pset, g in groups.items():
        total_lines = sum(len(v) for v in g["lines"].values())
        results.append({
            "pous": sorted(pset), "blocks": g["blocks"], "lines": total_lines,
            "intra": len(pset) == 1, "repeats": g["max_rep"],
        })
    results.sort(key=lambda r: -r["lines"])
    return results


# ---------- channel-mismatch: «скопировали соседний канал и не всё перенумеровали» ----------
#
# Класс дефектов, найденный при ревью боевого проекта: блок копируют с соседнего котла/насоса и
# часть индексов не перенумеровывают. Все имена существуют, типы сходятся, компилятор
# молчит — и остальные наши правила молчат тоже. В проектах-семействах (каскады котлов,
# группы насосов, зеркальные контуры) дефект системный.
#
# Индекс — это число, ПЕРЕД которым буква или подчёркивание. Наивное `\b(\d+)\b` здесь
# не работает: в `bPump1_Idle` между `1` и `_` границы слова нет, и индекс не находится
# вовсе. Побочный и важный плюс такой формы — литералы (`:= 1`, `T#5S`) и индексы
# массивов (`arr[1]`) отсекаются сами: перед ними не буква.
_CHAN_IDX = re.compile(r"(?<=[A-Za-z_])(\d+)(?![0-9])")
_CHAN_MEMBER = re.compile(r"\b([A-Za-z_][A-Za-z_0-9]*?)_?(\d+)_([A-Za-z_0-9]+)\b")
_CHAN_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)", re.S)
_CHAN_ARG = re.compile(r"([A-Za-z_]\w*)\s*(?::=|=>)\s*([^,]+)")

FAMILY_MIN_MEMBERS = 3      # два канала — это не семейство, а пара
INDEX_GROUP_MIN = 3         # минимум строк в группе, иначе «большинства» не существует
INDEX_STABLE = 0.75         # доля строк, где отношение позиций держится


def _families(text):
    """base → {индекс канала: {суффиксы полей}} для имён вида `kotel_4_alarms3`."""
    fam = {}
    for m in _CHAN_MEMBER.finditer(text):
        base, idx, suf = m.group(1), int(m.group(2)), m.group(3).lower()
        fam.setdefault(base, {}).setdefault(idx, set()).add(suf)
    return fam


def heur_family_gap(pous, root, extra=""):
    """Поле есть у всех каналов семейства, кроме ровно одного, — и там оно объявлено.

    Опора на объявления обязательна: разный состав полей у каналов — норма (разное
    оборудование), и без этой проверки правило зашумит. «Объявлено у всех, используется
    у всех кроме одного» — уже сильный сигнал, что блок скопировали и не дописали.
    """
    per_pou = {}          # (base, idx, suf) → POU, где поле реально используется
    # extra — использования вне программ. На боевом проекте без этого правило дало ложное
    # «у канала 2 поле не заполняется»: весь погодный график собран объектами
    # «Преобразование единиц», и в ST его уставок нет ни одной строкой.
    all_text = [extra or ""]
    for name, d in pous.items():
        text = strip_comments(d.get("fulltext") or d["body"])
        all_text.append(text)
        for m in _CHAN_MEMBER.finditer(text):
            per_pou.setdefault((m.group(1), int(m.group(2)), m.group(3).lower()), name)

    used = _families("\n".join(all_text))
    declared = _families("\n".join(v.get("name") or "" for gv in root.iter(q("globalVars"))
                                   for v in gv.findall(q("variable"))))
    hits = []
    for base, chans in sorted(used.items()):
        if len(chans) < FAMILY_MIN_MEMBERS:
            continue
        dec = declared.get(base, {})
        if not all(i in dec for i in chans):
            continue                      # канал вообще не объявлен — не наш случай
        common = set.intersection(*(dec[i] for i in chans))
        for suf in sorted(common):
            miss = [i for i in chans if suf not in chans[i]]
            have = sorted(i for i in chans if suf in chans[i])
            # ровно один отстающий: два и больше — это конфигурация, а не опечатка
            if len(miss) == 1 and len(have) >= 2:
                pou = next((per_pou.get((base, i, suf)) for i in have
                            if per_pou.get((base, i, suf))), "")
                hits.append((pou, base, miss[0], suf, have))
    return hits


def heur_param_channel_mismatch(pous):
    """В вызове FB имя параметра говорит про канал L, а значение берётся из канала M.

    Флагуем только когда нумерация каналов в этом же вызове ДОКАЗАНА: есть согласованные
    пары минимум для двух каналов. Иначе имя параметра и имя сигнала просто нумеруются
    по-разному — обычное дело, и правило зашумело бы.
    """
    hits = []
    for name, d in pous.items():
        src = strip_comments(d["body"])
        for m in _CHAN_CALL.finditer(src):
            fb, args = m.group(1), m.group(2)
            if ":=" not in args and "=>" not in args:
                continue
            line0 = src[:m.start()].count("\n") + 1
            chan = {}
            for a in _CHAN_ARG.finditer(args):
                pname, val = a.group(1), a.group(2)
                pidx = _CHAN_IDX.findall(pname)
                vidx = set(_CHAN_IDX.findall(val))
                if not pidx or not vidx:
                    continue
                chan.setdefault(pidx[-1], []).append((pname, val.strip(), pidx[-1] in vidx))
            proven = {ch for ch, rows in chan.items() if any(ok for *_, ok in rows)}
            if len(proven) < 2:
                continue
            for ch in sorted(proven):
                for pname, val, ok in chan[ch]:
                    if ok:
                        continue
                    other = sorted(set(_CHAN_IDX.findall(val)) & (proven - {ch}))
                    if other:
                        hits.append((name, line0, fb, pname, val[:70], ch, other))
    return hits


def _index_signature(line):
    """→ (шаблон с `#` вместо индексов, вектор индексов) для группировки однотипных строк."""
    idx = []

    def sub(m):
        idx.append(int(m.group(1)))
        return "#"
    tpl = re.sub(r"\s+", " ", _CHAN_IDX.sub(sub, line)).strip()
    return tpl, tuple(idx)


def heur_index_mismatch(pous):
    """В группе однотипных строк одна расставляет индексы иначе, чем все остальные.

    Ищем не «позиционный паттерн» строки целиком, а УСТОЙЧИВОЕ отношение конкретной пары
    позиций (v[i]==v[j] в ≥75% строк группы). Паттерн в лоб давал 48 ложных на двух
    экспортах: в `gvl.kotel_1_alarms1 := 1` номер котла случайно совпадает с номером блока
    аварий, а совпадение чисел из разных измерений — норма, не дефект. При переходе к
    отношению пары такая группа отбрасывается целиком: доля совпадений там мала.
    """
    hits = []
    for name, d in pous.items():
        src = strip_comments(d["body"])
        groups = {}
        for n, line in enumerate(src.splitlines(), 1):
            s = line.strip()
            if len(s) < 8 or ":=" not in s:
                continue
            tpl, vec = _index_signature(s)
            if len(vec) < 2:
                continue
            groups.setdefault(tpl, []).append((n, vec, s))
        for rows in groups.values():
            if len(rows) < INDEX_GROUP_MIN:
                continue
            k = len(rows[0][1])
            if any(len(v) != k for _, v, _ in rows):
                continue
            for i in range(k):
                for j in range(i + 1, k):
                    eq = [r for r in rows if r[1][i] == r[1][j]]
                    ne = [r for r in rows if r[1][i] != r[1][j]]
                    if not ne or len(eq) / len(rows) < INDEX_STABLE:
                        continue
                    for n, vec, s in ne:
                        hits.append((name, n, i + 1, j + 1, vec[i], vec[j],
                                     len(eq), len(rows), s[:110]))
    return hits


# ---------- self-enable: команда зависит от собственной обратной связи ----------
#
# Боевой случай: на вход FB защиты подан ФАКТ вращения насоса, а выход
# `bStartAllow := bStartCmd AND NOT bBlocked` заведён в команду пуска. Насос стоит →
# разрешения нет → команды нет → стоит. Контур не запускается вообще, и ни компилятор,
# ни остальные наши правила этого не видят: имена существуют, типы сходятся.
#
# Точность держится на слове КОМБИНАЦИОННАЯ. Выход `bBlocked` тоже зависит от входа,
# но через память (счётчик пусков за час) — и использовать его в разрешении законно,
# это и есть правильная правка. Правило на «любой зависимости» зарубило бы исправленный
# вариант вместе с дефектным, то есть было бы бесполезным.
_SE_ASSIGN = re.compile(r"^\s*([\w.\[\]]+)\s*:=\s*([^;]+);", re.M)
_SE_IDENT = re.compile(r"\b([A-Za-z_]\w*(?:\.\w+)?)\b")
_SE_CALL = re.compile(r"\b(\w+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)", re.S)
_SE_IN = re.compile(r"(\w+)\s*:=\s*([^,]+)")
_SE_OUT = re.compile(r"(\w+)\s*=>\s*([^,)]+)")
# обратная связь «оборудование реально работает»: факт вращения, а не команда на него
_SE_FEEDBACK = re.compile(r"work|running|state|feedback|fact", re.I)
_SE_COMMAND = re.compile(r"\brun_|\bcmd_|\bstart_|_run\b|_cmd\b", re.I)


def _iface_names(iface, tag):
    """Имена переменных одной секции интерфейса (inputVars/outputVars/localVars).

    Типы экземпляров FB лежат в декларациях, а не в теле: искать `имя : Тип` регэкспом
    по телу ST бессмысленно — в PLCopenXML тело и localVars разнесены (грабля Г1,
    из-за неё первый прогон прототипа дал ноль находок).
    """
    if iface is None:
        return {}
    sec = iface.find(q(tag))
    if sec is None:
        return {}
    out = {}
    for v in sec.findall(q("variable")):
        te = v.find(q("type"))
        typ = ""
        if te is not None:
            for c in te:
                typ = c.get("name") or loc(c)
        out[v.get("name")] = typ
    return out


def _combinational_inputs(body, ins, outs):
    """{выход: множество входов, от которых он зависит В ТОМ ЖЕ СКАНЕ}.

    Только data-flow — по правым частям присваиваний. Учитывать зависимости через условия
    IF нельзя: в реальном проекте команда транзитивно «зависит» от обратной связи через
    цепочку «нет отклика → таймер → авария → выбор ветки», а это штатная защита, а не петля.
    Прототип на control-flow взрывался ложными, на data-flow даёт ноль.
    """
    deps = {}
    for lhs, rhs in _SE_ASSIGN.findall(strip_comments(body)):
        deps.setdefault(lhs.split("[")[0], set()).update(_SE_IDENT.findall(rhs))
    res = {}
    for o in outs:
        seen, stack, acc = set(), [o], set()
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for d in deps.get(cur, ()):
                acc.add(d)
                stack.append(d)
        hit = acc & set(ins)
        if hit:
            res[o] = hit
    return res


def _chan_idx(name):
    """Последний индекс канала в имени: run_nasos_TC1 → '1'."""
    found = _CHAN_IDX.findall(name or "")
    return found[-1] if found else ""


def heur_self_enable(pous):
    """Команда пуска получена из выхода FB, который в том же скане равен функции входа,
    а на этот вход подана обратная связь того же канала."""
    fb_comb = {}
    for name, d in pous.items():
        ins = _iface_names(d.get("iface"), "inputVars")
        outs = _iface_names(d.get("iface"), "outputVars")
        if not ins or not outs:
            continue
        comb = _combinational_inputs(d["body"], ins, outs)
        if comb:
            fb_comb[name] = comb

    hits = []
    for pou, d in pous.items():
        src = strip_comments(d["body"])
        inst = _iface_names(d.get("iface"), "localVars")
        out_src = {}          # переменная-приёмник ← (тип FB, выход, {вход: поданный сигнал})
        for m in _SE_CALL.finditer(src):
            iname, args = m.group(1), m.group(2)
            ftype = inst.get(iname)
            if not ftype or ftype not in fb_comb:
                continue
            ins_map = {a: b.strip() for a, b in _SE_IN.findall(args)}
            for oname, target in ((a, b.strip()) for a, b in _SE_OUT.findall(args)):
                deps_in = fb_comb[ftype].get(oname)
                if deps_in:
                    out_src[target] = (ftype, oname,
                                       {i: ins_map.get(i, "") for i in deps_in})
        if not out_src:
            continue
        for m in _SE_ASSIGN.finditer(src):
            lhs, rhs = m.group(1), m.group(2)
            cmd = lhs.split(".")[-1]
            if not _SE_COMMAND.search(cmd):
                continue
            line = src[:m.start()].count("\n") + 1
            idx = _chan_idx(cmd)
            for var, (ftype, oname, ins_map) in out_src.items():
                if not re.search(rf"\b{re.escape(var)}\b", rhs):
                    continue
                for inp, sig in ins_map.items():
                    if not sig or not _SE_FEEDBACK.search(sig):
                        continue
                    # тот же канал: команда и обратная связь должны быть про один насос
                    if idx and _chan_idx(sig) == idx:
                        hits.append((pou, line, lhs, var, ftype, oname, inp, sig.strip(),
                                     m.group(0).strip()[:110]))
    return hits


def polarity_signal(pous):
    """Доля тегов класса «реле перепада», трактованных миноритарно (сигнал, НЕ правило).

    Замер по пяти проектам: конфликта ВНУТРИ одного тега нет нигде, полярность каждого
    входа настраивается своей инверсией DI, и смешанные соглашения формально рабочие —
    правило-ошибка дало бы шум и споры на 2 проектах из 5. Но на объекте это мина:
    наладчик ставит тумблеры одинаково (реле-то одинаковые), и контур встаёт. Поэтому
    считаем частоту и ждём данных, а не флагуем.
    """
    pos = neg = 0
    for d in pous.values():
        for ln in strip_comments(d["body"]).splitlines():
            for m in re.finditer(r"\b(NOT\s+)?(?:\w+\.)?(perepad\w*)\b", ln, re.I):
                if m.group(1):
                    pos += 1      # `NOT perepad` в условии аварии → TRUE = есть перепад
                else:
                    neg += 1
    total = pos + neg
    minority = min(pos, neg)
    return {"polarity_perepad_tags": total,
            # 0 — соглашение одно на проект; >0 — в проекте два соглашения сразу
            "polarity_perepad_minority_pct": round(100 * minority / total) if total else 0}


# ---------- разбор ST на дерево ветвей (нужен двум правилам ниже) ----------
# Условие в ST не содержит `;`, поэтому `[^;]*?` — надёжная граница для IF..THEN.
# Сканируем в ДВА прохода: сначала структурные слова, потом текст между ними режем
# по `;` на операторы. Один проход с «оператором» в альтернативах не годится: `[^;]+;`
# стартует раньше ключевого слова и съедает `IF ... THEN` вместе с телом ветви.
_ST_KW = re.compile(r"""
      (?P<endif>\bEND_IF\b)
    | (?P<elsif>\bELSIF\b(?P<ec>[^;]*?)\bTHEN\b)
    | (?P<else>\bELSE\b)
    | (?P<if>\bIF\b(?P<ic>[^;]*?)\bTHEN\b)
    | (?P<case>\bCASE\b[^;]*?\bOF\b) | (?P<endcase>\bEND_CASE\b)
    | (?P<for>\bFOR\b[^;]*?\bDO\b)   | (?P<endfor>\bEND_FOR\b)
    | (?P<while>\bWHILE\b[^;]*?\bDO\b) | (?P<endwhile>\bEND_WHILE\b)
    | (?P<repeat>\bREPEAT\b) | (?P<until>\bUNTIL\b[^;]*?\bEND_REPEAT\b)
""", re.I | re.S | re.X)
_ST_OPEN = ("case", "for", "while", "repeat")
_ST_CLOSE = ("endcase", "endfor", "endwhile", "until")
_ST_KINDS = ("endif", "elsif", "else", "if", "case", "endcase", "for", "endfor",
             "while", "endwhile", "repeat", "until")


def st_blocks(body):
    """ST → узлы: {kind:'stmt',line,text} | {kind:'if',line,has_else,branches:[{cond,line,
    items,is_else}]} | {kind:'loop',line,items}. CASE/FOR/WHILE — ветвь НЕ исчерпывающая."""
    src = blank_comments(body or "")
    root = []
    stack = [{"kind": "seq", "cur": root}]

    def lineno(pos):
        return src[:pos].count("\n") + 1

    def flush(a, b):
        pos = a
        for part in re.split(r"(;)", src[a:b]):
            if part == ";":
                pos += 1
                continue
            txt = part.strip()
            if txt:
                stack[-1]["cur"].append(
                    {"kind": "stmt", "text": txt + ";",
                     "line": lineno(pos + len(part) - len(part.lstrip()))})
            pos += len(part)

    prev = 0
    for m in _ST_KW.finditer(src):
        flush(prev, m.start())
        prev = m.end()
        kind = next(k for k in _ST_KINDS if m.group(k) is not None)
        line = lineno(m.start())
        cur = stack[-1]["cur"]
        if kind == "if":
            node = {"kind": "if", "line": line, "has_else": False,
                    "branches": [{"cond": m.group("ic"), "line": line,
                                  "items": [], "is_else": False}]}
            cur.append(node)
            stack.append({"kind": "if", "node": node, "cur": node["branches"][0]["items"]})
        elif kind in ("elsif", "else"):
            if stack[-1]["kind"] != "if":
                continue          # ELSE у CASE — не ветвь IF
            node = stack[-1]["node"]
            br = {"cond": m.group("ec") if kind == "elsif" else "", "line": line,
                  "items": [], "is_else": kind == "else"}
            node["branches"].append(br)
            node["has_else"] = node["has_else"] or kind == "else"
            stack[-1]["cur"] = br["items"]
        elif kind == "endif":
            if stack[-1]["kind"] == "if":
                stack.pop()
        elif kind in _ST_OPEN:
            node = {"kind": "loop", "line": line, "items": []}
            cur.append(node)
            stack.append({"kind": "loop", "node": node, "cur": node["items"]})
        elif kind in _ST_CLOSE:
            if stack[-1]["kind"] == "loop":
                stack.pop()
    flush(prev, len(src))
    return root


_ST_ASSIGN = re.compile(r"^\s*([A-Za-z_][\w.]*(?:\[[^\]]*\])?)\s*:=\s*(.+?);?\s*$", re.S)


def st_key(name):
    """Ключ переменной: регистр не значащий, префикс `gvl.` снят (в проектах с
    qualified_only глобал пишется `gvl.X`, а в GVL объявлен как `X`)."""
    k = (name or "").strip().lower()
    return k[4:] if k.startswith("gvl.") else k


def st_assignment(text):
    m = _ST_ASSIGN.match(text)
    if not m or "(" in m.group(1):
        return None
    return m.group(1).strip(), m.group(2).strip()


def st_assigned_in(items):
    """Всё, чему присваивается внутри узлов (рекурсивно)."""
    out = set()
    for it in items:
        if it["kind"] == "stmt":
            a = st_assignment(it["text"])
            if a:
                out.add(st_key(a[0]))
        elif it["kind"] == "if":
            for b in it["branches"]:
                out |= st_assigned_in(b["items"])
        else:
            out |= st_assigned_in(it["items"])
    return out


def st_defs(items):
    """Исчерпывающие присваивания ветви: {ключ: [(rhs, line), ...]}.

    Присвоили не на всех путях — ЗАБЫВАЕМ переменную: в этом скане у неё может
    остаться значение прошлого цикла, и подстановка была бы неверной."""
    cur = {}
    for it in items:
        if it["kind"] == "stmt":
            a = st_assignment(it["text"])
            if a:
                cur[st_key(a[0])] = [(a[1], it["line"])]
        elif it["kind"] == "if" and it["has_else"]:
            per = [st_defs(b["items"]) for b in it["branches"]]
            common = set(per[0])
            for d in per[1:]:
                common &= set(d)
            for d in per:
                for v in d:
                    if v not in common:
                        cur.pop(v, None)
            for v in common:
                cur[v] = [x for d in per for x in d[v]]
        else:
            for v in st_assigned_in([it]):
                cur.pop(v, None)
    return cur


# ---------- мини-решатель булевых формул ----------
# Сравнения и вызовы функций целиком становятся непрозрачным атомом: правилу нужна
# только структура AND/OR/XOR/NOT, арифметику оно не считает.
_BTOK = re.compile(r"\s*(\(|\)|\bAND\b|\bOR\b|\bXOR\b|\bNOT\b|[^\s()]+)", re.I)
_BCONT = re.compile(r"^(?:=|<>|<=|>=|<|>|\+|-|\*|/|\bMOD\b)$", re.I)
BOOL_MAX_ATOMS = 14          # 2^14 переборов — предел, выше формулу не трогаем


class _BoolParser:
    def __init__(self, text):
        self.toks, pos = [], 0
        while pos < len(text):
            m = _BTOK.match(text, pos)
            if not m:
                break
            self.toks.append(m.group(1))
            pos = m.end()
        self.i = 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def up(self):
        t = self.peek()
        return t.upper() if t else None

    def _chain(self, op, nxt):
        f = nxt()
        if f is None:
            return None
        parts = [f]
        while self.up() == op:
            self.i += 1
            f = nxt()
            if f is None:
                return None
            parts.append(f)
        return parts[0] if len(parts) == 1 else (op.lower(), parts)

    def p_or(self):
        return self._chain("OR", self.p_xor)

    def p_xor(self):
        return self._chain("XOR", self.p_and)

    def p_and(self):
        return self._chain("AND", self.p_not)

    def p_not(self):
        if self.up() == "NOT":
            self.i += 1
            f = self.p_not()
            return None if f is None else ("not", f)
        return self.p_prim()

    def p_prim(self):
        if self.peek() == "(":
            save = self.i
            self.i += 1
            f = self.p_or()
            if f is not None and self.peek() == ")":
                self.i += 1
                nxt = self.peek()
                # `(x + 1) > y` — скобка была частью арифметики, а не булевой группой
                if nxt is None or not _BCONT.match(nxt):
                    return f
            self.i = save
        return self.p_atom()

    def p_atom(self):
        start, depth = self.i, 0
        while self.i < len(self.toks):
            t = self.toks[self.i]
            u = t.upper()
            if depth == 0 and (u in ("AND", "OR", "XOR", "NOT") or t == ")"):
                break
            depth += 1 if t == "(" else (-1 if t == ")" else 0)
            self.i += 1
        if self.i == start:
            return None
        raw = " ".join(self.toks[start:self.i])
        norm = re.sub(r"\s+", "", raw).lower()
        if norm in ("true", "1"):
            return ("const", True)
        if norm in ("false", "0"):
            return ("const", False)
        return ("atom", norm[4:] if norm.startswith("gvl.") else norm, raw)


def bool_parse(text):
    """Формула или None (не разобралось / остался хвост)."""
    if not text or not text.strip():
        return None
    p = _BoolParser(text)
    f = p.p_or()
    return f if f is not None and p.i == len(p.toks) else None


def bool_atoms(f, acc=None):
    acc = set() if acc is None else acc
    if f[0] == "atom":
        acc.add(f[1])
    elif f[0] == "not":
        bool_atoms(f[1], acc)
    elif f[0] in ("and", "or", "xor"):
        for s in f[1]:
            bool_atoms(s, acc)
    return acc


def bool_eval(f, env):
    k = f[0]
    if k == "const":
        return f[1]
    if k == "atom":
        return env[f[1]]
    if k == "not":
        return not bool_eval(f[1], env)
    if k == "and":
        return all(bool_eval(s, env) for s in f[1])
    if k == "or":
        return any(bool_eval(s, env) for s in f[1])
    r = False
    for s in f[1]:
        r ^= bool_eval(s, env)
    return r


def bool_const(f):
    """True/False, если формула тождественна константе, иначе None."""
    names = sorted(bool_atoms(f))
    if len(names) > BOOL_MAX_ATOMS:
        return None
    vals = set()
    for mask in range(1 << len(names)):
        vals.add(bool_eval(f, {n: bool(mask >> i & 1) for i, n in enumerate(names)}))
        if len(vals) > 1:
            return None
    return vals.pop() if vals else None


# ---------- таймер сбрасывается собственным условием отсчёта ----------
_TR_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)", re.S)
_TR_IN = re.compile(r"\b(?:IN|CLK)\s*:=\s*([^,)]+)", re.I | re.S)
_TR_SIMPLE = re.compile(r"^[A-Za-z_][\w.]*(?:\[[^\]]*\])?$")
_TR_KNOWN = ("TON", "TOF", "TP", "TONOF", "BLINK")


def _tr_polarity(kind):
    """Что именно ломает отсчёт у таймера этого типа.

    Дефект один и тот же — отсчёт разрушает код, который сам же таймер и открывает, —
    но «неправильная запись» у разных таймеров разная. TON отсчитывает, пока вход
    держится TRUE, значит губит его гашение. TOF отсчитывает задержку выключения,
    пока вход держится FALSE, значит губит его повторное взведение: выдержка не
    истекает никогда, и оборудование не выключается.

    TP и BLINK не подходят ни подо что: у TP вход работает как фронт, импульс идёт
    независимо от входа, а BLINK — мигалка без выдержки. На них правило молчит.

    Неизвестный тип (своя обёртка над таймером, видим только `.Q`) считаем задержкой
    включения: так правило вело себя до разделения полярностей, и на корпусе это
    давало ноль ложных."""
    if kind == "TOF":
        return ("off",)
    if kind == "TONOF":
        return ("on", "off")
    if kind in ("TP", "BLINK"):
        return ()
    return ("on",)


def _tr_in_var(text):
    """`T(IN := V)` → ('T','V'), если V — простая булева переменная, иначе None."""
    for m in _TR_CALL.finditer(text):
        a = _TR_IN.search(m.group(2))
        if not a:
            continue
        v = a.group(1).strip()
        if _TR_SIMPLE.match(v) and v.upper() not in ("TRUE", "FALSE"):
            return m.group(1), v
    return None


def _tr_forced(items, var, want, start=0):
    """Приходит ли var к want на ВСЕХ путях среди items[start:]? → строка или None.

    `want=False` — гашение входа (губит TON), `want=True` — повторное взведение
    (губит TOF). В обе стороны требование одинаковое: значение должно быть именно
    константой. Любое другое присваивание (`V := alarm OR cx`) — не сброс, а пересчёт
    входа из других сигналов: с таким послаблением правило дало 9 ложных из 9 на
    боевом 1_4pump, где четыре каскада пересчитывают stop_pause_N после вызова."""
    k = st_key(var)
    for it in items[start:]:
        if it["kind"] == "stmt":
            a = st_assignment(it["text"])
            if not a or st_key(a[0]) != k:
                continue
            f = bool_parse(a[1])
            if f is None:
                continue
            val = bool_const(f)
            if val is want:
                return it["line"]
            if val is (not want):
                return None          # увели в другую сторону — дефекта нет
        elif it["kind"] == "if" and it["has_else"]:
            lines = [_tr_forced(b["items"], var, want) for b in it["branches"]]
            if all(lines):
                return min(lines)    # переписали в каждой ветви — путь не обойти
    return None


def _tr_rearmed(items, start, inst, var):
    """Между вызовом и сбросом таймер взвели ДРУГИМ условием → паттерн законный."""
    for it in items[start:]:
        if it["kind"] != "stmt":
            continue
        got = _tr_in_var(it["text"])
        if got and got[0].lower() == inst.lower() and st_key(got[1]) != st_key(var):
            return True
    return False


def _tr_scan(pou, items, timers, hits):
    for i, it in enumerate(items):
        if it["kind"] == "stmt":
            got = _tr_in_var(it["text"])
            if got and got[0].lower() in timers and not _tr_rearmed(items, i + 1, *got):
                for kind in timers[got[0].lower()]:
                    # 'on' — губит гашение входа (TON), 'off' — повторное взведение (TOF)
                    rl = _tr_forced(items, got[1], kind == "off", i + 1)
                    if rl:
                        hits.append((pou, it["line"], got[0], got[1], rl,
                                     re.sub(r"\s+", " ", it["text"]).strip()[:110], kind))
                        break
        elif it["kind"] == "if":
            for b in it["branches"]:
                _tr_scan(pou, b["items"], timers, hits)
        else:
            _tr_scan(pou, it["items"], timers, hits)


def heur_timer_reset(pous):
    """Таймер отсчитывает по переменной, которую гасят ниже в той же ветви.

    Боевой случай (пауза разгона пары раб/резерв): `pauseRazgon(IN := run_2);`, а run_2
    гасится в обеих ветвях следующего IF. Скан N — таймер пошёл, run_2 сброшен; скан N+1 —
    IN уже FALSE, таймер обнулён, условие открыто. Пауза живёт один цикл задачи вместо
    уставки: на модели 0,01 с при заданных 30 с. Уставка есть на экране, оператор её
    крутит, она ни на что не влияет.

    Точность держится на том, что сброс обязан быть НА ВСЕХ ПУТЯХ после вызова в той же
    ветви. Сброс под условием (`IF T.Q THEN V := FALSE`) — штатный одновыстрел, таймер
    успевает отсчитать PT. Сброс в соседней ветви — тоже норма. Поэтому правило смотрит
    дерево ветвей, а не соседство строк."""
    hits = []
    for name, d in pous.items():
        body = blank_comments(d["body"])
        # «таймер» = экземпляр, чей .Q читают в этом POU, либо объявленный TON/TOF/TP.
        # Без этого правило ловило бы любой FB со входом IN.
        decl = {n.lower(): (t or "").upper()
                for n, t in _iface_names(d.get("iface"), "localVars").items()}
        names = {m.group(1).lower() for m in re.finditer(r"\b([A-Za-z_]\w*)\.Q\b", body, re.I)}
        names |= {n for n, t in decl.items() if t in _TR_KNOWN}
        # имя → какие полярности для него дефект; пустой набор (TP, BLINK) выпадает
        timers = {n: _tr_polarity(decl.get(n, "")) for n in names}
        timers = {n: p for n, p in timers.items() if p}
        if timers:
            _tr_scan(name, st_blocks(d["body"]), timers, hits)
    return hits


# ---------- таймер не может отсчитать: три находки из матрицы ----------
#
# Правила ниже найдены перебором сочетаний (prototypes/timer-matrix) и проверены
# эмулятором скана: в каждой клетке измерено, доходит ли накопленное время до
# уставки. Там, где не доходит ни при каком поведении входов, дефект в коде,
# а не в стенде.

def _tm_sites(items, inst, conds, out):
    """Места вызова экземпляра вместе с условиями ветвей, внутри которых он лежит."""
    for it in items:
        if it["kind"] == "stmt":
            for m in _TR_CALL.finditer(it["text"]):
                if m.group(1).lower() != inst:
                    continue
                a = _TR_IN.search(m.group(2))
                out.append({"conds": list(conds), "in": a.group(1).strip() if a else None,
                            "line": it["line"], "items": items,
                            "text": re.sub(r"\s+", " ", it["text"]).strip()[:110]})
        elif it["kind"] == "if":
            for b in it["branches"]:
                _tm_sites(b["items"], inst, conds + ([] if b.get("is_else") else [b["cond"]]), out)
        else:
            _tm_sites(it["items"], inst, conds, out)


def _tm_implies(cond, var):
    """Условие ложно всегда, когда var = FALSE? Тогда внутрь ветви при снятом
    входе не попасть — а выдержке выключения считать именно там."""
    f = bool_parse(cond)
    if f is None:
        return False
    atoms = sorted(bool_atoms(f))
    k = st_key(var)
    if k not in atoms or len(atoms) > BOOL_MAX_ATOMS:
        return False
    rest = [a for a in atoms if a != k]
    for mask in range(1 << len(rest)):
        env = {a: bool(mask >> i & 1) for i, a in enumerate(rest)}
        env[k] = False
        if bool_eval(f, env):
            return False
    return True


_EDGES = ("R_TRIG", "F_TRIG")
_STATEFUL = _TR_KNOWN + _EDGES


def _tm_instances(d, kinds=None):
    """Экземпляры ФБ с памятью: имя → тип."""
    kinds = kinds or _TR_KNOWN
    return {n.lower(): (t or "").upper()
            for n, t in _iface_names(d.get("iface"), "localVars").items()
            if (t or "").upper() in kinds}


def heur_timer_off_delay_branch(pous):
    """TOF вызывается только внутри ветви, условие которой требует его же вход.

    Задержка выключения отсчитывается, пока вход СНЯТ. Если таймер вызывают
    только там, где вход поднят, в момент снятия команды вызова нет вовсе,
    накопленное время стоит на нуле, и выдержка не кончается никогда —
    оборудование не выключается. Для TON тот же код безупречен: он и должен
    считать, пока условие истинно. Замер на эмуляторе: ET остался 0 из 5000 мс
    при всех четырёх поведениях входов."""
    hits = []
    for name, d in pous.items():
        tree = st_blocks(d["body"] or "")
        for inst, typ in _tm_instances(d).items():
            if typ not in ("TOF", "TONOF"):
                continue
            sites = []
            _tm_sites(tree, inst, [], sites)
            if not sites:
                continue
            if all(s["in"] and any(_tm_implies(c, s["in"]) for c in s["conds"]) for s in sites):
                hits.append((name, sites[0]["line"], inst, sites[0]["in"], sites[0]["text"]))
    return hits


def heur_fb_call_overwritten(pous):
    """Два вызова одного экземпляра подряд в одной ветви с разными входами.

    Второй вызов перетирает первый в том же скане: до таймера доходит только
    последнее значение входа. Вызовы во ВЗАИМОИСКЛЮЧАЮЩИХ ветвях — приём
    законный («в одной ветви пускаем, в другой сбрасываем»), он встретился на
    корпусе семь раз и правилом не трогается."""
    hits = []
    for name, d in pous.items():
        tree = st_blocks(d["body"] or "")
        for inst in _tm_instances(d, _STATEFUL):
            sites = []
            _tm_sites(tree, inst, [], sites)
            with_in = [s for s in sites if s["in"]]
            for i in range(len(with_in) - 1):
                a, b = with_in[i], with_in[i + 1]
                if a["items"] is b["items"] and st_key(a["in"]) != st_key(b["in"]):
                    hits.append((name, b["line"], inst, a["in"], b["in"], a["line"], b["text"]))
                    break
    return hits


def heur_edge_lost_in_own_branch(pous):
    """R_TRIG/F_TRIG вызывают только внутри ветви, требующей его же вход.

    Детектор сравнивает вход с тем, что видел в ПРОШЛЫЙ раз. Если его вызывают
    только там, где вход поднят, то снятия входа он не видит вовсе: внутренняя
    память остаётся взведённой, и каждый следующий подъём фронтом уже не
    считается. Замер на эмуляторе: десять переходов входа — одно срабатывание,
    девять потеряны. Первый фронт при этом проходит, поэтому при беглой проверке
    на объекте всё выглядит рабочим."""
    hits = []
    for name, d in pous.items():
        tree = st_blocks(d["body"] or "")
        for inst, typ in _tm_instances(d, _EDGES).items():
            sites = []
            _tm_sites(tree, inst, [], sites)
            if not sites:
                continue
            if all(s["in"] and any(_tm_implies(c, s["in"]) for c in s["conds"]) for s in sites):
                hits.append((name, sites[0]["line"], inst, typ, sites[0]["in"], sites[0]["text"]))
    return hits


def heur_timer_preset_missing(pous):
    """У экземпляра нигде не задана уставка: ни в вызове, ни полем, ни в объявлении.

    PT остаётся нулевым, и выход появляется в том же скане, в котором подняли
    вход, — выдержки нет вовсе."""
    hits = []
    for name, d in pous.items():
        body = blank_comments(d["body"] or "")
        iface = d.get("iface")
        tree = st_blocks(d["body"] or "")
        for inst, typ in _tm_instances(d).items():
            sites = []
            _tm_sites(tree, inst, [], sites)
            if not sites:
                continue          # не вызван вовсе — это другое правило
            if any(re.search(r"\bPT\s*:=", _TR_CALL.match(s["text"]).group(2), re.I)
                   for s in sites if _TR_CALL.match(s["text"])):
                continue
            if re.search(rf"\b{re.escape(inst)}\s*\.\s*PT\s*:=", body, re.I):
                continue
            if iface is not None and _tm_decl_has_pt(iface, inst):
                continue
            hits.append((name, sites[0]["line"], inst, typ, sites[0]["text"]))
    return hits


def _tm_decl_has_pt(iface, inst):
    """Уставка задана начальным значением в объявлении: `t : TON := (PT := T#5S);`"""
    for v in iface.iter(q("variable")):
        if (v.get("name") or "").lower() != inst:
            continue
        return "PT" in "".join(v.itertext()).upper()
    return False


# ---------- условие, тождественно ложное после подстановки ----------
_AF_IN = re.compile(r"\bIN\s*:=\s*([^,)]+)", re.I | re.S)
_AF_CALL = re.compile(r"^\s*([A-Za-z_]\w*)\s*\(\s*\)\s*;", re.M)
AF_MAX_COMBOS = 8            # произведение вариантов присваивания; выше — не считаем


def _af_order(pous):
    """Порядок вызова программ из PLC_PRG. Обязателен: подставлять можно только то,
    что присвоено РАНЬШЕ в этом же скане. Для POU, вызванного позже, в условии живёт
    значение прошлого цикла, и свёртка была бы неверной."""
    main = next((n for n in pous if n.lower() in ("plc_prg", "main")), None)
    order = []
    if main:
        for m in _AF_CALL.finditer(blank_comments(pous[main]["body"])):
            order += [n for n in pous if n.lower() == m.group(1).lower() and n not in order]
    return order + [n for n in pous if n not in order]


def _af_alts(var, rhs_list, pou, snap, budget):
    """Варианты формулы для одного атома + плоская цепочка «кто чему равен».
    [] = подставлять нельзя."""
    out = []
    for rhs, line in rhs_list:
        f = bool_parse(rhs)
        if f is None:
            return []                       # хоть один путь не разобрали — молчим
        step = (var, rhs.strip(), pou, line)
        subs = _af_expand(f, snap, budget - 1) if budget > 0 else []
        out += [(g, [step] + ch) for g, ch in subs] or [(f, [step])]
    return out


def _af_expand(f, defs, budget):
    """[(формула, цепочка)] — все комбинации подстановок, [] если подставить нечего.

    У каждого присваивания свой снимок локалов НА МОМЕНТ присваивания. Брать итоговые
    значения нельзя: на боевом проекте это дало ложный FALSE на штатном детекторе фронта
    (`start_edge := (run AND PS) AND NOT run_last;` считается ДО обновления run_last,
    то есть по значению прошлого цикла)."""
    tables = []
    for n in sorted(a for a in bool_atoms(f) if a in defs):
        rhs_list, pou, hop, snap = defs[n]
        alts = _af_alts(n, rhs_list, pou, snap, budget if hop else 0)
        if alts:
            tables.append((n, alts))
    if not tables:
        return []
    total = 1
    for _n, alts in tables:
        total *= len(alts)
    if total > AF_MAX_COMBOS:
        return []
    combos = [({}, [])]
    for n, alts in tables:
        combos = [(dict(m, **{n: a[0]}), ch + a[1]) for m, ch in combos for a in alts]
    return [(_af_apply(f, m), ch) for m, ch in combos]


def _af_apply(f, mapping):
    if f[0] == "atom":
        return mapping.get(f[1], f)
    if f[0] == "not":
        return ("not", _af_apply(f[1], mapping))
    if f[0] in ("and", "or", "xor"):
        return (f[0], [_af_apply(s, mapping) for s in f[1]])
    return f


def _af_check(pou, line, kind, text, defs, hits):
    f = bool_parse(text)
    if f is None or len(bool_atoms(f)) < 2 or bool_const(f) is not None:
        return                      # свёрнуто без подстановки — это другое правило
    variants = _af_expand(f, defs, 2)
    if not variants:
        return
    vals = {bool_const(g) for g, _ch in variants}
    if len(vals) != 1 or None in vals:
        return
    hits.append((pou, line, kind, vals.pop(),
                 re.sub(r"\s+", " ", text).strip()[:110], variants[0][1]))


def _af_walk(pou, items, defs, locals_, hits):
    cur = dict(defs)

    def snap():
        return {k: v for k, v in cur.items() if k in locals_}

    for it in items:
        if it["kind"] == "stmt":
            for m in _AF_IN.finditer(it["text"]):
                _af_check(pou, it["line"], "in", m.group(1), cur, hits)
            a = st_assignment(it["text"])
            if a:
                _af_check(pou, it["line"], "assign", a[1], cur, hits)
                cur[st_key(a[0])] = ([(a[1], it["line"])], pou, 1, snap())
        elif it["kind"] == "if":
            for b in it["branches"]:
                if not b["is_else"]:
                    _af_check(pou, b["line"], "cond", b["cond"], cur, hits)
                _af_walk(pou, b["items"], cur, locals_, hits)
            if it["has_else"]:
                for k, v in st_defs([it]).items():
                    cur[k] = (v, pou, 1, snap())
            else:
                for k in st_assigned_in([it]):
                    cur.pop(k, None)
        else:
            _af_walk(pou, it["items"], cur, locals_, hits)
            for k in st_assigned_in([it]):
                cur.pop(k, None)


def heur_always_false(pous, decl):
    """Условие, которое после подстановки присваиваний этого же скана тождественно
    ложно (или истинно).

    Боевой случай: одна программа формирует команду (`gvl.run_podpitka := gvl.PS_podpitka`),
    другая проверяет её же вместе с источником (`IN := NOT gvl.PS_podpitka AND
    gvl.run_podpitka`). После подстановки — `NOT X AND X`, всегда FALSE: авария «нет воды»
    физически не может сработать, строка в журнале есть, защиты нет. Глазами такое не
    ловится: у владельца тот же дефект воспроизвёлся ВТОРОЙ раз в том же месте.

    Подставляем только то, что в этом скане известно точно: присваивание должно покрывать
    все пути (st_defs), а POU-источник — вызываться раньше по PLC_PRG. Если переменной
    присвоено в нескольких ветвях, подставляем КАЖДОЕ значение и флагуем лишь тогда, когда
    константа выходит при всех — иначе это не дефект, а один из режимов."""
    trees = {n: st_blocks(d["body"]) for n, d in pous.items()}
    gdefs, hits = {}, []
    for pou in _af_order(pous):
        locals_ = set()
        for tag in ("localVars", "inputVars", "outputVars", "inOutVars", "tempVars"):
            locals_ |= {k.lower() for k in _iface_names(pous[pou].get("iface"), tag)}
        _af_walk(pou, trees[pou], dict(gdefs), locals_, hits)
        final = st_defs(trees[pou])
        loc_snap = {k: (v, pou, 1, {}) for k, v in final.items() if k in locals_}
        for k, v in final.items():
            if k in decl or k not in locals_:
                gdefs[k] = (v, pou, 1, loc_snap)
    return hits


# ---------- сигнал состояния читается, но его никто не формирует ----------
# Г5 (главная грабля правила): «не присваивается в ST» ещё не значит «нет источника».
# Команды и уставки законно пишутся с экрана визуализации, а показания датчиков — прямо
# с канала модуля; в PLCopenXML ни того, ни другого в тексте программы не видно. Поэтому
# проверяем только имена, семантически являющиеся сигналами СОСТОЯНИЯ, только булевы,
# и выбрасываем всё, что привязано к каналу в дереве устройств. На боевом корпусе это
# сняло 71 ложное срабатывание из 77: выход FB пишет глобал прямо в вызове (`=>`),
# запись идёт в бит (`gvl.error_bits.0 := TRUE`), диагностический код канала — не BOOL.
_SWS_STATE = re.compile(r"^(?:alarm|error|err|fault|avar|warn|trip)_|"
                        r"_(?:alarm|avar|fault|error)$|^(?:alarm|avaria|avariya)\d*$", re.I)
_SWS_SCREEN = re.compile(r"^(?:run|start|stop|cmd|block|manual|hand|auto|reset|kvit|ack|set|"
                         r"mode|zadanie|rezhim)_|^(?:set|ustavka|zadanie)|"
                         r"_(?:ustavka|zadanie|set|sp|reset|kvit|ack)$|"
                         r"^(?:reset|kvit|ack|block|manual)$", re.I)
_SWS_WRITE = re.compile(r"([A-Za-z_][\w.]*(?:\[[^\]]*\])?)\s*:=|"
                        r"=>\s*([A-Za-z_][\w.]*(?:\[[^\]]*\])?)")
_SWS_IDENT = re.compile(r"\b((?:[A-Za-z_]\w*\.)?[A-Za-z_]\w*)\b")
_SWS_BOOL = re.compile(r"^(?:ARRAY\s*\[[^\]]*\]\s*OF\s*)?BOOL\s*$", re.I)


def _sws_base(name):
    """`gvl.error_bits.0` → `error_bits`: снимаем префикс gvl., индекс массива и побитовый
    доступ. Брать последний компонент нельзя — запись в бит тогда числится записью в «0»."""
    return st_key(re.sub(r"\[[^\]]*\]", "", name or "")).split(".")[0]


def heur_signal_without_source(pous, decl, root, screen_reads=(), screen_writes=()):
    """Авария читается в условии, но её никто не формирует: защита мёртвая.

    Боевой случай: `alarm_kotel[1..3]` и `alarm_peregrev_kotel[1..3]` читаются в трёх местах
    (исключение котла из каскада, общая авария, счётчик для шапки) и не присваиваются нигде —
    обратной связи от котлов на объекте нет вообще. Каскад никогда не узнает, что котёл встал:
    запрос висит, место в очереди не освобождается, в журнале мёртвые строки. Второй боевой
    случай: у одиночных насосов сигнал аварии ждали от электриков, он так и не пришёл, а
    условие блокировки пуска `NOT alarm_nasos_CO` осталось в коде и выполняется всегда.
    """
    io_bound = {st_key(m).split(".")[0]
                for m in _APPVAR_RE.findall(ET.tostring(root, encoding="unicode"))}
    # графику разбираем только по вхождению имён: отличить там чтение от записи нельзя,
    # поэтому всё упомянутое в LD/FBD/SFC/CFC считаем имеющим источник и не трогаем
    graph = set()
    for pou in root.iter(q("pou")):
        for b in pou.iter(q("body")):
            for m in _SWS_IDENT.finditer(graphical_text(b)):
                graph.add(_sws_base(m.group(1)))

    written, read_in = set(), {}
    for name, d in pous.items():
        src = blank_comments(d.get("fulltext", d["body"]))
        for m in _SWS_WRITE.finditer(src):
            written.add(_sws_base(m.group(1) or m.group(2)))
        # читаем ПОСЛЕ снятия левых частей: `x := 0` не делает x прочитанным
        for m in _SWS_IDENT.finditer(_SWS_WRITE.sub(" ", src)):
            read_in.setdefault(_sws_base(m.group(1)), set()).add(name)
    # Экран — полноправный источник: поле ввода уставки и кнопка ПИШУТ переменную.
    # В PLCopenXML этого не видно (отсюда осторожный список исключений по именам),
    # а в .export видно, и тогда «никто не формирует» — факт.
    written |= {_sws_base(n) for n in screen_writes}
    for n in screen_reads:
        read_in.setdefault(_sws_base(n), set()).add("visu")
    # Привязки экранов нам отдали → вывод подтверждён, а не выведен из имени.
    # Это и есть разница между осторожным medium на PLCopenXML и high на .export.
    confirmed = bool(screen_reads or screen_writes)

    hits = []
    for var in sorted(decl):
        k = _sws_base(var)
        if k in written or k in io_bound or k in graph or k not in read_in:
            continue
        if not _SWS_BOOL.match((decl.get(var) or "").strip()):
            continue
        if not _SWS_STATE.search(k) or _SWS_SCREEN.search(k):
            continue
        hits.append((var, sorted(read_in[k]), confirmed))
    return hits


# ---------- правила по CODESYS ExportFile: параметры модулей и экраны ----------
# В PLCopenXML этого нет вовсе: ни «Параметров устройства», ни привязок визуализации.
# Поэтому класс дефектов ниже не проверяет ни один статический анализатор — все читают ST.
_EX_FMT = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?[a-zA-Z%]")   # %d, %2.1f, %%, %s
_EX_RUS = re.compile(r"[А-Яа-яЁё]")
_EX_OFF = ("отключен", "выключен", "off", "disabled", "none")


def _ex_label(text):
    """Подпись без формата вывода. `%2.0f Гц` → `Гц`.

    Цифры формата — не номер оборудования: на боевом проекте сравнение «номер в подписи
    против индекса в переменной» дало 4 ложных из 4 именно на них (`act_FH1` ↔ `%2.0f Гц`)."""
    return _EX_FMT.sub(" ", text or "").strip()


def _ex_norm(text):
    """Подпись для сравнения: лишние пробелы не делают подписи разными.
    Без этого «Тек. уставка  %d °C» и «Тек. уставка %d °C» выглядели как две разные."""
    return re.sub(r"\s+", " ", _ex_label(text)).strip().lower()


def _ex_nums(text):
    return [int(x) for x in re.findall(r"\d+", text or "")]


def heur_export_devices(export):
    """Настройки модулей, молчаливое значение которых означает «канал не работает».

    → [(устройство, ключ параметра, подпись, вид)], вид ∈ sensor-off / output-off / module-off.

    Канал со снятым типом датчика не оцифровывается, а переменная остаётся нулём: для
    наружной температуры это «на улице 0 °C» и сразу неверный график отопления. Модуль
    с `Disable_module = TRUE` исключён из опроса целиком — все его сигналы мёртвые.

    Ключевая точность — «на ЗАНЯТОМ канале»: свободных входов у модуля больше, чем
    занятых, и для них «Отключен» — правильная настройка. Занятость определяется
    привязкой значения канала, а не кода статуса (его вешают и на свободные входы)."""
    hits = []
    for d in export.devices:
        used = d.used_channels()
        for key, label, val, _dflt, enums in d.params:
            human = (enums or {}).get(val) or ""
            low = human.strip().lower()
            if key.endswith(".SensorType") and val == "0":
                ch = "".join(re.findall(r"\d+", key.split(".")[0]))
                if ch and ch in used:
                    hits.append((d.name, key, label or human, "sensor-off"))
            elif key.endswith(".OutputType") and val == "0" and (not human or low in _EX_OFF):
                hits.append((d.name, key, label or human, "output-off"))
            elif key.endswith("Disable_module") and val.strip().upper() == "TRUE":
                hits.append((d.name, key, label or human, "module-off"))
    return hits


def heur_export_visu(export):
    """Экраны: копипаста элемента вместе с чужой привязкой.

    → [(экран, переменная, вид, подробность)], вид ∈ two-labels / index-mismatch.

    Две находки одного происхождения — элемент скопировали и не поправили привязку:
      * одна переменная выведена под разными подписями («насос 2 показывает насос 1»);
      * номер в подписи не совпадает с индексом в переменной («Котёл 3» ↔ alarm_kotel[2]).
    Сравниваем только осмысленные подписи (с буквами) и только однозначные номера:
    двузначные и выше — это адреса, уставки и шкалы, там совпадать ничего не обязано."""
    hits = []
    for v in export.visus:
        seen, idx = {}, []
        for props in v.elements:
            var = v.var_of(props)
            if not var:
                continue
            label = _ex_label(v.text_of(props))
            if not (label and _EX_RUS.search(label)):
                continue
            seen.setdefault(var, set()).add(_ex_norm(v.text_of(props)))
            nt, nv = _ex_nums(label), _ex_nums(var)
            if nt and nv and nt[-1] != nv[-1] and max(nt[-1], nv[-1]) <= 3:
                idx.append((v.name, var, "index-mismatch", label[:60]))
        two = {var for var, labels in seen.items() if len({s for s in labels if s}) > 1}
        hits += [(v.name, var, "two-labels", " | ".join(sorted(s for s in seen[var] if s))[:90])
                 for var in sorted(two)]
        # у скопированного элемента оба признака сразу; один дефект — одна находка
        hits += [h for h in idx if h[1] not in two]
    return hits


# ---------- сравнение беззнакового с нулём ----------
# Классика, которую компилятор пропускает: `IF cnt < 0 THEN` при `cnt : UINT`. Ветвь
# мертва, и обычно это не стиль, а след неверно выбранного типа: защиту от отрицательного
# значения написали, а тип её отменил. Нашлось на боевом проекте (`AO_temp_kotel : UINT`,
# зажим `IF AO_temp_kotel < 0 THEN AO_temp_kotel := 0`).
_UNSIGNED_T = re.compile(r"^(?:USINT|UINT|UDINT|ULINT|BYTE|WORD|DWORD|LWORD)$", re.I)
# `<` (но не `<>`) и `>=` слева, `>` и `<=` справа — только эти четыре формы тождественны
_UZ_LEFT = re.compile(r"\b(?:gvl\.)?([A-Za-z_]\w*)\s*(<(?!>)|>=)\s*0(?![.\d])")
_UZ_RIGHT = re.compile(r"(?<![\w.])0\s*(>|<=)\s*(?:gvl\.)?([A-Za-z_]\w*)\b")


def heur_unsigned_vs_zero(pous, decl):
    """[(pou, line, var, type, always_true, code)] — сравнение беззнакового с нулём."""
    gl = {k: v for k, v in decl.items() if _UNSIGNED_T.match((v or "").strip())}
    hits = []
    for name, d in pous.items():
        types = dict(gl)
        for tag in ("localVars", "inputVars", "outputVars", "inOutVars", "tempVars"):
            for var, typ in _iface_names(d.get("iface"), tag).items():
                if _UNSIGNED_T.match((typ or "").strip()):
                    types[var.lower()] = typ
                else:
                    types.pop(var.lower(), None)   # локал перекрывает глобал того же имени
        if not types:
            continue
        for i, line in enumerate(blank_comments(d["body"]).splitlines(), 1):
            for m in _UZ_LEFT.finditer(line):
                var, op = m.group(1), m.group(2)
                if var.lower() in types:
                    hits.append((name, i, var, types[var.lower()], op == ">=",
                                 line.strip()[:110]))
            for m in _UZ_RIGHT.finditer(line):
                op, var = m.group(1), m.group(2)
                if var.lower() in types:
                    hits.append((name, i, var, types[var.lower()], op == "<=",
                                 line.strip()[:110]))
    return hits


# ---------- правила поиска багов: границы массива / бесконечный цикл / и т.д. ----------
def _array_bounds(type_el):
    """(lower, upper) для одномерного ARRAY с целыми литеральными границами, иначе None."""
    if type_el is None:
        return None
    ch = list(type_el)
    c = ch[0] if ch else None
    if c is None or loc(c) != "array":
        return None
    dims = c.findall(q("dimension"))
    if len(dims) != 1:
        return None
    try:
        return (int(dims[0].get("lower")), int(dims[0].get("upper")))
    except (TypeError, ValueError):
        return None


def collect_arrays(pous, root):
    """Карты границ массивов: (local[pou][var_lower] = (lo,hi), global[var_lower] = (lo,hi))."""
    local = {}
    for name, d in pous.items():
        m = {}
        for v, kw in iter_vars(d["iface"]):
            b = _array_bounds(v.find(q("type")))
            if b:
                m[v.get("name").lower()] = b
        local[name] = m
    gmap = {}
    parent = {c: p for p in root.iter() for c in p}
    for gv in root.iter(q("globalVars")):
        p = parent.get(gv)
        if p is not None and loc(p) == "interface":
            continue
        for v in gv.findall(q("variable")):
            b = _array_bounds(v.find(q("type")))
            if b:
                gmap[v.get("name").lower()] = b
    return local, gmap


_IDX_RE = re.compile(r'\b(gvl\.)?([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]', re.I)


def heur_array_bounds(pous, local_arrays, global_arrays):
    """Литеральный индекс вне границ объявленного массива — гарантированный выход за границы."""
    hits = []
    for name, d in pous.items():
        larr = local_arrays.get(name, {})
        for i, ln in enumerate(strip_comments(d["body"]).splitlines(), 1):
            for m in _IDX_RE.finditer(ln):
                is_g = bool(m.group(1))
                var = m.group(2).lower()
                idx = int(m.group(3))
                bounds = global_arrays.get(var) if is_g else larr.get(var)
                if bounds is None:
                    continue
                lo, hi = bounds
                if idx < lo or idx > hi:
                    hits.append((name, i, m.group(2), idx, lo, hi, ln.strip()))
    return hits


def heur_infinite_loop(pous):
    """WHILE TRUE / REPEAT…UNTIL FALSE без EXIT/RETURN — блокировка скана (watchdog)."""
    hits = []
    for name, d in pous.items():
        lines = strip_comments(d["body"]).splitlines()
        n = len(lines)
        for i, ln in enumerate(lines):
            mw = re.search(r'\bWHILE\b(.+?)\bDO\b', ln, re.I)
            if mw and mw.group(1).strip().lower() in ("true", "1"):
                depth, j, has_exit = 1, i + 1, False
                while j < n and depth > 0:
                    l2 = lines[j]
                    depth += len(re.findall(r'\bWHILE\b.+?\bDO\b', l2, re.I))
                    depth -= len(re.findall(r'\bEND_WHILE\b', l2, re.I))
                    if depth > 0 and re.search(r'\b(EXIT|RETURN)\b', l2, re.I):
                        has_exit = True
                    j += 1
                if not has_exit:
                    hits.append((name, i + 1, "il.while"))
            if re.search(r'\bREPEAT\b', ln, re.I):
                depth, j, has_exit, until_false = 1, i + 1, False, False
                while j < n and depth > 0:
                    l2 = lines[j]
                    depth += len(re.findall(r'\bREPEAT\b', l2, re.I))
                    if re.search(r'\bEND_REPEAT\b', l2, re.I):
                        depth -= 1
                    if depth > 0 and re.search(r'\b(EXIT|RETURN)\b', l2, re.I):
                        has_exit = True
                    mu = re.search(r'\bUNTIL\b(.+)$', l2, re.I)
                    if mu and mu.group(1).strip().lower().rstrip(';').strip() in ("false", "0"):
                        until_false = True
                    j += 1
                if until_false and not has_exit:
                    hits.append((name, i + 1, "il.repeat"))
    return hits


_SELF_RE = re.compile(r'^\s*([A-Za-z_][\w.\[\]]*)\s*:=\s*([A-Za-z_][\w.\[\]]*)\s*;\s*$')


def heur_self_assign(pous):
    """x := x; — присваивание переменной самой себе (опечатка/потерянная логика)."""
    hits = []
    for name, d in pous.items():
        for i, ln in enumerate(strip_comments(d["body"]).splitlines(), 1):
            m = _SELF_RE.match(ln)
            if m and m.group(1).lower() == m.group(2).lower():
                hits.append((name, i, ln.strip()))
    return hits


_EMPTY_PATTERNS = [
    (r'\bTHEN\b\s*\bEND_IF\b', "eb.if-then-endif"),
    (r'\bTHEN\b\s*\bELSIF\b', "eb.then-elsif"),
    (r'\bTHEN\b\s*\bELSE\b', "eb.then-else"),
    (r'\bDO\b\s*\bEND_WHILE\b', "eb.while-body"),
    (r'\bDO\b\s*\bEND_FOR\b', "eb.for-body"),
]


def heur_empty_branch(pous):
    """Пустые ветви IF/циклов — забытая или удалённая логика."""
    hits = []
    for name, d in pous.items():
        body = strip_comments(d["body"])
        for pat, desc in _EMPTY_PATTERNS:
            for m in re.finditer(pat, body, re.I | re.S):
                line = body[:m.start()].count("\n") + 1
                hits.append((name, line, desc))
    return hits


def heur_unused_local(pous):
    """Локальная переменная (VAR) не встречается ни в теле, ни в actions/methods."""
    hits = []
    for name, d in pous.items():
        text = strip_comments(d.get("fulltext", d["body"]))
        for v, kw in iter_vars(d["iface"], tags={"localVars"}):
            vn = v.get("name")
            if not vn:
                continue
            if not re.search(rf'\b{re.escape(vn)}\b', text, re.I):
                hits.append((name, vn))
    return hits


# деление/MOD на литеральный ноль (0, 00, 0.0) — гарантированная ошибка исполнения
_DIV0_RE = re.compile(r'(?:/|\bMOD\b)\s*0+(?:\.0+)?(?![.\deE])', re.I)


def heur_div_zero(pous):
    hits = []
    for name, d in pous.items():
        for i, ln in enumerate(strip_comments(d["body"]).splitlines(), 1):
            if _DIV0_RE.search(ln):
                hits.append((name, i, ln.strip()))
    return hits


def heur_case_without_else(pous):
    """CASE без ELSE — неучтённые значения селектора молча игнорируются.
    Консервативно: если МЕЖДУ CASE и END_CASE есть любой ELSE (в т.ч. вложенного IF),
    не флагуем → нет ложных срабатываний, возможны ложноотрицательные."""
    hits = []
    for name, d in pous.items():
        stack = []  # [start_line_index, has_else]
        for idx, ln in enumerate(strip_comments(d["body"]).splitlines()):
            has_case = re.search(r'\bCASE\b', ln, re.I)
            has_end = re.search(r'\bEND_CASE\b', ln, re.I)
            if has_case and not has_end:
                stack.append([idx, False])
            if re.search(r'\bELSE\b', ln, re.I) and stack:
                stack[-1][1] = True
            if has_end and stack:
                start, has_else = stack.pop()
                if not has_else:
                    hits.append((name, start + 1))
    return hits


NESTING_MAX = 4  # глубже — трудно читать/сопровождать


def heur_deep_nesting(pous, threshold=NESTING_MAX):
    """Глубокая вложенность IF (> threshold) — кандидат на раннние выходы / вынос в FB."""
    hits = []
    for name, d in pous.items():
        depth = mx = 0
        flag_line = None
        for i, ln in enumerate(strip_comments(d["body"]).splitlines(), 1):
            for tok in re.findall(r'\bIF\b|\bEND_IF\b', ln, re.I):
                if tok.upper() == "IF":
                    depth += 1
                    mx = max(mx, depth)
                    if depth > threshold and flag_line is None:
                        flag_line = i
                else:
                    depth = max(0, depth - 1)
        if mx > threshold:
            hits.append((name, flag_line or 1, mx))
    return hits


# PT := T#0(S/MS/…) — нулевая выдержка: таймер срабатывает мгновенно
_ZERO_PT_RE = re.compile(r'\bPT\s*:=\s*T(?:IME)?#0+(?:\.0+)?(?![.\d])(?:MS|S|M|H|D)?\b', re.I)


def heur_timer_zero_pt(pous):
    hits = []
    for name, d in pous.items():
        for i, ln in enumerate(strip_comments(d["body"]).splitlines(), 1):
            if _ZERO_PT_RE.search(ln):
                hits.append((name, i, ln.strip()))
    return hits


# POUs for implicit checks (CODESYS) — добавляются вручную; без них нет рантайм-защит
_CHECK_POU_RE = re.compile(r'^Check(?:Bounds|Div|Range|LRange|Pointer)', re.I)


def has_implicit_checks(pous):
    return any(_CHECK_POU_RE.match(n) for n in pous)


def check_registrations(root):
    """POU → роль функции контроля из addData `<CheckFunction>` (регистрация = «включено»
    в компиляции). Незарегистрированный Check-POU рантайм не вызывает."""
    reg = {}
    for pou in root.iter(q("pou")):
        for el in pou.iter():
            if loc(el) == "CheckFunction":
                role = (el.text or "").strip()
                if role:
                    reg[pou.get("name")] = role
                break
    return reg


# --- анализ устройств/контроллера/задач (device tree из экспорта) ---
_ISO_DUR = re.compile(r'PT(\d+(?:\.\d+)?)S', re.I)
_IO_RE = re.compile(r'^M[VUK]\d{3}', re.I)          # OWEN Mx210 и подобные модули I/O
_BUS_RE = re.compile(r'Modbus|RS485|RS232|Ethernet|CANopen|Profinet|EtherCAT|\bCAN\b', re.I)


def _interval_ms(s):
    if not s:
        return None
    m = _ISO_DUR.search(s)
    if m:
        return round(float(m.group(1)) * 1000, 3)
    m = re.search(r't#\s*(\d+(?:\.\d+)?)\s*ms', s, re.I)
    return float(m.group(1)) if m else None


# ТОЛЬКО проверенные vendor-id (публичной полной таблицы у CODESYS нет — не гадаем).
# 0x1628 подтверждён interface="OWEN:PLC210" в экспорте; 0x0003/0x0004 — резерв 3S под open-source.
# Неизвестные коды показываем как 0xXXXX, не подсвечивая ложным именем. Пополняется по мере проверки.
VENDOR_IDS = {
    "0000": "generic (CODESYS)",
    "0001": "3S / CODESYS",
    "0003": "3S (open-source)",
    "0004": "3S (open-source)",
    "1628": "ОВЕН (OWEN)",
    "16bf": "Weintek",  # панели со встроенным CODESYS (подтв. пользователем)
}
VENDOR_GENERIC_CODES = {"0000", "0001", "0003", "0004"}


_STD_ID_RE = re.compile(r'^([0-9A-Fa-f]{1,4})\s+[0-9A-Fa-f]+$')

# admin-добавленные вендоры (заполняется приложением из БД) — дополняет VENDOR_IDS
EXTRA_VENDORS = {}


def _vendor(idstr):
    """(имя_или_hex, code) для vendor-части стандартного Id '<hex4> <hex>'.
    Нестандартный Id (напр. EtherCAT `3DC_..._BEFF`) → (None, None): вендора не извлекаем,
    чтобы не выдавать мусор. Неизвестный, но валидный код → '0xXXXX' (честно, без догадок)."""
    m = _STD_ID_RE.match((idstr or "").strip())
    if not m:
        return None, None
    c = m.group(1).lower()
    name = VENDOR_IDS.get(c) or EXTRA_VENDORS.get(c) or f"0x{m.group(1).upper()}"
    return name, c


def _cat(name):
    if re.match(r'PLC\d', name, re.I):
        return ("controller", "Контроллер")
    if _IO_RE.match(name):
        return ("io", "Модуль I/O")
    if _BUS_RE.search(name):
        return ("fieldbus", "Шина/связь")
    return ("other", "Прочее")


def _ip(s):
    n = re.findall(r'\d+', s or "")
    return ".".join(n[:4]) if len(n) >= 4 else None


_APPVAR_RE = re.compile(r'\bApplication\.([A-Za-z_][\w.]*)')


def _linked_vars(cfg):
    """Переменные, привязанные к каналам устройства (Application.<путь>). Только для листовых
    устройств надёжно — у мастер/родительских узлов агрегируются привязки детей."""
    blob = ET.tostring(cfg, encoding="unicode")
    return sorted(set(_APPVAR_RE.findall(blob)))


def device_summary(root, lang="ru"):
    """Разбор дерева устройств: контроллер+вендор, модули, задачи (цикл/watchdog), Modbus-адреса.
    Адрес берём только у ЛИСТОВЫХ I/O-модулей (надёжно); у мастер/родительских узлов параметры
    смешаны с дочерними — их адрес не извлекаем, чтобы не давать ложных дублей."""
    tasks = []
    for t in root.iter(q("task")):
        wd = None
        for el in t.iter():
            if loc(el) == "Watchdog":
                wd = (el.get("Enabled", "").lower() == "true")
                break
        tasks.append({"name": t.get("name"), "interval_ms": _interval_ms(t.get("interval")),
                      "priority": t.get("priority"), "watchdog": wd})

    devices = []
    root_vendor = root_vcode = None
    for cfg in root.iter(q("configuration")):
        name = cfg.get("name")
        if not name:
            continue
        if name == "Device":
            # корневой узел = контроллер; берём только его идентификацию (параметры смешаны с детьми)
            for el in cfg.iter():
                if loc(el) == "DeviceIdentification":
                    root_vendor, root_vcode = _vendor(el.findtext("Id"))
                    break
            continue
        cat, _ = _cat(name)
        label = i18n.term(lang, "cat." + cat)
        vendor = vcode = tcode = reconnect = None
        ip = uid = port = None
        for el in cfg.iter():
            l = loc(el)
            if l == "DeviceIdentification" and tcode is None:
                tcode = el.findtext("Type")
                vendor, vcode = _vendor(el.findtext("Id"))
            elif l == "Value":
                vn = (el.get("visiblename") or "").lower()
                if vn == "autoreconnect" and reconnect is None:
                    reconnect = (el.text or "").strip()
                elif cat == "io":  # адрес только у листовых модулей
                    if vn == "ipaddress" and ip is None:
                        ip = _ip(el.text)
                    elif vn == "unit-id" and uid is None:
                        uid = (el.text or "").strip()
                    elif vn == "port" and port is None:
                        port = (el.text or "").strip()
        addr = f"{ip}:{port}#{uid}" if ip else None
        # привязки I/O — только у листовых устройств; у шин/мастеров (контейнеров) агрегируются
        # привязки детей → не показываем (прочерк), чтобы не давать неточных данных
        container = (cat == "fieldbus")
        io_vars = None if container else _linked_vars(cfg)
        devices.append({"name": name, "cat": cat, "label": label, "vendor": vendor, "vcode": vcode,
                        "type": tcode, "reconnect": reconnect, "addr": addr,
                        "io_vars": io_vars, "io_count": (len(io_vars) if io_vars is not None else None)})

    controller = [d["name"] for d in devices if d["cat"] == "controller"]
    # вендор контроллера: у PLC-узла — его вендор; иначе — вендор корневого узла Device
    if controller:
        plc = next(d for d in devices if d["cat"] == "controller")
        controller_vendor, controller_vcode = plc.get("vendor"), plc.get("vcode")
        controller_label = ", ".join(controller) + (f" ({controller_vendor})" if controller_vendor else "")
    elif root_vcode is not None:
        controller_vcode = root_vcode
        controller_vendor = root_vendor if root_vcode not in VENDOR_GENERIC_CODES else None
        controller_label = i18n.term(lang, "builtin-codesys") + (f" ({controller_vendor})" if controller_vendor else "")
    else:
        controller_vendor = controller_label = controller_vcode = None
    # вендоры оборудования (без дженерик/системных 3S) + вендор контроллера
    all_vendors = {d["vendor"] for d in devices if d["vendor"] and d["vcode"] not in VENDOR_GENERIC_CODES}
    if controller_vendor:
        all_vendors.add(controller_vendor)
    other_vendors = sorted(all_vendors - ({controller_vendor} if controller_vendor else set()))
    io_total = len(set().union(*(set(d["io_vars"]) for d in devices if d["io_vars"]))) \
        if any(d["io_vars"] for d in devices) else 0
    return {"tasks": tasks, "devices": devices, "controller": controller,
            "controller_label": controller_label, "controller_vendor": controller_vendor,
            "controller_vcode": controller_vcode,
            "vendors": sorted(all_vendors), "other_vendors": other_vendors,
            "device_count": len(devices), "io_total": io_total}


def duplicate_module_addresses(device):
    """Дубли Modbus-адресов среди листовых I/O-модулей → [(addr, [names])]."""
    by_addr = {}
    for d in device.get("devices", []):
        if d.get("addr"):
            by_addr.setdefault(d["addr"], []).append(d["name"])
    return [(a, names) for a, names in by_addr.items() if len(names) > 1]


# роли по категориям рантайм-защиты
# ключи — нейтральные слаги (локализуются через i18n.term "chk.<slug>"), не русский текст
CHECK_CATEGORIES = {
    "array-bounds": {"CheckBounds"},
    "div-zero": {"CheckDivInt32", "CheckDivInt64", "CheckDivReal32", "CheckDivReal64"},
    "range": {"CheckRangeSigned", "CheckRangeUnsigned",
              "CheckLRangeSigned", "CheckLRangeUnsigned"},
    "pointer": {"CheckPointer"},
}


_CHECKDIV_RE = re.compile(r'^CheckDiv', re.I)
_ZERO_CMP_RE = re.compile(r'(?:=|<>|<|>)\s*0(?![.\d])')  # сравнение с литеральным 0


def heur_broken_implicit_check(pous):
    """Функция неявного контроля есть, но её защита выхолощена (человеческий фактор).
    Сломанная защита опаснее отсутствующей — ложное чувство безопасности."""
    hits = []
    for name, d in pous.items():
        if not _CHECK_POU_RE.match(name):
            continue
        body = strip_comments(d["body"])
        if not body.strip():
            hits.append((name, "bic.empty"))
            continue
        low = body.lower()
        if _CHECKDIV_RE.match(name):
            if not _ZERO_CMP_RE.search(body):
                hits.append((name, "bic.no-div"))
        elif re.match(r'^Check(?:Bounds|L?Range)', name, re.I):
            if not (re.search(r'\blower\b', low) and re.search(r'\bupper\b', low)):
                hits.append((name, "bic.no-bounds"))
    return hits


# --- стандарт-профиль: PLCopen naming (префиксы по типу, таблица CODESYS/PLCopen) ---
PLCOPEN_PREFIX = {
    "BOOL": "x", "BYTE": "by", "WORD": "w", "DWORD": "dw", "LWORD": "lw",
    "SINT": "si", "USINT": "usi", "INT": "i", "UINT": "ui",
    "DINT": "di", "UDINT": "udi", "LINT": "li", "ULINT": "uli",
    "REAL": "r", "LREAL": "lr", "STRING": "s", "WSTRING": "ws",
    "TIME": "t", "LTIME": "lt", "DATE": "dat",
    "TIME_OF_DAY": "tod", "TOD": "tod", "DATE_AND_TIME": "dt", "DT": "dt",
}


def _elem_prefix(v):
    """Ожидаемый PLCopen-префикс для элементарного типа переменной, иначе None."""
    te = v.find(q("type"))
    if te is None:
        return None
    ch = list(te)
    c = ch[0] if ch else None
    if c is None:
        return None
    return PLCOPEN_PREFIX.get(loc(c).upper())


def _name_conforms(name, prefix):
    """Имя начинается с префикса, за которым Верхний регистр/цифра/подчёркивание (или ничего)."""
    if not name.startswith(prefix):
        return False
    rest = name[len(prefix):]
    return rest == "" or rest[0].isupper() or rest[0].isdigit() or rest[0] == "_"


def check_plcopen_naming(pous):
    """Проверка префиксов имён по PLCopen. Локальные + I/O переменные элементарных типов
    (глобалы и derived/array — вне v1). Возвращает (violations, checked, ok)."""
    scopes = {"localVars", "inputVars", "outputVars", "inOutVars", "tempVars"}
    violations = []
    checked = ok = 0
    for name, d in pous.items():
        if name.startswith("Check"):  # авто-POU неявных проверок CODESYS — не наши имена
            continue
        for v, kw in iter_vars(d["iface"], tags=scopes):
            prefix = _elem_prefix(v)
            if prefix is None:
                continue
            vn = v.get("name") or ""
            checked += 1
            if _name_conforms(vn, prefix):
                ok += 1
            else:
                violations.append((name, vn, prefix))
    return violations, checked, ok


# --- доменные сигналы (котельная/ИТП) ---------------------------------------------
# Только счётчики, без findings: правило пишем ПОСЛЕ замера на реальных проектах, иначе
# получим ещё шесть правил, из которых стреляют два. Имена ищем и транслитом, и по-английски —
# в реальных экспортах `T_obr` и `TempReturn` лежат вперемешку.
RX_HEAT_RETURN = re.compile(r"[A-Za-z_]*(?:t_?obr|obratk|t_?ret\b|ret_?temp|return_?temp)\w*", re.I)
RX_HEAT_DHW = re.compile(r"[A-Za-z_]*(?:gvs|dhw|hot_?water|goryach)\w*", re.I)
RX_HEAT_PUMP = re.compile(r"[A-Za-z_]*(?:nasos|pump|nas_)\w*", re.I)
RX_HEAT_RUNTIME = re.compile(r"[A-Za-z_]*(?:narabotka|motohours|moto_?час|runtime|nar_)\w*", re.I)
RX_HEAT_STANDBY = re.compile(r"[A-Za-z_]*(?:rezerv|reserv|standby|backup)\w*", re.I)
RX_HEAT_IGNITE = re.compile(r"[A-Za-z_]*(?:rozzhig|rozjig|ignit|burner|gorelk)\w*", re.I)
RX_HEAT_POINT = re.compile(r"\bpoint_?\d", re.I)
RX_CMP = re.compile(r"(?:<=|>=|<|>)")
RX_LIMIT = re.compile(r"\b(?:LIMIT|MIN|MAX)\s*\(", re.I)
RX_SETPOINT_LIT = re.compile(r":=\s*(\d{1,3})(?:\.\d+)?\s*[;)]")
RX_ANALOG_READ = re.compile(r"%IW\d|_TO_REAL\s*\(", re.I)


def heat_signals(pous):
    """Счётчики доменных паттернов теплоснабжения. Ничего не флагует — сырьё для решения,
    какие доменные правила вообще имеет смысл писать (гейт: встретилось минимум в 3 проектах)."""
    sig = dict.fromkeys(
        ("heat_return_temp", "heat_return_limited", "heat_dhw_setpoint", "heat_dhw_below_60",
         "heat_ai_no_range", "heat_curve_points", "heat_pump_runtime", "heat_standby_pump",
         "heat_ignition_delay"), 0)
    for name, d in pous.items():
        text = strip_comments(d.get("fulltext") or d["body"])
        # имена из объявлений: переменную могут объявить здесь, а использовать через gvl.*
        decl_names = " ".join(v.get("name") or "" for v, _ in iter_vars(d.get("iface")))
        both = text + "\n" + decl_names
        lines = text.splitlines()

        sig["heat_return_temp"] += len(RX_HEAT_RETURN.findall(both))
        for ln in lines:
            if RX_HEAT_RETURN.search(ln) and (RX_CMP.search(ln) or RX_LIMIT.search(ln)):
                sig["heat_return_limited"] += 1
            if RX_HEAT_DHW.search(ln):
                m = RX_SETPOINT_LIT.search(ln)
                if m:
                    sig["heat_dhw_setpoint"] += 1
                    if 30 <= int(m.group(1)) < 60:
                        sig["heat_dhw_below_60"] += 1
        # наработка/резерв/розжиг ищем В ПРЕДЕЛАХ POU, а не строки: `Nasos1` и `narabotka[1]`
        # почти никогда не стоят в одной строке, а смысл сигнала — «в блоке насосов это есть»
        if RX_HEAT_PUMP.search(both):
            if RX_HEAT_RUNTIME.search(both):
                sig["heat_pump_runtime"] += 1
            if RX_HEAT_STANDBY.search(both):
                sig["heat_standby_pump"] += 1
        if RX_HEAT_IGNITE.search(both) and re.search(r"\bTON\b|\.PT\b", text, re.I):
            sig["heat_ignition_delay"] += 1

        # аналоговый вход/температура читается, но нигде не сравнивается с диапазоном →
        # обрыв Pt1000 приедет в регулятор как валидный ноль
        if RX_ANALOG_READ.search(text) and not RX_CMP.search(text):
            sig["heat_ai_no_range"] += 1
        # каскад точек погодного графика в одном условии
        for m in re.finditer(r"\b(?:IF|ELSIF)\b.+?\bTHEN\b", text, re.I | re.S):
            if len(RX_HEAT_POINT.findall(m.group(0))) >= 3:
                sig["heat_curve_points"] += 1
    return sig


# --- профиль heating: единственное доменное правило, прошедшее замер ---
# Присваивание в ST нужно только для поиска ПЕРЕСЧЁТА канала (raw → scaled): сам аналоговый
# вход в коде не присваивается никогда, он приходит из дерева устройств.
RX_AI_ASSIGN = re.compile(r"^\s*([A-Za-z_][\w.\[\]]*)\s*:=\s*(.+?);", re.M)


def _short(var):
    """Хвост квалифицированного имени без индекса: gvl.t_out[1] → t_out."""
    return var.split(".")[-1].split("[")[0]


def _var_re(var):
    """Имя переменной с ЛЮБЫМ квалификатором: `x`, `gvl.x`, `GVL.x`, `Application.GVL.x`.

    Срезать квалификатор из шаблона и одновременно запрещать его в тексте нельзя — так
    ни одна переменная из GVL (а в реальных проектах там весь ввод-вывод) не могла быть
    признана проверенной."""
    return r"(?<![A-Za-z0-9_.])(?:[A-Za-z_]\w*\s*\.\s*)*" + re.escape(_short(var))


def _is_range_checked(var, project_text):
    """Сравнивается ли переменная с чем-либо по величине хоть где-то в проекте.

    Ищем по всему проекту, а не по POU: достоверность аналога сплошь и рядом проверяют
    в отдельном блоке аварий, и проверка «в этом же POU» дала бы сплошной ложняк."""
    v = _var_re(var)
    if re.search(v + r"\s*(?:<=|>=|<|>)", project_text, re.I):
        return True
    if re.search(r"(?:<=|>=|<|>)\s*" + v + r"(?![A-Za-z0-9_])", project_text, re.I):
        return True
    return bool(re.search(r"\b(?:LIMIT|MIN|MAX)\s*\([^)]*" + v, project_text, re.I))


def _is_read(var, project_text):
    """Читается ли переменная где-либо (для диагностики модуля важен сам факт обращения)."""
    return bool(re.search(_var_re(var) + r"(?![A-Za-z0-9_])", project_text, re.I))


# диагностика канала/модуля: код ошибки от самого модуля — проверка достоверности ЛУЧШЕ
# сравнения с диапазоном (обрыв и КЗ ловятся железом, а не по попаданию в правдоподобный интервал)
_DIAG_RE = re.compile(r"error|status|diag|fault", re.I)
# Аналоговый канал: вещественное или целое ЧИСЛО. Битовые строки (BYTE/WORD/DWORD/LWORD)
# исключены сознательно — по IEC это не числа, а упакованные биты: МВ210-212 отдаёт все
# свои дискретные входы одним DWORD, и принимать его за аналог значит ругаться на дискретный
# ввод. ARRAY — буфер обмена или диагностика, BOOL — дискретный канал.
_ANALOG_TYPE_RE = re.compile(r"^(?:LREAL|REAL|U?SINT|U?INT|U?DINT|U?LINT)\s*$", re.I)


def _is_leaf_cfg(cfg):
    """Лист дерева устройств: внутри нет вложенных configuration. У мастеров и шин привязки
    детей агрегированы, поэтому по ним судить о канале нельзя."""
    return not any(c is not cfg for c in cfg.iter(q("configuration")))


def analog_inputs(root):
    """Аналоговые входы ПО ДЕРЕВУ УСТРОЙСТВ: [{node, vars, diag}].

    Источник — привязка переменной к каналу модуля, а не присваивание в ST. Настоящие входы
    в коде не присваиваются никогда (их пишет рантайм), а по ST в «аналоги» попадают регистры
    теплосчётчика по Modbus и буфер обмена с панелью — то есть показания прибора учёта
    и уставки оператора, а не измерения.

    Берём ЛИСТЬЯ (у мастеров привязки детей агрегированы) двух видов: модули I/O и всё, что
    висит под контроллером — встроенный ввод-вывод (LeftSide/RightSide у PLC210) под регулярку
    модулей `^M[VUK]\\d{3}` не подходит, а каналы там живые. Приборы на шине (ТРМ-регулятор,
    теплосчётчик ВКТ-9) и панель-slave сюда НЕ входят: там показания чужого прибора и уставки
    оператора, а не входы контроллера.
    """
    decl = globals_of(root)
    parent = {c: p for p in root.iter() for c in p}

    def under_controller(cfg):
        node = parent.get(cfg)
        while node is not None:
            if loc(node) == "configuration" and _cat(node.get("name") or "")[0] == "controller":
                return True
            node = parent.get(node)
        return False

    out = []
    for cfg in root.iter(q("configuration")):
        name = cfg.get("name")
        if not name or name == "Device" or not _is_leaf_cfg(cfg):
            continue
        cat = _cat(name)[0]
        if cat != "io" and not under_controller(cfg):
            continue
        chans, diag = [], []
        for v in _linked_vars(cfg):
            short = v.split(".")[-1].lower()
            if _DIAG_RE.search(short):
                diag.append(v)
            elif _ANALOG_TYPE_RE.match(decl.get(short) or ""):
                chans.append(v)
        if chans:
            out.append({"node": name, "vars": sorted(chans), "diag": sorted(diag)})
    return out


def _derived_from(var, pous):
    """Переменные, которым присвоено значение, вычисленное из var (один уровень пересчёта):
    `raw := UINT_TO_REAL(канал)` → `T := k*raw + b`. Проверяют обычно результат, а не сырьё."""
    pat = re.compile(r"(?<![A-Za-z0-9_.])" + re.escape(_short(var)) + r"(?![A-Za-z0-9_])", re.I)
    out = []
    for d in pous.values():
        for lhs, rhs in RX_AI_ASSIGN.findall(strip_comments(d["body"])):
            if pat.search(rhs) and _short(lhs).lower() != _short(var).lower():
                out.append(lhs)
    return out


def heur_ai_no_range(pous, root):
    """Аналоговый вход, достоверность которого нигде в проекте не проверяется.

    Обрыв Pt1000 читается как валидный 0 °C и уезжает в регулятор → клапан на полную.
    Проверкой считаем любой из трёх способов:
      • сравнение самого канала с диапазоном где угодно в проекте;
      • сравнение переменной, посчитанной из канала (масштабирование);
      • ЧТЕНИЕ диагностики модуля, к которому привязан канал (`error_analog_code` и т.п.) —
        это не «другой способ», а способ лучше: обрыв и КЗ ловит железо.

    Возвращает ([(узел, [каналы])], всего_каналов, проверенных).
    """
    project = "\n".join(strip_comments(d.get("fulltext") or d["body"]) for d in pous.values())
    hits, total, ok = [], 0, 0
    for node in analog_inputs(root):
        diag_used = any(_is_read(dv, project) for dv in node["diag"])
        unchecked = []
        for var in node["vars"]:
            total += 1
            checked = diag_used or _is_range_checked(var, project) or any(
                _is_range_checked(d2, project) for d2 in _derived_from(var, pous))
            if checked:
                ok += 1
            else:
                unchecked.append(var)
        if unchecked:
            hits.append((node["node"], unchecked))
    return hits, total, ok


def cfc_signals(root):
    """Счётчики по графике — без findings. cfc_stale_read: чтений значения с прошлого скана;
    cfc_reverse_edges/cfc_graph_edges: доля рёбер против порядка исполнения (высокая доля =
    стиль рисовки, а не ошибка — именно это и увело правило cfc-stale-read из RULES)."""
    stale = len(heur_cfc_stale_read(root))
    rev = tot = 0
    for pou in root.iter(q("pou")):
        b = pou.find(q("body"))
        if b is None or body_lang(b) not in _GRAPH_DATAFLOW_LANGS:
            continue
        nodes = cfc_nodes(b)
        for lid, n in nodes.items():
            de = n["exec"]
            if de is None:
                continue
            for c in n["el"].iter(q("connection")):
                se = nodes.get(_resolve_src(c.get("refLocalId"), nodes), {}).get("exec")
                if se is None:
                    continue
                tot += 1
                rev += se > de
    return {"cfc_stale_read": stale, "cfc_reverse_edges": rev, "cfc_graph_edges": tot}


def candidate_signals(pous):
    """Телеметрия паттернов, на которые ПРАВИЛ ЕЩЁ НЕТ — чтобы по логам реальных проектов
    приоритизировать, какие проверки добавлять (частый паттерн = кандидат в правило).
    Не порождает findings, только счётчики."""
    sig = {"case_without_else": 0, "div_by_var": 0, "div_by_zero_literal": 0,
           "pointer_usage": 0, "real_equality": 0, "direct_address": 0,
           "bool_eq_literal": 0, "loops": 0, "const_condition": 0,
           "todo_comments": 0, "max_if_depth": 0}
    for name, d in pous.items():
        body = strip_comments(d["body"])
        for m in re.finditer(r'\bCASE\b.*?\bEND_CASE\b', body, re.I | re.S):
            if not re.search(r'\bELSE\b', m.group(0), re.I):
                sig["case_without_else"] += 1
        sig["div_by_var"] += len(re.findall(r'/\s*[A-Za-z_]\w*', body))
        sig["div_by_zero_literal"] += len(re.findall(r'/\s*0(?![\d.])', body))
        sig["pointer_usage"] += len(re.findall(r'\bADR\s*\(|\^|\bPOINTER\s+TO\b', body, re.I))
        # только СРАВНЕНИЯ (= / <>), не присваивания := и не <=/>=
        sig["real_equality"] += len(re.findall(r'(?:(?<![:<>])=|<>)\s*\d+\.\d+', body))
        sig["direct_address"] += len(re.findall(r'%[IQM][XBWD]?\d', body, re.I))
        sig["bool_eq_literal"] += len(re.findall(r'(?:(?<![:<>])=|<>)\s*(?:TRUE|FALSE)\b', body, re.I))
        sig["loops"] += len(re.findall(r'\b(?:FOR|WHILE|REPEAT)\b', body, re.I))
        sig["const_condition"] += len(re.findall(r'\bIF\s+(?:TRUE|FALSE)\b', body, re.I))
        sig["todo_comments"] += len(re.findall(r'\b(?:TODO|FIXME|HACK|XXX)\b', d["body"], re.I))
        depth = mx = 0
        for tok in re.findall(r'\bIF\b|\bEND_IF\b', body, re.I):
            if tok.upper() == "IF":
                depth += 1
                mx = max(mx, depth)
            else:
                depth = max(0, depth - 1)
        sig["max_if_depth"] = max(sig["max_if_depth"], mx)
    sig.update(heat_signals(pous))
    sig.update(polarity_signal(pous))
    return sig


# ---------- модель отчёта ----------
@dataclass
class Finding:
    rule: str
    severity: str       # "high" | "medium" | "low"
    title: str
    pou: str
    line: Optional[int] = None
    detail: str = ""
    code: str = ""      # строка-исходник, если есть


@dataclass
class Report:
    name: str
    version: str
    pou_count: int
    globals_count: int
    findings: list = field(default_factory=list)
    rendered: dict = field(default_factory=dict)  # name -> читаемый ST
    signals: dict = field(default_factory=dict)   # телеметрия паттернов-кандидатов
    profile_stats: dict = field(default_factory=dict)  # {profile: {checked, ok, pct}}
    device: dict = field(default_factory=dict)    # контроллер/модули/задачи
    coverage: dict = field(default_factory=dict)  # покрытие языков: {total, st, by_lang, nonst_count}
    modified: str = ""      # contentHeader@modificationDateTime — по нему определяется, какая версия новее
    units: int = 0          # для .export: сколько объектов разобрано (модулей + экранов);
    #                         у PLCopenXML размер проекта меряется в POU

    @property
    def summary(self):
        s = {"high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            s[f.severity] = s.get(f.severity, 0) + 1
        return s


class NotPlcOpenError(Exception):
    """Валидный XML, но не экспорт PLCopenXML: не тот корень/namespace, либо с DTD/сущностями."""


# карта правил: (severity, человекочитаемый заголовок)
RULES = {
    "undeclared-global": ("high", "Опечатка в имени глобала (gvl.*)"),
    "unreachable-branch": ("high", "Недостижимая ветвь IF/ELSIF"),
    "uncalled-timer": ("high", "Невызванный таймер/триггер"),
    "int-division": ("medium", "Целочисленное деление (потеря дроби?)"),
    "real-to-time-mul": ("medium", "REAL_TO_TIME(...)*N — усечение уставки"),
    "real-to-word-mul": ("medium", "REAL_TO_WORD(...)*N — переполнение WORD?"),
    "double-semicolon": ("low", "Двойная `;;` (пустой оператор)"),
    "dead-pou": ("low", "Мёртвый код — POU нигде не вызывается"),
    "naming": ("low", "Криптовое имя переменной"),
    "magic-number": ("low", "Magic number — сырая константа в коде"),
    "missing-comments": ("low", "POU без единого комментария"),
    "routine-size": ("low", "Раздутая рутина (кандидат на декомпозицию)"),
    "copy-paste": ("low", "Дублированный блок логики (copy-paste)"),
    "array-bounds": ("high", "Индекс за границами массива"),
    "infinite-loop": ("high", "Бесконечный цикл без выхода"),
    "div-by-zero": ("high", "Деление на литеральный ноль"),
    "broken-implicit-check": ("high", "Функция неявного контроля не защищает"),
    "missing-implicit-checks": ("medium", "Нет POUs for implicit checks (рантайм-защиты)"),
    "implicit-check-disabled": ("medium", "Проверка присутствует, но не активна"),
    "watchdog-disabled": ("medium", "Сторожевой таймер задачи отключён"),
    "modbus-address-duplicate": ("high", "Дубль Modbus-адреса у модулей"),
    "timer-zero-pt": ("medium", "Таймер с нулевой выдержкой (PT := T#0)"),
    "case-without-else": ("medium", "CASE без ветви ELSE (нет default)"),
    "deep-nesting": ("low", "Глубокая вложенность IF"),
    "self-assignment": ("medium", "Присваивание переменной самой себе"),
    "empty-branch": ("medium", "Пустая ветвь IF/цикла"),
    "unused-local": ("low", "Неиспользуемая локальная переменная"),
    "plcopen-naming": ("low", "Имя не по стандарту PLCopen"),
    "heating-ai-no-range-check": ("high", "Аналог без проверки достоверности"),
    "cfc-div-zero": ("high", "CFC: делитель блока = литеральный 0"),
    # класс channel-mismatch: копия соседнего канала без полной перенумерации
    "family-gap": ("high", "Канал не заполняется — пропуск в семействе"),
    "param-channel-mismatch": ("high", "Параметр канала получает чужой канал"),
    "index-mismatch": ("medium", "Строка расставляет индексы иначе, чем группа"),
    "self-enable": ("high", "Команда зависит от собственной обратной связи"),
    "timer-reset-by-own-condition": ("high", "Таймер гасит собственное условие отсчёта"),
    "timer-rearmed-by-own-branch": ("high", "Задержка выключения не истекает никогда"),
    "timer-off-delay-in-own-branch": ("high", "Выдержку выключения не вызывают, когда она должна считать"),
    "fb-call-overwritten": ("high", "Второй вызов экземпляра перетирает первый"),
    "edge-lost-in-own-branch": ("high", "Детектор фронта теряет все фронты, кроме первого"),
    "timer-preset-missing": ("high", "У таймера нигде не задана уставка"),
    "always-false-condition": ("high", "Условие не выполнится ни при каких значениях"),
    "signal-without-source": ("medium", "Аварию никто не формирует"),
    "unsigned-vs-zero": ("medium", "Беззнаковое сравнивается с нулём"),
    # только для CODESYS ExportFile (.export): в PLCopenXML параметров модулей и
    # привязок визуализации нет вовсе
    "channel-sensor-off": ("high", "У занятого канала снят тип датчика"),
    "channel-output-off": ("high", "Выход модуля не настроен"),
    "module-disabled": ("high", "Модуль исключён из опроса"),
    "visu-two-labels": ("medium", "Одна переменная под двумя подписями"),
    "visu-index-mismatch": ("medium", "Номер в подписи не равен индексу"),
}


# веса штрафа по severity для итогового score (тюнится)
SCORE_WEIGHTS = {"high": 12.0, "medium": 4.0, "low": 0.3}
SCORE_FACTOR = 6.0


def quality_score(report) -> int:
    """0..100. Штраф по severity, нормированный на размер проекта (POU), чтобы крупные
    проекты не штрафовались несправедливо. Ориентир, не приговор."""
    penalty = sum(SCORE_WEIGHTS.get(f.severity, 0) for f in report.findings)
    # у .export нет POU: размер проекта там — число разобранных модулей и экранов,
    # иначе балл нормировался бы на единицу и любой экспорт получал бы ноль
    size = max(report.pou_count or report.units, 1)
    score = 100 - (penalty / size) * SCORE_FACTOR
    return max(0, min(100, round(score)))


def rule_counts(report) -> dict:
    """Счётчики по правилам (для профиля/агрегата)."""
    counts = {}
    for f in report.findings:
        counts[f.rule] = counts.get(f.rule, 0) + 1
    return counts


def _sev(rule: str) -> str:
    return RULES[rule][0]


def _title(rule: str) -> str:
    return RULES[rule][1]


def analyze_export(src, profiles=None, lang="ru") -> Report:
    """Разбор CODESYS ExportFile (.export): все правила по программам ПЛЮС пять правил,
    которых нет в PLCopenXML — по параметрам модулей и экранам визуализации.

    Программы в экспорте лежат построчно, а объявления отдельным разделом; мы собираем из
    них дерево В ФОРМЕ PLCopenXML и отдаём обычному analyze(). Это осознанно дороже на одну
    сериализацию, зато не появляется второй движок, который со временем разойдётся с первым:
    правила, тексты и фикстуры остаются одни.

    Чего на .export не будет: конфигурация задач в этом формате устроена иначе, поэтому
    правила про сторожевой таймер и дубли Modbus-адресов молчат. Раздел устройств в отчёте
    при этом заполняется — из дерева экспорта, а не из конфигурации PLCopenXML."""
    import export_file

    def T(rule):
        return i18n.rule_title(lang, rule)

    def D(key, **kw):
        return i18n.detail(lang, key, **kw)

    name = os.path.splitext(os.path.basename(src))[0] if isinstance(src, str) else "project"
    ex = export_file.read(src)
    reads, writes = ex.refs()
    rep = analyze(ET.tostring(export_file.to_plcopen(ex, name), encoding="utf-8"),
                  profiles=profiles, lang=lang,
                  extra_refs={"text": ex.ref_text(), "reads": reads, "writes": writes})
    rep.name = name

    rule_by_kind = {"sensor-off": "channel-sensor-off", "output-off": "channel-output-off",
                    "module-off": "module-disabled"}
    for dev, key, label, kind in heur_export_devices(ex):
        rule = rule_by_kind[kind]
        rep.findings.append(Finding(
            rule=rule, severity=_sev(rule), title=T(rule), pou=dev, line=0,
            detail=D(rule, dev=dev, par=key, label=label or key)))
    for screen, var, kind, extra in heur_export_visu(ex):
        rule = "visu-two-labels" if kind == "two-labels" else "visu-index-mismatch"
        rep.findings.append(Finding(
            rule=rule, severity=_sev(rule), title=T(rule), pou=screen, line=0,
            detail=D(rule, screen=screen, var=var, extra=extra)))

    order = {"high": 0, "medium": 1, "low": 2}
    rep.findings.sort(key=lambda f: (order.get(f.severity, 9), f.pou, f.line or 0, f.rule))
    # модули и экраны — то, чего в PLCopenXML нет; размер проекта по-прежнему в POU,
    # а units нужен, когда программ в экспорте не оказалось вовсе
    rep.device = {"devices": [{"name": d.name, "params": len(d.params)} for d in ex.devices],
                  "visus": [{"name": v.name, "elements": len(v.elements)} for v in ex.visus]}
    rep.units = len(ex.devices) + len(ex.visus)
    return rep


def analyze(src, profiles=None, lang="ru", extra_refs=None) -> Report:
    """src: путь (str), bytes или file-like. profiles — набор опциональных стандарт-профилей
    (напр. {'plcopen-naming'}). lang — язык заголовков/деталей находок (ru/en).

    extra_refs — использования ВНЕ программ: {"text", "reads", "writes"}. В PLCopenXML их
    нет и быть не может, а из .export они приходят (привязки экранов, параметры
    преобразований единиц). Без них правила «не используется / никто не формирует»
    считают мёртвым то, что живёт на экране.
    Возвращает Report со структурированными findings."""
    extra_refs = extra_refs or {}
    _xtext = extra_refs.get("text", "")
    _xreads = extra_refs.get("reads", ())
    _xwrites = extra_refs.get("writes", ())
    profiles = set(profiles or ())

    def T(rule):                      # локализованный заголовок правила
        return i18n.rule_title(lang, rule)

    def D(key, **kw):                 # локализованная деталь находки
        return i18n.detail(lang, key, **kw)

    def M(items, limit):              # "a, b, c" + " и ещё N" с учётом языка
        shown = ", ".join(items[:limit])
        if len(items) > limit:
            shown += " " + i18n.term(lang, "and_more", k=len(items) - limit)
        return shown
    if isinstance(src, (bytes, bytearray)):
        raw = bytes(src)
        # PLCopen-экспорт не содержит DTD/сущностей → отсекаем entity-expansion / XXE
        if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
            raise NotPlcOpenError("dtd/entity")
        tree = ET.parse(io.BytesIO(raw))
    elif hasattr(src, "read"):
        tree = ET.parse(src)
    else:
        tree = ET.parse(src)
    root = tree.getroot()

    # корень обязан быть <project> в namespace PLCopen — иначе это валидный, но посторонний
    # XML (SVG, чужой конфиг…), а не экспорт. Отсекаем «мусор» с понятной ошибкой.
    _tag = root.tag if isinstance(root.tag, str) else ""
    _local = _tag.rsplit("}", 1)[-1]
    _nsuri = _tag[1:_tag.index("}")] if _tag.startswith("{") else ""
    if _local != "project" or "plcopen.org" not in _nsuri:
        raise NotPlcOpenError(_local or _tag or "unknown")

    # имя проекта: ProjectInformation/property[@name="Project"] (реальное имя проекта в IDE)
    # → contentHeader@name → basename пути → "project". Загруженный файл приходит bytes,
    # поэтому без этого у всех отчётов/сертификатов имя было бы дефолтным "project".
    name = "project"
    ch = root.find(q("contentHeader"))
    proj = None
    for el in (ch if ch is not None else root).iter():
        if el.tag.rsplit("}", 1)[-1] == "property" and el.get("name") == "Project" \
                and (el.text or "").strip():
            proj = el.text.strip()
            break
    if proj:
        name = proj
    elif ch is not None and (ch.get("name") or "").strip():
        name = ch.get("name").strip()
    elif isinstance(src, str):
        name = os.path.splitext(os.path.basename(src))[0]

    version = ""
    fh = root.find(q("fileHeader"))
    if fh is not None:
        version = fh.get("productVersion", "")
    # время правки проекта: единственный надёжный признак «какая версия новее».
    # По именам файлов порядок не восстановить: _final, _final2, _испр ничего не говорят.
    modified = (ch.get("modificationDateTime") or "") if ch is not None else ""

    pous, rendered = extract(root)
    decl = globals_of(root)
    local_arrays, global_arrays = collect_arrays(pous, root)

    # покрытие по языкам: построчно анализируется только ST; графику (LD/FBD/SFC/CFC)
    # покрываем частично (по вхождению имён) и честно помечаем в отчёте.
    by_lang = {}
    for _n, _d in pous.items():
        by_lang.setdefault(_d.get("lang") or "?", []).append(_n)
    _nonst = {lg: v for lg, v in by_lang.items() if lg != "ST"}
    coverage = {
        "total": len(pous),
        "st": len(by_lang.get("ST", [])),
        "by_lang": {lg: len(v) for lg, v in sorted(_nonst.items())},
        "nonst_count": sum(len(v) for v in _nonst.values()),
    }

    findings = []

    for nm, i, var, idx, lo, hi, ln in heur_array_bounds(pous, local_arrays, global_arrays):
        findings.append(Finding(
            rule="array-bounds", severity=_sev("array-bounds"), title=T("array-bounds"),
            pou=nm, line=i, detail=D("array-bounds", var=var, idx=idx, lo=lo, hi=hi), code=ln))

    for nm, i, kind in heur_infinite_loop(pous):
        findings.append(Finding(
            rule="infinite-loop", severity=_sev("infinite-loop"), title=T("infinite-loop"),
            pou=nm, line=i, detail=i18n.term(lang, kind)))

    for nm, i, ln in heur_div_zero(pous):
        findings.append(Finding(
            rule="div-by-zero", severity=_sev("div-by-zero"), title=T("div-by-zero"),
            pou=nm, line=i, detail=D("div-by-zero"), code=ln))

    for nm, i, ln, vn, sev, dkey in heur_div_zero_var(pous, decl):
        findings.append(Finding(
            rule="div-by-zero", severity=sev, title=T("div-by-zero"),
            pou=nm, line=i, detail=D(dkey, var=vn), code=ln))

    for nm, i, ln in heur_timer_zero_pt(pous):
        findings.append(Finding(
            rule="timer-zero-pt", severity=_sev("timer-zero-pt"), title=T("timer-zero-pt"),
            pou=nm, line=i, detail=D("timer-zero-pt"), code=ln))

    # channel-mismatch — три признака одного класса: копия соседнего канала
    for nm, base, miss, suf, have in heur_family_gap(pous, root, extra=_xtext):
        findings.append(Finding(
            rule="family-gap", severity=_sev("family-gap"), title=T("family-gap"),
            pou=nm, detail=D("family-gap", field=f"{base}_{miss}_{suf}", ch=miss,
                             have=", ".join(str(h) for h in have))))

    for nm, i, fb, pname, val, ch, other in heur_param_channel_mismatch(pous):
        findings.append(Finding(
            rule="param-channel-mismatch", severity=_sev("param-channel-mismatch"),
            title=T("param-channel-mismatch"), pou=nm, line=i,
            detail=D("param-channel-mismatch", ch=ch, other=", ".join(other), fb=fb),
            code=f"{pname} := {val}"))

    for nm, i, cmd, var, ftype, oname, inp, sig, ln in heur_self_enable(pous):
        findings.append(Finding(
            rule="self-enable", severity=_sev("self-enable"), title=T("self-enable"),
            pou=nm, line=i, code=ln,
            detail=D("self-enable", cmd=cmd, fb=ftype, out=oname, inp=inp, sig=sig)))

    for nm, i, timer, var, rl, ln, kind in heur_timer_reset(pous):
        # Два зеркальных дефекта одной природы, но последствия разные: у задержки
        # включения выдержка не наступает, у задержки выключения — не кончается,
        # поэтому и правила разные, с разным текстом и разной подсказкой к правке.
        rid = ("timer-rearmed-by-own-branch" if kind == "off"
               else "timer-reset-by-own-condition")
        findings.append(Finding(
            rule=rid, severity=_sev(rid), title=T(rid), pou=nm, line=i, code=ln,
            detail=D(rid, timer=timer, var=var, rl=rl)))

    for nm, i, timer, var, ln in heur_timer_off_delay_branch(pous):
        findings.append(Finding(
            rule="timer-off-delay-in-own-branch", severity=_sev("timer-off-delay-in-own-branch"),
            title=T("timer-off-delay-in-own-branch"), pou=nm, line=i, code=ln,
            detail=D("timer-off-delay-in-own-branch", timer=timer, var=var)))

    for nm, i, timer, v1, v2, l1, ln in heur_fb_call_overwritten(pous):
        findings.append(Finding(
            rule="fb-call-overwritten", severity=_sev("fb-call-overwritten"),
            title=T("fb-call-overwritten"), pou=nm, line=i, code=ln,
            detail=D("fb-call-overwritten", timer=timer, first=v1, second=v2, fl=l1)))

    for nm, i, inst, typ, var, ln in heur_edge_lost_in_own_branch(pous):
        findings.append(Finding(
            rule="edge-lost-in-own-branch", severity=_sev("edge-lost-in-own-branch"),
            title=T("edge-lost-in-own-branch"), pou=nm, line=i, code=ln,
            detail=D("edge-lost-in-own-branch", edge=inst, type=typ, var=var)))

    for nm, i, timer, typ, ln in heur_timer_preset_missing(pous):
        findings.append(Finding(
            rule="timer-preset-missing", severity=_sev("timer-preset-missing"),
            title=T("timer-preset-missing"), pou=nm, line=i, code=ln,
            detail=D("timer-preset-missing", timer=timer, type=typ)))

    for nm, i, kind, val, ln, chain in heur_always_false(pous, decl):
        # цепочка подстановки — главное в сообщении: без неё человек видит нормальное
        # условие и не понимает, почему оно «всегда ложно»
        steps = " → ".join(
            "`{}` = `{}` ({}{})".format(v, rhs, p, i18n.term(lang, "af.at_line", n=ln2))
            for v, rhs, p, ln2 in chain)
        findings.append(Finding(
            rule="always-false-condition", severity=_sev("always-false-condition"),
            title=T("always-false-condition"), pou=nm, line=i, code=ln,
            detail=D("always-false-condition", what=i18n.term(lang, "af." + kind),
                     val=i18n.term(lang, "af.false" if val is False else "af.true"),
                     steps=steps)))

    for var, readers, confirmed in heur_signal_without_source(pous, decl, root,
                                                               _xreads, _xwrites):
        findings.append(Finding(
            rule="signal-without-source",
            # на .export привязки экранов видны: «не пишется нигде» — факт, а не догадка
            severity="high" if confirmed else _sev("signal-without-source"),
            title=T("signal-without-source"), pou=readers[0], line=0,
            detail=D("signal-without-source.confirmed" if confirmed else "signal-without-source",
                     var=var, n=len(readers), readers=M(readers, 3))))

    for nm, i, var, typ, always, ln in heur_unsigned_vs_zero(pous, decl):
        findings.append(Finding(
            rule="unsigned-vs-zero", severity=_sev("unsigned-vs-zero"),
            title=T("unsigned-vs-zero"), pou=nm, line=i, code=ln,
            detail=D("unsigned-vs-zero", var=var, type=typ,
                     val=i18n.term(lang, "af.true" if always else "af.false"))))

    for nm, i, p1, p2, v1, v2, eq, total, ln in heur_index_mismatch(pous):
        findings.append(Finding(
            rule="index-mismatch", severity=_sev("index-mismatch"), title=T("index-mismatch"),
            pou=nm, line=i, code=ln,
            detail=D("index-mismatch", p1=p1, p2=p2, v1=v1, v2=v2, eq=eq, total=total)))

    for base, in_pous in sorted(find_undeclared(pous, decl).items()):
        findings.append(Finding(
            rule="undeclared-global", severity=_sev("undeclared-global"),
            title=T("undeclared-global"), pou=", ".join(sorted(in_pous)),
            detail=D("undeclared-global", base=base)))

    for nm, l1, l2, v1, t1, t2 in heur_unreachable_if(pous):
        findings.append(Finding(
            rule="unreachable-branch", severity=_sev("unreachable-branch"),
            title=T("unreachable-branch"), pou=nm, line=l1,
            detail=D("unreachable-branch", l1=l1, l2=l2, v1=v1, t1=t1, t2=t2)))

    for nm, inst, t in heur_uncalled_fb(pous):
        findings.append(Finding(
            rule="uncalled-timer", severity=_sev("uncalled-timer"),
            title=T("uncalled-timer"), pou=nm,
            detail=D("uncalled-timer", inst=inst, typ=t)))

    for nm, i, ln in heur_int_division(pous, decl):
        findings.append(Finding(
            rule="int-division", severity=_sev("int-division"), title=T("int-division"),
            pou=nm, line=i, detail=T("int-division"), code=ln))

    for rule, pattern in (("real-to-time-mul", r'REAL_TO_TIME\s*\(.*\)\s*\*'),
                          ("real-to-word-mul", r'REAL_TO_WORD\s*\(.*\)\s*\*'),
                          ("double-semicolon", r';;')):
        for nm, i, ln in heur_regex(pous, pattern):
            findings.append(Finding(
                rule=rule, severity=_sev(rule), title=T(rule),
                pou=nm, line=i, detail=T(rule), code=ln))

    for nm in dead_pous(root, pous, extra=_xtext):
        findings.append(Finding(
            rule="dead-pou", severity=_sev("dead-pou"), title=T("dead-pou"),
            pou=nm, detail=D("dead-pou", nm=nm)))

    for nm, vn in heur_naming(pous):
        findings.append(Finding(
            rule="naming", severity=_sev("naming"), title=T("naming"),
            pou=nm, detail=D("naming", vn=vn)))

    for val, pous_list, (fpou, fline, fcode), total in heur_magic(pous):
        if len(pous_list) > 1:
            detail = D("magic-number.multi", val=val, n=len(pous_list), shown=M(pous_list, 5))
        else:
            detail = D("magic-number.single", val=val)
        findings.append(Finding(
            rule="magic-number", severity=_sev("magic-number"), title=T("magic-number"),
            pou=fpou, line=fline, detail=detail, code=fcode))

    for nm, n in heur_comments(pous):
        findings.append(Finding(
            rule="missing-comments", severity=_sev("missing-comments"),
            title=T("missing-comments"), pou=nm,
            detail=D("missing-comments", n=n)))

    for nm, n in heur_routine_size(pous):
        findings.append(Finding(
            rule="routine-size", severity=_sev("routine-size"), title=T("routine-size"),
            pou=nm, detail=D("routine-size", n=n, max=ROUTINE_MAX)))

    for g in heur_copy_paste(pous):
        if g["intra"]:
            detail = D("copy-paste.intra", pou=g["pous"][0], blocks=g["blocks"],
                       repeats=g["repeats"], lines=g["lines"])
        else:
            detail = D("copy-paste.inter", pous=M(g["pous"], 6), blocks=g["blocks"],
                       lines=g["lines"])
        findings.append(Finding(
            rule="copy-paste", severity=_sev("copy-paste"), title=T("copy-paste"),
            pou=g["pous"][0], detail=detail))

    for nm, i, ln in heur_self_assign(pous):
        findings.append(Finding(
            rule="self-assignment", severity=_sev("self-assignment"),
            title=T("self-assignment"), pou=nm, line=i,
            detail=D("self-assignment"), code=ln))

    for nm, i, desc in heur_empty_branch(pous):
        findings.append(Finding(
            rule="empty-branch", severity=_sev("empty-branch"), title=T("empty-branch"),
            pou=nm, line=i, detail=i18n.term(lang, desc)))

    for nm, i in heur_case_without_else(pous):
        findings.append(Finding(
            rule="case-without-else", severity=_sev("case-without-else"),
            title=T("case-without-else"), pou=nm, line=i,
            detail=D("case-without-else")))

    for nm, i, depth in heur_deep_nesting(pous):
        findings.append(Finding(
            rule="deep-nesting", severity=_sev("deep-nesting"), title=T("deep-nesting"),
            pou=nm, line=i, detail=D("deep-nesting", depth=depth, max=NESTING_MAX)))

    unused_by_pou = {}
    for nm, vn in heur_unused_local(pous):
        unused_by_pou.setdefault(nm, []).append(vn)
    for nm, vs in unused_by_pou.items():
        shown = M([f"`{v}`" for v in vs], 8)
        detail = (D("unused-local.multi", n=len(vs), shown=shown) if len(vs) > 1
                  else D("unused-local.single", shown=shown))
        findings.append(Finding(
            rule="unused-local", severity=_sev("unused-local"), title=T("unused-local"),
            pou=nm, detail=detail))

    # --- implicit checks: регистрация <CheckFunction> = «включено» в компиляции ---
    regs = check_registrations(root)
    active_roles = set(regs.values())
    check_named = [n for n in pous if _CHECK_POU_RE.match(n)]

    # (1) спящие: назван как Check*, но не зарегистрирован → рантайм его не вызывает
    for n in check_named:
        if n not in regs:
            findings.append(Finding(
                rule="implicit-check-disabled", severity=_sev("implicit-check-disabled"),
                title=T("implicit-check-disabled"), pou=n,
                detail=D("implicit-check-disabled.dormant")))

    if not active_roles and not check_named:
        # (2a) защит нет вовсе
        findings.append(Finding(
            rule="missing-implicit-checks", severity=_sev("missing-implicit-checks"),
            title=T("missing-implicit-checks"), pou=i18n.term(lang, "scope.project"),
            detail=D("missing-implicit-checks")))
    elif active_roles:
        # (2b) какие категории защиты не активны
        for cat, roles in CHECK_CATEGORIES.items():
            if not (active_roles & roles):
                findings.append(Finding(
                    rule="implicit-check-disabled", severity=_sev("implicit-check-disabled"),
                    title=T("implicit-check-disabled"), pou=i18n.term(lang, "scope.project"),
                    detail=D("implicit-check-disabled.category", cat=i18n.term(lang, "chk." + cat))))

    # (3) выхолощенная логика — только для зарегистрированных проверок
    for nm, whykey in heur_broken_implicit_check(pous):
        if nm in regs:
            findings.append(Finding(
                rule="broken-implicit-check", severity=_sev("broken-implicit-check"),
                title=T("broken-implicit-check"), pou=nm,
                detail=D("broken-implicit-check", why=i18n.term(lang, whykey))))

    # разбор устройств/задач + watchdog
    device = device_summary(root, lang)
    wd_off = [t["name"] for t in device["tasks"] if t["watchdog"] is False]
    if wd_off:
        findings.append(Finding(
            rule="watchdog-disabled", severity=_sev("watchdog-disabled"),
            title=T("watchdog-disabled"), pou=i18n.term(lang, "scope.tasks"),
            detail=D("watchdog-disabled", n=len(wd_off), names=", ".join(wd_off))))
    for addr, names in duplicate_module_addresses(device):
        findings.append(Finding(
            rule="modbus-address-duplicate", severity=_sev("modbus-address-duplicate"),
            title=T("modbus-address-duplicate"), pou=i18n.term(lang, "scope.devices"),
            detail=D("modbus-address-duplicate", addr=addr, names=", ".join(names))))

    # CFC/FBD граф-проверки (у графики нет номеров строк — привязка к POU)
    for nm, op in heur_cfc_div_zero(root):
        findings.append(Finding(
            rule="cfc-div-zero", severity=_sev("cfc-div-zero"), title=T("cfc-div-zero"),
            pou=nm, detail=D("cfc-div-zero", op=op)))

    # опциональные стандарт-профили
    profile_stats = {}
    if "plcopen-naming" in profiles:
        viols, checked, ok = check_plcopen_naming(pous)
        profile_stats["plcopen-naming"] = {
            "checked": checked, "ok": ok,
            "pct": round(100 * ok / checked) if checked else 100,
        }
        by_pou = {}
        for pou, vn, pfx in viols:
            by_pou.setdefault(pou, []).append((vn, pfx))
        for pou, items in by_pou.items():
            ex = ", ".join(f"{n}→{p}{n[:1].upper()}{n[1:]}" for n, p in items[:5])
            more = (" " + i18n.term(lang, "and_more", k=len(items) - 5)) if len(items) > 5 else ""
            findings.append(Finding(
                rule="plcopen-naming", severity=_sev("plcopen-naming"),
                title=T("plcopen-naming"), pou=pou,
                detail=D("plcopen-naming", n=len(items), ex=ex, more=more)))

    if "heating" in profiles:
        hits, total_ai, ok_ai = heur_ai_no_range(pous, root)
        profile_stats["heating"] = {
            "checked": total_ai, "ok": ok_ai,
            "pct": round(100 * ok_ai / total_ai) if total_ai else 100,
        }
        for pou, variables in hits:
            ex = ", ".join(variables[:5])
            more = (" " + i18n.term(lang, "and_more", k=len(variables) - 5)) if len(variables) > 5 else ""
            findings.append(Finding(
                rule="heating-ai-no-range-check", severity=_sev("heating-ai-no-range-check"),
                title=T("heating-ai-no-range-check"), pou=pou,
                detail=D("heating-ai-no-range-check", n=len(variables), ex=ex, more=more, pou=pou)))

    # сортировка: high → medium → low
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f.severity], f.pou, f.line or 0))

    return Report(name=name, version=version, pou_count=len(pous),
                  globals_count=len(decl), findings=findings, rendered=rendered,
                  modified=modified,
                  signals={**candidate_signals(pous), **cfc_signals(root)}, profile_stats=profile_stats, device=device,
                  coverage=coverage)


if __name__ == "__main__":
    import sys
    for path in sys.argv[1:]:
        rep = analyze(path)
        print(f"[{rep.name}] {rep.version}  POU:{rep.pou_count} globals:{rep.globals_count}  "
              f"{rep.summary}")
        for f in rep.findings:
            loc_s = f"{f.pou}:{f.line}" if f.line else f.pou
            print(f"  [{f.severity:6}] {f.rule:18} {loc_s}  {f.detail}")

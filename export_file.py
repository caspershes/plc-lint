#!/usr/bin/env python3
"""Чтение CODESYS ExportFile (.export): дерево устройств и экраны визуализации.

Зачем отдельный формат. PLCopenXML — это только программы: ни параметров модулей,
ни привязок визуализации в нём нет. А самые дорогие дефекты живут именно там:
канал, у которого тип датчика «Отключен», модуль, исключённый из опроса, выход ЦАП
в режиме «Выключен», элемент экрана, скопированный вместе с чужой привязкой. Ни одна
статика этого не смотрит, потому что все читают ST.

Разбор потоковый (iterparse с очисткой поддеревьев): боевой экспорт — 29 МБ, полное
дерево в памяти стоит ~200 МБ, а сервис живёт на VPS вместе с другим стеком.

ТРИ ГРАБЛИ ФОРМАТА, каждая стоила отдельного разбора:

1. Один параметр лежит в файле НЕСКОЛЬКО раз: шаблон из описания устройства, служебная
   копия и только последней — фактическая конфигурация. Брать надо ПОСЛЕДНЕЕ вхождение.
   По первому инструмент три раза подряд докладывал «тип датчика не выбран», когда в
   проекте стоял Pt1000.
2. Значение enum лежит не в самом параметре, а глубже — в `BaseType/Value`. Без этого
   у канала видно только постоянную фильтра, а тип датчика «не замечается».
3. Признак занятого канала — привязка `SensorValueN.SensorValue`, а НЕ `InputStatus`:
   коды статуса намеренно вешают и на свободные входы, чтобы не потерять статус при
   смене канала. По статусу все 12 входов выглядели бы занятыми.

И отдельная грабля экранов: у элемента есть вложенные под-элементы со своими такими же
списками свойств. Обход через iter() склеивает их вместе, и геометрия с текстами
«разъезжается» — берём только прямых детей (`List` самого элемента).
"""
import re
import xml.etree.ElementTree as ET

DEVICE_TYPE = "225bfe47-7336-4dbc-9419-4105a7c831fa"
VISU_TYPE = "f18bec89-9fef-401d-9953-2f11739a6808"
_MEMBER_TYPE = "c694e3a2-5c0b-4177-ab35-cb06bd5a6a02"

# Id свойств элемента визуализации. Смысл Id не документирован — расшифрован по
# фактическим значениям в боевых проектах.
P_TEXT = 390574330          # надпись («Котёл 2», «%.1f °C»)
P_VAR_OUTPUT = 2477733581   # переменная вывода значения
P_VAR_TEXT = 4168582468     # переменная, подставляемая в текст
P_TAP_VAR = 1999528970      # переменная нажатия (toggle/tap)
P_ACTION_VAR = 1647042231   # действие кнопки
P_CHECKBOX_VAR = 743958181  # переменная флажка — у него свой Id
P_VAR_ORDER = (P_VAR_OUTPUT, P_VAR_TEXT, P_TAP_VAR, P_ACTION_VAR)
# Экран не только показывает, но и ПИШЕТ: поле ввода уставки, флажок, кнопка-переключатель.
# Это ответ на главную граблю правила «сигнал без источника»: в PLCopenXML привязок не
# видно, и «не пишется в ST» там остаётся догадкой, а здесь становится фактом.
# Проверено на боевом проекте: все 9 уставок погодного графика, которых нет ни в одной
# строке ST, пишутся именно с экранов, а аварии котлов не пишутся нигде.
P_WRITE_IDS = (P_VAR_TEXT, P_TAP_VAR, P_ACTION_VAR, P_CHECKBOX_VAR)
# параметры объекта «Преобразование единиц»: отрезок графика читает уставки прямо отсюда,
# и в ST этих имён нет вовсе (в боевом проекте так собран весь погодный график)
_CONV_FIELDS = ("BaseStart", "BaseEnd", "TargetStart", "TargetEnd")
_REF_RE = re.compile(r"\b(?:[A-Za-z_]\w*\.)?([A-Za-z_]\w*)\b")


class Device:
    """Узел дерева устройств: имя, параметры и каналы, заведённые на переменные."""

    def __init__(self, name, params, mapped):
        self.name = name
        self.params = params            # [(ключ, подпись, значение, дефолт, {enum: подпись})]
        self.mapped = mapped            # {'SensorValue3.SensorValue', …}

    def used_channels(self):
        """Номера каналов, чьё ЗНАЧЕНИЕ заведено на переменную (грабля 3)."""
        nums = set()
        for key in self.mapped:
            if not key.endswith(".SensorValue"):
                continue
            nums.update(re.findall(r"\d+", key.split(".")[0]))
        return nums


class Visu:
    """Экран: имя и элементы, у каждого — свойства по Id."""

    def __init__(self, name, elements):
        self.name = name
        self.elements = elements        # [{Id: значение, …}]

    @staticmethod
    def var_of(props):
        for pid in P_VAR_ORDER:
            v = (props.get(pid) or "").strip()
            if v and not v.startswith("<"):
                return v
        return ""

    @staticmethod
    def text_of(props):
        return (props.get(P_TEXT) or "").strip()


def _declness(text):
    """Насколько текст похож на объявления: 2 — есть ключевое слово POU/TYPE/VAR_GLOBAL,
    1 — есть VAR-блок, 0 — это тело."""
    clean = re.sub(r"\(\*.*?\*\)", " ", text or "", flags=re.S)
    clean = re.sub(r"//[^\n]*", " ", clean)
    if re.search(r"^\s*(?:PROGRAM|FUNCTION_BLOCK|FUNCTION|INTERFACE|TYPE)\s+[A-Za-z_]", clean,
                 re.I | re.M) or re.search(r"\bVAR_GLOBAL\b", clean, re.I):
        return 2
    if re.search(r"\bEND_VAR\b", clean, re.I):
        return 1
    return 0


class Code:
    """Объект с текстом: POU, список глобалов, тип, действие или метод.

    В экспорте тело POU лежит построчно (TextLines: записи {Id, Tag, Text}), а объявления —
    отдельным таким же массивом. Разделы собираем обратно и различаем по содержимому:
    где есть VAR-блок или ключевое слово PROGRAM/FUNCTION_BLOCK — это объявления."""

    def __init__(self, name, guid, parent, sections):
        self.name = name
        self.guid = guid
        self.parent = parent
        # Опознаём раздел по тексту БЕЗ комментариев: у CheckBounds в реализации лежит
        # закомментированный вариант с END_VAR, и по сырому тексту тело уехало в объявления.
        scored = [(sec, _declness(sec)) for sec in sections]
        best = max((sc for _s, sc in scored), default=0)
        decl, impl = None, []
        for sec, sc in scored:
            if decl is None and sc > 0 and sc == best:
                decl = sec
            else:
                impl.append(sec)
        self.decl = decl or ""
        self.body = "\n".join(impl)
        self.kind, decl_name, self.return_type, self.sections = parse_declarations(self.decl)
        # имя из объявления точнее имени объекта: у действия это `work_kotel.act`
        self.decl_name = decl_name or name


class Export:
    def __init__(self, devices, visus, code=(), conversions=()):
        self.devices = devices
        self.visus = visus
        self.code = list(code)
        self.conversions = list(conversions)   # [(имя, [ссылки на переменные])]

    def refs(self):
        """({читается}, {пишется}) — имена переменных ВНЕ программ: привязки экранов и
        параметры преобразований. Для правил это такие же использования, как строки ST:
        без них уставки, которые крутят только с экрана, выглядят мёртвыми."""
        reads, writes = set(), set()
        for v in self.visus:
            for props in v.elements:
                for pid, val in props.items():
                    val = (val or "").strip()
                    if not val or val.startswith("<"):
                        continue          # «<toggle/tap variable>» — заглушка, не привязка
                    target = writes if pid in P_WRITE_IDS else reads
                    for m in _REF_RE.finditer(val):
                        target.add(m.group(1).lower())
        for _name, refs in self.conversions:
            for r in refs:
                for m in _REF_RE.finditer(r):
                    reads.add(m.group(1).lower())
        return reads, writes

    def ref_text(self):
        """Те же имена одной строкой — для правил, которые ищут «встречается ли имя»."""
        reads, writes = self.refs()
        return " ".join(sorted(reads | writes))


def _txt(el):
    return (el.text or "").strip() if el is not None else None


def _named(node, name):
    for c in node:
        if c.get("Name") == name:
            return c
    return None


def _enum_values(node):
    arr = _named(node, "Values")
    if arr is None:
        return None
    res = {}
    for v in arr:
        nm = _named(v, "Name")
        res[_txt(_named(v, "Value"))] = _txt(_named(nm, "Default")) if nm is not None else None
    return res or None


def _mapped_var(node):
    """Привязка канала к переменной IEC: '' — привязки нет, None — узел не о привязке."""
    io = _named(node, "IoMapping")
    if io is None:
        return None
    mp = _named(io, "Mappings")
    lst = _named(mp, "Mappings") if mp is not None else None
    if lst is None or not len(lst):
        return None
    for m in lst:
        for c in m.iter("Single"):
            if c.get("Name") in ("Variable", "VariableName", "Expression"):
                return _txt(c)
    return ""


def _dala(node, path, out, mapped):
    vn = _named(node, "VisibleName")
    ident = _txt(_named(vn, "Identifier")) if vn is not None else None
    label = _txt(_named(vn, "Default")) if vn is not None else None
    newpath = path + [ident or "?"]
    if _mapped_var(node) is not None:
        mapped.add(".".join(newpath))

    holder, val = node, _txt(_named(node, "Value"))
    if val is None:
        base = _named(node, "BaseType")          # грабля 2: enum лежит глубже
        if base is not None:
            holder, val = base, _txt(_named(base, "Value"))
    if val is not None:
        out.append((".".join(newpath), label, val, _txt(_named(holder, "Default")),
                    _enum_values(holder) or _enum_values(node)))

    sub = _named(node, "SubElements")
    lst = _named(sub, "elements") if sub is not None else None
    for ch in (lst if lst is not None else []):
        _dala(ch, newpath, out, mapped)


def _walk_dala(node, out, mapped):
    for child in node:
        if child.get("Name") == "DalaElement":
            _dala(child, [], out, mapped)
        else:
            _walk_dala(child, out, mapped)


def _device(name, obj):
    rows, mapped = [], set()
    _walk_dala(obj, rows, mapped)
    # грабля 1: побеждает ПОСЛЕДНЕЕ вхождение параметра
    last = {}
    for r in rows:
        last[r[0]] = r
    params = [last[k] for k in dict.fromkeys(r[0] for r in rows)]
    return Device(name, params, mapped)


def _visu(name, obj):
    elems = []
    for member in obj.iter("Single"):
        if member.get("Name") != "VisualElemMemberList":
            continue
        props = {}
        own = member.find("List")            # только прямые дети, не под-элементы
        for m in (own if own is not None else []):
            if m.get("Type", "").strip("{}") != _MEMBER_TYPE:
                continue
            kid = {c.get("Name"): _txt(c) for c in m}
            if "Id" in kid:
                props[int(kid["Id"])] = kid.get("Value") or ""
        if props:
            elems.append(props)
    return Visu(name, elems)


def _conversions(obj):
    """Преобразования единиц объекта: [(имя, [ссылки])]. Отрезок погодного графика —
    это именно такой объект, и уставки он читает из своих параметров, а не из кода."""
    out, cur, refs = [], None, []
    for el in obj.iter():
        nm = el.get("Name")
        if nm == "ConversionName":
            if cur:
                out.append((cur, refs))
            cur, refs = (el.text or "").strip(), []
        elif nm in _CONV_FIELDS and cur:
            val = (el.text or "").strip()
            if val and not val.replace(".", "", 1).replace("-", "", 1).isdigit():
                refs.append(val)
    if cur:
        out.append((cur, refs))
    return out


def _text_sections(obj):
    """Разделы текста объекта в порядке документа: тело и объявления."""
    out = []
    for arr in obj.iter("Array"):
        if arr.get("Name") != "TextLines":
            continue
        lines = []
        for rec in arr:
            t = _named(rec, "Text")
            lines.append(t.text or "" if t is not None else "")
        if any(l.strip() for l in lines):
            out.append("\n".join(lines))
    return out


def read(src):
    """src — путь, bytes или file-like. → Export."""
    if isinstance(src, (bytes, bytearray)):
        import io
        src = io.BytesIO(bytes(src))
    devices, visus, code, convs = [], [], [], []
    meta_name, meta_type, meta_guid, meta_parent = None, None, None, None
    for _ev, el in ET.iterparse(src, events=("end",)):
        if el.tag != "Single":
            continue
        name = el.get("Name")
        if name == "MetaObject":
            meta_name = _txt(_named(el, "Name"))
            meta_type = _txt(_named(el, "TypeGuid"))
            meta_guid = _txt(_named(el, "Guid"))
            meta_parent = _txt(_named(el, "ParentGuid"))
            el.clear()
            continue
        if name != "Object":
            continue
        typ = el.get("Type", "").strip("{}")
        if typ == DEVICE_TYPE and meta_type == DEVICE_TYPE:
            devices.append(_device(meta_name, el))
        else:
            if typ == VISU_TYPE:
                visus.append(_visu(meta_name, el))
            conv = _conversions(el)
            if conv:
                convs += conv
            # текст есть и у шаблонов визуализации (объявления интерфейса) — собираем всё,
            # чтобы ничего не терялось молча; что считать POU, решает to_plcopen()
            sections = _text_sections(el)
            if sections:
                code.append(Code(meta_name, meta_guid, meta_parent, sections))
        el.clear()                            # поддерево больше не нужно
    return Export(devices, visus, code, convs)


def looks_like_export(head):
    """Первые байты файла: это ExportFile, а не PLCopenXML?"""
    if isinstance(head, (bytes, bytearray)):
        head = head[:400].decode("utf-8", "replace")
    return "<ExportFile" in (head or "")


# ====================== экспорт → форма PLCopenXML ======================
# Движок читает PLCopenXML, и в нём 37 правил по программам. В экспорте программы тоже
# есть, только тело POU лежит не куском текста, а построчно (TextLines: записи {Id, Text}),
# а объявления — отдельным разделом. Поэтому вместо «ещё одного движка для .export» мы
# собираем из экспорта дерево В ФОРМЕ PLCopenXML и отдаём его обычному analyze(): все
# правила, все тексты, те же фикстуры — без второй реализации, которая разойдётся с первой.
NS = "http://www.plcopen.org/xml/tc6_0200"

# Ключевое слово объявления само говорит, что это за объект: GUID-археология не нужна и
# ломается от версии к версии, а `PROGRAM x` / `VAR_GLOBAL` — часть языка.
_KIND_RE = re.compile(r"^\s*(PROGRAM|FUNCTION_BLOCK|FUNCTION|INTERFACE)\s+([A-Za-z_]\w*)"
                      r"(?:\s*:\s*([^\s;]+))?", re.I | re.M)
_ACT_RE = re.compile(r"^\s*(ACTION|METHOD)\s+([A-Za-z_][\w.]*)", re.I | re.M)
_VAR_BLOCK = re.compile(r"^[ \t]*VAR(_INPUT|_OUTPUT|_IN_OUT|_TEMP|_GLOBAL|_STAT|_EXTERNAL)?\b"
                        r"([^\n]*)\n(.*?)^[ \t]*END_VAR\b", re.I | re.M | re.S)
_DECL_LINE = re.compile(r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*"
                        r"(?:AT\s+(%[A-Za-z0-9.*]+)\s*)?:\s*([^;:=]+?)\s*"
                        r"(?::=\s*(.+?))?\s*;", re.M)
_SECTION_TAG = {None: "localVars", "_INPUT": "inputVars", "_OUTPUT": "outputVars",
                "_IN_OUT": "inOutVars", "_TEMP": "tempVars", "_GLOBAL": "globalVars",
                "_STAT": "localVars", "_EXTERNAL": "externalVars"}
_BASE_TYPES = {
    "BOOL", "BYTE", "WORD", "DWORD", "LWORD", "SINT", "INT", "DINT", "LINT",
    "USINT", "UINT", "UDINT", "ULINT", "REAL", "LREAL", "TIME", "LTIME", "DATE",
    "TIME_OF_DAY", "TOD", "DATE_AND_TIME", "DT",
}
_ARRAY_RE = re.compile(r"^ARRAY\s*\[(.+?)\]\s*OF\s+(.+)$", re.I | re.S)
_STRING_RE = re.compile(r"^(W?STRING)\s*(?:[\[(]\s*(\d+)\s*[\])])?$", re.I)
_PTR_RE = re.compile(r"^(?:POINTER|REFERENCE)\s+TO\s+(.+)$", re.I)


def _el(parent, tag, **attrs):
    return ET.SubElement(parent, f"{{{NS}}}{tag}", {k: str(v) for k, v in attrs.items()})


def _type_el(parent, text):
    """<type> по тексту типа из объявления. Формы — те, что умеет engine.type_str()."""
    t = (text or "").strip()
    te = _el(parent, "type")
    m = _ARRAY_RE.match(t)
    if m:
        arr = _el(te, "array")
        for dim in m.group(1).split(","):
            lo, _, hi = dim.partition("..")
            _el(arr, "dimension", lower=lo.strip(), upper=(hi or lo).strip())
        _type_el(arr, m.group(2))
        # baseType внутри array должен называться baseType, а не type
        arr[-1].tag = f"{{{NS}}}baseType"
        return te
    m = _STRING_RE.match(t)
    if m:
        se = _el(te, m.group(1).lower())
        if m.group(2):
            _el(se, "length").text = m.group(2)
        return te
    m = _PTR_RE.match(t)
    if m:
        pe = _el(te, "pointer")
        _type_el(pe, m.group(1))
        pe[-1].tag = f"{{{NS}}}baseType"
        return te
    if t.upper() in _BASE_TYPES:
        _el(te, t.upper())
    else:
        _el(te, "derived", name=t)
    return te


def parse_declarations(text):
    """Текст объявлений → (kind, name, return_type, {тег секции: [(имена, адрес, тип, init, коммент)]}).

    kind ∈ program / functionBlock / function / interface / globals / type / None."""
    sections = {}
    for m in _VAR_BLOCK.finditer(text or ""):
        tag = _SECTION_TAG.get((m.group(1) or "").upper() or None, "localVars")
        const = "CONSTANT" in (m.group(2) or "").upper()
        body = m.group(3)
        for d in _DECL_LINE.finditer(body):
            names = [n.strip() for n in d.group(1).split(",")]
            # комментарий этой же строки — он уходит в documentation и виден в отчёте
            tail = body[d.end():body.find("\n", d.end()) if body.find("\n", d.end()) >= 0 else len(body)]
            cm = tail.strip()[2:].strip() if tail.strip().startswith("//") else ""
            for n in names:
                sections.setdefault(tag, []).append(
                    (n, d.group(2), d.group(3).strip(), (d.group(4) or "").strip(), cm, const))
    km = _KIND_RE.search(text or "")
    if km:
        kind = {"PROGRAM": "program", "FUNCTION_BLOCK": "functionBlock",
                "FUNCTION": "function", "INTERFACE": "interface"}[km.group(1).upper()]
        return kind, km.group(2), km.group(3), sections
    if re.search(r"\bVAR_GLOBAL\b", text or "", re.I):
        return "globals", None, None, sections
    if re.search(r"^\s*TYPE\s+[A-Za-z_]", text or "", re.I | re.M):
        return "type", None, None, sections
    am = _ACT_RE.search(text or "")
    if am:
        return am.group(1).lower(), am.group(2), None, sections
    return None, None, None, sections


def _iface_el(parent, sections, return_type):
    iface = _el(parent, "interface")
    if return_type:
        _type_el(iface, return_type)
        iface[-1].tag = f"{{{NS}}}returnType"
    for tag, _kw in (("inputVars", 0), ("outputVars", 0), ("inOutVars", 0),
                     ("externalVars", 0), ("tempVars", 0), ("localVars", 0)):
        rows = sections.get(tag)
        if not rows:
            continue
        sec = _el(iface, tag)
        if rows[0][5]:
            sec.set("constant", "true")
        for name, addr, typ, init, cm, _const in rows:
            v = _el(sec, "variable", name=name)
            if addr:
                v.set("address", addr)
            _type_el(v, typ)
            if init:
                iv = _el(v, "initialValue")
                _el(iv, "simpleValue", value=init)
            if cm:
                _el(v, "documentation").text = cm
    return iface


# Роль функции неявного контроля. В PLCopenXML CODESYS пишет КАНОНИЧЕСКОЕ имя роли,
# которое не совпадает с именем POU (`CheckDivDInt` → `CheckDivInt32`) — проверено на
# боевых экспортах. В .export понятия «регистрация» нет вовсе: функция активна тем, что
# названа так, как её ищет рантайм. Поэтому роль выставляем по имени.
_CHECK_ROLE = {
    "checkbounds": "CheckBounds", "checkpointer": "CheckPointer",
    "checkdivdint": "CheckDivInt32", "checkdivlint": "CheckDivInt64",
    "checkdivreal": "CheckDivReal32", "checkdivlreal": "CheckDivReal64",
    "checkdivint32": "CheckDivInt32", "checkdivint64": "CheckDivInt64",
    "checkdivreal32": "CheckDivReal32", "checkdivreal64": "CheckDivReal64",
    "checkrangesigned": "CheckRangeSigned", "checkrangeunsigned": "CheckRangeUnsigned",
    "checklrangesigned": "CheckLRangeSigned", "checklrangeunsigned": "CheckLRangeUnsigned",
}
_CHECK_NAME = re.compile(r"^Check(?:Bounds|Div|Range|LRange|Pointer)", re.I)


def to_plcopen(export, name="project"):
    """Дерево в форме PLCopenXML из экспорта: POU с интерфейсами и списки глобалов.

    Что НЕ переносится и почему:
      * экраны и шаблоны визуализации — у них есть только объявления интерфейса, тела нет;
        как POU они дали бы ложный «мёртвый код» на каждом экране;
      * типы (STRUCT/ENUM) — ни одно правило движка не читает dataType;
      * конфигурация задач — в экспорте она устроена иначе, чем в PLCopenXML, поэтому
        правила про сторожевой таймер и дубли Modbus-адресов на .export молчат. Это видно
        в отчёте: раздел устройств заполняется из дерева экспорта отдельно.
    """
    root = ET.Element(f"{{{NS}}}project")
    fh = _el(root, "fileHeader")
    fh.set("companyName", "")
    fh.set("productName", "CODESYS ExportFile")
    fh.set("productVersion", "")
    ch = _el(root, "contentHeader", name=name)
    types = _el(root, "types")
    _el(types, "dataTypes")
    pous = _el(types, "pous")

    by_guid = {c.guid: c for c in export.code if c.guid}
    children = {}
    for c in export.code:
        if c.kind in ("action", "method") and c.parent in by_guid:
            children.setdefault(c.parent, []).append(c)

    for c in export.code:
        if c.kind not in ("program", "functionBlock", "function"):
            continue
        pou = _el(pous, "pou", name=c.decl_name or c.name, pouType=c.kind)
        _iface_el(pou, c.sections, c.return_type)
        pname = pou.get("name")
        if _CHECK_NAME.match(pname or ""):
            ad = _el(pou, "addData")
            data = _el(ad, "data", name="check-function")
            data.set("handleUnknown", "implementation")
            _el(data, "CheckFunction").text = _CHECK_ROLE.get((pname or "").lower(), pname)
        body = _el(pou, "body")
        st = _el(body, "ST")
        xh = ET.SubElement(st, "{http://www.w3.org/1999/xhtml}xhtml")
        xh.text = c.body
        for kid in children.get(c.guid, []):
            tag = "action" if kid.kind == "action" else "method"
            sub = _el(pou, tag, name=(kid.decl_name or kid.name).split(".")[-1])
            if tag == "method":
                _iface_el(sub, kid.sections, kid.return_type)
            kb = _el(sub, "body")
            kst = _el(kb, "ST")
            kxh = ET.SubElement(kst, "{http://www.w3.org/1999/xhtml}xhtml")
            kxh.text = kid.body

    inst = _el(root, "instances")
    _el(inst, "configurations")

    # Глобалы кладём В addData, а не в интерфейс POU: engine.globals_of() намеренно
    # пропускает globalVars внутри interface (там это VAR_EXTERNAL, а не объявление).
    gl = [c for c in export.code if c.kind == "globals"]
    if gl:
        ad = _el(root, "addData")
        data = _el(ad, "data", name="globalVars")
        data.set("handleUnknown", "implementation")
        for c in gl:
            gv = _el(data, "globalVars", name=c.name or "GVL")
            for rows in c.sections.values():
                for vname, addr, typ, init, cm, _const in rows:
                    v = _el(gv, "variable", name=vname)
                    if addr:
                        v.set("address", addr)
                    _type_el(v, typ)
                    if init:
                        iv = _el(v, "initialValue")
                        _el(iv, "simpleValue", value=init)
                    if cm:
                        _el(v, "documentation").text = cm
    return root

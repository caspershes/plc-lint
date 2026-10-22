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
P_VAR_ORDER = (P_VAR_OUTPUT, P_VAR_TEXT, P_TAP_VAR, P_ACTION_VAR)


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


class Export:
    def __init__(self, devices, visus):
        self.devices = devices
        self.visus = visus


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


def read(src):
    """src — путь, bytes или file-like. → Export."""
    if isinstance(src, (bytes, bytearray)):
        import io
        src = io.BytesIO(bytes(src))
    devices, visus = [], []
    meta_name, meta_type = None, None
    for _ev, el in ET.iterparse(src, events=("end",)):
        if el.tag != "Single":
            continue
        name = el.get("Name")
        if name == "MetaObject":
            meta_name = _txt(_named(el, "Name"))
            meta_type = _txt(_named(el, "TypeGuid"))
            el.clear()
            continue
        if name != "Object":
            continue
        typ = el.get("Type", "").strip("{}")
        if typ == DEVICE_TYPE and meta_type == DEVICE_TYPE:
            devices.append(_device(meta_name, el))
        elif typ == VISU_TYPE:
            visus.append(_visu(meta_name, el))
        el.clear()                            # поддерево больше не нужно
    return Export(devices, visus)


def looks_like_export(head):
    """Первые байты файла: это ExportFile, а не PLCopenXML?"""
    if isinstance(head, (bytes, bytearray)):
        head = head[:400].decode("utf-8", "replace")
    return "<ExportFile" in (head or "")

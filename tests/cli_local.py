#!/usr/bin/env python3
"""
Локальная версия: тот же отчёт, что в вебе, и ни одного обращения к сети.

Главное обещание CLI — «файл не покидает компьютер». Оно продаёт продукт там, где
веб-версию не пустит политика заказчика, поэтому проверяется не глазами, а запретом:
socket подменяется на взрывающийся, и весь прогон идёт под ним. Любой сетевой вызов —
телеметрия, проверка обновлений, шрифт в отчёте — уронит тест, а не всплывёт у
инженера в корпоративном файрволе.

Второе: находки CLI и сайта должны совпадать. Разъехавшись, они превратят «тот же
движок» в неправду, а два набора правил — в два разных продукта.
"""
import io
import json
import os
import socket
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# В публичном репозитории та же фикстура лежит в examples/ рядом с разбором находок —
# ищем в обоих местах, чтобы файл работал без правок в любом из двух репозиториев.
FIXTURE = next(p for p in (os.path.join(HERE, "fixtures", "synthetic_bugs.xml"),
                           os.path.join(ROOT, "examples", "synthetic_bugs.xml"))
               if os.path.exists(p))
sys.path.insert(0, ROOT)

fail = 0


def check(cond, msg):
    global fail
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        fail += 1


print("1. прогон под запретом сети")


class _NoNetwork(socket.socket):
    def __init__(self, *a, **kw):
        raise AssertionError("CLI попытался открыть сокет — обещание «файл никуда не уходит» нарушено")


_real_socket, _real_create = socket.socket, socket.create_connection
socket.socket = _NoNetwork
socket.create_connection = lambda *a, **kw: (_ for _ in ()).throw(
    AssertionError("CLI попытался установить соединение"))
try:
    import cli  # импорт тоже под запретом: модуль не должен ничего дёргать на старте

    with open(FIXTURE, "rb") as fh:
        data = fh.read()
    out = io.StringIO()
    _stdout, sys.stdout = sys.stdout, out
    try:
        with tempfile.TemporaryDirectory() as tmp:
            xml = os.path.join(tmp, "client_project.xml")
            with open(xml, "wb") as fh:
                fh.write(data)
            code = cli.main([xml, "--lang", "ru", "--no-color"])
            html_path = os.path.join(tmp, "client_project-report.html")
            html_exists = os.path.exists(html_path)
            html_text = open(html_path, encoding="utf-8").read() if html_exists else ""
    finally:
        sys.stdout = _stdout
    check(True, "прогон завершился, сеть не тронута")
except AssertionError as e:
    check(False, str(e))
finally:
    socket.socket, socket.create_connection = _real_socket, _real_create

console = out.getvalue()
check(code == 0, f"код возврата без --fail-on: {code}")
check(html_exists, "HTML-отчёт сохранён рядом с файлом")

print("2. отчёт автономен — открывается без интернета")
for bad in ("http://", "https://cdn", "//fonts", "src=\"http"):
    check(bad not in html_text.replace('href="https://plc-linter', ""),
          f"нет внешней загрузки: {bad!r}")
check("<style>" in html_text, "стили встроены в файл")

print("3. находки совпадают с движком сайта")
import engine  # noqa: E402

report = engine.analyze(data, lang="ru")
check(f"{engine.quality_score(report)}" in html_text, "оценка в отчёте та же, что у движка")
for f in report.findings[:6]:
    check(f.title in html_text, f"находка в отчёте: {f.title[:44]}")

print("4. машинный вывод для CI")
res = subprocess.run([sys.executable, os.path.join(ROOT, "cli.py"), FIXTURE, "--json", "--no-html"],
                     capture_output=True, text=True, timeout=120)
check(res.returncode == 0, f"код возврата: {res.returncode}")
try:
    payload = json.loads(res.stdout)
    check(isinstance(payload, list) and payload, "JSON разобран")
    item = payload[0]
    check(item["summary"]["high"] == report.summary["high"],
          f"высоких находок столько же: {item['summary']['high']}")
    # в машинный вывод не должен просачиваться код клиента — только имена и места
    check(all("code" not in f for f in item["findings"]), "в JSON нет исходных строк кода")
except json.JSONDecodeError as e:
    check(False, f"JSON не разобран: {e}")

print("5. --fail-on для сборочной линии")
res = subprocess.run([sys.executable, os.path.join(ROOT, "cli.py"), FIXTURE,
                      "--fail-on", "high", "--no-html", "-q"], capture_output=True, text=True, timeout=120)
check(res.returncode == 1, f"есть высокие → код 1 (получено {res.returncode})")

print("6. посторонний XML не выдаётся за проект")
with tempfile.TemporaryDirectory() as tmp:
    junk = os.path.join(tmp, "notes.xml")
    with open(junk, "w", encoding="utf-8") as fh:
        fh.write("<?xml version='1.0'?><svg><rect/></svg>")
    res = subprocess.run([sys.executable, os.path.join(ROOT, "cli.py"), junk, "--no-html"],
                         capture_output=True, text=True, timeout=120)
    check(res.returncode == 2, f"код ошибки 2 (получено {res.returncode})")
    check("PLCopenXML" in res.stderr, "сказано, что это не экспорт PLCopenXML")

print()
print("CLI LOCAL OK" if not fail else f"CLI LOCAL: {fail} провал(ов)")
sys.exit(1 if fail else 0)

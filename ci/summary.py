#!/usr/bin/env python3
"""Превращает JSON от cli.py в то, что человек видит в интерфейсе GitHub Actions:
страницу итогов, аннотации и outputs для следующих шагов.

Отдельным файлом, а не строчками внутри action.yml: YAML с вложенным Python не
читается и не проверяется, а здесь то же самое запускается локально одной командой.

Наружу ничего не уходит: скрипт читает файл и пишет в файлы, пути к которым дал
сам раннер. Имена проектов и POU попадают в лог сборки заказчика — то есть в его
собственный репозиторий, и никуда больше.
"""
import json
import os
import sys

SEV = ("high", "medium", "low")
MARK = {"high": "🔴", "medium": "🟡", "low": "⚪"}
# GitHub показывает не больше 10 аннотаций одного уровня на шаг — остальные молча теряются
MAX_ANNOTATIONS = 10


def esc(text):
    """Экранирование для команд workflow: перевод строки убивает команду целиком."""
    return (str(text).replace("%", "%25").replace("\r", "%0D")
            .replace("\n", "%0A").replace("::", ":"))


def write(path_env, text):
    path = os.environ.get(path_env)
    if not path:
        return False
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)
    return True


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    if not args:
        print("usage: summary.py <report.json> [--no-summary] [--no-annotations]", file=sys.stderr)
        return 2

    try:
        with open(args[0], encoding="utf-8") as fh:
            reports = json.load(fh)
    except (OSError, ValueError):
        reports = []

    totals = {s: 0 for s in SEV}
    for r in reports:
        for s in SEV:
            totals[s] += r["summary"].get(s, 0)
    score = min((r["score"] for r in reports), default=0)

    write("GITHUB_OUTPUT", "".join(
        f"{k}={v}\n" for k, v in (
            ("score", score), ("high", totals["high"]), ("medium", totals["medium"]),
            ("low", totals["low"]), ("files", len(reports)), ("json", args[0]))))

    if not reports:
        # Самая частая причина: path указывает туда, где нет экспортов PLCopenXML
        msg = ("No PLCopenXML exports were analyzed. Check the `path` input — it should "
               "point at your export files or a directory containing them.")
        print(msg)
        if "--no-summary" not in flags:
            write("GITHUB_STEP_SUMMARY", f"## PLC Lint\n\n{msg}\n")
        return 0

    lines = ["## PLC Lint", "",
             f"**{len(reports)}** export(s) analyzed · lowest score **{score}/100** · "
             f"{totals['high']} high · {totals['medium']} medium · {totals['low']} low", "",
             "| Export | Project | POUs | Score | 🔴 | 🟡 | ⚪ |",
             "|---|---|---:|---:|---:|---:|---:|"]
    for r in reports:
        s = r["summary"]
        lines.append(f"| `{r['file']}` | {r['project']} | {r['pou_count']} | {r['score']}/100 "
                     f"| {s.get('high', 0)} | {s.get('medium', 0)} | {s.get('low', 0)} |")

    shown = {"high": 0, "medium": 0}
    lines += ["", "### Findings", ""]
    for r in reports:
        for f in r["findings"]:
            where = f"{f['pou']}:{f['line']}" if f.get("line") else (f.get("pou") or r["file"])
            lines.append(f"- {MARK.get(f['severity'], '·')} **{f['title']}** — `{where}` "
                         f"<br>{f['detail']}")
            print(f"{f['severity']:>6}  {where:<40} {f['title']}")

            sev = f["severity"]
            if ("--no-annotations" not in flags and sev in shown
                    and shown[sev] < MAX_ANNOTATIONS):
                shown[sev] += 1
                kind = "error" if sev == "high" else "warning"
                # Без file=: line у находки — строка внутри ST-кода POU, а не строка
                # в XML-файле, и привязка к файлу указывала бы не туда.
                print(f"::{kind} title=PLC Lint::{esc(r['file'])} — {esc(where)} — "
                      f"{esc(f['title'])}: {esc(f['detail'])}")

    if "--no-summary" not in flags:
        if not write("GITHUB_STEP_SUMMARY", "\n".join(lines) + "\n"):
            print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

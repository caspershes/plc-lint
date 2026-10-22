#!/usr/bin/env python3
"""
PLC Lint — локальная проверка экспорта PLCopenXML. Файл никуда не отправляется.

Зачем отдельная от сайта версия. Экспорт проекта — интеллектуальная собственность
заказчика, и решение «отправить его на чужой сервер» у инженера обычно не личное:
это политика компании или прямой пункт NDA. Никакое обещание на сайте этого не
снимает, потому что обещание нельзя проверить, а отсутствие сети — можно. Здесь
нет ни одного сетевого вызова: ни телеметрии, ни проверки обновлений, ни загрузки
шрифтов в отчёт. Отчёт получается ровно тот же, что и в вебе, — движок общий.

Зависимостей нет, только стандартная библиотека: файл работает на любом Python 3.9+
и собирается в один .exe для Windows (см. .github/workflows/windows-build.yml).

Примеры:
    plc-lint project.xml                  отчёт в консоль + HTML рядом с файлом
    plc-lint *.xml --no-html              только консоль, пакетом
    plc-lint p.xml --json > report.json   машинный вывод для CI
    plc-lint p.xml --fail-on high         код возврата 1, если есть высокие
    plc-lint p.xml --profile heating      отраслевой профиль (heating, plcopen-naming)

В Windows файл можно просто перетащить мышью на plc-lint.exe — отчёт откроется
в браузере, окно консоли дождётся Enter.
"""
import argparse
import glob
import html
import json
import os
import string
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import engine  # noqa: E402
import export_file  # noqa: E402
import i18n  # noqa: E402

VERSION = "1.0"
PROFILES = ("plcopen-naming", "heating")
SEV_ORDER = ("high", "medium", "low")
EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


# ---------- консоль ----------

def _enable_ansi():
    """Windows 10+ понимает ANSI-цвета только после явного включения VT-режима.
    Без этого в cmd.exe в отчёт сыплются «краказябры» вида ←[31m."""
    if sys.platform != "win32":
        return sys.stdout.isatty()
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k.SetConsoleMode(h, mode.value | 0x0004))
    except Exception:
        return False


def _fix_console_encoding():
    """Русская Windows даёт консоли cp866/cp1251, и заголовки находок падают с
    UnicodeEncodeError ещё до того, как инженер увидит первую строку отчёта."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


COLOR = False
_C = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m",
      "ok": "\033[92m", "dim": "\033[90m", "b": "\033[1m", "off": "\033[0m"}


def c(text, key):
    return f"{_C[key]}{text}{_C['off']}" if COLOR and key in _C else text


def _fix_steps(rule_fix, rule_help, rule):
    """RULE_FIX хранит список шагов, RULE_HELP — одну строку. Возвращаем список
    в обоих случаях, чтобы шаблон не разбирался в типах."""
    val = rule_fix.get(rule) or rule_help.get(rule) or []
    return [val] if isinstance(val, str) else list(val)


# ---------- HTML ----------

_HTML = string.Template("""<!doctype html>
<html lang="$lang"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
 :root { --bg:#0d1117; --panel:#161b22; --panel2:#1c2333; --border:#30363d; --text:#e6edf3;
         --muted:#8b949e; --accent:#4a9eff; --high:#f85149; --medium:#d29922; --low:#58a6ff; --ok:#3fb950; }
 * { box-sizing:border-box; }
 body { margin:0; background:var(--bg); color:var(--text); font:15px/1.55 -apple-system,
        "Segoe UI", Roboto, Arial, sans-serif; }
 .wrap { max-width:960px; margin:0 auto; padding:32px 20px 80px; }
 h1 { font-size:24px; margin:0 0 6px; }
 .meta { color:var(--muted); font-size:13px; margin-bottom:22px; }
 .meta code { background:var(--panel2); padding:1px 6px; border-radius:4px; }
 .claim { display:flex; gap:16px; align-items:center; background:var(--panel);
          border:1px solid var(--border); border-radius:10px; padding:16px 18px; margin-bottom:24px; }
 .score { flex:0 0 60px; width:60px; height:60px; border-radius:50%; border:3px solid;
          display:flex; align-items:center; justify-content:center; font-size:21px; font-weight:700; }
 .score.good { color:var(--ok); border-color:var(--ok); }
 .score.mid { color:var(--medium); border-color:var(--medium); }
 .score.bad { color:var(--high); border-color:var(--high); }
 .privacy { background:rgba(63,185,80,.08); border:1px solid var(--ok); border-radius:8px;
            padding:11px 14px; margin-bottom:22px; font-size:13.5px; }
 h2 { font-size:14px; text-transform:uppercase; letter-spacing:.4px; color:var(--muted);
      margin:30px 0 12px; padding-left:9px; border-left:3px solid var(--low); }
 h2.high { border-left-color:var(--high); } h2.medium { border-left-color:var(--medium); }
 .f { background:var(--panel); border:1px solid var(--border); border-left:3px solid var(--low);
      border-radius:0 8px 8px 0; padding:13px 16px; margin-bottom:10px; }
 .f.high { border-left-color:var(--high); } .f.medium { border-left-color:var(--medium); }
 .f .t { font-weight:600; }
 .f .w { color:var(--muted); font-size:13px; margin-top:3px; }
 .f .d { margin-top:7px; font-size:14px; }
 .f pre { background:var(--panel2); border-radius:6px; padding:9px 12px; margin:9px 0 0;
          overflow-x:auto; font:13px/1.5 "JetBrains Mono", Consolas, monospace; color:#c9d1d9; }
 .f .fix { margin-top:8px; font-size:13.5px; color:var(--muted); }
 .f .fix b { color:var(--text); }
 .none { background:var(--panel); border:1px solid var(--ok); border-radius:10px;
         padding:22px; text-align:center; }
 .foot { margin-top:44px; border-top:1px solid var(--border); padding-top:16px;
         color:var(--muted); font-size:13px; }
 a { color:var(--accent); }
</style></head><body><div class="wrap">
<h1>$h1</h1>
<div class="meta"><code>$filename</code> · $meta</div>
<div class="privacy">🔒 $privacy</div>
<div class="claim"><div class="score $scls">$score</div><div><b>$score_head</b><br>
 <span class="meta">$score_sub</span></div></div>
$body
<div class="foot">$foot</div>
</div></body></html>""")


def render_html(report, filename, lang):
    esc = html.escape
    score = engine.quality_score(report)
    sev_label = i18n.severity_label(lang)
    rule_help, rule_fix = i18n.rule_help(lang), i18n.rule_fix(lang)
    groups = {s: [f for f in report.findings if f.severity == s] for s in SEV_ORDER}

    parts = []
    if not report.findings:
        parts.append('<div class="none"><b>' + esc(i18n.t("report.none_big", lang)) + "</b><br>"
                     + '<span class="meta">' + esc(i18n.t("report.none_sub", lang)) + "</span></div>")
    for sev in SEV_ORDER:
        if not groups[sev]:
            continue
        parts.append(f'<h2 class="{sev}">{esc(sev_label.get(sev, sev))} — {len(groups[sev])}</h2>')
        for f in groups[sev]:
            where = esc(f.pou or "")
            if f.line:
                where += f":{f.line}"
            block = [f'<div class="f {sev}"><div class="t">{esc(f.title)}</div>',
                     f'<div class="w">{where}</div>']
            if f.detail:
                block.append(f'<div class="d">{esc(f.detail)}</div>')
            if f.code:
                block.append(f"<pre>{esc(f.code)}</pre>")
            for step in _fix_steps(rule_fix, rule_help, f.rule):
                block.append(f'<div class="fix"><b>→</b> {esc(step)}</div>')
            block.append("</div>")
            parts.append("".join(block))

    s = report.summary
    meta = (f"{i18n.t('report.meta_pou', lang)}: {report.pou_count} · "
            f"{i18n.t('report.meta_globals', lang)}: {report.globals_count} · "
            f"{sev_label.get('high', 'high')} {s['high']} · "
            f"{sev_label.get('medium', 'medium')} {s['medium']} · "
            f"{sev_label.get('low', 'low')} {s['low']}")
    txt = {
        "ru": ("Отчёт PLC Lint", "Отчёт по проекту",
               "Проверено локально: файл не покидал этот компьютер, отчёт собран на нём же.",
               "Оценка", "Ориентир, а не приговор: смотрите находки, а не цифру.",
               f"PLC Lint {VERSION} · локальная версия · правил в наборе: {len(engine.RULES)} · "
               'подробности о правилах — <a href="https://plc-linter.ru/rules">plc-linter.ru/rules</a>'),
        "en": ("PLC Lint report", "Project report",
               "Checked locally: the file never left this computer, and neither did this report.",
               "Score", "A hint, not a verdict: read the findings, not the number.",
               f"PLC Lint {VERSION} · local build · rules: {len(engine.RULES)} · "
               'rule reference — <a href="https://plc-linter.com/rules">plc-linter.com/rules</a>'),
    }[lang if lang in ("ru", "en") else "ru"]

    return _HTML.substitute(
        lang=lang, title=f"{txt[0]} — {esc(report.name)}", h1=f"{txt[1]}: {esc(report.name)}",
        filename=esc(os.path.basename(filename)), meta=esc(meta), privacy=esc(txt[2]),
        score=score, scls="good" if score >= 85 else ("mid" if score >= 60 else "bad"),
        score_head=f"{txt[3]}: {score}/100", score_sub=esc(txt[4]),
        body="\n".join(parts), foot=txt[5])


# ---------- вывод в консоль ----------

def print_report(report, path, lang, quiet=False):
    sev_label = i18n.severity_label(lang)
    rule_fix = i18n.rule_fix(lang)
    s = report.summary
    score = engine.quality_score(report)

    print()
    print(c(f"  {report.name}", "b") + c(f"   ({os.path.basename(path)})", "dim"))
    print(c(f"  {'─' * 66}", "dim"))
    tone = "ok" if score >= 85 else ("medium" if score >= 60 else "high")
    line = (f"  {c(str(score) + '/100', tone)}   "
            f"{c(str(s['high']), 'high')} · {c(str(s['medium']), 'medium')} · {c(str(s['low']), 'low')}"
            # у .export POU не читаются — показываем то, что реально разобрано
            f"   {c(('POU ' + str(report.pou_count)) if report.pou_count else i18n.term(lang, 'scope.units', n=report.units), 'dim')}")
    print(line)
    print()

    if not report.findings:
        print("  " + c(i18n.t("report.none_big", lang), "ok"))
        return

    for sev in SEV_ORDER:
        group = [f for f in report.findings if f.severity == sev]
        if not group:
            continue
        print(c(f"  {sev_label.get(sev, sev).upper()} ({len(group)})", sev))
        for f in group:
            where = f.pou or ""
            if f.line:
                where += f":{f.line}"
            print(f"    • {f.title}" + (c(f"  [{where}]", "dim") if where else ""))
            if not quiet:
                if f.detail:
                    print(f"      {c(f.detail, 'dim')}")
                if f.code:
                    print(f"      {c(f.code.strip()[:110], 'dim')}")
                for step in _fix_steps(rule_fix, {}, f.rule)[:1]:  # в консоли — первый шаг
                    print(f"      {c('→ ' + step, 'dim')}")
        print()


# ---------- сборка ----------

def expand(paths):
    """Разворачивает каталоги и маски. cmd.exe не раскрывает *.xml сам — это делает
    программа, иначе пакетный вызов в Windows молча проверяет один файл с именем «*.xml»."""
    out = []
    for p in paths:
        if os.path.isdir(p):
            for pat in ("*.xml", "*.export"):
                out.extend(sorted(glob.glob(os.path.join(p, "**", pat), recursive=True)))
        elif any(ch in p for ch in "*?["):
            out.extend(sorted(glob.glob(p, recursive=True)))
        else:
            out.append(p)
    return out


def main(argv=None):
    global COLOR
    _fix_console_encoding()
    argv = list(sys.argv[1:] if argv is None else argv)
    dragged = sys.platform == "win32" and len(argv) == 1 and not argv[0].startswith("-")

    ap = argparse.ArgumentParser(
        prog="plc-lint", description="Локальная проверка экспорта PLCopenXML или CODESYS .export. "
                                     "Файл никуда не отправляется — программа не выходит в сеть.")
    ap.add_argument("files", nargs="*", help="файлы .xml/.export, маски или каталоги")
    ap.add_argument("--lang", choices=("ru", "en"), default=None, help="язык отчёта")
    ap.add_argument("--profile", action="append", choices=PROFILES, default=[],
                    help="дополнительный профиль правил (можно повторять)")
    ap.add_argument("--html", metavar="PATH", help="куда сохранить HTML (по умолчанию рядом с файлом)")
    ap.add_argument("--no-html", action="store_true", help="не сохранять HTML")
    ap.add_argument("--open", dest="open_", action="store_true", help="открыть HTML в браузере")
    ap.add_argument("--json", action="store_true", help="машинный вывод в stdout")
    ap.add_argument("--fail-on", choices=("high", "medium", "low", "none"), default="none",
                    help="вернуть код 1, если есть находки такого уровня и выше (для CI)")
    ap.add_argument("--quiet", "-q", action="store_true", help="только заголовки находок")
    ap.add_argument("--no-color", action="store_true", help="без ANSI-цветов")
    ap.add_argument("--version", action="version", version=f"PLC Lint {VERSION} (локальная версия)")
    args = ap.parse_args(argv)

    if not args.files:
        ap.print_help()
        return EXIT_ERROR

    lang = args.lang or ("ru" if (os.environ.get("LANG", "") + os.environ.get("LANGUAGE", "")).lower().startswith("ru")
                         or sys.platform == "win32" and _win_is_russian() else "en")
    COLOR = not args.no_color and not args.json and _enable_ansi()

    files = expand(args.files)
    if not files:
        print("нет файлов для проверки", file=sys.stderr)
        return EXIT_ERROR

    results, worst, failed = [], "none", False
    for path in files:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            # .export — другой формат (дерево устройств и экраны), и у него свои правила.
            # Опознаём по содержимому, а не по расширению: экспорт сохраняют и как .xml.
            if export_file.looks_like_export(data[:400]):
                report = engine.analyze_export(path, profiles=args.profile, lang=lang)
            else:
                report = engine.analyze(data, profiles=args.profile, lang=lang)
        except FileNotFoundError:
            print(f"не найден: {path}", file=sys.stderr)
            failed = True
            continue
        except engine.NotPlcOpenError as e:
            print(f"{os.path.basename(path)}: это не экспорт PLCopenXML ({e})", file=sys.stderr)
            failed = True
            continue
        except Exception as e:  # битый XML и прочее — не роняем пакетный прогон
            print(f"{os.path.basename(path)}: не удалось разобрать — {e}", file=sys.stderr)
            failed = True
            continue

        results.append((path, report))
        for sev in SEV_ORDER:
            if report.summary[sev] and SEV_ORDER.index(sev) < (SEV_ORDER.index(worst) if worst in SEV_ORDER else 99):
                worst = sev

        if not args.json:
            print_report(report, path, lang, quiet=args.quiet)

        if not args.no_html:
            dst = args.html if (args.html and len(files) == 1) else \
                os.path.splitext(path)[0] + "-report.html"
            try:
                with open(dst, "w", encoding="utf-8") as fh:
                    fh.write(render_html(report, path, lang))
                if not args.json:
                    print(c(f"  HTML: {dst}", "dim"))
                if args.open_ or dragged:
                    webbrowser.open("file://" + os.path.abspath(dst))
            except OSError as e:
                print(f"не удалось записать HTML: {e}", file=sys.stderr)

    if args.json:
        print(json.dumps([{
            "file": os.path.basename(p),
            "project": r.name,
            "score": engine.quality_score(r),
            "pou_count": r.pou_count,
            "summary": r.summary,
            "rule_counts": engine.rule_counts(r),
            "findings": [{"rule": f.rule, "severity": f.severity, "title": f.title,
                          "pou": f.pou, "line": f.line, "detail": f.detail}
                         for f in r.findings],
        } for p, r in results], ensure_ascii=False, indent=2))

    if dragged:
        try:
            input("\n  Enter — закрыть окно… ")
        except (EOFError, KeyboardInterrupt):
            pass

    if failed and not results:
        return EXIT_ERROR
    if args.fail_on != "none" and worst in SEV_ORDER:
        if SEV_ORDER.index(worst) <= SEV_ORDER.index(args.fail_on):
            return EXIT_FINDINGS
    return EXIT_OK


def _win_is_russian():
    """Язык интерфейса Windows — чтобы по умолчанию говорить с инженером на его языке."""
    try:
        import ctypes
        return (ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF) == 0x19
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main())

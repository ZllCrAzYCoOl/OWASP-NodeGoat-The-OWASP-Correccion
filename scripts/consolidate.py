#!/usr/bin/env python3
"""Consolida los reportes JSON de las herramientas, homologa severidades (Tabla 1 del informe),
cuenta cada hallazgo una sola vez y calcula el porcentaje de mitigación.

Uso:
  python3 scripts/consolidate.py --dir reports/baseline                 # resumen de una ejecución
  python3 scripts/consolidate.py --dir reports/ci --gate                # falla (exit 1) si hay críticos
  python3 scripts/consolidate.py --compare reports/baseline reports/after   # Tablas 3 y 4 + % de mitigación

Falsos positivos: lista en evidencias/falsos_positivos.json con el formato
  [{"id": "<valor de la columna id de hallazgos.csv>", "justificacion": "..."}]
"""
import argparse, csv, json, os, re, sys
from collections import defaultdict

LEVELS = ["Crítica", "Alta", "Media", "Baja"]
RANK = {l: i for i, l in enumerate(LEVELS)}           # menor = más grave
CLOUD_RE = re.compile(r"(aws|gcp|gcs|google|azure|alibaba|digitalocean|heroku|ibm|oracle)", re.I)
CODE_TOOLS = ["semgrep", "dependency-check", "gitleaks"]
INFRA_TOOLS = ["hadolint", "trivy-image", "trivy-config", "zap"]
REQUIRED_REPORTS = ["semgrep.json", "dependency-check-report.json", "hadolint.json",
                    "trivy-image.json", "trivy-config.json", "zap.json"]


def load(path):
    if not os.path.exists(path):
        print(f"[AVISO] No existe {path}", file=sys.stderr)
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[AVISO] JSON inválido en {path}: {e}", file=sys.stderr)
        return None


def cvss_level(score):
    if score is None:
        return None
    s = float(score)
    if s >= 9.0: return "Crítica"
    if s >= 7.0: return "Alta"
    if s >= 4.0: return "Media"
    if s > 0.0:  return "Baja"
    return None


def F(tool, level, key, rule, loc, desc=""):
    return {"tool": tool, "level": level, "key": key, "rule": rule, "loc": loc, "desc": desc[:160]}


def parse_semgrep(d):
    m = {"ERROR": "Alta", "WARNING": "Media", "INFO": "Baja"}
    out = []
    for r in (d or {}).get("results", []):
        sev = r.get("extra", {}).get("severity", "")
        cwe = r.get("extra", {}).get("metadata", {}).get("cwe", "")
        cwe = ", ".join(cwe) if isinstance(cwe, list) else str(cwe)
        loc = f'{r.get("path")}:{r.get("start", {}).get("line")}'
        out.append(F("semgrep", m.get(sev), f'semgrep|{r.get("check_id")}|{loc}', r.get("check_id"), loc, cwe))
    return out


def parse_depcheck(d):
    out = []
    for dep in (d or {}).get("dependencies", []):
        for v in dep.get("vulnerabilities", []) or []:
            score = (v.get("cvssv3") or {}).get("baseScore")
            if score is None:
                score = (v.get("cvssv2") or {}).get("score")
            name = v.get("name", "?")
            out.append(F("dependency-check", cvss_level(score), f"vuln|{name}", name,
                         dep.get("fileName", ""), f"CVSS {score}"))
    return out


def parse_gitleaks(d):
    out = []
    for r in d or []:
        rule = r.get("RuleID", "?")
        level = "Crítica" if CLOUD_RE.search(rule) else "Alta"
        loc = f'{r.get("File")}:{r.get("StartLine")}'
        key = f'gitleaks|{rule}|{loc}|{(r.get("Commit") or "")[:8]}'
        out.append(F("gitleaks", level, key, rule, loc, r.get("Description", "")))
    return out


def parse_trivy(d, tool):
    m = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}   # UNKNOWN -> sin nivel
    out = []
    for res in (d or {}).get("Results", []) or []:
        tgt = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            vid = v.get("VulnerabilityID")
            out.append(F(tool, m.get(v.get("Severity")), f"vuln|{vid}", vid, f'{tgt} ({v.get("PkgName")})', v.get("Title", "")))
        for v in res.get("Misconfigurations", []) or []:
            loc = f'{tgt}:{(v.get("CauseMetadata") or {}).get("StartLine", "")}'
            out.append(F(tool, m.get(v.get("Severity")), f'misconf|{v.get("ID")}|{loc}', v.get("ID"), loc, v.get("Title", "")))
        for v in res.get("Secrets", []) or []:
            loc = f'{tgt}:{v.get("StartLine", "")}'
            out.append(F(tool, m.get(v.get("Severity")), f'secret|{v.get("RuleID")}|{loc}', v.get("RuleID"), loc, v.get("Title", "")))
    return out


def parse_hadolint(d):
    m = {"error": "Alta", "warning": "Media", "info": "Baja", "style": "Baja"}
    out = []
    for r in d or []:
        loc = f'{r.get("file")}:{r.get("line")}'
        out.append(F("hadolint", m.get(r.get("level")), f'hadolint|{r.get("code")}|{loc}', r.get("code"), loc, r.get("message", "")))
    return out


def parse_zap(d):
    m = {"3": "Alta", "2": "Media", "1": "Baja", "0": "Baja"}
    out = []
    for site in (d or {}).get("site", []) or []:
        for a in site.get("alerts", []) or []:
            pid = a.get("pluginid")
            out.append(F("zap", m.get(str(a.get("riskcode"))), f'zap|{pid}', pid, site.get("@name", ""), a.get("name", "")))
    return out


def collect(d):
    p = lambda n: os.path.join(d, n)
    items = []
    items += parse_semgrep(load(p("semgrep.json")))
    items += parse_depcheck(load(p("dependency-check-report.json")))
    items += parse_gitleaks(load(p("gitleaks.json")))
    items += parse_hadolint(load(p("hadolint.json")))
    items += parse_trivy(load(p("trivy-image.json")), "trivy-image")
    items += parse_trivy(load(p("trivy-config.json")), "trivy-config")
    items += parse_zap(load(p("zap.json")))
    return items


def load_fps(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return {x["id"]: x.get("justificacion", "") for x in json.load(f)}


def summarize(items, fps):
    active = [i for i in items if i["key"] not in fps]
    by_tool = defaultdict(lambda: defaultdict(set))
    glob = {}                                           # key -> nivel más grave (cuenta una sola vez)
    unscored = defaultdict(set)
    for i in active:
        if i["level"] is None:
            unscored[i["tool"]].add(i["key"]); continue
        by_tool[i["tool"]][i["level"]].add(i["key"])
        if i["key"] not in glob or RANK[i["level"]] < RANK[glob[i["key"]]]:
            glob[i["key"]] = i["level"]
    return {"by_tool": by_tool, "glob": glob, "unscored": unscored, "excluded": [i for i in items if i["key"] in fps]}


def n(s, tool, lvl):
    return len(s["by_tool"].get(tool, {}).get(lvl, set()))


def keys(s, tool, lvls):
    return set().union(*[s["by_tool"].get(tool, {}).get(l, set()) for l in lvls]) if lvls else set()


def glob_count(s, lvl, tools=None):
    if tools is None:
        return sum(1 for v in s["glob"].values() if v == lvl)
    ks = set()
    for t in tools:
        ks |= keys(s, t, [lvl])
    return sum(1 for k in ks if s["glob"].get(k) == lvl)


def write_outputs(d, items, s):
    with open(os.path.join(d, "hallazgos.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "herramienta", "severidad", "regla_cwe_cve", "ubicacion", "descripcion", "excluido_falso_positivo"])
        ex = {i["key"] for i in s["excluded"]}
        for i in sorted(items, key=lambda x: (RANK.get(x["level"], 9), x["tool"])):
            w.writerow([i["key"], i["tool"], i["level"] or "sin nivel", i["rule"], i["loc"], i["desc"], "sí" if i["key"] in ex else "no"])
    res = {"por_herramienta": {t: {l: n(s, t, l) for l in LEVELS} for t in s["by_tool"]},
           "sin_duplicados": {l: glob_count(s, l) for l in LEVELS},
           "sin_nivel_asignado": {t: len(v) for t, v in s["unscored"].items()},
           "falsos_positivos_excluidos": len(s["excluded"])}
    with open(os.path.join(d, "resumen.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    lines = [f"# Resumen de hallazgos ({d})", "", "| Herramienta | Crítica | Alta | Media | Baja |", "|---|---|---|---|---|"]
    for t in CODE_TOOLS + INFRA_TOOLS:
        if t in s["by_tool"] or t in s["unscored"]:
            lines.append(f"| {t} | " + " | ".join(str(n(s, t, l)) for l in LEVELS) + " |")
    lines.append("| **Todas (sin duplicados)** | " + " | ".join(str(res["sin_duplicados"][l]) for l in LEVELS) + " |")
    if res["sin_nivel_asignado"]:
        lines += ["", "Sin nivel asignado (registrar aparte, p. ej. UNKNOWN o sin CVSS): " + json.dumps(res["sin_nivel_asignado"], ensure_ascii=False)]
    lines += ["", f"Falsos positivos excluidos: {res['falsos_positivos_excluidos']}"]
    open(os.path.join(d, "resumen.md"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
    return "\n".join(lines)


def pct(base, after):
    return "N/A (línea base = 0)" if base == 0 else f"{(base - after) / base * 100:.1f} %"


def compare(bd, ad, fps):
    bs, as_ = summarize(collect(bd), fps), summarize(collect(ad), fps)
    out = ["## Tabla 3 (código y dependencias)", "",
           "| Herramienta | Severidad | Línea base | Tras las correcciones | Mitigados |", "|---|---|---|---|---|"]
    for t in CODE_TOOLS:
        for l in ["Crítica", "Alta"]:
            b, a = keys(bs, t, [l]), keys(as_, t, [l])
            out.append(f"| {t} | {l} | {len(b)} | {len(a)} | {len(b - a)} |")
    cb = glob_count(bs, "Crítica", CODE_TOOLS) + glob_count(bs, "Alta", CODE_TOOLS)
    ca = glob_count(as_, "Crítica", CODE_TOOLS) + glob_count(as_, "Alta", CODE_TOOLS)
    out.append(f"| Todas (sin duplicados) | Subtotal críticas y altas | {cb} | {ca} | {max(cb - ca, 0)} |")
    out.append(f"| Todas (sin duplicados) | **Porcentaje de mitigación** | – | – | **{pct(cb, ca)}** |")
    for l in ["Media", "Baja"]:
        out.append(f"| Todas (sin duplicados) | {l} (solo documentada) | {glob_count(bs, l, CODE_TOOLS)} | {glob_count(as_, l, CODE_TOOLS)} | No aplica |")
    nuevos = {k for k, v in as_["glob"].items() if v in ("Crítica", "Alta")} - set(bs["glob"])
    out += ["", f"Hallazgos críticos/altos NUEVOS tras las correcciones (ya incluidos en la columna final): {len(nuevos)}", ""]
    out += ["## Tabla 4 (infraestructura, críticos + altos)", "",
            "| Herramienta | Elemento | Resultado inicial | Resultado final |", "|---|---|---|---|"]
    for t, e in [("hadolint", "Dockerfile"), ("trivy-image", "Imagen"), ("trivy-config", "Configuración"), ("zap", "Aplicación en ejecución")]:
        b = len(keys(bs, t, ["Crítica", "Alta"])); a = len(keys(as_, t, ["Crítica", "Alta"]))
        out.append(f"| {t} | {e} | {b} | {a} |")
    ab = sum(1 for v in bs["glob"].values() if v in ("Crítica", "Alta"))
    aa = sum(1 for v in as_["glob"].values() if v in ("Crítica", "Alta"))
    out += ["", f"## Porcentaje de mitigación global (3 capas, sin duplicados): {pct(ab, aa)}  (base {ab} → final {aa})"]
    txt = "\n".join(out)
    open(os.path.join(ad, "comparacion.md"), "w", encoding="utf-8").write(txt + "\n")
    return txt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir")
    ap.add_argument("--compare", nargs=2, metavar=("BASE", "DESPUES"))
    ap.add_argument("--gate", action="store_true", help="exit 1 si hay hallazgos de nivel Crítica")
    ap.add_argument("--fp", default="evidencias/falsos_positivos.json")
    a = ap.parse_args()
    fps = load_fps(a.fp)
    if a.compare:
        print(compare(a.compare[0], a.compare[1], fps)); return 0
    if not a.dir:
        ap.error("indica --dir o --compare")
    items = collect(a.dir)
    s = summarize(items, fps)
    print(write_outputs(a.dir, items, s))
    if a.gate:
        # Un reporte ausente se contaría como "0 hallazgos" y daría un verde falso. gitleaks.json se
        # omite porque algunas versiones no escriben el archivo cuando no hay secretos.
        faltan = [n for n in REQUIRED_REPORTS if not os.path.exists(os.path.join(a.dir, n))]
        if faltan:
            print(f"\n[BLOQUEADO] Faltan reportes de herramientas: {', '.join(faltan)}", file=sys.stderr)
            return 1
        crit = sorted(k for k, v in s["glob"].items() if v == "Crítica")
        if crit:
            print(f"\n[BLOQUEADO] {len(crit)} hallazgo(s) crítico(s):", file=sys.stderr)
            for k in crit[:30]:
                print("  -", k, file=sys.stderr)
            return 1
        print("\n[OK] Sin hallazgos críticos.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

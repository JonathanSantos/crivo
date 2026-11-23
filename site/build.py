#!/usr/bin/env python3
"""Gera o site do GitHub Pages em _site/.

Uso: python3 site/build.py <binário crivo> [release.json]

- A demo é a saída real do crivo: cada linha de site/demo.sql passa por
  `crivo test` contra examples/vendas.crivo e testdata/schema.sql.
- A política exibida é o próprio examples/vendas.crivo.
- release.json (de `gh release view --json tagName,publishedAt`) define a
  versão impressa na página; o navegador ainda confere a última pela API do
  GitHub, então a página não fica velha entre um deploy e outro. Os links de
  download usam /releases/latest/download/, que sempre apontam para a última.
"""
import html
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "_site")
MONTHS = "jan fev mar abr mai jun jul ago set out nov dez".split()


def demo(crivo):
    cases = []
    with open(os.path.join(ROOT, "site", "demo.sql"), encoding="utf-8") as f:
        queries = [l.strip() for l in f if l.strip() and not l.lstrip().startswith("--")]
    for q in queries:
        r = subprocess.run(
            [crivo, "test", "examples/vendas.crivo", "--schema-sql", "testdata/schema.sql", q],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        )
        if r.returncode not in (0, 2):
            sys.exit(f"crivo test saiu com {r.returncode} em {q!r}:\n{r.stdout}{r.stderr}")
        cases.append({"sql": q, "exit": r.returncode, "out": (r.stdout + r.stderr).rstrip()})
    return cases


def release(path):
    if not path or not os.path.exists(path):
        return "", ""
    with open(path, encoding="utf-8") as f:
        r = json.load(f)
    tag, date = r.get("tagName", ""), r.get("publishedAt", "")[:10]
    if date:
        y, m, d = date.split("-")
        date = f"{int(d)} {MONTHS[int(m) - 1]} {y}"
    return tag, date


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    crivo = os.path.abspath(sys.argv[1])
    tag, date = release(sys.argv[2] if len(sys.argv) > 2 else "")
    repo = os.environ.get("GITHUB_REPOSITORY", "JonathanSantos/crivo")
    with open(os.path.join(ROOT, "examples", "vendas.crivo"), encoding="utf-8") as f:
        policy = f.read().rstrip()
    cases = demo(crivo)
    data = json.dumps(cases, ensure_ascii=False).replace("</", "<\\/")

    with open(os.path.join(ROOT, "site", "index.html"), encoding="utf-8") as f:
        page = f.read()
    for k, v in {
        "__REPO__": repo,
        "__TAG__": html.escape(tag or "última versão"),
        "__DATE__": html.escape(date),
        "__POLICY__": html.escape(policy),
        "__DEMO__": data,
    }.items():
        page = page.replace(k, v)

    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(os.path.join(OUT, "img"))
    with open(os.path.join(OUT, "index.html"), "w", encoding="utf-8") as f:
        f.write(page)
    for src, dst in [
        ("icons/dark/crivo-icon.svg", "img/crivo.svg"),
        ("icons/dark/crivo-32.png", "img/crivo-32.png"),
        ("icons/dark/crivo-512.png", "img/crivo-512.png"),
        ("docs/img/guard.pt.svg", "img/guard.svg"),
        ("docs/img/layers.pt.svg", "img/layers.svg"),
    ]:
        shutil.copy(os.path.join(ROOT, src), os.path.join(OUT, dst))
    open(os.path.join(OUT, ".nojekyll"), "w").close()
    print(f"_site/ gerado: {tag or 'sem release'}, {len(cases)} casos de demo")


if __name__ == "__main__":
    main()

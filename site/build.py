#!/usr/bin/env python3
"""Gera o site do GitHub Pages em _site/.

Uso: python3 site/build.py <binário crivo> [release.json]

- Duas páginas: site/index.html (português, em _site/) e site/index.en.html
  (inglês, em _site/en/). As duas usam a mesma demo e os mesmos assets.
- A demo é a saída real do crivo: cada linha de site/demo.sql passa por
  `crivo test` contra examples/vendas.crivo e testdata/schema.sql. Roda uma
  vez só; a saída do CLI é em português nas duas páginas.
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

# template, saída (relativa a _site/), meses, texto quando não há release
PAGES = [
    ("index.html", "index.html", "jan fev mar abr mai jun jul ago set out nov dez", "última versão"),
    ("index.en.html", "en/index.html", "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", "latest release"),
]

ASSETS = [
    ("icons/dark/crivo-icon.svg", "img/crivo.svg"),
    ("icons/dark/crivo-32.png", "img/crivo-32.png"),
    ("icons/dark/crivo-512.png", "img/crivo-512.png"),
    ("docs/img/guard.pt.svg", "img/guard.svg"),
    ("docs/img/layers.pt.svg", "img/layers.svg"),
    ("docs/img/guard.en.svg", "img/guard.en.svg"),
    ("docs/img/layers.en.svg", "img/layers.en.svg"),
]


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
    """Devolve (tag, (ano, mês, dia) ou None)."""
    if not path or not os.path.exists(path):
        return "", None
    with open(path, encoding="utf-8") as f:
        r = json.load(f)
    tag, date = r.get("tagName", ""), r.get("publishedAt", "")[:10]
    if not date:
        return tag, None
    y, m, d = date.split("-")
    return tag, (y, int(m), int(d))


def site_url(repo):
    owner, _, name = repo.partition("/")
    return os.environ.get("SITE_URL") or f"https://{owner.lower()}.github.io/{name}/"


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    crivo = os.path.abspath(sys.argv[1])
    tag, ymd = release(sys.argv[2] if len(sys.argv) > 2 else "")
    repo = os.environ.get("GITHUB_REPOSITORY", "JonathanSantos/crivo")
    with open(os.path.join(ROOT, "examples", "vendas.crivo"), encoding="utf-8") as f:
        policy = f.read().rstrip()
    cases = demo(crivo)
    data = json.dumps(cases, ensure_ascii=False).replace("</", "<\\/")

    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(os.path.join(OUT, "img"))
    for template, dst, months, no_tag in PAGES:
        months = months.split()
        date = f"{ymd[2]} {months[ymd[1] - 1]} {ymd[0]}" if ymd else ""
        with open(os.path.join(ROOT, "site", template), encoding="utf-8") as f:
            page = f.read()
        for k, v in {
            "__REPO__": repo,
            "__SITE__": site_url(repo),
            "__TAG__": html.escape(tag or no_tag),
            "__DATE__": html.escape(date),
            "__POLICY__": html.escape(policy),
            "__DEMO__": data,
        }.items():
            page = page.replace(k, v)
        out = os.path.join(OUT, dst)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(page)
    for src, dst in ASSETS:
        shutil.copy(os.path.join(ROOT, src), os.path.join(OUT, dst))
    open(os.path.join(OUT, ".nojekyll"), "w").close()
    print(f"_site/ gerado: {tag or 'sem release'}, {len(cases)} casos de demo, {len(PAGES)} páginas")


if __name__ == "__main__":
    main()

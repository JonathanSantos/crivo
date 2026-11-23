#!/usr/bin/env python3
"""Gera Formula/crivo.rb (Homebrew) e bucket/crivo.json (Scoop) de um release.

Uso:
    python3 scripts/packages.py <versão> <checksums.txt> [--out <raiz do repo>]

<versão> aceita "v0.1.4" ou "0.1.4". As URLs apontam para o asset versionado
(releases/download/vX.Y.Z/...), nunca para /latest. Assets ausentes no
checksums.txt (por exemplo crivo-linux-arm64 em releases antigos) são pulados:
a fórmula simplesmente não oferece aquela plataforma. Só biblioteca padrão.
"""

import argparse
import json
import re
import sys
from pathlib import Path

REPO = "JonathanSantos/crivo"
HOMEPAGE = f"https://github.com/{REPO}"
DESC = "CLI de acesso a Postgres governado por um arquivo de política"

# Lista fechada: o checksums.txt vem da rede, então só nomes conhecidos entram
# no Ruby/JSON gerado.
ASSETS = (
    "crivo-macos-arm64",
    "crivo-macos-amd64",
    "crivo-linux-arm64",
    "crivo-linux-amd64",
    "crivo-windows-amd64.exe",
)

VERSION_RE = re.compile(r"^v?(\d+\.\d+\.\d+)$")
LINE_RE = re.compile(r"^([0-9a-f]{64})\s+\*?(\S+)$")


def parse_checksums(text):
    sums = {}
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        m = LINE_RE.match(line)
        if not m:
            sys.exit(f"checksums.txt:{n}: linha inválida: {line!r}")
        digest, name = m.groups()
        if name in ASSETS:
            sums[name] = digest
    return sums


def url(tag, name):
    return f"{HOMEPAGE}/releases/download/{tag}/{name}"


def resource(tag, sums, name, indent):
    pad = " " * indent
    return f'{pad}url "{url(tag, name)}"\n{pad}sha256 "{sums[name]}"\n'


def arch_block(tag, sums, arm, intel):
    """Corpo de on_macos/on_linux: escolhe o asset pelo Hardware::CPU.arm?."""
    has_arm, has_intel = arm in sums, intel in sums
    if has_arm and has_intel:
        return (
            "    if Hardware::CPU.arm?\n"
            + resource(tag, sums, arm, 6)
            + "    else\n"
            + resource(tag, sums, intel, 6)
            + "    end\n"
        )
    if has_arm:
        return "    depends_on arch: :arm64\n\n" + resource(tag, sums, arm, 4)
    if has_intel:
        return "    depends_on arch: :x86_64\n\n" + resource(tag, sums, intel, 4)
    return ""


def formula(version, tag, sums):
    blocks = []
    for os_name, arm, intel in (
        ("macos", "crivo-macos-arm64", "crivo-macos-amd64"),
        ("linux", "crivo-linux-arm64", "crivo-linux-amd64"),
    ):
        body = arch_block(tag, sums, arm, intel)
        if body:
            blocks.append(f"  on_{os_name} do\n{body}  end\n")
    if not blocks:
        sys.exit("nenhum binário de macOS/Linux no checksums.txt")
    return (
        "# Gerado por scripts/packages.py a cada release; não edite à mão.\n"
        "class Crivo < Formula\n"
        f'  desc "{DESC}"\n'
        f'  homepage "{HOMEPAGE}"\n'
        f'  version "{version}"\n'
        "\n"
        + "\n".join(blocks)
        + "\n"
        "  def install\n"
        '    bin.install Dir["crivo-*"].first => "crivo"\n'
        "  end\n"
        "\n"
        "  test do\n"
        '    assert_match version.to_s, shell_output("#{bin}/crivo version")\n'
        "  end\n"
        "end\n"
    )


def scoop(version, tag, sums):
    exe = "crivo-windows-amd64.exe"
    if exe not in sums:
        return None
    manifest = {
        "version": version,
        "description": DESC,
        "homepage": HOMEPAGE,
        "architecture": {
            "64bit": {"url": url(tag, exe), "hash": sums[exe]},
        },
        "bin": [[exe, "crivo"]],
        "checkver": "github",
        "autoupdate": {
            "architecture": {
                "64bit": {
                    "url": f"{HOMEPAGE}/releases/download/v$version/{exe}",
                    "hash": {"url": "$baseurl/checksums.txt"},
                },
            },
        },
    }
    return json.dumps(manifest, indent=4, ensure_ascii=False) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version", help="vX.Y.Z ou X.Y.Z")
    ap.add_argument("checksums", type=Path, help="checksums.txt do release")
    ap.add_argument("--out", type=Path, default=Path("."), help="raiz do repo (padrão: .)")
    args = ap.parse_args()

    m = VERSION_RE.match(args.version)
    if not m:
        sys.exit(f"versão inválida: {args.version!r} (esperado vX.Y.Z)")
    version = m.group(1)
    tag = "v" + version

    sums = parse_checksums(args.checksums.read_text(encoding="utf-8"))
    for name in ASSETS:
        if name not in sums:
            print(f"aviso: {name} ausente em {args.checksums}; pulando", file=sys.stderr)

    out_rb = args.out / "Formula" / "crivo.rb"
    out_rb.parent.mkdir(parents=True, exist_ok=True)
    out_rb.write_text(formula(version, tag, sums), encoding="utf-8")
    print(f"escrito {out_rb}")

    manifest = scoop(version, tag, sums)
    if manifest is None:
        print("aviso: sem binário de Windows; bucket/crivo.json não foi alterado", file=sys.stderr)
    else:
        out_json = args.out / "bucket" / "crivo.json"
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(manifest, encoding="utf-8")
        print(f"escrito {out_json}")


if __name__ == "__main__":
    main()

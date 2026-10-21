#!/usr/bin/env python3
"""Gera as ilustrações do README (pt e en) com a paleta de icons/.

Uso: python3 docs/img/gen.py docs/img
"""
import sys, os
from html import escape as e

OUT = sys.argv[1]

INK = "#0D1117"     # placa
RAISE = "#151B23"   # card sobre a placa
LINE = "#39434F"    # barra barrada
MUTED = "#8A96A6"   # haste da placa
PAPER = "#F2EFE6"   # texto
SAND = "#C9C2B2"
GREEN = "#3EE08F"   # sinal: a query que atravessa
GREEN_DIM = "#1E6B47"

MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"
SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"


def svg(w, h, body, label):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{e(label)}">
<defs>
  <pattern id="dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1" fill="{LINE}" opacity="0.45"/></pattern>
  <marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M1 1 L8 5 L1 9" fill="none" stroke="{MUTED}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></marker>
  <marker id="arrg" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M1 1 L8 5 L1 9" fill="none" stroke="{GREEN}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></marker>
</defs>
<rect width="{w}" height="{h}" rx="24" fill="{INK}"/>
<rect width="{w}" height="{h}" rx="24" fill="url(#dots)"/>
{body}
</svg>
'''


def t(x, y, s, size=16, fill=PAPER, font=MONO, weight=400, anchor="start", extra=""):
    return f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}" xml:space="preserve" {extra}>{e(s)}</text>'


def icon(x, y, size):
    k = size / 64
    return f'''<g transform="translate({x} {y}) scale({k})">
  <rect width="64" height="64" rx="14" fill="{INK}" stroke="{LINE}" stroke-width="1"/>
  <rect x="29" y="10" width="6" height="16" rx="3" fill="{MUTED}"/>
  <rect x="29" y="38" width="6" height="16" rx="3" fill="{MUTED}"/>
  <rect x="10" y="15" width="15" height="6" rx="3" fill="{LINE}"/>
  <rect x="10" y="29" width="15" height="6" rx="3" fill="{LINE}"/>
  <rect x="10" y="43" width="15" height="6" rx="3" fill="{LINE}"/>
  <rect x="30" y="29" width="24" height="6" rx="3" fill="{GREEN}"/>
</g>'''


def card(x, y, w, h, stroke=LINE, fill=RAISE, rx=14, dash=""):
    d = f'stroke-dasharray="{dash}"' if dash else ""
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="1.5" {d}/>'


# --------------------------------------------------------------------------- hero
def hero(L):
    W, H = 1200, 380
    b = [icon(64, 92, 112)]
    b.append(t(200, 160, "crivo", 72, PAPER, SANS, 700, extra='letter-spacing="-1.5"'))
    b.append(t(204, 200, L["tag"], 22, SAND, SANS))
    b.append(t(204, 236, L["sub1"], 17, MUTED, SANS))
    b.append(t(204, 260, L["sub2"], 17, MUTED, SANS))
    chips = ["deny *", "fail closed", "pg_query", "READ ONLY"]
    cx = 204
    for c in chips:
        w = len(c) * 9.6 + 28
        b.append(f'<rect x="{cx}" y="296" width="{w}" height="30" rx="15" fill="none" stroke="{LINE}" stroke-width="1.5"/>')
        b.append(t(cx + w / 2, 316, c, 15, MUTED, anchor="middle"))
        cx += w + 10

    # o crivo: três queries entram, a placa barra duas, uma atravessa
    px = 975
    b.append(f'<rect x="{px}" y="52" width="20" height="112" rx="10" fill="{MUTED}"/>')
    b.append(f'<rect x="{px}" y="216" width="20" height="112" rx="10" fill="{MUTED}"/>')
    rows = [(108, "DROP TABLE pedidos", False), (190, "SELECT * FROM clientes", True), (272, "SELECT cpf FROM clientes", False)]
    for y, q, ok in rows:
        x0 = 660
        w = px - 14 - x0
        if ok:
            b.append(f'<rect x="{x0}" y="{y-21}" width="{1150-x0}" height="42" rx="21" fill="{GREEN}" opacity="0.12"/>')
            b.append(f'<rect x="{x0}" y="{y-21}" width="{1150-x0}" height="42" rx="21" fill="none" stroke="{GREEN}" stroke-width="1.5"/>')
            b.append(t(x0 + 22, y + 6, q, 17, PAPER))
            b.append(t(1128, y + 6, "exit 0", 15, GREEN, anchor="end", weight=600))
        else:
            b.append(f'<rect x="{x0}" y="{y-21}" width="{w}" height="42" rx="21" fill="{LINE}" opacity="0.55"/>')
            b.append(t(x0 + 22, y + 6, q, 17, MUTED))
            b.append(t(px + 40, y + 6, "exit 2", 15, MUTED, weight=600, extra='opacity="0.6"'))
    return svg(W, H, "\n".join(b), L["alt_hero"])


# --------------------------------------------------------------------------- fluxo
def flow(L):
    W, H = 1200, 560
    b = []
    cw, ch, gap, x0 = 252, 132, 24, 60

    def row(y, title, badge, items, last_green=False):
        b.append(t(x0, y - 22, badge, 15, GREEN, weight=600))
        b.append(t(x0 + len(badge) * 9.6 + 14, y - 22, title, 17, SAND, SANS))
        for i, (num, cmd, d1, d2) in enumerate(items):
            x = x0 + i * (cw + gap)
            green = last_green and i == len(items) - 1
            b.append(card(x, y, cw, ch, GREEN if green else LINE))
            b.append(t(x + 20, y + 32, num, 14, GREEN if green else MUTED, weight=600))
            b.append(t(x + 20, y + 64, cmd, 16, PAPER, weight=600))
            b.append(t(x + 20, y + 92, d1, 15, MUTED, SANS))
            b.append(t(x + 20, y + 113, d2, 15, MUTED, SANS))
            if i < len(items) - 1:
                ay = y + ch / 2
                b.append(f'<line x1="{x+cw+4}" y1="{ay}" x2="{x+cw+gap-4}" y2="{ay}" stroke="{MUTED}" stroke-width="1.6" marker-end="url(#arr)"/>')

    y1, y2 = 78, 360
    row(y1, L["row1"], "crivo", L["steps1"])
    row(y2, L["row2"], "./vendas", L["steps2"], last_green=True)
    # build -> binário
    xb = x0 + 3 * (cw + gap) + cw / 2
    xs = x0 + cw / 2
    yA, yB = y1 + ch, y2 - 46
    mid = (yA + yB) / 2 + 4
    b.append(f'<path d="M{xb} {yA+4} V{mid-12} Q{xb} {mid} {xb-12} {mid} H{xs+12} Q{xs} {mid} {xs} {mid+12} V{yB-4}" fill="none" stroke="{GREEN}" stroke-width="1.6" stroke-dasharray="5 5" marker-end="url(#arrg)"/>')
    b.append(f'<rect x="{(xb+xs)/2-150}" y="{mid-15}" width="300" height="30" rx="15" fill="{INK}" stroke="{GREEN_DIM}" stroke-width="1.5"/>')
    b.append(t((xb + xs) / 2, mid + 5, L["slot"], 14, GREEN, anchor="middle"))
    b.append(t(W - 60, H - 30, L["foot"], 14, MUTED, SANS, anchor="end"))
    return svg(W, H, "\n".join(b), L["alt_flow"])


# --------------------------------------------------------------------------- guard
def guard(L):
    W, H = 1200, 640
    b = []
    y = 196
    # entrada
    b.append(t(60, 70, L["g_title"], 17, SAND, SANS))
    b.append(card(60, 92, 470, 46, LINE, RAISE, 23))
    b.append(t(82, 121, 'vendas query "SELECT * FROM clientes"', 16, PAPER))
    b.append(t(548, 121, L["g_from"], 15, MUTED, SANS))
    b.append(f'<line x1="60" y1="{y}" x2="1140" y2="{y}" stroke="{LINE}" stroke-width="3" stroke-linecap="round"/>')
    b.append(f'<line x1="90" y1="140" x2="90" y2="{y-6}" stroke="{MUTED}" stroke-width="1.6" marker-end="url(#arr)"/>')

    st = L["stations"]
    n = len(st)
    xs = [150 + i * (960 / (n - 1)) for i in range(n)]
    for i, ((name, s1, s2, refuse), x) in enumerate(zip(st, xs)):
        last = i == n - 1
        col = GREEN if last else MUTED
        b.append(f'<rect x="{x-9}" y="{y-34}" width="18" height="68" rx="9" fill="{col}"/>')
        b.append(t(x, y + 66, name, 16, PAPER, weight=600, anchor="middle"))
        b.append(t(x, y + 90, s1, 14, MUTED, SANS, anchor="middle"))
        b.append(t(x, y + 110, s2, 14, MUTED, SANS, anchor="middle"))
        if refuse:
            b.append(f'<line x1="{x}" y1="{y+124}" x2="{x}" y2="380" stroke="{MUTED}" stroke-width="1.4" stroke-dasharray="3 5" opacity="0.7"/>')
    b.append(f'<line x1="{xs[0]+14}" y1="{y}" x2="{xs[-1]-16}" y2="{y}" stroke="{GREEN}" stroke-width="3" stroke-linecap="round" opacity="0.9"/>')

    rx = [x for (_, _, _, r), x in zip(st, xs) if r]
    b.append(f'<line x1="{rx[0]}" y1="380" x2="{rx[-1]}" y2="380" stroke="{MUTED}" stroke-width="1.4" stroke-dasharray="3 5" opacity="0.7"/>')
    b.append(f'<line x1="630" y1="380" x2="630" y2="430" stroke="{MUTED}" stroke-width="1.6" marker-end="url(#arr)"/>')
    b.append(f'<line x1="{xs[-1]}" y1="{y+124}" x2="{xs[-1]}" y2="430" stroke="{GREEN}" stroke-width="1.6" marker-end="url(#arrg)"/>')

    # recusa (formato real de internal/output/output_test.go)
    b.append(t(60, 420, L["g_no"], 15, SAND, weight=600))
    b.append(card(60, 436, 592, 156, LINE))
    msg = [("✗ barrado pelo crivo", PAPER), ("  regra   pedidos  read, update(status, observacao) max 20", MUTED),
           ('  motivo  coluna "total" não pode ser alterada', MUTED), ("  aceito  status, observacao", MUTED)]
    b.append(t(84, 466, 'vendas exec "UPDATE pedidos SET total = 0 WHERE id = 7"', 14, MUTED, extra='opacity="0.7"'))
    for k, (ln, c) in enumerate(msg):
        b.append(t(84, 500 + k * 22, ln, 15, c, weight=600 if k == 0 else 400))
    b.append(t(628, 580, "exit 2", 14, SAND, anchor="end", weight=600))

    # saída: SQL reescrito (internal/sqlguard/guard_test.go)
    b.append(t(680, 420, L["g_ok"], 15, GREEN, weight=600))
    b.append(card(680, 436, 460, 156, GREEN_DIM))
    lines = ["SELECT clientes.id,", "       clientes.nome,", "       clientes.email,     -- partial", "       clientes.telefone,  -- redact", "       clientes.cidade", "  FROM clientes LIMIT 501"]
    for k, ln in enumerate(lines):
        code, _, com = ln.partition("--")
        tail = f'<tspan fill="{GREEN}" fill-opacity="0.75">--{e(com)}</tspan>' if com else ""
        b.append(f'<text x="704" y="{466 + k * 21}" font-family="{MONO}" font-size="15" fill="{PAPER}" xml:space="preserve">{e(code)}{tail}</text>')
    b.append(t(W - 60, H - 22, L["g_foot"], 14, MUTED, SANS, anchor="end"))
    return svg(W, H, "\n".join(b), L["alt_guard"])


# --------------------------------------------------------------------------- camadas
def layers(L):
    W, H = 1200, 440
    b = [t(60, 70, L["l_title"], 17, SAND, SANS)]
    items = L["layers"]
    y0, rh = 100, 50
    for i, (name, desc) in enumerate(items):
        y = y0 + i * (rh + 8)
        inset = i * 26
        x = 60 + inset
        w = 640 - inset * 2
        core = i == len(items) - 1
        b.append(f'<rect x="{x}" y="{y}" width="{w}" height="{rh}" rx="{rh/2}" fill="{GREEN if core else LINE}" opacity="{1 if core else 0.35 + i*0.08}"/>')
        b.append(t(x + 24, y + 31, name, 16, INK if core else PAPER, weight=600))
        b.append(t(740, y + 31, desc, 15, MUTED, SANS))
        b.append(f'<line x1="{x+w+8}" y1="{y+rh/2}" x2="728" y2="{y+rh/2}" stroke="{LINE}" stroke-width="1.2" stroke-dasharray="2 4"/>')
    return svg(W, H, "\n".join(b), L["alt_layers"])


PT = dict(
    tag="Toda query passa pelo crivo.",
    sub1="Política declarativa → CLI local de acesso a Postgres",
    sub2="de pré-produção, com skill para o GitHub Copilot.",
    alt_hero="Crivo: três queries entram, a placa barra duas e só uma atravessa",
    row1="você escreve e compila a política", row2="a IA consulta pelo binário gerado",
    steps1=[("01", "crivo init", "gera vendas.crivo", "com tudo negado"),
            ("02", "$EDITOR vendas.crivo", "libera tabelas, colunas,", "filtros e máscaras"),
            ("03", "crivo check · test", "sintaxe, schema real,", "TLS e privilégios"),
            ("04", "crivo build", "gera ./vendas com a", "política embutida")],
    steps2=[("05", "skill install", ".github/skills/", "crivo-vendas/SKILL.md"),
            ("06", "Copilot · agent", "chama vendas query", "no terminal (ou MCP)"),
            ("07", "guard", "pg_query, política,", "reescrita, re-checagem"),
            ("08", "Postgres", "READ ONLY, timeout,", "TLS verify-full")],
    slot="política no slot de 64 KiB do binário",
    foot="crivo secret set vendas guarda a senha no keychain do SO",
    alt_flow="Fluxo do Crivo: init, editar a política, check e test, build, skill, Copilot, guard e Postgres",
    g_title="O caminho de uma query",
    g_from="← enviada pela IA",
    stations=[("parse", "pg_query:", "o parser real", True),
              ("policy", "tabelas, colunas,", "funções, deny *", True),
              ("rewrite", "* → colunas, where,", "LIMIT, max N", True),
              ("re-check", "deparse → parse:", "AST idêntico", True),
              ("execute", "READ ONLY", "statement_timeout", False),
              ("mask", "partial · redact", "· hash", False)],
    g_ok="✓ o banco recebe o deparse validado",
    g_no="✗ recusa que ensina: regra, motivo, o que seria aceito",
    g_foot="Saídas reais dos testes do guard e do output; LIMIT 501 detecta o corte no teto de 500",
    alt_guard="Pipeline do guard: parse, política, reescrita, re-checagem, execução e máscara; recusas saem com exit 2",
    l_title="Camadas: o Crivo é a segunda linha, não a única",
    layers=[("usuário de privilégio mínimo", "crivo grants gera os GRANTs a partir da política"),
            ("TLS verify-full", "o check e o binário recusam conexão sem validar o certificado"),
            ("statement_timeout", "SET LOCAL a cada execução (timeout 5s)"),
            ("transação READ ONLY", "query e explain nunca escrevem; exec tem teto max N"),
            ("AST validado + re-checado", "deny por padrão, fail closed, deparse re-parseado")],
    alt_layers="Camadas de defesa do Crivo",
)

EN = dict(
    tag="Every query goes through the sieve.",
    sub1="Declarative policy → local CLI for a pre-production",
    sub2="Postgres, plus a skill for GitHub Copilot.",
    alt_hero="Crivo: three queries come in, the plate blocks two and only one gets through",
    row1="you write and build the policy", row2="the AI queries through the generated binary",
    steps1=[("01", "crivo init", "creates vendas.crivo", "with everything denied"),
            ("02", "$EDITOR vendas.crivo", "allow tables, columns,", "filters and masks"),
            ("03", "crivo check · test", "syntax, real schema,", "TLS and privileges"),
            ("04", "crivo build", "creates ./vendas with", "the policy embedded")],
    steps2=[("05", "skill install", ".github/skills/", "crivo-vendas/SKILL.md"),
            ("06", "Copilot · agent", "runs vendas query", "in the terminal (or MCP)"),
            ("07", "guard", "pg_query, policy,", "rewrite, re-check"),
            ("08", "Postgres", "READ ONLY, timeout,", "TLS verify-full")],
    slot="policy in the binary's 64 KiB slot",
    foot="crivo secret set vendas stores the password in the OS keychain",
    alt_flow="Crivo flow: init, edit the policy, check and test, build, skill, Copilot, guard and Postgres",
    g_title="The path of a query",
    g_from="← sent by the AI",
    stations=[("parse", "pg_query:", "the real parser", True),
              ("policy", "tables, columns,", "functions, deny *", True),
              ("rewrite", "* → columns, where,", "LIMIT, max N", True),
              ("re-check", "deparse → parse:", "identical AST", True),
              ("execute", "READ ONLY", "statement_timeout", False),
              ("mask", "partial · redact", "· hash", False)],
    g_ok="✓ the database receives the validated deparse",
    g_no="✗ refusals that teach: rule, reason, what is accepted",
    g_foot="Real outputs from the guard and output tests; LIMIT 501 detects the cut at the 500 cap",
    alt_guard="Guard pipeline: parse, policy, rewrite, re-check, execute and mask; refusals exit with code 2",
    l_title="Layers: Crivo is the second line, not the only one",
    layers=[("least-privilege user", "crivo grants generates the GRANTs from the policy"),
            ("TLS verify-full", "check and the binary refuse unverified certificates"),
            ("statement_timeout", "SET LOCAL on every execution (timeout 5s)"),
            ("READ ONLY transaction", "query and explain never write; exec is capped by max N"),
            ("validated + re-checked AST", "deny by default, fail closed, deparse re-parsed")],
    alt_layers="Crivo defense layers",
)

os.makedirs(OUT, exist_ok=True)
for lang, L in (("pt", PT), ("en", EN)):
    for name, fn in (("hero", hero), ("flow", flow), ("guard", guard), ("layers", layers)):
        with open(os.path.join(OUT, f"{name}.{lang}.svg"), "w") as f:
            f.write(fn(L))
print("ok")

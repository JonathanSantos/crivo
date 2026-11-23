'use strict';

// Checagem da gramática sem npm: o JSON precisa parsear, todo regex precisa
// compilar em JS e todo #include precisa existir. Os escopos são conferidos
// por um mini-tokenizador TextMate (abaixo), não pelo vscode-textmate +
// Oniguruma do VS Code: ele cobre begin/end/match/captures/contentName, o
// suficiente para pegar erros de ordem e de região, mas não é o motor real.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const grammar = JSON.parse(fs.readFileSync(path.join(ROOT, 'syntaxes', 'crivo.tmLanguage.json'), 'utf8'));
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const vendas = fs.readFileSync(path.join(ROOT, '..', '..', 'examples', 'vendas.crivo'), 'utf8').split('\n');

function compile(src) {
  let flags = 'dgm';
  if (src.startsWith('(?i)')) {
    src = src.slice(4);
    flags += 'i';
  }
  return new RegExp(src, flags);
}

function resolve(p) {
  if (p.include) {
    assert.ok(p.include.startsWith('#'), `include não suportado: ${p.include}`);
    const r = grammar.repository[p.include.slice(1)];
    assert.ok(r, `include sem destino: ${p.include}`);
    return r;
  }
  return p;
}

// flatten expande includes e contêineres (só "patterns") na ordem.
function flatten(patterns, seen = new Set()) {
  const out = [];
  for (const raw of patterns || []) {
    const p = resolve(raw);
    if (!p.match && !p.begin) {
      if (seen.has(p)) continue;
      out.push(...flatten(p.patterns, new Set([...seen, p])));
    } else {
      out.push(p);
    }
  }
  return out;
}

function cache(p, key) {
  const k = `_re_${key}`;
  if (!p[k]) Object.defineProperty(p, k, { value: compile(p[key]), enumerable: false });
  return p[k];
}

function execAt(re, text, pos) {
  re.lastIndex = pos;
  return re.exec(text);
}

// tokenize devolve, por linha, um array de escopos por caractere.
function tokenize(lines) {
  const stack = [{ rule: grammar, scopes: ['source.crivo'] }];
  const result = [];
  for (const line of lines) {
    const text = line + '\n';
    const scopes = new Array(line.length).fill(null);
    const paint = (from, to, sc) => {
      for (let i = from; i < Math.min(to, line.length); i++) scopes[i] = sc;
    };
    const paintCaptures = (m, caps, base) => {
      if (!caps) return;
      for (const [k, c] of Object.entries(caps)) {
        const span = m.indices[Number(k)];
        if (!span) continue;
        const sc = c.name ? [...base, c.name] : base;
        paint(span[0], span[1], sc);
        for (const sub of flatten(c.patterns)) {
          const re = cache(sub, 'match');
          const part = text.slice(span[0], span[1]);
          re.lastIndex = 0;
          let mm;
          while ((mm = re.exec(part))) {
            paint(span[0] + mm.index, span[0] + mm.index + mm[0].length, [...sc, sub.name]);
            if (mm[0].length === 0) re.lastIndex++;
          }
        }
      }
    };
    let pos = 0;
    let guard = 0;
    while (pos <= line.length) {
      if (++guard > 10000) throw new Error(`laço sem avanço na linha: ${line}`);
      const top = stack[stack.length - 1];
      let best = null;
      if (top.end) {
        const m = execAt(top.end, text, pos);
        if (m) best = { kind: 'end', m };
      }
      for (const p of flatten(top.rule.patterns)) {
        const m = execAt(cache(p, p.match ? 'match' : 'begin'), text, pos);
        if (m && (!best || m.index < best.m.index)) best = { kind: p.match ? 'match' : 'begin', m, p };
      }
      if (!best || best.m.index > line.length) {
        paint(pos, line.length, top.contentScopes || top.scopes);
        break;
      }
      const { m } = best;
      const inner = top.contentScopes || top.scopes;
      paint(pos, m.index, inner);
      const endPos = m.index + m[0].length;
      if (best.kind === 'end') {
        paint(m.index, endPos, top.scopes);
        paintCaptures(m, top.rule.endCaptures, top.scopes);
        stack.pop();
      } else if (best.kind === 'match') {
        const sc = best.p.name ? [...inner, best.p.name] : inner;
        paint(m.index, endPos, sc);
        paintCaptures(m, best.p.captures, sc);
        if (m[0].length === 0) {
          pos = endPos + 1;
          continue;
        }
      } else {
        const sc = best.p.name ? [...inner, best.p.name] : inner;
        paint(m.index, endPos, sc);
        paintCaptures(m, best.p.beginCaptures, sc);
        stack.push({
          rule: best.p,
          end: compile(best.p.end),
          scopes: sc,
          contentScopes: best.p.contentName ? [...sc, best.p.contentName] : null,
        });
      }
      pos = endPos;
    }
    result.push(scopes.map((s) => s || stack[0].scopes));
  }
  return result;
}

// scope devolve os escopos do primeiro caractere da n-ésima ocorrência de word.
function scopeOf(tokens, lines, lineIdx, word, nth = 0) {
  let i = -1;
  for (let k = 0; k <= nth; k++) {
    i = lines[lineIdx].indexOf(word, i + 1);
    assert.ok(i >= 0, `"${word}" não está na linha ${lineIdx + 1}: ${lines[lineIdx]}`);
  }
  return tokens[lineIdx][i];
}

function expectScope(tokens, lines, lineIdx, word, scope, nth = 0) {
  const sc = scopeOf(tokens, lines, lineIdx, word, nth);
  assert.ok(sc.includes(scope), `"${word}" (linha ${lineIdx + 1}) esperava ${scope}, tem ${sc.join(' ')}`);
}

function expectNotScope(tokens, lines, lineIdx, word, scope, nth = 0) {
  const sc = scopeOf(tokens, lines, lineIdx, word, nth);
  assert.ok(!sc.some((s) => s.startsWith(scope)), `"${word}" (linha ${lineIdx + 1}) não devia ter ${scope}: ${sc.join(' ')}`);
}

test('package.json aponta para a gramática e a configuração de linguagem', () => {
  const g = pkg.contributes.grammars[0];
  assert.strictEqual(g.scopeName, grammar.scopeName);
  assert.ok(fs.existsSync(path.join(ROOT, g.path)));
  assert.ok(fs.existsSync(path.join(ROOT, pkg.contributes.languages[0].configuration)));
  JSON.parse(fs.readFileSync(path.join(ROOT, 'language-configuration.json'), 'utf8'));
  assert.ok(fs.existsSync(path.join(ROOT, pkg.main)));
});

test('todos os regex compilam e todos os includes existem', () => {
  let n = 0;
  const visit = (node) => {
    if (Array.isArray(node)) return node.forEach(visit);
    if (!node || typeof node !== 'object') return;
    for (const key of ['match', 'begin', 'end']) {
      if (typeof node[key] === 'string') {
        compile(node[key]);
        n++;
      }
    }
    if (node.include) resolve(node);
    for (const v of Object.values(node)) visit(v);
  };
  visit(grammar);
  assert.ok(n > 40, `poucos regex: ${n}`);
});

test('examples/vendas.crivo: escopos principais', () => {
  const t = tokenize(vendas);
  const at = (needle) => vendas.findIndex((l) => l.includes(needle));
  const L = {
    title: at('# vendas.crivo'),
    name: at('name    vendas'),
    about: at('about'),
    env: at('env     preprod'),
    connect: at('connect'),
    secret: at('secret'),
    schema: at('schema  public'),
    limit: at('limit   500'),
    timeout: at('timeout'),
    doc: at('## Pedidos'),
    pedidos: at('pedidos         read'),
    itens: at('pedido_itens    read'),
    clientes: at('clientes        read'),
    pagamentos: at('pagamentos      read'),
    audit: at('audit_*'),
  };
  for (const [k, v] of Object.entries(L)) assert.ok(v >= 0, `linha ${k} não encontrada`);

  expectScope(t, vendas, L.title, '#', 'comment.line.number-sign.crivo');
  expectScope(t, vendas, L.doc, 'Pedidos', 'comment.line.double-number-sign.documentation.crivo');
  expectNotScope(t, vendas, L.doc, 'Pedidos', 'comment.line.number-sign');

  expectScope(t, vendas, L.name, 'name', 'keyword.other.directive.crivo');
  expectScope(t, vendas, L.name, 'vendas', 'entity.name.policy.crivo');
  expectScope(t, vendas, L.about, 'Base do', 'string.quoted.double.crivo');
  expectScope(t, vendas, L.env, 'preprod', 'constant.language.env.crivo');
  expectScope(t, vendas, L.connect, 'connect', 'keyword.other.directive.crivo');
  expectScope(t, vendas, L.connect, 'postgres://', 'string.unquoted.url.connect.crivo');
  expectScope(t, vendas, L.connect, 'sslmode', 'string.unquoted.url.connect.crivo');
  expectScope(t, vendas, L.secret, 'keychain', 'support.constant.secret.crivo');
  expectScope(t, vendas, L.schema, 'public', 'entity.name.namespace.crivo');
  expectScope(t, vendas, L.limit, 'limit', 'keyword.other.directive.crivo');
  expectScope(t, vendas, L.limit, '500', 'constant.numeric.integer.crivo');
  expectScope(t, vendas, L.limit, 'rows', 'keyword.other.unit.crivo');
  expectScope(t, vendas, L.timeout, '5s', 'constant.numeric.duration.crivo');

  expectScope(t, vendas, L.pedidos, 'pedidos', 'entity.name.type.table.crivo');
  expectScope(t, vendas, L.pedidos, 'read', 'keyword.control.verb.crivo');
  expectScope(t, vendas, L.pedidos, 'update', 'keyword.control.verb.crivo');
  expectScope(t, vendas, L.pedidos, 'status', 'variable.other.column.crivo');
  expectScope(t, vendas, L.pedidos, 'observacao', 'variable.other.column.crivo');
  expectScope(t, vendas, L.pedidos, 'max', 'storage.modifier.crivo');
  expectScope(t, vendas, L.pedidos, '20', 'constant.numeric.integer.crivo');
  expectScope(t, vendas, L.itens, 'delete', 'keyword.control.verb.crivo');
  expectScope(t, vendas, L.itens, '5', 'constant.numeric.integer.crivo');

  expectScope(t, vendas, L.clientes, 'except', 'storage.modifier.except.crivo');
  expectScope(t, vendas, L.clientes, 'cpf', 'variable.other.column.crivo');
  expectScope(t, vendas, L.clientes, 'mask', 'storage.modifier.mask.crivo');
  expectScope(t, vendas, L.clientes, 'email', 'variable.other.column.crivo');
  expectScope(t, vendas, L.clientes, 'partial', 'support.constant.mask-mode.crivo');
  expectScope(t, vendas, L.clientes, 'redact', 'support.constant.mask-mode.crivo');

  expectScope(t, vendas, L.pagamentos, 'where', 'storage.modifier.where.crivo');
  expectScope(t, vendas, L.pagamentos, 'status', 'meta.embedded.expression.sql.crivo');
  expectScope(t, vendas, L.pagamentos, '<>', 'keyword.operator.sql');
  expectScope(t, vendas, L.pagamentos, "'estornado'", 'string.quoted.single.sql');

  expectScope(t, vendas, L.audit, 'audit_', 'entity.name.type.table.crivo');
  expectScope(t, vendas, L.audit, '*', 'keyword.operator.wildcard.crivo');
  expectScope(t, vendas, L.audit, 'deny', 'keyword.control.deny.crivo');
});

test('construções novas: expires, cost, rate, quota, approval, audit, query, máscaras', () => {
  const lines = [
    'expires  2026-12-31',
    'cost     5000',
    'rate     30/min',
    'quota    20000 rows/day',
    'approval writes',
    'audit    syslog',
    'query pedidos_do_cliente(cliente_id int, desde date) "SELECT id FROM pedidos WHERE cliente_id = $1 AND criado_em >= $2 AND status <> \'x\'"',
    'secret   env:PG_SENHA',
    'functions unaccent, similarity',
    'clientes read mask(salario: bucket 1000, cartao: last4, nascimento: month, email: email, nome: pseudonym, x: hash)',
  ];
  const t = tokenize(lines);
  expectScope(t, lines, 0, 'expires', 'keyword.other.directive.crivo');
  expectScope(t, lines, 0, '2026-12-31', 'constant.numeric.date.crivo');
  expectScope(t, lines, 1, '5000', 'constant.numeric.crivo');
  expectScope(t, lines, 2, '30', 'constant.numeric.integer.crivo');
  expectScope(t, lines, 2, 'min', 'keyword.other.unit.crivo');
  expectScope(t, lines, 3, '20000', 'constant.numeric.integer.crivo');
  expectScope(t, lines, 3, 'rows', 'keyword.other.unit.crivo');
  expectScope(t, lines, 3, 'day', 'keyword.other.unit.crivo');
  expectScope(t, lines, 4, 'writes', 'constant.language.approval.crivo');
  expectScope(t, lines, 5, 'syslog', 'constant.language.audit.crivo');
  expectScope(t, lines, 6, 'query', 'keyword.other.directive.crivo');
  expectScope(t, lines, 6, 'pedidos_do_cliente', 'entity.name.function.query.crivo');
  expectScope(t, lines, 6, 'cliente_id', 'variable.parameter.crivo');
  expectScope(t, lines, 6, 'int', 'storage.type.crivo');
  expectScope(t, lines, 6, 'date', 'storage.type.crivo');
  expectScope(t, lines, 6, 'SELECT', 'keyword.other.sql');
  expectScope(t, lines, 6, 'SELECT', 'string.quoted.double.crivo');
  expectScope(t, lines, 6, '$1', 'variable.parameter.positional.sql');
  expectScope(t, lines, 6, "'x'", 'string.quoted.single.sql');
  expectScope(t, lines, 7, 'env', 'support.constant.secret.crivo');
  expectScope(t, lines, 7, 'PG_SENHA', 'variable.other.env.crivo');
  expectScope(t, lines, 8, 'similarity', 'entity.name.function.crivo');
  expectScope(t, lines, 9, 'bucket', 'support.constant.mask-mode.crivo');
  expectScope(t, lines, 9, '1000', 'constant.numeric.integer.crivo');
  for (const m of ['last4', 'month', 'pseudonym', 'hash']) expectScope(t, lines, 9, m, 'support.constant.mask-mode.crivo');
  expectScope(t, lines, 9, 'email', 'variable.other.column.crivo', 0);
  expectScope(t, lines, 9, 'email', 'support.constant.mask-mode.crivo', 1);
});

test('where: vírgula aninhada, continuação, # no meio, fim na vírgula de nível zero', () => {
  const lines = [
    "pagamentos read where status in ('a,b', 'c') and f(x, y) > 0, update(obs) where id = 1",
    '    and valor > 0',
    'public.notas read where texto <> \'#nao é comentário\'',
    '  # comentário dentro da regra',
    '    , insert',
    '## doc',
    'outra read',
    'limit   10 rows',
  ];
  const t = tokenize(lines);
  expectScope(t, lines, 0, "'a,b'", 'string.quoted.single.sql');
  expectScope(t, lines, 0, 'f(', 'entity.name.function.sql');
  expectScope(t, lines, 0, 'y)', 'meta.where.crivo');
  expectScope(t, lines, 0, 'update', 'keyword.control.verb.crivo');
  expectNotScope(t, lines, 0, 'update', 'meta.where');
  expectScope(t, lines, 0, 'obs', 'variable.other.column.crivo');
  // continuação: ainda dentro do segundo where (vai até a vírgula ou o fim da regra)
  expectScope(t, lines, 1, 'valor', 'meta.where.crivo');
  expectScope(t, lines, 1, 'and', 'keyword.other.sql');
  expectScope(t, lines, 2, 'public', 'entity.name.namespace.crivo');
  expectScope(t, lines, 2, 'notas', 'entity.name.type.table.crivo');
  expectScope(t, lines, 2, '#nao', 'string.quoted.single.sql');
  expectNotScope(t, lines, 2, '#nao', 'comment');
  expectScope(t, lines, 3, 'comentário', 'comment.line.number-sign.crivo');
  expectScope(t, lines, 4, 'insert', 'keyword.control.verb.crivo');
  expectScope(t, lines, 4, 'insert', 'meta.rule.crivo');
  expectScope(t, lines, 5, 'doc', 'comment.line.double-number-sign.documentation.crivo');
  expectNotScope(t, lines, 5, 'doc', 'meta.rule');
  expectScope(t, lines, 6, 'outra', 'entity.name.type.table.crivo');
  // limit no início da linha é diretiva; dentro da regra é modificador
  expectScope(t, lines, 7, 'limit', 'keyword.other.directive.crivo');
  expectNotScope(t, lines, 7, 'limit', 'meta.rule');
});

test('nome de tabela que começa com palavra de diretiva continua tabela', () => {
  const lines = ['limits_tbl read limit 10', 'names read'];
  const t = tokenize(lines);
  expectScope(t, lines, 0, 'limits_tbl', 'entity.name.type.table.crivo');
  expectScope(t, lines, 0, 'limit 10', 'storage.modifier.crivo');
  expectScope(t, lines, 1, 'names', 'entity.name.type.table.crivo');
});

module.exports = { tokenize };

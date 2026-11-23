'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const {
  normalizeSeverity,
  parseCheckOutput,
  byteColToChar,
  toDescriptors,
  expandArgs,
  resolveCommand,
  summarize,
} = require('../diagnostics');

// Saída real de:
//   crivo check internal/cli/tool/testdata/checks.crivo --schema-sql testdata/schema.sql --json
const REAL = JSON.stringify({
  file: '/repo/internal/cli/tool/testdata/checks.crivo',
  ok: false,
  note: 'schema conferido pelo DDL /repo/testdata/schema.sql',
  diagnostics: [
    { line: 0, col: 0, severity: 'warning', message: '3 tabela(s) do banco sem regra: invisíveis para a IA (deny por padrão)' },
    { line: 5, col: 9, severity: 'warning', message: 'connect sem sslmode: aceito só porque o host localhost é local' },
    { line: 8, col: 1, severity: 'error', message: 'tabela "fantasma" não existe no banco (schema public)' },
    { line: 9, col: 23, severity: 'error', message: 'coluna "nao_existe" não existe em pedidos' },
    { line: 10, col: 27, severity: 'error', message: 'coluna mascarada "sumida" não existe em clientes' },
    { line: 11, col: 28, severity: 'error', message: 'o where cita a coluna "coluna_x", que não existe em pagamentos' },
    { line: 12, col: 17, severity: 'error', message: 'read em produtos não libera nenhuma coluna' },
    { line: 13, col: 1, severity: 'warning', message: 'o padrão tmp_* não cobre nenhuma tabela do banco' },
  ],
});

const CHECKS_SRC = [
  '# Política com problemas de propósito: cada regra quebra uma checagem contra o schema.',
  'name    checks',
  'about   "Teste das checagens contra o schema"',
  'env     dev',
  'connect postgres://svc@localhost:5432/vendas',
  'secret  keychain',
  '',
  'fantasma        read',
  'pedidos         read, update(status, nao_existe)',
  'clientes        read mask(sumida: hash)',
  'pagamentos      read where coluna_x > 0',
  'produtos        read except(id, nome, preco, ativo)',
  'tmp_*           read',
  '',
];

function descriptorsFor(lines, stdout) {
  const r = parseCheckOutput(stdout, '');
  return toDescriptors(r.diagnostics, (i) => lines[i], lines.length);
}

function slice(lines, d) {
  return lines[d.line].slice(d.startChar, d.endChar);
}

test('saída real: posições e trechos destacados', () => {
  const r = parseCheckOutput(REAL, '');
  assert.strictEqual(r.error, null);
  assert.strictEqual(r.ok, false);
  assert.match(r.note, /schema conferido/);
  assert.strictEqual(r.diagnostics.length, 8);

  const ds = descriptorsFor(CHECKS_SRC, REAL);
  assert.deepStrictEqual(
    ds.map((d) => [d.line, d.severity, slice(CHECKS_SRC, d)]),
    [
      [0, 'warning', CHECKS_SRC[0]],
      [4, 'warning', 'postgres://svc@localhost:5432/vendas'],
      [7, 'error', 'fantasma'],
      [8, 'error', 'update'], // o crivo aponta a ação
      [9, 'error', 'sumida'],
      [10, 'error', 'coluna_x'],
      [11, 'error', 'read'],
      [12, 'warning', 'tmp_*'],
    ],
  );
});

test('posição 0 vai para a linha 1, coluna 1, cobrindo a linha', () => {
  const lines = ['name x', 'about "a"'];
  const out = JSON.stringify({ ok: false, diagnostics: [{ line: 0, col: 0, severity: 'error', message: 'diretiva obrigatória ausente: env' }] });
  const [d] = descriptorsFor(lines, out);
  assert.deepStrictEqual(d, { line: 0, startChar: 0, endChar: 6, severity: 'error', message: 'diretiva obrigatória ausente: env' });
});

test('linha sem coluna cobre a linha; linha além do fim vai para a última', () => {
  const lines = ['name x', 'env dev'];
  const out = JSON.stringify({
    diagnostics: [
      { line: 2, col: 0, severity: 'warning', message: 'a' },
      { line: 99, col: 3, severity: 'error', message: 'b' },
    ],
  });
  const [a, b] = descriptorsFor(lines, out);
  assert.deepStrictEqual([a.line, a.startChar, a.endChar], [1, 0, 7]);
  assert.deepStrictEqual([b.line, b.startChar, b.endChar], [1, 2, 3]);
});

test('coluna é offset em bytes UTF-8: convertida para UTF-16', () => {
  // Saída real do crivo para esta linha: col 47 (bytes) aponta para "Yy".
  const line = "clientes read where nome = 'ção', update(x, Yy)";
  assert.strictEqual(byteColToChar(line, 47), line.indexOf('Yy'));
  assert.strictEqual(byteColToChar('abc', 1), 0);
  assert.strictEqual(byteColToChar('🙂x', 5), 2); // emoji: 4 bytes, 2 unidades UTF-16
  assert.strictEqual(byteColToChar('ab', 50), 2); // além do fim: fim da linha
  const [d] = descriptorsFor([line], JSON.stringify({ diagnostics: [{ line: 1, col: 47, severity: 'error', message: 'm' }] }));
  assert.strictEqual(slice([line], d), 'Yy');
});

test('coluna depois do fim da linha não estoura', () => {
  const lines = ['tmp_*  read'];
  const [d] = descriptorsFor(lines, JSON.stringify({ diagnostics: [{ line: 1, col: 30, severity: 'error', message: 'm' }] }));
  assert.deepStrictEqual([d.startChar, d.endChar], [11, 11]);
});

test('severidade desconhecida vira warning; info e hint são aceitas', () => {
  assert.strictEqual(normalizeSeverity('fatal'), 'warning');
  assert.strictEqual(normalizeSeverity(undefined), 'warning');
  assert.strictEqual(normalizeSeverity(3), 'warning');
  assert.strictEqual(normalizeSeverity('ERROR'), 'error');
  assert.strictEqual(normalizeSeverity('info'), 'information');
  assert.strictEqual(normalizeSeverity('hint'), 'hint');
  const r = parseCheckOutput(JSON.stringify({ diagnostics: [{ line: 1, col: 1, severity: 'catastrófico', message: 'x' }] }), '');
  assert.strictEqual(r.diagnostics[0].severity, 'warning');
});

test('JSON inválido ou vazio: um erro sem posição com o stderr', () => {
  const r = parseCheckOutput('', 'crivo: unknown flag --bogus (veja crivo --help)\nmais texto');
  assert.ok(r.error);
  assert.strictEqual(r.diagnostics.length, 1);
  assert.deepStrictEqual([r.diagnostics[0].line, r.diagnostics[0].col, r.diagnostics[0].severity], [0, 0, 'error']);
  assert.match(r.diagnostics[0].message, /unknown flag --bogus/);
  assert.doesNotMatch(r.diagnostics[0].message, /mais texto/);

  const r2 = parseCheckOutput('Usage: crivo check <file>', '');
  assert.ok(r2.error);
  assert.match(r2.diagnostics[0].message, /Usage: crivo check/);

  const r3 = parseCheckOutput('{"ok": tru', '');
  assert.ok(r3.error);

  for (const bad of ['null', '42', '[1,2]', '"texto"']) {
    const rb = parseCheckOutput(bad, '');
    assert.ok(rb.error, bad);
    assert.strictEqual(rb.diagnostics.length, 1, bad);
  }
});

test('campos defensivos: diagnostics ausente, itens e posições inválidas', () => {
  const r = parseCheckOutput('{"file":"x","ok":true}', '');
  assert.strictEqual(r.error, null);
  assert.deepStrictEqual(r.diagnostics, []);
  assert.strictEqual(r.ok, true);

  const r2 = parseCheckOutput(
    JSON.stringify({ diagnostics: [null, 'x', { line: -3, col: 2.5, severity: 'error', message: 7 }, { line: '4', col: '2' }] }),
    '',
  );
  assert.deepStrictEqual(r2.diagnostics, [
    { line: 0, col: 0, severity: 'error', message: '7' },
    { line: 0, col: 0, severity: 'warning', message: '' },
  ]);
  // ok ausente: deduzido dos erros
  assert.strictEqual(r2.ok, false);
});

test('documento vazio não quebra', () => {
  const ds = toDescriptors([{ line: 3, col: 2, severity: 'error', message: 'm' }], () => undefined, 0);
  assert.deepStrictEqual(ds[0], { line: 0, startChar: 0, endChar: 0, severity: 'error', message: 'm' });
});

test('summarize conta erros e avisos', () => {
  assert.deepStrictEqual(summarize(parseCheckOutput(REAL, '').diagnostics), { errors: 5, warnings: 3 });
});

test('expandArgs troca variáveis e ignora não-strings', () => {
  assert.deepStrictEqual(
    expandArgs(['--schema-sql', '${workspaceFolder}/testdata/schema.sql', 3, '${fileDirname}', '${outra}'], {
      workspaceFolder: '/ws',
      fileDirname: '/ws/examples',
    }),
    ['--schema-sql', '/ws/testdata/schema.sql', '/ws/examples', '${outra}'],
  );
  assert.deepStrictEqual(expandArgs(['${workspaceFolder}'], {}), ['${workspaceFolder}']);
  assert.deepStrictEqual(expandArgs('--offline', {}), []);
});

test('resolveCommand: nome simples fica para o PATH; ~ e relativo são resolvidos', () => {
  const opts = { home: '/home/u', base: '/ws', path: path.posix };
  assert.strictEqual(resolveCommand('crivo', opts), 'crivo');
  assert.strictEqual(resolveCommand('', opts), 'crivo');
  assert.strictEqual(resolveCommand(undefined, opts), 'crivo');
  assert.strictEqual(resolveCommand('~/go/bin/crivo', opts), '/home/u/go/bin/crivo');
  assert.strictEqual(resolveCommand('./bin/crivo', opts), '/ws/bin/crivo');
  assert.strictEqual(resolveCommand('/usr/local/bin/crivo', opts), '/usr/local/bin/crivo');
});

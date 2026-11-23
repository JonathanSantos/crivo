'use strict';

// Parte pura da extensão: transforma a saída de `crivo check --json` em
// descritores de diagnóstico. Não importa vscode, para ser testável com node.
//
// Contrato (stdout, com código de saída 0 = ok ou 5 = há erros):
//   {"file": "...", "ok": false, "note": "...",
//    "diagnostics": [{"line": 8, "col": 1, "severity": "error", "message": "..."}]}
// line e col começam em 1; 0 significa "sem posição". col é offset em BYTES
// (UTF-8) na linha, como o scanner do Go conta.

const SEVERITIES = {
  error: 'error',
  warning: 'warning',
  info: 'information',
  information: 'information',
  hint: 'hint',
};

// Severidade desconhecida vira aviso: aparece no editor sem fingir que
// bloqueia o build.
function normalizeSeverity(s) {
  const k = typeof s === 'string' ? s.toLowerCase() : '';
  return SEVERITIES[k] || 'warning';
}

function toPosInt(v) {
  return Number.isInteger(v) && v > 0 ? v : 0;
}

function firstLine(s) {
  const t = String(s || '').trim();
  const nl = t.indexOf('\n');
  const line = nl >= 0 ? t.slice(0, nl) : t;
  return line.length > 300 ? line.slice(0, 300) + '…' : line;
}

function failure(message) {
  return { line: 0, col: 0, severity: 'error', message };
}

// parseCheckOutput interpreta stdout/stderr de `crivo check --json`.
// Sempre devolve { ok, note, diagnostics, error }: diagnostics já normalizados
// (line/col inteiros >= 0, severity conhecida, message string). Se a saída
// não for o JSON esperado, error descreve o problema e diagnostics traz um
// único erro sem posição com essa mensagem.
function parseCheckOutput(stdout, stderr) {
  const text = String(stdout || '').trim();
  let data;
  try {
    if (!text) throw new Error('saída vazia');
    data = JSON.parse(text);
  } catch (_) {
    const detail = firstLine(stderr) || firstLine(stdout) || 'sem saída';
    const error = `crivo check não devolveu JSON (versão antiga do crivo ou argumento inválido em crivo.checkArgs?): ${detail}`;
    return { ok: false, note: '', diagnostics: [failure(error)], error };
  }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    const error = 'crivo check devolveu JSON fora do formato esperado (não é um objeto)';
    return { ok: false, note: '', diagnostics: [failure(error)], error };
  }
  const list = Array.isArray(data.diagnostics) ? data.diagnostics : [];
  const diagnostics = [];
  for (const d of list) {
    if (d === null || typeof d !== 'object') continue;
    diagnostics.push({
      line: toPosInt(d.line),
      col: toPosInt(d.col),
      severity: normalizeSeverity(d.severity),
      message: typeof d.message === 'string' ? d.message : String(d.message ?? ''),
    });
  }
  const ok = typeof data.ok === 'boolean' ? data.ok : !diagnostics.some((d) => d.severity === 'error');
  return { ok, note: typeof data.note === 'string' ? data.note : '', diagnostics, error: null };
}

function utf8Len(cp) {
  if (cp < 0x80) return 1;
  if (cp < 0x800) return 2;
  if (cp < 0x10000) return 3;
  return 4;
}

// byteColToChar converte uma coluna em bytes UTF-8 (1-based) para o índice
// UTF-16 (0-based) que o VS Code usa.
function byteColToChar(lineText, col) {
  const target = Math.max(0, col - 1);
  let bytes = 0;
  let i = 0;
  while (i < lineText.length && bytes < target) {
    const cp = lineText.codePointAt(i);
    bytes += utf8Len(cp);
    i += cp > 0xffff ? 2 : 1;
  }
  return i;
}

// tokenEnd estende o destaque até o fim do "token" que começa em start:
// sequência sem espaço, vírgula ou parêntese (a URL do connect inteira,
// tmp_*, rows/day), sem ':' ou '.' finais (mask(coluna: ...)).
function tokenEnd(lineText, start) {
  let end = start;
  while (end < lineText.length && !/[\s,()]/.test(lineText[end])) end++;
  while (end > start + 1 && /[:.;]/.test(lineText[end - 1])) end--;
  if (end === start && start < lineText.length) end = start + 1;
  return end;
}

// toDescriptors converte diagnósticos normalizados em faixas do editor
// (0-based, colunas UTF-16). getLineText(i) devolve o texto da linha i
// (0-based); lineCount é o número de linhas do documento.
// Sem posição (line 0): linha 1 inteira. Linha sem coluna: a linha inteira.
// Linha além do fim do documento: última linha.
function toDescriptors(diagnostics, getLineText, lineCount) {
  const count = Math.max(1, lineCount | 0);
  return diagnostics.map((d) => {
    const line = d.line > 0 ? Math.min(d.line, count) - 1 : 0;
    const text = String(getLineText(line) ?? '');
    let startChar;
    let endChar;
    if (d.line === 0 || d.col === 0) {
      startChar = 0;
      endChar = text.length;
    } else {
      startChar = Math.min(byteColToChar(text, d.col), text.length);
      endChar = tokenEnd(text, startChar);
    }
    return { line, startChar, endChar, severity: d.severity, message: d.message };
  });
}

// expandArgs troca ${workspaceFolder}, ${fileDirname} e ${file} nos argumentos.
function expandArgs(args, vars) {
  if (!Array.isArray(args)) return [];
  return args
    .filter((a) => typeof a === 'string')
    .map((a) => a.replace(/\$\{(workspaceFolder|fileDirname|file)\}/g, (m, k) => (vars[k] != null ? vars[k] : m)));
}

// resolveCommand expande ~ e resolve caminhos relativos (com separador) a
// partir de base; um nome simples ("crivo") fica como está para o PATH.
function resolveCommand(cmd, { home, base, path }) {
  let c = typeof cmd === 'string' && cmd.trim() ? cmd.trim() : 'crivo';
  if (c === '~' || c.startsWith('~/') || c.startsWith('~\\')) c = path.join(home, c.slice(1));
  if (!path.isAbsolute(c) && /[\\/]/.test(c)) c = path.resolve(base, c);
  return c;
}

function summarize(diagnostics) {
  let errors = 0;
  let warnings = 0;
  for (const d of diagnostics) {
    if (d.severity === 'error') errors++;
    else if (d.severity === 'warning') warnings++;
  }
  return { errors, warnings };
}

module.exports = {
  normalizeSeverity,
  parseCheckOutput,
  byteColToChar,
  toDescriptors,
  expandArgs,
  resolveCommand,
  summarize,
};

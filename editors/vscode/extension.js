'use strict';

const vscode = require('vscode');
const { execFile } = require('child_process');
const os = require('os');
const path = require('path');
const {
  parseCheckOutput,
  toDescriptors,
  expandArgs,
  resolveCommand,
  summarize,
} = require('./diagnostics');

const TIMEOUT_MS = 10000;

const SEVERITY = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};

// Só mata processo que chegou a nascer: um spawn que falhou (ENOENT) não tem
// pid, e kill() nele pode acabar sinalizando o grupo de processos inteiro.
function stop(child) {
  if (child && Number.isInteger(child.pid) && child.pid > 0 && child.exitCode === null && !child.killed) {
    child.kill();
  }
}

let collection;
let output;
let warnedMissing = false;
// Geração por arquivo: uma execução lenta não sobrescreve uma mais nova.
const generation = new Map();
const running = new Map();

function isPolicy(doc) {
  return doc && doc.languageId === 'crivo' && doc.uri.scheme === 'file';
}

function config(doc) {
  return vscode.workspace.getConfiguration('crivo', doc.uri);
}

function publish(doc, diags) {
  const descriptors = toDescriptors(
    diags,
    (i) => (i < doc.lineCount ? doc.lineAt(i).text : ''),
    doc.lineCount,
  );
  collection.set(
    doc.uri,
    descriptors.map((d) => {
      const range = new vscode.Range(d.line, d.startChar, d.line, d.endChar);
      const diag = new vscode.Diagnostic(range, d.message, SEVERITY[d.severity] ?? vscode.DiagnosticSeverity.Warning);
      diag.source = 'crivo';
      return diag;
    }),
  );
}

function noPosition(message, severity) {
  return [{ line: 0, col: 0, severity, message }];
}

// check roda `<crivo.path> check <arquivo> --json ...checkArgs` sem shell e
// publica os diagnósticos. Lê o arquivo do disco: alterações não salvas não
// entram. Devolve o resultado interpretado (com error preenchido se a
// checagem não rodou) ou null se foi superado por uma execução mais nova.
// explicit: veio do comando, que mostra o erro por conta própria.
function check(doc, explicit = false) {
  if (!isPolicy(doc)) return Promise.resolve(null);
  const key = doc.uri.toString();
  const gen = (generation.get(key) || 0) + 1;
  generation.set(key, gen);
  stop(running.get(key));

  const file = doc.uri.fsPath;
  const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
  const cwd = folder ? folder.uri.fsPath : path.dirname(file);
  const cfg = config(doc);
  const cmd = resolveCommand(cfg.get('path', 'crivo'), { home: os.homedir(), base: cwd, path });
  const extra = expandArgs(cfg.get('checkArgs', ['--offline']), {
    workspaceFolder: folder ? folder.uri.fsPath : undefined,
    fileDirname: path.dirname(file),
    file,
  });
  const args = ['check', file, '--json', ...extra];

  return new Promise((resolve) => {
    const child = execFile(
      cmd,
      args,
      { cwd, timeout: TIMEOUT_MS, maxBuffer: 4 * 1024 * 1024, windowsHide: true },
      (err, stdout, stderr) => {
        if (running.get(key) === child) running.delete(key);
        if (generation.get(key) !== gen) return resolve(null);

        if (err && err.code === 'ENOENT') {
          collection.delete(doc.uri);
          const msg = `não encontrei o executável "${cmd}". Instale o crivo ou ajuste a configuração crivo.path.`;
          if (!explicit && !warnedMissing) {
            warnedMissing = true;
            vscode.window
              .showWarningMessage(
                `Crivo: ${msg}`,
                'Abrir configurações',
              )
              .then((choice) => {
                if (choice) vscode.commands.executeCommand('workbench.action.openSettings', 'crivo.path');
              });
          }
          output.appendLine(`[crivo] executável não encontrado: ${cmd}`);
          return resolve({ error: msg, diagnostics: [] });
        }
        if (err && typeof err.code === 'string') {
          // Outra falha ao iniciar o processo (EACCES, crivo.path é pasta...).
          const msg = `não consegui executar "${cmd}": ${err.message}`;
          output.appendLine(`[crivo] ${msg}`);
          publish(doc, noPosition(msg, 'error'));
          return resolve({ error: msg, diagnostics: [] });
        }
        if (err && (err.killed || err.signal)) {
          const msg = `crivo check não terminou em ${TIMEOUT_MS / 1000}s (banco inacessível? use --offline em crivo.checkArgs)`;
          output.appendLine(`[crivo] ${file}: ${msg}`);
          publish(doc, noPosition(msg, 'warning'));
          return resolve({ error: msg, diagnostics: [] });
        }
        // Código 0 (ok) ou 5 (há erros): o JSON vem no stdout nos dois casos.
        const result = parseCheckOutput(stdout, stderr);
        if (result.error) {
          output.appendLine(`[crivo] ${cmd} ${args.join(' ')}`);
          if (stderr) output.appendLine(String(stderr).trim());
          if (stdout) output.appendLine(String(stdout).trim());
        }
        publish(doc, result.diagnostics);
        resolve(result);
      },
    );
    running.set(key, child);
  });
}

function maybeCheck(doc) {
  if (isPolicy(doc) && config(doc).get('checkOnSave', true)) check(doc);
}

async function checkCommand() {
  const editor = vscode.window.activeTextEditor;
  const doc = editor && editor.document;
  if (!doc || doc.languageId !== 'crivo') {
    vscode.window.showInformationMessage('Crivo: abra um arquivo .crivo para checar.');
    return;
  }
  if (doc.uri.scheme !== 'file') {
    vscode.window.showInformationMessage('Crivo: salve o arquivo em disco antes de checar.');
    return;
  }
  // crivo check lê o arquivo do disco.
  if (doc.isDirty && !(await doc.save())) return;
  const result = await check(doc, true);
  if (!result) return;
  if (result.error) {
    vscode.window.showErrorMessage(`Crivo: ${result.error}`);
    return;
  }
  const { errors, warnings } = summarize(result.diagnostics);
  const note = result.note ? ` (${result.note})` : '';
  vscode.window.setStatusBarMessage(`Crivo: ${errors} erro(s), ${warnings} aviso(s)${note}`, 5000);
}

function activate(context) {
  collection = vscode.languages.createDiagnosticCollection('crivo');
  output = vscode.window.createOutputChannel('Crivo');
  context.subscriptions.push(
    collection,
    output,
    vscode.workspace.onDidOpenTextDocument(maybeCheck),
    vscode.workspace.onDidSaveTextDocument(maybeCheck),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      const key = doc.uri.toString();
      collection.delete(doc.uri);
      generation.delete(key);
      stop(running.get(key));
      running.delete(key);
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (!e.affectsConfiguration('crivo')) return;
      warnedMissing = false;
      for (const doc of vscode.workspace.textDocuments) {
        if (!isPolicy(doc)) continue;
        if (config(doc).get('checkOnSave', true)) check(doc);
        else collection.delete(doc.uri);
      }
    }),
    vscode.commands.registerCommand('crivo.check', checkCommand),
  );
  // Arquivos já abertos quando a extensão ativa não disparam onDidOpen.
  vscode.workspace.textDocuments.forEach(maybeCheck);
}

function deactivate() {
  for (const child of running.values()) stop(child);
  running.clear();
}

module.exports = { activate, deactivate };

// Package skill gera o SKILL.md (padrão Agent Skills) a partir da política
// embutida, instala no workspace e gera o trecho de auto-approve do VS Code.
// O conteúdo é determinístico: mesma política, mesmo arquivo.
package skill

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"crivo/internal/policy"
	"crivo/internal/schema"
)

// Options controla a geração.
type Options struct {
	Bin        string         // como a skill chama o binário (nome ou caminho)
	WithSchema bool           // anexa as colunas permitidas
	Schema     *schema.Schema // obrigatório com WithSchema
}

// Name é o nome da skill: crivo-<name>.
func Name(p *policy.Policy) string { return "crivo-" + p.Name }

// MaxDescription é o limite do campo description.
const MaxDescription = 1024

func code(s string) string {
	if strings.Contains(s, "`") {
		return "``" + s + "``"
	}
	return "`" + s + "`"
}

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ")
}

func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasSuffix(s, ".") || strings.HasSuffix(s, "!") || strings.HasSuffix(s, "?") {
		return s
	}
	return s + "."
}

func joinPT(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " e " + items[len(items)-1]
}

// visibleRules são as regras com ações (deny não aparece na skill).
func visibleRules(p *policy.Policy) []*policy.Rule {
	var out []*policy.Rule
	for _, r := range p.Rules {
		if !r.Deny && len(r.Actions) > 0 && !policy.AlwaysBlocked(p.SchemaOf(r), r.Pattern) {
			out = append(out, r)
		}
	}
	return out
}

// Description monta o campo description do frontmatter.
func Description(p *policy.Policy, bin string) string {
	var tables []string
	for _, r := range visibleRules(p) {
		tables = append(tables, r.Label())
	}
	head := fmt.Sprintf("Consulta a base %s (Postgres, %s) via CLI `%s`. %s", p.Name, p.EnvLabel(), bin, sentence(p.About))
	tail := " conferir dados de teste ou validar o efeito de uma mudança. Toda query passa pelo Crivo, que valida e pode recusar."
	for n := len(tables); n >= 0; n-- {
		list := tables[:n]
		if n < len(tables) {
			list = append(append([]string{}, list...), fmt.Sprintf("outras %d tabelas", len(tables)-n))
		}
		var d string
		if len(list) > 0 {
			d = head + " Use para investigar " + joinPT(list) + "," + tail
		} else {
			d = head + " Use para" + tail
		}
		if len([]rune(d)) <= MaxDescription {
			return d
		}
	}
	r := []rune(head)
	if len(r) > MaxDescription {
		r = r[:MaxDescription]
	}
	return string(r)
}

func yamlQuote(s string) string {
	b, _ := json.Marshal(s) // JSON string é YAML válido entre aspas duplas
	return string(b)
}

func colsText(a *policy.Action, all string) string {
	switch {
	case a.Cols == nil:
		return all
	case a.Except:
		return "todas menos " + strings.Join(a.Cols, ", ")
	}
	return strings.Join(a.Cols, ", ")
}

func maskText(m policy.Mask) string {
	switch m.Mode {
	case policy.MaskPartial:
		return m.Column + " sai mascarado (parcial)"
	case policy.MaskRedact:
		return m.Column + " sai como ***"
	case policy.MaskHash:
		return m.Column + " sai como hash curto (h:…), estável só dentro de uma execução"
	case policy.MaskEmail:
		return m.Column + " sai só com o domínio (***@dominio)"
	case policy.MaskLast4:
		return m.Column + " sai só com os 4 últimos caracteres"
	case policy.MaskMonth:
		return m.Column + " sai só com ano e mês (AAAA-MM)"
	case policy.MaskBucket:
		return fmt.Sprintf("%s sai como faixa de %d (ex.: 1800..1900)", m.Column, m.Arg)
	case policy.MaskPseudonym:
		return m.Column + " sai como pseudônimo (p:…), o mesmo para o mesmo valor em qualquer execução"
	}
	return m.Column + " sai como ***"
}

func writeText(r *policy.Rule) string {
	var parts []string
	for _, a := range r.Actions {
		if !a.Verb.IsWrite() {
			continue
		}
		s := string(a.Verb)
		if a.Cols != nil {
			if a.Except {
				s += " (todas menos " + strings.Join(a.Cols, ", ") + ")"
			} else {
				s += " de " + strings.Join(a.Cols, ", ")
			}
		}
		if a.Max > 0 {
			s += fmt.Sprintf(" (máx. %d %s)", a.Max, pick(a.Max == 1, "linha", "linhas"))
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "; ")
}

func pick(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

func notesText(r *policy.Rule) string {
	var parts []string
	if r.Doc != "" {
		parts = append(parts, strings.TrimSuffix(r.Doc, "."))
	}
	if r.IsPattern() {
		parts = append(parts, "padrão: vale para toda tabela com esse formato de nome")
	}
	if rd := r.Action(policy.Read); rd != nil {
		for _, m := range rd.Masks {
			parts = append(parts, maskText(m))
		}
		if rd.Where != "" {
			parts = append(parts, "só linhas com "+code(rd.Where)+"; as demais nunca aparecem")
		}
		if rd.Limit > 0 {
			parts = append(parts, fmt.Sprintf("no máximo %d linhas por query", rd.Limit))
		}
	}
	for _, v := range []policy.Verb{policy.Update, policy.Delete} {
		if a := r.Action(v); a != nil && a.Where != "" {
			parts = append(parts, fmt.Sprintf("%s só alcança linhas com %s", v, code(a.Where)))
		}
	}
	return strings.Join(parts, "; ")
}

func durationText(p *policy.Policy) string {
	s := p.Timeout.String() // 5s, 1m30s, 1m0s, 500ms
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// Generate devolve o SKILL.md.
func Generate(p *policy.Policy, opts Options) (string, error) {
	bin := opts.Bin
	if bin == "" {
		bin = p.Name
	}
	rules := visibleRules(p)
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("---\nname: %s\ndescription: %s\n---\n\n", Name(p), yamlQuote(Description(p, bin)))
	w("# Base %s (%s)\n\n", p.Name, p.EnvLabel())
	w("Você acessa esta base **somente** pelo comando %s no terminal. Toda query passa pelo Crivo: ele analisa o SQL antes de executar e recusa o que a política não permite.\n\n", code(bin))

	w("## Comandos\n\n")
	w("- %s: tabelas que você pode usar e o que pode fazer em cada uma.\n", code(bin+" tables"))
	w("- %s: colunas permitidas, tipos e máscaras.\n", code(bin+" describe <tabela>"))
	if p.HasRead() {
		w("- %s: executa leitura. Saída em TSV com cabeçalho.\n", code(bin+` query "<SELECT>"`))
		w("- %s: plano da query, sem executar.\n", code(bin+` explain "<SELECT>"`))
	}
	if len(p.Queries) > 0 {
		w("- %s: roda uma consulta pronta da política (sem nome, lista as consultas).\n", code(bin+" run <consulta> nome=valor ..."))
	}
	if p.HasRead() && p.ExportRows > 0 {
		w("- %s: grava o resultado em CSV, até %d linhas (para planilhas e análises).\n", code(bin+` export "<SELECT>" -o arquivo.csv`), p.ExportRows)
	}
	if p.HasWrite() {
		w("- %s: simula uma escrita.\n", code(bin+` exec "<INSERT|UPDATE|DELETE>" --dry-run`))
		if p.ApprovalWrites {
			w("- %s: registra a escrita como pendente; só o usuário a executa, com %s.\n", code(bin+` exec "<INSERT|UPDATE|DELETE>"`), code(bin+" approve <id>"))
			w("- %s: lista as escritas pendentes.\n", code(bin+" pending"))
		} else {
			w("- %s: executa a escrita (pede confirmação ao usuário).\n", code(bin+` exec "<INSERT|UPDATE|DELETE>"`))
		}
	}
	w("- %s: a política completa, com a lista de funções liberadas.\n", code(bin+" policy"))
	w("\nPara SQL com aspas ou várias linhas, grave num arquivo e use %s. Para saída em JSON, use %s.\n\n", code("-f arquivo.sql"), code("--format json"))

	w("## O que você pode fazer\n\n")
	if len(rules) == 0 {
		w("Nenhuma tabela está liberada.\n\n")
	} else {
		w("| Tabela | Leitura | Escrita | Observações |\n| --- | --- | --- | --- |\n")
		for _, r := range rules {
			read := "—"
			if a := r.Action(policy.Read); a != nil {
				read = colsText(a, "todas as colunas")
			}
			w("| %s | %s | %s | %s |\n", cell(r.Label()), cell(read), cell(writeText(r)), cell(notesText(r)))
		}
		w("\nQualquer outra tabela não existe para você.\n\n")
	}

	w("## Regras aplicadas automaticamente\n\n")
	if p.HasRead() {
		w("- No máximo %d linhas por query. Se o rodapé disser %s, refine o filtro ou agregue.\n", p.Limit, code("truncado"))
	}
	w("- Timeout de %s por execução.\n", durationText(p))
	var masked, hashed, hidden, emails, months, pseudo []string
	for _, r := range rules {
		rd := r.Action(policy.Read)
		if rd == nil {
			continue
		}
		if rd.Where != "" {
			w("- %s já vem filtrado (%s). Linhas fora do filtro não aparecem: não conclua que elas não existem.\n", code(r.Label()), code(rd.Where))
		}
		for _, m := range rd.Masks {
			masked = append(masked, code(r.Label()+"."+m.Column))
			if m.Mode.EqualityStable() {
				hashed = append(hashed, code(r.Label()+"."+m.Column))
			}
			switch m.Mode {
			case policy.MaskEmail:
				emails = append(emails, m.Column)
			case policy.MaskMonth:
				months = append(months, m.Column)
			case policy.MaskPseudonym:
				pseudo = append(pseudo, code(r.Label()+"."+m.Column))
			}
		}
		if rd.Except {
			for _, c := range rd.Cols {
				hidden = append(hidden, code(r.Label()+"."+c))
			}
		}
	}
	if len(masked) > 0 {
		w("- Colunas mascaradas (%s) só podem aparecer na lista do SELECT, sem funções em volta, e não podem ser usadas em WHERE, JOIN, ORDER BY ou GROUP BY.", joinPT(masked))
		if len(hashed) > 0 {
			w(" As com hash ou pseudonym (%s) também podem ir em GROUP BY, DISTINCT e count(DISTINCT ...).", joinPT(hashed))
		}
		w("\n")
		if len(emails) > 0 {
			w("- Para filtrar, juntar ou agrupar pelo domínio de um email mascarado, use %s (ex.: %s); o resto do email não pode ser usado.\n",
				code("split_part("+emails[0]+", '@', 2)"), code("WHERE split_part("+emails[0]+", '@', 2) = 'empresa.com.br'"))
		}
		if len(months) > 0 {
			w("- Para filtrar ou agrupar por período uma data mascarada, use %s ou %s (só ano, trimestre ou mês).\n",
				code("date_trunc('month', "+months[0]+")"), code("extract(year FROM "+months[0]+")"))
		}
		if len(pseudo) > 0 {
			w("- Nomes com pseudônimo (%s) não revelam o nome real: identifique os registros pelo id ou pelo próprio pseudônimo ao responder.\n", joinPT(pseudo))
		}
	}
	if len(hidden) > 0 {
		w("- Colunas bloqueadas (%s) não podem ser citadas em nenhuma parte da query, nem em filtro.\n", joinPT(hidden))
	}
	w("- %s é expandido para as colunas permitidas; prefira listar as colunas que você precisa.\n", code("SELECT *"))
	w("- Só funções comuns de agregação, texto, data, matemática e JSON. Use %s se precisar da lista.\n", code(bin+" policy"))
	w("- Um statement por chamada, sem %s: escreva os valores direto na query.\n", code("$1"))
	if p.HasWrite() {
		w("- UPDATE e DELETE exigem WHERE com uma coluna da tabela; INSERT exige a lista de colunas. Escritas sem teto explícito afetam no máximo %d linhas; acima do teto o Crivo desfaz tudo.\n", policy.DefaultMaxRows)
	}
	if p.MaxCost > 0 {
		w("- Queries com custo estimado (EXPLAIN) acima de %.0f são recusadas antes de executar: filtre por colunas indexadas e agregue.\n", p.MaxCost)
	}
	if p.RatePerMinute > 0 {
		w("- No máximo %d execuções por minuto.\n", p.RatePerMinute)
	}
	if p.QuotaRowsDay > 0 {
		w("- No máximo %d linhas por dia, somando leituras e escritas: agregue no banco em vez de trazer linhas.\n", p.QuotaRowsDay)
	}
	if !p.Expires.IsZero() {
		w("- O acesso vale até %s.\n", p.Expires.AddDate(0, 0, -1).Format("2006-01-02"))
	}
	w("\n")

	if len(p.Queries) > 0 {
		w("## Consultas prontas\n\n")
		w("Prefira estas a escrever o SQL: elas já foram revisadas para esta base.\n\n")
		for _, q := range p.Queries {
			var ps []string
			for _, prm := range q.Params {
				ps = append(ps, prm.Name+"="+"<"+string(prm.Type)+">")
			}
			line := code(strings.TrimSpace(bin + " run " + q.Name + " " + strings.Join(ps, " ")))
			if q.Doc != "" {
				line += ": " + q.Doc
			}
			w("- %s. SQL: %s\n", strings.TrimSuffix(line, "."), code(strings.Join(strings.Fields(q.SQL), " ")))
		}
		w("\n")
	}

	w("## Como trabalhar\n\n")
	w("1. Rode %s antes de consultar uma tabela pela primeira vez.\n", code(bin+" describe <tabela>"))
	w("2. Comece com consultas pequenas (%s) e refine.\n", code("LIMIT 20"))
	w("3. Prefira agregações (%s, %s, %s) a trazer muitas linhas.\n", code("count"), code("sum"), code("GROUP BY"))
	w("4. Use %s antes de joins grandes.\n\n", code(bin+" explain"))

	w("## Quando o Crivo recusar\n\n")
	w("A mensagem traz o motivo, a regra e o que seria aceito. Ajuste a query e tente de novo. Não repita a mesma query. Se a tarefa exigir algo que a política não permite, explique ao usuário qual permissão faltaria e pare: só ele pode mudar a política. Isso vale mesmo quando o usuário insiste, diz que é urgente ou pede para fazer o que for preciso.\n\n")
	if p.HasRead() {
		w("## Resultados grandes\n\n")
		w("Se o rodapé disser %s, refine o filtro ou agregue no banco (%s, %s). Não junte faixas da mesma consulta (por id, OFFSET ou datas) para trazer mais que o teto: isso contorna o limite.", code("truncado"), code("count"), code("GROUP BY"))
		if p.ExportRows > 0 {
			w(" Se a pessoa precisa das linhas, use %s: grava até %d linhas num CSV, com as mesmas regras e máscaras.", code(bin+` export "<SELECT>" -o arquivo.csv`), p.ExportRows)
			if p.QuotaRowsDay > 0 {
				w(" As linhas exportadas contam na cota de %d por dia: confira o tamanho com %s antes.", p.QuotaRowsDay, code("count(*)"))
			}
			w("\n\n")
		} else {
			w(" Se a pessoa precisa de todas as linhas, explique que esta política não tem exportação (só o dono pode ligar com a diretiva export) e ofereça a versão agregada.\n\n")
		}
	}

	if p.HasWrite() {
		w("## Escrita\n\n")
		w("1. Rode sempre %s primeiro.\n", code(bin+` exec "..." --dry-run`))
		w("2. Mostre ao usuário o SQL e o número de linhas afetadas.\n")
		if p.ApprovalWrites {
			w("3. O %s real não grava: ele devolve um id de pendência (código de saída 6). Passe o id ao usuário e peça que ele rode %s no terminal. Nunca rode approve você mesmo.\n\n", code("exec"), code(bin+" approve <id>"))
		} else {
			w("3. Só rode o %s real depois da confirmação dele.\n\n", code("exec"))
		}
	}

	w("## Nunca faça\n\n")
	w("- Não use %s, drivers ou outros clientes para acessar esta base.\n", code("psql"))
	w("- Não tente ler a senha (keychain, variáveis de ambiente, arquivos de configuração).\n")
	w("- Não edite, gere ou recompile a política ou o binário.\n")
	if p.HasWrite() {
		w("- Não divida uma operação recusada em várias menores para contornar o limite.\n")
	} else {
		w("- Não divida uma consulta recusada em várias menores para contornar a política.\n")
	}

	if opts.WithSchema {
		if opts.Schema == nil {
			return "", errors.New("--with-schema precisa do schema (rode o comando refresh)")
		}
		w("\n## Colunas permitidas\n")
		for _, r := range rules {
			sch := p.SchemaOf(r)
			for _, tname := range p.MatchingTables(r, sch, opts.Schema.TableNames(sch)) {
				t := opts.Schema.Table(sch, tname)
				w("\n### %s\n\n", tableLabel(p, sch, tname))
				w("| Coluna | Tipo | Nulo | Chave | Máscara |\n| --- | --- | --- | --- | --- |\n")
				for _, c := range DescribeColumns(r, t) {
					w("| %s | %s | %s | %s | %s |\n", c.Name, cell(c.Type), c.Null, cell(c.Key), c.Mask)
				}
			}
		}
	}
	return b.String(), nil
}

func tableLabel(p *policy.Policy, sch, name string) string {
	if sch != p.Schema {
		return sch + "." + name
	}
	return name
}

// ColumnInfo é uma linha do describe.
type ColumnInfo struct {
	Name, Type, Null, Key, Mask string
	Writable                    []string
}

// DescribeColumns lista as colunas legíveis (ou graváveis, se a regra não
// tem read) de uma tabela, com tipo, nulabilidade, chave e máscara.
func DescribeColumns(r *policy.Rule, t *schema.Table) []ColumnInfo {
	rd := r.Action(policy.Read)
	var out []ColumnInfo
	for _, c := range t.Columns {
		var writable []string
		for _, v := range []policy.Verb{policy.Insert, policy.Update} {
			if a := r.Action(v); a != nil && a.AllowsCol(c.Name) {
				writable = append(writable, string(v))
			}
		}
		if !rd.AllowsCol(c.Name) && len(writable) == 0 {
			continue
		}
		ci := ColumnInfo{Name: c.Name, Type: c.Type, Null: "sim", Writable: writable}
		if c.NotNull {
			ci.Null = "não"
		}
		var keys []string
		if t.IsPK(c.Name) {
			keys = append(keys, "PK")
		}
		if fk := t.FKOf(c.Name); fk != nil && len(fk.Columns) == 1 {
			keys = append(keys, "FK → "+fk.RefTable+"."+strings.Join(fk.RefColumns, ","))
		}
		ci.Key = strings.Join(keys, ", ")
		if m, ok := rd.MaskFor(c.Name); ok {
			ci.Mask = m.Text()
		}
		if !rd.AllowsCol(c.Name) {
			ci.Mask = "só escrita"
		}
		out = append(out, ci)
	}
	return out
}

// dryRunArg é o único formato de SQL que a regra de auto-approve do --dry-run
// aceita: um argumento entre aspas sem nada que o shell interprete (aspas
// duplas sem $, crase ou barra invertida; trechos em aspas simples, literais no bash e
// no PowerShell) ou -f com um caminho simples. Assim um "--dry-run" escrito
// dentro do SQL, ou escapado (DELETE\ --dry-run, ou com crase no
// PowerShell), não vira uma escrita real aprovada sem clique.
const dryRunArg = `(?:"[^"$` + "`" + `\\]*"|(?:'[^']*')+|-f [\w./:-]+)`

// VSCodeSettings devolve o trecho de settings.json de auto-approve.
func VSCodeSettings(p *policy.Policy, bin string) string {
	if bin == "" {
		bin = p.Name
	}
	q := regexp.QuoteMeta(bin)
	type kv struct {
		k string
		v bool
	}
	read := []string{"tables", "describe", "policy"}
	if p.HasRead() {
		read = append(read, "query", "explain")
	}
	if len(p.Queries) > 0 {
		read = append(read, "run")
	}
	if p.ApprovalWrites && p.HasWrite() {
		read = append(read, "pending")
	}
	read = append(read, "refresh")
	items := []kv{{"/^" + q + " (" + strings.Join(read, "|") + `)\b/`, true}}
	if p.HasWrite() {
		items = append(items, kv{"/^" + q + " exec " + dryRunArg + ` --dry-run$/`, true}, kv{"/^" + q + ` exec\b/`, false})
		if p.ApprovalWrites {
			// approve executa de verdade: sempre com o clique de quem está no terminal
			items = append(items, kv{"/^" + q + ` approve\b/`, false})
		}
	}
	var b strings.Builder
	b.WriteString(`"chat.tools.terminal.autoApprove": {` + "\n")
	for i, it := range items {
		k, _ := json.Marshal(it.k)
		sep := ","
		if i == len(items)-1 {
			sep = ""
		}
		fmt.Fprintf(&b, "  %s: %v%s\n", k, it.v, sep)
	}
	b.WriteString("}\n")
	return b.String()
}

// MCPConfig devolve os trechos de configuração do servidor MCP (stdio) para
// VS Code, Claude Code e Claude Desktop.
func MCPConfig(p *policy.Policy, bin string, allowExec bool) string {
	if bin == "" {
		bin = p.Name
	}
	name := Name(p)
	args := []string{"mcp"}
	if allowExec {
		args = append(args, "--allow-exec")
	}
	entry := map[string]any{"command": bin, "args": args}
	vscode := map[string]any{"servers": map[string]any{name: map[string]any{"type": "stdio", "command": bin, "args": args}}}
	desktop := map[string]any{"mcpServers": map[string]any{name: entry}}
	js := func(v any) string {
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	}
	var b strings.Builder
	b.WriteString("// VS Code (Copilot): .vscode/mcp.json\n" + js(vscode) + "\n\n")
	b.WriteString("// Claude Code:\n//   claude mcp add " + name + " -- " + bin + " " + strings.Join(args, " ") + "\n\n")
	b.WriteString("// Claude Desktop e outros clientes: claude_desktop_config.json\n" + js(desktop) + "\n")
	if !allowExec && p.HasWrite() {
		b.WriteString("\n// Sem --allow-exec a ferramenta exec só simula (dry_run). Ligue só se quiser escrita real pelo MCP.\n")
	}
	return b.String()
}

// WorkspaceRoot é a pasta com .git mais próxima subindo a partir de dir;
// sem .git, o próprio dir.
func WorkspaceRoot(dir string) string {
	for d := dir; ; {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return dir
		}
		d = parent
	}
}

// Install grava SKILL.md em <base>/<crivo-name>/SKILL.md.
func Install(p *policy.Policy, base, content string, force bool) (string, error) {
	dir := filepath.Join(base, Name(p))
	path := filepath.Join(dir, "SKILL.md")
	if _, err := os.Stat(path); err == nil && !force {
		return "", fmt.Errorf("%s já existe; use --force para sobrescrever", path)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return path, os.WriteFile(path, []byte(content), 0o644)
}

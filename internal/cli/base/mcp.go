package base

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"crivo/internal/cli"
	"crivo/internal/output"
	"crivo/internal/policy"
	"crivo/internal/sqlguard"
)

// mcpCmd serve a política como servidor MCP por stdio: as mesmas operações
// do CLI, passando pelo mesmo guard, para qualquer cliente de IA que fale
// MCP. É opcional; o modo principal continua sendo o CLI com a skill.
type mcpCmd struct {
	AllowExec bool `name:"allow-exec" help:"Expõe escrita real (dry_run=false) na ferramenta exec. Sem a flag, exec só simula."`
}

func (c *mcpCmd) Run(e *env) error {
	s := &mcpServer{p: e.p, format: e.format, allowExec: c.AllowExec}
	// stdout é o canal do protocolo: nada mais pode escrever nele.
	return s.server().Run(context.Background(), &mcp.StdioTransport{})
}

type mcpServer struct {
	p         *policy.Policy
	format    output.Format
	allowExec bool
}

type noArgs struct{}

type describeArgs struct {
	Table string `json:"table" jsonschema:"tabela (ou schema.tabela) da lista de tables"`
}

type sqlToolArgs struct {
	SQL    string `json:"sql" jsonschema:"um único statement SQL, com os valores escritos na query (sem $1)"`
	Format string `json:"format,omitempty" jsonschema:"formato da saída: tsv (padrão), json ou table"`
}

type execToolArgs struct {
	SQL    string `json:"sql" jsonschema:"um único INSERT, UPDATE ou DELETE, com WHERE (UPDATE/DELETE) e lista de colunas (INSERT)"`
	DryRun *bool  `json:"dry_run,omitempty" jsonschema:"true (padrão): executa, informa as linhas afetadas e desfaz. false: executa de verdade; só funciona se o servidor foi iniciado com --allow-exec"`
	Format string `json:"format,omitempty" jsonschema:"formato da saída: tsv (padrão), json ou table"`
}

func boolPtr(b bool) *bool { return &b }

func (s *mcpServer) server() *mcp.Server {
	p := s.p
	srv := mcp.NewServer(&mcp.Implementation{
		Name: "crivo-" + p.Name, Title: "Crivo: " + p.Name, Version: cli.Version,
		Description: fmt.Sprintf("%s (%s). Toda query passa pelo Crivo.", p.About, p.EnvLabel()),
	}, &mcp.ServerOptions{Instructions: s.instructions()})

	ro := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)}

	mcp.AddTool(srv, &mcp.Tool{Name: "tables", Annotations: ro,
		Description: "Tabelas que você pode usar, as ações permitidas em cada uma e a descrição. Qualquer outra tabela não existe para você."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
			return s.run("tables", "", func(e *env) error { return (&tablesCmd{}).Run(e) }), nil, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "describe", Annotations: ro,
		Description: "Colunas permitidas de uma tabela, com tipo, nulabilidade, chaves, máscaras e colunas graváveis. Rode antes da primeira consulta a uma tabela."},
		func(_ context.Context, _ *mcp.CallToolRequest, a describeArgs) (*mcp.CallToolResult, any, error) {
			return s.run("describe", "", func(e *env) error { return (&describeCmd{Table: a.Table}).Run(e) }), nil, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "policy", Annotations: ro,
		Description: "A política completa com números de linha e a lista de funções SQL liberadas."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
			return s.run("policy", "", func(e *env) error { return (&policyCmd{}).Run(e) }), nil, nil
		})
	if p.HasRead() {
		mcp.AddTool(srv, &mcp.Tool{Name: "query", Annotations: ro,
			Description: fmt.Sprintf("Executa um SELECT em transação READ ONLY, com teto de %d linhas e timeout de %s. Se a saída disser truncado, refine o filtro ou agregue.", p.Limit, p.Timeout)},
			func(_ context.Context, _ *mcp.CallToolRequest, a sqlToolArgs) (*mcp.CallToolResult, any, error) {
				return s.run("query", a.Format, func(e *env) error {
					c := &queryCmd{}
					c.SQL = a.SQL
					return c.Run(e)
				}), nil, nil
			})
		mcp.AddTool(srv, &mcp.Tool{Name: "explain", Annotations: ro,
			Description: "Plano (EXPLAIN sem ANALYZE) de um SELECT validado, sem executar. Use antes de joins grandes."},
			func(_ context.Context, _ *mcp.CallToolRequest, a sqlToolArgs) (*mcp.CallToolResult, any, error) {
				return s.run("explain", a.Format, func(e *env) error {
					c := &explainCmd{}
					c.SQL = a.SQL
					return c.Run(e)
				}), nil, nil
			})
	}
	if p.HasWrite() {
		desc := "Executa INSERT, UPDATE ou DELETE com teto de linhas afetadas; acima do teto o Crivo desfaz tudo. Sempre chame com dry_run=true primeiro e mostre ao usuário o SQL e as linhas afetadas."
		if s.allowExec {
			desc += " Com dry_run=false a escrita é real e só deve acontecer depois da confirmação explícita do usuário."
		} else {
			desc += " Neste servidor a escrita real está desligada: dry_run=false é recusado."
		}
		mcp.AddTool(srv, &mcp.Tool{Name: "exec", Description: desc,
			Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)}},
			func(_ context.Context, _ *mcp.CallToolRequest, a execToolArgs) (*mcp.CallToolResult, any, error) {
				dry := a.DryRun == nil || *a.DryRun
				if !dry && !s.allowExec {
					return s.run("exec", a.Format, func(e *env) error {
						d := &sqlguard.Denial{
							Reason:   "escrita real está desligada neste servidor MCP",
							Accepted: fmt.Sprintf("dry_run=true, ou o usuário iniciar o servidor com: %s mcp --allow-exec", p.Name),
						}
						e.audit("exec", a.SQL, nil, time.Now(), 0, false, d)
						return d
					}), nil, nil
				}
				return s.run("exec", a.Format, func(e *env) error {
					c := &execCmd{DryRun: dry}
					c.SQL = a.SQL
					return c.Run(e)
				}), nil, nil
			})
	}
	return srv
}

// run executa um comando do CLI num ambiente novo (sessão e conexão
// próprias, saída em memória) e empacota o resultado como conteúdo MCP.
// Recusas e erros viram IsError com a mesma mensagem que o terminal mostra.
func (s *mcpServer) run(cmd, format string, fn func(e *env) error) *mcp.CallToolResult {
	f := s.format
	switch format {
	case "":
	case "tsv", "json", "table":
		f = output.Format(format)
	default:
		return errorResult(output.Message{Title: "configuração", Reason: fmt.Sprintf("format %q inválido", format), Accepted: "tsv, json ou table", Code: output.ExitConfig})
	}
	var out, errs bytes.Buffer
	e := &env{p: s.p, stdout: &out, stderr: &errs, format: f, via: "mcp:"}
	e.sess = cli.NewSession(s.p, &errs)
	defer e.sess.Close()

	err := fn(e)
	res := &mcp.CallToolResult{}
	text := out.String()
	if err != nil {
		var msg bytes.Buffer
		code := cli.Report(&msg, s.p, err, false)
		res.IsError = true
		text = strings.TrimRight(msg.String(), "\n") + fmt.Sprintf("\n  código  %d", code)
	}
	if w := strings.TrimSpace(errs.String()); w != "" {
		text = strings.TrimRight(text, "\n") + "\n" + w
	}
	_ = cmd
	res.Content = []mcp.Content{&mcp.TextContent{Text: text}}
	return res
}

func errorResult(m output.Message) *mcp.CallToolResult {
	var b bytes.Buffer
	output.WriteMessage(&b, m, false)
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: strings.TrimRight(b.String(), "\n")}}}
}

// instructions é o texto que o cliente MCP entrega ao modelo junto com as
// ferramentas: o equivalente curto da skill.
func (s *mcpServer) instructions() string {
	p := s.p
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w("Base %s (%s): %s\n\n", p.Name, p.EnvLabel(), p.About)
	w("Toda chamada passa pelo Crivo: ele valida o SQL contra a política antes de executar e recusa o que ela não permite. ")
	w("Uma recusa traz o motivo, a regra e o que seria aceito; ajuste a query e tente de novo, sem repetir a mesma. ")
	w("Se a tarefa exigir algo que a política não permite, explique ao usuário qual permissão faltaria e pare.\n\n")
	w("Como trabalhar: comece por tables e describe; use consultas pequenas e agregações; ")
	if p.HasRead() {
		w("o teto é de %d linhas por query e %s de timeout. ", p.Limit, p.Timeout)
	}
	w("Um statement por chamada, sem $1: escreva os valores na query. SELECT * é expandido para as colunas permitidas.\n")
	if p.HasWrite() {
		w("\nEscrita: chame exec com dry_run=true, mostre ao usuário o SQL e o número de linhas afetadas e só rode dry_run=false depois da confirmação explícita dele")
		if s.allowExec {
			w(".\n")
		} else {
			w(" (neste servidor a escrita real está desligada; só o usuário pode ligá-la com --allow-exec).\n")
		}
	}
	w("\nNunca tente acessar o banco por outro caminho, ler a senha, alterar a política ou dividir uma operação recusada em várias menores.\n")
	return b.String()
}

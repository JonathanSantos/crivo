package base

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"crivo/internal/cli"
	"crivo/internal/output"
	"crivo/internal/policy"
	"crivo/internal/skill"
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
	Table  string `json:"table" jsonschema:"tabela (ou schema.tabela) da lista de tables"`
	Sample int    `json:"sample,omitempty" jsonschema:"quantas linhas de exemplo mostrar (0 a 20), já mascaradas"`
}

type sqlToolArgs struct {
	SQL    string `json:"sql" jsonschema:"um único statement SQL, com os valores escritos na query (sem $1)"`
	Format string `json:"format,omitempty" jsonschema:"formato da saída: tsv (padrão), json, table ou markdown"`
}

type execToolArgs struct {
	SQL    string `json:"sql" jsonschema:"um único INSERT, UPDATE ou DELETE, com WHERE (UPDATE/DELETE) e lista de colunas (INSERT)"`
	DryRun *bool  `json:"dry_run,omitempty" jsonschema:"true (padrão): executa, informa as linhas afetadas e desfaz. false: executa de verdade; só funciona se o servidor foi iniciado com --allow-exec"`
	Format string `json:"format,omitempty" jsonschema:"formato da saída: tsv (padrão), json, table ou markdown"`
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
			return s.run("describe", "", func(e *env) error { return (&describeCmd{Table: a.Table, Sample: a.Sample}).Run(e) }), nil, nil
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
	for _, q := range p.Queries {
		s.addNamedQuery(srv, q)
	}
	s.addResources(srv)
	if p.HasWrite() {
		desc := "Executa INSERT, UPDATE ou DELETE com teto de linhas afetadas; acima do teto o Crivo desfaz tudo. Sempre chame com dry_run=true primeiro e mostre ao usuário o SQL e as linhas afetadas."
		switch {
		case p.ApprovalWrites:
			desc += " Com dry_run=false a escrita NÃO é feita: ela fica pendente e o retorno traz o id; só o usuário aprova, no terminal, com " + p.Name + " approve <id>."
		case s.allowExec:
			desc += " Com dry_run=false a escrita é real e só deve acontecer depois da confirmação explícita do usuário."
		default:
			desc += " Neste servidor a escrita real está desligada: dry_run=false é recusado."
		}
		mcp.AddTool(srv, &mcp.Tool{Name: "exec", Description: desc,
			Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)}},
			func(_ context.Context, _ *mcp.CallToolRequest, a execToolArgs) (*mcp.CallToolResult, any, error) {
				dry := a.DryRun == nil || *a.DryRun
				if !dry && !s.allowExec && !p.ApprovalWrites {
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
					c := &execCmd{DryRun: switchFlag(dry)}
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
	case "tsv", "json", "table", "markdown":
		f = output.Format(format)
	default:
		return errorResult(output.Message{Title: "configuração", Reason: fmt.Sprintf("format %q inválido", format), Accepted: "tsv, json, table ou markdown", Code: output.ExitConfig})
	}
	var out, errs bytes.Buffer
	e := &env{p: s.p, stdout: &out, stderr: &errs, format: f, via: "mcp:"}
	e.sess = cli.NewSession(s.p, &errs)
	defer e.sess.Close()

	err := fn(e)
	res := &mcp.CallToolResult{}
	text := out.String()
	var pend *cli.PendingError
	if errors.As(err, &pend) {
		err = nil // pendência não é erro: o texto já explica o próximo passo
	}
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

// addResources expõe a política e o guia (skill com as colunas permitidas)
// como recursos, para o cliente carregar como contexto sem gastar uma chamada.
func (s *mcpServer) addResources(srv *mcp.Server) {
	p := s.p
	policyURI := "crivo://" + p.Name + "/policy"
	srv.AddResource(&mcp.Resource{URI: policyURI, Name: p.Name + "-policy", MIMEType: "text/plain",
		Description: "A política desta base, com números de linha (o que a IA pode ler e escrever)."},
		func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: policyURI, MIMEType: "text/plain", Text: p.Numbered()}}}, nil
		})
	guideURI := "crivo://" + p.Name + "/guide"
	srv.AddResource(&mcp.Resource{URI: guideURI, Name: p.Name + "-guide", MIMEType: "text/markdown",
		Description: "Guia de uso desta base: regras, máscaras e as colunas permitidas de cada tabela."},
		func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			var errs bytes.Buffer
			e := &env{p: p, stderr: &errs}
			e.sess = cli.NewSession(p, &errs)
			defer e.sess.Close()
			if err := e.gate(); err != nil {
				return nil, err
			}
			sc, err := e.sess.LoadSchema(cli.SchemaFresh)
			if err != nil {
				return nil, fmt.Errorf("schema indisponível: %v", err)
			}
			text, err := skill.Generate(p, skill.Options{Bin: p.Name, WithSchema: true, Schema: sc})
			if err != nil {
				return nil, err
			}
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: guideURI, MIMEType: "text/markdown", Text: text}}}, nil
		})
}

// addNamedQuery expõe a consulta nomeada como ferramenta própria, com os
// parâmetros tipados no schema de entrada.
func (s *mcpServer) addNamedQuery(srv *mcp.Server, q *policy.NamedQuery) {
	props := map[string]any{}
	var required []string
	for _, p := range q.Params {
		prop := map[string]any{"description": p.Name}
		switch p.Type {
		case policy.ParamInt:
			prop["type"] = "integer"
		case policy.ParamNumeric:
			prop["type"] = "number"
		case policy.ParamBool:
			prop["type"] = "boolean"
		case policy.ParamDate:
			prop["type"], prop["format"] = "string", "date"
		default:
			prop["type"] = "string"
		}
		props[p.Name] = prop
		required = append(required, p.Name)
	}
	schema := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	desc := q.Doc
	if desc == "" {
		desc = "Consulta pronta da política."
	}
	desc += " Passa pelas mesmas regras e máscaras de query."
	srv.AddTool(&mcp.Tool{Name: "q_" + q.Name, Description: desc, InputSchema: schema,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)}},
		func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			values, err := namedArgs(req.Params.Arguments)
			if err != nil {
				return errorResult(output.Message{Title: "configuração", Reason: err.Error(), Code: output.ExitConfig}), nil
			}
			return s.run("run", "", func(e *env) error { return e.runNamed(q, values) }), nil
		})
}

// namedArgs converte os argumentos JSON em texto, sem notação científica.
func namedArgs(raw json.RawMessage) (map[string]string, error) {
	out := map[string]string{}
	if len(raw) == 0 {
		return out, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("argumentos inválidos: %v", err)
	}
	for k, v := range m {
		switch x := v.(type) {
		case string:
			out[k] = x
		case json.Number:
			out[k] = x.String()
		case bool:
			out[k] = strconv.FormatBool(x)
		default:
			return nil, fmt.Errorf("parâmetro %s precisa ser texto, número ou booleano", k)
		}
	}
	return out, nil
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
		switch {
		case p.ApprovalWrites:
			w(". Mesmo assim a escrita fica pendente: passe ao usuário o id do retorno; só ele aprova, no terminal, com %s approve <id>. Nunca tente aprovar você mesmo.\n", p.Name)
		case s.allowExec:
			w(".\n")
		default:
			w(" (neste servidor a escrita real está desligada; só o usuário pode ligá-la com --allow-exec).\n")
		}
	}
	w("\nNunca tente acessar o banco por outro caminho, ler a senha, alterar a política ou dividir uma operação recusada em várias menores.\n")
	return b.String()
}

package integration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestMain sobe um Postgres descartável quando CRIVO_TEST_LOCALPG=1 e não há
// CRIVO_TEST_DSN: initdb numa pasta temporária, só em 127.0.0.1 numa porta
// livre, sem socket unix. Ele é parado pelo pg_ctl daquela pasta (nunca por
// nome de processo) antes do os.Exit, que não roda defers.
func TestMain(m *testing.M) {
	stop, err := localPostgres()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Postgres local: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

func localPostgres() (stop func(), err error) {
	stop = func() {}
	if os.Getenv("CRIVO_TEST_DSN") != "" || os.Getenv("CRIVO_TEST_LOCALPG") != "1" {
		return stop, nil
	}
	initdb, err := exec.LookPath("initdb")
	if err != nil {
		return stop, fmt.Errorf("CRIVO_TEST_LOCALPG=1 pede initdb e pg_ctl no PATH: %w", err)
	}
	pgctl := filepath.Join(filepath.Dir(initdb), "pg_ctl")
	dir, err := os.MkdirTemp("", "crivo-pg-")
	if err != nil {
		return stop, err
	}
	data := filepath.Join(dir, "data")
	cleanup := func() { _ = os.RemoveAll(dir) }
	// senha de verdade (scram), como no contêiner: trust aceitaria qualquer
	// senha e esconderia erro de autenticação nos testes
	pwfile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwfile, []byte("postgres\n"), 0o600); err != nil {
		cleanup()
		return stop, err
	}
	if out, err := pgCmd(initdb, "-D", data, "-U", "postgres", "--auth=scram-sha-256", "--pwfile="+pwfile, "-E", "UTF8", "--no-locale").CombinedOutput(); err != nil {
		cleanup()
		return stop, fmt.Errorf("initdb: %v\n%s", err, out)
	}
	port, err := freePort()
	if err != nil {
		cleanup()
		return stop, err
	}
	opts := fmt.Sprintf("-p %d -c listen_addresses=127.0.0.1 -c unix_socket_directories=''", port)
	logFile := filepath.Join(dir, "log")
	if out, err := pgCmd(pgctl, "-D", data, "-o", opts, "-l", logFile, "-w", "start").CombinedOutput(); err != nil {
		log, _ := os.ReadFile(logFile)
		cleanup()
		return stop, fmt.Errorf("pg_ctl start: %v\n%s\n%s", err, out, log)
	}
	stop = func() {
		_ = pgCmd(pgctl, "-D", data, "-m", "immediate", "-w", "stop").Run()
		cleanup()
	}
	os.Setenv("CRIVO_TEST_DSN", fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres?sslmode=disable", port))
	return stop, nil
}

// pgCmd roda um binário do Postgres com localidade C: no macOS, a localidade
// do sistema faz o postmaster virar multithread na partida e recusar subir.
func pgCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	return cmd
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

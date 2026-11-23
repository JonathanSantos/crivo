//go:build !windows && !plan9

package audit

import "log/syslog"

// toSyslog envia a linha de auditoria ao syslog local (facility LOCAL0, nível
// notice: o macOS descarta info do syslog antigo por padrão).
func toSyslog(line []byte) error {
	w, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_LOCAL0, "crivo")
	if err != nil {
		return err
	}
	defer w.Close()
	return w.Notice(string(line))
}

//go:build windows || plan9

package audit

import "errors"

func toSyslog([]byte) error {
	return errors.New("syslog não existe neste sistema; o log em arquivo continua")
}

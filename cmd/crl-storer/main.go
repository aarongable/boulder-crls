package notmain

import "github.com/letsencrypt/boulder/cmd"

type Config struct {
	CRLStorer struct {
		cmd.ServiceConfig
		Features map[string]bool
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
}

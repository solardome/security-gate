package securitygate

import enginereport "github.com/solardome/security-gate/internal/report"

type auditLogger struct {
	delegate *enginereport.AuditLogger
}

func newAuditLogger(path string) (*auditLogger, error) {
	l, err := enginereport.NewAuditLogger(path)
	if err != nil {
		return nil, err
	}
	return &auditLogger{delegate: l}, nil
}

func (l *auditLogger) close() {
	if l == nil || l.delegate == nil {
		return
	}
	l.delegate.Close()
}

func (l *auditLogger) info(event string, fields map[string]interface{}) {
	if l == nil || l.delegate == nil {
		return
	}
	l.delegate.Info(event, fields)
}

func (l *auditLogger) warn(event string, fields map[string]interface{}) {
	if l == nil || l.delegate == nil {
		return
	}
	l.delegate.Warn(event, fields)
}

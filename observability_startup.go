package main

// observability_startup.go — startup-time loader for the
// observability slice (P4.3 / S1). Mirrors the pre-extraction body
// of initObservability (main.go:539–579) byte-for-byte except
// parameterized.
//
// Behaviour invariants preserved:
//   - Each of the four sub-blocks (syslog, OTLP, audit log, request
//     log) is independently guarded and skipped when its config
//     field is empty.
//   - Every error path logs and continues — startup never aborts on
//     an observability failure.
//   - Log strings are unchanged so operators see the same startup
//     banner and the same fallback warnings.
//   - syslogConfigured is set to cfg.SyslogAddr only after a
//     successful InitSyslog. Preserves the dual-write contract with
//     admin_settings.go:140 — the admin API readback at
//     admin_settings.go:242–243 sees the same initial value as
//     before.
//   - globalOTLP and globalOTLPTraces both receive Configure when
//     OTLPEndpoint is non-empty. Their internal goroutine lifecycles
//     are unchanged — out of scope for the slice.
//   - The audit-log file handle on auditCloser, the request-log
//     file handle on requestLogCloser, and the syslog conn on
//     globalSyslog continue to be read by the existing shutdown
//     hooks (syslog-close, request-log-close, audit-log-close at
//     orders 110 / 130 / 135). No carry to startupState.

// loadObservability applies cfg to the observability subsystems.
// Void return — closers stay on their package globals and are
// consumed directly by the shutdown registry.
func loadObservability(cfg observabilityStartupConfig) {
	if cfg.SyslogAddr != "" {
		if err := InitSyslog(cfg.SyslogAddr, cfg.SyslogFormat); err != nil {
			logger.Printf("Syslog: connect failed (%v) — continuing without syslog", err)
		} else {
			syslogConfigured = cfg.SyslogAddr
		}
	}

	if cfg.OTLPEndpoint != "" {
		globalOTLP.Configure(cfg.OTLPEndpoint, nil)
		globalOTLPTraces.Configure(cfg.OTLPEndpoint, nil)
	}

	if cfg.AuditLogPath != "" {
		if err := InitAuditLog(cfg.AuditLogPath); err != nil {
			logger.Printf("Audit: log file error (%v) — falling back to in-memory", err)
		} else {
			logger.Printf("Audit: persisting to %s", cfg.AuditLogPath)
		}
	}

	if cfg.RequestLogPath != "" {
		if err := initRequestLog(cfg.RequestLogPath, cfg.RequestLogMaxMB); err != nil {
			logger.Printf("RequestLog: file error (%v) — falling back to in-memory only", err)
		} else {
			logger.Printf("RequestLog: persisting to %s (max %d MB)", cfg.RequestLogPath, cfg.RequestLogMaxMB)
		}
	}
}

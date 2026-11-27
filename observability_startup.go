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
//   - syslogConfigured is set to cfg.SyslogAddr only on a successful
//     InitSyslog — but by InitSyslog itself, inside the same critical
//     section that publishes the writer, so the two can never disagree
//     (Codex P2, PR #1494). Callers record only the INTENT beforehand,
//     which is what survives a dial that produces no writer. Read both
//     through syslogConfiguredSnapshot(), never off the variables.
//   - globalOTLP and globalOTLPTraces both receive Configure when
//     OTLPEndpoint is non-empty. Their internal goroutine lifecycles
//     are unchanged — out of scope for the slice.
//   - The audit-log file handle (internal/audit), the request-log
//     file handle (internal/reqlog), and the syslog conn on
//     globalSyslogHandle continue to be released by the existing shutdown
//     hooks (syslog-close, request-log-close, audit-log-close at
//     orders 110 / 130 / 135). No carry to startupState.

// loadObservability applies cfg to the observability subsystems.
// Void return — closers stay on their package globals and are
// consumed directly by the shutdown registry.
func loadObservability(cfg observabilityStartupConfig) {
	if cfg.SyslogAddr != "" {
		// Record intent regardless of Init's outcome (see syslogConfiguredAddr)
		// so checkSyslogFeed can distinguish an intentional no-SIEM setup from a
		// configured feed that silently failed to connect at startup.
		noteSyslogConfiguredIntent(cfg.SyslogAddr)
		// Same intent, recorded where the health plane can read it under a
		// mutex (CHAOS-81 P1-F): without it a failed dial exports no
		// culvert_syslog_* series at all, so the documented
		// `culvert_syslog_up == 0` paging rule cannot fire for a feed that
		// never came up.
		noteSyslogIntent(cfg.SyslogAddr)
		// On success InitSyslog publishes syslogConfigured with the writer, in
		// one critical section; the intent recorded above is what survives a
		// dial that never produces one.
		if err := InitSyslog(cfg.SyslogAddr, cfg.SyslogFormat); err != nil {
			// The dial that noteSyslogIntent opened a grace for has returned:
			// the intent is unmet NOW, so every read surface may say so
			// without waiting the grace out.
			noteSyslogDialResolved()
			logger.Printf("Syslog: connect failed (%v) — continuing without syslog; the connection is retried automatically in the background", err)
			// The intent stands and this dial is safe to repeat: hand it to
			// the background retry so a collector that was merely late (or
			// unresolvable while DNS was still coming up) does not stay dark
			// until an operator re-saves the target or restarts the node.
			armSyslogIntentRetry(cfg.SyslogAddr, cfg.SyslogFormat)
		}
	}

	if cfg.OTLPEndpoint != "" {
		// One transition for the pair (CHAOS-130).
		configureOTLPPair(cfg.OTLPEndpoint, nil)
	}

	if cfg.AuditLogPath != "" {
		// Recorded regardless of Init's outcome (see auditLogConfiguredPath)
		// so GET /api/stats can tell an intentional in-memory-only setup
		// apart from a configured path that silently failed to open.
		auditLogConfiguredPath = cfg.AuditLogPath
		if err := InitAuditLog(cfg.AuditLogPath); err != nil {
			// CWE-117: the error text embeds the operator-configured path and,
			// for a wrapped syscall error, arbitrary OS-supplied bytes. Same
			// barrier the retry path 15 lines downstream already applies
			// (request_log_persist_retry.go) and that internal/audit states for
			// this exact value.
			logger.Printf("Audit: log file error (%q) — falling back to in-memory", sanitizeLog(err.Error()))
			// The configured path stays the operator's intent: the
			// background-services slice re-attempts it and the entries
			// recorded meanwhile are kept for it (audit_persist_retry.go).
			armAuditDeferredOpen(cfg.AuditLogPath)
		} else {
			logger.Printf("Audit: persisting to %q", sanitizeLog(cfg.AuditLogPath))
		}
	}

	if cfg.RequestLogPath != "" {
		requestLogConfiguredPath = cfg.RequestLogPath
		if err := initRequestLog(cfg.RequestLogPath, cfg.RequestLogMaxMB); err != nil {
			logger.Printf("RequestLog: file error (%q) — falling back to in-memory only", sanitizeLog(err.Error()))
			// The configured path stays the operator's intent: the
			// background-services slice re-attempts it with the same
			// rotation size (request_log_persist_retry.go).
			armRequestLogDeferredOpen(cfg.RequestLogPath, cfg.RequestLogMaxMB)
		} else {
			logger.Printf("RequestLog: persisting to %q (max %d MB)", sanitizeLog(cfg.RequestLogPath), cfg.RequestLogMaxMB)
		}
	}
}

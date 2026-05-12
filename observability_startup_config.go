package main

// observability_startup_config.go — resolved config for the
// observability startup slice (P4.3 / S1): syslog forwarding, OTLP
// metrics + traces, persistent audit log, persistent request log.
// Pure DTO + a single side-effect-free resolver invoked from the
// initObservability shim. No globals are read or written here.

// observabilityStartupConfig carries the resolved inputs for the
// four observability subsystems configured at startup. The loader
// consumes this struct and owns the side effects on globalSyslog,
// syslogConfigured, globalOTLP, globalOTLPTraces, and the persistent
// audit / request log file handles.
type observabilityStartupConfig struct {
	// SyslogAddr is the syslog forwarder target ("udp://host:port",
	// "tcp://host:port", or "host:port" — UDP default). "" disables
	// syslog forwarding entirely.
	SyslogAddr string

	// SyslogFormat is the message wire format. "" lets InitSyslog
	// pick its documented default ("rfc3164"). Other accepted value
	// is "rfc5424".
	SyslogFormat string

	// OTLPEndpoint is the OpenTelemetry collector base URL. ""
	// disables both metrics and trace export. Configuring a non-
	// empty endpoint spawns the OTLP push-loop goroutines (managed
	// internally by globalOTLP / globalOTLPTraces — out of scope
	// for the slice).
	OTLPEndpoint string

	// AuditLogPath is the persistent JSONL audit log file. ""
	// keeps the audit log in-memory only (ring buffer still
	// active).
	AuditLogPath string

	// RequestLogPath is the persistent JSONL request log file. ""
	// keeps the request log in-memory only (ring buffer still
	// active).
	RequestLogPath string

	// RequestLogMaxMB is the rotation size for the request log
	// file. Resolver applies a default of 100 when both the CLI
	// flag and FileConfig value are zero.
	RequestLogMaxMB int
}

// resolveObservabilityStartupConfig is the single startup-time
// reader of fc.Syslog* / fc.OTLPEndpoint / fc.AuditLogFile /
// fc.RequestLogFile / fc.RequestLogMaxMB combined with their CLI
// flag overrides. None of the six inputs are pre-resolved into
// startupState derived fields today, so the resolver applies the
// firstStr / firstNonZero precedence inline — mirroring the GeoIP
// pilot.
//
// Pure and deterministic; safe on a zero-value *FileConfig.
func resolveObservabilityStartupConfig(
	fc *FileConfig,
	cliSyslogAddr, cliSyslogFormat, cliOTLPEndpoint,
	cliAuditLog, cliRequestLogPath string,
	cliRequestLogMaxMB int,
) observabilityStartupConfig {
	return observabilityStartupConfig{
		SyslogAddr:      firstStr(cliSyslogAddr, fc.SyslogAddr),
		SyslogFormat:    firstStr(cliSyslogFormat, fc.SyslogFormat),
		OTLPEndpoint:    firstStr(cliOTLPEndpoint, fc.OTLPEndpoint),
		AuditLogPath:    firstStr(cliAuditLog, fc.AuditLogFile),
		RequestLogPath:  firstStr(cliRequestLogPath, fc.RequestLogFile),
		RequestLogMaxMB: firstNonZero(cliRequestLogMaxMB, fc.RequestLogMaxMB, 100),
	}
}

/*
 * SPDX-FileCopyrightText: © 2017-2025 Istari Digital, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package badger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// Logger is implemented by any logging system that is used for standard logs.
type Logger interface {
	Errorf(string, ...interface{})
	Warningf(string, ...interface{})
	Infof(string, ...interface{})
	Debugf(string, ...interface{})
}

// Errorf logs an ERROR log message to the logger specified in opts or to the
// global logger if no logger is specified in opts.
func (opt *Options) Errorf(format string, v ...interface{}) {
	if opt.Logger == nil {
		return
	}
	opt.Logger.Errorf("%s", logLine(format, v...))
}

// Infof logs an INFO message to the logger specified in opts.
func (opt *Options) Infof(format string, v ...interface{}) {
	if opt.Logger == nil {
		return
	}
	opt.Logger.Infof("%s", logLine(format, v...))
}

// Warningf logs a WARNING message to the logger specified in opts.
func (opt *Options) Warningf(format string, v ...interface{}) {
	if opt.Logger == nil {
		return
	}
	opt.Logger.Warningf("%s", logLine(format, v...))
}

// Debugf logs a DEBUG message to the logger specified in opts.
func (opt *Options) Debugf(format string, v ...interface{}) {
	if opt.Logger == nil {
		return
	}
	opt.Logger.Debugf("%s", logLine(format, v...))
}

// logLine renders a log message with CR/LF escaped. CULVERT PATCH (scanner):
// keys and values reach these messages (e.g. "Unable to read: Key: %v"), so a
// key carrying a newline could forge a log line (CWE-117).
func logLine(format string, v ...interface{}) string {
	s := fmt.Sprintf(format, v...)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, "\r", `\r`)
}

type loggingLevel int

const (
	DEBUG loggingLevel = iota
	INFO
	WARNING
	ERROR
)

type defaultLog struct {
	*log.Logger
	level loggingLevel
}

func defaultLogger(level loggingLevel) *defaultLog {
	return &defaultLog{Logger: log.New(os.Stderr, "badger ", log.LstdFlags), level: level}
}

func (l *defaultLog) Errorf(f string, v ...interface{}) {
	if l.level <= ERROR {
		l.Printf("ERROR: "+f, v...)
	}
}

func (l *defaultLog) Warningf(f string, v ...interface{}) {
	if l.level <= WARNING {
		l.Printf("WARNING: "+f, v...)
	}
}

func (l *defaultLog) Infof(f string, v ...interface{}) {
	if l.level <= INFO {
		l.Printf("INFO: "+f, v...)
	}
}

func (l *defaultLog) Debugf(f string, v ...interface{}) {
	if l.level <= DEBUG {
		l.Printf("DEBUG: "+f, v...)
	}
}

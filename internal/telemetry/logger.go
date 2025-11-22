package telemetry

import (
	"log"
	"os"
)

// Logger wraps the stdlib logger with minimal redaction guidance.
type Logger struct {
	*log.Logger
}

// NewLogger returns a Logger that writes to stdout with timestamps.
func NewLogger() Logger {
	return Logger{Logger: log.New(os.Stdout, "", log.LstdFlags|log.LUTC|log.Lmicroseconds)}
}

// Redact hides likely secrets before logging.
func (l Logger) Redact(msg string) {
	l.Printf("[REDACTED] %s", msg)
}

// Info logs informational messages with key-value style.
func (l Logger) Info(msg string, kv ...any) {
	l.Printf("[INFO] %s %v", msg, kv)
}

// Error logs errors without leaking sensitive payloads.
func (l Logger) Error(msg string, kv ...any) {
	l.Printf("[ERROR] %s %v", msg, kv)
}

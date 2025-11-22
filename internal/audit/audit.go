package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Event represents a security-relevant action for audit logging.
type Event struct {
	Time          time.Time         `json:"time"`
	Actor         string            `json:"actor,omitempty"`
	Action        string            `json:"action"`
	Resource      string            `json:"resource,omitempty"`
	Result        string            `json:"result"`
	IP            string            `json:"ip,omitempty"`
	UserAgent     string            `json:"user_agent,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
}

// Logger writes audit events in JSON lines.
type Logger struct {
	w io.Writer
}

// NewLogger initializes an audit logger writing to the given writer.
func NewLogger(w io.Writer) *Logger {
	return &Logger{w: w}
}

// Log writes an audit event; caller must redact PII in metadata.
func (l *Logger) Log(ev Event) error {
	ev.Time = ev.Time.UTC()
	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal audit: %w", err)
	}
	_, err = l.w.Write(append(b, '\n'))
	return err
}

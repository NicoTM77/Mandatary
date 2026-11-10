package authz

import (
	"fmt"
	"io"
	"log/slog"
)

// Returned authorization handles retain private verification material. Redact at
// the containing type boundary: fmt does not invoke nested credential methods
// when reflecting over an unexported field (including with %#v).
func (Decision) String() string               { return "Decision{[REDACTED]}" }
func (d Decision) GoString() string           { return d.String() }
func (d Decision) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, d.String()) }
func (d Decision) LogValue() slog.Value       { return slog.StringValue(d.String()) }

func (*Lease) String() string               { return "Lease{[REDACTED]}" }
func (l *Lease) GoString() string           { return l.String() }
func (l *Lease) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, l.String()) }
func (l *Lease) LogValue() slog.Value       { return slog.StringValue(l.String()) }

// Package log is yardstick's logger, set once by the CLI from clio's. Info names the high-level
// actions a run takes, debug the lower-level detail behind them, and trace timings and verbose
// output.
package log

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/discard"
)

var log = discard.New()

func Set(l logger.Logger) {
	log = l
}

func Get() logger.Logger {
	return log
}

func Errorf(format string, args ...any) { log.Errorf(format, escaped(args)...) }
func Warnf(format string, args ...any)  { log.Warnf(format, escaped(args)...) }
func Infof(format string, args ...any)  { log.Infof(format, escaped(args)...) }
func Debugf(format string, args ...any) { log.Debugf(format, escaped(args)...) }
func Tracef(format string, args ...any) { log.Tracef(format, escaped(args)...) }

// Timed logs how long a step took at trace level. Use it as `defer log.Timed("scan %s", name)()`.
func Timed(format string, args ...any) func() {
	start := time.Now()
	return func() {
		log.WithFields("elapsed", time.Since(start).Round(time.Millisecond)).Tracef(format, escaped(args)...)
	}
}

// escaped makes every argument write a CR or LF in it (a path, a gate name, a request field) as \r
// or \n, so an argument can't start a log line of its own. The format string is the caller's own
// and is left alone. Numbers and bools can't hold either and stay as they are, since the redacting
// logger clio installs passes those through and turns anything else into a string.
func escaped(args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case string:
			out[i] = escape(v)
		case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
			out[i] = v
		default:
			out[i] = escapedArg{v}
		}
	}
	return out
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "\r", `\r`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

// escapedArg formats its value with the verb and flags it is formatted with, then escapes it.
type escapedArg struct{ v any }

func (e escapedArg) Format(f fmt.State, verb rune) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, fmt.FormatString(f, verb), e.v)
	_, _ = f.Write([]byte(escape(buf.String())))
}

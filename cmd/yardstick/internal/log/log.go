// Package log is yardstick's logger, set once by the CLI from clio's. Info names the high-level
// actions a run takes, debug the lower-level detail behind them, and trace timings and verbose
// output.
package log

import (
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

func Errorf(format string, args ...any) { log.Errorf("%s", escaped(format, args...)) }
func Warnf(format string, args ...any)  { log.Warnf("%s", escaped(format, args...)) }
func Infof(format string, args ...any)  { log.Infof("%s", escaped(format, args...)) }
func Debugf(format string, args ...any) { log.Debugf("%s", escaped(format, args...)) }
func Tracef(format string, args ...any) { log.Tracef("%s", escaped(format, args...)) }

// Timed logs how long a step took at trace level. Use it as `defer log.Timed("scan %s", name)()`.
func Timed(format string, args ...any) func() {
	start := time.Now()
	return func() {
		log.WithFields("elapsed", time.Since(start).Round(time.Millisecond)).Tracef("%s", escaped(format, args...))
	}
}

// escaped formats the whole message and writes any CR or LF in it (from a path, a gate name, a
// request field) as \r or \n, so nothing logged can start a log line of its own. Escaping the
// finished message rather than each argument keeps the sanitizer a plain strings.ReplaceAll,
// which is what CodeQL's log injection check recognizes.
func escaped(format string, args ...any) string {
	s := fmt.Sprintf(format, args...)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

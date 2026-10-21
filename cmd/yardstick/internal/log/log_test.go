package log

import (
	"errors"
	"fmt"
	"testing"
)

func TestEscaped(t *testing.T) {
	type name string
	tests := []struct {
		format string
		args   []any
		want   string
	}{
		{"gate %s", []any{"a\nINFO forged"}, `gate a\nINFO forged`},
		{"gate %s", []any{"a\r\nb"}, `gate a\r\nb`},
		// a string is escaped before %q sees it, so %q shows the escape itself escaped
		{"gate %q", []any{"a\r\nb"}, `gate "a\\r\\nb"`},
		{"gate %s", []any{name("x\ny")}, `gate x\ny`},
		{"err: %v", []any{errors.New("bad\nline")}, `err: bad\nline`},
		{"%v", []any{[]string{"a\nb", "c"}}, `[a\nb c]`},
		// the caller's width, precision and flags still apply
		{"%5d|%-4s|%.2f", []any{42, "ab", 1.5}, "   42|ab  |1.50"},
		{"line one\nline two %s", []any{"x"}, "line one\nline two x"},
	}
	for _, tt := range tests {
		got := fmt.Sprintf(tt.format, escaped(tt.args)...)
		if got != tt.want {
			t.Errorf("Sprintf(%q, %q) = %q, want %q", tt.format, tt.args, got, tt.want)
		}
	}
}

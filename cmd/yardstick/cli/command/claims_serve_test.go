package command

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// the label server listens only on loopback, and says so with an address LocalOnly allows
func TestServeListensOnLoopbackOnly(t *testing.T) {
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, addr := range []string{"0.0.0.0:0", ":0"} {
		if err := serve(context.Background(), &cobra.Command{}, addr, false, ok); err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("%s: expected refused, got %v", addr, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := serve(ctx, cmd, "127.0.0.1:0", false, ok); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "http://127.0.0.1:") {
		t.Errorf("expected a 127.0.0.1 URL, got %q", out.String())
	}
}

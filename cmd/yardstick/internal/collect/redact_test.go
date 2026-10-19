package collect

import "testing"

func TestRedact(t *testing.T) {
	log := []byte("auth hunter2 db https://bob:s3@cret@mirror.example/db token abc123 keep public")
	got := string(redact(log, []string{"GRYPE_REGISTRY_AUTH_USERNAME=hunt", "GRYPE_REGISTRY_AUTH_PASSWORD=hunter2", "GRYPE_REGISTRY_AUTH_AUTHORITY=abc123", "HOME=public"}))
	want := "auth ******* db https://*******@mirror.example/db token ******* keep public"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

package research

import (
	"os"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRenderLog(t *testing.T) {
	tests := []struct {
		name string
		log  []byte
		want string
	}{
		{
			name: "a stream's text, and the result once with its cost",
			log:  readFixture(t, "claude-stream.jsonl"),
			want: "started on claude-haiku-5-5\n\nok\n\n-- success: $0.00, 1 turns, 1s\n",
		},
		{
			name: "a tool use is one line and its result is trimmed",
			log:  readFixture(t, "claude-stream-tool.jsonl"),
			want: "started on claude-haiku-5-5\n\n> Bash: seq 1 8\n    1\n    2\n    3\n    4\n    ... 4 more lines\n\ndone\n\n-- success: $0.00, 2 turns, 4s\n",
		},
		{
			name: "json mode's one result object is its text and cost",
			log:  readFixture(t, "claude-result.json"),
			want: "ok\n\n-- success: $0.00, 1 turns, 2s\n",
		},
		{
			name: "stderr among events stays, and an event still being written is left out",
			log:  []byte("warning: slow\n" + `{"type":"assistant","message":{"content":[{"type":"text","text":"looking"}]}}` + "\n" + `{"type":"user","message":{"con`),
			want: "warning: slow\nlooking\n\n",
		},
		{
			name: "a log with no claude event is as it was",
			log:  []byte("args: -p x\n{\"row\":\"a\"}\nno newline"),
			want: "args: -p x\n{\"row\":\"a\"}\nno newline",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(RenderLog(tt.log)); got != tt.want {
				t.Errorf("expected\n%q\ngot\n%q", tt.want, got)
			}
		})
	}
}

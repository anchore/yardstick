package research

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// event is the part of one claude stream-json line (or json mode's whole output) RenderLog reads.
type event struct {
	result
	Subtype string `json:"subtype"`
	Model   string `json:"model"` // on the init event
	Result  string `json:"result"`
	IsError bool   `json:"is_error"`
	Message struct {
		Content json.RawMessage `json:"content"` // blocks, or a plain string
	} `json:"message"`
}

type block struct {
	Type    string          `json:"type"`
	Text    string          `json:"text"`
	Name    string          `json:"name"`
	Input   map[string]any  `json:"input"`
	Content json.RawMessage `json:"content"` // a tool result's: a string, or text blocks
	IsError bool            `json:"is_error"`
}

// the input a tool use is shown by, first one present wins
var toolKeys = []string{"command", "url", "file_path", "path", "pattern", "query", "skill", "description", "prompt"}

const (
	resultLines = 4   // tool result lines kept
	lineWidth   = 240 // characters kept of any one line
)

// RenderLog is a job's log as text a person reads, when claude wrote it as JSON: the agent's text,
// one line per tool use, tool results trimmed, and the result with what it cost. A log with no
// claude event in it (another command, or plain output) comes back as it is, and a non-JSON line
// among events (stderr shares the log) is kept in place.
func RenderLog(data []byte) []byte {
	var out bytes.Buffer
	seen := false
	last := "" // the agent's last text, which a stream's result repeats
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	for i, line := range lines {
		var e event
		if !bytes.HasPrefix(line, []byte("{")) || json.Unmarshal(line, &e) != nil {
			// a running job's last line can be an event still being written
			if i == len(lines)-1 && !bytes.HasSuffix(data, []byte("\n")) && bytes.HasPrefix(line, []byte("{")) {
				continue
			}
			out.Write(line)
			out.WriteByte('\n')
			continue
		}
		switch e.Type {
		case "system":
			seen = true
			if e.Subtype == "init" {
				fmt.Fprintf(&out, "started on %s\n\n", e.Model)
			}
		case "assistant", "user":
			seen = true
			last = writeMessage(&out, e.Message.Content, last)
		case "result":
			seen = true
			if text := strings.TrimSpace(e.Result); text != "" && text != last {
				fmt.Fprintf(&out, "%s\n\n", text)
			}
			state := e.Subtype
			if e.IsError && state == "success" {
				state = "error"
			}
			fmt.Fprintf(&out, "-- %s: $%.2f, %d turns, %.0fs\n", state, e.TotalCostUSD, e.NumTurns, float64(e.DurationMs)/1000)
		case "":
			out.Write(line) // JSON, but not claude's
			out.WriteByte('\n')
		}
	}
	if !seen {
		return data
	}
	return out.Bytes()
}

// writeMessage writes a message's text, tool uses and tool results, and returns its last text
func writeMessage(out *bytes.Buffer, content json.RawMessage, last string) string {
	var blocks []block
	if json.Unmarshal(content, &blocks) != nil {
		return last // a plain string is the prompt
	}
	for _, b := range blocks {
		switch b.Type {
		case "text":
			last = strings.TrimSpace(b.Text)
			fmt.Fprintf(out, "%s\n\n", last)
		case "tool_use":
			fmt.Fprintf(out, "> %s\n", clip(strings.Join(strings.Fields(b.Name+toolInput(b.Input)), " ")))
		case "tool_result":
			writeToolResult(out, b)
		}
	}
	return last
}

func toolInput(in map[string]any) string {
	for _, k := range toolKeys {
		if v, ok := in[k].(string); ok && v != "" {
			return ": " + v
		}
	}
	return ""
}

func writeToolResult(out *bytes.Buffer, b block) {
	var text string
	if json.Unmarshal(b.Content, &text) != nil {
		var parts []block
		_ = json.Unmarshal(b.Content, &parts)
		for _, p := range parts {
			text += p.Text
		}
	}
	text = strings.TrimRight(text, "\n")
	if text == "" && !b.IsError {
		return
	}
	lines := strings.Split(text, "\n")
	if b.IsError {
		lines[0] = "error: " + lines[0]
	}
	for i, l := range lines {
		if i == resultLines {
			fmt.Fprintf(out, "    ... %d more lines\n", len(lines)-i)
			break
		}
		fmt.Fprintf(out, "    %s\n", clip(l))
	}
	out.WriteByte('\n')
}

// clip is s cut to lineWidth runes
func clip(s string) string {
	if r := []rune(s); len(r) > lineWidth {
		return string(r[:lineWidth]) + "..."
	}
	return s
}

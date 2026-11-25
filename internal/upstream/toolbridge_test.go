package upstream

import (
	"encoding/json"
	"strings"
	"testing"
)

func runBridgeStreamChunked(input string, allowed map[string]bool, chunkSize int) (string, []ToolCall) {
	var out strings.Builder
	bs := NewBridgeStream(allowed, func(s string) { out.WriteString(s) })
	for i := 0; i < len(input); i += chunkSize {
		end := i + chunkSize
		if end > len(input) {
			end = len(input)
		}
		bs.Push(input[i:end])
	}
	calls := bs.Finish()
	return out.String(), calls
}

func assertCallsEqual(t *testing.T, label string, got, want []ToolCall) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d tool calls (%+v), want %d (%+v)", label, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i].Name != want[i].Name {
			t.Fatalf("%s: call[%d].Name = %q, want %q", label, i, got[i].Name, want[i].Name)
		}
		if got[i].Arguments != want[i].Arguments {
			t.Fatalf("%s: call[%d].Arguments = %q, want %q", label, i, got[i].Arguments, want[i].Arguments)
		}
	}
}

func TestToolBridgeClosingTagInsideJSONString(t *testing.T) {
	allowed := map[string]bool{"write_file": true, "bash": true}

	t.Run("literal_closing_tag_in_argument", func(t *testing.T) {
		code := `const closeTag = "</client_tool_call>"` + "\n" + `fmt.Println("end </client_tool_call> ok")`
		argsJSON, _ := marshalJSONNoEscape(map[string]any{"path": "toolbridge.go", "content": code}, false)
		input := `Updating file now. <client_tool_call>{"name":"write_file","arguments":` + string(argsJSON) + `}</client_tool_call>`

		clean, calls := ParseClientToolCalls(input, allowed)
		if clean != "Updating file now." {
			t.Fatalf("clean = %q, want %q", clean, "Updating file now.")
		}
		if len(calls) != 1 || calls[0].Name != "write_file" {
			t.Fatalf("unexpected calls: %+v", calls)
		}
		var parsed map[string]string
		if err := json.Unmarshal([]byte(calls[0].Arguments), &parsed); err != nil {
			t.Fatalf("arguments not valid JSON (%v): %q", err, calls[0].Arguments)
		}
		if parsed["content"] != code {
			t.Fatalf("content truncated or altered:\ngot : %q\nwant: %q", parsed["content"], code)
		}
	})

	t.Run("multiple_calls_with_closing_tag_and_extra_leading_key", func(t *testing.T) {
		input := `<client_tool_call>{"id":"c1","name":"write_file","arguments":{"content":"a \"</client_tool_call>\" {b}"}}</client_tool_call>` +
			"\n" +
			`<client_tool_call>{"name":"bash","arguments":{"cmd":"echo </client_tool_call>"}}</client_tool_call>`
		clean, calls := ParseClientToolCalls(input, allowed)
		if clean != "" {
			t.Fatalf("clean = %q, want empty", clean)
		}
		if len(calls) != 2 || calls[0].Name != "write_file" || calls[1].Name != "bash" {
			t.Fatalf("unexpected calls: %+v", calls)
		}
		if !strings.Contains(calls[0].Arguments, `</client_tool_call>`) || !strings.Contains(calls[1].Arguments, `</client_tool_call>`) {
			t.Fatalf("closing tag lost from arguments: %+v", calls)
		}
	})
}

func TestToolBridgeStrayProseMarkerDoesNotSwallowRealCall(t *testing.T) {
	allowed := map[string]bool{"bash": true, "read_file": true}

	cases := []struct {
		name         string
		input        string
		wantClean    string
		wantToolName string
		wantArgSub   string
	}{
		{
			name:         "prose_mentions_open_tag",
			input:        `Note that <client_tool_call> is the marker format. Let me run: <client_tool_call>{"name":"bash","arguments":{"cmd":"pwd"}}</client_tool_call>`,
			wantClean:    `Note that <client_tool_call> is the marker format. Let me run:`,
			wantToolName: "bash",
			wantArgSub:   `"pwd"`,
		},
		{
			name:         "placeholder_braces_before_real_call",
			input:        `Format: <client_tool_call>{...}</client_tool_call> Now calling: <client_tool_call>{"name":"read_file","arguments":{"path":"go.mod"}}</client_tool_call>`,
			wantClean:    `Format: <client_tool_call>{...}</client_tool_call> Now calling:`,
			wantToolName: "read_file",
			wantArgSub:   `"go.mod"`,
		},
		{
			name:         "unclosed_brace_prose_before_real_call",
			input:        `Broken example <client_tool_call>{not valid json here. Actual call: <client_tool_call>{"name":"bash","arguments":{"cmd":"ls"}}</client_tool_call>`,
			wantClean:    `Broken example <client_tool_call>{not valid json here. Actual call:`,
			wantToolName: "bash",
			wantArgSub:   `"ls"`,
		},
		{
			name:         "unclosed_json_string_before_real_call",
			input:        "Stray <client_tool_call>{\"unclosed\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"whoami\"}}</client_tool_call>",
			wantClean:    "Stray <client_tool_call>{\"unclosed",
			wantToolName: "bash",
			wantArgSub:   `"whoami"`,
		},
		{
			name:         "unknown_tool_kept_real_tool_extracted",
			input:        `<client_tool_call>{"name":"unknown_tool","arguments":{}}</client_tool_call> and <client_tool_call>{"name":"bash","arguments":{"cmd":"date"}}</client_tool_call>`,
			wantClean:    `<client_tool_call>{"name":"unknown_tool","arguments":{}}</client_tool_call> and`,
			wantToolName: "bash",
			wantArgSub:   `"date"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clean, calls := ParseClientToolCalls(tc.input, allowed)
			if clean != tc.wantClean {
				t.Fatalf("clean = %q, want %q", clean, tc.wantClean)
			}
			if len(calls) != 1 || calls[0].Name != tc.wantToolName || !strings.Contains(calls[0].Arguments, tc.wantArgSub) {
				t.Fatalf("unexpected calls: %+v", calls)
			}
		})
	}

	// Verify stray prose <client_tool_call> releases text incrementally during streaming.
	var streamed strings.Builder
	bs := NewBridgeStream(allowed, func(s string) { streamed.WriteString(s) })
	bs.Push("Use <client_tool_call> to invoke tools, then continue streaming.")
	if !strings.Contains(streamed.String(), "continue streaming") {
		t.Fatalf("expected stray prose marker to release before Finish, got %q", streamed.String())
	}
	if calls := bs.Finish(); len(calls) != 0 {
		t.Fatalf("expected no calls, got %+v", calls)
	}
}

func TestToolBridgeMarkdownFencesNotExecuted(t *testing.T) {
	allowed := map[string]bool{"bash": true}

	t.Run("fenced_examples_ignored", func(t *testing.T) {
		examples := []string{
			"Example:\n```xml\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"rm -rf /\"}}</client_tool_call>\n```\nDone.",
			"Example:\n```\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"id\"}}</client_tool_call>\n```",
			"Example:\n~~~json\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"id\"}}</client_tool_call>\n~~~",
			"Nested:\n````markdown\n```\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"id\"}}</client_tool_call>\n```\n````",
			"Unclosed fence:\n```xml\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"id\"}}</client_tool_call>",
			"```python\n{\"name\":\"bash\",\"arguments\":{\"cmd\":\"id\"}}\n```",
		}
		for i, input := range examples {
			clean, calls := ParseClientToolCalls(input, allowed)
			if len(calls) != 0 {
				t.Fatalf("case %d: fenced example must not execute, got calls=%+v", i, calls)
			}
			if clean != input {
				t.Fatalf("case %d: text altered:\ngot : %q\nwant: %q", i, clean, input)
			}
			sText, sCalls := runBridgeStreamChunked(input, allowed, 3)
			if len(sCalls) != 0 {
				t.Fatalf("case %d (stream): fenced example must not execute, got calls=%+v", i, sCalls)
			}
			if sText != input {
				t.Fatalf("case %d (stream): text altered:\ngot : %q\nwant: %q", i, sText, input)
			}
		}
	})

	t.Run("real_call_after_closed_fence_executes", func(t *testing.T) {
		input := "Here is an example:\n```xml\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"echo example\"}}</client_tool_call>\n```\nNow executing:\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"echo real\"}}</client_tool_call>"
		clean, calls := ParseClientToolCalls(input, allowed)
		if len(calls) != 1 || calls[0].Name != "bash" || !strings.Contains(calls[0].Arguments, "echo real") {
			t.Fatalf("expected only real call after fence, got %+v", calls)
		}
		if !strings.Contains(clean, "echo example") || strings.Contains(clean, "echo real") {
			t.Fatalf("cleaned text should preserve example and strip real call: %q", clean)
		}
	})
}

func TestBridgeStreamEarlyReleaseProbe(t *testing.T) {
	allowed := map[string]bool{"bash": true}

	earlyCases := []struct {
		name   string
		chunks []string
	}{
		{
			name:   "inline_backtick_prose",
			chunks: []string{"`", "foo` is a helper ", "that streams immediately."},
		},
		{
			name:   "non_json_code_fence",
			chunks: []string{"```", "go\n", "package main\n", "func main() {}\n```"},
		},
		{
			name:   "json_fence_non_tool_object",
			chunks: []string{"```json\n", `{"status":`, `"ok","count":42}`, "\n```"},
		},
		{
			name:   "plain_json_object_non_tool",
			chunks: []string{"{", `"status"`, `:"ok",`, `"items":[1,2,3]}`},
		},
		{
			name:   "plain_json_array_primitives",
			chunks: []string{"[", "1, 2, ", "3]"},
		},
		{
			name:   "plain_json_array_non_tool_objects",
			chunks: []string{"[", `{"id":`, `1,"title":"hello"}]`},
		},
	}

	for _, tc := range earlyCases {
		t.Run("early_release_"+tc.name, func(t *testing.T) {
			var streamed strings.Builder
			bs := NewBridgeStream(allowed, func(s string) { streamed.WriteString(s) })
			for _, c := range tc.chunks {
				bs.Push(c)
			}
			if streamed.Len() == 0 {
				t.Fatalf("expected streaming output BEFORE Finish(), but entire turn was buffered")
			}
			calls := bs.Finish()
			if len(calls) != 0 {
				t.Fatalf("expected 0 calls, got %+v", calls)
			}
			want := strings.Join(tc.chunks, "")
			if streamed.String() != want {
				t.Fatalf("streamed = %q, want %q", streamed.String(), want)
			}
		})
	}

	heldToolCases := []struct {
		name   string
		chunks []string
	}{
		{
			name:   "bare_json_tool_call",
			chunks: []string{"{", `"name"`, `:"bash","arguments":{"cmd":"ls"}}`},
		},
		{
			name:   "bare_array_tool_call",
			chunks: []string{"[", `{"name"`, `:"bash","arguments":{"cmd":"ls"}}]`},
		},
		{
			name:   "fenced_json_tool_call",
			chunks: []string{"```json\n", `{"name":`, `"bash","arguments":{"cmd":"ls"}}`, "\n```"},
		},
	}

	for _, tc := range heldToolCases {
		t.Run("held_tool_"+tc.name, func(t *testing.T) {
			var streamed strings.Builder
			bs := NewBridgeStream(allowed, func(s string) { streamed.WriteString(s) })
			for _, c := range tc.chunks {
				bs.Push(c)
			}
			if streamed.Len() != 0 {
				t.Fatalf("bare tool call leaked text before Finish(): %q", streamed.String())
			}
			calls := bs.Finish()
			if streamed.Len() != 0 {
				t.Fatalf("bare tool call emitted text on Finish(): %q", streamed.String())
			}
			if len(calls) != 1 || calls[0].Name != "bash" {
				t.Fatalf("expected bash tool call, got %+v", calls)
			}
		})
	}

	t.Run("held_non_tool_with_name_key_flushes_on_finish", func(t *testing.T) {
		input := `{"name":"Alice","age":30}`
		var streamed strings.Builder
		bs := NewBridgeStream(allowed, func(s string) { streamed.WriteString(s) })
		bs.Push(input)
		if streamed.Len() != 0 {
			t.Fatalf("expected {\"name\":...} to be held until Finish, got %q", streamed.String())
		}
		calls := bs.Finish()
		if len(calls) != 0 || streamed.String() != input {
			t.Fatalf("expected full text flush with 0 calls, got text=%q calls=%+v", streamed.String(), calls)
		}
	})
}

func TestToolBridgeXMLEntityToleranceAndNoHTMLEscape(t *testing.T) {
	allowed := map[string]bool{"bash": true, "write_file": true}

	t.Run("marked_call_with_xml_entities", func(t *testing.T) {
		input := `Running check: <client_tool_call>{&quot;name&quot;:&quot;bash&quot;,&quot;arguments&quot;:{&quot;cmd&quot;:&quot;echo &#39;a &lt; b &amp;&amp; c &gt; d&#39;&quot;}}</client_tool_call>`
		clean, calls := ParseClientToolCalls(input, allowed)
		if clean != "Running check:" {
			t.Fatalf("clean = %q, want %q", clean, "Running check:")
		}
		if len(calls) != 1 || calls[0].Name != "bash" {
			t.Fatalf("expected 1 bash call, got %+v", calls)
		}
		var args map[string]string
		if err := json.Unmarshal([]byte(calls[0].Arguments), &args); err != nil {
			t.Fatalf("invalid arguments JSON: %v (%q)", err, calls[0].Arguments)
		}
		wantCmd := "echo 'a < b && c > d'"
		if args["cmd"] != wantCmd {
			t.Fatalf("cmd = %q, want %q", args["cmd"], wantCmd)
		}
	})

	t.Run("marked_call_with_numeric_quote_entities_and_escaped_close_tag", func(t *testing.T) {
		input := `<client_tool_call>{&#34;name&#34;:&#34;write_file&#34;,&#34;arguments&#34;:{&#x22;content&#x22;:&#x22;&lt;/client_tool_call&gt; &amp; ok&#x22;}}</client_tool_call>`
		clean, calls := ParseClientToolCalls(input, allowed)
		if clean != "" || len(calls) != 1 || calls[0].Name != "write_file" {
			t.Fatalf("unexpected result: clean=%q calls=%+v", clean, calls)
		}
		var args map[string]string
		if err := json.Unmarshal([]byte(calls[0].Arguments), &args); err != nil {
			t.Fatalf("invalid arguments JSON: %v", err)
		}
		if args["content"] != "</client_tool_call> & ok" {
			t.Fatalf("content = %q, want %q", args["content"], "</client_tool_call> & ok")
		}
	})

	t.Run("bare_json_with_xml_entities", func(t *testing.T) {
		input := `{&quot;name&quot;:&quot;bash&quot;,&quot;arguments&quot;:{&quot;cmd&quot;:&quot;ls &amp;&amp; pwd&quot;}}`
		clean, calls := ParseClientToolCalls(input, allowed)
		if clean != "" || len(calls) != 1 || calls[0].Name != "bash" {
			t.Fatalf("unexpected result: clean=%q calls=%+v", clean, calls)
		}
		if calls[0].Arguments != `{"cmd":"ls && pwd"}` {
			t.Fatalf("arguments = %q, want %q", calls[0].Arguments, `{"cmd":"ls && pwd"}`)
		}
	})

	t.Run("valid_raw_json_not_double_unescaped", func(t *testing.T) {
		input := `<client_tool_call>{"name":"write_file","arguments":{"content":"<span>&lt;div&gt; &amp; &#39;</span>"}}</client_tool_call>`
		_, calls := ParseClientToolCalls(input, allowed)
		if len(calls) != 1 {
			t.Fatalf("expected 1 call, got %+v", calls)
		}
		var args map[string]string
		if err := json.Unmarshal([]byte(calls[0].Arguments), &args); err != nil {
			t.Fatalf("invalid arguments JSON: %v", err)
		}
		want := "<span>&lt;div&gt; &amp; &#39;</span>"
		if args["content"] != want {
			t.Fatalf("valid raw JSON was altered: got %q, want %q", args["content"], want)
		}
	})

	t.Run("prompt_schema_marshal_does_not_html_escape", func(t *testing.T) {
		rfPrompt := BuildResponseFormatPrompt(ResponseFormat{
			Type:   "json_schema",
			Name:   "cmp",
			Schema: map[string]any{"description": "a < b && c > d"},
		})
		if strings.Contains(rfPrompt, `\u003c`) || strings.Contains(rfPrompt, `\u003e`) || strings.Contains(rfPrompt, `\u0026`) {
			t.Fatalf("BuildResponseFormatPrompt HTML-escaped schema: %q", rfPrompt)
		}
		defs := []ToolDef{{
			Name:        "cmp",
			Description: "compare a < b && c > d",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"op": map[string]any{"type": "string", "enum": []any{"<", ">", "&&"}},
				},
			},
		}}
		for _, detail := range []string{"full", "160"} {
			prompt := BuildToolBridgePrompt(defs, ToolChoice{Mode: "auto"}, true, detail)
			if strings.Contains(prompt, `\u003c`) || strings.Contains(prompt, `\u003e`) || strings.Contains(prompt, `\u0026`) {
				t.Fatalf("BuildToolBridgePrompt(detail=%s) HTML-escaped schema: %q", detail, prompt)
			}
		}
	})
}

func TestBridgeStreamChunkParity137Bytes(t *testing.T) {
	allowed := map[string]bool{"bash": true, "write_file": true, "read_file": true}

	corpus := []struct {
		name  string
		input string
	}{
		{
			name:  "closing_tag_inside_json_string_with_cjk",
			input: "准备写入代码。\n<client_tool_call>{\"name\":\"write_file\",\"arguments\":{\"path\":\"a.go\",\"content\":\"tag := \\\"</client_tool_call>\\\"\\n\"}}</client_tool_call>",
		},
		{
			name:  "stray_prose_then_real_call",
			input: "说明：不要手写 <client_tool_call> 或 <client_tool_call>{...} 占位符。\n现在执行：<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"ls -la\"}}</client_tool_call>",
		},
		{
			name:  "fenced_example_then_real_call",
			input: "示例：\n```xml\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"echo fake\"}}</client_tool_call>\n```\n真实调用：\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"echo real\"}}</client_tool_call>",
		},
		{
			name:  "unclosed_fence_example",
			input: "示例代码：\n```xml\n<client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"echo fake\"}}</client_tool_call>",
		},
		{
			name:  "leading_non_json_fence_with_example_and_real_call",
			input: "```go\n// <client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"fake\"}}</client_tool_call>\n```\n<client_tool_call>{\"name\":\"read_file\",\"arguments\":{\"path\":\"main.go\"}}</client_tool_call>",
		},
		{
			name:  "entity_escaped_marked_call",
			input: "检查中：<client_tool_call>{&quot;name&quot;:&quot;bash&quot;,&quot;arguments&quot;:{&quot;cmd&quot;:&quot;a &lt; b &amp;&amp; echo &#39;ok&#39;&quot;}}</client_tool_call>",
		},
		{
			name:  "entity_escaped_bare_json",
			input: "{&quot;name&quot;:&quot;bash&quot;,&quot;arguments&quot;:{&quot;cmd&quot;:&quot;echo 1 &amp;&amp; echo 2&quot;}}",
		},
		{
			name:  "bare_fenced_json_tool_call",
			input: "```json\n{\"name\":\"bash\",\"arguments\":{\"cmd\":\"uname -a\"}}\n```",
		},
		{
			name:  "bare_non_json_fence_not_executed",
			input: "```python\n{\"name\":\"bash\",\"arguments\":{\"cmd\":\"uname -a\"}}\n```",
		},
		{
			name:  "plain_json_answer",
			input: `{"status":"ok","items":["a","b","c"]}`,
		},
		{
			name:  "leading_whitespace_only_around_tool_call",
			input: "  \n\t <client_tool_call>{\"name\":\"read_file\",\"arguments\":{\"path\":\"go.mod\"}}</client_tool_call>  \n",
		},
		{
			name:  "multi_calls_with_prose_between",
			input: "Step 1: <client_tool_call>{\"name\":\"read_file\",\"arguments\":{\"path\":\"a.txt\"}}</client_tool_call> Step 2: <client_tool_call>{\"name\":\"bash\",\"arguments\":{\"cmd\":\"wc -l a.txt\"}}</client_tool_call>",
		},
		{
			name:  "short_probe_eof",
			input: "```json\n",
		},
	}

	for _, tc := range corpus {
		wantText, wantCalls := ParseClientToolCalls(tc.input, allowed)
		for _, chunkSize := range []int{1, 3, 7} {
			gotText, gotCalls := runBridgeStreamChunked(tc.input, allowed, chunkSize)
			if strings.TrimSpace(gotText) != strings.TrimSpace(wantText) {
				t.Errorf("[%s chunk=%d] text mismatch:\ngot : %q\nwant: %q", tc.name, chunkSize, gotText, wantText)
			}
			assertCallsEqual(t, tc.name+"/chunk="+string(rune('0'+chunkSize)), gotCalls, wantCalls)
		}
	}
}

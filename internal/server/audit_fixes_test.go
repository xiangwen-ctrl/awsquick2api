package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"awsquick2api/internal/config"
)

func ssePayloads(t *testing.T, body string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	return events
}

func TestResponsesCompletedMatchesInterleavedItems(t *testing.T) {
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		for _, delta := range []struct{ kind, text string }{
			{"thinking_delta", "first thought "}, {"text_delta", "first text "},
			{"thinking_delta", "second thought "}, {"text_delta", "second text "},
		} {
			send(map[string]any{"type": delta.kind, "payload": map[string]any{"delta": strings.Repeat(delta.text, 16)}})
		}
		completeTurn(send)
	})
	g := newTestGateway(t, mock.URL, "good_token", 2, func(c *config.Config) { c.Features.StrictPrivacyDLP = false })
	w := postJSON(g.h, "/v1/responses", `{"model":"amazon-smart","stream":true,"input":"hi"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var addedIDs []any
	var completedItems, finalItems []any
	for i, event := range ssePayloads(t, w.Body.String()) {
		if event["sequence_number"] != float64(i) {
			t.Fatalf("wrong sequence number for event %d: %v", i, event["sequence_number"])
		}
		switch event["type"] {
		case "response.output_item.added":
			if event["output_index"] != float64(len(addedIDs)) {
				t.Fatalf("wrong added index: %v", event)
			}
			addedIDs = append(addedIDs, event["item"].(map[string]any)["id"])
		case "response.output_item.done":
			idx := len(completedItems)
			item := event["item"].(map[string]any)
			if idx >= len(addedIDs) || event["output_index"] != float64(idx) || item["id"] != addedIDs[idx] {
				t.Fatalf("wrong completed index or ID: %v", event)
			}
			completedItems = append(completedItems, item)
		case "response.completed":
			finalItems = event["response"].(map[string]any)["output"].([]any)
		}
	}
	if len(addedIDs) < 4 || !reflect.DeepEqual(completedItems, finalItems) {
		t.Fatalf("added=%d done=%d final=%d, equal=%v", len(addedIDs), len(completedItems), len(finalItems), reflect.DeepEqual(completedItems, finalItems))
	}
}

func TestTurnCompletedRequiresMessageComplete(t *testing.T) {
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": strings.Repeat("unfinished text ", 40)}})
		send(map[string]any{"type": "turn_completed", "payload": map[string]any{}})
	})
	for _, tc := range []struct {
		body   string
		status int
		marker string
	}{
		{`{"model":"amazon-smart","input":"hi"}`, http.StatusBadGateway, "upstream_incomplete_response"},
		{`{"model":"amazon-smart","input":"hi","stream":true}`, http.StatusOK, "response.failed"},
	} {
		g := newTestGateway(t, mock.URL, "good_token", 2, nil)
		w := postJSON(g.h, "/v1/responses", tc.body)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.marker) || strings.Contains(w.Body.String(), "response.completed") {
			t.Fatalf("wrong terminal response: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestOutputLimitWireContracts(t *testing.T) {
	for _, tc := range []struct{ path, key, marker string }{
		{"/v1/chat/completions", "max_completion_tokens", `"finish_reason":"length"`},
		{"/v1/chat/completions", "max_tokens", `"finish_reason":"length"`},
		{"/v1/messages", "max_tokens", `"stop_reason":"max_tokens"`},
		{"/v1/responses", "max_output_tokens", `"reason":"max_output_tokens"`},
	} {
		t.Run(tc.path+"/"+tc.key, func(t *testing.T) {
			mock, hits := newMockQuick(t, "", func(send func(map[string]any), prompt string) {
				send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "example generated output"}})
				if strings.Contains(prompt, "without usage") {
					send(map[string]any{"type": "message_complete", "payload": map[string]any{}})
					return
				}
				if tc.path == "/v1/responses" {
					send(map[string]any{"type": "turn_usage", "payload": map[string]any{"input_tokens": 5}})
					send(map[string]any{"type": "turn_usage", "payload": map[string]any{"output_tokens": "3"}})
					send(map[string]any{"type": "message_complete", "payload": map[string]any{}})
					send(map[string]any{"type": "turn_completed", "payload": map[string]any{}})
					return
				}
				completeTurn(send)
			})
			g := newTestGateway(t, mock.URL, "good_token", 2, nil)
			for _, sample := range []struct {
				limit       any
				stream      bool
				missing     bool
				status      int
				marker      string
				wantContent bool
			}{
				{1, false, false, 200, tc.marker, true},
				{1, true, false, 200, tc.marker, true},
				{3, false, false, 200, "example generated output", true},
				{3, true, false, 200, "example generated output", true},
				{nil, false, false, 200, "example generated output", true},
				{3, true, true, 200, "example generated output", true},
				{1.5, false, false, 400, "must be a positive integer", false},
			} {
				prompt := "hello"
				if sample.missing {
					prompt = "without usage"
				}
				body := map[string]any{
					"model": "amazon-smart", "stream": sample.stream, tc.key: sample.limit,
					"messages": []map[string]any{{"role": "user", "content": prompt}}, "input": prompt,
				}
				raw, _ := json.Marshal(body)
				w := postJSON(g.h, tc.path, string(raw))
				got := w.Body.String()
				if w.Code != sample.status || !strings.Contains(got, sample.marker) {
					t.Fatalf("limit=%v stream=%v missing=%v: want %d and marker %q, got %d %s", sample.limit, sample.stream, sample.missing, sample.status, sample.marker, w.Code, got)
				}
				if sample.wantContent && !strings.Contains(got, "example generated output") {
					t.Fatalf("limit=%v stream=%v: expected generated output preserved, got %s", sample.limit, sample.stream, got)
				}
			}
			if n := hits.Load(); n != 6 {
				t.Fatalf("expected one turn per valid request; got %d turns", n)
			}
		})
	}
	// Mixed precedence with JSON null fallback must also succeed.
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "ok"}})
		completeTurn(send)
	})
	g := newTestGateway(t, mock.URL, "good_token", 2, nil)
	w := postJSON(g.h, "/v1/chat/completions", `{"model":"amazon-smart","max_completion_tokens":64,"max_tokens":null,"messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok"`) {
		t.Fatalf("mixed max_completion_tokens + null max_tokens failed: %d %s", w.Code, w.Body.String())
	}
}

func TestAnthropicMaxTokensStreamsIncrementally(t *testing.T) {
	release := make(chan struct{})
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		// Emit enough runes to clear the strict DLP straddle window and flush live.
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": strings.Repeat("streamed chunk ", 200)}})
		<-release
		completeTurn(send)
	})
	g := newTestGateway(t, mock.URL, "good_token", 2, func(c *config.Config) {
		c.Features.StrictPrivacyDLP = false
	})
	srv := httptest.NewServer(g.h)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-5","stream":true,"max_tokens":4096,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("x-api-key", "qk_test_key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer resp.Body.Close()

	gotDelta := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "streamed chunk") {
				gotDelta <- true
				return
			}
		}
		gotDelta <- false
	}()

	select {
	case ok := <-gotDelta:
		close(release)
		if !ok {
			t.Fatal("stream closed without incremental delta")
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("Anthropic streaming request with max_tokens buffered until turn completion instead of streaming live")
	}
}

func TestChunkedPayloadBudgetShrinksForConcurrentStreaming(t *testing.T) {
	inUpstream := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		if calls.Add(1) == 1 {
			close(inUpstream)
			<-release
		}
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "ok"}})
		completeTurn(send)
	})
	g := newTestGateway(t, mock.URL, "good_token", 4, func(c *config.Config) {
		c.Server.MaxPayloadBytes = 2 << 20
		c.Server.MaxInflightPayloadBytes = 2 << 20
	})
	h := NewHandler(Config{
		Pool:                    g.pool,
		Upstream:                g.h.cfg.Upstream,
		Scheduler:               g.h.cfg.Scheduler,
		Live:                    g.h.cfg.Live,
		MaxPayloadBytes:         2 << 20,
		MaxInflightPayloadBytes: 2 << 20,
	})

	body := `{"model":"amazon-smart","messages":[{"role":"user","content":"hello"}]}`
	r1 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r1.ContentLength = -1
	r1.Header.Set("Authorization", "Bearer qk_test_key")
	w1 := httptest.NewRecorder()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.ServeHTTP(w1, r1)
	}()

	select {
	case <-inUpstream:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("first chunked request did not reach upstream")
	}

	// Second chunked request arrives while first is still streaming; because the first
	// shrank its reservation after reading its small body, the second must NOT 429.
	r2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r2.ContentLength = -1
	r2.Header.Set("Authorization", "Bearer qk_test_key")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	close(release)
	wg.Wait()

	if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
		t.Fatalf("concurrent chunked requests failed: w1=%d (%s) w2=%d (%s)", w1.Code, w1.Body.String(), w2.Code, w2.Body.String())
	}
}

func TestResponsesToolChoiceModesAndCustomToolUnescaped(t *testing.T) {
	tools := []any{
		map[string]any{"type": "function", "name": "ping"},
		map[string]any{"type": "namespace", "name": "mcp__fs", "tools": []any{
			map[string]any{"type": "function", "name": "read"},
			map[string]any{"type": "function", "name": "write"},
		}},
	}
	readAlias := responseToolAlias("mcp__fs", "read")

	// allowed_tools with mode=required filters declared tools and sets mode=required.
	req, _, err := responsesToChatRequest(map[string]any{
		"model": "amazon-smart",
		"input": "go",
		"tools": tools,
		"tool_choice": map[string]any{
			"type":  "allowed_tools",
			"mode":  "required",
			"tools": []any{map[string]any{"type": "function", "namespace": "mcp__fs", "name": "read"}},
		},
	}, http.Header{})
	if err != nil {
		t.Fatalf("allowed_tools failed: %v", err)
	}
	if req.ToolChoice != "required" || len(req.Tools.([]any)) != 1 {
		t.Fatalf("allowed_tools mismatch: choice=%v tools=%v", req.ToolChoice, req.Tools)
	}

	// namespace tool_choice narrows to tools in that namespace and requires one.
	req, _, err = responsesToChatRequest(map[string]any{
		"model":       "amazon-smart",
		"input":       "go",
		"tools":       tools,
		"tool_choice": map[string]any{"type": "namespace", "name": "mcp__fs"},
	}, http.Header{})
	if err != nil {
		t.Fatalf("namespace tool_choice failed: %v", err)
	}
	if req.ToolChoice != "required" || len(req.Tools.([]any)) != 2 {
		t.Fatalf("namespace tool_choice mismatch: choice=%v tools=%v", req.ToolChoice, req.Tools)
	}

	// Nested function with namespace must resolve to the bridged alias.
	req, _, err = responsesToChatRequest(map[string]any{
		"model": "amazon-smart",
		"input": "go",
		"tools": tools,
		"tool_choice": map[string]any{
			"type":      "function",
			"namespace": "mcp__fs",
			"function":  map[string]any{"name": "read"},
		},
	}, http.Header{})
	if err != nil {
		t.Fatalf("nested namespaced function tool_choice failed: %v", err)
	}
	tcMap := req.ToolChoice.(map[string]any)["function"].(map[string]any)
	if tcMap["name"] != readAlias {
		t.Fatalf("got alias %v, want %q", tcMap["name"], readAlias)
	}

	// Object-form required mode passes through.
	req, _, err = responsesToChatRequest(map[string]any{
		"model":       "amazon-smart",
		"input":       "go",
		"tools":       tools,
		"tool_choice": map[string]any{"type": "required"},
	}, http.Header{})
	if err != nil || req.ToolChoice != "required" {
		t.Fatalf("object-mode tool_choice failed: choice=%v err=%v", req.ToolChoice, err)
	}

	// custom_tool_call history must not HTML-escape <, >, &.
	req, _, err = responsesToChatRequest(map[string]any{
		"model": "amazon-smart",
		"input": []any{
			map[string]any{"type": "message", "role": "user", "content": "patch"},
			map[string]any{"type": "custom_tool_call", "call_id": "c1", "name": "apply_patch", "input": "if (a < b && c > d)"},
			map[string]any{"type": "custom_tool_call_output", "call_id": "c1", "output": "ok"},
		},
	}, http.Header{})
	if err != nil {
		t.Fatalf("custom_tool_call history failed: %v", err)
	}
	tcs := req.Messages[1]["tool_calls"].([]any)
	args := tcs[0].(map[string]any)["function"].(map[string]any)["arguments"].(string)
	if strings.Contains(args, `\u003c`) || !strings.Contains(args, "a < b && c > d") {
		t.Fatalf("custom_tool_call arguments HTML-escaped: %s", args)
	}
}

func TestProtocolErrorEnvelopesAndClientCancelDuringRefresh(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "qk_test_key"
	h := NewHandler(Config{Live: config.NewLiveHolder(cfg), MaxPayloadBytes: 64, MaxInflightPayloadBytes: 64})

	// Anthropic 413 returns request_too_large for both known Content-Length and chunked bodies.
	for _, cl := range []int64{128, -1} {
		r := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(strings.Repeat("x", 128)))
		r.ContentLength = cl
		r.Header.Set("x-api-key", cfg.APIKey)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), `"request_too_large"`) {
			t.Fatalf("anthropic 413 (cl=%d): got %d %s", cl, w.Code, w.Body.String())
		}
	}

	// OpenAI 413 returns payload_too_large consistently for both paths.
	for _, cl := range []int64{128, -1} {
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(strings.Repeat("x", 128)))
		r.ContentLength = cl
		r.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), `"payload_too_large"`) {
			t.Fatalf("openai 413 (cl=%d): got %d %s", cl, w.Code, w.Body.String())
		}
	}

	// Mid-stream 429 on Anthropic emits rate_limit_error; Responses response.failed includes output array.
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": strings.Repeat("partial ", 20)}})
		send(map[string]any{"type": "error", "payload": map[string]any{"code": "ThrottlingException", "message": "rate limit exceeded"}})
	})
	g := newTestGateway(t, mock.URL, "good_token", 2, func(c *config.Config) { c.Features.StrictPrivacyDLP = false })
	wa := postJSON(g.h, "/v1/messages", `{"model":"claude-sonnet-4-5","stream":true,"max_tokens":256,"messages":[{"role":"user","content":"hi"}]}`)
	if !strings.Contains(wa.Body.String(), `"type":"rate_limit_error"`) {
		t.Fatalf("anthropic mid-stream 429 should emit rate_limit_error, got: %s", wa.Body.String())
	}

	g2 := newTestGateway(t, mock.URL, "good_token", 2, func(c *config.Config) { c.Features.StrictPrivacyDLP = false })
	wr := postJSON(g2.h, "/v1/responses", `{"model":"amazon-smart","stream":true,"input":"hi"}`)
	foundFailed := false
	for _, ev := range ssePayloads(t, wr.Body.String()) {
		if ev["type"] == "response.failed" {
			foundFailed = true
			respObj := ev["response"].(map[string]any)
			if _, ok := respObj["output"].([]any); !ok {
				t.Fatalf("response.failed missing output array: %v", respObj)
			}
		}
	}
	if !foundFailed {
		t.Fatalf("expected response.failed event, got: %s", wr.Body.String())
	}

	// Cancelling client context while a 401 refresh is running must not mark the account unhealthy.
	mock401, _ := newMockQuick(t, "stale_token", func(send func(map[string]any), _ string) {
		completeTurn(send)
	})
	g3 := newTestGateway(t, mock401.URL, "stale_token", 2, nil)
	ctx, cancel := context.WithCancel(context.Background())
	// Pre-acquire the refresh lock so RefreshOneTokenIfStale blocks until we cancel ctx.
	lockHeld := make(chan struct{})
	releaseLock := make(chan struct{})
	go func() {
		_ = g3.pool.WithRefreshLock("soc_u1_example_com_abcd", func() error {
			close(lockHeld)
			<-releaseLock
			return nil
		})
	}()
	<-lockHeld
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"amazon-smart","messages":[{"role":"user","content":"hi"}]}`))
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer qk_test_key")
	done := make(chan struct{})
	go func() {
		defer close(done)
		g3.h.ServeHTTP(httptest.NewRecorder(), req)
	}()
	time.Sleep(80 * time.Millisecond)
	cancel()
	close(releaseLock)
	<-done
	if snap := g3.pool.Snapshot(); len(snap) != 1 || !snap[0].Healthy {
		t.Fatalf("account must remain healthy after client cancel during 401 refresh, got %+v", snap)
	}
}

func TestStrictSchemaOnBothOpenAIEndpoints(t *testing.T) {
	mock, hits := newMockQuick(t, "", func(send func(map[string]any), prompt string) {
		text := `{"unexpected":1}`
		if strings.Contains(prompt, "valid answer") {
			text = `{"answer":"ok"}`
		}
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": text}})
		completeTurn(send)
	})
	g := newTestGateway(t, mock.URL, "good_token", 2, nil)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, sample := range []struct {
			prompt string
			schema string
			status int
		}{
			{"valid answer", `{"type":"object","properties":{"answer":{"$ref":"#/$defs/text"}},"required":["answer"],"$defs":{"text":{"type":"string"}}}`, 200},
			{"wrong answer", `{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"],"additionalProperties":false}`, 502},
			{"wrong answer", `{"$ref":"https://example.invalid/schema"}`, 400},
		} {
			schema := json.RawMessage(sample.schema)
			req := map[string]any{
				"model": "amazon-smart", "stream": true, "input": sample.prompt,
				"messages":        []map[string]any{{"role": "user", "content": sample.prompt}},
				"response_format": map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "answer", "strict": true, "schema": schema}},
				"text":            map[string]any{"format": map[string]any{"type": "json_schema", "name": "answer", "strict": true, "schema": schema}},
			}
			raw, _ := json.Marshal(req)
			w := postJSON(g.h, path, string(raw))
			if w.Code != sample.status || (w.Code != 200 && strings.Contains(w.Body.String(), "unexpected")) {
				t.Fatalf("%s: want %d, got %d %s", path, sample.status, w.Code, w.Body.String())
			}
		}
	}
	if n := hits.Load(); n != 4 {
		t.Fatalf("invalid schema reached upstream or completed output was retried: %d", n)
	}
}

func TestUnsupportedImagesReturnInvalidRequest(t *testing.T) {
	mock, hits := newMockQuick(t, "", func(send func(map[string]any), _ string) { completeTurn(send) })
	g := newTestGateway(t, mock.URL, "good_token", 2, nil)
	for _, tc := range []struct{ path, body string }{
		{"/v1/chat/completions", `{"messages":[{"role":"user","content":[{"type":"text","text":"caption"},{"type":"image_url","image_url":{"url":"https://example.invalid/photo.png"}}]}]}`},
		{"/v1/messages", `{"messages":[{"role":"user","content":[{"type":"text","text":"caption"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"bad"}}]}]}`},
		{"/v1/responses", `{"input":[{"role":"user","content":[{"type":"input_text","text":"caption"},{"type":"input_image","file_id":"file-example"}]}]}`},
	} {
		w := postJSON(g.h, tc.path, tc.body)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "inline base64 image") {
			t.Fatalf("%s: got %d %s", tc.path, w.Code, w.Body.String())
		}
	}
	if hits.Load() != 0 {
		t.Fatal("unsupported images reached the upstream")
	}
}

type heldRequestBody struct {
	entered chan<- struct{}
	release <-chan struct{}
	reader  io.Reader
}

func (b *heldRequestBody) Read(p []byte) (int, error) {
	if b.entered != nil {
		close(b.entered)
		<-b.release
		b.entered = nil
	}
	return b.reader.Read(p)
}

func (b *heldRequestBody) Close() error { return nil }

func TestRequestPayloadBudgetReleased(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "qk_test_key"
	h := NewHandler(Config{Live: config.NewLiveHolder(cfg), MaxPayloadBytes: 2 << 20, MaxInflightPayloadBytes: 2 << 20})
	path := "/v1/messages/count_tokens"
	body := `{"messages":[{"role":"user","content":"hello"}]}`
	entered := make(chan struct{})
	release := make(chan struct{})
	r := httptest.NewRequest(http.MethodPost, path, &heldRequestBody{entered, release, strings.NewReader(body)})
	r.ContentLength = 2 << 20
	r.Header.Set("X-Api-Key", cfg.APIKey)
	first := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(first, r)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("first request did not reach the body reader")
	}
	second := postJSON(h, path, body)
	close(release)
	<-done
	if first.Code != 200 || second.Code != 429 {
		t.Fatalf("want 200 then 429, got %d and %d", first.Code, second.Code)
	}
	if third := postJSON(h, path, body); third.Code != 200 {
		t.Fatalf("budget was not released: %d", third.Code)
	}
	// Chunked request that grows past remaining inflight budget must be rejected with 429 mid-read.
	smallBudget := NewHandler(Config{Live: config.NewLiveHolder(cfg), MaxPayloadBytes: 2 << 20, MaxInflightPayloadBytes: 128 << 10})
	overshoot := `{"messages":[{"role":"user","content":"` + strings.Repeat("a", 200<<10) + `"}]}`
	chunked := httptest.NewRequest(http.MethodPost, path, strings.NewReader(overshoot))
	chunked.ContentLength = -1
	chunked.Header.Set("X-Api-Key", cfg.APIKey)
	cw := httptest.NewRecorder()
	smallBudget.ServeHTTP(cw, chunked)
	if cw.Code != http.StatusTooManyRequests && cw.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked overshoot got %d, want 429 or 413", cw.Code)
	}
	// Two concurrent 1.5 MiB chunked bodies against a 2 MiB budget cannot both fit.
	entered2 := make(chan struct{})
	release2 := make(chan struct{})
	big1 := `{"messages":[{"role":"user","content":"` + strings.Repeat("x", (1536<<10)-50) + `"}]}`
	big2 := `{"messages":[{"role":"user","content":"` + strings.Repeat("y", (1536<<10)-50) + `"}]}`
	rBig1 := httptest.NewRequest(http.MethodPost, path, io.MultiReader(strings.NewReader(big1[:1400<<10]), &heldRequestBody{entered2, release2, strings.NewReader(big1[1400<<10:])}))
	rBig1.ContentLength = -1
	rBig1.Header.Set("X-Api-Key", cfg.APIKey)
	wBig1 := httptest.NewRecorder()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		h.ServeHTTP(wBig1, rBig1)
	}()
	select {
	case <-entered2:
	case <-time.After(time.Second):
		close(release2)
		t.Fatal("big chunked request did not reach second stage")
	}
	rBig2 := httptest.NewRequest(http.MethodPost, path, strings.NewReader(big2))
	rBig2.ContentLength = -1
	rBig2.Header.Set("X-Api-Key", cfg.APIKey)
	wBig2 := httptest.NewRecorder()
	h.ServeHTTP(wBig2, rBig2)
	close(release2)
	<-done2
	if wBig1.Code != 200 || wBig2.Code != 429 {
		t.Fatalf("incremental chunked budget failed: wBig1=%d wBig2=%d", wBig1.Code, wBig2.Code)
	}
	if after := postJSON(h, path, body); after.Code != 200 {
		t.Fatalf("budget leaked after chunked 429: %d", after.Code)
	}
	large := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	large.ContentLength = (2 << 20) + 1
	large.Header.Set("X-Api-Key", cfg.APIKey)
	largeResponse := httptest.NewRecorder()
	h.ServeHTTP(largeResponse, large)
	if largeResponse.Code != 413 {
		t.Fatalf("oversize body returned %d", largeResponse.Code)
	}
}

func TestThreadReuseRequiresDedicatedConversationHeader(t *testing.T) {
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "Noted."}})
		completeTurn(send)
	})
	for _, hdr := range []string{"X-Aws-Quick-Conversation", "Session-Id"} {
		t.Run(hdr, func(t *testing.T) {
			g := newTestGateway(t, mock.URL, "good_token", 2, func(c *config.Config) { c.Upstream.Stateful = true })
			for i, body := range []string{
				`{"model":"amazon-smart","messages":[{"role":"user","content":"First question"}]}`,
				`{"model":"amazon-smart","messages":[{"role":"user","content":"First question"},{"role":"assistant","content":"Noted."},{"role":"user","content":"Follow-up"}]}`,
			} {
				r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
				r.Header.Set("Authorization", "Bearer qk_test_key")
				r.Header.Set(hdr, "test-conversation")
				w := httptest.NewRecorder()
				g.h.ServeHTTP(w, r)
				reused := w.Header().Get("X-Quick-Thread-Reused") == "true"
				if w.Code != http.StatusOK || reused != (i == 1 && hdr == "X-Aws-Quick-Conversation") {
					t.Fatalf("turn %d: status %d, thread reuse=%v", i+1, w.Code, reused)
				}
			}
		})
	}
}

func TestInferenceRequiresUsableConfiguredKey(t *testing.T) {
	for _, key := range []string{"", "  ", config.ExampleAPIKey} {
		cfg := config.Default()
		cfg.APIKey = key
		h := NewHandler(Config{Live: config.NewLiveHolder(cfg)})
		for _, path := range []string{"/v1/chat/completions", "/v1/messages", "/v1/responses"} {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			r.Header.Set("Authorization", "Bearer "+key)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("%s: expected authentication failure, got %d", path, w.Code)
			}
		}
	}
}

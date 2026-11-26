package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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
				limit   any
				stream  bool
				missing bool
				status  int
				marker  string
			}{
				{1, false, false, 200, tc.marker},
				{1, true, false, 200, tc.marker},
				{3, false, false, 200, "example generated output"},
				{3, true, false, 200, "example generated output"},
				{3, true, true, 502, "did not report valid output token usage"},
				{1.5, false, false, 400, "must be a positive integer"},
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
				if w.Code != sample.status || !strings.Contains(got, sample.marker) ||
					(sample.marker != "example generated output" && strings.Contains(got, "example generated output")) {
					t.Fatalf("want %d and marker %q, got %d %s", sample.status, sample.marker, w.Code, got)
				}
			}
			if n := hits.Load(); n != 5 {
				t.Fatalf("expected one turn per valid request; got %d turns", n)
			}
		})
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
	r.ContentLength = -1
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

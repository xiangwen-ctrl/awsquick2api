package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
)

// mockTurn is invoked once per received user_message; n is the 1-based count
// across all connections. Returning closes the connection.
type mockTurn func(n int, conn *websocket.Conn, send func(env map[string]any), sendRaw func([]byte))

func newMockQuick(t *testing.T, turn mockTurn) (*httptest.Server, func() int) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var (
		mu    sync.Mutex
		count int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != auth.DefaultWSPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		send := func(env map[string]any) {
			inner, _ := json.Marshal(env)
			outer, _ := json.Marshal(map[string]any{"payload": base64.StdEncoding.EncodeToString(inner)})
			_ = conn.WriteMessage(websocket.BinaryMessage, EventStreamEncode(map[string]string{
				":event-type":   "rawOutputEvent",
				":message-type": "event",
			}, outer))
		}
		sendRaw := func(b []byte) { _ = conn.WriteMessage(websocket.BinaryMessage, b) }
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var outer struct {
				Payload struct {
					Payload string `json:"payload"`
				} `json:"payload"`
			}
			if json.Unmarshal(raw, &outer) != nil {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(outer.Payload.Payload)
			if err != nil {
				continue
			}
			var msg map[string]any
			if json.Unmarshal(decoded, &msg) != nil || msg["type"] != "user_message" {
				continue
			}
			mu.Lock()
			count++
			n := count
			mu.Unlock()
			turn(n, conn, send, sendRaw)
			return
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() int {
		mu.Lock()
		defer mu.Unlock()
		return count
	}
}

func mockClient(srv *httptest.Server, maxFrame int) (*Client, *auth.Account) {
	cfg := config.Default().Upstream
	cfg.DataPlaneURL = srv.URL
	cfg.Stateful = true
	cfg.Attachments = false
	cfg.MaxFrameBytes = maxFrame
	cfg.IdleTimeoutSeconds = 5
	cfg.TimeoutSeconds = 10
	client := NewClient(cfg, nil)
	acct := &auth.Account{
		UID:         "soc_fix_test",
		Provider:    auth.ProviderSocial,
		Stage:       "prod",
		TenantURL:   srv.URL,
		WSHost:      "ws://" + strings.TrimPrefix(srv.URL, "http://"),
		AccessToken: "tok_test",
		DeviceID:    auth.NewUUID(),
	}
	return client, acct
}

func completeTurn(send func(map[string]any), text string) {
	if text != "" {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": text}})
	}
	send(map[string]any{"type": "message_complete", "payload": map[string]any{"continuation_expected": false}})
	send(map[string]any{"type": "turn_completed", "payload": map[string]any{}})
}

func chatOnce(client *Client, acct *auth.Account, conv string, msgs []map[string]any, onEvent func(ChatEvent)) (ChatResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return client.Chat(ctx, acct, ChatRequest{
		Model:          "amazon-smart",
		Slot:           "smart",
		ConversationID: conv,
		ThreadSession:  conv,
		Stream:         onEvent != nil,
		Messages:       msgs,
	}, onEvent)
}

// P1-4: a disconnect after partial text but before message_complete must fail,
// and the partial turn must not be committed to the ThreadStore.
func TestWSDisconnectBeforeCompleteIsError(t *testing.T) {
	srv, count := newMockQuick(t, func(n int, conn *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "partial <client_tool_call>{\"na"}})
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	})
	client, acct := mockClient(srv, 65536)
	_, err := chatOnce(client, acct, "conv-cut", []map[string]any{{"role": "user", "content": "hi"}}, nil)
	if err == nil {
		t.Fatal("expected error when stream ends without message_complete")
	}
	if count() != 1 {
		t.Fatalf("expected exactly 1 upstream attempt, got %d", count())
	}
	if len(client.Threads.threads) != 0 {
		t.Fatal("partial turn must not be committed")
	}
}

// P1-4: an empty-text message_complete followed by an immediate close is a valid (empty) reply.
func TestWSEmptyCompleteThenCloseSucceeds(t *testing.T) {
	srv, _ := newMockQuick(t, func(n int, conn *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		send(map[string]any{"type": "message_complete", "payload": map[string]any{"continuation_expected": false}})
	})
	client, acct := mockClient(srv, 65536)
	res, err := chatOnce(client, acct, "conv-empty", []map[string]any{{"role": "user", "content": "hi"}}, nil)
	if err != nil {
		t.Fatalf("empty complete should not be an upstream error: %v", err)
	}
	if res.Text != "" {
		t.Fatalf("expected empty text, got %q", res.Text)
	}
}

func twoTurnMessages() []map[string]any {
	return []map[string]any{
		{"role": "user", "content": "first"},
		{"role": "assistant", "content": "one"},
		{"role": "user", "content": "second"},
	}
}

// P1-5: once a resumed-thread attempt has streamed output, the stale-thread
// fallback must not run a second attempt into the same stream.
func TestChatNoRetryAfterStreamedOutput(t *testing.T) {
	srv, count := newMockQuick(t, func(n int, conn *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		if n == 1 {
			completeTurn(send, "one")
			return
		}
		// Long enough to pass the strict-DLP stream hold window, so it really reaches the caller.
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "half an ans " + strings.Repeat("filler words here ", 400)}})
		time.Sleep(100 * time.Millisecond)
		send(map[string]any{"type": "turn_failed", "payload": map[string]any{"message": "boom"}})
	})
	client, acct := mockClient(srv, 65536)
	if _, err := chatOnce(client, acct, "conv-retry", []map[string]any{{"role": "user", "content": "first"}}, nil); err != nil {
		t.Fatalf("turn 1: %v", err)
	}
	var streamed strings.Builder
	_, err := chatOnce(client, acct, "conv-retry", twoTurnMessages(), func(ev ChatEvent) {
		if ev.Type == "text" {
			streamed.WriteString(ev.Text)
		}
	})
	if err == nil {
		t.Fatal("expected turn 2 to fail")
	}
	if count() != 2 {
		t.Fatalf("expected no retry after streamed output (2 attempts), got %d", count())
	}
	if !strings.Contains(streamed.String(), "half an ans") {
		t.Fatalf("test setup: expected partial output to be streamed, got %q", streamed.String())
	}
	if strings.Count(streamed.String(), "half an ans") > 1 {
		t.Fatalf("stream spliced two attempts: %q", streamed.String())
	}
}

// P1-5 counterpart: a resumed-thread failure before any output still falls back to a fresh thread.
func TestChatRetriesStaleThreadBeforeOutput(t *testing.T) {
	srv, count := newMockQuick(t, func(n int, conn *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		switch n {
		case 1:
			completeTurn(send, "one")
		case 2:
			send(map[string]any{"type": "turn_failed", "payload": map[string]any{"message": "stale thread"}})
		default:
			completeTurn(send, "ok")
		}
	})
	client, acct := mockClient(srv, 65536)
	if _, err := chatOnce(client, acct, "conv-stale", []map[string]any{{"role": "user", "content": "first"}}, nil); err != nil {
		t.Fatalf("turn 1: %v", err)
	}
	res, err := chatOnce(client, acct, "conv-stale", twoTurnMessages(), func(ChatEvent) {})
	if err != nil {
		t.Fatalf("expected fallback to succeed: %v", err)
	}
	if count() != 3 || res.ThreadReused {
		t.Fatalf("expected fresh-thread fallback (3 attempts, not reused), got %d reused=%v", count(), res.ThreadReused)
	}
}

// P3-3: an EventStream exception frame with FrameTooLarge must map to ErrKindTooLarge
// so the 70% re-compose retry runs.
func TestEventStreamFrameTooLargeIsRetried(t *testing.T) {
	srv, count := newMockQuick(t, func(n int, conn *websocket.Conn, send func(map[string]any), sendRaw func([]byte)) {
		if n == 1 {
			sendRaw(EventStreamEncode(map[string]string{
				":message-type":   "exception",
				":exception-type": "FrameTooLarge",
				":error-message":  "frame too large",
			}, nil))
			return
		}
		completeTurn(send, "fits now")
	})
	client, acct := mockClient(srv, 65536)
	res, err := chatOnce(client, acct, "conv-big", []map[string]any{{"role": "user", "content": "hi"}}, nil)
	if err != nil {
		t.Fatalf("expected 70%% retry to succeed: %v", err)
	}
	if count() != 2 || res.Text != "fits now" {
		t.Fatalf("expected 2 attempts and retried text, got %d %q", count(), res.Text)
	}
}

// P3-3: unbounded distinct _chunked_frame ids are rejected instead of buffering forever.
func TestChunkedFrameAssemblyIsBounded(t *testing.T) {
	srv, _ := newMockQuick(t, func(n int, conn *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		for i := 0; i < maxChunkAssemblies+5; i++ {
			send(map[string]any{"type": "_chunked_frame", "payload": map[string]any{
				"chunk_id":     "c" + strings.Repeat("x", i+1),
				"chunk_index":  0,
				"total_chunks": 2,
				"data":         "{",
			}})
		}
		completeTurn(send, "late")
	})
	client, acct := mockClient(srv, 65536)
	_, err := chatOnce(client, acct, "conv-chunks", []map[string]any{{"role": "user", "content": "hi"}}, nil)
	if err == nil {
		t.Fatal("expected error for too many concurrent chunked frames")
	}
}

func TestCBORRejectsOversizedDeclaredLength(t *testing.T) {
	for _, data := range [][]byte{
		{0x99, 0xff, 0xff},             // array of 65535 with no elements
		{0xb9, 0x40, 0x00},             // map of 16384 with no entries
		{0x81, 0x81, 0x81, 0x99, 0x10}, // nested, truncated head
	} {
		if _, err := CBORDecode(data); err == nil {
			t.Fatalf("expected error for %x", data)
		}
	}
	if _, err := CBORDecode([]byte{0x99, 0xff, 0xff}); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected up-front size rejection, got %v", err)
	}
}

func TestMessageKeyDistinguishesImagesAndErrors(t *testing.T) {
	img := func(u string) map[string]any {
		return map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "what is this"},
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": u}},
		}}
	}
	if MessageKey(img("https://a.example/1.png")) == MessageKey(img("https://a.example/2.png")) {
		t.Fatal("messages differing only by image must not share a key")
	}
	ok := map[string]any{"role": "tool", "tool_call_id": "c1", "content": "out"}
	bad := map[string]any{"role": "tool", "tool_call_id": "c1", "content": "out", "is_error": true}
	if MessageKey(ok) == MessageKey(bad) {
		t.Fatal("is_error must be part of the tool message key")
	}
}

func TestMessageKeyIncludesAssistantOutput(t *testing.T) {
	first := MessageKey(map[string]any{"role": "assistant", "content": "first"})
	second := MessageKey(map[string]any{"role": "assistant", "content": "second"})
	if first == second {
		t.Fatal("different assistant replies have the same history key")
	}
}

func TestThreadStoreTTLCleansOrder(t *testing.T) {
	s := NewThreadStore()
	s.Commit("t-old", "acct", "sess", "", []string{"user:a"})
	s.mu.Lock()
	s.threads["t-old"].At = time.Now().Add(-threadTTL - time.Minute)
	s.mu.Unlock()
	if m := s.Match("acct", "sess", []string{"user:a", "assistant", "user:b"}); m != nil {
		t.Fatalf("expired thread must not match: %+v", m)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.threads) != 0 || len(s.order) != 0 {
		t.Fatalf("expected TTL eviction to clear order too, threads=%d order=%d", len(s.threads), len(s.order))
	}
}

func TestDataImageWithParameters(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 0}
	u := "data:image/png;charset=utf-8;base64," + base64.StdEncoding.EncodeToString(png)
	var images []InlineImage
	total := 0
	ContentText([]any{map[string]any{"type": "image_url", "image_url": map[string]any{"url": u}}}, &images, &total)
	if len(images) != 1 {
		t.Fatalf("expected parameterised data URL to be accepted, got %d images", len(images))
	}
}

func TestArgumentStringKeepsHTMLChars(t *testing.T) {
	got := ArgumentString(map[string]any{"code": "if a < b && c > d { x := <T>() }"})
	if strings.Contains(got, `\u003c`) || strings.Contains(got, `\u0026`) || !strings.Contains(got, "a < b && c > d") {
		t.Fatalf("arguments must not be HTML-escaped: %s", got)
	}
}

func TestToolResultIsErrorStatus(t *testing.T) {
	msgs := []map[string]any{
		{"role": "user", "content": "run it"},
		{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "bash", "arguments": "{}"}}}},
		{"role": "tool", "tool_call_id": "c1", "content": "permission denied", "is_error": true},
	}
	blocks, _, err := PromptBlocks(msgs, msgs, false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if pt := strings.Join(blocks, "\n"); !strings.Contains(pt, "status=error") {
		t.Fatalf("expected status=error marker in transcript, got %q", blocks)
	}
}

func TestEmptyCatalogResolveDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Resolve panicked on empty catalog: %v", r)
		}
	}()
	slot, _, _, _ := (&ModelCatalog{}).Resolve("", "smart", false)
	if slot == "" {
		t.Fatal("expected a fallback slot")
	}
	_, _, _, _ = (&ModelCatalog{}).Resolve("unknown-model", "smart", false)
}

func TestModelCatalogAliasGaps(t *testing.T) {
	cat := DefaultCatalog()
	for in, want := range map[string]string{
		"claude-haiku-4-5-20251001":                     "fast",
		"us.anthropic.claude-sonnet-4-5-20250929-v1:0":  "balanced",
		"anthropic.claude-opus-4-1-20250805-v1:0":       "smart",
		"global.anthropic.claude-haiku-4-5-20251001-v1": "fast",
		"claude-sonnet-4-5[1m]":                         "balanced",
	} {
		slot, _, _, known := cat.Resolve(in, "smart", true)
		if !known || slot != want {
			t.Fatalf("Resolve(%q) = %q known=%v, want %q", in, slot, known, want)
		}
	}
	ov := map[string]string{"claude-sonnet-4-5": "low"}
	if got := lookupOverride(ov, "claude-sonnet-4-5[1m]", "balanced"); got != "low" {
		t.Fatalf("[1m] suffix must match the bare override, got %q", got)
	}
	for _, m := range cat.VisibleModels(nil, nil, false, false, true, false) {
		if strings.HasPrefix(m.ID, "amazon-fast-") {
			t.Fatalf("fast slot must not expose thinking variants, got %s", m.ID)
		}
	}
}

// P1-5: guardrail_blocked on a resumed thread must not trigger a fresh-thread retry.
func TestChatNoRetryOnGuardrailBlocked(t *testing.T) {
	srv, count := newMockQuick(t, func(n int, conn *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		if n == 1 {
			completeTurn(send, "one")
			return
		}
		send(map[string]any{"type": "guardrail_blocked", "payload": map[string]any{"message": "policy violation"}})
	})
	client, acct := mockClient(srv, 65536)
	if _, err := chatOnce(client, acct, "conv-blocked", []map[string]any{{"role": "user", "content": "first"}}, nil); err != nil {
		t.Fatalf("turn 1: %v", err)
	}
	_, err := chatOnce(client, acct, "conv-blocked", twoTurnMessages(), nil)
	if err == nil {
		t.Fatal("expected guardrail_blocked error")
	}
	if count() != 2 {
		t.Fatalf("guardrail_blocked must not retry on fresh thread, got %d attempts", count())
	}
}

// P2-15: tools + response_format validates JSON objects (and rejects "null") in both buffered and streaming modes.
func TestToolsWithResponseFormatValidation(t *testing.T) {
	toolDefs := []any{map[string]any{
		"type":     "function",
		"function": map[string]any{"name": "lookup", "description": "lookup"},
	}}
	jsonObjFmt := map[string]any{"type": "json_object"}

	t.Run("rejects_null_streaming", func(t *testing.T) {
		srv, _ := newMockQuick(t, func(_ int, _ *websocket.Conn, send func(map[string]any), _ func([]byte)) {
			completeTurn(send, "```json\nnull\n```")
		})
		client, acct := mockClient(srv, 65536)
		var streamed strings.Builder
		_, err := client.Chat(context.Background(), acct, ChatRequest{
			Model:          "amazon-smart",
			Slot:           "smart",
			Stream:         true,
			Tools:          toolDefs,
			ToolChoice:     "auto",
			ResponseFormat: jsonObjFmt,
			Messages:       []map[string]any{{"role": "user", "content": "hi"}},
		}, func(ev ChatEvent) {
			if ev.Type == "text" {
				streamed.WriteString(ev.Text)
			}
		})
		if err == nil {
			t.Fatal("expected \"null\" to be rejected for json_object")
		}
		if streamed.Len() != 0 {
			t.Fatalf("invalid json_object must not stream raw text, got %q", streamed.String())
		}
	})

	t.Run("cleans_valid_object_streaming", func(t *testing.T) {
		srv, _ := newMockQuick(t, func(_ int, _ *websocket.Conn, send func(map[string]any), _ func([]byte)) {
			completeTurn(send, "```json\n{\"ok\":true}\n```")
		})
		client, acct := mockClient(srv, 65536)
		var streamed strings.Builder
		res, err := client.Chat(context.Background(), acct, ChatRequest{
			Model:          "amazon-smart",
			Slot:           "smart",
			Stream:         true,
			Tools:          toolDefs,
			ToolChoice:     "auto",
			ResponseFormat: jsonObjFmt,
			Messages:       []map[string]any{{"role": "user", "content": "hi"}},
		}, func(ev ChatEvent) {
			if ev.Type == "text" {
				streamed.WriteString(ev.Text)
			}
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Text != `{"ok":true}` || streamed.String() != `{"ok":true}` {
			t.Fatalf("expected cleaned JSON object, res=%q streamed=%q", res.Text, streamed.String())
		}
	})

	t.Run("allows_tool_call_with_response_format", func(t *testing.T) {
		srv, _ := newMockQuick(t, func(_ int, _ *websocket.Conn, send func(map[string]any), _ func([]byte)) {
			completeTurn(send, `<client_tool_call>{"name":"lookup","arguments":{"q":"go"}}</client_tool_call>`)
		})
		client, acct := mockClient(srv, 65536)
		res, err := client.Chat(context.Background(), acct, ChatRequest{
			Model:          "amazon-smart",
			Slot:           "smart",
			Stream:         true,
			Tools:          toolDefs,
			ToolChoice:     "auto",
			ResponseFormat: jsonObjFmt,
			Messages:       []map[string]any{{"role": "user", "content": "hi"}},
		}, func(ChatEvent) {})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res.ToolCalls) != 1 || res.ToolCalls[0].Name != "lookup" {
			t.Fatalf("expected lookup tool call, got %+v", res.ToolCalls)
		}
	})
}

// P2-12: cancelling ctx mid-turn returns promptly instead of blocking stopSettleWait (2.5s).
func TestWSUserCancelReturnsQuickly(t *testing.T) {
	srv, _ := newMockQuick(t, func(_ int, conn *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "working..."}})
		time.Sleep(5 * time.Second)
	})
	client, acct := mockClient(srv, 65536)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.Chat(ctx, acct, ChatRequest{
		Model:    "amazon-smart",
		Slot:     "smart",
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context error on cancel")
	}
	if elapsed > 1200*time.Millisecond {
		t.Fatalf("user cancel blocked too long (%v); should not wait 2.5s stopSettleWait", elapsed)
	}
}

// P3-3: RFC 8949 indefinite-length CBOR items decode cleanly and reject truncation.
func TestCBORIndefiniteLength(t *testing.T) {
	// Indefinite-length map { "payload": indefinite bytes("hi" + "!") }
	data := []byte{
		0xbf, // start indefinite map
		0x67, 'p', 'a', 'y', 'l', 'o', 'a', 'd',
		0x5f,           // start indefinite byte string
		0x42, 'h', 'i', // chunk "hi"
		0x41, '!', // chunk "!"
		0xff, // break bytes
		0xff, // break map
	}
	v, err := CBORDecode(data)
	if err != nil {
		t.Fatalf("CBORDecode indefinite map failed: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok || string(m["payload"].([]byte)) != "hi!" {
		t.Fatalf("unexpected decoded indefinite CBOR: %#v", v)
	}
	if _, err := CBORDecode([]byte{0x9f, 0x01}); err == nil {
		t.Fatal("expected error on unterminated indefinite array")
	}
}

// P3-3: nested _chunked_frame recursion is bounded.
func TestChunkedFrameNestingDepthGuard(t *testing.T) {
	nested := map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "deep"}}
	for i := 0; i < 6; i++ {
		raw, _ := json.Marshal(nested)
		nested = map[string]any{
			"type": "_chunked_frame",
			"payload": map[string]any{
				"chunk_id":     strings.Repeat("d", i+1),
				"chunk_index":  0,
				"total_chunks": 1,
				"data":         string(raw),
			},
		}
	}
	srv, _ := newMockQuick(t, func(_ int, _ *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		send(nested)
		completeTurn(send, "after")
	})
	client, acct := mockClient(srv, 65536)
	_, err := chatOnce(client, acct, "conv-deep", []map[string]any{{"role": "user", "content": "hi"}}, nil)
	if err == nil {
		t.Fatal("expected error for deeply nested _chunked_frame")
	}
}

// P2-19: invalid upstream.proxy_url fails closed in HTTPClient instead of falling back to direct.
func TestHTTPClientFailsClosedOnInvalidProxy(t *testing.T) {
	cfg := config.Default().Upstream
	cfg.ProxyURL = "ftp://127.0.0.1:9999"
	client := NewClient(cfg, nil)
	hc := client.HTTPClient(2 * time.Second)
	_, err := hc.Get("http://127.0.0.1:1/should-not-dial")
	if err == nil || !strings.Contains(err.Error(), "proxy_url") {
		t.Fatalf("expected invalid proxy_url error, got %v", err)
	}
}

// P2-3 / P2-1: sessionFromAccount rejects untrusted TenantURL (even with custom endpoints)
// and rejects loopback WSHost/TenantURL when no custom endpoints are configured.
func TestSessionRejectsUntrustedTenantURL(t *testing.T) {
	cfg := config.Default().Upstream
	client := NewClient(cfg, nil)
	for _, acct := range []*auth.Account{
		{UID: "soc_evil", Provider: auth.ProviderSocial, TenantURL: "https://evil.example.com", AccessToken: "tok_test"},
		{UID: "soc_loop_ws", Provider: auth.ProviderSocial, WSHost: "ws://127.0.0.1:8080", AccessToken: "tok_test"},
		{UID: "soc_loop_tenant", Provider: auth.ProviderSocial, TenantURL: "http://127.0.0.1:8080", AccessToken: "tok_test"},
	} {
		if _, err := client.sessionFromAccount(context.Background(), acct, cfg); err == nil {
			t.Fatalf("expected account %s to be rejected without custom endpoints", acct.UID)
		}
	}

	// Even when custom endpoints are configured, an untrusted remote TenantURL must still be rejected.
	customCfg := config.Default().Upstream
	customCfg.DataPlaneURL = "http://127.0.0.1:9999"
	customClient := NewClient(customCfg, nil)
	evilAcct := &auth.Account{
		UID:         "soc_evil_custom",
		Provider:    auth.ProviderSocial,
		TenantURL:   "https://evil.example.com",
		AccessToken: "tok_test",
	}
	if _, err := customClient.sessionFromAccount(context.Background(), evilAcct, customCfg); err == nil {
		t.Fatal("expected untrusted remote TenantURL to be rejected even when custom endpoints are set")
	}
}

// P2-5: client cancel during continuous active token streaming must stop promptly
// instead of resetting the read deadline to idleDur on every frame.
func TestWSCancelStopsContinuousStreamingPromptly(t *testing.T) {
	srv, _ := newMockQuick(t, func(_ int, conn *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		tk := time.NewTicker(5 * time.Millisecond)
		defer tk.Stop()
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			<-tk.C
			send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "tok "}})
		}
		completeTurn(send, "done")
	})
	client, acct := mockClient(srv, 65536)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.Chat(ctx, acct, ChatRequest{
		Model:    "amazon-smart",
		Slot:     "smart",
		Stream:   true,
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}, func(ChatEvent) {})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context error when cancelled mid-stream")
	}
	if elapsed > 600*time.Millisecond {
		t.Fatalf("continuous streaming ignored ctx cancel for %v", elapsed)
	}
}

// P2-10: CBOR indefinite-length map duplicate keys must not bypass the entry cap,
// and EventStream headersLen with high bit set must be rejected safely without panic.
func TestWireCBORIndefiniteMapCapAndEventStreamUnsignedBounds(t *testing.T) {
	// 65537 duplicate entries {"a": 1} inside an indefinite-length map (0xbf ... 0xff).
	buf := make([]byte, 0, 2+65537*3)
	buf = append(buf, 0xbf)
	for i := 0; i < 65537; i++ {
		buf = append(buf, 0x61, 'a', 0x01)
	}
	buf = append(buf, 0xff)
	if _, err := CBORDecode(buf); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected CBOR indefinite map duplicate-key cap error, got %v", err)
	}

	// EventStream prelude with total=20 and headersLen=0xffffffff (negative if cast to int32).
	badFrame := make([]byte, 20)
	badFrame[3] = 20
	badFrame[4], badFrame[5], badFrame[6], badFrame[7] = 0xff, 0xff, 0xff, 0xff
	if _, err := EventStreamDecodeAll(badFrame); err == nil || !strings.Contains(err.Error(), "invalid event-stream lengths") {
		t.Fatalf("expected invalid event-stream lengths error for high-bit headersLen, got %v", err)
	}
}

func TestDelayOutputCoversStructuredFormatsOnly(t *testing.T) {
	if (ChatRequest{MaxOutputTokens: 1024}).DelayOutput() {
		t.Fatal("MaxOutputTokens must not disable live streaming via DelayOutput")
	}
	for _, rf := range []any{
		map[string]any{"type": "json_object"},
		map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "x", "strict": false, "schema": map[string]any{"type": "object"}}},
		map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "x", "strict": true, "schema": map[string]any{"type": "object"}}},
	} {
		if !(ChatRequest{ResponseFormat: rf}).DelayOutput() {
			t.Fatalf("expected DelayOutput=true for %#v", rf)
		}
	}
}

func TestDelayedStreamingReasoningWithEmptyTextDoesNotEmit(t *testing.T) {
	srv, _ := newMockQuick(t, func(_ int, _ *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		send(map[string]any{"type": "thinking_delta", "payload": map[string]any{"delta": "internal thought"}})
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "   \n"}})
		send(map[string]any{"type": "message_complete", "payload": map[string]any{}})
		send(map[string]any{"type": "turn_completed", "payload": map[string]any{}})
	})
	client, acct := mockClient(srv, 65536)
	var emitted []ChatEvent
	_, err := client.Chat(context.Background(), acct, ChatRequest{
		Model:          "amazon-smart",
		Slot:           "smart",
		Stream:         true,
		ResponseFormat: map[string]any{"type": "json_object"},
		Messages:       []map[string]any{{"role": "user", "content": "hi"}},
	}, func(ev ChatEvent) {
		emitted = append(emitted, ev)
	})
	if err == nil {
		t.Fatal("expected invalid_structured_output error for whitespace-only json_object reply")
	}
	if len(emitted) != 0 {
		t.Fatalf("delayed streaming must not emit reasoning/whitespace before validation, got %+v", emitted)
	}
}

func TestThreadReuseIgnoresAssistantReasoningContent(t *testing.T) {
	srv, count := newMockQuick(t, func(_ int, _ *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		send(map[string]any{"type": "thinking_delta", "payload": map[string]any{"delta": "let me think"}})
		completeTurn(send, "Answer one.")
	})
	client, acct := mockClient(srv, 65536)
	req1 := ChatRequest{
		Model:         "amazon-smart",
		Slot:          "smart",
		ThreadSession: "sess-rsn",
		Messages:      []map[string]any{{"role": "user", "content": "Q1"}},
	}
	res1, err := client.Chat(context.Background(), acct, req1, nil)
	if err != nil {
		t.Fatalf("turn 1 failed: %v", err)
	}
	if res1.Reasoning == "" {
		t.Fatal("expected non-empty reasoning on turn 1")
	}

	// Turn 2 omits reasoning_content (matching /v1/messages, /v1/responses, and standard OpenAI clients).
	req2 := ChatRequest{
		Model:         "amazon-smart",
		Slot:          "smart",
		ThreadSession: "sess-rsn",
		Messages: []map[string]any{
			{"role": "user", "content": "Q1"},
			{"role": "assistant", "content": "Answer one."},
			{"role": "user", "content": "Q2"},
		},
	}
	res2, err := client.Chat(context.Background(), acct, req2, nil)
	if err != nil {
		t.Fatalf("turn 2 failed: %v", err)
	}
	if !res2.ThreadReused || res2.ThreadID != res1.ThreadID {
		t.Fatalf("expected thread reuse without echoed reasoning_content (t1=%s t2=%s reused=%v)", res1.ThreadID, res2.ThreadID, res2.ThreadReused)
	}
	if count() != 2 {
		t.Fatalf("expected 2 attempts, got %d", count())
	}
}

func TestStrictJSONSchemaSupportsNonObjectRoot(t *testing.T) {
	arraySchema := map[string]any{
		"type": "json_schema",
		"json_schema": map[string]any{
			"name":   "tags",
			"strict": true,
			"schema": map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "string"},
			},
		},
	}
	srv, _ := newMockQuick(t, func(n int, _ *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		if n == 1 {
			completeTurn(send, `["alpha","beta"]`)
			return
		}
		completeTurn(send, `{"wrong":true}`)
	})
	client, acct := mockClient(srv, 65536)
	res, err := client.Chat(context.Background(), acct, ChatRequest{
		Model:          "amazon-smart",
		Slot:           "smart",
		ResponseFormat: arraySchema,
		Messages:       []map[string]any{{"role": "user", "content": "tags"}},
	}, nil)
	if err != nil || res.Text != `["alpha","beta"]` {
		t.Fatalf("expected valid array root to pass strict schema, got res=%q err=%v", res.Text, err)
	}
	if _, err := client.Chat(context.Background(), acct, ChatRequest{
		Model:          "amazon-smart",
		Slot:           "smart",
		ResponseFormat: arraySchema,
		Messages:       []map[string]any{{"role": "user", "content": "tags"}},
	}, nil); err == nil {
		t.Fatal("expected object to fail array root strict schema")
	}
}

func TestRateLimitSkipsStaleThreadRetryAndNonStreamSkipsLiveOutput(t *testing.T) {
	srv, count := newMockQuick(t, func(n int, _ *websocket.Conn, send func(map[string]any), _ func([]byte)) {
		switch n {
		case 1:
			completeTurn(send, "ok")
		case 2:
			send(map[string]any{"type": "error", "payload": map[string]any{"code": "ThrottlingException", "message": "rate limit exceeded"}})
		default:
			completeTurn(send, "unexpected retry")
		}
	})
	client, acct := mockClient(srv, 65536)
	var nonStreamEvents int
	_, err := client.Chat(context.Background(), acct, ChatRequest{
		Model:         "amazon-smart",
		Slot:          "smart",
		Stream:        false,
		ThreadSession: "sess-rl",
		Messages:      []map[string]any{{"role": "user", "content": "hi"}},
	}, func(ChatEvent) {
		nonStreamEvents++
	})
	if err != nil {
		t.Fatalf("turn 1 failed: %v", err)
	}
	if nonStreamEvents != 0 {
		t.Fatalf("non-streaming turn must not invoke streaming onEvent callback, got %d events", nonStreamEvents)
	}
	_, err = client.Chat(context.Background(), acct, ChatRequest{
		Model:         "amazon-smart",
		Slot:          "smart",
		Stream:        false,
		ThreadSession: "sess-rl",
		Messages: []map[string]any{
			{"role": "user", "content": "hi"},
			{"role": "assistant", "content": "ok"},
			{"role": "user", "content": "next"},
		},
	}, nil)
	if err == nil {
		t.Fatal("expected rate limit error on turn 2")
	}
	if count() != 2 {
		t.Fatalf("rate-limited resumed thread must not retry on fresh thread, got %d upstream attempts", count())
	}
}

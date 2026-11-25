package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
	"awsquick2api/internal/pool"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/scheduler"
	"awsquick2api/internal/session"
	"awsquick2api/internal/upstream"
)

// mockReply is invoked once per upstream user_message with the prompt text; it streams
// AIDP envelopes back through send.
type mockReply func(send func(env map[string]any), prompt string)

func sendAIDPFrame(conn *websocket.Conn, mu *sync.Mutex, env map[string]any) {
	inner, _ := json.Marshal(env)
	outer, _ := json.Marshal(map[string]any{"payload": base64.StdEncoding.EncodeToString(inner)})
	frame := upstream.EventStreamEncode(map[string]string{
		":event-type":   "rawOutputEvent",
		":message-type": "event",
	}, outer)
	mu.Lock()
	defer mu.Unlock()
	_ = conn.WriteMessage(websocket.BinaryMessage, frame)
}

// newMockQuick starts a fake OIDC + Quick data-plane server. Handshakes presenting
// rejectToken get HTTP 401; all other handshakes are served by reply.
func newMockQuick(t *testing.T, rejectToken string, reply mockReply) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var handshakes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessToken":  "fresh_token",
				"refreshToken": "fresh_refresh",
				"expiresIn":    3600,
			})
		case "/integration/quick-work/user-info":
			_ = json.NewEncoder(w).Encode(map[string]any{"userInfo": map[string]any{"email": "u1@example.com"}})
		case auth.DefaultWSPath:
			handshakes.Add(1)
			if rejectToken != "" && r.URL.Query().Get("token") == rejectToken {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("expired"))
				return
			}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			var wmu sync.Mutex
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
				dec, _ := base64.StdEncoding.DecodeString(outer.Payload.Payload)
				var msg map[string]any
				_ = json.Unmarshal(dec, &msg)
				if msg["type"] != "user_message" {
					continue
				}
				p, _ := msg["payload"].(map[string]any)
				txt, _ := p["text"].(string)
				reply(func(env map[string]any) { sendAIDPFrame(conn, &wmu, env) }, txt)
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &handshakes
}

func completeTurn(send func(map[string]any)) {
	send(map[string]any{"type": "turn_usage", "payload": map[string]any{"input_tokens": 5, "output_tokens": 3}})
	send(map[string]any{"type": "message_complete", "payload": map[string]any{"continuation_expected": false}})
	send(map[string]any{"type": "turn_completed", "payload": map[string]any{}})
}

type testGateway struct {
	h    *Handler
	pool *pool.Pool
}

func newTestGateway(t *testing.T, mockURL, accessToken string, maxInFlight int, mutate func(*config.Config)) *testGateway {
	t.Helper()
	cfg := config.Default()
	cfg.APIKey = "qk_test_key"
	cfg.Upstream.OIDCBase = mockURL
	cfg.Upstream.DataPlaneURL = mockURL
	cfg.Upstream.Stateful = false
	if mutate != nil {
		mutate(cfg)
	}
	p := pool.New(pool.Config{MaxInFlight: maxInFlight})
	p.SyncAccounts([]*auth.Account{{
		UID:           "soc_u1_example_com_abcd",
		Email:         "u1@example.com",
		Provider:      auth.ProviderSocial,
		Stage:         "prod",
		Region:        "us-east-1",
		IDCRegion:     "us-east-1",
		TenantURL:     mockURL,
		WSHost:        "ws://" + strings.TrimPrefix(mockURL, "http://"),
		TokenEndpoint: mockURL + "/token",
		ClientID:      "cid",
		AccessToken:   accessToken,
		RefreshToken:  "ref_1",
		ExpiresAt:     time.Now().Add(time.Hour).UnixMilli(),
		DeviceID:      auth.NewUUID(),
	}})
	up := upstream.NewClient(cfg.Upstream, nil)
	h := NewHandler(Config{
		Pool:             p,
		Upstream:         up,
		Scheduler:        scheduler.New(scheduler.Config{Pool: p, Upstream: up}),
		Session:          session.New(10 * time.Minute),
		Live:             config.NewLiveHolder(cfg),
		ReqLog:           reqlog.New("", false),
		QueueWaitTimeout: 2 * time.Second,
		Version:          "test",
	})
	return &testGateway{h: h, pool: p}
}

func (g *testGateway) totalInFlight() int {
	n := 0
	for _, v := range g.pool.Snapshot() {
		n += v.InFlight
	}
	return n
}

func postJSON(h http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer qk_test_key")
	req.Header.Set("x-api-key", "qk_test_key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// P0-2: a 401 refresh retry followed by an empty-reply retry used to exit the
// per-account loop without releasing the lease, permanently consuming in-flight slots.
func TestLeaseReleasedAfterAuthRefreshAndEmptyRetry(t *testing.T) {
	mock, handshakes := newMockQuick(t, "stale_token", func(send func(map[string]any), _ string) {
		completeTurn(send) // empty reply: no text, no tool calls
	})
	g := newTestGateway(t, mock.URL, "stale_token", 2, nil)

	// One request walks: 401 -> refresh -> retry (empty) -> empty-retry (empty) -> 502.
	// (Afterwards the account is in soft-failure cooldown, so later requests would
	// legitimately get 503; the invariant under test is the in-flight counter.)
	w := postJSON(g.h, "/v1/chat/completions", `{"model":"amazon-smart","messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "upstream_empty_response") {
		t.Fatalf("expected 502 upstream_empty_response, got %d %s", w.Code, w.Body.String())
	}
	if n := g.totalInFlight(); n != 0 {
		t.Fatalf("in-flight leases = %d after request returned, want 0 (lease leaked)", n)
	}
	if handshakes.Load() < 3 {
		t.Fatalf("expected the 401 + refresh + empty retry path to be exercised, handshakes=%d", handshakes.Load())
	}
}

// P0-3: the header_wait timer used to call onStartStream concurrently with onEvent and
// with the error path, racing on ResponseWriter headers and reordering SSE events.
func TestHeaderWaitTimerSerializedWithStreamEvents(t *testing.T) {
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		// First event lands right around the 1s header_wait deadline.
		time.Sleep(990 * time.Millisecond)
		for i := 0; i < 20; i++ {
			send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "tok "}})
		}
		completeTurn(send)
	})
	const n = 6
	g := newTestGateway(t, mock.URL, "good_token", n, func(c *config.Config) {
		c.Upstream.HeaderWaitSeconds = 1
	})
	srv := httptest.NewServer(g.h)
	defer srv.Close()

	paths := []struct{ path, body, first, delta string }{
		{"/v1/messages", `{"model":"claude-sonnet-4-5","stream":true,"max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`, "event: message_start", "event: content_block_delta"},
		{"/v1/chat/completions", `{"model":"amazon-smart","stream":true,"messages":[{"role":"user","content":"hi"}]}`, `"role":"assistant"`, `"content":"tok `},
		{"/v1/responses", `{"model":"amazon-smart","stream":true,"input":"hi"}`, "event: response.created", "event: response.output_text.delta"},
	}
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pc := paths[i%len(paths)]
			req, _ := http.NewRequest(http.MethodPost, srv.URL+pc.path, strings.NewReader(pc.body))
			req.Header.Set("Authorization", "Bearer qk_test_key")
			req.Header.Set("x-api-key", "qk_test_key")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err.Error()
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			out := string(b)
			if resp.StatusCode != http.StatusOK {
				errs <- pc.path + ": status " + resp.Status + ": " + out
				return
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
				errs <- pc.path + ": content-type " + ct
				return
			}
			fi, di := strings.Index(out, pc.first), strings.Index(out, pc.delta)
			if fi < 0 || di < 0 || di < fi {
				errs <- pc.path + ": stream start event missing or after first delta: " + out
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if n := g.totalInFlight(); n != 0 {
		t.Fatalf("in-flight leases = %d, want 0", n)
	}
}

// P1-1: public responses must not carry the e-mail-derived account UID.
func TestAccountHeaderIsOpaque(t *testing.T) {
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "Hello"}})
		completeTurn(send)
	})
	g := newTestGateway(t, mock.URL, "good_token", 2, nil)
	for _, tc := range []struct{ path, body string }{
		{"/v1/chat/completions", `{"model":"amazon-smart","messages":[{"role":"user","content":"hi"}]}`},
		{"/v1/chat/completions", `{"model":"amazon-smart","stream":true,"messages":[{"role":"user","content":"hi"}]}`},
	} {
		w := postJSON(g.h, tc.path, tc.body)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", tc.path, w.Code, w.Body.String())
		}
		got := w.Header().Get("X-Quick-Account")
		if got == "" || len(got) != 12 || strings.Contains(got, "u1") || strings.Contains(got, "example") {
			t.Fatalf("X-Quick-Account leaks or is malformed: %q", got)
		}
		if got != opaqueAccountID("soc_u1_example_com_abcd") {
			t.Fatalf("X-Quick-Account = %q, want stable digest", got)
		}
	}
}

func TestModelPermittedEnforcesAllowAndHidden(t *testing.T) {
	cat := upstream.DefaultCatalog()
	check := func(allowed, hidden []string, model string) bool {
		cfg := config.Default()
		cfg.Models.Allowed = allowed
		cfg.Models.Hidden = hidden
		snap := config.SnapshotFromConfig(cfg)
		slot, spec, eff, known := cat.Resolve(model, snap.Upstream.DefaultModel, true)
		return modelPermitted(snap, cat, model, slot, spec, eff, known)
	}
	if !check(nil, nil, "amazon-smart") {
		t.Fatal("no allowlist: amazon-smart must be permitted")
	}
	if check([]string{"amazon-fast"}, nil, "amazon-smart") {
		t.Fatal("allowlist [amazon-fast] must reject amazon-smart")
	}
	if !check([]string{"amazon-fast"}, nil, "amazon-fast") {
		t.Fatal("allowlist [amazon-fast] must accept amazon-fast")
	}
	if !check([]string{"amazon-fast"}, nil, "aws-quick/amazon-fast") {
		t.Fatal("provider prefix must not defeat allowlist match")
	}
	if check([]string{"amazon-fast"}, nil, "claude-opus-4-6") {
		t.Fatal("allowlist [amazon-fast] must reject claude aliases mapped to other slots")
	}
	if check(nil, []string{"amazon-smart"}, "amazon-smart") {
		t.Fatal("hidden amazon-smart must be rejected")
	}
	if !check([]string{"amazon-fast"}, nil, "") {
		t.Fatal("empty model maps to operator default and must be permitted")
	}
	// P2-3: unknown model names must not bypass allowlist or hidden default slot.
	if check([]string{"smart"}, nil, "unknown-bypass-model") {
		t.Fatal("allowlist [smart] must reject unknown model name falling back to default slot")
	}
	if check([]string{"amazon-smart"}, nil, "unknown-bypass-model") {
		t.Fatal("allowlist [amazon-smart] must reject unknown model name")
	}
	if check(nil, []string{"smart"}, "amazon-smart") {
		t.Fatal("hidden canonical slot [smart] must reject amazon-smart")
	}
	if check(nil, []string{"smart"}, "claude-opus-4-6") {
		t.Fatal("hidden canonical slot [smart] must reject claude alias resolving to smart")
	}
	if check(nil, []string{"amazon-smart"}, "unknown-bypass-model") {
		t.Fatal("unknown model falling back to hidden default slot model ID must be rejected")
	}
	if check(nil, []string{"smart"}, "unknown-bypass-model") {
		t.Fatal("unknown model falling back to hidden default slot name must be rejected")
	}
	if !check(nil, []string{"amazon-fast"}, "unknown-fallback-ok") {
		t.Fatal("unknown model falling back to non-hidden default without allowlist should remain permitted")
	}
}

func TestModelNotAllowedReturns403WithoutAcquire(t *testing.T) {
	mock, handshakes := newMockQuick(t, "", func(send func(map[string]any), _ string) { completeTurn(send) })
	g := newTestGateway(t, mock.URL, "good_token", 2, func(c *config.Config) {
		c.Models.Allowed = []string{"amazon-fast"}
	})
	w := postJSON(g.h, "/v1/chat/completions", `{"model":"amazon-smart","messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "model_not_allowed") {
		t.Fatalf("expected 403 model_not_allowed, got %d %s", w.Code, w.Body.String())
	}
	w = postJSON(g.h, "/v1/messages", `{"model":"amazon-smart","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "permission_error") {
		t.Fatalf("expected anthropic 403 permission_error, got %d %s", w.Code, w.Body.String())
	}
	if handshakes.Load() != 0 {
		t.Fatalf("rejected model must not reach upstream, handshakes=%d", handshakes.Load())
	}
}

func TestCountTokensRejectsMissingMessages(t *testing.T) {
	g := &testGateway{h: NewHandler(Config{Live: config.NewLiveHolder(func() *config.Config {
		c := config.Default()
		c.APIKey = "qk_test_key"
		return c
	}())})}
	for _, body := range []string{`{}`, `{"messages":null}`, `{"messages":[]}`, `{"messages":"x"}`} {
		w := postJSON(g.h, "/v1/messages/count_tokens", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %s: expected 400, got %d %s", body, w.Code, w.Body.String())
		}
	}
	w := postJSON(g.h, "/v1/messages/count_tokens", `{"messages":[{"role":"user","content":"hello"}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("valid count_tokens: %d %s", w.Code, w.Body.String())
	}
}

func TestSSEKeepaliveStopWaitsForInFlightSend(t *testing.T) {
	var (
		running atomic.Int32
		after   atomic.Int32
		stopped atomic.Bool
	)
	k := startSSEKeepalive(context.Background(), 5*time.Millisecond, func() {
		running.Add(1)
		time.Sleep(20 * time.Millisecond)
		if stopped.Load() {
			after.Add(1)
		}
		running.Add(-1)
	})
	time.Sleep(12 * time.Millisecond)
	k.Stop()
	stopped.Store(true)
	if running.Load() != 0 {
		t.Fatal("Stop returned while a heartbeat send was still running")
	}
	time.Sleep(30 * time.Millisecond)
	if after.Load() != 0 {
		t.Fatal("heartbeat ran after Stop returned")
	}
	k.Stop() // idempotent
	var nilK *sseKeepalive
	nilK.Stop() // nil-safe
}

func TestResponsesRequestTranslationFidelity(t *testing.T) {
	// previous_response_id cannot be honored by this stateless gateway.
	if _, _, err := responsesToChatRequest(map[string]any{"input": "hi", "previous_response_id": "resp_1"}, http.Header{}); err == nil {
		t.Fatal("previous_response_id must be rejected explicitly")
	}

	body := map[string]any{
		"input": []any{
			map[string]any{"role": "user", "content": "do two things"},
			map[string]any{"type": "function_call", "call_id": "c1", "name": "a", "arguments": "{}"},
			map[string]any{"type": "function_call", "call_id": "c2", "name": "b", "arguments": "{}"},
			map[string]any{"type": "custom_tool_call", "call_id": "c3", "name": "patch"},
			map[string]any{"type": "function_call_output", "call_id": "c1", "output": "ok"},
		},
		"text": map[string]any{"format": map[string]any{"type": "json_schema", "name": "out", "schema": map[string]any{"type": "object"}, "strict": true}},
	}
	req, _, err := responsesToChatRequest(body, http.Header{})
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Messages) != 3 {
		t.Fatalf("parallel calls must merge into one assistant message; got %d messages: %+v", len(req.Messages), req.Messages)
	}
	calls, _ := req.Messages[1]["tool_calls"].([]any)
	if len(calls) != 3 {
		t.Fatalf("expected 3 tool calls on the assistant message, got %d", len(calls))
	}
	fn := calls[2].(map[string]any)["function"].(map[string]any)
	if strings.Contains(fn["arguments"].(string), "<nil>") {
		t.Fatalf("missing custom tool input rendered as <nil>: %s", fn["arguments"])
	}
	rf, ok := req.ResponseFormat.(map[string]any)
	if !ok || rf["type"] != "json_schema" {
		t.Fatalf("text.format not mapped to response_format: %#v", req.ResponseFormat)
	}
	if js, _ := rf["json_schema"].(map[string]any); js["name"] != "out" || js["schema"] == nil {
		t.Fatalf("json_schema payload lost: %#v", rf)
	}
}

func TestResponsesCompletedReusesStreamedItemIDs(t *testing.T) {
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "Hello"}})
		completeTurn(send)
	})
	g := newTestGateway(t, mock.URL, "good_token", 2, nil)
	w := postJSON(g.h, "/v1/responses", `{"model":"amazon-smart","stream":true,"input":"hi"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var addedID, completedID string
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev map[string]any
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev) != nil {
			continue
		}
		switch ev["type"] {
		case "response.output_item.added":
			if item, _ := ev["item"].(map[string]any); item["type"] == "message" {
				addedID, _ = item["id"].(string)
			}
		case "response.completed":
			resp, _ := ev["response"].(map[string]any)
			out, _ := resp["output"].([]any)
			for _, o := range out {
				if om, _ := o.(map[string]any); om["type"] == "message" {
					completedID, _ = om["id"].(string)
				}
			}
		}
	}
	if addedID == "" || addedID != completedID {
		t.Fatalf("message item id mismatch: added=%q completed=%q", addedID, completedID)
	}
}

func TestAnthropicServerToolsSkippedAndIsErrorForwarded(t *testing.T) {
	body := map[string]any{
		"messages": []any{
			map[string]any{"role": "user", "content": "hi"},
			map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t1", "name": "run", "input": map[string]any{}}}},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "is_error": true, "content": "boom"}}},
		},
		"tools": []any{
			map[string]any{"type": "web_search_20250305", "name": "web_search", "max_uses": 3},
			map[string]any{"name": "run", "input_schema": map[string]any{"type": "object"}},
		},
	}
	req, err := anthropicToChatRequest(body, http.Header{})
	if err != nil {
		t.Fatal(err)
	}
	tools, _ := req.Tools.([]any)
	if len(tools) != 1 {
		t.Fatalf("server-side web_search tool must be skipped; got %d tools", len(tools))
	}
	last := req.Messages[len(req.Messages)-1]
	if last["role"] != "tool" || last["is_error"] != true {
		t.Fatalf("tool_result is_error not forwarded: %#v", last)
	}
}

// P1-11: the advanced tier must only be routed to accounts with AdvancedEnabled.
func TestAdvancedSlotRequiresAdvancedAccount(t *testing.T) {
	mock, handshakes := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "adv"}})
		completeTurn(send)
	})
	g := newTestGateway(t, mock.URL, "good_token", 2, nil)
	body := `{"model":"amazon-advanced","messages":[{"role":"user","content":"hi"}]}`

	w := postJSON(g.h, "/v1/chat/completions", body)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "model_not_available") {
		t.Fatalf("no advanced account: expected 400 model_not_available, got %d %s", w.Code, w.Body.String())
	}
	if handshakes.Load() != 0 {
		t.Fatalf("advanced request must not be sent to a non-advanced account, handshakes=%d", handshakes.Load())
	}
	if n := g.totalInFlight(); n != 0 {
		t.Fatalf("in-flight leases = %d, want 0", n)
	}

	g.pool.SetAdvancedEnabled("soc_u1_example_com_abcd", true)
	w = postJSON(g.h, "/v1/chat/completions", body)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "adv") {
		t.Fatalf("advanced account available: expected 200, got %d %s", w.Code, w.Body.String())
	}
	if n := g.totalInFlight(); n != 0 {
		t.Fatalf("in-flight leases = %d, want 0", n)
	}
}

// P1-11: advanced accounts that exist but are temporarily unusable must not be
// reported as a 400 "model not available" client error.
func TestAdvancedSlotUnavailableAccountIsNot400(t *testing.T) {
	// Cooling-down advanced account: AcquireWith yields ErrNoAdvancedAccounts with no
	// prior attempt, but the pool does have advanced capacity -> 503.
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) { completeTurn(send) })
	g := newTestGateway(t, mock.URL, "good_token", 2, nil)
	g.pool.SetAdvancedEnabled("soc_u1_example_com_abcd", true)
	g.pool.MarkSoftFailure("soc_u1_example_com_abcd", "test_cooldown")
	body := `{"model":"amazon-advanced","messages":[{"role":"user","content":"hi"}]}`
	w := postJSON(g.h, "/v1/chat/completions", body)
	if w.Code == http.StatusBadRequest || strings.Contains(w.Body.String(), "model_not_available") {
		t.Fatalf("cooling-down advanced account must not map to 400, got %d %s", w.Code, w.Body.String())
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for temporarily unavailable advanced account, got %d %s", w.Code, w.Body.String())
	}

	// Advanced account rejected with 401 (refresh does not help) and excluded after
	// the attempt: the client must see the upstream error, not a 400.
	mock2, _ := newMockQuick(t, "fresh_token", func(send func(map[string]any), _ string) { completeTurn(send) })
	g2 := newTestGateway(t, mock2.URL, "fresh_token", 2, nil)
	g2.pool.SetAdvancedEnabled("soc_u1_example_com_abcd", true)
	w = postJSON(g2.h, "/v1/chat/completions", body)
	if w.Code == http.StatusBadRequest || strings.Contains(w.Body.String(), "model_not_available") {
		t.Fatalf("401-excluded advanced account must not map to 400, got %d %s", w.Code, w.Body.String())
	}
	if n := g2.totalInFlight(); n != 0 {
		t.Fatalf("in-flight leases = %d, want 0", n)
	}
}

// P1-1: once a streaming turn is committed (e.g. after first delta), an upstream error
// must still cool down / rate-limit the account and unbind the sticky session without rotating.
func TestCommittedStreamErrorStillPenalizesAndUnbindsSession(t *testing.T) {
	mock, handshakes := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		// Emit enough benign text to flush past the privacy DLP lookahead window and commit SSE headers.
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": strings.Repeat("hello world ", 25)}})
		send(map[string]any{"type": "error", "payload": map[string]any{"message": "ThrottlingException: rate limit exceeded"}})
	})
	g := newTestGateway(t, mock.URL, "good_token", 2, nil)
	const uid = "soc_u1_example_com_abcd"
	sessKey := session.DeriveKey("conv_sticky_1", nil)
	g.h.cfg.Session.Bind(sessKey, uid, "conv_sticky_1")

	body := `{"model":"amazon-smart","stream":true,"conversation_id":"conv_sticky_1","messages":[{"role":"user","content":"hi"}]}`
	w := postJSON(g.h, "/v1/chat/completions", body)
	if w.Code != http.StatusOK {
		t.Fatalf("committed stream should have HTTP 200 SSE status, got %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("expected SSE error event in body: %s", w.Body.String())
	}
	if handshakes.Load() != 1 {
		t.Fatalf("committed stream must not rotate/retry, handshakes=%d", handshakes.Load())
	}
	if g.pool.IsEligible(uid) {
		t.Fatal("account must be placed in cooldown after committed stream upstream error")
	}
	if _, _, stillBound := g.h.cfg.Session.Lookup(sessKey); stillBound {
		t.Fatal("sticky session must be unbound after committed stream upstream error")
	}
}

// P2-4: upstream errors returned to /v1/* callers (both JSON and SSE) must have credentials scrubbed.
func TestUpstreamErrorScrubbedOnPublicEndpoints(t *testing.T) {
	secretMsg := "upstream dial wss://cell001.example/stream?token=secretWsTok999 via http://alice:proxyPass88@p:8080 key qk_my-custom-secret-1234"
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), prompt string) {
		if strings.Contains(prompt, "COMMIT_FIRST") {
			send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": strings.Repeat("hello world ", 25)}})
		}
		send(map[string]any{"type": "error", "payload": map[string]any{"message": secretMsg}})
	})

	cases := []struct {
		name     string
		path     string
		body     string
		wantCode int
	}{
		{"openai non-stream", "/v1/chat/completions", `{"model":"amazon-smart","messages":[{"role":"user","content":"hi"}]}`, http.StatusBadGateway},
		{"openai stream", "/v1/chat/completions", `{"model":"amazon-smart","stream":true,"messages":[{"role":"user","content":"COMMIT_FIRST"}]}`, http.StatusOK},
		{"anthropic non-stream", "/v1/messages", `{"model":"claude-sonnet-4-5","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`, http.StatusBadGateway},
		{"anthropic stream", "/v1/messages", `{"model":"claude-sonnet-4-5","stream":true,"max_tokens":32,"messages":[{"role":"user","content":"COMMIT_FIRST"}]}`, http.StatusOK},
		{"responses non-stream", "/v1/responses", `{"model":"amazon-smart","input":"hi"}`, http.StatusBadGateway},
		{"responses stream", "/v1/responses", `{"model":"amazon-smart","stream":true,"input":"COMMIT_FIRST"}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGateway(t, mock.URL, "good_token", 2, nil)
			w := postJSON(g.h, tc.path, tc.body)
			if w.Code != tc.wantCode {
				t.Fatalf("%s: status = %d, want %d; body=%s", tc.name, w.Code, tc.wantCode, w.Body.String())
			}
			out := w.Body.String()
			for _, leaked := range []string{"secretWsTok999", "proxyPass88", "my-custom-secret-1234"} {
				if strings.Contains(out, leaked) {
					t.Fatalf("%s leaked secret %q in response: %s", tc.name, leaked, out)
				}
			}
			if !strings.Contains(out, "REDACTED") {
				t.Fatalf("%s expected redaction marker in response: %s", tc.name, out)
			}
		})
	}
}

// P3: transient 401 token refresh failure must only count as a single soft failure, not two.
func TestTransient401RefreshFailureNoDoubleMarkSoftFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
		case auth.DefaultWSPath:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("expired"))
		}
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.APIKey = "qk_test_key"
	cfg.Upstream.OIDCBase = srv.URL
	cfg.Upstream.DataPlaneURL = srv.URL
	cfg.Upstream.Stateful = false

	p := pool.New(pool.Config{
		MaxInFlight:     2,
		SoftCooldown:    5 * time.Second,
		BreakerThresh:   2, // A double MarkSoftFailure would trip the circuit breaker on a single request!
		BreakerCooldown: 10 * time.Minute,
	})
	const uid = "soc_u1_example_com_abcd"
	p.SyncAccounts([]*auth.Account{{
		UID:           uid,
		Email:         "u1@example.com",
		Provider:      auth.ProviderSocial,
		Stage:         "prod",
		Region:        "us-east-1",
		IDCRegion:     "us-east-1",
		TenantURL:     srv.URL,
		WSHost:        "ws://" + strings.TrimPrefix(srv.URL, "http://"),
		TokenEndpoint: srv.URL + "/token",
		ClientID:      "cid",
		AccessToken:   "stale_tok",
		RefreshToken:  "ref_1",
		ExpiresAt:     time.Now().Add(time.Hour).UnixMilli(),
		DeviceID:      auth.NewUUID(),
	}})
	up := upstream.NewClient(cfg.Upstream, nil)
	h := NewHandler(Config{
		Pool:      p,
		Upstream:  up,
		Scheduler: scheduler.New(scheduler.Config{Pool: p, Upstream: up}),
		Session:   session.New(10 * time.Minute),
		Live:      config.NewLiveHolder(cfg),
		ReqLog:    reqlog.New("", false),
		Version:   "test",
	})

	_ = postJSON(h, "/v1/chat/completions", `{"model":"amazon-smart","messages":[{"role":"user","content":"hi"}]}`)
	views := p.Snapshot()
	if len(views) != 1 {
		t.Fatalf("expected 1 account, got %d", len(views))
	}
	if strings.HasPrefix(views[0].CooldownReason, "circuit_breaker:") {
		t.Fatalf("single transient 401 refresh failure tripped circuit breaker (double MarkSoftFailure): %+v", views[0])
	}
	if views[0].CooldownReason != "401_refresh_failed" {
		t.Fatalf("expected cooldown reason 401_refresh_failed, got %q", views[0].CooldownReason)
	}
}

// P3: Anthropic tool_use.input must always be a JSON object even if tool arguments are non-object JSON.
func TestAnthropicToolUseNonObjectInputCoercedToObject(t *testing.T) {
	w := httptest.NewRecorder()
	writeAnthropicNonStream(w, "msg_1", "claude-sonnet-4-5", upstream.ChatResult{
		ToolCalls: []upstream.ToolCall{
			{ID: "tc_1", Name: "fn_arr", Arguments: `[1,2,3]`},
			{ID: "tc_2", Name: "fn_str", Arguments: `"hello"`},
			{ID: "tc_3", Name: "fn_obj", Arguments: `{"a":1}`},
		},
	})
	var resp struct {
		Content []struct {
			Type  string `json:"type"`
			Name  string `json:"name"`
			Input any    `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Content) != 3 {
		t.Fatalf("expected 3 tool_use blocks, got %d", len(resp.Content))
	}
	for i, c := range resp.Content {
		obj, ok := c.Input.(map[string]any)
		if !ok {
			t.Fatalf("block %d (%s) input is not a JSON object: %#v", i, c.Name, c.Input)
		}
		if c.Name == "fn_obj" && obj["a"] != float64(1) {
			t.Fatalf("valid object input was altered: %#v", obj)
		}
		if c.Name != "fn_obj" && len(obj) != 0 {
			t.Fatalf("non-object input for %s should coerce to {}, got %#v", c.Name, obj)
		}
	}
}

// P3: Responses buildResponsesObject normalizes empty arguments to {} and responsesToChatRequest
// ignores unknown non-message input item types cleanly.
func TestResponsesEmptyArgumentsAndUnknownItemTypes(t *testing.T) {
	obj := buildResponsesObject("resp_1", 100, "amazon-smart", "completed", upstream.ChatResult{
		ToolCalls: []upstream.ToolCall{{ID: "c1", Name: "ping", Arguments: "   "}},
	}, nil, nil)
	out, _ := obj["output"].([]map[string]any)
	if len(out) != 1 || out[0]["arguments"] != "{}" {
		t.Fatalf("empty function_call arguments not normalized to {}: %#v", out)
	}

	req, _, err := responsesToChatRequest(map[string]any{
		"input": []any{
			map[string]any{"type": "item_reference", "id": "msg_prev"},
			map[string]any{"type": "web_search_call", "status": "completed"},
			map[string]any{"type": "message", "role": "user", "content": "actual prompt"},
		},
	}, http.Header{})
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Messages) != 1 || req.Messages[0]["content"] != "actual prompt" {
		t.Fatalf("unknown non-message items injected bogus messages: %#v", req.Messages)
	}
}

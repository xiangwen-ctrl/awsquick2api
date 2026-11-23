package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestServerThreeProtocolsAndRetryRotation(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var tokenExpiredOnce atomic.Bool
	tokenExpiredOnce.Store(true)

	sendAIDP := func(conn *websocket.Conn, env map[string]any) {
		inner, _ := json.Marshal(env)
		outer, _ := json.Marshal(map[string]any{"payload": base64.StdEncoding.EncodeToString(inner)})
		frame := upstream.EventStreamEncode(map[string]string{
			":event-type":   "rawOutputEvent",
			":message-type": "event",
		}, outer)
		_ = conn.WriteMessage(websocket.BinaryMessage, frame)
	}

	mockAWS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			tok := r.URL.Query().Get("token")
			if tok == "stale_token" && tokenExpiredOnce.CompareAndSwap(true, false) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("expired"))
				return
			}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
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
				sendAIDP(conn, map[string]any{"type": "thinking_delta", "payload": map[string]any{"delta": "step1"}})
				if strings.Contains(txt, "CALL_TOOL") {
					sendAIDP(conn, map[string]any{"type": "text_delta", "payload": map[string]any{"delta": `<client_tool_call>{"name":"get_time","arguments":{"tz":"UTC"}}</client_tool_call>`}})
				} else {
					sendAIDP(conn, map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "Hello world!"}})
				}
				sendAIDP(conn, map[string]any{"type": "turn_usage", "payload": map[string]any{"input_tokens": 50, "output_tokens": 12, "resolved_model_id": "claude-opus-4-6"}})
				sendAIDP(conn, map[string]any{"type": "message_complete", "payload": map[string]any{"continuation_expected": false}})
				sendAIDP(conn, map[string]any{"type": "turn_completed", "payload": map[string]any{}})
				return
			}
		}
	}))
	defer mockAWS.Close()

	cfg := config.Default()
	cfg.APIKey = "qk_test_key"
	cfg.Upstream.OIDCBase = mockAWS.URL
	cfg.Upstream.DataPlaneURL = mockAWS.URL
	cfg.Upstream.Stateful = false

	p := pool.New(pool.Config{MaxInFlight: 4})
	p.SyncAccounts([]*auth.Account{
		{
			UID:           "soc_u1",
			Email:         "u1@example.com",
			Provider:      auth.ProviderSocial,
			Stage:         "prod",
			Region:        "us-east-1",
			IDCRegion:     "us-east-1",
			TenantURL:     mockAWS.URL,
			WSHost:        "ws://" + strings.TrimPrefix(mockAWS.URL, "http://"),
			TokenEndpoint: mockAWS.URL + "/token",
			ClientID:      "cid",
			AccessToken:   "stale_token",
			RefreshToken:  "ref_1",
			ExpiresAt:     time.Now().Add(time.Hour).UnixMilli(),
			DeviceID:      auth.NewUUID(),
		},
	})

	up := upstream.NewClient(cfg.Upstream, nil)
	sch := scheduler.New(scheduler.Config{Pool: p, Upstream: up})
	sess := session.New(10 * time.Minute)
	rec := reqlog.New("", false)
	live := config.NewLiveHolder(cfg)

	h := NewHandler(Config{
		Pool:      p,
		Upstream:  up,
		Scheduler: sch,
		Session:   sess,
		Live:      live,
		ReqLog:    rec,
		Version:   "test",
	})

	// 1. GET /healthz
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("/healthz status=%d", w.Code)
	}

	// 2. GET /v1/models (auth required)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without key, got %d", w.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer qk_test_key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "amazon-smart") {
		t.Fatalf("unexpected /v1/models: %d %s", w.Code, w.Body.String())
	}

	// 3. POST /v1/chat/completions (also exercises pre-output 401 auto-refresh & single retry!)
	chatBody := `{"model":"amazon-smart-high","messages":[{"role":"user","content":"Hi"}],"stream":false}`
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(chatBody))
	req.Header.Set("Authorization", "Bearer qk_test_key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("OpenAI chat failed after 401 refresh retry: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Hello world!") || !strings.Contains(w.Body.String(), "step1") {
		t.Fatalf("unexpected OpenAI chat response: %s", w.Body.String())
	}

	// 4. POST /v1/messages (Anthropic Messages streaming with tool_use!)
	anthBody := `{"model":"claude-opus-4-6","stream":true,"messages":[{"role":"user","content":"CALL_TOOL"}],"tools":[{"name":"get_time","input_schema":{"type":"object","properties":{"tz":{"type":"string"}}}}]}`
	req = httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(anthBody))
	req.Header.Set("x-api-key", "qk_test_key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Anthropic stream failed: %d %s", w.Code, w.Body.String())
	}
	sseOut := w.Body.String()
	if !strings.Contains(sseOut, "event: message_start") || !strings.Contains(sseOut, `"type":"tool_use"`) || !strings.Contains(sseOut, `"name":"get_time"`) {
		t.Fatalf("unexpected Anthropic SSE: %s", sseOut)
	}

	// 5. POST /v1/messages/count_tokens
	req = httptest.NewRequest(http.MethodPost, "/messages/count_tokens", bytes.NewBufferString(`{"messages":[{"role":"user","content":"hello world"}]}`))
	req.Header.Set("x-api-key", "qk_test_key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "input_tokens") {
		t.Fatalf("count_tokens failed: %d %s", w.Code, w.Body.String())
	}

	// 6. POST /v1/responses (Codex Responses streaming) & GET /v1/responses (426)
	respBody := `{"model":"amazon-smart","stream":true,"input":"Hello Codex"}`
	req = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(respBody))
	req.Header.Set("Authorization", "Bearer qk_test_key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "response.output_text.delta") || !strings.Contains(w.Body.String(), "response.completed") {
		t.Fatalf("Responses stream failed: %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	req.Header.Set("Authorization", "Bearer qk_test_key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("expected 426 on GET /v1/responses, got %d", w.Code)
	}

	// 7. Verify reqlog stores metadata only (no prompt/reply content or client IP).
	recent := rec.Recent(10)
	if len(recent) < 3 {
		t.Fatalf("expected >= 3 recorded metadata entries, got %d", len(recent))
	}
	rawLog, _ := json.Marshal(recent)
	if strings.Contains(string(rawLog), "Hello world!") || strings.Contains(string(rawLog), "Hello Codex") {
		t.Fatalf("reqlog must never contain dialogue content: %s", string(rawLog))
	}
}

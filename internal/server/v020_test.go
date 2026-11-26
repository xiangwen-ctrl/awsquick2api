package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"awsquick2api/internal/apikeys"
	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
	"awsquick2api/internal/pool"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/scheduler"
	"awsquick2api/internal/upstream"
)

func TestV020ModelsMetadataSingleModelAndScopedKeys(t *testing.T) {
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), _ string) {
		send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "scoped ok"}})
		completeTurn(send)
	})

	cfg := config.Default()
	cfg.APIKey = "qk_master_key"
	cfg.Upstream.OIDCBase = mock.URL
	cfg.Upstream.DataPlaneURL = mock.URL
	cfg.Features.StrictPrivacyDLP = false

	p := pool.New(pool.Config{MaxInFlight: 4})
	p.AddOrUpdate(&auth.Account{
		UID:           "soc_v020_1",
		Email:         "v020@example.com",
		Provider:      auth.ProviderSocial,
		Stage:         "prod",
		Region:        "us-east-1",
		TenantURL:     mock.URL,
		WSHost:        "ws://" + strings.TrimPrefix(mock.URL, "http://"),
		TokenEndpoint: mock.URL + "/token",
		AccessToken:   "good_token",
		RefreshToken:  "ref_1",
		ExpiresAt:     time.Now().Add(time.Hour).UnixMilli(),
		DeviceID:      auth.NewUUID(),
	})

	ks, err := apikeys.NewStore(filepath.Join(t.TempDir(), "api-keys.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	view, scopedPlain, err := ks.Create(apikeys.CreateInput{
		Name:             "Fast Only Key",
		AllowedModels:    []string{"amazon-fast"},
		MaxDailyRequests: 2,
	})
	if err != nil {
		t.Fatalf("Create scoped key: %v", err)
	}

	up := upstream.NewClient(cfg.Upstream, nil)
	sch := scheduler.New(scheduler.Config{Pool: p, Upstream: up})
	rec := reqlog.New("", false)
	live := config.NewLiveHolder(cfg)

	h := NewHandler(Config{
		Pool:      p,
		Upstream:  up,
		Scheduler: sch,
		Live:      live,
		ReqLog:    rec,
		APIKeys:   ks,
		Version:   "0.2.0",
	})

	// 1. Master key GET /v1/models returns reasoning_options & supported_reasoning_levels.
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /v1/models: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"reasoning_options"`) || !strings.Contains(w.Body.String(), `"supported_reasoning_levels"`) {
		t.Fatalf("/v1/models missing reasoning metadata: %s", w.Body.String())
	}

	// 2. Master key GET /v1/models/{id}: existing -> 200, missing -> 404 model_not_found.
	req = httptest.NewRequest(http.MethodGet, "/v1/models/amazon-smart", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"id":"amazon-smart"`) || !strings.Contains(w.Body.String(), `"reasoning_options"`) {
		t.Fatalf("GET /v1/models/amazon-smart: %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/models/no-such-model", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"model_not_found"`) {
		t.Fatalf("GET /v1/models/no-such-model: %d %s", w.Code, w.Body.String())
	}

	// 3. Scoped key GET /v1/models only exposes allowed_models (amazon-fast).
	req = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+scopedPlain)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("scoped GET /v1/models: %d %s", w.Code, w.Body.String())
	}
	var listResp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	if len(listResp.Data) != 1 || listResp.Data[0].ID != "amazon-fast" {
		t.Fatalf("scoped /v1/models = %+v, want only [amazon-fast]", listResp.Data)
	}

	// 4. Scoped key GET /v1/models/{id} enforces allowed_models.
	req = httptest.NewRequest(http.MethodGet, "/v1/models/amazon-smart", nil)
	req.Header.Set("Authorization", "Bearer "+scopedPlain)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("scoped disallowed GET /v1/models/amazon-smart want 404, got %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/models/amazon-fast", nil)
	req.Header.Set("Authorization", "Bearer "+scopedPlain)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("scoped allowed GET /v1/models/amazon-fast want 200, got %d", w.Code)
	}

	// 5. Scoped key POST /v1/chat/completions rejects disallowed model (403 model_not_allowed).
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"amazon-smart","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer "+scopedPlain)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"model_not_allowed"`) {
		t.Fatalf("scoped disallowed chat want 403 model_not_allowed, got %d %s", w.Code, w.Body.String())
	}

	// 6. Scoped key succeeds on OpenAI (/v1/chat/completions) and Anthropic (/v1/messages via x-api-key).
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"amazon-fast","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer "+scopedPlain)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "scoped ok") {
		t.Fatalf("scoped OpenAI chat failed: %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"amazon-fast","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("x-api-key", scopedPlain)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "scoped ok") {
		t.Fatalf("scoped Anthropic messages failed: %d %s", w.Code, w.Body.String())
	}

	// 7. Verify reqlog tagged key_id & key_name, and usage counter hit daily limit (2) -> 3rd call returns 429.
	recent := rec.Recent(10)
	if len(recent) < 2 || recent[0].KeyID != view.ID || recent[0].KeyName != "Fast Only Key" {
		t.Fatalf("reqlog missing scoped key tags: %+v", recent)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"amazon-fast","input":"hi"}`))
	req.Header.Set("Authorization", "Bearer "+scopedPlain)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("scoped key over daily limit want 429, got %d %s", w.Code, w.Body.String())
	}

	// 8. Master api_key remains completely unaffected by scoped key limit.
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"amazon-smart","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("master api_key failed: %d %s", w.Code, w.Body.String())
	}
}

func TestV020PerRequestDynamicWebSearch(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var mu sync.Mutex
	var captured []bool

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
		if r.URL.Path != auth.DefaultWSPath {
			w.WriteHeader(http.StatusNotFound)
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
			pl, _ := msg["payload"].(map[string]any)
			wsEnabled, _ := pl["web_search_enabled"].(bool)
			mu.Lock()
			captured = append(captured, wsEnabled)
			mu.Unlock()
			sendAIDP(conn, map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "search reply"}})
			sendAIDP(conn, map[string]any{"type": "turn_usage", "payload": map[string]any{"input_tokens": 5, "output_tokens": 3}})
			sendAIDP(conn, map[string]any{"type": "message_complete", "payload": map[string]any{"continuation_expected": false}})
			sendAIDP(conn, map[string]any{"type": "turn_completed", "payload": map[string]any{}})
			return
		}
	}))
	defer mockAWS.Close()

	g := newTestGateway(t, mockAWS.URL, "good_token", 2, func(c *config.Config) {
		c.Upstream.WebSearch = false
		c.Features.StrictPrivacyDLP = false
	})

	// 1. /v1/responses with web_search_preview tool enables upstream web_search_enabled=true.
	w := postJSON(g.h, "/v1/responses", `{"model":"amazon-smart","input":"latest news","tools":[{"type":"web_search_preview"}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("responses web_search: %d %s", w.Code, w.Body.String())
	}
	// 2. /v1/messages with web_search_20250305 tool enables upstream web_search_enabled=true.
	w = postJSON(g.h, "/v1/messages", `{"model":"amazon-smart","max_tokens":64,"messages":[{"role":"user","content":"latest news"}],"tools":[{"type":"web_search_20250305","name":"web_search"}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("anthropic web_search: %d %s", w.Code, w.Body.String())
	}
	// 3. /v1/responses without web_search keeps default web_search_enabled=false.
	w = postJSON(g.h, "/v1/responses", `{"model":"amazon-smart","input":"hello"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("responses plain: %d %s", w.Code, w.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 3 || !captured[0] || !captured[1] || captured[2] {
		t.Fatalf("captured web_search_enabled = %v, want [true true false]", captured)
	}
}

func TestV020CORSAllowlistAndPanelIsolation(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "qk_cors_key"
	cfg.AdminKey = "qka_cors_admin"
	cfg.Server.CORSAllowedOrigins = []string{"https://chat.example.com"}

	dummyPanel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	h := NewHandler(Config{
		Live:     config.NewLiveHolder(cfg),
		Upstream: upstream.NewClient(cfg.Upstream, nil),
		Panel:    dummyPanel,
	})

	// 1. Preflight on /v1/chat/completions from allowed Origin -> 204 + ACAO + Vary: Origin.
	req := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
	req.Header.Set("Origin", "https://chat.example.com")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("CORS preflight status=%d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://chat.example.com" {
		t.Fatalf("ACAO = %q, want https://chat.example.com", got)
	}
	if !strings.Contains(w.Header().Get("Vary"), "Origin") {
		t.Fatalf("expected Vary: Origin, got %q", w.Header().Get("Vary"))
	}

	// 2. Disallowed Origin receives NO ACAO header.
	req = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("disallowed origin got ACAO=%q", got)
	}

	// 3. /panel/* MUST NEVER receive CORS headers even for an allowed origin.
	req = httptest.NewRequest(http.MethodOptions, "/panel/api/overview", nil)
	req.Header.Set("Origin", "https://chat.example.com")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("/panel/* leaked ACAO=%q", got)
	}
}

func TestV020OversizedPayload413DrainsCleanlyOverTCP(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "qk_413_key"
	h := NewHandler(Config{
		Live:                    config.NewLiveHolder(cfg),
		MaxPayloadBytes:         1024,
		MaxInflightPayloadBytes: 1024,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Send a 64 KiB body over real TCP; server must drain and return clean JSON 413 without connection reset.
	payload := bytes.Repeat([]byte("a"), 64*1024)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request failed (possible TCP reset before 413): %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read 413 body failed: %v", err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(body), `"payload_too_large"`) {
		t.Fatalf("expected clean JSON 413, got %d %s", resp.StatusCode, string(body))
	}
}

func TestV020UpstreamHealthTrackerSlidingWindow(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	tr := NewUpstreamHealthTracker()
	tr.now = func() time.Time { return now }

	// 499 and 4xx are ignored and never pollute samples.
	for range 20 {
		tr.Record(499, 15*time.Second)
		tr.Record(400, 15*time.Second)
	}
	if snap := tr.Snapshot(); snap.Samples != 0 || snap.Degraded {
		t.Fatalf("499/4xx polluted tracker: %+v", snap)
	}

	// 7 fast + 3 slow (>=8s) = 10 samples, 30% slow -> degraded=true.
	for range 7 {
		tr.Record(200, 500*time.Millisecond)
	}
	for range 3 {
		tr.Record(200, 9*time.Second)
	}
	snap := tr.Snapshot()
	if !snap.Degraded || snap.Samples != 10 || snap.SlowCount != 3 || snap.SlowPercent != 30 || snap.WorstTTFBMs != 9000 {
		t.Fatalf("unexpected slow degraded snapshot: %+v", snap)
	}

	// Advance past 5m window -> buckets expire, degraded clears.
	now = now.Add(6 * time.Minute)
	snap = tr.Snapshot()
	if snap.Degraded || snap.Samples != 0 {
		t.Fatalf("expected expired window to clear, got %+v", snap)
	}

	// 7 fast + 3 502s -> 30% 5xx -> degraded=true.
	for range 7 {
		tr.Record(200, 300*time.Millisecond)
	}
	for range 3 {
		tr.Record(502, 0)
	}
	snap = tr.Snapshot()
	if !snap.Degraded || snap.FailCount != 3 || snap.FailPercent != 30 {
		t.Fatalf("unexpected 5xx degraded snapshot: %+v", snap)
	}
}

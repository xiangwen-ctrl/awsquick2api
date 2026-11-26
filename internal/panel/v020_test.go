package panel

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"awsquick2api/internal/apikeys"
	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
	"awsquick2api/internal/pool"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/upstream"
)

func TestPanelV020ScopedKeysCRUDAndStrictIsolation(t *testing.T) {
	dir := t.TempDir()
	ks, err := apikeys.NewStore(filepath.Join(dir, "api-keys.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	pn, _, _ := newHardeningPanel(t, func(c *Config) {
		c.APIKeys = ks
		c.UpstreamHealth = func() any {
			return map[string]any{"window_seconds": 300, "samples": 12, "degraded": true, "slow_percent": 40}
		}
	})
	host := "127.0.0.1:8045"

	// 1. List initially empty.
	w := doPanelReq(pn, http.MethodGet, "/panel/api/keys", host, "", testAdminKey, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"keys":[]`) {
		t.Fatalf("initial keys list: %d %s", w.Code, w.Body.String())
	}

	// 2. Create scoped key.
	w = doPanelReq(pn, http.MethodPost, "/panel/api/keys", host, "", testAdminKey, map[string]any{
		"name":               "Cherry Studio",
		"allowed_models":     []string{"amazon-smart", "amazon-fast"},
		"max_daily_requests": 50,
		"max_total_tokens":   100000,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create key: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		OK        bool            `json:"ok"`
		Key       apikeys.KeyView `json:"key"`
		Plaintext string          `json:"plaintext"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create resp: %v", err)
	}
	if !created.OK || created.Key.ID == "" || !strings.HasPrefix(created.Plaintext, "qk_") {
		t.Fatalf("unexpected create payload: %+v", created)
	}

	// 3. Scoped key MUST NEVER unlock /panel/api/* (strict isolation).
	for _, path := range []string{"/panel/api/overview", "/panel/api/keys"} {
		wIso := doPanelReq(pn, http.MethodGet, path, host, "", created.Plaintext, nil)
		if wIso.Code != http.StatusUnauthorized {
			t.Fatalf("scoped key accepted on %s: status=%d", path, wIso.Code)
		}
	}

	// 4. Overview surfaces upstream_health & scoped_keys_count.
	w = doPanelReq(pn, http.MethodGet, "/panel/api/overview", host, "", testAdminKey, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("overview: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"scoped_keys_count":1`) || !strings.Contains(w.Body.String(), `"degraded":true`) {
		t.Fatalf("overview missing v0.2.0 fields: %s", w.Body.String())
	}

	// 5. Patch scoped key (rename + disable).
	w = doPanelReq(pn, http.MethodPatch, "/panel/api/keys/"+created.Key.ID, host, "", testAdminKey, map[string]any{
		"name":    "Cherry Updated",
		"enabled": false,
	})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"Cherry Updated"`) || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("patch key failed: %d %s", w.Code, w.Body.String())
	}

	// 6. Delete scoped key & confirm 404 on repeat.
	w = doPanelReq(pn, http.MethodDelete, "/panel/api/keys/"+created.Key.ID, host, "", testAdminKey, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete key failed: %d %s", w.Code, w.Body.String())
	}
	w = doPanelReq(pn, http.MethodDelete, "/panel/api/keys/"+created.Key.ID, host, "", testAdminKey, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("repeat delete want 404, got %d", w.Code)
	}
}

func TestPanelV020LogsExportZIPScrubbed(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "awsquick2api.log")
	rawSecretLine := "2026/06/01 12:00:00 WARN upstream failed Authorization: Bearer qk_supersecretvalue1234567890 access_token=\"tok_abc123456789\"\n"
	if err := os.WriteFile(logPath, []byte(rawSecretLine), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := reqlog.New("", false)
	_, _ = rec.Write([]byte("startup check Authorization: Bearer qka_adminsecretvalue987654321\n"))

	pn, _, _ := newHardeningPanel(t, func(c *Config) {
		c.ReqLog = rec
		c.LogFilePath = logPath
	})

	w := doPanelReq(pn, http.MethodGet, "/panel/api/logs/export", "127.0.0.1:8045", "", testAdminKey, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("logs export status=%d body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type = %q, want application/zip", ct)
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("invalid zip archive: %v", err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = string(b)
	}
	if _, ok := files["awsquick2api.log"]; !ok {
		t.Fatalf("zip missing awsquick2api.log: %v", files)
	}
	if _, ok := files["recent-runtime.log"]; !ok {
		t.Fatalf("zip missing recent-runtime.log: %v", files)
	}
	for name, content := range files {
		for _, forbidden := range []string{"qk_supersecretvalue1234567890", "tok_abc123456789", "qka_adminsecretvalue987654321"} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("zip entry %s leaked raw secret %q: %s", name, forbidden, content)
			}
		}
	}
}

func TestPanelV020PlaygroundEndpoint(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
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
			sendAIDP(conn, map[string]any{"type": "thinking_delta", "payload": map[string]any{"delta": "checking"}})
			sendAIDP(conn, map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "Playground OK!"}})
			sendAIDP(conn, map[string]any{"type": "turn_usage", "payload": map[string]any{"input_tokens": 11, "output_tokens": 4, "resolved_model_id": "claude-sonnet-4-6"}})
			sendAIDP(conn, map[string]any{"type": "message_complete", "payload": map[string]any{"continuation_expected": false}})
			sendAIDP(conn, map[string]any{"type": "turn_completed", "payload": map[string]any{}})
			return
		}
	}))
	defer mockAWS.Close()

	cfg := config.Default()
	cfg.APIKey = "qk_pg_test"
	cfg.AdminKey = testAdminKey
	cfg.Upstream.OIDCBase = mockAWS.URL
	cfg.Upstream.DataPlaneURL = mockAWS.URL
	cfg.Features.StrictPrivacyDLP = false

	p := pool.New(pool.Config{MaxInFlight: 2})
	p.AddOrUpdate(&auth.Account{
		UID:           "soc_pg_1",
		Email:         "pg@example.com",
		Provider:      auth.ProviderSocial,
		Stage:         "prod",
		Region:        "us-east-1",
		TenantURL:     mockAWS.URL,
		WSHost:        "ws://" + strings.TrimPrefix(mockAWS.URL, "http://"),
		TokenEndpoint: mockAWS.URL + "/token",
		AccessToken:   "good_tok",
		RefreshToken:  "ref_tok",
		ExpiresAt:     time.Now().Add(time.Hour).UnixMilli(),
		DeviceID:      auth.NewUUID(),
	})

	pn := New(Config{
		Pool:       p,
		Upstream:   upstream.NewClient(cfg.Upstream, nil),
		Live:       config.NewLiveHolder(cfg),
		ListenAddr: "127.0.0.1:8045",
	})
	host := "127.0.0.1:8045"

	// Empty prompt -> 400.
	w := doPanelReq(pn, http.MethodPost, "/panel/api/playground", host, "", testAdminKey, map[string]any{"prompt": "   "})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty prompt want 400, got %d", w.Code)
	}

	// Over 4000 runes -> 400.
	w = doPanelReq(pn, http.MethodPost, "/panel/api/playground", host, "", testAdminKey, map[string]any{"prompt": strings.Repeat("a", 4001)})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized prompt want 400, got %d", w.Code)
	}

	// Valid prompt -> 200 with reply, reasoning, actual_model, tokens.
	w = doPanelReq(pn, http.MethodPost, "/panel/api/playground", host, "", testAdminKey, map[string]any{
		"model":      "amazon-smart",
		"effort":     "low",
		"prompt":     "ping",
		"web_search": true,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("playground call failed: %d %s", w.Code, w.Body.String())
	}
	var res map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res["ok"] != true || res["text"] != "Playground OK!" || res["reasoning"] != "checking" || res["actual_model"] != "claude-sonnet-4-6" || res["total_tokens"] != float64(15) {
		t.Fatalf("unexpected playground response: %v", res)
	}
}

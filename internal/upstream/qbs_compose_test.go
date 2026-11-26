package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
)

// attachMock simulates the AIDP attachment endpoints (upload, DLP status, thread delivery).
type attachMock struct {
	srv       *httptest.Server
	uploads   atomic.Int32
	dlpPolls  atomic.Int32
	delivered atomic.Int32
}

// newAttachMock: uploadStatus != 200 makes the raw upload fail; dlp == nil makes the
// DLP status endpoint answer HTTP 500 forever.
func newAttachMock(t *testing.T, uploadStatus int, dlp map[string]any) *attachMock {
	t.Helper()
	m := &attachMock{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/integration/quick-work/upload-attachment":
			m.uploads.Add(1)
			if uploadStatus != http.StatusOK {
				w.WriteHeader(uploadStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"attachmentId": "att_qc"})
		case "/integration/quick-work/attachment-dlp-status":
			m.dlpPolls.Add(1)
			if dlp == nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(dlp)
		case "/integration/quick-work/qbs-event":
			m.delivered.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"path": "uploads/ctx.txt"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *attachMock) client(attachments bool) (*Client, *auth.Account, config.UpstreamConfig) {
	cfg := config.Default().Upstream
	cfg.DataPlaneURL = m.srv.URL
	cfg.Attachments = attachments
	c := NewClient(cfg, nil)
	acct := &auth.Account{
		UID:         "soc_qc",
		Provider:    auth.ProviderSocial,
		Stage:       "prod",
		TenantURL:   m.srv.URL,
		WSHost:      "ws://" + strings.TrimPrefix(m.srv.URL, "http://"),
		AccessToken: "tok_qc",
		DeviceID:    auth.NewUUID(),
	}
	return c, acct, cfg
}

func shortDLPPolling(t *testing.T, attempts int) {
	t.Helper()
	oldA, oldI := dlpPollAttempts, dlpPollInterval
	dlpPollAttempts, dlpPollInterval = attempts, time.Millisecond
	t.Cleanup(func() { dlpPollAttempts, dlpPollInterval = oldA, oldI })
}

func composeFor(t *testing.T, c *Client, acct *auth.Account, cfg config.UpstreamConfig, req ChatRequest, thread *ThreadEntry, maxFrame int) (composedTurn, *preparedTurn, error) {
	t.Helper()
	pt, err := prepareTurn(req, cfg)
	if err != nil {
		t.Fatalf("prepareTurn: %v", err)
	}
	ct, err := c.composeTurn(context.Background(), acct, wsSession{}, cfg, pt, thread, "thread-qc", maxFrame)
	return ct, pt, err
}

func pngDataURL() string {
	raw := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, make([]byte, 24)...)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(raw)
}

func imageRequest() ChatRequest {
	return ChatRequest{
		Slot: "smart",
		Messages: []map[string]any{{
			"role": "user",
			"content": []any{
				map[string]any{"type": "text", "text": "describe this image"},
				map[string]any{"type": "image_url", "image_url": map[string]any{"url": pngDataURL()}},
			},
		}},
	}
}

func overflowRequest(strict *bool) ChatRequest {
	return ChatRequest{
		Slot:             "smart",
		StrictPrivacyDLP: strict,
		Messages: []map[string]any{
			{"role": "user", "content": strings.Repeat("history line with plenty of words. ", 600)},
			{"role": "assistant", "content": "noted"},
			{"role": "user", "content": "final question"},
		},
	}
}

func boolPtr(b bool) *bool { return &b }

// P2-13: DLP polling that never reaches a verdict must fail closed and never deliver.
func TestUploadAttachmentDLPInconclusiveFailsClosed(t *testing.T) {
	shortDLPPolling(t, 3)
	for name, dlp := range map[string]map[string]any{
		"in_progress": {"dlpJobStatus": "IN_PROGRESS"},
		"http_500":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			m := newAttachMock(t, http.StatusOK, dlp)
			c, acct, _ := m.client(true)
			_, err := c.UploadAttachment(context.Background(), acct, "thread-1", "a.txt", "text/plain", []byte("hello"), true)
			var ue *UpstreamError
			if !errors.As(err, &ue) || ue.Code != dlpInconclusiveCode {
				t.Fatalf("expected fail-closed %q error, got %v", dlpInconclusiveCode, err)
			}
			if got := m.dlpPolls.Load(); got != 3 {
				t.Fatalf("expected 3 DLP polls, got %d", got)
			}
			if got := m.delivered.Load(); got != 0 {
				t.Fatalf("attachment delivered despite missing DLP verdict (%d)", got)
			}
		})
	}
}

func TestUploadAttachmentDLPAllowDelivers(t *testing.T) {
	shortDLPPolling(t, 3)
	m := newAttachMock(t, http.StatusOK, map[string]any{"dlpJobStatus": "COMPLETED", "policyAction": "ALLOW"})
	c, acct, _ := m.client(true)
	att, err := c.UploadAttachment(context.Background(), acct, "thread-1", "a.txt", "text/plain", []byte("hello"), true)
	if err != nil {
		t.Fatalf("UploadAttachment: %v", err)
	}
	if att.AttachmentID != "att_qc" || att.Path != "uploads/ctx.txt" || m.delivered.Load() != 1 || m.dlpPolls.Load() != 1 {
		t.Fatalf("unexpected result %+v delivered=%d polls=%d", att, m.delivered.Load(), m.dlpPolls.Load())
	}
}

// P2-13: a non-DLP image upload failure must be surfaced instead of silently dropping the image.
func TestComposeImageUploadErrorSurfaces(t *testing.T) {
	shortDLPPolling(t, 3)
	m := newAttachMock(t, http.StatusInternalServerError, map[string]any{"dlpJobStatus": "COMPLETED", "policyAction": "ALLOW"})
	c, acct, cfg := m.client(true)
	_, _, err := composeFor(t, c, acct, cfg, imageRequest(), nil, 64*1024)
	var ue *UpstreamError
	if !errors.As(err, &ue) || !strings.Contains(ue.Message, "图片附件") {
		t.Fatalf("expected image upload failure to surface, got %v", err)
	}
	if m.uploads.Load() != 1 {
		t.Fatalf("expected one upload attempt, got %d", m.uploads.Load())
	}
}

func TestComposeImageUploadSuccessAttaches(t *testing.T) {
	shortDLPPolling(t, 3)
	m := newAttachMock(t, http.StatusOK, map[string]any{"dlpJobStatus": "COMPLETED", "policyAction": "ALLOW"})
	c, acct, cfg := m.client(true)
	ct, _, err := composeFor(t, c, acct, cfg, imageRequest(), nil, 64*1024)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if len(ct.Input.Attachments) != 1 || ct.Input.Attachments[0].Type != "image" {
		t.Fatalf("expected one image attachment, got %+v", ct.Input.Attachments)
	}
}

// P2-13: the Stage-3 overflow context file follows strictDLP (WARN blocks in strict mode).
func TestComposeOverflowOffloadHonorsStrictDLP(t *testing.T) {
	shortDLPPolling(t, 3)
	warn := map[string]any{"dlpJobStatus": "COMPLETED", "policyAction": "WARN"}

	t.Run("strict_blocks", func(t *testing.T) {
		m := newAttachMock(t, http.StatusOK, warn)
		c, acct, cfg := m.client(true)
		_, _, err := composeFor(t, c, acct, cfg, overflowRequest(nil), nil, 4096)
		var ue *UpstreamError
		if !errors.As(err, &ue) || ue.Kind != ErrKindBlocked {
			t.Fatalf("expected ErrKindBlocked in strict mode, got %v", err)
		}
		if m.uploads.Load() != 1 || m.delivered.Load() != 0 {
			t.Fatalf("uploads=%d delivered=%d", m.uploads.Load(), m.delivered.Load())
		}
	})

	t.Run("strict_inconclusive_blocks", func(t *testing.T) {
		m := newAttachMock(t, http.StatusOK, map[string]any{"dlpJobStatus": "IN_PROGRESS"})
		c, acct, cfg := m.client(true)
		_, _, err := composeFor(t, c, acct, cfg, overflowRequest(nil), nil, 4096)
		var ue *UpstreamError
		if !errors.As(err, &ue) || ue.Code != dlpInconclusiveCode {
			t.Fatalf("expected fail-closed DLP error in strict mode, got %v", err)
		}
	})

	t.Run("lenient_warn_passes", func(t *testing.T) {
		m := newAttachMock(t, http.StatusOK, warn)
		c, acct, cfg := m.client(true)
		ct, _, err := composeFor(t, c, acct, cfg, overflowRequest(boolPtr(false)), nil, 4096)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		if len(ct.Input.Attachments) != 1 || !strings.Contains(ct.Input.Prompt, "has been attached") || !strings.Contains(ct.Input.Prompt, "final question") {
			t.Fatalf("expected offloaded context, got prompt=%q attachments=%+v", ct.Input.Prompt, ct.Input.Attachments)
		}
	})
}

// P2-13: the offloaded context is size-capped.
func TestComposeOverflowOffloadSizeCap(t *testing.T) {
	old := maxContextAttachmentBytes
	maxContextAttachmentBytes = 1000
	t.Cleanup(func() { maxContextAttachmentBytes = old })
	m := newAttachMock(t, http.StatusOK, map[string]any{"dlpJobStatus": "COMPLETED", "policyAction": "ALLOW"})
	c, acct, cfg := m.client(true)
	_, _, err := composeFor(t, c, acct, cfg, overflowRequest(boolPtr(false)), nil, 4096)
	var ue *UpstreamError
	if !errors.As(err, &ue) || ue.Kind != ErrKindTooLarge {
		t.Fatalf("expected ErrKindTooLarge, got %v", err)
	}
	if m.uploads.Load() != 0 {
		t.Fatalf("oversized context must not be uploaded (uploads=%d)", m.uploads.Load())
	}
}

// P2-14: the recorded custom digest describes the compacted prompt actually sent, so a
// resumed turn re-sends the full instructions instead of staying truncated forever.
func TestComposeCustomDigestMatchesSentPrompt(t *testing.T) {
	m := newAttachMock(t, http.StatusOK, nil)
	c, acct, cfg := m.client(false)
	system := strings.Repeat("Rule: be careful, precise and consistent. ", 800)

	req1 := ChatRequest{Slot: "smart", Messages: []map[string]any{
		{"role": "system", "content": system},
		{"role": "user", "content": "hi"},
	}}
	ct1, pt1, err := composeFor(t, c, acct, cfg, req1, nil, 8192)
	if err != nil {
		t.Fatalf("turn 1 compose: %v", err)
	}
	if ct1.Input.SystemPrompt == "" || ct1.Input.SystemPrompt == pt1.fullCustom {
		t.Fatalf("expected a compacted custom prompt (len=%d full=%d)", len(ct1.Input.SystemPrompt), len(pt1.fullCustom))
	}
	if ct1.CustomDigest != Digest(ct1.Input.SystemPrompt) || ct1.CustomDigest == Digest(pt1.fullCustom) {
		t.Fatalf("custom digest must match the compacted prompt that was sent")
	}

	req2 := ChatRequest{Slot: "smart", Messages: []map[string]any{
		{"role": "system", "content": system},
		{"role": "user", "content": "hi"},
		{"role": "assistant", "content": "hello"},
		{"role": "user", "content": "next"},
	}}
	thread := &ThreadEntry{ID: "thread-qc", Custom: ct1.CustomDigest, Keys: append([]string(nil), pt1.keys...)}

	// Resumed turn with room: full instructions are re-sent and recorded.
	ct2, pt2, err := composeFor(t, c, acct, cfg, req2, thread, 1<<20)
	if err != nil {
		t.Fatalf("turn 2 compose: %v", err)
	}
	if ct2.Input.SystemPrompt != pt2.fullCustom || ct2.CustomDigest != Digest(pt2.fullCustom) {
		t.Fatalf("expected full custom prompt to be re-sent on resume (sent=%d full=%d)", len(ct2.Input.SystemPrompt), len(pt2.fullCustom))
	}

	// Resuming a constrained thread would change the committed context. Start fresh.
	_, _, err = composeFor(t, c, acct, cfg, req2, thread, 8192)
	var resumeErr *UpstreamError
	if !errors.As(err, &resumeErr) || resumeErr.Code != "thread_resume_frame_limit" {
		t.Fatalf("expected fresh thread for a constrained resume, got %v", err)
	}

	// Thread already holds the full prompt: nothing is re-sent.
	full := &ThreadEntry{ID: "thread-qc", Custom: Digest(pt2.fullCustom), Keys: append([]string(nil), pt1.keys...)}
	ct4, _, err := composeFor(t, c, acct, cfg, req2, full, 1<<20)
	if err != nil {
		t.Fatalf("turn 2 (full thread) compose: %v", err)
	}
	if ct4.Input.SystemPrompt != "" || ct4.CustomDigest != full.Custom {
		t.Fatalf("expected no custom prompt re-send, got len=%d digest=%s", len(ct4.Input.SystemPrompt), ct4.CustomDigest)
	}
}

// P2-19: a /v1/discovery failure must not pin the fallback host for the full cache TTL.
func TestGatewayDiscoveryFallbackCaching(t *testing.T) {
	var hits atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	var discPath atomic.Value
	discPath.Store("/ws/discovered")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/discovery" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		hits.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cellHost": strings.TrimPrefix("http://"+r.Host, "http://"),
			"wsPath":   discPath.Load().(string),
		})
	}))
	defer srv.Close()

	cfg := config.Default().Upstream
	cfg.DataPlaneURL = srv.URL
	c := NewClient(cfg, nil)
	acct := &auth.Account{UID: "gw_qc", Provider: auth.ProviderGateway, TenantURL: srv.URL, AccessToken: "tok_qc"}
	base := strings.TrimRight(srv.URL, "/")
	wantHost := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()

	oldFallback := gwHostFallbackTTL
	t.Cleanup(func() { gwHostFallbackTTL = oldFallback })

	// Fallback caching disabled: every call retries discovery.
	gwHostFallbackTTL = 0
	for i := 0; i < 2; i++ {
		host, _, err := c.gatewayHost(ctx, acct)
		if err != nil || host != wantHost {
			t.Fatalf("fallback host: %q %v", host, err)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("expected discovery to be retried, hits=%d", hits.Load())
	}

	// Default short fallback TTL: cached for at most ~30s.
	gwHostFallbackTTL = 30 * time.Second
	if _, _, err := c.gatewayHost(ctx, acct); err != nil {
		t.Fatal(err)
	}
	c.gwHostMu.Lock()
	entry := c.gwHosts[base]
	c.gwHostMu.Unlock()
	if remaining := gwHostTTL - time.Since(entry.at); remaining <= 0 || remaining > gwHostFallbackTTL+time.Second {
		t.Fatalf("fallback entry lives %v, want <= %v", remaining, gwHostFallbackTTL)
	}
	if _, _, err := c.gatewayHost(ctx, acct); err != nil || hits.Load() != 3 {
		t.Fatalf("expected short-lived fallback cache hit, hits=%d err=%v", hits.Load(), err)
	}

	// Discovery recovers: the real answer is cached for the full TTL.
	c.gwHostMu.Lock()
	c.gwHosts = map[string]gwHostEntry{}
	c.gwHostMu.Unlock()
	fail.Store(false)
	host, wsPath, err := c.gatewayHost(ctx, acct)
	if err != nil || host != wantHost || wsPath != "/ws/discovered" {
		t.Fatalf("discovered: host=%q path=%q err=%v", host, wsPath, err)
	}
	c.gwHostMu.Lock()
	entry = c.gwHosts[base]
	c.gwHostMu.Unlock()
	if remaining := gwHostTTL - time.Since(entry.at); remaining < gwHostTTL-time.Minute {
		t.Fatalf("discovered entry should use full TTL, remaining %v", remaining)
	}
	if _, _, err := c.gatewayHost(ctx, acct); err != nil || hits.Load() != 4 {
		t.Fatalf("expected cached discovery, hits=%d err=%v", hits.Load(), err)
	}

	// An unsafe discovered wsPath is ignored.
	c.gwHostMu.Lock()
	c.gwHosts = map[string]gwHostEntry{}
	c.gwHostMu.Unlock()
	discPath.Store("/ws/../../evil")
	if _, wsPath, err := c.gatewayHost(ctx, acct); err != nil || wsPath != "" {
		t.Fatalf("unsafe discovered wsPath accepted: %q %v", wsPath, err)
	}
}

// P2-3 / P2-1: strict ws_host / ws_path validation.
func TestValidateWSHost(t *testing.T) {
	okProd := map[string]string{
		"": "",
		"cell1.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev": "wss://cell1.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
		"wss://foo.quicksight.aws.amazon.com":                      "wss://foo.quicksight.aws.amazon.com",
		"https://foo.amazonaws.com/":                               "wss://foo.amazonaws.com",
		"wss://foo.amazonaws.com:443":                              "wss://foo.amazonaws.com:443",
	}
	for in, want := range okProd {
		got, err := validateWSHost(in, false)
		if err != nil || got != want {
			t.Errorf("validateWSHost(%q, false) = %q, %v; want %q", in, got, err, want)
		}
	}
	// Loopback hosts must be rejected by default (allowCustom == false),
	// and accepted only when allowCustom == true.
	loopback := map[string]string{
		"ws://127.0.0.1:1234":   "ws://127.0.0.1:1234",
		"wss://127.0.0.1:1234":  "wss://127.0.0.1:1234",
		"http://localhost:8080": "ws://localhost:8080",
		"ws://[::1]:9":          "ws://[::1]:9",
	}
	for in, want := range loopback {
		if got, err := validateWSHost(in, false); err == nil {
			t.Errorf("validateWSHost(%q, false) = %q, want loopback rejection", in, got)
		}
		if got, err := validateWSHost(in, true); err != nil || got != want {
			t.Errorf("validateWSHost(%q, true) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"ws://foo.amazonaws.com",
		"http://foo.amazonaws.com",
		"wss://evil.example.com",
		"evil.example.com",
		"wss://foo.amazonaws.com.evil.com",
		"wss://foo.amazonaws.com:8443",
		"wss://user@foo.amazonaws.com",
		"wss://evil.com@foo.amazonaws.com",
		"wss://foo.amazonaws.com/path",
		"wss://foo.amazonaws.com?x=1",
		"wss://evil.com#.amazonaws.com",
		`wss://foo.amazonaws.com\evil`,
		"ftp://foo.amazonaws.com",
		"wss://foo .amazonaws.com",
	}
	for _, in := range bad {
		if got, err := validateWSHost(in, false); err == nil {
			t.Errorf("validateWSHost(%q, false) = %q, want error", in, got)
		}
		if got, err := validateWSHost(in, true); err == nil {
			t.Errorf("validateWSHost(%q, true) = %q, want error", in, got)
		}
	}
}

func TestValidateWSPath(t *testing.T) {
	for _, in := range []string{"", auth.DefaultWSPath, auth.GatewayWSPath, "/a/b-c_d.e"} {
		if got, err := validateWSPath(in); err != nil || got != in {
			t.Errorf("validateWSPath(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{
		"streaming",
		"//evil.com/x",
		"/a//b",
		"/a/../b",
		"/..",
		"/a/./b",
		"/x@evil.com",
		`/a\b`,
		"wss://evil.com/x",
		"/redirect?to=wss://evil.com",
		"/x%2e%2e/y",
		"/a#frag",
		"/a b",
		"/caf\u00e9",
	} {
		if got, err := validateWSPath(in); err == nil {
			t.Errorf("validateWSPath(%q) = %q, want error", in, got)
		}
	}
}

func TestAccountWSEndpoint(t *testing.T) {
	_, _, err := accountWSEndpoint(&auth.Account{WSHost: "ws://cell.amazonaws.com"}, false)
	var ue *UpstreamError
	if !errors.As(err, &ue) || ue.Kind != ErrKindHandshake {
		t.Fatalf("expected plaintext remote ws_host to be rejected, got %v", err)
	}
	if _, _, err := accountWSEndpoint(&auth.Account{WSHost: "ws://127.0.0.1:9999"}, false); err == nil {
		t.Fatal("expected loopback ws_host to be rejected when allowCustom=false")
	}
	if host, _, err := accountWSEndpoint(&auth.Account{WSHost: "ws://127.0.0.1:9999"}, true); err != nil || host != "ws://127.0.0.1:9999" {
		t.Fatalf("expected loopback ws_host allowed when allowCustom=true, got %q %v", host, err)
	}
	host, path, err := accountWSEndpoint(&auth.Account{WSHost: "cell.amazonaws.com", WSPath: "/../evil"}, false)
	if err != nil || host != "wss://cell.amazonaws.com" || path != "" {
		t.Fatalf("got host=%q path=%q err=%v", host, path, err)
	}
	host, path, err = accountWSEndpoint(&auth.Account{WSHost: "wss://cell.amazonaws.com", WSPath: auth.DefaultWSPath}, false)
	if err != nil || host != "wss://cell.amazonaws.com" || path != auth.DefaultWSPath {
		t.Fatalf("got host=%q path=%q err=%v", host, path, err)
	}
}

// P1-3: composeTurn must account for image & Stage-3 attachment metadata in size()
// BEFORE Stage 1..4 sizing so near-limit multimodal or attached turns fit without ErrKindTooLarge.
func TestComposeTurnAccountsForAttachmentsInFrameBudget(t *testing.T) {
	shortDLPPolling(t, 3)

	t.Run("multimodal_near_limit_fits", func(t *testing.T) {
		m := newAttachMock(t, http.StatusOK, map[string]any{"dlpJobStatus": "COMPLETED", "policyAction": "ALLOW"})
		c, acct, cfg := m.client(true)
		// Construct a turn whose text + envelope alone is just under 4096 bytes,
		// so adding the ~250-byte image Attachment JSON would overflow 4096 unless
		// attachments are included in size() before Stage 1..4.
		req := ChatRequest{
			Slot: "smart",
			Messages: []map[string]any{{
				"role": "user",
				"content": []any{
					map[string]any{"type": "text", "text": strings.Repeat("a", 3150)},
					map[string]any{"type": "image_url", "image_url": map[string]any{"url": pngDataURL()}},
				},
			}},
		}
		ct, _, err := composeFor(t, c, acct, cfg, req, nil, 4096)
		if err != nil {
			t.Fatalf("expected near-limit multimodal turn to fit via offload/compaction, got %v", err)
		}
		if len(ct.Input.Attachments) < 1 {
			t.Fatalf("expected image attachment preserved, got %+v", ct.Input.Attachments)
		}
		if fb := FrameBytes(false, buildUserMessageFrame(wsSession{}, cfg, ct.Input)); fb > 4096 {
			t.Fatalf("composed frame %d exceeds maxFrameBytes 4096", fb)
		}
	})

	t.Run("stage3_offload_plus_long_last_fits", func(t *testing.T) {
		m := newAttachMock(t, http.StatusOK, map[string]any{"dlpJobStatus": "COMPLETED", "policyAction": "ALLOW"})
		c, acct, cfg := m.client(true)
		// Long history triggers Stage-3 offload; final block is <= 6000 bytes so Stage-3
		// keeps it inline alongside the notice + attachment metadata, pushing total past 4096.
		// Stage-4 must see input.Attachments and trim accurately to <= 4096.
		req := ChatRequest{
			Slot:             "smart",
			StrictPrivacyDLP: boolPtr(false),
			Messages: []map[string]any{
				{"role": "user", "content": strings.Repeat("old context ", 500)},
				{"role": "assistant", "content": "ok"},
				{"role": "user", "content": strings.Repeat("final turn ", 320)},
			},
		}
		ct, _, err := composeFor(t, c, acct, cfg, req, nil, 4096)
		if err != nil {
			t.Fatalf("expected Stage-3 + Stage-4 turn with attachment to fit, got %v", err)
		}
		if len(ct.Input.Attachments) != 1 {
			t.Fatalf("expected 1 offloaded attachment, got %d", len(ct.Input.Attachments))
		}
		if fb := FrameBytes(false, buildUserMessageFrame(wsSession{}, cfg, ct.Input)); fb > 4096 {
			t.Fatalf("composed frame %d exceeds maxFrameBytes 4096", fb)
		}
	})
}

// P2-2: DLP FAILED/ERROR status and HTTP 401/403 from /attachment-dlp-status must fail
// closed under strictDLP instead of falling back to Stage-4 inline.
func TestComposeOverflowOffloadDLPFailClosedStatuses(t *testing.T) {
	shortDLPPolling(t, 2)

	cases := []struct {
		name       string
		dlpStatus  int
		dlpBody    map[string]any
		wantStatus int
	}{
		{"dlp_failed", http.StatusOK, map[string]any{"dlpJobStatus": "FAILED"}, 502},
		{"dlp_error", http.StatusOK, map[string]any{"dlpJobStatus": "ERROR"}, 502},
		{"dlp_http_401", http.StatusUnauthorized, nil, http.StatusUnauthorized},
		{"dlp_http_403", http.StatusForbidden, nil, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name+"_strict_blocks", func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/integration/quick-work/upload-attachment":
					_ = json.NewEncoder(w).Encode(map[string]any{"attachmentId": "att_fc"})
				case "/integration/quick-work/attachment-dlp-status":
					w.WriteHeader(tc.dlpStatus)
					if tc.dlpBody != nil {
						_ = json.NewEncoder(w).Encode(tc.dlpBody)
					}
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			cfg := config.Default().Upstream
			cfg.DataPlaneURL = srv.URL
			cfg.Attachments = true
			c := NewClient(cfg, nil)
			acct := &auth.Account{
				UID:         "soc_fc",
				Provider:    auth.ProviderSocial,
				Stage:       "prod",
				TenantURL:   srv.URL,
				WSHost:      "ws://" + strings.TrimPrefix(srv.URL, "http://"),
				AccessToken: "tok_fc",
				DeviceID:    auth.NewUUID(),
			}

			_, _, err := composeFor(t, c, acct, cfg, overflowRequest(nil), nil, 4096)
			var ue *UpstreamError
			if !errors.As(err, &ue) || ue.Code != dlpInconclusiveCode || ue.StatusCode != tc.wantStatus {
				t.Fatalf("strictDLP must fail closed with code=%q status=%d, got %v", dlpInconclusiveCode, tc.wantStatus, err)
			}

			// Lenient mode (StrictPrivacyDLP=false) still falls back to Stage-4 inline.
			ct, _, lerr := composeFor(t, c, acct, cfg, overflowRequest(boolPtr(false)), nil, 4096)
			if lerr != nil {
				t.Fatalf("lenient mode should fall back to Stage-4 inline, got %v", lerr)
			}
			if len(ct.Input.Attachments) != 0 {
				t.Fatalf("expected no attachment in Stage-4 fallback, got %+v", ct.Input.Attachments)
			}
		})
	}
}

// P3: UploadAttachment must not sleep dlpPollInterval after the final poll attempt.
func TestUploadAttachmentDLPSkipsFinalSleep(t *testing.T) {
	oldA, oldI := dlpPollAttempts, dlpPollInterval
	dlpPollAttempts, dlpPollInterval = 1, 2*time.Second
	t.Cleanup(func() { dlpPollAttempts, dlpPollInterval = oldA, oldI })

	m := newAttachMock(t, http.StatusOK, map[string]any{"dlpJobStatus": "IN_PROGRESS"})
	c, acct, _ := m.client(true)
	start := time.Now()
	_, err := c.UploadAttachment(context.Background(), acct, "thread-1", "a.txt", "text/plain", []byte("hello"), true)
	elapsed := time.Since(start)
	var ue *UpstreamError
	if !errors.As(err, &ue) || ue.Code != dlpInconclusiveCode {
		t.Fatalf("expected %q error, got %v", dlpInconclusiveCode, err)
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("UploadAttachment slept after final poll attempt (%v)", elapsed)
	}
}

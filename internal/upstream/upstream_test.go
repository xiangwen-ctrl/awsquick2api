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

func TestEventStreamAndCBORCodecs(t *testing.T) {
	// EventStream round-trip + incremental split feed.
	raw := EventStreamEncode(map[string]string{
		":event-type":   "rawOutputEvent",
		":message-type": "event",
	}, []byte(`{"payload":"aGVsbG8="}`))

	var dec EventStreamDecoder
	m1, err := dec.Feed(raw[:7])
	if err != nil || len(m1) != 0 {
		t.Fatalf("expected buffered partial, got msgs=%d err=%v", len(m1), err)
	}
	m2, err := dec.Feed(raw[7:])
	if err != nil || len(m2) != 1 {
		t.Fatalf("expected 1 decoded msg, got msgs=%d err=%v", len(m2), err)
	}
	if m2[0].Headers[":event-type"] != "rawOutputEvent" {
		t.Fatalf("unexpected headers: %+v", m2[0].Headers)
	}

	// Corrupt CRC must fail.
	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := EventStreamDecodeAll(corrupt); err == nil {
		t.Fatal("expected CRC failure on corrupted message")
	}

	// CBOR Gateway round-trip.
	sample := []byte(`{"type":"text_delta","payload":{"delta":"你好 Quick"}}`)
	gwFrame, err := EncodeGateway(sample)
	if err != nil {
		t.Fatalf("EncodeGateway: %v", err)
	}
	wdec := NewWireDecoder(true)
	frames, err := wdec.Feed(gwFrame)
	if err != nil || len(frames) != 1 || frames[0] != string(sample) {
		t.Fatalf("gateway decode mismatch: frames=%v err=%v", frames, err)
	}
}

func TestModelCatalogResolution(t *testing.T) {
	cat := DefaultCatalog()
	cases := []struct {
		in         string
		wantSlot   string
		wantEffort string
		wantKnown  bool
	}{
		{"amazon-smart", "smart", "", true},
		{"amazon-smart-high", "smart", "high", true},
		{"aws-quick/balanced-medium", "balanced", "medium", true},
		{"qw-fast[1m]", "fast", "", true},
		{"claude-opus-4-6[1m]", "smart", "", true},
		{"claude-sonnet-4-5-low", "balanced", "low", true},
		{"claude-haiku-4-5", "fast", "", true},
		{"unknown-model", "smart", "", false},
	}
	for _, tc := range cases {
		slot, _, eff, known := cat.Resolve(tc.in, "smart", true)
		if slot != tc.wantSlot || eff != tc.wantEffort || known != tc.wantKnown {
			t.Errorf("Resolve(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, slot, eff, known, tc.wantSlot, tc.wantEffort, tc.wantKnown)
		}
	}
}

func TestBridgeStreamStreamingAndTools(t *testing.T) {
	allowed := map[string]bool{"read_file": true, "bash": true}

	// Normal text streamed incrementally followed by split <client_tool_call> tag.
	var streamed strings.Builder
	bs := NewBridgeStream(allowed, func(s string) { streamed.WriteString(s) })
	deltas := []string{
		"Checking file now. ",
		"<client_",
		`tool_call>{"name":"read_file","arguments":{"path":"go.mod"}}</client_tool_call>`,
	}
	for _, d := range deltas {
		bs.Push(d)
	}
	calls := bs.Finish()
	if strings.TrimSpace(streamed.String()) != "Checking file now." {
		t.Fatalf("unexpected streamed text: %q", streamed.String())
	}
	if len(calls) != 1 || calls[0].Name != "read_file" || !strings.Contains(calls[0].Arguments, "go.mod") {
		t.Fatalf("unexpected calls: %+v", calls)
	}

	// Bare fenced JSON fallback.
	var streamed2 strings.Builder
	bs2 := NewBridgeStream(allowed, func(s string) { streamed2.WriteString(s) })
	bs2.Push("```json\n{\"name\":\"bash\",\"arguments\":{\"cmd\":\"ls\"}}\n```")
	calls2 := bs2.Finish()
	if streamed2.Len() != 0 || len(calls2) != 1 || calls2[0].Name != "bash" {
		t.Fatalf("bare JSON fallback failed: text=%q calls=%+v", streamed2.String(), calls2)
	}
}

func TestAccountPIIRedactorAndAntiBypassDLP(t *testing.T) {
	acct := &auth.Account{
		Email:          "zhangsan88@gmail.com",
		DisplayNameVal: "张三",
		UserName:       "alice",
		AWSAccountID:   "123456789012",
		ActorARN:       "arn:aws:iam::123456789012:user/zhangsan88",
	}
	msgs := []map[string]any{
		{"role": "user", "content": "Please help me write unit tests."},
		{"role": "tool", "tool_call_id": "c1", "content": `{"maintainer":"dev.lead@myproject.io"}`},
	}
	pol := buildAccountPrivacyPolicy(acct, msgs, true)

	b64Direct := base64.StdEncoding.EncodeToString([]byte("zhangsan88@gmail.com"))
	b64Shifted := base64.RawStdEncoding.EncodeToString([]byte("Account owner: 张三 <zhangsan88@gmail.com>"))
	attackCases := []struct {
		name      string
		input     string
		forbidden []string
	}{
		{"literal_email", "Hi 张三, your email is zhangsan88@gmail.com (123456789012).", []string{"张三", "zhangsan88", "123456789012"}},
		{"spaced_email", "Email: z h a n g s a n 8 8 @ g m a i l . c o m!", []string{"z h a n g", "g m a i l"}},
		{"hyphen_email", "Email: z-h-a-n-g-s-a-n-8-8@g-m-a-i-l.c-o-m", []string{"z-h-a-n-g"}},
		{"backtick_split", "Name: `张` · `三`, user: [a][l][i][c][e]", []string{"张", "三", "[a][l][i][c][e]"}},
		{"zwsp_split", "Name: 张\u200b三", []string{"张", "三"}},
		{"at_dot_spoken", "Mail is zhangsan88 [at] gmail [dot] com", []string{"zhangsan88", "gmail"}},
		{"reversed_email", "Reversed: moc.liamg@88nasgnahz", []string{"nasgnahz", "moc.liamg"}},
		{"base64_direct", "Encoded: " + b64Direct, []string{b64Direct}},
		{"base64_sentence_shifted", "Blob: " + b64Shifted, []string{b64Shifted}},
		{"hex_contiguous", "Hex: 7a68616e6773616e383840676d61696c2e636f6d", []string{"7a68616e6773"}},
		{"hex_spaced", "Hex: 7a 68 61 6e 67 73 61 6e 38 38 40 67 6d 61 69 6c 2e 63 6f 6d", []string{"7a 68 61 6e"}},
		{"unicode_escape", `JSON: \u007a\u0068\u0061\u006e\u0067\u0073\u0061\u006e\u0038\u0038@gmail.com`, []string{`\u007a\u0068`, "gmail.com"}},
		{"url_escape", "URL: zhangsan88%40gmail%2ecom", []string{"zhangsan88", "gmail"}},
		{"html_entity", "HTML: &#122;&#104;&#97;&#110;&#103;&#115;&#97;&#110;&#56;&#56;&#64;gmail.com", []string{"&#122;&#104;", "gmail.com"}},
		{"unknown_secondary_email", "Secondary: hidden.alias@awsapps.com and colleague (at) corp (dot) net", []string{"hidden.alias", "awsapps.com", "colleague"}},
	}

	for _, tc := range attackCases {
		got := pol.Scrub(tc.input)
		for _, bad := range tc.forbidden {
			if strings.Contains(got, bad) {
				t.Fatalf("[%s] non-stream Scrub leaked %q in %q", tc.name, bad, got)
			}
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Fatalf("[%s] expected [REDACTED] in %q", tc.name, got)
		}

		var streamed strings.Builder
		red := newPrivacyPolicyStreamRedactor(pol, func(s string) { streamed.WriteString(s) })
		rs := []rune(tc.input)
		for i := 0; i < len(rs); i += 3 {
			end := min(i+3, len(rs))
			red.Push(string(rs[i:end]))
		}
		red.Finish()
		sGot := streamed.String()
		for _, bad := range tc.forbidden {
			if strings.Contains(sGot, bad) {
				t.Fatalf("[%s] 3-rune streaming redactor leaked %q in %q", tc.name, bad, sGot)
			}
		}
	}

	benignCases := []string{
		"Use test@example.com, admin@localhost, noreply@github.com, and git@github.com in tests.",
		"Maintainer from tool result is dev.lead@myproject.io and asset is logo@2x.png.",
		"English prose with real ice, malice, and chalice stays intact.",
		"业务快速扩张。\n三、下一步工作计划。",
		"SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	for _, safe := range benignCases {
		if got := pol.Scrub(safe); got != safe {
			t.Fatalf("FALSE POSITIVE on benign text:\nwant: %q\ngot : %q", safe, got)
		}
	}

	// Tool-call exfiltration check.
	var toolStreamed strings.Builder
	bs := NewBridgeStream(map[string]bool{"bash": true}, func(s string) { toolStreamed.WriteString(s) })
	tGuard := newPrivacyPolicyStreamRedactor(pol, func(s string) { bs.Push(s) })
	rawTool := `Sure! <client_tool_call>{"name":"bash","arguments":{"cmd":"echo z-h-a-n-g-s-a-n-8-8@gmail.com"}}</client_tool_call>`
	for i := 0; i < len(rawTool); i += 5 {
		tGuard.Push(rawTool[i:min(i+5, len(rawTool))])
	}
	tGuard.Finish()
	calls := bs.Finish()
	if len(calls) != 1 || calls[0].Name != "bash" {
		t.Fatalf("expected valid bash tool call after redaction, got %+v", calls)
	}
	if strings.Contains(calls[0].Arguments, "z-h-a-n-g") || !strings.Contains(calls[0].Arguments, "[REDACTED]") {
		t.Fatalf("tool call arguments leaked split email: %q", calls[0].Arguments)
	}
}

func TestMockUpstreamAIDPThreadReuseAndAttachments(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var (
		mu             sync.Mutex
		seenUserMsgs   []map[string]any
		uploadedFiles  []string
		deliveredFiles []string
	)

	sendAIDPEvent := func(conn *websocket.Conn, env map[string]any) {
		inner, _ := json.Marshal(env)
		outer, _ := json.Marshal(map[string]any{
			"payload": base64.StdEncoding.EncodeToString(inner),
		})
		frame := EventStreamEncode(map[string]string{
			":event-type":   "rawOutputEvent",
			":message-type": "event",
		}, outer)
		_ = conn.WriteMessage(websocket.BinaryMessage, frame)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case auth.DefaultWSPath:
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				msgType, raw, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if msgType != websocket.BinaryMessage {
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
				if json.Unmarshal(decoded, &msg) != nil {
					continue
				}
				if msg["type"] == "user_message" {
					p, _ := msg["payload"].(map[string]any)
					mu.Lock()
					seenUserMsgs = append(seenUserMsgs, p)
					mu.Unlock()

					sendAIDPEvent(conn, map[string]any{"type": "thinking_delta", "payload": map[string]any{"delta": "Let me think..."}})
					sendAIDPEvent(conn, map[string]any{"type": "tool_start", "payload": map[string]any{"tool_id": "t1", "tool_name": "web_search"}})
					// Chunked text_delta reassembly test.
					chunkInner, _ := json.Marshal(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "Hello from Quick!"}})
					half := len(chunkInner) / 2
					sendAIDPEvent(conn, map[string]any{
						"type": "_chunked_frame",
						"payload": map[string]any{
							"chunk_id":     "c1",
							"chunk_index":  1,
							"total_chunks": 2,
							"data":         string(chunkInner[half:]),
						},
					})
					sendAIDPEvent(conn, map[string]any{
						"type": "_chunked_frame",
						"payload": map[string]any{
							"chunk_id":     "c1",
							"chunk_index":  0,
							"total_chunks": 2,
							"data":         string(chunkInner[:half]),
						},
					})
					// Two turn_usage events: input should take LAST call, output should SUM.
					sendAIDPEvent(conn, map[string]any{"type": "turn_usage", "payload": map[string]any{"input_tokens": 1000, "cache_read_tokens": 500, "output_tokens": 20, "resolved_model_id": "claude-opus-4-6"}})
					sendAIDPEvent(conn, map[string]any{"type": "turn_usage", "payload": map[string]any{"input_tokens": 1200, "cache_read_tokens": 600, "output_tokens": 30, "resolved_model_id": "claude-opus-4-6"}})
					sendAIDPEvent(conn, map[string]any{"type": "message_complete", "payload": map[string]any{"continuation_expected": false}})
					sendAIDPEvent(conn, map[string]any{"type": "turn_completed", "payload": map[string]any{}})
					return
				}
			}

		case "/integration/quick-work/upload-attachment":
			mu.Lock()
			uploadedFiles = append(uploadedFiles, r.URL.Query().Get("name"))
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"attachmentId": "att_001"})

		case "/integration/quick-work/attachment-dlp-status":
			_ = json.NewEncoder(w).Encode(map[string]any{"dlpJobStatus": "COMPLETED", "policyAction": "ALLOW"})

		case "/integration/quick-work/qbs-event":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			eb, _ := body["eventBody"].(map[string]any)
			ia, _ := eb["invokeAgent"].(map[string]any)
			path, _ := ia["path"].(string)
			if path == "profile/usage" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"eventResponse": map[string]any{
						"invokeAgentResponse": map[string]any{
							"status": 200,
							"body": map[string]any{
								"subscription": map[string]any{"subscription_type": "PRO"},
								"monthly":      map[string]any{"used": 120, "limit": 1000},
								"session":      map[string]any{"used": 10, "limit": 100},
							},
						},
					},
				})
				return
			}
			if strings.HasPrefix(path, "files/upload/") {
				mu.Lock()
				deliveredFiles = append(deliveredFiles, path)
				mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]any{
					"eventResponse": map[string]any{
						"invokeAgentResponse": map[string]any{
							"status": 200,
							"body":   map[string]any{"path": "/workspace/context.txt"},
						},
					},
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := config.Default().Upstream
	cfg.DataPlaneURL = srv.URL
	cfg.Stateful = true
	cfg.Attachments = true
	cfg.MaxFrameBytes = 4096
	cfg.ShowQuickTools = true

	client := NewClient(cfg, nil)
	acct := &auth.Account{
		UID:         "soc_test",
		Provider:    auth.ProviderSocial,
		Stage:       "prod",
		TenantURL:   srv.URL,
		WSHost:      "ws://" + strings.TrimPrefix(srv.URL, "http://"),
		AccessToken: "tok_test",
		DeviceID:    auth.NewUUID(),
	}

	// Turn 1
	var events []ChatEvent
	res1, err := client.Chat(context.Background(), acct, ChatRequest{
		Model:          "amazon-smart",
		Slot:           "smart",
		ThinkingEffort: "high",
		ConversationID: "conv-1",
		Stream:         true,
		Messages: []map[string]any{
			{"role": "system", "content": "Be concise."},
			{"role": "user", "content": "First turn question"},
		},
	}, func(ev ChatEvent) {
		events = append(events, ev)
	})
	if err != nil {
		t.Fatalf("Turn 1 Chat failed: %v", err)
	}
	if res1.Text != "Hello from Quick!" || res1.Usage.PromptTokens != 1800 || res1.Usage.CompletionTokens != 50 || res1.Usage.ResolvedModel != "claude-opus-4-6" {
		t.Fatalf("unexpected Turn 1 result: %+v", res1)
	}
	if !strings.Contains(res1.Reasoning, "[Quick: web_search]") {
		t.Fatalf("expected Quick tool progress in reasoning, got %q", res1.Reasoning)
	}

	// Turn 2: should reuse thread_id and send only newly appended user turn!
	res2, err := client.Chat(context.Background(), acct, ChatRequest{
		Model:          "amazon-smart",
		Slot:           "smart",
		ConversationID: "conv-1",
		Stream:         false,
		Messages: []map[string]any{
			{"role": "system", "content": "Be concise."},
			{"role": "user", "content": "First turn question"},
			{"role": "assistant", "content": "Hello from Quick!"},
			{"role": "user", "content": "Second turn follow-up"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("Turn 2 Chat failed: %v", err)
	}
	if !res2.ThreadReused || res2.ThreadID != res1.ThreadID {
		t.Fatalf("expected thread reuse (t1=%s t2=%s reused=%v)", res1.ThreadID, res2.ThreadID, res2.ThreadReused)
	}
	mu.Lock()
	if len(seenUserMsgs) != 2 {
		t.Fatalf("expected 2 user_messages, got %d", len(seenUserMsgs))
	}
	if seenUserMsgs[1]["custom_prompt"] != nil {
		t.Fatalf("expected unchanged custom_prompt omitted (nil) on resumed turn, got %v", seenUserMsgs[1]["custom_prompt"])
	}
	if txt, _ := seenUserMsgs[1]["text"].(string); !strings.Contains(txt, "Second turn follow-up") || strings.Contains(txt, "First turn question") {
		t.Fatalf("expected only delta text on resumed turn, got %q", txt)
	}
	mu.Unlock()

	// Turn 3: oversized message triggers context_*.txt attachment upload & DLP delivery.
	bigText := strings.Repeat("Long context line for attachment overflow testing. ", 120)
	_, err = client.Chat(context.Background(), acct, ChatRequest{
		Model:          "amazon-smart",
		Slot:           "smart",
		ConversationID: "conv-big",
		Messages: []map[string]any{
			{"role": "user", "content": bigText},
		},
	}, nil)
	if err != nil {
		t.Fatalf("Turn 3 big Chat failed: %v", err)
	}
	mu.Lock()
	if len(uploadedFiles) == 0 || len(deliveredFiles) == 0 {
		t.Fatalf("expected context attachment upload & delivery, uploaded=%v delivered=%v", uploadedFiles, deliveredFiles)
	}
	mu.Unlock()

	// Quota test.
	q, err := client.GetQuota(context.Background(), acct)
	if err != nil || !q.Known || q.Plan != "Pro" || q.MonthlyLimit != 1000 || q.MonthlyUsed != 120 {
		t.Fatalf("unexpected quota: %+v err=%v", q, err)
	}
	q.SessionUsed = 100
	q.SessionResumeMin = 15
	spent := SpentAllowanceFromQuota(q, time.Now())
	if spent == nil || spent.Window != "session" || spent.RetryAfter != 15*time.Minute {
		t.Fatalf("unexpected spent allowance: %+v", spent)
	}
}

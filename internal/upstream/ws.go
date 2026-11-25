package upstream

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
)

const (
	afterCompleteWait = 5 * time.Second
	stopSettleWait    = 2500 * time.Millisecond
)

var (
	terminalEvents = map[string]bool{
		"turn_completed": true,
		"turn_aborted":   true,
		"turn_ended":     true,
		"stream_ended":   true,
		"chat_complete":  true,
	}
	failureEvents = map[string]bool{
		"error":         true,
		"session_error": true,
		"stream_error":  true,
		"turn_failed":   true,
	}
)

// Usage holds token counts reported by Amazon Quick's turn_usage events.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	CacheReadTokens  int
	CacheWriteTokens int
	ResolvedModel    string
}

// ChatEvent is a single streamed event emitted during an upstream chat turn.
type ChatEvent struct {
	Type string // "reasoning" | "text"
	Text string
}

// ChatResult is the complete outcome of one Amazon Quick chat turn.
type ChatResult struct {
	Text         string
	Reasoning    string
	ToolCalls    []ToolCall
	Usage        Usage
	ThreadReused bool
	ThreadID     string
}

type wsSession struct {
	Bearer           string
	WSHost           string
	WSPath           string
	Provider         string
	ActorARN         string
	Surface          string
	OutpostID        string
	WorkingSessionID string
	Gateway          bool
}

func buildUserMessageFrame(sess wsSession, cfg config.UpstreamConfig, input turnInput) map[string]any {
	text := input.Prompt
	agentMode := input.Slot
	autoRouting := false
	if agentMode == "auto" {
		agentMode = "smart"
		autoRouting = true
	}
	var customPrompt any
	if strings.TrimSpace(input.SystemPrompt) != "" {
		customPrompt = input.SystemPrompt
	}

	payload := map[string]any{
		"text":                   text,
		"send_origin":            "programmatic",
		"had_physical_input":     false,
		"surfaceType":            sess.Surface,
		"outpostId":              sess.OutpostID,
		"appVersion":             cfg.AppVersion,
		"acp_first_text":         1,
		"user_notification":      1,
		"subtask_progress":       1,
		"external_agent_sign_in": 1,
		"recents_promotion":      1,
		"traceId":                auth.NewUUID(),
		"message_id":             auth.NewUUID(),
		"thread_id":              input.ThreadID,
		"agent_mode":             agentMode,
		"user_timezone":          cfg.Timezone,
		"user_locale":            cfg.Locale,
		"chat_agent_id":          nil,
		"auto_routing":           autoRouting,
		"web_search_enabled":     input.WebSearch,
		"direct_chat":            false,
		"voice_mode":             false,
		"pre_approved_tools":     []any{},
		"preload_skills":         []any{},
		"panel_edits":            []any{},
		"custom_prompt":          customPrompt,
		"incognito":              !cfg.KeepSessions,
	}
	if input.ThinkingEffort != "" && input.ThinkingEffort != "off" {
		payload["thinking_effort"] = input.ThinkingEffort
	} else {
		payload["thinking_effort"] = "off"
	}
	if len(input.Attachments) > 0 {
		payload["attachments"] = input.Attachments
	}
	return map[string]any{
		"type":    "user_message",
		"payload": payload,
	}
}

func (c *Client) sessionFromAccount(ctx context.Context, acct *auth.Account, cfg config.UpstreamConfig) (wsSession, error) {
	if acct == nil {
		return wsSession{}, &UpstreamError{Kind: ErrKindHandshake, StatusCode: 401, Message: "账号为空"}
	}
	bearer := acct.WSBearer()
	if bearer == "" {
		return wsSession{}, &UpstreamError{Kind: ErrKindHandshake, StatusCode: 401, Message: "账号缺少有效访问令牌，请重新授权"}
	}
	gw := acct.IsGateway()
	allowCustom := c.hasCustomEndpoints()
	// Stored/imported endpoints are validated strictly: an untrusted ws_host is
	// rejected and never downgraded to plaintext ws:// (loopback test servers are
	// accepted only when explicit custom endpoint overrides are configured).
	wsHost, wsPath, verr := accountWSEndpoint(acct, allowCustom)
	if verr != nil {
		return wsSession{}, verr
	}

	if gw {
		// gatewayHost already validated the discovered host against the trusted allowlist.
		if host, path, err := c.gatewayHost(ctx, acct); err == nil && host != "" {
			if allowCustom && strings.HasPrefix(acct.TenantURL, "http://") && isLoopbackWSHost(hostOnly(host)) {
				wsHost = "ws://" + host
			} else {
				wsHost = host
			}
			if path != "" {
				wsPath = path
			}
		}
	}
	if wsHost == "" && acct.TenantURL != "" {
		base := strings.TrimRight(strings.TrimSpace(acct.TenantURL), "/")
		if _, terr := auth.ValidateTrustedURL(base, allowCustom); terr != nil {
			return wsSession{}, (&UpstreamError{
				Kind:       ErrKindHandshake,
				StatusCode: http.StatusBadGateway,
				Message:    "账号 tenant_url 未通过安全校验（" + terr.Error() + "），请重新授权",
			}).Normalize()
		}
		if u, err := url.Parse(base); err == nil && u.Host != "" {
			cand := "wss://" + u.Host
			if strings.EqualFold(u.Scheme, "http") {
				cand = "ws://" + u.Host
			}
			validated, terr := validateWSHost(cand, allowCustom)
			if terr != nil {
				return wsSession{}, (&UpstreamError{
					Kind:       ErrKindHandshake,
					StatusCode: http.StatusBadGateway,
					Message:    "账号 tenant_url 未通过安全校验（" + terr.Error() + "），请重新授权",
				}).Normalize()
			}
			wsHost = validated
		}
	}
	if wsHost == "" {
		return wsSession{}, &UpstreamError{Kind: ErrKindHandshake, StatusCode: 401, Message: "账号缺少 ws_host，请重新授权"}
	}

	outpostID := ""
	if cfg.StableDeviceID && !gw && auth.IsDeviceID(acct.DeviceID) {
		outpostID = acct.DeviceID
	} else if gw {
		if auth.IsDeviceID(acct.DeviceID) {
			outpostID = acct.DeviceID
		} else {
			outpostID = auth.NewUUID()
		}
	}

	return wsSession{
		Bearer:           bearer,
		WSHost:           wsHost,
		WSPath:           wsPath,
		Provider:         acct.Provider,
		ActorARN:         acct.ActorARN,
		Surface:          cfg.Surface,
		OutpostID:        outpostID,
		WorkingSessionID: auth.NewUUID(),
		Gateway:          gw,
	}, nil
}

// hostOnly strips an optional :port from host for loopback checks.
func hostOnly(h string) string {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		return hh
	}
	return h
}

func dialTarget(sess wsSession) (string, http.Header, error) {
	host := strings.TrimRight(strings.TrimSpace(sess.WSHost), "/")
	switch {
	case strings.HasPrefix(host, "https://"):
		host = "wss://" + strings.TrimPrefix(host, "https://")
	case strings.HasPrefix(host, "http://"):
		host = "ws://" + strings.TrimPrefix(host, "http://")
	case !strings.HasPrefix(host, "wss://") && !strings.HasPrefix(host, "ws://"):
		host = "wss://" + host
	}

	path := strings.TrimSpace(sess.WSPath)
	if path == "" {
		if sess.Gateway {
			path = auth.GatewayWSPath
		} else {
			path = auth.DefaultWSPath
		}
	}
	target := host
	// ws_path is validated to be a plain absolute path; it can never replace the host.
	if strings.HasPrefix(path, "/") {
		target += path
	} else {
		target += "/" + path
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", nil, &UpstreamError{Kind: ErrKindTransport, StatusCode: 502, Message: fmt.Sprintf("invalid ws_url %q: %v", target, err)}
	}
	headers := http.Header{}
	headers.Set("Origin", "file://")
	headers.Set("X-Surface-Type", sess.Surface)
	headers.Set("X-Outpost-Id", sess.OutpostID)
	headers.Set("X-Agent-Service-Type", "UNIFIED_QUICK")
	if sess.WorkingSessionID != "" {
		headers.Set("X-Working-Session-Id", sess.WorkingSessionID)
	}

	if !sess.Gateway {
		q := u.Query()
		if sess.Surface != "" {
			q.Set("surfaceType", sess.Surface)
		}
		if sess.OutpostID != "" {
			q.Set("outpostId", sess.OutpostID)
		}
		if sess.WorkingSessionID != "" {
			q.Set("workingSessionId", sess.WorkingSessionID)
		}
		if strings.EqualFold(sess.Provider, auth.ProviderSocial) {
			q.Set("token", sess.Bearer)
		}
		u.RawQuery = q.Encode()
	}
	headers.Set("Authorization", "Bearer "+sess.Bearer)
	return u.String(), headers, nil
}

type chunkAssembly struct {
	parts []string
	seen  []bool
	have  int
	size  int
}

const (
	// maxChunkAssemblies caps how many distinct _chunked_frame ids may be
	// in flight at once; maxChunkBytes caps their combined buffered payload.
	maxChunkAssemblies = 64
	maxChunkBytes      = maxEventStreamFrame
)

func (c *Client) executeWSTurn(
	ctx context.Context,
	acct *auth.Account,
	sess wsSession,
	cfg config.UpstreamConfig,
	input turnInput,
	onEvent func(ChatEvent),
) (ChatResult, error) {
	wsURL, headers, err := dialTarget(sess)
	if err != nil {
		return ChatResult{}, err
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: time.Duration(cfg.HandshakeTimeoutSeconds) * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ReadBufferSize:  64 * 1024,
		WriteBufferSize: 64 * 1024,
	}
	_, dialFn, derr := c.transportAndDialer()
	if derr != nil {
		return ChatResult{}, &UpstreamError{Kind: ErrKindTransport, StatusCode: 502, Message: "代理配置无效: " + derr.Error()}
	}
	if dialFn != nil {
		dialer.NetDialContext = dialFn
	}

	reqTimeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if reqTimeout <= 0 {
		reqTimeout = 5 * time.Minute
	}
	turnCtx, cancelTurn := context.WithTimeout(ctx, reqTimeout)
	defer cancelTurn()

	conn, resp, err := dialer.DialContext(turnCtx, wsURL, headers)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
			if resp.Body != nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
			}
		}
		if errors.Is(turnCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return ChatResult{}, (&UpstreamError{Kind: ErrKindTimeout, StatusCode: 504, Message: "upstream WebSocket handshake timed out"}).Normalize()
		}
		if ctx.Err() != nil {
			return ChatResult{}, ctx.Err()
		}
		msg := "upstream WebSocket dial failed"
		if status > 0 {
			msg = fmt.Sprintf("upstream WebSocket handshake failed (HTTP %d)", status)
		}
		return ChatResult{}, (&UpstreamError{
			Kind:       ErrKindHandshake,
			StatusCode: status,
			Message:    msg,
		}).Normalize()
	}
	conn.SetReadLimit(16 * 1024 * 1024)

	var (
		writeMu  sync.Mutex
		closed   bool
		live     bool
		readDead bool
	)
	encodeAndSend := func(val any) error {
		rawJSON, jerr := json.Marshal(val)
		if jerr != nil {
			return jerr
		}
		var wire []byte
		if sess.Gateway {
			wire, jerr = EncodeGateway(rawJSON)
		} else {
			wire, jerr = EncodeAIDP(rawJSON)
		}
		if jerr != nil {
			return jerr
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		if closed {
			return errors.New("websocket closed")
		}
		_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		return conn.WriteMessage(websocket.BinaryMessage, wire)
	}

	sendStopAndClose := func() {
		// Interrupt any in-flight write (e.g. a keepalive ping stuck on a black-holed
		// TCP connection) so acquiring writeMu never waits out its 15s deadline.
		if nc := conn.UnderlyingConn(); nc != nil {
			_ = nc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		}
		settle := stopSettleWait
		if ctx.Err() != nil {
			// The caller has gone away: just flush stop_generation, don't linger.
			settle = 200 * time.Millisecond
		}

		writeMu.Lock()
		wasLive := live
		wasClosed := closed
		wasReadDead := readDead
		closed = true
		if wasClosed {
			writeMu.Unlock()
			return
		}
		var stopWriteErr error
		if wasLive && !wasReadDead {
			stopJSON, _ := json.Marshal(map[string]any{
				"type":    "stop_generation",
				"payload": map[string]any{"thread_id": input.ThreadID},
			})
			var wire []byte
			if sess.Gateway {
				wire, _ = EncodeGateway(stopJSON)
			} else {
				wire, _ = EncodeAIDP(stopJSON)
			}
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			stopWriteErr = conn.WriteMessage(websocket.BinaryMessage, wire)
		}
		writeMu.Unlock()

		if wasLive && !wasReadDead && stopWriteErr == nil {
			// Brief drain so stop_generation flushes before TCP FIN.
			_ = conn.SetReadDeadline(time.Now().Add(settle))
			for i := 0; i < 8; i++ {
				if _, _, rerr := conn.ReadMessage(); rerr != nil {
					break
				}
			}
		}
		if !wasReadDead && stopWriteErr == nil {
			writeMu.Lock()
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(500*time.Millisecond))
			writeMu.Unlock()
		}
		_ = conn.Close()
	}

	// Handshake frames.
	var connectFrame map[string]any
	if sess.Gateway {
		connectFrame = map[string]any{
			"type":       "session_connect",
			"session_id": sess.OutpostID,
		}
	} else {
		connectFrame = map[string]any{
			"type": "session_connect",
			"payload": map[string]any{
				"actor_id":               sess.ActorARN,
				"surfaceType":            sess.Surface,
				"outpostId":              sess.OutpostID,
				"appVersion":             cfg.AppVersion,
				"acp_first_text":         1,
				"user_notification":      1,
				"subtask_progress":       1,
				"external_agent_sign_in": 1,
				"recents_promotion":      1,
			},
		}
	}
	if err := encodeAndSend(connectFrame); err != nil {
		sendStopAndClose()
		return ChatResult{}, (&UpstreamError{Kind: ErrKindTransport, StatusCode: 502, Message: "send session_connect: " + err.Error()}).Normalize()
	}
	if err := encodeAndSend(map[string]any{"type": "federate_status", "payload": map[string]any{}}); err != nil {
		sendStopAndClose()
		return ChatResult{}, (&UpstreamError{Kind: ErrKindTransport, StatusCode: 502, Message: "send federate_status: " + err.Error()}).Normalize()
	}
	if cfg.KeepSessions && !input.Resume {
		_ = encodeAndSend(map[string]any{
			"type": "session_create",
			"payload": map[string]any{
				"session_id": input.ThreadID,
				"title":      input.Title,
			},
		})
	}
	if err := encodeAndSend(buildUserMessageFrame(sess, cfg, input)); err != nil {
		sendStopAndClose()
		return ChatResult{}, (&UpstreamError{Kind: ErrKindTransport, StatusCode: 502, Message: "send user_message: " + err.Error()}).Normalize()
	}
	writeMu.Lock()
	live = true
	writeMu.Unlock()

	// App-level keepalive ping goroutine (prevents AWS Quick's 95s IDLE_TIMEOUT).
	pingDone := make(chan struct{})
	keepaliveDur := time.Duration(cfg.KeepaliveSeconds) * time.Second
	if keepaliveDur <= 0 {
		keepaliveDur = 25 * time.Second
	}
	var pingWG sync.WaitGroup
	pingWG.Add(1)
	go func() {
		defer pingWG.Done()
		tk := time.NewTicker(keepaliveDur)
		defer tk.Stop()
		for {
			select {
			case <-pingDone:
				return
			case <-turnCtx.Done():
				return
			case <-tk.C:
				if err := encodeAndSend(map[string]any{
					"type":    "ping",
					"payload": map[string]any{"timestamp": time.Now().UnixMilli()},
				}); err != nil {
					return
				}
				select {
				case <-pingDone:
					return
				case <-turnCtx.Done():
					return
				default:
				}
				writeMu.Lock()
				if !closed {
					_ = conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
				}
				writeMu.Unlock()
			}
		}
	}()

	// Cancel watcher: unblock ReadMessage when turnCtx cancels.
	cancelStop := context.AfterFunc(turnCtx, func() {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	})
	defer func() {
		cancelStop()
		close(pingDone)
		if ctx.Err() != nil {
			// User cancelled: return immediately; the bounded stop/close
			// handshake finishes in the background.
			go func() {
				sendStopAndClose()
				pingWG.Wait()
			}()
			return
		}
		sendStopAndClose()
		pingWG.Wait()
	}()

	var (
		textBuf     strings.Builder
		thoughtBuf  strings.Builder
		usage       Usage
		chunks      = map[string]*chunkAssembly{}
		chunkBytes  int
		seenTools   = map[string]bool{}
		decoder     = NewWireDecoder(sess.Gateway)
		idleDur     = time.Duration(cfg.IdleTimeoutSeconds) * time.Second
		completeAt  time.Time
		hasComplete bool
	)
	if idleDur <= 0 {
		idleDur = 2 * time.Minute
	}

	emit := func(ev ChatEvent) {
		if onEvent != nil {
			onEvent(ev)
		}
	}
	emitThought := func(delta string) {
		if delta == "" {
			return
		}
		thoughtBuf.WriteString(delta)
		emit(ChatEvent{Type: "reasoning", Text: delta})
	}
	emitText := func(delta string) {
		if delta == "" {
			return
		}
		textBuf.WriteString(delta)
		emit(ChatEvent{Type: "text", Text: delta})
	}

	var handleEnv func(env map[string]any, depth int) (done bool, failErr error)
	handleEnv = func(env map[string]any, depth int) (bool, error) {
		if depth > 4 {
			return false, (&UpstreamError{Kind: ErrKindUpstream, StatusCode: 502, Message: "upstream chunked frame nesting too deep"}).Normalize()
		}
		evType, _ := env["type"].(string)
		p, _ := env["payload"].(map[string]any)
		if p == nil {
			p = map[string]any{}
		}
		switch evType {
		case "_chunked_frame":
			src := p
			if len(src) == 0 {
				src = env
			}
			cid, _ := src["chunk_id"].(string)
			data, _ := src["data"].(string)
			idx := int(asFloat(src["chunk_index"]))
			total := int(asFloat(src["total_chunks"]))
			if cid == "" || total < 1 || total > 4096 || idx < 0 || idx >= total {
				return false, nil
			}
			entry := chunks[cid]
			if entry == nil || len(entry.parts) != total {
				if entry != nil {
					chunkBytes -= entry.size
				} else if len(chunks) >= maxChunkAssemblies {
					return false, (&UpstreamError{Kind: ErrKindUpstream, StatusCode: 502, Message: "too many concurrent upstream chunked frames"}).Normalize()
				}
				entry = &chunkAssembly{parts: make([]string, total), seen: make([]bool, total)}
				chunks[cid] = entry
			}
			if !entry.seen[idx] {
				entry.seen[idx] = true
				entry.have++
			}
			delta := len(data) - len(entry.parts[idx])
			entry.parts[idx] = data
			entry.size += delta
			chunkBytes += delta
			if chunkBytes > maxChunkBytes {
				return false, (&UpstreamError{Kind: ErrKindUpstream, StatusCode: 502, Message: "upstream chunked frame exceeds size limit"}).Normalize()
			}
			if entry.have < total {
				return false, nil
			}
			delete(chunks, cid)
			chunkBytes -= entry.size
			var inner map[string]any
			if json.Unmarshal([]byte(strings.Join(entry.parts, "")), &inner) == nil && inner != nil {
				return handleEnv(inner, depth+1)
			}
			return false, nil

		case "thinking_delta":
			if d := extractDeltaText(env["payload"]); d != "" {
				emitThought(d)
			}
			return false, nil

		case "guardrail_blocked":
			writeMu.Lock()
			live = false
			writeMu.Unlock()
			msg := firstMapStr(p, "message")
			if msg == "" {
				msg = firstMapStr(env, "message")
			}
			if msg == "" {
				msg = "Amazon Quick's guardrail blocked the reply"
			}
			return false, (&UpstreamError{Kind: ErrKindBlocked, StatusCode: 400, Message: msg}).Normalize()

		case "text_delta":
			if d := extractDeltaText(env["payload"]); d != "" {
				emitText(d)
			}
			return false, nil

		case "text_complete", "stream_snapshot":
			if snap, ok := p["text"].(string); ok && snap != "" {
				cur := textBuf.String()
				if cur == "" {
					emitText(snap)
				} else if strings.HasPrefix(snap, cur) && len(snap) > len(cur) {
					emitText(snap[len(cur):])
				}
			}
			return false, nil

		case "turn_usage":
			inTok := int(asFloat(p["input_tokens"]))
			cacheRead := int(asFloat(p["cache_read_tokens"]))
			cacheWrite := int(asFloat(p["cache_write_tokens"]))
			if inTok > 0 || cacheRead > 0 || cacheWrite > 0 {
				usage.PromptTokens = inTok + cacheRead + cacheWrite
				usage.CacheReadTokens = cacheRead
				usage.CacheWriteTokens = cacheWrite
			}
			usage.CompletionTokens += int(asFloat(p["output_tokens"]))
			usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
			if rm, ok := p["resolved_model_id"].(string); ok && strings.TrimSpace(rm) != "" {
				usage.ResolvedModel = strings.TrimSpace(rm)
			}
			return false, nil

		case "tool_start":
			tid := firstMapStr(p, "tool_id", "tool_call_id", "toolCallId")
			tname := firstMapStr(p, "tool_name", "name")
			if cfg.ShowQuickTools && tname != "" && (tid == "" || !seenTools[tid]) {
				if tid != "" {
					seenTools[tid] = true
				}
				prefix := ""
				if thoughtBuf.Len() > 0 && !strings.HasSuffix(thoughtBuf.String(), "\n") {
					prefix = "\n"
				}
				emitThought(fmt.Sprintf("%s[Quick: %s]\n", prefix, tname))
			}
			return false, nil

		case "message_complete":
			cont, _ := p["continuation_expected"].(bool)
			if !cont {
				writeMu.Lock()
				live = false
				writeMu.Unlock()
				hasComplete = true
				completeAt = time.Now().Add(afterCompleteWait)
			} else {
				hasComplete = false
			}
			return false, nil

		default:
			if failureEvents[evType] {
				writeMu.Lock()
				live = false
				writeMu.Unlock()
				code := firstMapStr(p, "code", "error_code")
				if code == "" {
					code = firstMapStr(env, "code", "error_code")
				}
				msg := extractErrorText(env, p)
				if code == "FrameTooLarge" {
					return false, (&UpstreamError{Kind: ErrKindTooLarge, StatusCode: 400, Code: "context_length_exceeded", Message: msg}).Normalize()
				}
				if code == "ThrottlingException" || code == "rate_limited" {
					return false, (&UpstreamError{Kind: ErrKindUpstream, StatusCode: 429, Code: "rate_limit_exceeded", Message: msg}).Normalize()
				}
				return false, (&UpstreamError{Kind: ErrKindUpstream, StatusCode: 502, Message: fmt.Sprintf("upstream %s: %s", evType, msg)}).Normalize()
			}
			if terminalEvents[evType] {
				writeMu.Lock()
				live = false
				writeMu.Unlock()
				return true, nil
			}
		}
		return false, nil
	}

	checkTurnCtx := func() (bool, error) {
		if turnCtx.Err() == nil {
			return false, nil
		}
		if hasComplete {
			return true, nil
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, (&UpstreamError{Kind: ErrKindTimeout, StatusCode: 504, Message: "upstream request timed out"}).Normalize()
	}

	for {
		if done, cerr := checkTurnCtx(); cerr != nil {
			return ChatResult{}, cerr
		} else if done {
			break
		}
		dl := time.Now().Add(idleDur)
		if hasComplete && completeAt.Before(dl) {
			dl = completeAt
		}
		if ctxDL, ok := turnCtx.Deadline(); ok && ctxDL.Before(dl) {
			dl = ctxDL
		}
		_ = conn.SetReadDeadline(dl)
		if done, cerr := checkTurnCtx(); cerr != nil {
			return ChatResult{}, cerr
		} else if done {
			break
		}

		msgType, rawMsg, rerr := conn.ReadMessage()
		if rerr != nil {
			// Success is decided strictly by a final message_complete: a reply that
			// was cut off mid-stream must not be treated as a complete answer
			// (it would poison the ThreadStore and leak half-open tool XML), while
			// an empty-text complete followed by an immediate close is still valid.
			if hasComplete {
				break
			}
			if ctx.Err() != nil {
				return ChatResult{}, ctx.Err()
			}
			// Connection already failed or timed out on read: don't linger draining on close.
			writeMu.Lock()
			readDead = true
			writeMu.Unlock()
			if errors.Is(turnCtx.Err(), context.DeadlineExceeded) {
				return ChatResult{}, (&UpstreamError{Kind: ErrKindTimeout, StatusCode: 504, Message: "upstream request timed out"}).Normalize()
			}
			if ne, ok := rerr.(interface{ Timeout() bool }); ok && ne.Timeout() {
				return ChatResult{}, (&UpstreamError{Kind: ErrKindTimeout, StatusCode: 504, Message: "upstream WebSocket read timed out"}).Normalize()
			}
			return ChatResult{}, (&UpstreamError{Kind: ErrKindTransport, StatusCode: 502, Message: "upstream WebSocket read: " + rerr.Error()}).Normalize()
		}

		var frames []string
		if msgType == websocket.TextMessage {
			frames = []string{string(rawMsg)}
		} else if msgType == websocket.BinaryMessage {
			var derr error
			frames, derr = decoder.Feed(rawMsg)
			if derr != nil {
				if isUpstreamErrorFrame(derr) {
					writeMu.Lock()
					live = false
					writeMu.Unlock()
					// EventStream exception frames carry the same codes as JSON
					// failure events; FrameTooLarge must stay retryable at 70%.
					if strings.Contains(derr.Error(), "[FrameTooLarge]") {
						return ChatResult{}, (&UpstreamError{Kind: ErrKindTooLarge, StatusCode: 400, Code: "context_length_exceeded", Message: derr.Error()}).Normalize()
					}
					if strings.Contains(derr.Error(), "[ThrottlingException]") {
						return ChatResult{}, (&UpstreamError{Kind: ErrKindUpstream, StatusCode: 429, Code: "rate_limit_exceeded", Message: derr.Error()}).Normalize()
					}
					return ChatResult{}, (&UpstreamError{Kind: ErrKindUpstream, StatusCode: 502, Message: derr.Error()}).Normalize()
				}
				continue
			}
		}

		for _, frame := range frames {
			var env map[string]any
			if err := json.Unmarshal([]byte(frame), &env); err != nil || env == nil {
				continue
			}
			done, ferr := handleEnv(env, 0)
			if ferr != nil {
				return ChatResult{}, ferr
			}
			if done {
				return ChatResult{
					Text:      textBuf.String(),
					Reasoning: thoughtBuf.String(),
					Usage:     usage,
					ThreadID:  input.ThreadID,
				}, nil
			}
		}
	}

	return ChatResult{
		Text:      textBuf.String(),
		Reasoning: thoughtBuf.String(),
		Usage:     usage,
		ThreadID:  input.ThreadID,
	}, nil
}

func extractDeltaText(payload any) string {
	if s, ok := payload.(string); ok {
		return s
	}
	m, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	if d, ok := m["delta"].(string); ok && d != "" {
		return d
	}
	if t, ok := m["text"].(string); ok {
		return t
	}
	return ""
}

func extractErrorText(env, p map[string]any) string {
	for _, s := range []string{
		firstMapStr(p, "message", "error", "code", "error_code"),
		firstMapStr(env, "message", "error", "code", "error_code"),
	} {
		if s != "" {
			return s
		}
	}
	return "unknown upstream error"
}

// Package server exposes OpenAI Chat Completions, Anthropic Messages, and Codex Responses
// compatible HTTP endpoints backed by the Amazon Quick account pool and upstream client.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
	"awsquick2api/internal/httpauth"
	"awsquick2api/internal/pool"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/scheduler"
	"awsquick2api/internal/session"
	"awsquick2api/internal/upstream"
)

const ServiceName = "awsquick2api"

// Config wires dependencies into the HTTP gateway Handler.
type Config struct {
	Pool             *pool.Pool
	Upstream         *upstream.Client
	Scheduler        *scheduler.Scheduler
	Session          *session.Router
	Live             *config.LiveHolder
	ReqLog           *reqlog.Recorder
	Panel            http.Handler
	MaxPayloadBytes  int64
	MaxRotate        int
	QueueWaitTimeout time.Duration
	MaxQueue         int
	Version          string
}

// Handler is the root HTTP router for awsquick2api.
type Handler struct {
	cfg Config
	mux *http.ServeMux
}

func NewHandler(cfg Config) *Handler {
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = 64 << 20
	}
	if cfg.MaxRotate <= 0 {
		cfg.MaxRotate = 3
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	h := &Handler{
		cfg: cfg,
		mux: http.NewServeMux(),
	}

	// OpenAI Chat Completions & Models
	h.mux.HandleFunc("POST /v1/chat/completions", h.withBearerAuth(h.handleOpenAIChat))
	h.mux.HandleFunc("GET /v1/models", h.withDualAuth(h.handleModels))

	// Anthropic Messages (both /v1/messages and /messages aliases for Claude Code)
	h.mux.HandleFunc("POST /v1/messages", h.withAnthropicAuth(h.handleAnthropicMessages))
	h.mux.HandleFunc("POST /messages", h.withAnthropicAuth(h.handleAnthropicMessages))
	h.mux.HandleFunc("POST /v1/messages/count_tokens", h.withAnthropicAuth(h.handleAnthropicCountTokens))
	h.mux.HandleFunc("POST /messages/count_tokens", h.withAnthropicAuth(h.handleAnthropicCountTokens))

	// Codex / OpenAI Responses (both /v1/responses and /responses aliases)
	h.mux.HandleFunc("POST /v1/responses", h.withBearerAuth(h.handleResponses))
	h.mux.HandleFunc("POST /responses", h.withBearerAuth(h.handleResponses))
	h.mux.HandleFunc("GET /v1/responses", h.withBearerAuth(h.handleResponsesWSUnsupported))
	h.mux.HandleFunc("GET /responses", h.withBearerAuth(h.handleResponsesWSUnsupported))

	// Health probe
	h.mux.HandleFunc("GET /healthz", h.handleHealthz)

	// Embedded Web management panel
	if cfg.Panel != nil {
		h.mux.Handle("/panel/", cfg.Panel)
		h.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/panel/", http.StatusFound)
		})
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) loadSnapshot() config.LiveSnapshot {
	if h.cfg.Live != nil {
		return h.cfg.Live.Load()
	}
	return config.LiveSnapshot{
		Upstream:          config.Default().Upstream,
		Thinking:          config.Default().Thinking,
		ClaudeAliases:     true,
		EmptyRetryEnabled: true,
		StrictPrivacyDLP:  true,
		MaxRotate:         h.cfg.MaxRotate,
	}
}

func (h *Handler) catalog() *upstream.ModelCatalog {
	if h.cfg.Upstream != nil {
		return h.cfg.Upstream.GetCatalog()
	}
	return upstream.DefaultCatalog()
}

func (h *Handler) apiKey() string {
	if h.cfg.Live != nil {
		return h.cfg.Live.Load().APIKey
	}
	return ""
}

func (h *Handler) maxRotate(snap config.LiveSnapshot) int {
	if snap.MaxRotate > 0 {
		return snap.MaxRotate
	}
	if h.cfg.MaxRotate > 0 {
		return h.cfg.MaxRotate
	}
	return 3
}

func (h *Handler) queueWaitTimeout() time.Duration {
	if h.cfg.QueueWaitTimeout > 0 {
		return h.cfg.QueueWaitTimeout
	}
	return 35 * time.Second
}

func (h *Handler) maxQueue() int {
	if h.cfg.MaxQueue > 0 {
		return h.cfg.MaxQueue
	}
	return 32
}

func (h *Handler) withBearerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !httpauth.VerifyBearer(r, h.apiKey()) {
			writeOpenAIError(w, http.StatusUnauthorized, "authentication_error", "Invalid or missing API key")
			return
		}
		next(w, r)
	}
}

func (h *Handler) withAnthropicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !httpauth.VerifyAnthropic(r, h.apiKey()) {
			writeAnthropicError(w, http.StatusUnauthorized, "authentication_error", "Invalid or missing API key")
			return
		}
		next(w, r)
	}
}

func (h *Handler) withDualAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !httpauth.VerifyDual(r, h.apiKey()) {
			writeOpenAIError(w, http.StatusUnauthorized, "authentication_error", "Invalid or missing API key")
			return
		}
		next(w, r)
	}
}

func (h *Handler) readBodyLimited(
	w http.ResponseWriter,
	r *http.Request,
	writeErr func(http.ResponseWriter, int, string, string),
) ([]byte, bool) {
	if writeErr == nil {
		writeErr = writeOpenAIError
	}
	limit := h.cfg.MaxPayloadBytes
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("Request body exceeds limit (%d bytes)", limit))
			return nil, false
		}
		writeErr(w, http.StatusBadRequest, "invalid_request_error", "Failed to read request body")
		return nil, false
	}
	return raw, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeOpenAIError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": msg,
			"type":    code,
			"code":    code,
		},
	})
}

func writeAnthropicError(w http.ResponseWriter, status int, errType, msg string) {
	writeJSON(w, status, map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    errType,
			"message": msg,
		},
	})
}

// turnOutcome captures everything needed by protocol encoders and reqlog after executing a chat turn.
type turnOutcome struct {
	ReqID        string
	Start        time.Time
	FirstEventAt time.Time
	Account      *auth.Account
	Slot         string
	Result       upstream.ChatResult
	EmptyRetried bool
}

// runChatTurn handles sticky conversation routing, proactive/401 token refresh, pre-output
// account rotation on 429/5xx, optional empty-output retry, and metadata-only reqlog recording.
func (h *Handler) runChatTurn(
	ctx context.Context,
	r *http.Request,
	path string,
	reqModel string,
	req upstream.ChatRequest,
	onStartStream func(acct *auth.Account, reqID string),
	onEvent func(ev upstream.ChatEvent),
) (*turnOutcome, *upstream.UpstreamError) {
	snap := h.loadSnapshot()
	cat := h.catalog()
	slot, _, suffixEffort, _ := cat.Resolve(reqModel, snap.Upstream.DefaultModel, snap.ClaudeAliases)
	req.Slot = slot
	req.ThinkingEffort = upstream.ResolveThinkingEffort(snap.Thinking, reqModel, slot, suffixEffort, req.ThinkingEffort)
	strictDLP := snap.StrictPrivacyDLP
	req.StrictPrivacyDLP = &strictDLP
	if req.ConversationID == "" {
		req.ConversationID = upstream.ConversationIDFromHeaders(r.Header)
	}

	reqID := reqlog.NewRequestID()
	start := time.Now()

	// Derive sticky conversation key for account affinity.
	rawMsgs := make([]any, len(req.Messages))
	for i, m := range req.Messages {
		rawMsgs[i] = m
	}
	sessKey := session.DeriveKey(req.ConversationID, rawMsgs)
	var preferredUID string
	if h.cfg.Session != nil && sessKey != "" {
		if uid, _, ok := h.cfg.Session.Lookup(sessKey); ok {
			preferredUID = uid
		}
	}

	maxRot := h.maxRotate(snap)
	excluded := map[string]bool{}
	var (
		lastErr      *upstream.UpstreamError
		lastAcct     *auth.Account
		emptyRetried bool
	)

	recordResult := func(acct *auth.Account, status int, errCode, errMsg string, out *turnOutcome) {
		if h.cfg.ReqLog == nil {
			return
		}
		e := reqlog.Entry{
			ID:             reqID,
			Timestamp:      start.UnixMilli(),
			Path:           path,
			RequestedModel: reqModel,
			ModelSlot:      slot,
			Status:         status,
			ErrorCode:      errCode,
			ErrorMessage:   errMsg,
			Stream:         req.Stream,
			TotalMs:        time.Since(start).Milliseconds(),
			EmptyRetried:   emptyRetried,
		}
		if acct != nil {
			e.AccountUID = acct.UID
			e.AccountLabel = acct.DisplayName()
		}
		if out != nil {
			e.ActualModel = out.Result.Usage.ResolvedModel
			e.ThreadReused = out.Result.ThreadReused
			e.PromptTokens = out.Result.Usage.PromptTokens
			e.CompletionTokens = out.Result.Usage.CompletionTokens
			e.CacheReadTokens = out.Result.Usage.CacheReadTokens
			if !out.FirstEventAt.IsZero() {
				e.TTFBMs = out.FirstEventAt.Sub(start).Milliseconds()
			}
		}
		h.cfg.ReqLog.Record(e)
	}

	for attempt := 0; attempt < maxRot; attempt++ {
		if ctx.Err() != nil {
			return nil, &upstream.UpstreamError{StatusCode: 499, Code: "client_canceled", Message: "client canceled"}
		}

		pref := preferredUID
		if excluded[pref] {
			pref = ""
		}
		lease, aerr := h.cfg.Pool.Acquire(ctx, pref, excluded, h.queueWaitTimeout(), h.maxQueue())
		if aerr != nil {
			if ctx.Err() != nil {
				return nil, &upstream.UpstreamError{StatusCode: 499, Code: "client_canceled", Message: "client canceled"}
			}
			status := http.StatusServiceUnavailable
			code := "no_accounts_available"
			if errors.Is(aerr, pool.ErrPoolBusy) {
				status = http.StatusTooManyRequests
				code = "pool_busy"
			}
			ue := &upstream.UpstreamError{StatusCode: status, Code: code, Message: aerr.Error()}
			if lastErr != nil {
				ue = lastErr
			}
			recordResult(lastAcct, ue.StatusCode, ue.Code, ue.Error(), nil)
			return nil, ue
		}

		acct := lease.Account
		lastAcct = acct

		// Proactive refresh if access token is within 2 minutes of expiring.
		if h.cfg.Scheduler != nil && acct.NeedsRefresh(time.Now(), 2*time.Minute) {
			if rerr := h.cfg.Scheduler.RefreshOneTokenIfStale(ctx, acct.UID, acct.AccessToken); rerr == nil {
				if fresh := h.cfg.Pool.AuthByUID(acct.UID); fresh != nil {
					acct = fresh
				}
			}
		}

		// Try up to 2 times on the same account when a 401 occurs before any output is emitted.
		for authTry := 0; authTry < 2; authTry++ {
			var (
				commitMu     sync.Mutex
				committed    bool
				firstEventAt time.Time
				waitTimer    *time.Timer
			)
			commitStream := func() {
				commitMu.Lock()
				if committed {
					commitMu.Unlock()
					return
				}
				committed = true
				if waitTimer != nil {
					waitTimer.Stop()
				}
				commitMu.Unlock()
				if onStartStream != nil {
					onStartStream(acct, reqID)
				}
			}

			if req.Stream && onStartStream != nil && snap.Upstream.HeaderWaitSeconds > 0 {
				waitTimer = time.AfterFunc(time.Duration(snap.Upstream.HeaderWaitSeconds)*time.Second, commitStream)
			}

			res, cerr := h.cfg.Upstream.Chat(ctx, acct, req, func(ev upstream.ChatEvent) {
				commitMu.Lock()
				if firstEventAt.IsZero() {
					firstEventAt = time.Now()
				}
				commitMu.Unlock()
				if req.Stream {
					commitStream()
					if onEvent != nil {
						onEvent(ev)
					}
				}
			})

			commitMu.Lock()
			if waitTimer != nil {
				waitTimer.Stop()
			}
			wasCommitted := committed
			firstAt := firstEventAt
			commitMu.Unlock()

			// Check for empty output (no text and no tool calls) before committing.
			if cerr == nil && strings.TrimSpace(res.Text) == "" && len(res.ToolCalls) == 0 {
				if snap.EmptyRetryEnabled && !wasCommitted && !emptyRetried {
					emptyRetried = true
					log.Printf("[server] empty reply from acct=%s slot=%s; retrying once", acct.UID, slot)
					continue
				}
				cerr = (&upstream.UpstreamError{
					Kind:       upstream.ErrKindUpstream,
					StatusCode: http.StatusBadGateway,
					Code:       "upstream_empty_response",
					Message:    "Amazon Quick returned an empty response with no text or tool calls",
				}).Normalize()
			}

			if cerr == nil {
				lease.Release()
				h.cfg.Pool.MarkSuccess(acct.UID, res.Usage.TotalTokens)
				if h.cfg.Session != nil && sessKey != "" {
					h.cfg.Session.Bind(sessKey, acct.UID, req.ConversationID)
				}
				if req.Stream && !wasCommitted && onStartStream != nil {
					commitStream()
				}
				out := &turnOutcome{
					ReqID:        reqID,
					Start:        start,
					FirstEventAt: firstAt,
					Account:      acct,
					Slot:         slot,
					Result:       res,
					EmptyRetried: emptyRetried,
				}
				recordResult(acct, http.StatusOK, "", "", out)
				return out, nil
			}

			// Client disconnect / cancel.
			if ctx.Err() != nil {
				lease.Release()
				recordResult(acct, 499, "client_canceled", "client canceled", nil)
				return nil, &upstream.UpstreamError{StatusCode: 499, Code: "client_canceled", Message: "client canceled"}
			}

			var ue *upstream.UpstreamError
			if !errors.As(cerr, &ue) {
				ue = (&upstream.UpstreamError{Kind: upstream.ErrKindUpstream, StatusCode: http.StatusBadGateway, Message: cerr.Error()}).Normalize()
			} else {
				ue = ue.Normalize()
			}
			lastErr = ue

			// Once stream headers have already been flushed to the client, do not rotate.
			if wasCommitted {
				lease.Release()
				recordResult(acct, ue.StatusCode, ue.Code, ue.Error(), nil)
				return nil, ue
			}

			// Pre-output 401: try forcing a single token refresh on this account.
			if ue.IsAuthError() && authTry == 0 && h.cfg.Scheduler != nil {
				log.Printf("[server] 401 on acct=%s; attempting token refresh and single retry", acct.UID)
				if rerr := h.cfg.Scheduler.RefreshOneTokenIfStale(ctx, acct.UID, acct.AccessToken); rerr == nil {
					if fresh := h.cfg.Pool.AuthByUID(acct.UID); fresh != nil {
						acct = fresh
						continue
					}
				} else {
					var se *auth.StepError
					if errors.As(rerr, &se) && se.Expired {
						log.Printf("WARN: [server] acct=%s refresh expired; rotating", acct.UID)
					} else {
						h.cfg.Pool.MarkSoftFailure(acct.UID, "401_refresh_failed")
					}
				}
			}

			// Apply appropriate pool cooldown / failure accounting before rotating.
			if ue.IsRateLimit() {
				h.cfg.Pool.MarkRateLimited(acct.UID, "quota_exhausted", ue.RetryAfter)
			} else if ue.ShouldSwitchAccount() {
				h.cfg.Pool.MarkSoftFailure(acct.UID, fmt.Sprintf("http_%d_%s", ue.StatusCode, ue.Kind))
			}

			if h.cfg.Session != nil && sessKey != "" && ue.ShouldSwitchAccount() {
				h.cfg.Session.Unbind(sessKey)
			}
			excluded[acct.UID] = true
			lease.Release()

			if !ue.ShouldSwitchAccount() {
				recordResult(acct, ue.StatusCode, ue.Code, ue.Error(), nil)
				return nil, ue
			}
			break // break authTry loop -> rotate to next account
		}
	}

	if lastErr == nil {
		lastErr = &upstream.UpstreamError{StatusCode: http.StatusBadGateway, Code: "upstream_error", Message: "all retry attempts failed"}
	}
	recordResult(lastAcct, lastErr.StatusCode, lastErr.Code, lastErr.Error(), nil)
	return nil, lastErr
}

func setGatewayResponseHeaders(w http.ResponseWriter, reqID string, acct *auth.Account, actualModel string, threadReused bool) {
	if reqID != "" {
		w.Header().Set("X-Request-Id", reqID)
	}
	if acct != nil {
		w.Header().Set("X-Quick-Account", acct.UID)
	}
	if actualModel != "" {
		w.Header().Set("X-Quick-Actual-Model", actualModel)
	}
	if threadReused {
		w.Header().Set("X-Quick-Thread-Reused", "true")
	}
}

func writeUpstreamErrorWithRetryAfter(w http.ResponseWriter, ue *upstream.UpstreamError, anthropic bool) {
	if ue == nil {
		if anthropic {
			writeAnthropicError(w, http.StatusBadGateway, "api_error", "upstream error")
		} else {
			writeOpenAIError(w, http.StatusBadGateway, "upstream_error", "upstream error")
		}
		return
	}
	if ue.RetryAfter > 0 {
		secs := int(ue.RetryAfter.Seconds())
		if secs < 1 {
			secs = 1
		}
		if secs > 6*3600 {
			secs = 6 * 3600
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	status := ue.StatusCode
	if status < 400 {
		status = http.StatusBadGateway
	}
	if anthropic {
		etype := "api_error"
		switch status {
		case http.StatusBadRequest:
			etype = "invalid_request_error"
		case http.StatusUnauthorized:
			etype = "authentication_error"
		case http.StatusForbidden:
			etype = "permission_error"
		case http.StatusTooManyRequests:
			etype = "rate_limit_error"
		case http.StatusGatewayTimeout:
			etype = "overloaded_error"
		}
		writeAnthropicError(w, status, etype, ue.Error())
		return
	}
	writeOpenAIError(w, status, ue.Code, ue.Error())
}

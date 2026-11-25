// Package server exposes OpenAI Chat Completions, Anthropic Messages, and Codex Responses
// compatible HTTP endpoints backed by the Amazon Quick account pool and upstream client.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	slot, spec, suffixEffort, known := cat.Resolve(reqModel, snap.Upstream.DefaultModel, snap.ClaudeAliases)
	if !modelPermitted(snap, cat, reqModel, slot, spec, suffixEffort, known) {
		return nil, &upstream.UpstreamError{
			Kind:       upstream.ErrKindInvalid,
			StatusCode: http.StatusForbidden,
			Code:       "model_not_allowed",
			Message:    fmt.Sprintf("model %q is not allowed on this gateway", reqModel),
		}
	}
	// The advanced tier is only served by accounts whose quota reports AdvancedEnabled;
	// routing it to ordinary accounts would fail upstream and wrongly penalise them.
	requireAdvanced := slot == "advanced"
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
		lease, aerr := h.cfg.Pool.AcquireWith(ctx, pool.AcquireOptions{
			PreferredUID:    pref,
			Exclude:         excluded,
			WaitTimeout:     h.queueWaitTimeout(),
			MaxWaiters:      h.maxQueue(),
			RequireAdvanced: requireAdvanced,
		})
		if aerr != nil {
			if ctx.Err() != nil {
				return nil, &upstream.UpstreamError{StatusCode: 499, Code: "client_canceled", Message: "client canceled"}
			}
			status := http.StatusServiceUnavailable
			code := "no_accounts_available"
			switch {
			case errors.Is(aerr, pool.ErrPoolBusy):
				status = http.StatusTooManyRequests
				code = "pool_busy"
			case errors.Is(aerr, pool.ErrNoAdvancedAccounts) && lastErr == nil && !h.cfg.Pool.HasAdvancedAccount():
				// Only a pool with no advanced-capable account at all is a client
				// error. Advanced accounts that exist but are excluded, cooling down
				// or circuit-broken keep the normal 503 (or lastErr after rotation).
				status = http.StatusBadRequest
				code = "model_not_available"
			}
			ue := &upstream.UpstreamError{StatusCode: status, Code: code, Message: reqlog.ScrubCredentials(aerr.Error())}
			if code == "model_not_available" {
				ue.Kind = upstream.ErrKindInvalid
			}
			if lastErr != nil {
				ue = lastErr
			}
			recordResult(lastAcct, ue.StatusCode, ue.Code, ue.Error(), nil)
			return nil, ue
		}

		out, ue, rotate := func() (*turnOutcome, *upstream.UpstreamError, bool) {
			// Every exit path of a single-account attempt (success, cancel, 401 refresh
			// retry, empty-reply retry, rotation) must release the concurrency lease.
			defer lease.Release()
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

			authRefreshed := false
			for {
				var (
					// streamMu serializes the header_wait timer callback, upstream
					// events, and the post-Chat bookkeeping so that onStartStream /
					// onEvent never run concurrently and never run after this attempt
					// has handed the ResponseWriter back to the caller.
					streamMu     sync.Mutex
					committed    bool
					turnDone     bool
					timerStopped bool
					firstEventAt time.Time
					waitTimer    *time.Timer
					timerExited  chan struct{}
				)
				commitStreamLocked := func() {
					if committed {
						return
					}
					committed = true
					if waitTimer != nil && waitTimer.Stop() {
						timerStopped = true
					}
					if onStartStream != nil {
						onStartStream(acct, reqID)
					}
				}

				if req.Stream && onStartStream != nil && snap.Upstream.HeaderWaitSeconds > 0 {
					// Create the timer and publish waitTimer/timerExited while holding
					// streamMu: the callback acquires streamMu before reading waitTimer
					// (via commitStreamLocked), which gives a happens-before edge even
					// when the timer fires before any upstream event.
					exited := make(chan struct{})
					streamMu.Lock()
					timerExited = exited
					waitTimer = time.AfterFunc(time.Duration(snap.Upstream.HeaderWaitSeconds)*time.Second, func() {
						defer close(exited)
						streamMu.Lock()
						defer streamMu.Unlock()
						if turnDone {
							return
						}
						commitStreamLocked()
					})
					streamMu.Unlock()
				}

				res, cerr := h.cfg.Upstream.Chat(ctx, acct, req, func(ev upstream.ChatEvent) {
					streamMu.Lock()
					defer streamMu.Unlock()
					if turnDone {
						return
					}
					if firstEventAt.IsZero() {
						firstEventAt = time.Now()
					}
					if req.Stream {
						commitStreamLocked()
						if onEvent != nil {
							onEvent(ev)
						}
					}
				})

				streamMu.Lock()
				turnDone = true
				timerFired := false
				if waitTimer != nil && !timerStopped && !waitTimer.Stop() {
					// The AfterFunc callback has fired (or is about to run); wait for
					// it to exit so no goroutine touches the ResponseWriter later.
					timerFired = true
				}
				timerStopped = true
				wasCommitted := committed
				firstAt := firstEventAt
				streamMu.Unlock()
				if timerFired {
					<-timerExited
				}

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
					h.cfg.Pool.MarkSuccess(acct.UID, res.Usage.TotalTokens)
					if h.cfg.Session != nil && sessKey != "" {
						h.cfg.Session.Bind(sessKey, acct.UID, req.ConversationID)
					}
					if req.Stream && !wasCommitted && onStartStream != nil {
						streamMu.Lock()
						commitStreamLocked()
						streamMu.Unlock()
					}
					resOut := &turnOutcome{
						ReqID:        reqID,
						Start:        start,
						FirstEventAt: firstAt,
						Account:      acct,
						Slot:         slot,
						Result:       res,
						EmptyRetried: emptyRetried,
					}
					recordResult(acct, http.StatusOK, "", "", resOut)
					return resOut, nil, false
				}

				// Client disconnect / cancel.
				if ctx.Err() != nil {
					recordResult(acct, 499, "client_canceled", "client canceled", nil)
					return nil, &upstream.UpstreamError{StatusCode: 499, Code: "client_canceled", Message: "client canceled"}, false
				}

				var uerr *upstream.UpstreamError
				if !errors.As(cerr, &uerr) {
					uerr = (&upstream.UpstreamError{Kind: upstream.ErrKindUpstream, StatusCode: http.StatusBadGateway, Message: reqlog.ScrubCredentials(cerr.Error())}).Normalize()
				} else {
					cp := *uerr
					cp.Message = reqlog.ScrubCredentials(cp.Message)
					uerr = cp.Normalize()
				}
				lastErr = uerr

				// Pre-output 401: try forcing a single token refresh on this account.
				alreadyPenalized := false
				if !wasCommitted && uerr.IsAuthError() && !authRefreshed && h.cfg.Scheduler != nil {
					authRefreshed = true
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
							alreadyPenalized = true
						} else {
							h.cfg.Pool.MarkSoftFailure(acct.UID, "401_refresh_failed")
							alreadyPenalized = true
						}
					}
				}

				// Apply appropriate pool cooldown / failure accounting even when the stream has
				// already been committed (only retrying/rotating is skipped post-commit).
				if !alreadyPenalized {
					if uerr.IsRateLimit() {
						h.cfg.Pool.MarkRateLimited(acct.UID, "quota_exhausted", uerr.RetryAfter)
					} else if uerr.ShouldSwitchAccount() {
						h.cfg.Pool.MarkSoftFailure(acct.UID, fmt.Sprintf("http_%d_%s", uerr.StatusCode, uerr.Kind))
					}
				}

				if h.cfg.Session != nil && sessKey != "" && uerr.ShouldSwitchAccount() {
					h.cfg.Session.Unbind(sessKey)
				}
				excluded[acct.UID] = true

				// Once stream headers have already been flushed to the client, do not rotate.
				if wasCommitted || !uerr.ShouldSwitchAccount() {
					recordResult(acct, uerr.StatusCode, uerr.Code, uerr.Error(), nil)
					return nil, uerr, false
				}
				return nil, nil, true
			}
		}()
		if !rotate {
			return out, ue
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
	if acct != nil && acct.UID != "" {
		// Never expose the raw UID on public /v1/* responses: it is derived from the
		// account e-mail. An opaque digest still lets operators correlate requests.
		w.Header().Set("X-Quick-Account", opaqueAccountID(acct.UID))
	}
	if actualModel != "" {
		w.Header().Set("X-Quick-Actual-Model", actualModel)
	}
	if threadReused {
		w.Header().Set("X-Quick-Thread-Reused", "true")
	}
}

// opaqueAccountID returns a non-reversible short identifier for an account UID.
func opaqueAccountID(uid string) string {
	sum := sha256.Sum256([]byte(uid))
	return hex.EncodeToString(sum[:])[:12]
}

// modelPermitted enforces models.allowed / models.hidden at inference time so that
// callers cannot bypass the GET /v1/models visibility rules by naming a model directly
// or sending an unknown model name that falls back to the default slot.
// An empty requested model always maps to the operator-configured default.
func modelPermitted(snap config.LiveSnapshot, cat *upstream.ModelCatalog, reqModel, slot string, spec upstream.ModelSpec, suffixEffort string, known bool) bool {
	key := strings.ToLower(strings.TrimSpace(reqModel))
	if key == "" {
		return true
	}
	if idx := strings.LastIndexByte(key, '/'); idx >= 0 {
		key = key[idx+1:]
	}
	specID := strings.ToLower(spec.ID)
	slotLow := strings.ToLower(strings.TrimSpace(slot))
	cands := []string{key, specID, slotLow}
	if suffixEffort != "" && specID != "" {
		cands = append(cands, specID+"-"+suffixEffort)
	}
	if !known && cat != nil && slotLow != "" {
		for _, s := range cat.Specs {
			if strings.EqualFold(s.Slot, slotLow) {
				if id := strings.ToLower(strings.TrimSpace(s.ID)); id != "" {
					cands = append(cands, id)
				}
				break
			}
		}
	}
	for _, c := range cands {
		if c != "" && snap.HiddenModels[c] {
			return false
		}
	}
	if !snap.AllowlistEnabled {
		return true
	}
	if !known {
		return false
	}
	for _, c := range cands {
		if c != "" && snap.AllowedModels[c] {
			return true
		}
	}
	return false
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
	msg := reqlog.ScrubCredentials(ue.Error())
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
		writeAnthropicError(w, status, etype, msg)
		return
	}
	writeOpenAIError(w, status, ue.Code, msg)
}

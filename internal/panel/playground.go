package panel

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"awsquick2api/internal/config"
	"awsquick2api/internal/pool"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/upstream"
)

const (
	maxPlaygroundPromptRunes = 4000
	playgroundTimeout        = 90 * time.Second
)

// handlePlayground runs a lightweight single-turn live diagnostic prompt through
// the configured account pool and upstream client (with DLP enabled per config)
// so operators can verify models, thinking effort, and latency directly from the panel.
func (p *Panel) handlePlayground(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Pool == nil || p.cfg.Upstream == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "upstream gateway unavailable"})
		return
	}
	var req struct {
		Model   string `json:"model"`
		Effort  string `json:"effort"`
		Prompt  string `json:"prompt"`
		WebSrch *bool  `json:"web_search,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	prompt := strings.TrimSpace(req.Prompt)
	if prompt == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "prompt is required"})
		return
	}
	if len([]rune(prompt)) > maxPlaygroundPromptRunes {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "prompt exceeds 4000 characters"})
		return
	}

	defaultModel := "smart"
	allowClaude := true
	strictDLP := true
	var thinkingCfg config.ThinkingConfig
	if p.cfg.Live != nil {
		snap := p.cfg.Live.Load()
		defaultModel = snap.Upstream.DefaultModel
		allowClaude = snap.ClaudeAliases
		strictDLP = snap.StrictPrivacyDLP
		thinkingCfg = snap.Thinking
	}
	cat := p.cfg.Upstream.GetCatalog()
	slot, _, suffixEffort, _ := cat.Resolve(req.Model, defaultModel, allowClaude)
	effort := upstream.ResolveThinkingEffort(thinkingCfg, req.Model, slot, suffixEffort, req.Effort)

	ctx, cancel := context.WithTimeout(r.Context(), playgroundTimeout)
	defer cancel()

	lease, err := p.cfg.Pool.AcquireWith(ctx, pool.AcquireOptions{
		WaitTimeout:     10 * time.Second,
		RequireAdvanced: slot == "advanced",
	})
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, pool.ErrNoAdvancedAccounts) && !p.cfg.Pool.HasAdvancedAccount() {
			status = http.StatusBadRequest
		} else if errors.Is(err, pool.ErrPoolBusy) {
			status = http.StatusTooManyRequests
		}
		writeJSON(w, status, map[string]any{"error": reqlog.ScrubCredentials(err.Error())})
		return
	}
	defer lease.Release()

	acct := lease.Account
	if p.cfg.Scheduler != nil && acct.NeedsRefresh(time.Now(), 2*time.Minute) {
		_ = p.cfg.Scheduler.RefreshOneTokenIfStale(ctx, acct.UID, acct.AccessToken)
		if fresh := p.cfg.Pool.AuthByUID(acct.UID); fresh != nil {
			acct = fresh
		}
	}

	start := time.Now()
	var ttfbMs int64
	res, cerr := p.cfg.Upstream.Chat(ctx, acct, upstream.ChatRequest{
		Model:            req.Model,
		Slot:             slot,
		ThinkingEffort:   effort,
		Messages:         []map[string]any{{"role": "user", "content": prompt}},
		WebSearch:        req.WebSrch,
		Stream:           true,
		StrictPrivacyDLP: &strictDLP,
	}, func(ev upstream.ChatEvent) {
		if ttfbMs == 0 && ev.Text != "" {
			ttfbMs = time.Since(start).Milliseconds()
		}
	})
	totalMs := time.Since(start).Milliseconds()
	if cerr != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":       false,
			"error":    reqlog.ScrubCredentials(cerr.Error()),
			"total_ms": totalMs,
			"account":  acct.DisplayName(),
		})
		return
	}
	totalTok := res.Usage.TotalTokens
	if totalTok == 0 {
		totalTok = res.Usage.PromptTokens + res.Usage.CompletionTokens
	}
	p.cfg.Pool.MarkSuccess(acct.UID, totalTok)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"account":           acct.DisplayName(),
		"slot":              slot,
		"actual_model":      res.Usage.ResolvedModel,
		"text":              res.Text,
		"reasoning":         res.Reasoning,
		"ttfb_ms":           ttfbMs,
		"total_ms":          totalMs,
		"prompt_tokens":     res.Usage.PromptTokens,
		"completion_tokens": res.Usage.CompletionTokens,
		"total_tokens":      totalTok,
	})
}

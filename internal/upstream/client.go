package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
)

type gwHostEntry struct {
	host   string
	wsPath string
	at     time.Time
}

// Client is the thread-safe Amazon Quick upstream client managing WebSocket chat turns,
// stateful thread reuse, QBS quota/settings/attachment APIs, and token refresh.
type Client struct {
	Threads *ThreadStore

	mu      sync.RWMutex
	cfg     config.UpstreamConfig
	catalog *ModelCatalog

	trMu    sync.Mutex
	trCache *cachedTransport

	gwHostMu      sync.Mutex
	gwHosts       map[string]gwHostEntry
	settingsMu    sync.Mutex
	settingsCache map[string]settingsCacheEntry
}

func NewClient(cfg config.UpstreamConfig, cat *ModelCatalog) *Client {
	if cat == nil {
		cat = DefaultCatalog()
	}
	return &Client{
		Threads:       NewThreadStore(),
		cfg:           cfg,
		catalog:       cat,
		gwHosts:       map[string]gwHostEntry{},
		settingsCache: map[string]settingsCacheEntry{},
	}
}

func (c *Client) UpdateConfig(cfg config.UpstreamConfig) {
	c.mu.Lock()
	c.cfg = cfg
	c.mu.Unlock()
}

func (c *Client) Config() config.UpstreamConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg
}

func (c *Client) EndpointOverrides() auth.EndpointOverrides {
	cfg := c.Config()
	return auth.EndpointOverrides{
		OIDCBase:     cfg.OIDCBase,
		DiscoveryURL: cfg.DiscoveryURL,
		DataPlaneURL: cfg.DataPlaneURL,
	}
}

func (c *Client) hasCustomEndpoints() bool {
	ov := c.EndpointOverrides()
	return ov.OIDCBase != "" || ov.DiscoveryURL != "" || ov.DataPlaneURL != ""
}

func (c *Client) GetCatalog() *ModelCatalog {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.catalog == nil {
		return DefaultCatalog()
	}
	return c.catalog
}

func (c *Client) SetCatalog(cat *ModelCatalog) {
	if cat == nil {
		return
	}
	c.mu.Lock()
	c.catalog = cat
	c.mu.Unlock()
}

// RefreshToken refreshes one account's OAuth tokens using the configured outbound transport.
func (c *Client) RefreshToken(ctx context.Context, acct *auth.Account) (*auth.Account, error) {
	cl, err := c.upstreamHTTPClient(30 * time.Second)
	if err != nil {
		return nil, err
	}
	return auth.RefreshTokens(ctx, cl, acct, c.EndpointOverrides())
}

// Chat executes one full Amazon Quick chat turn (handling stateful thread reuse, 64 KB frame
// fitting, 70% FrameTooLarge auto-retry, stale-thread fallback, and streaming BridgeStream tool parsing).
func (c *Client) Chat(ctx context.Context, acct *auth.Account, req ChatRequest, onEvent func(ChatEvent)) (ChatResult, error) {
	cfg := c.Config()
	pt, err := prepareTurn(req, cfg)
	if err != nil {
		return ChatResult{}, err
	}

	sess, err := c.sessionFromAccount(ctx, acct, cfg)
	if err != nil {
		return ChatResult{}, err
	}
	acctKey := acct.TenantURL + "|" + acct.UID
	strictDLP := true
	if req.StrictPrivacyDLP != nil {
		strictDLP = *req.StrictPrivacyDLP
	}
	piiPolicy := buildAccountPrivacyPolicy(acct, req.Messages, strictDLP)

	// emittedAny records whether any event already reached the caller's stream.
	// Once output has been forwarded, no retry (stale-thread fallback or 70%
	// FrameTooLarge re-compose) may run, or two answers would be spliced into
	// one SSE response.
	emittedAny := false
	if userOnEvent := onEvent; userOnEvent != nil {
		onEvent = func(ev ChatEvent) {
			emittedAny = true
			userOnEvent(ev)
		}
	}

	runAttempt := func(thread *ThreadEntry) (ChatResult, error) {
		threadID := auth.NewUUID()
		if thread != nil && thread.ID != "" {
			threadID = thread.ID
		}
		retriedBudget := false
		composed, cerr := c.composeTurn(ctx, acct, sess, cfg, pt, thread, threadID, cfg.MaxFrameBytes)
		if cerr != nil {
			var ue *UpstreamError
			if errors.As(cerr, &ue) && ue.Kind == ErrKindTooLarge && cfg.MaxFrameBytes > 0 && !emittedAny {
				smallerLimit := int(float64(cfg.MaxFrameBytes) * 0.7)
				if smallerLimit >= 4096 {
					retriedBudget = true
					if comp2, c2err := c.composeTurn(ctx, acct, sess, cfg, pt, thread, threadID, smallerLimit); c2err == nil {
						composed, cerr = comp2, nil
					}
				}
			}
		}
		if cerr != nil {
			if thread != nil {
				c.Threads.Drop(thread.ID)
			}
			return ChatResult{}, cerr
		}

		// Stream wrapper with PII redaction and BridgeStream when client tools are declared.
		var (
			bridge      *BridgeStream
			streamedTxt strings.Builder
			textGuard   *privacyStreamRedactor
			rsnGuard    *privacyStreamRedactor
		)
		// When response_format is json_object/json_schema, text must be cleaned and validated
		// before emission, so even with tools enabled we buffer text instead of streaming raw deltas.
		streamBridge := pt.bridge && req.Stream && onEvent != nil && pt.respFmt.Type == "text"
		needRsnStream := onEvent != nil
		needTextStream := streamBridge || (onEvent != nil && !pt.bridge && pt.respFmt.Type == "text")
		initStreamGuards := func() {
			streamedTxt.Reset()
			if streamBridge {
				bridge = NewBridgeStream(pt.bridgeAllowed, func(t string) {
					streamedTxt.WriteString(t)
					onEvent(ChatEvent{Type: "text", Text: t})
				})
			} else {
				bridge = nil
			}
			if needRsnStream {
				rsnGuard = newPrivacyPolicyStreamRedactor(piiPolicy, func(t string) {
					onEvent(ChatEvent{Type: "reasoning", Text: t})
				})
			} else {
				rsnGuard = nil
			}
			if needTextStream {
				textGuard = newPrivacyPolicyStreamRedactor(piiPolicy, func(t string) {
					if streamBridge {
						bridge.Push(t)
						return
					}
					onEvent(ChatEvent{Type: "text", Text: t})
				})
			} else {
				textGuard = nil
			}
		}
		initStreamGuards()

		var emitWrapped func(ChatEvent)
		if needRsnStream || needTextStream {
			emitWrapped = func(ev ChatEvent) {
				if ev.Text == "" {
					return
				}
				if ev.Type == "reasoning" {
					if rsnGuard != nil {
						rsnGuard.Push(ev.Text)
					}
					return
				}
				if ev.Type == "text" && textGuard != nil {
					textGuard.Push(ev.Text)
				}
			}
		}

		res, werr := c.executeWSTurn(ctx, acct, sess, cfg, composed.Input, emitWrapped)
		if werr != nil && !retriedBudget {
			var ue *UpstreamError
			if errors.As(werr, &ue) && ue.Kind == ErrKindTooLarge && cfg.MaxFrameBytes > 0 && !emittedAny {
				smallerLimit := int(float64(cfg.MaxFrameBytes) * 0.7)
				if smallerLimit >= 4096 {
					if comp2, c2err := c.composeTurn(ctx, acct, sess, cfg, pt, thread, threadID, smallerLimit); c2err == nil {
						initStreamGuards()
						res, werr = c.executeWSTurn(ctx, acct, sess, cfg, comp2.Input, emitWrapped)
						if werr == nil {
							composed = comp2
						}
					}
				}
			}
		}
		if werr != nil {
			if thread != nil {
				c.Threads.Drop(thread.ID)
			}
			return ChatResult{}, werr
		}

		rsnGuard.Finish()
		textGuard.Finish()

		res.Text = piiPolicy.Scrub(res.Text)
		res.Reasoning = piiPolicy.Scrub(res.Reasoning)

		// Finalize tool calls & response_format output.
		var calls []ToolCall
		finalText := res.Text
		if pt.bridge {
			if streamBridge && bridge != nil {
				calls = bridge.Finish()
				finalText = streamedTxt.String()
			} else {
				finalText, calls = ParseClientToolCalls(res.Text, pt.bridgeAllowed)
			}
			for i := range calls {
				calls[i].Arguments = piiPolicy.Scrub(calls[i].Arguments)
			}
			if !pt.parallel && len(calls) > 1 {
				calls = calls[:1]
			}
			// tools + response_format: a plain (non tool-call) answer must still
			// satisfy the requested JSON format (both buffered and streaming paths).
			if pt.respFmt.Type != "" && pt.respFmt.Type != "text" {
				if len(calls) == 0 {
					cleaned := CleanJSONOutput(finalText)
					var obj map[string]any
					if jerr := json.Unmarshal([]byte(cleaned), &obj); jerr != nil || obj == nil {
						if thread != nil {
							c.Threads.Drop(thread.ID)
						}
						return ChatResult{}, (&UpstreamError{
							Kind:       ErrKindUpstream,
							StatusCode: 502,
							Message:    "Amazon Quick 未返回符合 response_format 的有效 JSON 对象",
						}).Normalize()
					}
					finalText = cleaned
				}
				if req.Stream && onEvent != nil && finalText != "" {
					onEvent(ChatEvent{Type: "text", Text: finalText})
				}
			}
		} else if pt.respFmt.Type != "text" {
			cleaned := CleanJSONOutput(res.Text)
			var obj map[string]any
			// "null" unmarshals into a nil map without error; json_object requires an object.
			if jerr := json.Unmarshal([]byte(cleaned), &obj); jerr != nil || obj == nil {
				if thread != nil {
					c.Threads.Drop(thread.ID)
				}
				return ChatResult{}, (&UpstreamError{
					Kind:       ErrKindUpstream,
					StatusCode: 502,
					Message:    "Amazon Quick 未返回符合 response_format 的有效 JSON 对象",
				}).Normalize()
			}
			finalText = cleaned
			if req.Stream && onEvent != nil && finalText != "" {
				onEvent(ChatEvent{Type: "text", Text: finalText})
			}
		}

		if cfg.Stateful && c.Threads != nil {
			c.Threads.Commit(threadID, acctKey, req.ConversationID, composed.CustomDigest, pt.keys)
		}

		res.Text = finalText
		res.ToolCalls = calls
		res.ThreadReused = thread != nil
		res.ThreadID = threadID
		return res, nil
	}

	var matched *ThreadEntry
	if cfg.Stateful && c.Threads != nil {
		matched = c.Threads.Match(acctKey, req.ConversationID, pt.keys)
	}
	res, err := runAttempt(matched)
	if err != nil && matched != nil && ctx.Err() == nil && !emittedAny {
		var ue *UpstreamError
		// If a resumed thread failed before any output reached the caller, retry cleanly on a
		// fresh full-history thread. Handshake, guardrail and invalid-request failures are not
		// caused by the stale thread, so retrying them only doubles cost.
		if !errors.As(err, &ue) || (ue.Kind != ErrKindHandshake && ue.Kind != ErrKindBlocked && ue.Kind != ErrKindInvalid) {
			res, err = runAttempt(nil)
		}
	}
	if err != nil {
		var ue *UpstreamError
		if errors.As(err, &ue) {
			ue.AccountUID = acct.UID
			if ue.IsRefusedByQuick() {
				if spent := c.CheckSpentAllowance(ctx, acct); spent != nil {
					ue.StatusCode = 429
					ue.Code = "rate_limit_exceeded"
					ue.RetryAfter = spent.RetryAfter
					ue.Message = "Amazon Quick " + spent.Window + " 额度已耗尽 (" + ue.Message + ")"
				}
			}
		}
		return ChatResult{}, err
	}
	return res, nil
}

// TestAccount sends a tiny diagnostic prompt ("Reply with OK") without touching sticky thread cache.
func (c *Client) TestAccount(ctx context.Context, acct *auth.Account) (ChatResult, time.Duration, error) {
	tctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cfg := c.Config()
	cfg.Stateful = false
	cfg.KeepSessions = false

	sess, err := c.sessionFromAccount(tctx, acct, cfg)
	if err != nil {
		return ChatResult{}, 0, err
	}
	input := turnInput{
		Prompt:         "Reply with OK only.",
		Slot:           "fast",
		ThreadID:       auth.NewUUID(),
		Title:          "Diagnostic Probe",
		ThinkingEffort: "off",
		WebSearch:      false,
	}
	start := time.Now()
	res, err := c.executeWSTurn(tctx, acct, sess, cfg, input, nil)
	return res, time.Since(start), err
}

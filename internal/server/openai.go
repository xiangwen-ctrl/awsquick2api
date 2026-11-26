package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"awsquick2api/internal/apikeys"
	"awsquick2api/internal/auth"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/upstream"
)

func modelOwner(id string) string {
	low := strings.ToLower(strings.TrimSpace(id))
	if strings.HasPrefix(low, "claude") {
		return "anthropic"
	}
	return "amazon-quick"
}

func formatModelObject(m upstream.ModelSpec, now int64) map[string]any {
	inMod := []string{"text"}
	if m.Caps.Image {
		inMod = append(inMod, "image")
	}
	obj := map[string]any{
		"id":                m.ID,
		"object":            "model",
		"created":           now,
		"owned_by":          modelOwner(m.ID),
		"name":              m.Display,
		"context_length":    m.ContextWindow,
		"max_output_tokens": m.MaxOutputTokens,
		"tool_call":         m.Caps.Tools,
		"reasoning":         m.Caps.Reasoning,
		"vision":            m.Caps.Image,
		"modalities": map[string]any{
			"input":  inMod,
			"output": []string{"text"},
		},
		"limit": map[string]any{
			"context": m.ContextWindow,
			"output":  m.MaxOutputTokens,
		},
	}
	if m.Caps.Reasoning {
		obj["reasoning_options"] = []map[string]any{
			{"type": "effort", "values": []string{"low", "medium", "high"}},
			{"type": "toggle"},
		}
		obj["supported_reasoning_levels"] = []map[string]string{
			{"effort": "none"},
			{"effort": "low"},
			{"effort": "medium"},
			{"effort": "high"},
		}
	}
	return obj
}

func (h *Handler) visibleModelsForRequest(r *http.Request) []upstream.ModelSpec {
	snap := h.loadSnapshot()
	cat := h.catalog()
	hasAdv := false
	if h.cfg.Pool != nil {
		hasAdv = h.cfg.Pool.HasAdvancedAccount()
	}
	models := cat.VisibleModels(
		snap.HiddenModels,
		snap.AllowedModels,
		snap.AllowlistEnabled,
		snap.ClaudeAliases,
		snap.ExposeEffortVariants,
		hasAdv,
	)
	sk := scopedKeyFromRequest(r)
	if sk == nil || len(sk.AllowedModels) == 0 {
		return models
	}
	slotID := make(map[string]string, len(cat.Specs))
	for _, s := range cat.Specs {
		slotID[strings.ToLower(strings.TrimSpace(s.Slot))] = s.ID
	}
	filtered := make([]upstream.ModelSpec, 0, len(models))
	for _, m := range models {
		cands := []string{m.ID, m.Slot}
		if base := slotID[strings.ToLower(strings.TrimSpace(m.Slot))]; base != "" &&
			strings.HasPrefix(strings.ToLower(m.ID), strings.ToLower(base)+"-") {
			cands = append(cands, base)
		}
		if apikeys.ModelAllowed(sk, cands) {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func (h *Handler) handleModels(w http.ResponseWriter, r *http.Request) {
	models := h.visibleModelsForRequest(r)
	now := time.Now().Unix()
	data := make([]map[string]any, 0, len(models))
	for _, m := range models {
		data = append(data, formatModelObject(m, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   data,
	})
}

func (h *Handler) handleModelGet(w http.ResponseWriter, r *http.Request) {
	want := strings.TrimSpace(r.PathValue("id"))
	if want == "" {
		writeOpenAIError(w, http.StatusNotFound, "model_not_found", "model not found")
		return
	}
	models := h.visibleModelsForRequest(r)
	now := time.Now().Unix()
	for _, m := range models {
		if strings.EqualFold(m.ID, want) {
			writeJSON(w, http.StatusOK, formatModelObject(m, now))
			return
		}
	}
	writeOpenAIError(w, http.StatusNotFound, "model_not_found", fmt.Sprintf("model %q not found", want))
}

func (h *Handler) handleOpenAIChat(w http.ResponseWriter, r *http.Request) {
	raw, ok := h.readBodyLimited(w, r, writeOpenAIError)
	if !ok {
		return
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "Invalid JSON body: "+err.Error())
		return
	}
	if nVal, ok := body["n"].(float64); ok && nVal > 1 {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "n > 1 is not supported")
		return
	}

	reqModel, _ := body["model"].(string)
	streamFlag, _ := body["stream"].(bool)
	includeUsage := false
	if so, ok := body["stream_options"].(map[string]any); ok {
		includeUsage, _ = so["include_usage"].(bool)
	}

	msgs, err := extractMapSlice(body["messages"])
	if err != nil || len(msgs) == 0 {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "messages must be a non-empty array")
		return
	}

	reqEffort, _ := body["reasoning_effort"].(string)
	if reqEffort == "" {
		if rObj, ok := body["reasoning"].(map[string]any); ok {
			reqEffort, _ = rObj["effort"].(string)
		}
	}

	var parallelPtr *bool
	if p, ok := body["parallel_tool_calls"].(bool); ok {
		parallelPtr = &p
	}
	var webSearchPtr *bool
	if ws, ok := body["web_search_enabled"].(bool); ok {
		webSearchPtr = &ws
	}

	toolChoice := body["tool_choice"]
	if toolChoice == nil {
		toolChoice = body["function_call"]
	}
	legacyFunctions := body["functions"] != nil && body["tools"] == nil

	convID := upstream.ConversationIDFromHeaders(r.Header)
	if convID == "" {
		if c, ok := body["conversation_id"].(string); ok {
			convID = strings.TrimSpace(c)
		}
	}

	maxOutput, err := outputTokenLimit(body, "max_completion_tokens", "max_tokens")
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	upReq := upstream.ChatRequest{
		MaxOutputTokens:   maxOutput,
		Model:             reqModel,
		ThinkingEffort:    reqEffort,
		Messages:          msgs,
		Tools:             body["tools"],
		Functions:         body["functions"],
		ToolChoice:        toolChoice,
		ParallelToolCalls: parallelPtr,
		ResponseFormat:    body["response_format"],
		WebSearch:         webSearchPtr,
		ConversationID:    convID,
		Stream:            streamFlag,
	}

	cmplID := "chatcmpl-" + strings.ReplaceAll(auth.NewUUID(), "-", "")
	created := time.Now().Unix()

	if !streamFlag {
		out, ue := h.runChatTurn(r.Context(), r, "/v1/chat/completions", reqModel, upReq, nil, nil)
		if ue != nil {
			if ue.StatusCode != 499 {
				writeUpstreamErrorWithRetryAfter(w, ue, false)
			}
			return
		}
		setGatewayResponseHeaders(w, out.ReqID, out.Account, out.Result.Usage.ResolvedModel, out.Result.ThreadReused)
		writeOpenAINonStreamResponse(w, cmplID, created, reqModel, out.Result, legacyFunctions)
		return
	}

	// Streaming SSE mode.
	flusher, _ := w.(http.Flusher)
	var (
		writeMu   sync.Mutex
		started   bool
		keepalive *sseKeepalive
	)
	// Stop (and wait for) the heartbeat before any terminal write and on every return.
	defer func() { keepalive.Stop() }()
	writeSSEChunk := func(payload any) {
		b, err := json.Marshal(payload)
		if err != nil {
			return
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	baseChunk := func(delta map[string]any, finish any) map[string]any {
		return map[string]any{
			"id":      cmplID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   reqModel,
			"choices": []map[string]any{
				{
					"index":         0,
					"delta":         delta,
					"finish_reason": finish,
				},
			},
		}
	}

	onStart := func(acct *auth.Account, reqID string) {
		writeMu.Lock()
		if started {
			writeMu.Unlock()
			return
		}
		started = true
		setGatewayResponseHeaders(w, reqID, acct, "", false)
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		writeMu.Unlock()

		writeSSEChunk(baseChunk(map[string]any{"role": "assistant"}, nil))
		keepalive = startSSEKeepalive(r.Context(), sseKeepaliveInterval, func() {
			writeMu.Lock()
			defer writeMu.Unlock()
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		})
	}

	onEvent := func(ev upstream.ChatEvent) {
		switch ev.Type {
		case "reasoning":
			writeSSEChunk(baseChunk(map[string]any{"reasoning_content": ev.Text}, nil))
		case "text":
			writeSSEChunk(baseChunk(map[string]any{"content": ev.Text}, nil))
		}
	}

	out, ue := h.runChatTurn(r.Context(), r, "/v1/chat/completions", reqModel, upReq, onStart, onEvent)
	keepalive.Stop()
	if ue != nil {
		if ue.StatusCode == 499 {
			return
		}
		writeMu.Lock()
		wasStarted := started
		writeMu.Unlock()
		if !wasStarted {
			writeUpstreamErrorWithRetryAfter(w, ue, false)
			return
		}
		writeSSEChunk(map[string]any{
			"error": map[string]any{
				"message": reqlog.ScrubCredentials(ue.Error()),
				"type":    ue.Code,
				"code":    ue.Code,
			},
		})
		writeMu.Lock()
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		writeMu.Unlock()
		return
	}

	finishReason := "stop"
	if out.Result.OutputLimitReached {
		finishReason = "length"
	}
	if len(out.Result.ToolCalls) > 0 {
		if legacyFunctions {
			tc := out.Result.ToolCalls[0]
			writeSSEChunk(baseChunk(map[string]any{
				"function_call": map[string]any{
					"name":      tc.Name,
					"arguments": tc.Arguments,
				},
			}, nil))
			finishReason = "function_call"
		} else {
			for i, tc := range out.Result.ToolCalls {
				writeSSEChunk(baseChunk(map[string]any{
					"tool_calls": []map[string]any{
						{
							"index": i,
							"id":    tc.ID,
							"type":  "function",
							"function": map[string]any{
								"name":      tc.Name,
								"arguments": tc.Arguments,
							},
						},
					},
				}, nil))
			}
			finishReason = "tool_calls"
		}
	}

	writeSSEChunk(baseChunk(map[string]any{}, finishReason))
	if includeUsage {
		writeSSEChunk(map[string]any{
			"id":      cmplID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   reqModel,
			"choices": []any{},
			"usage":   formatOpenAIUsage(out.Result.Usage),
		})
	}
	writeMu.Lock()
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
	writeMu.Unlock()
}

func writeOpenAINonStreamResponse(w http.ResponseWriter, id string, created int64, model string, res upstream.ChatResult, legacyFunctions bool) {
	msg := map[string]any{
		"role": "assistant",
	}
	if strings.TrimSpace(res.Text) != "" {
		msg["content"] = res.Text
	} else {
		msg["content"] = nil
	}
	if res.Reasoning != "" {
		msg["reasoning_content"] = res.Reasoning
	}
	finishReason := "stop"
	if res.OutputLimitReached {
		finishReason = "length"
		if msg["content"] == nil {
			msg["content"] = ""
		}
	}
	if len(res.ToolCalls) > 0 {
		if legacyFunctions {
			tc := res.ToolCalls[0]
			msg["function_call"] = map[string]any{
				"name":      tc.Name,
				"arguments": tc.Arguments,
			}
			finishReason = "function_call"
		} else {
			tcs := make([]map[string]any, 0, len(res.ToolCalls))
			for _, tc := range res.ToolCalls {
				tcs = append(tcs, map[string]any{
					"id":   tc.ID,
					"type": "function",
					"function": map[string]any{
						"name":      tc.Name,
						"arguments": tc.Arguments,
					},
				})
			}
			msg["tool_calls"] = tcs
			finishReason = "tool_calls"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []map[string]any{
			{
				"index":         0,
				"message":       msg,
				"finish_reason": finishReason,
			},
		},
		"usage": formatOpenAIUsage(res.Usage),
	})
}

func formatOpenAIUsage(u upstream.Usage) map[string]any {
	total := u.TotalTokens
	if total == 0 {
		total = u.PromptTokens + u.CompletionTokens
	}
	m := map[string]any{
		"prompt_tokens":     u.PromptTokens,
		"completion_tokens": u.CompletionTokens,
		"total_tokens":      total,
	}
	if u.CacheReadTokens > 0 {
		m["prompt_tokens_details"] = map[string]any{
			"cached_tokens": u.CacheReadTokens,
		}
	}
	return m
}

func extractMapSlice(raw any) ([]map[string]any, error) {
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("expected array")
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/upstream"
)

const (
	imageTokenEstimate    = 1600
	anthropicPingInterval = 15 * time.Second
)

func (h *Handler) handleAnthropicCountTokens(w http.ResponseWriter, r *http.Request) {
	raw, ok := h.readBodyLimited(w, r, writeAnthropicError)
	if !ok {
		return
	}
	var req map[string]any
	if err := json.Unmarshal(raw, &req); err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "Invalid JSON: "+err.Error())
		return
	}
	if msgs, ok := req["messages"].([]any); !ok || len(msgs) == 0 {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "messages: field required and must be a non-empty array")
		return
	}
	runes, images := estimateAnthropicPayload(req)
	est := max(runes/3+images*imageTokenEstimate, 1)
	w.Header().Set("X-Quick-Usage", "estimated")
	writeJSON(w, http.StatusOK, map[string]any{
		"input_tokens": est,
	})
}

func estimateAnthropicPayload(req map[string]any) (runes int, images int) {
	if sys, ok := req["system"]; ok {
		r, img := estimateAnthropicValue(sys)
		runes += r
		images += img
	}
	if msgs, ok := req["messages"]; ok {
		r, img := estimateAnthropicValue(msgs)
		runes += r
		images += img
	}
	if tools, ok := req["tools"]; ok {
		if b, err := json.Marshal(tools); err == nil {
			runes += utf8.RuneCount(b)
		}
	}
	if tc, ok := req["tool_choice"]; ok {
		if b, err := json.Marshal(tc); err == nil {
			runes += utf8.RuneCount(b)
		}
	}
	return runes, images
}

func estimateAnthropicValue(v any) (runes int, images int) {
	switch x := v.(type) {
	case string:
		return utf8.RuneCountInString(x), 0
	case []any:
		for _, item := range x {
			r, img := estimateAnthropicValue(item)
			runes += r
			images += img
		}
		return runes, images
	case map[string]any:
		if typ, _ := x["type"].(string); typ == "image" || typ == "image_url" {
			return 0, 1
		}
		for k, val := range x {
			switch k {
			case "type", "role", "id", "tool_use_id", "cache_control", "media_type":
				continue
			case "text", "thinking", "name":
				if s, ok := val.(string); ok {
					runes += utf8.RuneCountInString(s)
				}
			case "content":
				r, img := estimateAnthropicValue(val)
				runes += r
				images += img
			case "input":
				if b, err := json.Marshal(val); err == nil {
					runes += utf8.RuneCount(b)
				}
			}
		}
		return runes, images
	default:
		return 0, 0
	}
}

func (h *Handler) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	raw, ok := h.readBodyLimited(w, r, writeAnthropicError)
	if !ok {
		return
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "Invalid JSON: "+err.Error())
		return
	}

	reqModel, _ := body["model"].(string)
	streamFlag, _ := body["stream"].(bool)

	upReq, err := anthropicToChatRequest(body, r.Header)
	if err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	upReq.Stream = streamFlag

	msgID := "msg_" + strings.ReplaceAll(auth.NewUUID(), "-", "")

	if !streamFlag {
		out, ue := h.runChatTurn(r.Context(), r, "/v1/messages", reqModel, upReq, nil, nil)
		if ue != nil {
			if ue.StatusCode != 499 {
				writeUpstreamErrorWithRetryAfter(w, ue, true)
			}
			return
		}
		setGatewayResponseHeaders(w, out.ReqID, out.Account, out.Result.Usage.ResolvedModel, out.Result.ThreadReused)
		writeAnthropicNonStream(w, msgID, reqModel, out.Result)
		return
	}

	flusher, _ := w.(http.Flusher)
	var (
		writeMu   sync.Mutex
		started   bool
		blockIdx  int
		openBlock string // "" | "thinking" | "text"
		pinger    *sseKeepalive
	)
	// stopPing blocks until the ping goroutine has exited, so no "ping" event can be
	// written after message_stop or after ServeHTTP returns (e.g. on 499).
	stopPing := func() { pinger.Stop() }
	defer stopPing()

	writeEvent := func(eventName string, payload any) {
		b, err := json.Marshal(payload)
		if err != nil {
			return
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventName, b)
		if flusher != nil {
			flusher.Flush()
		}
	}

	closeOpenBlock := func() {
		if openBlock == "" {
			return
		}
		idx := blockIdx
		openBlock = ""
		blockIdx++
		writeEvent("content_block_stop", map[string]any{
			"type":  "content_block_stop",
			"index": idx,
		})
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

		writeEvent("message_start", map[string]any{
			"type": "message_start",
			"message": map[string]any{
				"id":            msgID,
				"type":          "message",
				"role":          "assistant",
				"model":         reqModel,
				"content":       []any{},
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage": map[string]any{
					"input_tokens":  0,
					"output_tokens": 0,
				},
			},
		})

		pinger = startSSEKeepalive(r.Context(), anthropicPingInterval, func() {
			writeEvent("ping", map[string]any{"type": "ping"})
		})
	}

	onEvent := func(ev upstream.ChatEvent) {
		switch ev.Type {
		case "reasoning":
			if openBlock != "thinking" {
				closeOpenBlock()
				openBlock = "thinking"
				writeEvent("content_block_start", map[string]any{
					"type":  "content_block_start",
					"index": blockIdx,
					"content_block": map[string]any{
						"type":     "thinking",
						"thinking": "",
					},
				})
			}
			writeEvent("content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": blockIdx,
				"delta": map[string]any{
					"type":     "thinking_delta",
					"thinking": ev.Text,
				},
			})

		case "text":
			if openBlock != "text" {
				closeOpenBlock()
				openBlock = "text"
				writeEvent("content_block_start", map[string]any{
					"type":  "content_block_start",
					"index": blockIdx,
					"content_block": map[string]any{
						"type": "text",
						"text": "",
					},
				})
			}
			writeEvent("content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": blockIdx,
				"delta": map[string]any{
					"type": "text_delta",
					"text": ev.Text,
				},
			})
		}
	}

	out, ue := h.runChatTurn(r.Context(), r, "/v1/messages", reqModel, upReq, onStart, onEvent)
	stopPing()
	if ue != nil {
		if ue.StatusCode == 499 {
			return
		}
		writeMu.Lock()
		wasStarted := started
		writeMu.Unlock()
		if !wasStarted {
			writeUpstreamErrorWithRetryAfter(w, ue, true)
			return
		}
		writeEvent("error", map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "api_error",
				"message": reqlog.ScrubCredentials(ue.Error()),
			},
		})
		return
	}

	closeOpenBlock()

	stopReason := "end_turn"
	if len(out.Result.ToolCalls) > 0 {
		stopReason = "tool_use"
		for _, tc := range out.Result.ToolCalls {
			idx := blockIdx
			blockIdx++
			writeEvent("content_block_start", map[string]any{
				"type":  "content_block_start",
				"index": idx,
				"content_block": map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": map[string]any{},
				},
			})
			args := strings.TrimSpace(tc.Arguments)
			var objCheck map[string]any
			if args == "" || json.Unmarshal([]byte(args), &objCheck) != nil || objCheck == nil {
				args = "{}"
			}
			writeEvent("content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": idx,
				"delta": map[string]any{
					"type":         "input_json_delta",
					"partial_json": args,
				},
			})
			writeEvent("content_block_stop", map[string]any{
				"type":  "content_block_stop",
				"index": idx,
			})
		}
	}

	usage := formatAnthropicUsage(out.Result.Usage)
	writeEvent("message_delta", map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   stopReason,
			"stop_sequence": nil,
		},
		"usage": usage,
	})
	writeEvent("message_stop", map[string]any{
		"type": "message_stop",
	})
}

func writeAnthropicNonStream(w http.ResponseWriter, msgID, model string, res upstream.ChatResult) {
	blocks := make([]map[string]any, 0, 2+len(res.ToolCalls))
	if res.Reasoning != "" {
		blocks = append(blocks, map[string]any{
			"type":     "thinking",
			"thinking": res.Reasoning,
		})
	}
	if strings.TrimSpace(res.Text) != "" {
		blocks = append(blocks, map[string]any{
			"type": "text",
			"text": res.Text,
		})
	}
	stopReason := "end_turn"
	if len(res.ToolCalls) > 0 {
		stopReason = "tool_use"
		for _, tc := range res.ToolCalls {
			var inputObj map[string]any
			if err := json.Unmarshal([]byte(tc.Arguments), &inputObj); err != nil || inputObj == nil {
				inputObj = map[string]any{}
			}
			blocks = append(blocks, map[string]any{
				"type":  "tool_use",
				"id":    tc.ID,
				"name":  tc.Name,
				"input": inputObj,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":            msgID,
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"content":       blocks,
		"stop_reason":   stopReason,
		"stop_sequence": nil,
		"usage":         formatAnthropicUsage(res.Usage),
	})
}

func formatAnthropicUsage(u upstream.Usage) map[string]any {
	inTok := u.PromptTokens
	if u.CacheReadTokens > 0 || u.CacheWriteTokens > 0 {
		nonCached := u.PromptTokens - u.CacheReadTokens - u.CacheWriteTokens
		if nonCached < 0 {
			nonCached = 0
		}
		inTok = nonCached
	}
	m := map[string]any{
		"input_tokens":  inTok,
		"output_tokens": u.CompletionTokens,
	}
	if u.CacheReadTokens > 0 {
		m["cache_read_input_tokens"] = u.CacheReadTokens
	}
	if u.CacheWriteTokens > 0 {
		m["cache_creation_input_tokens"] = u.CacheWriteTokens
	}
	return m
}

func anthropicToChatRequest(body map[string]any, headers http.Header) (upstream.ChatRequest, error) {
	reqModel, _ := body["model"].(string)
	var msgs []map[string]any

	// Translate system prompt (string or array of blocks).
	if sysRaw, ok := body["system"]; ok && sysRaw != nil {
		sysText := flattenAnthropicText(sysRaw)
		if strings.TrimSpace(sysText) != "" {
			msgs = append(msgs, map[string]any{
				"role":    "system",
				"content": sysText,
			})
		}
	}

	rawMsgs, ok := body["messages"].([]any)
	if !ok || len(rawMsgs) == 0 {
		return upstream.ChatRequest{}, fmt.Errorf("messages must be a non-empty array")
	}
	for _, item := range rawMsgs {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role, _ := m["role"].(string)
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "" {
			role = "user"
		}
		content := m["content"]
		switch c := content.(type) {
		case string:
			msgs = append(msgs, map[string]any{"role": role, "content": c})
		case []any:
			if role == "assistant" {
				var textParts []string
				var toolCalls []any
				for _, b := range c {
					bm, ok := b.(map[string]any)
					if !ok {
						continue
					}
					switch bm["type"] {
					case "text":
						if t, ok := bm["text"].(string); ok {
							textParts = append(textParts, t)
						}
					case "tool_use":
						id, _ := bm["id"].(string)
						if id == "" {
							id = upstream.NewCallID()
						}
						name, _ := bm["name"].(string)
						toolCalls = append(toolCalls, map[string]any{
							"id":   id,
							"type": "function",
							"function": map[string]any{
								"name":      name,
								"arguments": upstream.ArgumentString(bm["input"]),
							},
						})
					}
				}
				asst := map[string]any{"role": "assistant"}
				if len(textParts) > 0 {
					asst["content"] = strings.Join(textParts, "\n")
				}
				if len(toolCalls) > 0 {
					asst["tool_calls"] = toolCalls
				}
				if asst["content"] != nil || len(toolCalls) > 0 {
					msgs = append(msgs, asst)
				}
			} else {
				// User message may contain mixed tool_result blocks + user text/image blocks.
				var userParts []any
				flushUser := func() {
					if len(userParts) > 0 {
						msgs = append(msgs, map[string]any{"role": role, "content": userParts})
						userParts = nil
					}
				}
				for _, b := range c {
					bm, ok := b.(map[string]any)
					if !ok {
						continue
					}
					switch bm["type"] {
					case "tool_result":
						flushUser()
						tcID, _ := bm["tool_use_id"].(string)
						resContent := convertAnthropicToolResultContent(bm["content"])
						toolMsg := map[string]any{
							"role":         "tool",
							"tool_call_id": tcID,
							"content":      resContent,
						}
						if isErr, _ := bm["is_error"].(bool); isErr {
							toolMsg["is_error"] = true
						}
						msgs = append(msgs, toolMsg)
					case "text":
						if t, ok := bm["text"].(string); ok {
							userParts = append(userParts, map[string]any{"type": "text", "text": t})
						}
					case "image":
						if imgPart := convertAnthropicImageBlock(bm); imgPart != nil {
							userParts = append(userParts, imgPart)
						}
					}
				}
				flushUser()
			}
		}
	}

	// Translate tools.
	var oaTools []any
	if rawTools, ok := body["tools"].([]any); ok {
		for _, item := range rawTools {
			tm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			// Skip Anthropic server-side built-in tools (web_search_*, web_fetch_*,
			// code_execution_*, ...): they are typed, carry no input_schema, and are
			// executed by Anthropic itself, so they must not be bridged as client tools.
			if typ, _ := tm["type"].(string); typ != "" && typ != "custom" && tm["input_schema"] == nil {
				continue
			}
			name, _ := tm["name"].(string)
			if strings.TrimSpace(name) == "" {
				continue
			}
			fn := map[string]any{"name": name}
			if desc, ok := tm["description"].(string); ok && desc != "" {
				fn["description"] = desc
			}
			if schema, ok := tm["input_schema"]; ok && schema != nil {
				fn["parameters"] = schema
			}
			oaTools = append(oaTools, map[string]any{
				"type":     "function",
				"function": fn,
			})
		}
	}

	// Translate tool_choice and parallel_tool_calls.
	var toolChoice any
	var parallelPtr *bool
	if tc, ok := body["tool_choice"].(map[string]any); ok {
		if dis, ok := tc["disable_parallel_tool_use"].(bool); ok && dis {
			f := false
			parallelPtr = &f
		}
		switch tc["type"] {
		case "auto":
			toolChoice = "auto"
		case "any":
			toolChoice = "required"
		case "none":
			toolChoice = "none"
		case "tool":
			if name, _ := tc["name"].(string); name != "" {
				toolChoice = map[string]any{"type": "function", "function": map[string]any{"name": name}}
			}
		}
	}

	// Translate thinking / output_config.effort.
	effort := ""
	if oc, ok := body["output_config"].(map[string]any); ok {
		if e, ok := oc["effort"].(string); ok && strings.TrimSpace(e) != "" {
			effort = e
		}
	}
	if th, ok := body["thinking"].(map[string]any); ok {
		switch strings.ToLower(strings.TrimSpace(fmt.Sprint(th["type"]))) {
		case "disabled":
			effort = "off"
		case "adaptive":
			if effort == "" {
				effort = "high"
			}
		case "enabled":
			if effort == "" {
				if bt, ok := th["budget_tokens"].(float64); ok && bt > 0 {
					effort = upstream.EffortFromBudgetTokens(int(bt))
				} else {
					effort = "medium"
				}
			}
		}
	}

	convID := upstream.ConversationIDFromHeaders(headers)
	if convID == "" {
		if meta, ok := body["metadata"].(map[string]any); ok {
			if uid, ok := meta["user_id"].(string); ok && strings.TrimSpace(uid) != "" {
				convID = strings.TrimSpace(uid)
			}
		}
	}

	return upstream.ChatRequest{
		Model:             reqModel,
		ThinkingEffort:    effort,
		Messages:          msgs,
		Tools:             oaTools,
		ToolChoice:        toolChoice,
		ParallelToolCalls: parallelPtr,
		ConversationID:    convID,
	}, nil
}

func flattenAnthropicText(raw any) string {
	switch x := raw.(type) {
	case string:
		return x
	case []any:
		var parts []string
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				if t, ok := m["text"].(string); ok && strings.TrimSpace(t) != "" {
					parts = append(parts, t)
				}
			}
		}
		return strings.Join(parts, "\n\n")
	default:
		return ""
	}
}

func convertAnthropicImageBlock(bm map[string]any) map[string]any {
	src, ok := bm["source"].(map[string]any)
	if !ok {
		return nil
	}
	if src["type"] == "base64" {
		mt, _ := src["media_type"].(string)
		data, _ := src["data"].(string)
		if mt != "" && data != "" {
			return map[string]any{
				"type": "image_url",
				"image_url": map[string]any{
					"url": "data:" + mt + ";base64," + data,
				},
			}
		}
	}
	if src["type"] == "url" {
		if u, ok := src["url"].(string); ok && u != "" {
			return map[string]any{
				"type": "image_url",
				"image_url": map[string]any{
					"url": u,
				},
			}
		}
	}
	return nil
}

func convertAnthropicToolResultContent(raw any) any {
	switch x := raw.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		var out []any
		for _, item := range x {
			bm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			switch bm["type"] {
			case "text":
				if t, ok := bm["text"].(string); ok {
					out = append(out, map[string]any{"type": "text", "text": t})
				}
			case "image":
				if img := convertAnthropicImageBlock(bm); img != nil {
					out = append(out, img)
				}
			}
		}
		if len(out) == 0 {
			return ""
		}
		return out
	default:
		b, _ := json.Marshal(raw)
		return string(b)
	}
}

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/upstream"
)

func (h *Handler) handleResponsesWSUnsupported(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Upgrade", "HTTP/1.1")
	writeOpenAIError(w, http.StatusUpgradeRequired, "websocket_not_supported",
		"WebSocket transport for /v1/responses is not enabled; please fall back to POST /v1/responses over HTTP")
}

func (h *Handler) handleResponses(w http.ResponseWriter, r *http.Request) {
	raw, ok := h.readBodyLimited(w, r, writeOpenAIError)
	if !ok {
		return
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "Invalid JSON: "+err.Error())
		return
	}

	reqModel, _ := body["model"].(string)
	streamFlag, _ := body["stream"].(bool)

	upReq, customTools, err := responsesToChatRequest(body, r.Header)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	upReq.Stream = streamFlag

	respID := "resp_" + strings.ReplaceAll(auth.NewUUID(), "-", "")
	created := time.Now().Unix()

	if !streamFlag {
		out, ue := h.runChatTurn(r.Context(), r, "/v1/responses", reqModel, upReq, nil, nil)
		if ue != nil {
			if ue.StatusCode != 499 {
				writeUpstreamErrorWithRetryAfter(w, ue, false)
			}
			return
		}
		setGatewayResponseHeaders(w, out.ReqID, out.Account, out.Result.Usage.ResolvedModel, out.Result.ThreadReused)
		writeJSON(w, http.StatusOK, buildResponsesObject(respID, created, reqModel, "completed", out.Result, customTools, nil))
		return
	}

	flusher, _ := w.(http.Flusher)
	var (
		writeMu      sync.Mutex
		keepalive    *sseKeepalive
		itemIDs      responseItemIDs
		started      bool
		seq          int
		outIdx       int
		rsnOpened    bool
		rsnItemID    string
		rsnIdx       int
		msgOpened    bool
		msgItemID    string
		msgIdx       int
		textAcc      strings.Builder
		reasoningAcc strings.Builder
	)
	defer func() { keepalive.Stop() }()

	sendEvent := func(eventName string, payload map[string]any) {
		writeMu.Lock()
		defer writeMu.Unlock()
		payload["type"] = eventName
		payload["sequence_number"] = seq
		seq++
		b, err := json.Marshal(payload)
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventName, b)
		if flusher != nil {
			flusher.Flush()
		}
	}

	closeReasoning := func() {
		if !rsnOpened {
			return
		}
		rsnOpened = false
		full := reasoningAcc.String()
		sendEvent("response.reasoning_summary_text.done", map[string]any{
			"item_id":       rsnItemID,
			"output_index":  rsnIdx,
			"summary_index": 0,
			"text":          full,
		})
		sendEvent("response.reasoning_summary_part.done", map[string]any{
			"item_id":       rsnItemID,
			"output_index":  rsnIdx,
			"summary_index": 0,
			"part":          map[string]any{"type": "summary_text", "text": full},
		})
		sendEvent("response.output_item.done", map[string]any{
			"output_index": rsnIdx,
			"item": map[string]any{
				"id":      rsnItemID,
				"type":    "reasoning",
				"status":  "completed",
				"summary": []map[string]any{{"type": "summary_text", "text": full}},
			},
		})
	}

	closeMessage := func() {
		if !msgOpened {
			return
		}
		msgOpened = false
		full := textAcc.String()
		sendEvent("response.output_text.done", map[string]any{
			"item_id":       msgItemID,
			"output_index":  msgIdx,
			"content_index": 0,
			"text":          full,
		})
		sendEvent("response.content_part.done", map[string]any{
			"item_id":       msgItemID,
			"output_index":  msgIdx,
			"content_index": 0,
			"part": map[string]any{
				"type":        "output_text",
				"text":        full,
				"annotations": []any{},
			},
		})
		sendEvent("response.output_item.done", map[string]any{
			"output_index": msgIdx,
			"item": map[string]any{
				"id":     msgItemID,
				"type":   "message",
				"status": "completed",
				"role":   "assistant",
				"content": []map[string]any{
					{"type": "output_text", "text": full, "annotations": []any{}},
				},
			},
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

		baseResp := map[string]any{
			"id":         respID,
			"object":     "response",
			"created_at": created,
			"status":     "in_progress",
			"model":      reqModel,
			"output":     []any{},
		}
		sendEvent("response.created", map[string]any{"response": baseResp})
		sendEvent("response.in_progress", map[string]any{"response": baseResp})
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
			if !rsnOpened {
				rsnOpened = true
				rsnIdx = outIdx
				outIdx++
				rsnItemID = "rs_" + strings.ReplaceAll(auth.NewUUID(), "-", "")
				if itemIDs.Reasoning == "" {
					itemIDs.Reasoning = rsnItemID
				}
				sendEvent("response.output_item.added", map[string]any{
					"output_index": rsnIdx,
					"item": map[string]any{
						"id":      rsnItemID,
						"type":    "reasoning",
						"status":  "in_progress",
						"summary": []any{},
					},
				})
				sendEvent("response.reasoning_summary_part.added", map[string]any{
					"item_id":       rsnItemID,
					"output_index":  rsnIdx,
					"summary_index": 0,
					"part":          map[string]any{"type": "summary_text", "text": ""},
				})
			}
			reasoningAcc.WriteString(ev.Text)
			sendEvent("response.reasoning_summary_text.delta", map[string]any{
				"item_id":       rsnItemID,
				"output_index":  rsnIdx,
				"summary_index": 0,
				"delta":         ev.Text,
			})

		case "text":
			if rsnOpened {
				closeReasoning()
			}
			if !msgOpened {
				msgOpened = true
				msgIdx = outIdx
				outIdx++
				msgItemID = "msg_" + strings.ReplaceAll(auth.NewUUID(), "-", "")
				if itemIDs.Message == "" {
					itemIDs.Message = msgItemID
				}
				sendEvent("response.output_item.added", map[string]any{
					"output_index": msgIdx,
					"item": map[string]any{
						"id":      msgItemID,
						"type":    "message",
						"status":  "in_progress",
						"role":    "assistant",
						"content": []any{},
					},
				})
				sendEvent("response.content_part.added", map[string]any{
					"item_id":       msgItemID,
					"output_index":  msgIdx,
					"content_index": 0,
					"part": map[string]any{
						"type":        "output_text",
						"text":        "",
						"annotations": []any{},
					},
				})
			}
			textAcc.WriteString(ev.Text)
			sendEvent("response.output_text.delta", map[string]any{
				"item_id":       msgItemID,
				"output_index":  msgIdx,
				"content_index": 0,
				"delta":         ev.Text,
			})
		}
	}

	out, ue := h.runChatTurn(r.Context(), r, "/v1/responses", reqModel, upReq, onStart, onEvent)
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
		sendEvent("response.failed", map[string]any{
			"response": map[string]any{
				"id":         respID,
				"object":     "response",
				"created_at": created,
				"status":     "failed",
				"model":      reqModel,
				"error": map[string]any{
					"code":    ue.Code,
					"message": reqlog.ScrubCredentials(ue.Error()),
				},
			},
		})
		return
	}

	closeReasoning()
	closeMessage()

	for _, tc := range out.Result.ToolCalls {
		idx := outIdx
		outIdx++
		itemID := "fc_" + strings.ReplaceAll(auth.NewUUID(), "-", "")
		itemIDs.Calls = append(itemIDs.Calls, itemID)
		if customTools[tc.Name] {
			inputStr := extractCustomToolInput(tc.Arguments)
			item := map[string]any{
				"id":      itemID,
				"type":    "custom_tool_call",
				"status":  "completed",
				"call_id": tc.ID,
				"name":    tc.Name,
				"input":   inputStr,
			}
			sendEvent("response.output_item.added", map[string]any{
				"output_index": idx,
				"item":         map[string]any{"id": itemID, "type": "custom_tool_call", "status": "in_progress", "call_id": tc.ID, "name": tc.Name, "input": ""},
			})
			sendEvent("response.custom_tool_call_input.delta", map[string]any{
				"item_id":      itemID,
				"output_index": idx,
				"delta":        inputStr,
			})
			sendEvent("response.custom_tool_call_input.done", map[string]any{
				"item_id":      itemID,
				"output_index": idx,
				"input":        inputStr,
			})
			sendEvent("response.output_item.done", map[string]any{
				"output_index": idx,
				"item":         item,
			})
			continue
		}

		args := strings.TrimSpace(tc.Arguments)
		if args == "" {
			args = "{}"
		}
		sendEvent("response.output_item.added", map[string]any{
			"output_index": idx,
			"item": map[string]any{
				"id":        itemID,
				"type":      "function_call",
				"status":    "in_progress",
				"call_id":   tc.ID,
				"name":      tc.Name,
				"arguments": "",
			},
		})
		sendEvent("response.function_call_arguments.delta", map[string]any{
			"item_id":      itemID,
			"output_index": idx,
			"delta":        args,
		})
		sendEvent("response.function_call_arguments.done", map[string]any{
			"item_id":      itemID,
			"output_index": idx,
			"arguments":    args,
		})
		sendEvent("response.output_item.done", map[string]any{
			"output_index": idx,
			"item": map[string]any{
				"id":        itemID,
				"type":      "function_call",
				"status":    "completed",
				"call_id":   tc.ID,
				"name":      tc.Name,
				"arguments": args,
			},
		})
	}

	sendEvent("response.completed", map[string]any{
		"response": buildResponsesObject(respID, created, reqModel, "completed", out.Result, customTools, &itemIDs),
	})
}

// responseItemIDs carries the output item IDs already announced on the SSE stream so
// that response.completed reports the same IDs instead of minting fresh ones.
type responseItemIDs struct {
	Reasoning string
	Message   string
	Calls     []string
}

func newItemID(prefix string) string {
	return prefix + strings.ReplaceAll(auth.NewUUID(), "-", "")
}

func buildResponsesObject(respID string, created int64, model, status string, res upstream.ChatResult, customTools map[string]bool, ids *responseItemIDs) map[string]any {
	if ids == nil {
		ids = &responseItemIDs{}
	}
	pick := func(existing, prefix string) string {
		if existing != "" {
			return existing
		}
		return newItemID(prefix)
	}
	output := make([]map[string]any, 0, 2+len(res.ToolCalls))
	if res.Reasoning != "" {
		output = append(output, map[string]any{
			"id":      pick(ids.Reasoning, "rs_"),
			"type":    "reasoning",
			"status":  "completed",
			"summary": []map[string]any{{"type": "summary_text", "text": res.Reasoning}},
		})
	}
	if strings.TrimSpace(res.Text) != "" {
		output = append(output, map[string]any{
			"id":     pick(ids.Message, "msg_"),
			"type":   "message",
			"status": "completed",
			"role":   "assistant",
			"content": []map[string]any{
				{
					"type":        "output_text",
					"text":        res.Text,
					"annotations": []any{},
				},
			},
		})
	}
	for i, tc := range res.ToolCalls {
		callItemID := ""
		if i < len(ids.Calls) {
			callItemID = ids.Calls[i]
		}
		callItemID = pick(callItemID, "fc_")
		if customTools[tc.Name] {
			output = append(output, map[string]any{
				"id":      callItemID,
				"type":    "custom_tool_call",
				"status":  "completed",
				"call_id": tc.ID,
				"name":    tc.Name,
				"input":   extractCustomToolInput(tc.Arguments),
			})
		} else {
			args := strings.TrimSpace(tc.Arguments)
			if args == "" {
				args = "{}"
			}
			output = append(output, map[string]any{
				"id":        callItemID,
				"type":      "function_call",
				"status":    "completed",
				"call_id":   tc.ID,
				"name":      tc.Name,
				"arguments": args,
			})
		}
	}
	total := res.Usage.TotalTokens
	if total == 0 {
		total = res.Usage.PromptTokens + res.Usage.CompletionTokens
	}
	usageMap := map[string]any{
		"input_tokens":  res.Usage.PromptTokens,
		"output_tokens": res.Usage.CompletionTokens,
		"total_tokens":  total,
	}
	if res.Usage.CacheReadTokens > 0 {
		usageMap["input_tokens_details"] = map[string]any{"cached_tokens": res.Usage.CacheReadTokens}
	}
	return map[string]any{
		"id":          respID,
		"object":      "response",
		"created_at":  created,
		"status":      status,
		"model":       model,
		"output":      output,
		"output_text": res.Text,
		"usage":       usageMap,
	}
}

func extractCustomToolInput(argsJSON string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &m); err == nil {
		if s, ok := m["input"].(string); ok {
			return s
		}
	}
	return argsJSON
}

// customToolInputString converts a custom_tool_call "input" value to its raw string
// form without turning a missing/null value into the literal "<nil>".
func customToolInputString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// appendAssistantToolCall attaches a tool call to the preceding assistant message when
// there is one, so a single assistant turn (text + N parallel calls) stays one message.
// Splitting it into several assistant messages breaks thread-history matching upstream.
func appendAssistantToolCall(msgs []map[string]any, call map[string]any) []map[string]any {
	if n := len(msgs); n > 0 {
		last := msgs[n-1]
		if role, _ := last["role"].(string); role == "assistant" {
			calls, _ := last["tool_calls"].([]any)
			last["tool_calls"] = append(calls, call)
			return msgs
		}
	}
	return append(msgs, map[string]any{
		"role":       "assistant",
		"tool_calls": []any{call},
	})
}

// responsesTextFormat maps the Responses API `text.format` object onto the Chat
// Completions `response_format` shape understood by the upstream tool bridge.
func responsesTextFormat(body map[string]any) any {
	textObj, ok := body["text"].(map[string]any)
	if !ok {
		return nil
	}
	f, ok := textObj["format"].(map[string]any)
	if !ok {
		return nil
	}
	typ, _ := f["type"].(string)
	switch typ {
	case "json_object":
		return map[string]any{"type": "json_object"}
	case "json_schema":
		js := map[string]any{}
		for _, k := range []string{"name", "schema", "strict", "description"} {
			if v, ok := f[k]; ok && v != nil {
				js[k] = v
			}
		}
		return map[string]any{"type": "json_schema", "json_schema": js}
	default:
		return nil
	}
}

func responsesToChatRequest(body map[string]any, headers http.Header) (upstream.ChatRequest, map[string]bool, error) {
	reqModel, _ := body["model"].(string)
	var msgs []map[string]any

	// This gateway is stateless: it does not persist response objects, so a
	// previous_response_id cannot be resolved. Fail loudly instead of silently
	// answering without the referenced context.
	if prev, ok := body["previous_response_id"].(string); ok && strings.TrimSpace(prev) != "" {
		return upstream.ChatRequest{}, nil, fmt.Errorf("previous_response_id is not supported by this gateway; resend the full conversation in input (store=false)")
	}

	if inst, ok := body["instructions"].(string); ok && strings.TrimSpace(inst) != "" {
		msgs = append(msgs, map[string]any{
			"role":    "system",
			"content": inst,
		})
	}

	switch inp := body["input"].(type) {
	case string:
		if strings.TrimSpace(inp) != "" {
			msgs = append(msgs, map[string]any{"role": "user", "content": inp})
		}
	case []any:
		for _, rawItem := range inp {
			item, ok := rawItem.(map[string]any)
			if !ok {
				if s, ok := rawItem.(string); ok && strings.TrimSpace(s) != "" {
					msgs = append(msgs, map[string]any{"role": "user", "content": s})
				}
				continue
			}
			typ, _ := item["type"].(string)
			switch typ {
			case "function_call":
				callID, _ := item["call_id"].(string)
				if callID == "" {
					callID, _ = item["id"].(string)
				}
				name, _ := item["name"].(string)
				msgs = appendAssistantToolCall(msgs, map[string]any{
					"id":   callID,
					"type": "function",
					"function": map[string]any{
						"name":      name,
						"arguments": upstream.ArgumentString(item["arguments"]),
					},
				})
			case "custom_tool_call":
				callID, _ := item["call_id"].(string)
				if callID == "" {
					callID, _ = item["id"].(string)
				}
				name, _ := item["name"].(string)
				argsJSON, _ := json.Marshal(map[string]any{"input": customToolInputString(item["input"])})
				msgs = appendAssistantToolCall(msgs, map[string]any{
					"id":   callID,
					"type": "function",
					"function": map[string]any{
						"name":      name,
						"arguments": string(argsJSON),
					},
				})
			case "function_call_output", "custom_tool_call_output":
				callID, _ := item["call_id"].(string)
				msgs = append(msgs, map[string]any{
					"role":         "tool",
					"tool_call_id": callID,
					"content":      convertResponsesContent(item["output"]),
				})
			case "reasoning":
				continue
			case "", "message":
				role, _ := item["role"].(string)
				if strings.TrimSpace(role) == "" {
					role = "user"
				}
				msgs = append(msgs, map[string]any{
					"role":    strings.ToLower(strings.TrimSpace(role)),
					"content": convertResponsesContent(item["content"]),
				})
			default:
				// Ignore unknown non-message input item types (e.g. item_reference, web_search_call)
				// unless they explicitly carry non-empty message content.
				rawContent, hasContent := item["content"]
				if !hasContent {
					continue
				}
				content := convertResponsesContent(rawContent)
				if s, ok := content.(string); ok && strings.TrimSpace(s) == "" {
					continue
				}
				role, _ := item["role"].(string)
				if strings.TrimSpace(role) == "" {
					role = "user"
				}
				msgs = append(msgs, map[string]any{
					"role":    strings.ToLower(strings.TrimSpace(role)),
					"content": content,
				})
			}
		}
	}

	if len(msgs) == 0 {
		return upstream.ChatRequest{}, nil, fmt.Errorf("input must not be empty")
	}

	customTools := map[string]bool{}
	var oaTools []any
	if rawTools, ok := body["tools"].([]any); ok {
		for _, item := range rawTools {
			tm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			typ, _ := tm["type"].(string)
			switch typ {
			case "function":
				name, _ := tm["name"].(string)
				if name == "" {
					if fn, ok := tm["function"].(map[string]any); ok {
						name, _ = fn["name"].(string)
						tm = fn
					}
				}
				if strings.TrimSpace(name) == "" {
					continue
				}
				fn := map[string]any{"name": name}
				if desc, ok := tm["description"].(string); ok && desc != "" {
					fn["description"] = desc
				}
				if params, ok := tm["parameters"]; ok && params != nil {
					fn["parameters"] = params
				}
				oaTools = append(oaTools, map[string]any{"type": "function", "function": fn})
			case "custom":
				name, _ := tm["name"].(string)
				if strings.TrimSpace(name) == "" {
					continue
				}
				customTools[name] = true
				fn := map[string]any{
					"name": name,
					"parameters": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"input": map[string]any{"type": "string", "description": "Raw input string for this custom tool"},
						},
						"required": []string{"input"},
					},
				}
				if desc, ok := tm["description"].(string); ok && desc != "" {
					fn["description"] = desc
				}
				oaTools = append(oaTools, map[string]any{"type": "function", "function": fn})
			}
		}
	}

	var toolChoice any
	if rawTC := body["tool_choice"]; rawTC != nil {
		switch tc := rawTC.(type) {
		case string:
			toolChoice = tc
		case map[string]any:
			if name, _ := tc["name"].(string); name != "" {
				toolChoice = map[string]any{"type": "function", "function": map[string]any{"name": name}}
			} else if fn, ok := tc["function"].(map[string]any); ok {
				toolChoice = map[string]any{"type": "function", "function": fn}
			}
		}
	}

	effort := ""
	if rObj, ok := body["reasoning"].(map[string]any); ok {
		effort, _ = rObj["effort"].(string)
	}
	var parallelPtr *bool
	if p, ok := body["parallel_tool_calls"].(bool); ok {
		parallelPtr = &p
	}

	convID := upstream.ConversationIDFromHeaders(headers)
	if convID == "" {
		if k, ok := body["prompt_cache_key"].(string); ok && strings.TrimSpace(k) != "" {
			convID = strings.TrimSpace(k)
		}
	}

	return upstream.ChatRequest{
		Model:             reqModel,
		ThinkingEffort:    effort,
		Messages:          msgs,
		Tools:             oaTools,
		ToolChoice:        toolChoice,
		ParallelToolCalls: parallelPtr,
		ResponseFormat:    responsesTextFormat(body),
		ConversationID:    convID,
	}, customTools, nil
}

func convertResponsesContent(raw any) any {
	switch x := raw.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		var out []any
		for _, item := range x {
			pm, ok := item.(map[string]any)
			if !ok {
				if s, ok := item.(string); ok {
					out = append(out, map[string]any{"type": "text", "text": s})
				}
				continue
			}
			typ, _ := pm["type"].(string)
			switch typ {
			case "input_image":
				u := ""
				switch iu := pm["image_url"].(type) {
				case string:
					u = strings.TrimSpace(iu)
				case map[string]any:
					u, _ = iu["url"].(string)
				}
				if u != "" {
					out = append(out, map[string]any{
						"type":      "image_url",
						"image_url": map[string]any{"url": u},
					})
				}
			default:
				if t, ok := pm["text"].(string); ok {
					out = append(out, map[string]any{"type": "text", "text": t})
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

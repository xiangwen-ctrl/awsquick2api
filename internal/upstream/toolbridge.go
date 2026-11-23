package upstream

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	ToolOpen  = "<client_tool_call>"
	ToolClose = "</client_tool_call>"
)

// ToolDetailLevels defines the progressive schema compaction levels used to fit 64 KB frames.
var ToolDetailLevels = []string{"full", "160", "60", "0", "names"}

// ToolDef represents a normalized client function/tool schema.
type ToolDef struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
}

// ToolCall is a parsed client tool invocation returned to the API caller.
type ToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolChoice represents normalized tool_choice / function_call constraints.
type ToolChoice struct {
	Mode string // "auto" | "none" | "required" | "function"
	Name string
}

// ResponseFormat describes OpenAI response_format constraints (text | json_object | json_schema).
type ResponseFormat struct {
	Type   string
	Name   string
	Schema map[string]any
}

// ExtractToolDefs extracts function tool definitions from OpenAI `tools` and legacy `functions`.
func ExtractToolDefs(toolsRaw, funcsRaw any) []ToolDef {
	var defs []ToolDef
	add := func(fn map[string]any) {
		if fn == nil {
			return
		}
		name, _ := fn["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		d := ToolDef{Name: name}
		if desc, ok := fn["description"].(string); ok && strings.TrimSpace(desc) != "" {
			d.Description = desc
		}
		if params, ok := fn["parameters"]; ok && params != nil {
			d.Parameters = params
		}
		defs = append(defs, d)
	}
	if list, ok := toolsRaw.([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				if fn, ok := m["function"].(map[string]any); ok {
					add(fn)
				} else if m["name"] != nil {
					add(m)
				}
			}
		}
	}
	if list, ok := funcsRaw.([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				add(m)
			}
		}
	}
	return defs
}

// ParseToolChoice normalizes OpenAI tool_choice or legacy function_call.
func ParseToolChoice(raw any) ToolChoice {
	switch v := raw.(type) {
	case string:
		m := strings.ToLower(strings.TrimSpace(v))
		if m != "" {
			return ToolChoice{Mode: m}
		}
	case map[string]any:
		if fn, ok := v["function"].(map[string]any); ok {
			if n, _ := fn["name"].(string); strings.TrimSpace(n) != "" {
				return ToolChoice{Mode: "function", Name: strings.TrimSpace(n)}
			}
		}
		if n, _ := v["name"].(string); strings.TrimSpace(n) != "" {
			return ToolChoice{Mode: "function", Name: strings.TrimSpace(n)}
		}
		if typ, _ := v["type"].(string); strings.TrimSpace(typ) != "" {
			return ToolChoice{Mode: strings.ToLower(strings.TrimSpace(typ))}
		}
	}
	return ToolChoice{Mode: "auto"}
}

// ParseResponseFormat parses OpenAI response_format.
func ParseResponseFormat(raw any) ResponseFormat {
	m, ok := raw.(map[string]any)
	if !ok || m == nil {
		return ResponseFormat{Type: "text"}
	}
	typ, _ := m["type"].(string)
	typ = strings.ToLower(strings.TrimSpace(typ))
	switch typ {
	case "json_object":
		return ResponseFormat{Type: "json_object"}
	case "json_schema":
		rf := ResponseFormat{Type: "json_schema"}
		if js, ok := m["json_schema"].(map[string]any); ok {
			rf.Name, _ = js["name"].(string)
			if sc, ok := js["schema"].(map[string]any); ok {
				rf.Schema = sc
			}
		}
		return rf
	default:
		return ResponseFormat{Type: "text"}
	}
}

// BuildResponseFormatPrompt produces an instruction suffix for json_object / json_schema.
func BuildResponseFormatPrompt(rf ResponseFormat) string {
	switch rf.Type {
	case "json_object":
		return "Output format requirement: Return a single valid JSON object only, with no Markdown code fences and no surrounding prose."
	case "json_schema":
		schemaStr := "{}"
		if rf.Schema != nil {
			if b, err := json.Marshal(rf.Schema); err == nil {
				schemaStr = string(b)
			}
		}
		return "Output format requirement: Return a single valid JSON object only, with no Markdown code fences and no surrounding prose, strictly conforming to this JSON Schema:\n" + schemaStr
	default:
		return ""
	}
}

func shortSchemaType(schema any, depth int) string {
	m, ok := schema.(map[string]any)
	if !ok || m == nil {
		return "any"
	}
	if en, ok := m["enum"].([]any); ok && len(en) > 0 && len(en) <= 8 {
		parts := make([]string, 0, len(en))
		for _, v := range en {
			b, _ := json.Marshal(v)
			parts = append(parts, string(b))
		}
		return strings.Join(parts, "|")
	}
	typ := ""
	switch t := m["type"].(type) {
	case string:
		typ = t
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && s != "null" {
				typ = s
				break
			}
		}
	}
	if typ == "array" {
		return shortSchemaType(m["items"], depth+1) + "[]"
	}
	if typ == "object" || m["properties"] != nil {
		props, ok := m["properties"].(map[string]any)
		if !ok || len(props) == 0 || depth >= 2 {
			return "object"
		}
		reqSet := map[string]bool{}
		if reqs, ok := m["required"].([]any); ok {
			for _, r := range reqs {
				if s, ok := r.(string); ok {
					reqSet[s] = true
				}
			}
		}
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			star := ""
			if reqSet[k] {
				star = "*"
			}
			parts = append(parts, fmt.Sprintf("%s%s: %s", k, star, shortSchemaType(props[k], depth+1)))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	if typ != "" {
		return typ
	}
	return "any"
}

func compactToolSignature(def ToolDef, descLimit int) string {
	var args []string
	if params, ok := def.Parameters.(map[string]any); ok {
		reqSet := map[string]bool{}
		if reqs, ok := params["required"].([]any); ok {
			for _, r := range reqs {
				if s, ok := r.(string); ok {
					reqSet[s] = true
				}
			}
		}
		if props, ok := params["properties"].(map[string]any); ok {
			keys := make([]string, 0, len(props))
			for k := range props {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				star := ""
				if reqSet[k] {
					star = "*"
				}
				args = append(args, fmt.Sprintf("%s%s: %s", k, star, shortSchemaType(props[k], 1)))
			}
		}
	}
	line := fmt.Sprintf("- %s(%s)", def.Name, strings.Join(args, ", "))
	if descLimit > 0 {
		desc := strings.Join(strings.Fields(def.Description), " ")
		if desc != "" {
			runes := []rune(desc)
			if len(runes) > descLimit {
				desc = string(runes[:descLimit]) + "…"
			}
			line += ": " + desc
		}
	}
	return line
}

func formatToolListing(defs []ToolDef, detail string) string {
	switch detail {
	case "names":
		const maxBytes = 12000
		var sb strings.Builder
		listed := 0
		for _, d := range defs {
			if sb.Len()+len(d.Name)+2 > maxBytes {
				break
			}
			if sb.Len() > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(d.Name)
			listed++
		}
		if listed < len(defs) {
			sb.WriteString(fmt.Sprintf(", … and %d more", len(defs)-listed))
		}
		return "(names only: there are too many to describe here; take a tool's arguments from its name and from the task)\n" + sb.String()
	case "160", "60", "0":
		limit := 0
		if detail == "160" {
			limit = 160
		} else if detail == "60" {
			limit = 60
		}
		header := "(name(arguments); * marks a required argument)\n"
		if limit > 0 {
			header = "(name(arguments): description; * marks a required argument)\n"
		}
		lines := make([]string, 0, len(defs))
		for _, d := range defs {
			lines = append(lines, compactToolSignature(d, limit))
		}
		return header + strings.Join(lines, "\n")
	default:
		b, _ := json.MarshalIndent(defs, "", "  ")
		return string(b)
	}
}

// BuildToolBridgePrompt builds a concise tool-calling specification for client-defined tools.
func BuildToolBridgePrompt(defs []ToolDef, choice ToolChoice, parallel bool, detail string) string {
	if choice.Mode == "none" || len(defs) == 0 {
		return ""
	}
	lines := []string{
		"<client_tool_protocol>",
		"Available client-side tools:",
		formatToolListing(defs, detail),
		"",
		"Invoke a client tool by emitting a raw tag containing JSON (no Markdown fences):",
		`<client_tool_call>{"name":"TOOL_NAME","arguments":{...}}</client_tool_call>`,
		"Wait for the caller to return each tool result before continuing.",
	}
	if choice.Mode == "function" && choice.Name != "" {
		b, _ := json.Marshal(choice.Name)
		lines = append(lines, fmt.Sprintf("Required tool: %s.", string(b)))
	}
	if choice.Mode == "required" {
		lines = append(lines, "At least one tool call is required in this response.")
	}
	if !parallel {
		lines = append(lines, "Emit at most one tool call in this turn.")
	}
	lines = append(lines, "</client_tool_protocol>")
	return strings.Join(lines, "\n")
}

func parseToolEnvelopes(payload string) []map[string]any {
	s := strings.TrimSpace(payload)
	if s == "" {
		return nil
	}
	var val any
	if err := json.Unmarshal([]byte(s), &val); err != nil {
		return nil
	}
	switch x := val.(type) {
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		if arr, ok := x["tool_calls"].([]any); ok && len(arr) > 0 {
			out := make([]map[string]any, 0, len(arr))
			for _, item := range arr {
				if m, ok := item.(map[string]any); ok {
					out = append(out, m)
				}
			}
			return out
		}
		return []map[string]any{x}
	default:
		return nil
	}
}

func toolCallsFromEnvelopes(envs []map[string]any, allowed map[string]bool) []ToolCall {
	var out []ToolCall
	for _, env := range envs {
		name, _ := env["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" || !allowed[name] {
			continue
		}
		out = append(out, ToolCall{
			ID:        NewCallID(),
			Name:      name,
			Arguments: ArgumentString(env["arguments"]),
		})
	}
	return out
}

// ExtractMarkedToolCalls strips valid <client_tool_call>...</client_tool_call> blocks and returns cleaned text + calls.
func ExtractMarkedToolCalls(text string, allowed map[string]bool) (string, []ToolCall) {
	if len(allowed) == 0 {
		return text, nil
	}
	var (
		clean   strings.Builder
		replies []ToolCall
		rest    = text
	)
	for {
		start := strings.Index(rest, ToolOpen)
		if start < 0 {
			break
		}
		end := strings.Index(rest[start+len(ToolOpen):], ToolClose)
		if end < 0 {
			break
		}
		end += start + len(ToolOpen)
		clean.WriteString(rest[:start])
		inner := rest[start+len(ToolOpen) : end]
		parsed := toolCallsFromEnvelopes(parseToolEnvelopes(inner), allowed)
		if len(parsed) > 0 {
			replies = append(replies, parsed...)
		} else {
			// Unknown or malformed marker: keep original text untouched.
			clean.WriteString(rest[start : end+len(ToolClose)])
		}
		rest = rest[end+len(ToolClose):]
	}
	if len(replies) == 0 {
		return text, nil
	}
	clean.WriteString(rest)
	return strings.TrimSpace(clean.String()), replies
}

// ExtractBareToolCalls handles a model that answered with bare JSON (optionally fenced) instead of markers.
func ExtractBareToolCalls(text string, allowed map[string]bool) (string, []ToolCall) {
	if len(allowed) == 0 {
		return text, nil
	}
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "```") {
		if nl := strings.IndexByte(trimmed, '\n'); nl >= 0 {
			trimmed = strings.TrimSpace(trimmed[nl+1:])
			if strings.HasSuffix(trimmed, "```") {
				trimmed = strings.TrimSpace(trimmed[:len(trimmed)-3])
			}
		}
	}
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return text, nil
	}
	replies := toolCallsFromEnvelopes(parseToolEnvelopes(trimmed), allowed)
	if len(replies) > 0 {
		return "", replies
	}
	return text, nil
}

// ParseClientToolCalls tries marked <client_tool_call> tags first, then bare JSON fallback.
func ParseClientToolCalls(text string, allowed map[string]bool) (string, []ToolCall) {
	clean, calls := ExtractMarkedToolCalls(text, allowed)
	if len(calls) > 0 {
		return clean, calls
	}
	return ExtractBareToolCalls(text, allowed)
}

// BridgeStream incrementally forwards assistant text deltas in real time while holding back
// potential <client_tool_call> markers or bare-JSON responses until completion.
type BridgeStream struct {
	allowed map[string]bool
	onText  func(string)
	mode    string // "start" | "text" | "held"
	pending string
	emitted bool
}

func NewBridgeStream(allowed map[string]bool, onText func(string)) *BridgeStream {
	return &BridgeStream{
		allowed: allowed,
		onText:  onText,
		mode:    "start",
	}
}

func (b *BridgeStream) emit(text string) {
	if text == "" {
		return
	}
	if !b.emitted && strings.TrimSpace(text) == "" {
		b.pending = text + b.pending
		return
	}
	b.emitted = true
	if b.onText != nil {
		b.onText(text)
	}
}

func (b *BridgeStream) Push(delta string) {
	if delta == "" {
		return
	}
	b.pending += delta
	if b.mode == "held" {
		return
	}
	if b.mode == "start" {
		lead := strings.TrimLeft(b.pending, " \t\r\n")
		if lead == "" {
			return
		}
		if lead[0] == '{' || lead[0] == '[' || lead[0] == '`' {
			b.mode = "held"
			return
		}
		b.mode = "text"
	}
	if idx := strings.Index(b.pending, ToolOpen); idx >= 0 {
		before := b.pending[:idx]
		b.pending = b.pending[idx:]
		b.mode = "held"
		b.emit(before)
		return
	}
	keep := 0
	maxPrefix := len(ToolOpen) - 1
	if len(b.pending) < maxPrefix {
		maxPrefix = len(b.pending)
	}
	for n := maxPrefix; n > 0; n-- {
		if strings.HasPrefix(ToolOpen, b.pending[len(b.pending)-n:]) {
			keep = n
			break
		}
	}
	ready := b.pending[:len(b.pending)-keep]
	b.pending = b.pending[len(b.pending)-keep:]
	b.emit(ready)
}

func (b *BridgeStream) Finish() []ToolCall {
	rest := b.pending
	b.pending = ""
	var (
		text    string
		replies []ToolCall
	)
	if b.emitted {
		text, replies = ExtractMarkedToolCalls(rest, b.allowed)
	} else {
		text, replies = ParseClientToolCalls(rest, b.allowed)
	}
	if len(replies) > 0 {
		if strings.TrimSpace(text) != "" {
			b.emitted = true
			if b.onText != nil {
				b.onText(text)
			}
		}
		return replies
	}
	if strings.TrimSpace(rest) != "" || b.emitted {
		b.emit(rest)
	}
	return nil
}

// CleanJSONOutput strips optional Markdown code fences for json_object / json_schema responses.
func CleanJSONOutput(text string) string {
	s := strings.TrimSpace(text)
	if strings.HasPrefix(s, "```") {
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			inner := strings.TrimSpace(s[nl+1:])
			if strings.HasSuffix(inner, "```") {
				return strings.TrimSpace(inner[:len(inner)-3])
			}
		}
	}
	return s
}

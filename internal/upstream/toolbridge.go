package upstream

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
)

func marshalJSONNoEscape(v any, indent bool) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

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
	Strict bool
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
			rf.Strict, _ = js["strict"].(bool)
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
			if b, err := marshalJSONNoEscape(rf.Schema, false); err == nil {
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
			b, _ := marshalJSONNoEscape(v, false)
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
		b, _ := marshalJSONNoEscape(defs, true)
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
		"These tools run in the API caller. Return this raw tag in your reply to request execution, using the exact listed tool name (no Markdown fences):",
		`<client_tool_call>{"name":"TOOL_NAME","arguments":{...}}</client_tool_call>`,
		"Wait for the caller to return each tool result before continuing.",
	}
	if choice.Mode == "function" && choice.Name != "" {
		b, _ := marshalJSONNoEscape(choice.Name, false)
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
		// Some model outputs XML/HTML-escape the payload (&quot; &lt; &amp; &#39; ...).
		// Only when the raw text is not valid JSON, unescape the entities and try once more.
		if !strings.Contains(s, "&") {
			return nil
		}
		if err := json.Unmarshal([]byte(html.UnescapeString(s)), &val); err != nil {
			return nil
		}
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
//
// The scan is JSON-aware: a literal closing tag inside a JSON string never ends a call early.
// A stray opening tag that is not followed by a tool JSON payload is kept as text and skipped,
// so it cannot swallow a later real call. Markers inside Markdown code fences (``` or ~~~,
// including an unclosed fence) are examples and are never executed.
func ExtractMarkedToolCalls(text string, allowed map[string]bool) (string, []ToolCall) {
	if len(allowed) == 0 {
		return text, nil
	}
	var clean strings.Builder
	sc := newMarkerScanner(allowed, func(s string) { clean.WriteString(s) })
	sc.push(text)
	sc.finish()
	if len(sc.calls) == 0 {
		return text, nil
	}
	return strings.TrimSpace(clean.String()), sc.calls
}

// ExtractBareToolCalls handles a model that answered with bare JSON (optionally fenced) instead of markers.
func ExtractBareToolCalls(text string, allowed map[string]bool) (string, []ToolCall) {
	if len(allowed) == 0 {
		return text, nil
	}
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "```") {
		if nl := strings.IndexByte(trimmed, '\n'); nl >= 0 {
			lang := strings.ToLower(strings.TrimSpace(trimmed[3:nl]))
			if lang != "" && lang != "json" {
				return text, nil
			}
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

type markerStatus int

const (
	markerMore markerStatus = iota // undecidable until more input arrives
	markerCall                     // valid call(s); consume through the closing tag
	markerText                     // well-formed block without a usable call; keep it verbatim
	markerSkip                     // not a tool payload; keep only the opening tag as text
)

type jsonScanState int

const (
	jsonIncomplete jsonScanState = iota
	jsonComplete
	jsonInvalid
)

// jsonStructScan incrementally finds the end of a JSON object/array, honoring strings and
// escapes so brackets or tags inside string values are ignored. It only tracks structure;
// full validation is left to encoding/json.
type jsonStructScan struct {
	pos   int
	stack []byte
	inStr bool
	esc   bool
	state jsonScanState
	end   int
}

func (j *jsonStructScan) scan(s string) (int, jsonScanState) {
	if j.state != jsonIncomplete {
		return j.end, j.state
	}
	for ; j.pos < len(s); j.pos++ {
		c := s[j.pos]
		if j.inStr {
			if c < 0x20 {
				// RFC 8259 forbids unescaped control characters (including raw newlines) inside strings.
				j.state, j.end = jsonInvalid, j.pos
				return j.end, j.state
			}
			switch {
			case j.esc:
				j.esc = false
			case c == '\\':
				j.esc = true
			case c == '"':
				j.inStr = false
			}
			continue
		}
		switch c {
		case '"':
			j.inStr = true
		case '{':
			j.stack = append(j.stack, '}')
		case '[':
			j.stack = append(j.stack, ']')
		case '}', ']':
			n := len(j.stack)
			if n == 0 || j.stack[n-1] != c {
				j.state, j.end = jsonInvalid, j.pos
				return j.end, j.state
			}
			j.stack = j.stack[:n-1]
			if n == 1 {
				j.state, j.end = jsonComplete, j.pos+1
				return j.end, j.state
			}
		}
	}
	return len(s), jsonIncomplete
}

func matchEntityQuotePrefix(after string) probeDecision {
	low := strings.ToLower(after)
	for _, q := range []string{"&quot;", "&#34;", "&#x22;"} {
		if strings.HasPrefix(low, q) {
			return probeHold
		}
		if strings.HasPrefix(q, low) {
			return probeMore
		}
	}
	return probeRelease
}

// classifyMarkedJSONLead checks whether a payload starting with '{' or '[' after <client_tool_call>
// begins like a JSON object (or array of objects), allowing any first key name and tolerating
// XML entity quotes (&quot; / &#34; / &#x22;). Non-JSON prose like "{...}" is rejected immediately.
func classifyMarkedJSONLead(body string) (entity bool, dec probeDecision) {
	if body == "" {
		return false, probeMore
	}
	s := body
	if s[0] == '[' {
		after := strings.TrimLeft(s[1:], " \t\r\n")
		if after == "" {
			return false, probeMore
		}
		if after[0] != '{' {
			return false, probeRelease
		}
		s = after
	}
	if s[0] != '{' {
		return false, probeRelease
	}
	after := strings.TrimLeft(s[1:], " \t\r\n")
	if after == "" {
		return false, probeMore
	}
	if after[0] == '"' {
		return false, probeHold
	}
	if after[0] == '&' {
		d := matchEntityQuotePrefix(after)
		return d == probeHold, d
	}
	return false, probeRelease
}

func partialSuffixLen(s, tag string) int {
	limit := len(tag) - 1
	if len(s) < limit {
		limit = len(s)
	}
	for n := limit; n > 0; n-- {
		if strings.HasPrefix(tag, s[len(s)-n:]) {
			return n
		}
	}
	return 0
}

// markerScanner is the single incremental parser behind both ExtractMarkedToolCalls and
// BridgeStream, so chunked streaming and one-shot parsing always agree.
type markerScanner struct {
	allowed   map[string]bool
	onText    func(string)
	buf       string
	midLine   bool
	inMarker  bool
	fenceChar byte
	fenceLen  int
	js        jsonStructScan
	calls     []ToolCall
}

func newMarkerScanner(allowed map[string]bool, onText func(string)) *markerScanner {
	return &markerScanner{allowed: allowed, onText: onText}
}

func (s *markerScanner) text(t string) {
	if t != "" && s.onText != nil {
		s.onText(t)
	}
}

func (s *markerScanner) push(delta string) {
	if delta == "" {
		return
	}
	s.buf += delta
	s.run(false)
}

func (s *markerScanner) finish() {
	s.run(true)
	if s.buf != "" {
		s.text(s.buf)
		s.buf = ""
	}
}

// resolve decides what the <client_tool_call> at the start of s.buf is.
func (s *markerScanner) resolve(final bool) (markerStatus, int, []ToolCall) {
	after := s.buf[len(ToolOpen):]
	body := strings.TrimLeft(after, " \t\r\n")
	if body == "" {
		if final {
			return markerSkip, len(ToolOpen), nil
		}
		return markerMore, 0, nil
	}
	if body[0] != '{' && body[0] != '[' {
		return markerSkip, len(ToolOpen), nil
	}
	base := len(ToolOpen) + len(after) - len(body)
	// Reject obvious non-JSON immediately (e.g. "{...}" or prose after a stray tag) while still
	// allowing any valid JSON object key order inside an explicit <client_tool_call> tag.
	entity, leadDec := classifyMarkedJSONLead(body)
	switch leadDec {
	case probeMore:
		if !final {
			return markerMore, 0, nil
		}
		return markerSkip, len(ToolOpen), nil
	case probeRelease:
		return markerSkip, len(ToolOpen), nil
	}
	if entity {
		// Entity-escaped quotes hide string boundaries from the structural scan, so fall back
		// to the first closing tag and let parseToolEnvelopes unescape the payload.
		k := strings.Index(body, ToolClose)
		if k < 0 {
			if final {
				return markerSkip, len(ToolOpen), nil
			}
			return markerMore, 0, nil
		}
		if calls := toolCallsFromEnvelopes(parseToolEnvelopes(body[:k]), s.allowed); len(calls) > 0 {
			return markerCall, base + k + len(ToolClose), calls
		}
		return markerSkip, len(ToolOpen), nil
	}
	end, st := s.js.scan(body)
	switch st {
	case jsonIncomplete:
		if final {
			return markerSkip, len(ToolOpen), nil
		}
		return markerMore, 0, nil
	case jsonInvalid:
		return markerSkip, len(ToolOpen), nil
	}
	tail := body[end:]
	rest := strings.TrimLeft(tail, " \t\r\n")
	if strings.HasPrefix(rest, ToolClose) {
		consumed := base + end + len(tail) - len(rest) + len(ToolClose)
		if calls := toolCallsFromEnvelopes(parseToolEnvelopes(body[:end]), s.allowed); len(calls) > 0 {
			return markerCall, consumed, calls
		}
		if strings.Contains(body[:end], ToolOpen) {
			// The "block" spans another opening tag: treat this one as stray text instead.
			return markerSkip, len(ToolOpen), nil
		}
		return markerText, consumed, nil
	}
	if !final && len(rest) < len(ToolClose) && strings.HasPrefix(ToolClose, rest) {
		return markerMore, 0, nil
	}
	return markerSkip, len(ToolOpen), nil
}

func (s *markerScanner) run(final bool) {
	for s.buf != "" {
		if s.inMarker {
			if !s.handleMarker(final) {
				return
			}
			continue
		}
		if !s.midLine {
			i := 0
			for i < len(s.buf) && (s.buf[i] == ' ' || s.buf[i] == '\t') {
				i++
			}
			if i == len(s.buf) {
				if final {
					s.text(s.buf)
					s.buf = ""
				}
				return
			}
			if c := s.buf[i]; c == '`' || c == '~' {
				j := i
				for j < len(s.buf) && s.buf[j] == c {
					j++
				}
				if j == len(s.buf) && !final {
					return
				}
				if run := j - i; run >= 3 {
					nl := strings.IndexByte(s.buf[j:], '\n')
					if nl < 0 && !final {
						return
					}
					end := len(s.buf)
					if nl >= 0 {
						end = j + nl + 1
					}
					info := strings.TrimSpace(s.buf[j:end])
					fenceLine := false
					switch {
					case s.fenceLen == 0:
						// CommonMark: a backtick fence's info string cannot contain backticks.
						if c != '`' || strings.IndexByte(info, '`') < 0 {
							s.fenceChar, s.fenceLen = c, run
							fenceLine = true
						}
					case c == s.fenceChar && run >= s.fenceLen && info == "":
						s.fenceLen = 0
						fenceLine = true
					default:
						fenceLine = true // ordinary line inside a fence
					}
					if fenceLine {
						s.text(s.buf[:end])
						s.buf = s.buf[end:]
						continue
					}
				}
			}
			s.midLine = true
		}
		if s.fenceLen > 0 {
			nl := strings.IndexByte(s.buf, '\n')
			if nl < 0 {
				s.text(s.buf)
				s.buf = ""
				return
			}
			s.text(s.buf[:nl+1])
			s.buf = s.buf[nl+1:]
			s.midLine = false
			continue
		}
		nl := strings.IndexByte(s.buf, '\n')
		line := s.buf
		if nl >= 0 {
			line = s.buf[:nl+1]
		}
		idx := strings.Index(line, ToolOpen)
		if idx < 0 {
			if nl >= 0 {
				s.text(line)
				s.buf = s.buf[nl+1:]
				s.midLine = false
				continue
			}
			keep := 0
			if !final {
				keep = partialSuffixLen(s.buf, ToolOpen)
			}
			s.text(s.buf[:len(s.buf)-keep])
			s.buf = s.buf[len(s.buf)-keep:]
			return
		}
		s.text(s.buf[:idx])
		s.buf = s.buf[idx:]
		s.inMarker = true
	}
}

// handleMarker resolves the <client_tool_call> at the start of s.buf. It returns false when
// more input is needed; the JSON scan position is kept, so a long call is scanned only once.
func (s *markerScanner) handleMarker(final bool) bool {
	st, n, calls := s.resolve(final)
	switch st {
	case markerMore:
		return false
	case markerCall:
		s.calls = append(s.calls, calls...)
		s.buf = s.buf[n:]
	case markerText:
		s.text(s.buf[:n])
		s.buf = s.buf[n:]
	default:
		s.text(ToolOpen)
		s.buf = s.buf[len(ToolOpen):]
	}
	s.inMarker = false
	s.js = jsonStructScan{}
	return true
}

// BridgeStream incrementally forwards assistant text deltas in real time while holding back
// potential <client_tool_call> markers or bare-JSON responses until they can be decided.
type BridgeStream struct {
	allowed map[string]bool
	onText  func(string)
	mode    string // "start" | "probe" | "text" | "held"
	pending string
	lead    string
	emitted bool
	sc      *markerScanner
}

func NewBridgeStream(allowed map[string]bool, onText func(string)) *BridgeStream {
	b := &BridgeStream{
		allowed: allowed,
		onText:  onText,
		mode:    "start",
	}
	b.sc = newMarkerScanner(allowed, b.emit)
	return b
}

func (b *BridgeStream) emit(text string) {
	if text == "" {
		return
	}
	if !b.emitted && strings.TrimSpace(text) == "" {
		b.lead += text
		return
	}
	text = b.lead + text
	b.lead = ""
	b.emitted = true
	if b.onText != nil {
		b.onText(text)
	}
}

type probeDecision int

const (
	probeMore probeDecision = iota
	probeHold
	probeRelease
)

func classifyJSONObjectPrefix(s string) probeDecision {
	after := strings.TrimLeft(s[1:], " \t\r\n")
	if after == "" {
		return probeMore
	}
	if after[0] == '&' {
		// Entity-escaped key quote, e.g. {&quot;name&quot;:...}.
		return matchEntityQuotePrefix(after)
	}
	if after[0] != '"' {
		return probeRelease
	}
	endQ := strings.IndexByte(after[1:], '"')
	if endQ < 0 {
		if len(after) > 32 {
			return probeRelease
		}
		return probeMore
	}
	switch after[1 : 1+endQ] {
	case "name", "arguments", "tool_calls":
		return probeHold
	default:
		return probeRelease
	}
}

func classifyBareJSONPrefix(body string) probeDecision {
	if body == "" {
		return probeMore
	}
	switch body[0] {
	case '{':
		return classifyJSONObjectPrefix(body)
	case '[':
		after := strings.TrimLeft(body[1:], " \t\r\n")
		if after == "" {
			return probeMore
		}
		if after[0] != '{' {
			return probeRelease
		}
		return classifyJSONObjectPrefix(after)
	default:
		return probeRelease
	}
}

// classifyLeadProbe decides early whether a response that starts with '{', '[' or '`' could be
// a bare-JSON tool call (hold it) or is an ordinary answer (stream it right away).
func classifyLeadProbe(lead string) probeDecision {
	if lead == "" {
		return probeMore
	}
	switch lead[0] {
	case '{', '[':
		return classifyBareJSONPrefix(lead)
	case '`':
		if len(lead) == 1 {
			return probeMore
		}
		if len(lead) == 2 {
			if lead == "``" {
				return probeMore
			}
			return probeRelease
		}
		if !strings.HasPrefix(lead, "```") {
			return probeRelease
		}
		nl := strings.IndexByte(lead, '\n')
		if nl < 0 {
			if len(lead) > 24 {
				return probeRelease
			}
			return probeMore
		}
		lang := strings.ToLower(strings.TrimSpace(lead[3:nl]))
		if lang != "" && lang != "json" {
			return probeRelease
		}
		return classifyBareJSONPrefix(strings.TrimLeft(lead[nl+1:], " \t\r\n"))
	default:
		return probeRelease
	}
}

func (b *BridgeStream) Push(delta string) {
	if delta == "" {
		return
	}
	if len(b.allowed) == 0 {
		b.mode = "text"
		b.emit(delta)
		return
	}
	switch b.mode {
	case "text":
		b.sc.push(delta)
		return
	case "held":
		b.pending += delta
		return
	}
	b.pending += delta
	lead := strings.TrimLeft(b.pending, " \t\r\n")
	if lead == "" {
		return
	}
	switch classifyLeadProbe(lead) {
	case probeMore:
		b.mode = "probe"
		return
	case probeHold:
		b.mode = "held"
		return
	}
	b.mode = "text"
	p := b.pending
	b.pending = ""
	b.sc.push(p)
}

func (b *BridgeStream) Finish() []ToolCall {
	if b.mode == "text" {
		b.sc.finish()
		calls := b.sc.calls
		b.sc.calls = nil
		return calls
	}
	rest := b.pending
	b.pending = ""
	text, replies := ParseClientToolCalls(rest, b.allowed)
	if len(replies) > 0 {
		if strings.TrimSpace(text) != "" {
			b.emit(text)
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

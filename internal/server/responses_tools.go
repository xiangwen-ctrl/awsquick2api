package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"awsquick2api/internal/upstream"
)

type responseToolSpec struct {
	Name      string
	Namespace string
	Custom    bool
}

var invalidResponseToolAliasChars = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

func responseToolAlias(namespace, name string) string {
	name = strings.TrimSpace(name)
	if namespace = strings.TrimSpace(namespace); namespace != "" && name != "" {
		// Keep the bridge name safe for upstream tool-name parsers and use the
		// digest to distinguish namespaces and tool names containing "__".
		qualified := invalidResponseToolAliasChars.ReplaceAllString(namespace+"__"+name, "_")
		digest := sha256.Sum256([]byte(namespace + "\x00" + name))
		suffix := "_" + hex.EncodeToString(digest[:8])
		return qualified[:min(len(qualified), 64-len(suffix))] + suffix
	}
	return name
}

func responsesToolName(item map[string]any) string {
	name, _ := item["name"].(string)
	namespace, _ := item["namespace"].(string)
	return responseToolAlias(namespace, name)
}

func responsesToolDefinitions(raw any) ([]any, map[string]responseToolSpec, error) {
	var defs []any
	specs := make(map[string]responseToolSpec)
	add := func(namespace string, tool map[string]any) error {
		kind, _ := tool["type"].(string)
		if kind != "function" && kind != "custom" {
			return nil
		}
		name, _ := tool["name"].(string)
		if kind == "function" && strings.TrimSpace(name) == "" {
			tool, _ = tool["function"].(map[string]any)
			name, _ = tool["name"].(string)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil
		}
		alias := responseToolAlias(namespace, name)
		spec := responseToolSpec{Name: name, Namespace: namespace, Custom: kind == "custom"}
		if existing, ok := specs[alias]; ok && existing != spec {
			return fmt.Errorf("ambiguous tool name %q", alias)
		}
		specs[alias] = spec

		function := map[string]any{"name": alias}
		if description, ok := tool["description"].(string); ok && description != "" {
			function["description"] = description
		}
		if spec.Custom {
			function["parameters"] = map[string]any{
				"type": "object",
				"properties": map[string]any{
					"input": map[string]any{"type": "string", "description": "Raw input string for this custom tool"},
				},
				"required": []string{"input"},
			}
		} else if params := tool["parameters"]; params != nil {
			function["parameters"] = params
		}
		defs = append(defs, map[string]any{"type": "function", "function": function})
		return nil
	}

	list, _ := raw.([]any)
	for _, entry := range list {
		tool, _ := entry.(map[string]any)
		if tool["type"] != "namespace" {
			if err := add("", tool); err != nil {
				return nil, nil, err
			}
			continue
		}
		name, _ := tool["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, nil, fmt.Errorf("namespace tool requires a name")
		}
		children, _ := tool["tools"].([]any)
		for _, child := range children {
			tool, _ := child.(map[string]any)
			if err := add(name, tool); err != nil {
				return nil, nil, err
			}
		}
	}
	return defs, specs, nil
}

func responsesToolItem(call upstream.ToolCall, spec responseToolSpec) map[string]any {
	name := spec.Name
	if name == "" {
		name = call.Name
	}
	item := map[string]any{
		"id": newItemID("fc_"), "type": "function_call", "status": "completed",
		"call_id": call.ID, "name": name,
	}
	if spec.Namespace != "" {
		item["namespace"] = spec.Namespace
	}
	if spec.Custom {
		item["type"] = "custom_tool_call"
		item["input"] = extractCustomToolInput(call.Arguments)
	} else {
		args := strings.TrimSpace(call.Arguments)
		if args == "" {
			args = "{}"
		}
		item["arguments"] = args
	}
	return item
}

func resolveResponsesToolChoice(rawTC any, oaTools []any, toolSpecs map[string]responseToolSpec) ([]any, any, error) {
	if rawTC == nil {
		return oaTools, nil, nil
	}
	filterByAliases := func(allowed map[string]bool) []any {
		if len(allowed) == 0 {
			return nil
		}
		var out []any
		for _, entry := range oaTools {
			tm, _ := entry.(map[string]any)
			fn, _ := tm["function"].(map[string]any)
			name, _ := fn["name"].(string)
			if allowed[name] {
				out = append(out, entry)
			}
		}
		return out
	}
	extractNamedAlias := func(m map[string]any, allowNested bool) string {
		ns, _ := m["namespace"].(string)
		name, _ := m["name"].(string)
		if strings.TrimSpace(name) == "" && allowNested {
			if fn, ok := m["function"].(map[string]any); ok {
				name, _ = fn["name"].(string)
				if strings.TrimSpace(ns) == "" {
					ns, _ = fn["namespace"].(string)
				}
			}
		}
		return responseToolAlias(ns, name)
	}
	namespaceAliases := func(ns string) map[string]bool {
		ns = strings.TrimSpace(ns)
		out := map[string]bool{}
		if ns == "" {
			return out
		}
		for alias, spec := range toolSpecs {
			if spec.Namespace == ns {
				out[alias] = true
			}
		}
		return out
	}

	switch tc := rawTC.(type) {
	case string:
		return oaTools, tc, nil
	case map[string]any:
		typ, _ := tc["type"].(string)
		typ = strings.ToLower(strings.TrimSpace(typ))
		switch typ {
		case "auto", "none", "required":
			return oaTools, typ, nil
		case "function", "custom":
			alias := extractNamedAlias(tc, typ == "function")
			if alias == "" {
				return nil, nil, fmt.Errorf("tool_choice of type %q requires a tool name", typ)
			}
			return oaTools, map[string]any{"type": "function", "function": map[string]any{"name": alias}}, nil
		case "namespace":
			ns, _ := tc["name"].(string)
			if strings.TrimSpace(ns) == "" {
				ns, _ = tc["namespace"].(string)
			}
			ns = strings.TrimSpace(ns)
			if ns == "" {
				return nil, nil, fmt.Errorf("namespace tool_choice requires a name")
			}
			filtered := filterByAliases(namespaceAliases(ns))
			if len(filtered) == 0 {
				return nil, nil, fmt.Errorf("unknown tool namespace %q in tool_choice", ns)
			}
			return filtered, "required", nil
		case "allowed_tools":
			mode, _ := tc["mode"].(string)
			mode = strings.ToLower(strings.TrimSpace(mode))
			if mode == "" {
				mode = "auto"
			}
			if mode != "auto" && mode != "required" {
				return nil, nil, fmt.Errorf("unsupported allowed_tools mode %q", mode)
			}
			allowed := map[string]bool{}
			list, _ := tc["tools"].([]any)
			for _, rawItem := range list {
				item, _ := rawItem.(map[string]any)
				if item == nil {
					continue
				}
				kind, _ := item["type"].(string)
				kind = strings.ToLower(strings.TrimSpace(kind))
				switch kind {
				case "namespace":
					ns, _ := item["name"].(string)
					if strings.TrimSpace(ns) == "" {
						ns, _ = item["namespace"].(string)
					}
					for alias := range namespaceAliases(ns) {
						allowed[alias] = true
					}
				case "", "function", "custom":
					if alias := extractNamedAlias(item, kind != "custom"); alias != "" {
						allowed[alias] = true
					}
				}
			}
			filtered := filterByAliases(allowed)
			if mode == "required" && len(filtered) == 0 {
				return nil, nil, fmt.Errorf("allowed_tools with mode=required matched no declared tools")
			}
			return filtered, mode, nil
		case "":
			if alias := extractNamedAlias(tc, true); alias != "" {
				return oaTools, map[string]any{"type": "function", "function": map[string]any{"name": alias}}, nil
			}
			return oaTools, nil, nil
		default:
			// Ignore unsupported hosted tool choices rather than manufacturing a
			// bogus client-function filter that blocks declared tools.
			return oaTools, nil, nil
		}
	default:
		return oaTools, nil, nil
	}
}

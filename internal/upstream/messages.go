package upstream

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"awsquick2api/internal/auth"
)

const (
	PrivacyPreferenceNote = "Privacy preference: Please do not address me by name, and do not mention, repeat, or display any account profile details (such as my display name, username, email address, organization/workspace name, or account ID) in your greetings or replies. If asked for my name or email in this chat, simply say that account profile details are hidden in this session unless explicitly provided in the conversation."

	maxSingleImageBytes = 5 * 1024 * 1024
	maxTotalImageBytes  = 12 * 1024 * 1024
	maxImagesPerRequest = 8
)

var (
	dataImageRE = regexp.MustCompile(`(?is)^data:(image/[a-z0-9.+-]+);base64,(.+)$`)
	imageExts   = map[string]string{
		"image/png":  "png",
		"image/jpeg": "jpg",
		"image/gif":  "gif",
		"image/webp": "webp",
	}
)

// InlineImage is a validated base64 image extracted from user/tool messages for attachment upload.
type InlineImage struct {
	Name     string
	MimeType string
	Bytes    []byte
}

// NewCallID creates an OpenAI-style function call ID.
func NewCallID() string {
	return "call_" + strings.ReplaceAll(auth.NewUUID(), "-", "")
}

// ArgumentString normalizes an OpenAI function argument value to compact JSON string.
func ArgumentString(raw any) string {
	if raw == nil {
		return "{}"
	}
	if s, ok := raw.(string); ok {
		if strings.TrimSpace(s) == "" {
			return "{}"
		}
		return s
	}
	b, err := json.Marshal(raw)
	if err != nil || len(b) == 0 {
		return "{}"
	}
	return string(b)
}

func validateImageMagic(mimeType string, raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	switch mimeType {
	case "image/png":
		return len(raw) >= 8 && bytes.Equal(raw[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	case "image/jpeg":
		return bytes.HasPrefix(raw, []byte{0xff, 0xd8, 0xff})
	case "image/gif":
		return bytes.HasPrefix(raw, []byte("GIF87a")) || bytes.HasPrefix(raw, []byte("GIF89a"))
	case "image/webp":
		return len(raw) >= 12 && bytes.Equal(raw[:4], []byte("RIFF")) && bytes.Equal(raw[8:12], []byte("WEBP"))
	default:
		return false
	}
}

func extractImageURL(part map[string]any) string {
	switch v := part["image_url"].(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		if u, ok := v["url"].(string); ok {
			return strings.TrimSpace(u)
		}
	}
	return ""
}

// ContentText flattens an OpenAI message content field into plain text.
// When images != nil, valid inline data:image/*;base64,... parts are collected for upload.
func ContentText(content any, images *[]InlineImage, totalImageBytes *int) string {
	if content == nil {
		return ""
	}
	if s, ok := content.(string); ok {
		return s
	}
	parts, ok := content.([]any)
	if !ok {
		b, err := json.Marshal(content)
		if err != nil {
			return ""
		}
		return string(b)
	}

	var sb strings.Builder
	for _, rawPart := range parts {
		if s, ok := rawPart.(string); ok {
			sb.WriteString(s)
			continue
		}
		part, ok := rawPart.(map[string]any)
		if !ok {
			if b, err := json.Marshal(rawPart); err == nil {
				sb.Write(b)
			}
			continue
		}
		typ, _ := part["type"].(string)
		switch typ {
		case "text", "input_text", "output_text":
			if t, ok := part["text"].(string); ok {
				sb.WriteString(t)
			}
		case "image_url", "input_image":
			u := extractImageURL(part)
			if m := dataImageRE.FindStringSubmatch(u); m != nil && images != nil {
				mimeType := strings.ToLower(m[1])
				if ext, ok := imageExts[mimeType]; ok && len(*images) < maxImagesPerRequest {
					b64 := strings.Map(func(r rune) rune {
						if unicode.IsSpace(r) {
							return -1
						}
						return r
					}, m[2])
					decoded, err := base64.StdEncoding.DecodeString(b64)
					if err == nil && len(decoded) > 0 && len(decoded) <= maxSingleImageBytes && validateImageMagic(mimeType, decoded) {
						curTotal := 0
						if totalImageBytes != nil {
							curTotal = *totalImageBytes
						}
						if curTotal+len(decoded) <= maxTotalImageBytes {
							name := fmt.Sprintf("image_%d.%s", len(*images)+1, ext)
							*images = append(*images, InlineImage{
								Name:     name,
								MimeType: mimeType,
								Bytes:    decoded,
							})
							if totalImageBytes != nil {
								*totalImageBytes = curTotal + len(decoded)
							}
							sb.WriteString(fmt.Sprintf("[image: attached file %s]", name))
							continue
						}
					}
				}
			}
			if u != "" && !strings.HasPrefix(strings.ToLower(u), "data:") {
				sb.WriteString("[image: " + u + "]")
			} else {
				sb.WriteString("[image]")
			}
		case "input_audio":
			sb.WriteString("[audio]")
		case "file":
			sb.WriteString("[file]")
		default:
			if t, ok := part["text"].(string); ok {
				sb.WriteString(t)
			} else if b, err := json.Marshal(part); err == nil {
				sb.Write(b)
			}
		}
	}
	return sb.String()
}

func msgRole(m map[string]any) string {
	r, _ := m["role"].(string)
	r = strings.ToLower(strings.TrimSpace(r))
	if r == "" {
		return "user"
	}
	return r
}

func isSystemRole(role string) bool {
	return role == "system" || role == "developer"
}

// IsSystemMessage reports whether m is a system or developer message.
func IsSystemMessage(m map[string]any) bool {
	return isSystemRole(msgRole(m))
}

// PromptBlocks renders OpenAI-format messages into text blocks for Amazon Quick's user_message.
func PromptBlocks(messages, all []map[string]any, collectImages bool) ([]string, []InlineImage, error) {
	if len(messages) == 0 {
		return nil, nil, fmt.Errorf("messages must not be empty")
	}
	if len(all) == 0 {
		all = messages
	}

	toolNames := map[string]string{}
	for _, m := range all {
		if tcs, ok := m["tool_calls"].([]any); ok {
			for _, item := range tcs {
				if tc, ok := item.(map[string]any); ok {
					id, _ := tc["id"].(string)
					if fn, ok := tc["function"].(map[string]any); ok {
						name, _ := fn["name"].(string)
						if id != "" && name != "" {
							toolNames[id] = name
						}
					}
				}
			}
		}
	}

	var (
		blocks      []string
		images      []InlineImage
		totalImgB   int
		turns       int
		onlyUserTxt string
		onlyUserOK  bool
	)

	for _, m := range messages {
		role := msgRole(m)
		if isSystemRole(role) {
			continue
		}
		turns++
		var imgPtr *[]InlineImage
		if collectImages && (role == "user" || role == "tool") {
			imgPtr = &images
		}
		content := ContentText(m["content"], imgPtr, &totalImgB)
		hasContent := strings.TrimSpace(content) != ""
		if role == "user" {
			onlyUserTxt = content
			onlyUserOK = true
		} else {
			onlyUserOK = false
		}

		switch role {
		case "assistant":
			if hasContent {
				blocks = append(blocks, "Assistant: "+content)
			}
			if tcs, ok := m["tool_calls"].([]any); ok {
				for _, item := range tcs {
					tc, ok := item.(map[string]any)
					if !ok {
						continue
					}
					id, _ := tc["id"].(string)
					if strings.TrimSpace(id) == "" {
						id = "unknown"
					}
					name := "unknown"
					var rawArgs any
					if fn, ok := tc["function"].(map[string]any); ok {
						if n, _ := fn["name"].(string); strings.TrimSpace(n) != "" {
							name = strings.TrimSpace(n)
						}
						rawArgs = fn["arguments"]
					}
					blocks = append(blocks, fmt.Sprintf("Assistant tool call (id=%s, name=%s): %s",
						strings.TrimSpace(id), name, strings.TrimSpace(ArgumentString(rawArgs))))
				}
			}
			if fc, ok := m["function_call"].(map[string]any); ok {
				name, _ := fc["name"].(string)
				if strings.TrimSpace(name) == "" {
					name = "unknown"
				}
				blocks = append(blocks, fmt.Sprintf("Assistant function call (name=%s): %s",
					strings.TrimSpace(name), strings.TrimSpace(ArgumentString(fc["arguments"]))))
			}

		case "tool":
			id, _ := m["tool_call_id"].(string)
			id = strings.TrimSpace(id)
			name, _ := m["name"].(string)
			name = strings.TrimSpace(name)
			if name == "" && id != "" {
				name = toolNames[id]
			}
			var meta []string
			if id != "" {
				meta = append(meta, "call_id="+id)
			}
			if name != "" {
				meta = append(meta, "name="+name)
			}
			body := content
			if !hasContent {
				body = "(empty)"
			}
			if len(meta) > 0 {
				blocks = append(blocks, fmt.Sprintf("Tool result (%s): %s", strings.Join(meta, ", "), body))
			} else {
				blocks = append(blocks, "Tool result: "+body)
			}

		case "function":
			name, _ := m["name"].(string)
			name = strings.TrimSpace(name)
			body := content
			if !hasContent {
				body = "(empty)"
			}
			if name != "" {
				blocks = append(blocks, fmt.Sprintf("Function result (name=%s): %s", name, body))
			} else {
				blocks = append(blocks, "Function result: "+body)
			}

		case "user":
			if hasContent {
				blocks = append(blocks, "User: "+content)
			}

		default:
			if hasContent {
				lbl := strings.ToUpper(role[:1]) + role[1:]
				blocks = append(blocks, lbl+": "+content)
			}
		}
	}

	if len(blocks) == 0 {
		return nil, nil, fmt.Errorf("messages contain no text or tool calls")
	}
	if turns == 1 && onlyUserOK {
		return []string{onlyUserTxt}, images, nil
	}
	return blocks, images, nil
}

// SystemText extracts and joins all system/developer messages in order.
func SystemText(messages []map[string]any) string {
	var parts []string
	for _, m := range messages {
		if !IsSystemMessage(m) {
			continue
		}
		t := strings.TrimSpace(ContentText(m["content"], nil, nil))
		if t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "\n\n")
}

// LastUserText returns the most recent non-empty user message text for session titling.
func LastUserText(messages []map[string]any) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if msgRole(messages[i]) != "user" {
			continue
		}
		if t := strings.TrimSpace(ContentText(messages[i]["content"], nil, nil)); t != "" {
			return t
		}
	}
	return ""
}

// TitleFor derives a clean <= 60-rune conversation title.
func TitleFor(prompt string) string {
	clean := strings.Join(strings.Fields(prompt), " ")
	if clean == "" {
		return "New Conversation"
	}
	runes := []rune(clean)
	if len(runes) > 60 {
		return string(runes[:60]) + "…"
	}
	return clean
}

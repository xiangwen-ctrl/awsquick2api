package upstream

import (
	"encoding/base64"
	"fmt"
	"maps"
	"strings"
	"unicode"
)

func decodeInlineImage(url string, count, used int) (InlineImage, bool) {
	m := dataImageRE.FindStringSubmatch(url)
	if m == nil || count >= maxImagesPerRequest {
		return InlineImage{}, false
	}
	mimeType := strings.ToLower(m[1])
	ext, ok := imageExts[mimeType]
	if !ok {
		return InlineImage{}, false
	}
	encoded := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, m[2])
	limit := min(maxSingleImageBytes, maxTotalImageBytes-used)
	if limit <= 0 || len(encoded) > base64.StdEncoding.EncodedLen(limit) {
		return InlineImage{}, false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > limit || !validateImageMagic(mimeType, decoded) {
		return InlineImage{}, false
	}
	return InlineImage{Name: fmt.Sprintf("image_%d.%s", count+1, ext), MimeType: mimeType, Bytes: decoded}, true
}

func imageInputError(message string) *UpstreamError {
	return &UpstreamError{Kind: ErrKindInvalid, StatusCode: 400, Code: "unsupported_image_input", Message: message}
}

// ValidateImageInputs prepares attachments before an account is selected.
func (r *ChatRequest) ValidateImageInputs(enabled bool) (bool, *UpstreamError) {
	if r.imagesValidated {
		if !enabled && len(r.images) != 0 {
			return false, imageInputError("Image attachments are unavailable for this request")
		}
		return len(r.images) != 0, nil
	}
	var rendered []map[string]any
	var images []InlineImage
	used := 0
	for i, message := range r.Messages {
		parts, _ := message["content"].([]any)
		var rewritten []any
		for j, val := range parts {
			part, _ := val.(map[string]any)
			kind, _ := part["type"].(string)
			if kind != "image_url" && kind != "input_image" {
				continue
			}
			role := msgRole(message)
			if !enabled || (role != "user" && role != "tool") {
				return false, imageInputError("Image attachments are unavailable for this request")
			}
			img, ok := decodeInlineImage(extractImageURL(part), len(images), used)
			if !ok {
				return false, imageInputError("Expected a supported inline base64 image within the size and count limits")
			}
			if rewritten == nil {
				rewritten = append([]any(nil), parts...)
			}
			rewritten[j] = map[string]any{"type": "text", "text": "[image: attached file " + img.Name + "]"}
			images = append(images, img)
			used += len(img.Bytes)
		}
		if rewritten != nil {
			if rendered == nil {
				rendered = append([]map[string]any(nil), r.Messages...)
			}
			rendered[i] = maps.Clone(message)
			rendered[i]["content"] = rewritten
		}
	}
	r.imagesValidated = true
	r.images = images
	r.imageMessages = rendered
	return len(images) != 0, nil
}

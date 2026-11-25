package upstream

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
)

// maxContextAttachmentBytes caps the Stage-3 overflow context file uploaded as an
// attachment. Larger histories are rejected with ErrKindTooLarge instead of being
// shipped as an unbounded upload (variable so tests can lower it).
var maxContextAttachmentBytes = 4 << 20

// strictDLPEnabled reports whether strict privacy DLP applies to this request (default on).
func (p *preparedTurn) strictDLPEnabled() bool {
	if p.req.StrictPrivacyDLP != nil {
		return *p.req.StrictPrivacyDLP
	}
	return true
}

// ChatRequest is the normalized OpenAI-style chat request passed into upstream.Client.
type ChatRequest struct {
	Model             string
	Slot              string // resolved agent_mode: smart | balanced | fast | auto | advanced
	ThinkingEffort    string // off | low | medium | high
	Messages          []map[string]any
	Tools             any
	Functions         any
	ToolChoice        any
	ParallelToolCalls *bool
	ResponseFormat    any
	WebSearch         *bool
	ConversationID    string
	Stream            bool
	StrictPrivacyDLP  *bool
}

type preparedTurn struct {
	req           ChatRequest
	convo         []map[string]any
	keys          []string
	system        string
	privacyNote   string
	toolDefs      []ToolDef
	choice        ToolChoice
	parallel      bool
	bridge        bool
	bridgeAllowed map[string]bool
	respFmt       ResponseFormat
	respFmtPrompt string
	title         string
	fullCustom    string
	webSearch     bool
	toolCache     map[string]string
}

func prepareTurn(req ChatRequest, cfg config.UpstreamConfig) (*preparedTurn, error) {
	if len(req.Messages) == 0 {
		return nil, &UpstreamError{Kind: ErrKindInvalid, StatusCode: 400, Message: "messages must not be empty"}
	}
	convo := make([]map[string]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		if !IsSystemMessage(m) {
			convo = append(convo, m)
		}
	}
	if len(convo) == 0 {
		return nil, &UpstreamError{Kind: ErrKindInvalid, StatusCode: 400, Message: "messages contain no user/assistant turns"}
	}
	// Validate there is at least one non-empty prompt block overall.
	if _, _, err := PromptBlocks(convo, convo, false); err != nil {
		return nil, &UpstreamError{Kind: ErrKindInvalid, StatusCode: 400, Message: err.Error()}
	}

	toolDefs := ExtractToolDefs(req.Tools, req.Functions)
	allowed := make(map[string]bool, len(toolDefs))
	for _, d := range toolDefs {
		allowed[d.Name] = true
	}
	choice := ParseToolChoice(req.ToolChoice)
	if choice.Mode == "function" && choice.Name != "" {
		allowed[choice.Name] = true
	}
	parallel := true
	if req.ParallelToolCalls != nil {
		parallel = *req.ParallelToolCalls
	}
	respFmt := ParseResponseFormat(req.ResponseFormat)
	respFmtPrompt := BuildResponseFormatPrompt(respFmt)

	strictDLP := true
	if req.StrictPrivacyDLP != nil {
		strictDLP = *req.StrictPrivacyDLP
	}
	privacyNote := ""
	if strictDLP {
		privacyNote = PrivacyPreferenceNote
	}

	pt := &preparedTurn{
		req:           req,
		convo:         convo,
		system:        SystemText(req.Messages),
		privacyNote:   privacyNote,
		toolDefs:      toolDefs,
		choice:        choice,
		parallel:      parallel,
		respFmt:       respFmt,
		respFmtPrompt: respFmtPrompt,
		title:         TitleFor(LastUserText(req.Messages)),
		toolCache:     map[string]string{},
	}
	pt.keys = make([]string, len(convo))
	for i, m := range convo {
		pt.keys[i] = MessageKey(m)
	}

	fullTools := pt.toolsPrompt("full")
	pt.bridge = fullTools != ""
	if choice.Mode == "function" && choice.Name != "" {
		pt.bridgeAllowed = map[string]bool{choice.Name: true}
	} else {
		pt.bridgeAllowed = allowed
	}
	pt.fullCustom = pt.joinCustom(pt.system, fullTools)
	if req.WebSearch != nil {
		pt.webSearch = *req.WebSearch
	} else {
		pt.webSearch = cfg.WebSearch
	}
	return pt, nil
}

func (p *preparedTurn) toolsPrompt(detail string) string {
	if v, ok := p.toolCache[detail]; ok {
		return v
	}
	s := BuildToolBridgePrompt(p.toolDefs, p.choice, p.parallel, detail)
	p.toolCache[detail] = s
	return s
}

func (p *preparedTurn) joinCustom(sys, tools string) string {
	var parts []string
	for _, s := range []string{sys, p.privacyNote, tools, p.respFmtPrompt} {
		if strings.TrimSpace(s) != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n\n")
}

type turnInput struct {
	Prompt         string
	Slot           string
	ThreadID       string
	Title          string
	SystemPrompt   string
	ThinkingEffort string
	WebSearch      bool
	Resume         bool
	Attachments    []Attachment
}

type composedTurn struct {
	Input        turnInput
	CustomDigest string
}

func middleCut(text string, keepRunes int) string {
	runes := []rune(text)
	if len(runes) <= keepRunes {
		return text
	}
	note := []rune("\n…[shortened to fit 64 KB message limit]…\n")
	if keepRunes <= len(note) {
		return string(runes[:max(0, keepRunes)])
	}
	half := (keepRunes - len(note)) / 2
	return string(runes[:half]) + string(note) + string(runes[len(runes)-half:])
}

func longestFit(text string, fits func(string) bool) string {
	runes := []rune(text)
	low, high := 0, len(runes)
	for low < high {
		mid := (low + high + 1) / 2
		if fits(middleCut(text, mid)) {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return middleCut(text, low)
}

// composeTurn fits a turn (full or resumed delta) into Amazon Quick's 64 KB frame budget
// using progressive tool compaction -> system prompt cut -> context attachment -> fallback truncation.
func (c *Client) composeTurn(
	ctx context.Context,
	acct *auth.Account,
	sess wsSession,
	cfg config.UpstreamConfig,
	pt *preparedTurn,
	thread *ThreadEntry,
	threadID string,
	maxFrameBytes int,
) (composedTurn, error) {
	gateway := acct.IsGateway()
	startIdx := 0
	if thread != nil {
		startIdx = len(thread.Keys)
	}
	fresh := pt.convo[startIdx:]
	blocks, images, err := PromptBlocks(fresh, pt.convo, cfg.Attachments && !gateway)
	if err != nil {
		return composedTurn{}, &UpstreamError{Kind: ErrKindInvalid, StatusCode: 400, Message: err.Error()}
	}

	input := turnInput{
		Prompt:         strings.Join(blocks, "\n\n"),
		Slot:           pt.req.Slot,
		ThreadID:       threadID,
		Title:          pt.title,
		SystemPrompt:   pt.fullCustom,
		ThinkingEffort: pt.req.ThinkingEffort,
		WebSearch:      pt.webSearch,
		Resume:         thread != nil,
	}

	size := func() int {
		return FrameBytes(gateway, buildUserMessageFrame(sess, cfg, input))
	}
	fits := func() bool {
		return maxFrameBytes <= 0 || size() <= maxFrameBytes
	}

	strictDLP := pt.strictDLPEnabled()
	attach := func(name, mimeType string, data []byte, strictDLP bool) error {
		att, err := c.UploadAttachment(ctx, acct, threadID, name, mimeType, data, strictDLP)
		if err != nil {
			return err
		}
		input.Attachments = append(input.Attachments, att)
		return nil
	}

	// Upload inline base64 images before frame sizing so input.Attachments metadata is
	// accurately included in Stage 1..4 size() checks. Any failure is surfaced: the caller
	// must never get an answer computed without an image it sent.
	for _, img := range images {
		if err := attach(img.Name, img.MimeType, img.Bytes, true); err != nil {
			if ctx.Err() != nil {
				return composedTurn{}, ctx.Err()
			}
			var ue *UpstreamError
			if errors.As(err, &ue) {
				if ue.Kind == ErrKindBlocked {
					return composedTurn{}, ue
				}
				return composedTurn{}, (&UpstreamError{
					Kind:       ue.Kind,
					StatusCode: ue.StatusCode,
					Code:       ue.Code,
					RetryAfter: ue.RetryAfter,
					Message:    fmt.Sprintf("图片附件 %s 上传失败，未发送该请求: %s", img.Name, ue.Message),
				}).Normalize()
			}
			return composedTurn{}, (&UpstreamError{
				Kind:       ErrKindUpstream,
				StatusCode: 502,
				Message:    fmt.Sprintf("图片附件 %s 上传失败，未发送该请求: %v", img.Name, err),
			}).Normalize()
		}
	}

	askedDigest := Digest(pt.fullCustom)
	if thread != nil && thread.Custom == askedDigest {
		input.SystemPrompt = ""
	}
	instructed := input.SystemPrompt != ""

	// Stage 1 & 2: Compact tool schemas and system instructions if frame exceeds limit.
	if !fits() && instructed {
		savedPrompt := input.Prompt
		input.SystemPrompt = ""
		shortPrompt := size() <= maxFrameBytes/2
		if !shortPrompt {
			input.Prompt = ""
		}
		bare := size()
		room := maxFrameBytes / 2
		if !shortPrompt && bare < maxFrameBytes {
			room = max(room, bare+(maxFrameBytes-bare)/2)
		}
		if shortPrompt {
			room = maxFrameBytes
		}
		setCustom := func(sys, detail string) int {
			input.SystemPrompt = pt.joinCustom(sys, pt.toolsPrompt(detail))
			return size()
		}
		chosenDetail := ToolDetailLevels[len(ToolDetailLevels)-1]
		for _, d := range ToolDetailLevels {
			if setCustom(pt.system, d) <= room || setCustom("", d)-bare <= (room-bare)/2 {
				chosenDetail = d
				break
			}
		}
		if setCustom(pt.system, chosenDetail) > room {
			cutSys := longestFit(pt.system, func(cut string) bool {
				return setCustom(cut, chosenDetail) <= room
			})
			setCustom(cutSys, chosenDetail)
		}
		input.Prompt = savedPrompt
	}
	// The thread may already hold exactly this (compacted) custom prompt; resending it is
	// redundant. Digests always describe what was actually sent, never the uncut text.
	if instructed && thread != nil && thread.Custom != "" && Digest(input.SystemPrompt) == thread.Custom {
		input.SystemPrompt = ""
		instructed = false
	}

	// Stage 3: Offload oversized conversation history into an uploaded context file attachment.
	if !fits() && cfg.Attachments && !gateway {
		last := ""
		longBlocks := blocks
		if len(blocks) > 1 && len(blocks[len(blocks)-1]) <= 6000 {
			last = blocks[len(blocks)-1]
			longBlocks = blocks[:len(blocks)-1]
		}
		longText := strings.Join(longBlocks, "\n\n")
		name := "context_" + auth.NewUUID()[:8] + ".txt"
		data := []byte(longText)
		if len(data) > maxContextAttachmentBytes {
			return composedTurn{}, (&UpstreamError{
				Kind:       ErrKindTooLarge,
				StatusCode: 400,
				Message:    fmt.Sprintf("溢出的对话上下文为 %d 字节，超过附件卸载上限 %d 字节", len(data), maxContextAttachmentBytes),
			}).Normalize()
		}
		// The offloaded context is subject to the same DLP policy as everything else.
		if aerr := attach(name, "text/plain", data, strictDLP); aerr == nil {
			input.Prompt = fmt.Sprintf(
				"Additional conversation context (%d bytes) has been attached as %s. Read the attached file first, then respond to the conversation.",
				len(data), name,
			)
			if last != "" {
				input.Prompt += "\n\n" + last
			}
			blocks = []string{input.Prompt}
		} else if ctx.Err() != nil {
			return composedTurn{}, ctx.Err()
		} else {
			var ue *UpstreamError
			if errors.As(aerr, &ue) && (ue.Kind == ErrKindBlocked || (strictDLP && ue.Code == dlpInconclusiveCode)) {
				// A DLP block (or, in strict mode, no DLP verdict / scan failure / 401-403)
				// must not be bypassed by falling back to sending the same content inline.
				return composedTurn{}, ue
			}
			// Other upload failures fall back to Stage-4 inline truncation.
		}
	}

	// Stage 4: Fallback block compaction / truncation when attachments are disabled,
	// unavailable, or Stage-3 notice + attachment metadata still exceed the frame limit.
	if !fits() {
		syncPrompt := func() bool {
			input.Prompt = strings.Join(blocks, "\n\n")
			return fits()
		}
		for i := 0; i < len(blocks)-1 && !syncPrompt(); i++ {
			blocks[i] = middleCut(blocks[i], 1500)
		}
		for len(blocks) > 1 && !syncPrompt() {
			blocks = blocks[1:]
		}
		if !syncPrompt() {
			blocks[0] = longestFit(blocks[0], func(cut string) bool {
				blocks[0] = cut
				return syncPrompt()
			})
		}
		syncPrompt()
	}

	if !fits() {
		return composedTurn{}, &UpstreamError{
			Kind:       ErrKindTooLarge,
			StatusCode: 400,
			Message:    fmt.Sprintf("消息压缩后仍为 %d 字节，超过 Amazon Quick 的 %d 字节单帧上限", size(), maxFrameBytes),
		}
	}

	// Record the digest of the custom prompt that was actually sent (possibly compacted),
	// so a later turn re-sends the full instructions once they fit instead of assuming the
	// thread already holds them.
	customDigest := ""
	if instructed {
		customDigest = Digest(input.SystemPrompt)
	} else if thread != nil {
		customDigest = thread.Custom
	}
	return composedTurn{Input: input, CustomDigest: customDigest}, nil
}

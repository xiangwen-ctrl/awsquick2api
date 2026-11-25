package upstream

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"awsquick2api/internal/config"
	"awsquick2api/internal/safefile"
)

var bracketTagRE = regexp.MustCompile(`\[[^\]]*\]`)

// ModelCaps describes model capabilities advertised on /v1/models.
type ModelCaps struct {
	Text      bool `json:"text"`
	Image     bool `json:"image"`
	Tools     bool `json:"tools"`
	Reasoning bool `json:"reasoning"`
}

// ModelSpec defines one external model ID and its Amazon Quick agent_mode slot mapping.
type ModelSpec struct {
	ID              string    `json:"name"`
	Slot            string    `json:"slot"` // smart | balanced | fast | auto | advanced
	Display         string    `json:"display"`
	Description     string    `json:"desc,omitempty"`
	ContextWindow   int       `json:"context_window"`
	MaxOutputTokens int       `json:"max_output_tokens"`
	Caps            ModelCaps `json:"caps"`
	Alts            []string  `json:"alts,omitempty"`
}

// ClaudeAlias maps a Claude model ID to an Amazon Quick agent_mode slot.
type ClaudeAlias struct {
	Name string `json:"name"`
	Slot string `json:"slot"`
}

// ModelCatalog holds the model registry and fast alias lookup indexes.
type ModelCatalog struct {
	Specs         []ModelSpec
	ClaudeAliases []ClaudeAlias
	byLower       map[string]ModelSpec
	claudeByLower map[string]ModelSpec
}

// DefaultCatalog builds the built-in Amazon Quick model catalog.
func DefaultCatalog() *ModelCatalog {
	specs := []ModelSpec{
		{
			ID:              "amazon-smart",
			Slot:            "smart",
			Display:         "Amazon Quick Smart (Opus 档)",
			Description:     "最强档位，支持 1M 上下文、思考深度、视觉图片与客户端工具桥接",
			ContextWindow:   1000000,
			MaxOutputTokens: 64000,
			Caps:            ModelCaps{Text: true, Image: true, Tools: true, Reasoning: true},
			Alts:            []string{"smart", "qw-smart", "aws-quick/smart"},
		},
		{
			ID:              "amazon-balanced",
			Slot:            "balanced",
			Display:         "Amazon Quick Balanced (Sonnet 档)",
			Description:     "均衡主力档位，兼顾速度与编码能力",
			ContextWindow:   1000000,
			MaxOutputTokens: 64000,
			Caps:            ModelCaps{Text: true, Image: true, Tools: true, Reasoning: true},
			Alts:            []string{"balanced", "qw-balanced", "aws-quick/balanced"},
		},
		{
			ID:              "amazon-fast",
			Slot:            "fast",
			Display:         "Amazon Quick Fast (Haiku 档)",
			Description:     "高速轻量档位，适合快速检索与日常问答",
			ContextWindow:   1000000,
			MaxOutputTokens: 32000,
			Caps:            ModelCaps{Text: true, Image: true, Tools: true, Reasoning: false},
			Alts:            []string{"fast", "qw-fast", "aws-quick/fast"},
		},
		{
			ID:              "amazon-auto",
			Slot:            "auto",
			Display:         "Amazon Quick Auto (自动路由)",
			Description:     "启用 Amazon Quick auto_routing 由上游自动选择模型",
			ContextWindow:   1000000,
			MaxOutputTokens: 64000,
			Caps:            ModelCaps{Text: true, Image: true, Tools: true, Reasoning: true},
			Alts:            []string{"auto", "qw-auto", "aws-quick/auto"},
		},
		{
			ID:              "amazon-advanced",
			Slot:            "advanced",
			Display:         "Amazon Quick Advanced (高级档)",
			Description:     "仅限已开通 Advanced 权限的账号使用",
			ContextWindow:   1000000,
			MaxOutputTokens: 64000,
			Caps:            ModelCaps{Text: true, Image: true, Tools: true, Reasoning: true},
			Alts:            []string{"advanced", "qw-advanced", "aws-quick/advanced"},
		},
	}

	claudeAliases := []ClaudeAlias{
		{Name: "claude-opus-4-6", Slot: "smart"},
		{Name: "claude-opus-4-5", Slot: "smart"},
		{Name: "claude-opus-4-5-20251101", Slot: "smart"},
		{Name: "claude-opus-4-1", Slot: "smart"},
		{Name: "claude-opus-4-1-20250805", Slot: "smart"},
		{Name: "claude-opus-4-20250514", Slot: "smart"},
		{Name: "claude-sonnet-4-6", Slot: "balanced"},
		{Name: "claude-sonnet-4-5", Slot: "balanced"},
		{Name: "claude-sonnet-4-5-20250929", Slot: "balanced"},
		{Name: "claude-sonnet-4-20250514", Slot: "balanced"},
		{Name: "claude-3-7-sonnet-20250219", Slot: "balanced"},
		{Name: "claude-3-5-sonnet-20241022", Slot: "balanced"},
		{Name: "claude-haiku-4-5", Slot: "fast"},
		{Name: "claude-haiku-4-5-20251001", Slot: "fast"},
		{Name: "claude-3-5-haiku-20241022", Slot: "fast"},
	}

	return buildCatalog(specs, claudeAliases)
}

func LoadCatalogFile(path string) *ModelCatalog {
	def := DefaultCatalog()
	if strings.TrimSpace(path) == "" {
		return def
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return def
	}
	var fileShape struct {
		Aliases       []ModelSpec   `json:"aliases"`
		ClaudeAliases []ClaudeAlias `json:"claude_aliases"`
	}
	if err := json.Unmarshal(raw, &fileShape); err != nil || len(fileShape.Aliases) == 0 {
		return def
	}
	ca := fileShape.ClaudeAliases
	if len(ca) == 0 {
		ca = def.ClaudeAliases
	}
	return buildCatalog(fileShape.Aliases, ca)
}

func SaveCatalogFile(path string, cat *ModelCatalog) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("models.json path is empty")
	}
	if cat == nil || len(cat.Specs) == 0 {
		return fmt.Errorf("catalog is empty")
	}
	fileShape := struct {
		Aliases       []ModelSpec   `json:"aliases"`
		ClaudeAliases []ClaudeAlias `json:"claude_aliases,omitempty"`
	}{
		Aliases:       cat.Specs,
		ClaudeAliases: cat.ClaudeAliases,
	}
	raw, err := json.MarshalIndent(fileShape, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return safefile.WriteAtomic(path, raw, 0o644)
}

func (c *ModelCatalog) RenameSlot(slot, newID, newDisplay string) (*ModelCatalog, ModelSpec, string, error) {
	if c == nil {
		c = DefaultCatalog()
	}
	slotKey := strings.ToLower(strings.TrimSpace(slot))
	if slotKey == "" {
		return nil, ModelSpec{}, "", fmt.Errorf("missing model slot")
	}
	cleanID := strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, newID))
	if cleanID == "" {
		return nil, ModelSpec{}, "", fmt.Errorf("模型 ID 不能为空")
	}
	if len([]rune(cleanID)) > 80 {
		return nil, ModelSpec{}, "", fmt.Errorf("模型 ID 最长 80 个字符")
	}
	if strings.ContainsAny(cleanID, " \t\r\n") {
		return nil, ModelSpec{}, "", fmt.Errorf("模型 ID 不能包含空格")
	}
	cleanDisplay := strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, newDisplay))

	targetIdx := -1
	for i := range c.Specs {
		if strings.EqualFold(c.Specs[i].Slot, slotKey) {
			targetIdx = i
			break
		}
	}
	if targetIdx < 0 {
		return nil, ModelSpec{}, "", fmt.Errorf("未找到槽位 %q", slot)
	}
	newLow := strings.ToLower(cleanID)
	for i, s := range c.Specs {
		if i == targetIdx {
			continue
		}
		if strings.EqualFold(s.ID, cleanID) || strings.EqualFold(s.Slot, cleanID) {
			return nil, ModelSpec{}, "", fmt.Errorf("模型 ID %q 与其他模型冲突", cleanID)
		}
	}

	newSpecs := make([]ModelSpec, len(c.Specs))
	for i, s := range c.Specs {
		cp := s
		if len(s.Alts) > 0 {
			alts := make([]string, 0, len(s.Alts))
			for _, a := range s.Alts {
				if strings.ToLower(strings.TrimSpace(a)) == newLow {
					continue
				}
				alts = append(alts, a)
			}
			cp.Alts = alts
		}
		newSpecs[i] = cp
	}
	oldID := newSpecs[targetIdx].ID
	newSpecs[targetIdx].ID = cleanID
	if cleanDisplay != "" {
		newSpecs[targetIdx].Display = cleanDisplay
	} else {
		newSpecs[targetIdx].Display = cleanID
	}

	newAliases := make([]ClaudeAlias, len(c.ClaudeAliases))
	copy(newAliases, c.ClaudeAliases)
	next := buildCatalog(newSpecs, newAliases)
	return next, newSpecs[targetIdx], oldID, nil
}

func buildCatalog(specs []ModelSpec, claudeAliases []ClaudeAlias) *ModelCatalog {
	c := &ModelCatalog{
		Specs:         specs,
		ClaudeAliases: claudeAliases,
		byLower:       make(map[string]ModelSpec, len(specs)*4),
		claudeByLower: make(map[string]ModelSpec, len(claudeAliases)),
	}
	slotMap := map[string]ModelSpec{}
	for _, s := range specs {
		c.byLower[strings.ToLower(s.ID)] = s
		c.byLower[strings.ToLower(s.Slot)] = s
		slotMap[strings.ToLower(s.Slot)] = s
		for _, alt := range s.Alts {
			c.byLower[strings.ToLower(alt)] = s
		}
	}
	for _, ca := range claudeAliases {
		base, ok := slotMap[strings.ToLower(ca.Slot)]
		if !ok && len(specs) > 0 {
			base = specs[0]
		}
		mapped := base
		mapped.ID = ca.Name
		mapped.Slot = ca.Slot
		c.claudeByLower[strings.ToLower(ca.Name)] = mapped
	}
	return c
}

// Resolve maps a client-requested model ID to an Amazon Quick agent_mode slot, ModelSpec,
// and optional thinking_effort extracted from a "-off"/"-low"/"-medium"/"-high" suffix.
func (c *ModelCatalog) Resolve(requested, defaultSlot string, allowClaude bool) (slot string, spec ModelSpec, suffixEffort string, known bool) {
	if c == nil || len(c.Specs) == 0 {
		// An empty catalog (e.g. a broken models.json) must not panic on Specs[0].
		c = DefaultCatalog()
	}
	if defaultSlot == "" {
		defaultSlot = "smart"
	}
	cleaned := strings.TrimSpace(bracketTagRE.ReplaceAllString(requested, ""))
	if cleaned == "" {
		if s, ok := c.byLower[strings.ToLower(defaultSlot)]; ok {
			return s.Slot, s, "", true
		}
		return defaultSlot, c.Specs[0], "", true
	}

	key := strings.ToLower(cleaned)
	// Strip optional provider prefix like "aws-quick/smart" or "qw/smart".
	if idx := strings.LastIndexByte(key, '/'); idx >= 0 {
		key = key[idx+1:]
	}
	if strings.HasPrefix(key, "qw-") {
		key = strings.TrimPrefix(key, "qw-")
	}
	key = normalizeBedrockModelID(key)

	// Check for optional thinking effort suffix (-off, -low, -medium, -high).
	baseKey := key
	for _, suf := range []string{"-off", "-low", "-medium", "-high"} {
		if strings.HasSuffix(baseKey, suf) && len(baseKey) > len(suf) {
			cand := strings.TrimSuffix(baseKey, suf)
			if _, ok := c.byLower[cand]; ok {
				baseKey = cand
				suffixEffort = strings.TrimPrefix(suf, "-")
				break
			}
			if allowClaude {
				if _, ok := c.claudeByLower[cand]; ok || strings.HasPrefix(cand, "claude-") {
					baseKey = cand
					suffixEffort = strings.TrimPrefix(suf, "-")
					break
				}
			}
		}
	}

	if s, ok := c.byLower[baseKey]; ok {
		return s.Slot, s, suffixEffort, true
	}

	if allowClaude {
		if s, ok := c.claudeByLower[baseKey]; ok {
			return s.Slot, s, suffixEffort, true
		}
		if strings.HasPrefix(baseKey, "claude-") {
			target := "balanced"
			switch {
			case strings.Contains(baseKey, "haiku"):
				target = "fast"
			case strings.Contains(baseKey, "opus"):
				target = "smart"
			}
			base, ok := c.byLower[target]
			if !ok && len(c.Specs) > 0 {
				base = c.Specs[0]
			}
			base.ID = cleaned
			base.Slot = target
			return target, base, suffixEffort, true
		}
	}

	// Fallback to configured defaultSlot for unknown model IDs.
	fallbackSpec := c.Specs[0]
	if s, ok := c.byLower[strings.ToLower(defaultSlot)]; ok {
		fallbackSpec = s
	}
	fallbackSpec.ID = cleaned
	return fallbackSpec.Slot, fallbackSpec, suffixEffort, false
}

// VisibleModels returns the models advertised on GET /v1/models after applying visibility rules.
func (c *ModelCatalog) VisibleModels(hidden, allowed map[string]bool, allowlistOn, claudeAliasesOn, exposeEffortVariants, hasAdvanced bool) []ModelSpec {
	if c == nil {
		c = DefaultCatalog()
	}
	out := make([]ModelSpec, 0, len(c.Specs)*4+len(c.ClaudeAliases))
	keep := func(id string) bool {
		k := strings.ToLower(id)
		if hidden[k] {
			return false
		}
		if allowlistOn && !allowed[k] {
			return false
		}
		return true
	}
	for _, s := range c.Specs {
		// Hide amazon-advanced by default unless an account supports it or allowlist explicitly asks for it.
		if s.Slot == "advanced" && !hasAdvanced && !allowed[strings.ToLower(s.ID)] && !allowed["advanced"] {
			continue
		}
		if keep(s.ID) {
			out = append(out, s)
		}
		// Effort variants only make sense for slots that actually reason (fast does not).
		if exposeEffortVariants && s.Caps.Reasoning && (s.Slot == "smart" || s.Slot == "balanced" || s.Slot == "advanced") {
			for _, eff := range []string{"low", "medium", "high"} {
				v := s
				v.ID = s.ID + "-" + eff
				v.Display = fmt.Sprintf("%s (%s)", s.Display, eff)
				if keep(v.ID) {
					out = append(out, v)
				}
			}
		}
	}
	if claudeAliasesOn {
		for _, ca := range c.ClaudeAliases {
			if spec, ok := c.claudeByLower[strings.ToLower(ca.Name)]; ok {
				if keep(spec.ID) {
					out = append(out, spec)
				}
			}
		}
	}
	return out
}

// NormalizeEffort normalizes arbitrary reasoning effort tokens into "off"|"low"|"medium"|"high"|"".
func NormalizeEffort(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return ""
	case "off", "none", "disabled", "false", "0":
		return "off"
	case "minimal", "low":
		return "low"
	case "medium", "med":
		return "medium"
	case "high", "max", "xhigh", "enabled", "adaptive":
		return "high"
	default:
		return "medium"
	}
}

// EffortFromBudgetTokens maps Anthropic thinking budget_tokens into Quick effort levels.
func EffortFromBudgetTokens(budget int) string {
	switch {
	case budget <= 0:
		return "medium"
	case budget >= 16384:
		return "high"
	case budget >= 8192:
		return "medium"
	default:
		return "low"
	}
}

// ResolveThinkingEffort computes the effective Amazon Quick thinking_effort for one request.
func ResolveThinkingEffort(cfg config.ThinkingConfig, reqModel, slot, suffixEffort, reqEffort string) string {
	if strings.EqualFold(cfg.Policy, "gateway") {
		if ov := lookupOverride(cfg.ModelOverrides, reqModel, slot); ov != "" {
			return NormalizeEffort(ov)
		}
		return NormalizeEffort(cfg.DefaultEffort)
	}
	// Policy "client": explicit request effort > model suffix effort > model override > default effort.
	if e := NormalizeEffort(reqEffort); e != "" {
		return e
	}
	if e := NormalizeEffort(suffixEffort); e != "" {
		return e
	}
	if ov := lookupOverride(cfg.ModelOverrides, reqModel, slot); ov != "" {
		return NormalizeEffort(ov)
	}
	return NormalizeEffort(cfg.DefaultEffort)
}

func lookupOverride(m map[string]string, reqModel, slot string) string {
	if len(m) == 0 {
		return ""
	}
	get := func(target string) string {
		if target == "" {
			return ""
		}
		if v := strings.TrimSpace(m[target]); v != "" {
			return v
		}
		for k, v := range m {
			if strings.ToLower(strings.TrimSpace(k)) == target {
				if tv := strings.TrimSpace(v); tv != "" {
					return tv
				}
			}
		}
		return ""
	}
	model := strings.ToLower(strings.TrimSpace(reqModel))
	if v := get(model); v != "" {
		return v
	}
	// Strip [1m] bracket tags, optional provider prefixes (aws-quick/, qw-) and Bedrock prefixes.
	bare := strings.TrimSpace(bracketTagRE.ReplaceAllString(model, ""))
	if bare != "" && bare != model {
		if v := get(bare); v != "" {
			return v
		}
	}
	norm := bare
	if idx := strings.LastIndexByte(norm, '/'); idx >= 0 {
		norm = norm[idx+1:]
	}
	norm = strings.TrimPrefix(norm, "qw-")
	norm = normalizeBedrockModelID(norm)
	if norm != "" && norm != model && norm != bare {
		if v := get(norm); v != "" {
			return v
		}
	}
	return get(strings.ToLower(strings.TrimSpace(slot)))
}

var (
	bedrockRegionPrefixes = []string{"us.", "eu.", "ap.", "apac.", "jp.", "au.", "global."}
	bedrockVersionRE      = regexp.MustCompile(`-v\d+(?::\d+)?$`)
)

// normalizeBedrockModelID maps Bedrock-style IDs such as
// "us.anthropic.claude-sonnet-4-5-20250929-v1:0" to "claude-sonnet-4-5-20250929".
func normalizeBedrockModelID(key string) string {
	for _, p := range bedrockRegionPrefixes {
		if strings.HasPrefix(key, p+"anthropic.") {
			key = strings.TrimPrefix(key, p)
			break
		}
	}
	if !strings.HasPrefix(key, "anthropic.claude-") {
		return key
	}
	key = strings.TrimPrefix(key, "anthropic.")
	return bedrockVersionRE.ReplaceAllString(key, "")
}

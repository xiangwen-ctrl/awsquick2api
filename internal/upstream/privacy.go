package upstream

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"awsquick2api/internal/auth"
)

const redactedMarker = "[REDACTED]"

var (
	genericPrivacyWords = map[string]bool{
		"user":      true,
		"admin":     true,
		"root":      true,
		"owner":     true,
		"guest":     true,
		"member":    true,
		"default":   true,
		"personal":  true,
		"workspace": true,
		"account":   true,
		"quick":     true,
		"amazon":    true,
		"aws":       true,
		"claude":    true,
		"assistant": true,
		"redacted":  true,
	}

	// RFC-2606 & standard code/doc placeholder email domains that must never be
	// mangled when coding agents generate unit tests, docs, or git examples.
	safePlaceholderEmailDomains = map[string]bool{
		"example.com":              true,
		"example.org":              true,
		"example.net":              true,
		"example.edu":              true,
		"test.com":                 true,
		"test.org":                 true,
		"localhost":                true,
		"invalid":                  true,
		"domain.com":               true,
		"yourdomain.com":           true,
		"company.com":              true,
		"yourcompany.com":          true,
		"acme.com":                 true,
		"acme.org":                 true,
		"sample.com":               true,
		"foo.com":                  true,
		"bar.com":                  true,
		"email.com":                true,
		"users.noreply.github.com": true,
	}

	// Common asset/source file extensions so tokens like "icon@2x.png" or "pkg@v1.json"
	// are never mistaken for email addresses.
	nonEmailFileExts = map[string]bool{
		"png": true, "jpg": true, "jpeg": true, "gif": true, "webp": true, "svg": true, "ico": true,
		"css": true, "js": true, "mjs": true, "cjs": true, "ts": true, "tsx": true, "jsx": true,
		"json": true, "map": true, "woff": true, "woff2": true, "ttf": true, "otf": true,
		"mp4": true, "webm": true, "mp3": true, "wav": true, "pdf": true, "zip": true, "gz": true, "tar": true,
		"go": true, "py": true, "rs": true, "java": true, "rb": true, "php": true, "c": true, "cpp": true, "h": true,
		"html": true, "htm": true, "md": true, "txt": true, "yaml": true, "yml": true, "toml": true, "lock": true,
	}

	emailStdRE     = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}`)
	emailObfRE     = regexp.MustCompile(`(?i)\b([a-z0-9._%+\-]+)\s*(?:\[at\]|\(at\)|\{at\}|\bat\b)\s*([a-z0-9.\-]+(?:\s*(?:\.|\[dot\]|\(dot\)|\{dot\}|\bdot\b)\s*[a-z0-9\-]+)*)\s*(?:\.|\[dot\]|\(dot\)|\{dot\}|\bdot\b)\s*([a-z]{2,24})\b`)
	obfDotSplitRE  = regexp.MustCompile(`(?i)\s*(?:\.|\[dot\]|\(dot\)|\{dot\}|\bdot\b)\s*`)
	sepHexRE       = regexp.MustCompile(`(?:0x|\\x)?[0-9a-fA-F]{2}(?:(?:[\s,:\-]|\\x|0x)+[0-9a-fA-F]{2}){4,}`)
	contigHexRE    = regexp.MustCompile(`\b[0-9a-fA-F]{10,}\b`)
	mixedEscSpanRE = regexp.MustCompile(`(?:\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|%[0-9a-fA-F]{2}|&#x[0-9a-fA-F]{1,6};|&#[0-9]{2,6};|[A-Za-z0-9.@_\-+]){6,}`)
	unicodeEsc4RE  = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	unicodeEsc8RE  = regexp.MustCompile(`\\U([0-9a-fA-F]{8})`)
	base64TokenRE  = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{8,}`)
)

type literalTarget struct {
	text         string
	requireBound bool
}

type skelTarget struct {
	runes        []rune
	requireBound bool
}

// accountPrivacyPolicy defines the per-turn DLP rules protecting the upstream account owner's PII.
type accountPrivacyPolicy struct {
	strict       bool
	literals     []literalTarget
	skeletons    []skelTarget
	acctEmails   map[string]bool
	userEmails   map[string]bool
	maxSecretLen int
}

func buildAccountPrivacyPolicy(acct *auth.Account, messages []map[string]any, strict bool) *accountPrivacyPolicy {
	p := &accountPrivacyPolicy{
		strict:     strict,
		acctEmails: map[string]bool{},
		userEmails: map[string]bool{},
	}

	var inputSB strings.Builder
	for _, m := range messages {
		inputSB.WriteString(ContentText(m["content"], nil, nil))
		inputSB.WriteByte('\n')
		if tcs, ok := m["tool_calls"].([]any); ok {
			for _, tc := range tcs {
				inputSB.WriteString(ArgumentString(tc))
				inputSB.WriteByte('\n')
			}
		}
	}
	inputFull := inputSB.String()
	inputLower := strings.ToLower(inputFull)

	for _, em := range emailStdRE.FindAllString(inputLower, -1) {
		p.userEmails[em] = true
	}

	if acct == nil {
		return p
	}
	if em := strings.ToLower(strings.TrimSpace(acct.Email)); em != "" {
		p.acctEmails[em] = true
	}

	rawSecrets := collectRawAccountSecrets(acct, inputLower)
	seenLit := map[string]bool{}
	addLiteral := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		low := strings.ToLower(s)
		if genericPrivacyWords[low] || seenLit[low] {
			return
		}
		seenLit[low] = true
		nRunes := utf8.RuneCountInString(s)
		if nRunes > p.maxSecretLen {
			p.maxSecretLen = nRunes
		}
		p.literals = append(p.literals, literalTarget{
			text:         s,
			requireBound: isPureASCIIAlphaNum(s) && nRunes < 8,
		})
	}

	seenSkel := map[string]bool{}
	addSkeleton := func(raw string) {
		sk := toSkeletonRunes(raw)
		if len(sk) == 0 {
			return
		}
		pureASCII := isPureASCIIRunes(sk)
		if pureASCII && len(sk) < 5 {
			return
		}
		if !pureASCII && len(sk) < 2 {
			return
		}
		key := string(sk)
		if genericPrivacyWords[key] || seenSkel[key] {
			return
		}
		seenSkel[key] = true
		if len(sk) > p.maxSecretLen {
			p.maxSecretLen = len(sk)
		}
		p.skeletons = append(p.skeletons, skelTarget{
			runes:        sk,
			requireBound: pureASCII && len(sk) < 10,
		})
	}

	for _, sec := range rawSecrets {
		addLiteral(sec)
		if strict {
			addSkeleton(sec)
			if utf8.RuneCountInString(sec) >= 5 {
				rev := reverseRunesStr(sec)
				if !strings.Contains(inputLower, strings.ToLower(rev)) {
					addLiteral(rev)
					addSkeleton(rev)
				}
			}
		}
	}

	// Add spoken/bracketed email skeleton variant (e.g., "alice [at] gmail [dot] com" -> "aliceatgmaildotcom").
	if strict && acct.Email != "" {
		em := strings.ToLower(strings.TrimSpace(acct.Email))
		if !strings.Contains(inputLower, em) && strings.Contains(em, "@") {
			spoken := strings.ReplaceAll(strings.ReplaceAll(em, "@", "at"), ".", "dot")
			addSkeleton(spoken)
		}
	}

	sort.Slice(p.literals, func(i, j int) bool {
		if len(p.literals[i].text) != len(p.literals[j].text) {
			return len(p.literals[i].text) > len(p.literals[j].text)
		}
		return p.literals[i].text < p.literals[j].text
	})
	sort.Slice(p.skeletons, func(i, j int) bool {
		if len(p.skeletons[i].runes) != len(p.skeletons[j].runes) {
			return len(p.skeletons[i].runes) > len(p.skeletons[j].runes)
		}
		return string(p.skeletons[i].runes) < string(p.skeletons[j].runes)
	})
	return p
}

func collectRawAccountSecrets(acct *auth.Account, inputLower string) []string {
	if acct == nil {
		return nil
	}
	candidates := []struct {
		val      string
		minRunes int
	}{
		{acct.Email, 5},
		{acct.ActorARN, 10},
		{acct.AWSAccountID, 10},
		{acct.DisplayNameVal, 2},
		{acct.UserName, 3},
		{acct.AccountName, 4},
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string, minRunes int) {
		s = strings.TrimSpace(s)
		if s == "" || utf8.RuneCountInString(s) < minRunes {
			return
		}
		low := strings.ToLower(s)
		if genericPrivacyWords[low] || seen[low] || strings.Contains(inputLower, low) {
			return
		}
		seen[low] = true
		out = append(out, s)
	}
	for _, c := range candidates {
		add(c.val, c.minRunes)
	}
	if local, _, ok := strings.Cut(strings.TrimSpace(acct.Email), "@"); ok {
		add(local, 5)
	}
	for _, part := range strings.Fields(acct.DisplayNameVal) {
		add(part, 3)
	}
	return out
}

// collectAccountPII preserves backward-compatible helper access for basic literal list checks.
func collectAccountPII(acct *auth.Account, messages []map[string]any) []string {
	pol := buildAccountPrivacyPolicy(acct, messages, false)
	out := make([]string, 0, len(pol.literals))
	for _, l := range pol.literals {
		out = append(out, l.text)
	}
	return out
}

func scrubAccountPII(text string, secrets []string) string {
	if text == "" || len(secrets) == 0 {
		return text
	}
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		text = replaceFoldLiteralBounded(text, sec, redactedMarker, isPureASCIIAlphaNum(sec) && utf8.RuneCountInString(sec) < 8)
	}
	return text
}

func (p *accountPrivacyPolicy) active() bool {
	if p == nil {
		return false
	}
	return p.strict || len(p.literals) > 0
}

// Scrub applies all active DLP layers (literal/reversed, skeleton de-obfuscation,
// encoded-span decoding, and generic unauthorized email fallback).
func (p *accountPrivacyPolicy) Scrub(text string) string {
	if text == "" || !p.active() {
		return text
	}
	return p.scrubDepth(text, 0)
}

func (p *accountPrivacyPolicy) scrubDepth(text string, depth int) string {
	out := text
	if p.strict && depth < 2 {
		out = p.scrubEncodedSpans(out, depth)
	}
	return p.scrubCore(out)
}

func (p *accountPrivacyPolicy) scrubCore(text string) string {
	if text == "" {
		return ""
	}
	if p.strict {
		text = p.scrubUnauthorizedEmails(text)
		if len(p.skeletons) > 0 {
			text = p.scrubSkeletons(text)
		}
	}
	for _, lit := range p.literals {
		text = replaceFoldLiteralBounded(text, lit.text, redactedMarker, lit.requireBound)
	}
	return text
}

func (p *accountPrivacyPolicy) containsSensitive(decoded string, depth int) bool {
	if strings.TrimSpace(decoded) == "" {
		return false
	}
	return p.scrubDepth(decoded, depth+1) != decoded
}

// scrubSkeletons maps letter+digit+CJK characters back to original rune indices to catch
// spaced, hyphenated, bracketed, backtick-wrapped, zero-width, or [at]/[dot] split PII.
func (p *accountPrivacyPolicy) scrubSkeletons(text string) string {
	sRunes := []rune(text)
	if len(sRunes) < 2 {
		return text
	}
	markerRunes := []rune(redactedMarker)
	skel := make([]rune, 0, len(sRunes))
	origIdx := make([]int, 0, len(sRunes))

	for i := 0; i < len(sRunes); {
		if i+len(markerRunes) <= len(sRunes) && runesEqual(sRunes[i:i+len(markerRunes)], markerRunes) {
			// Emit opaque sentinel so [REDACTED] never fuses surrounding letters into false matches.
			skel = append(skel, 0)
			origIdx = append(origIdx, i)
			i += len(markerRunes)
			continue
		}
		r := sRunes[i]
		if isSkelRune(r) {
			skel = append(skel, foldRuneLower(r))
			origIdx = append(origIdx, i)
		}
		i++
	}
	if len(skel) < 2 {
		return text
	}

	type span struct{ start, end int }
	var matches []span

	for i := 0; i < len(skel); {
		if skel[i] == 0 {
			i++
			continue
		}
		matched := false
		for _, tgt := range p.skeletons {
			L := len(tgt.runes)
			if i+L > len(skel) || !runesEqual(skel[i:i+L], tgt.runes) {
				continue
			}
			origStart := origIdx[i]
			origEnd := origIdx[i+L-1]
			if !validSkeletonSpan(sRunes, origIdx[i:i+L], tgt.requireBound) {
				continue
			}
			matches = append(matches, span{start: origStart, end: origEnd + 1})
			i += L
			matched = true
			break
		}
		if !matched {
			i++
		}
	}

	if len(matches) == 0 {
		return text
	}
	var sb strings.Builder
	sb.Grow(len(text))
	cur := 0
	for _, m := range matches {
		if m.start < cur {
			continue
		}
		sb.WriteString(string(sRunes[cur:m.start]))
		sb.WriteString(redactedMarker)
		cur = m.end
	}
	sb.WriteString(string(sRunes[cur:]))
	return sb.String()
}

func validSkeletonSpan(sRunes []rune, pos []int, requireBound bool) bool {
	L := len(pos)
	if L == 0 {
		return false
	}
	origStart := pos[0]
	origEnd := pos[L-1]
	if requireBound {
		if origStart > 0 && isASCIIAlphaNum(sRunes[origStart-1]) {
			return false
		}
		if origEnd+1 < len(sRunes) && isASCIIAlphaNum(sRunes[origEnd+1]) {
			return false
		}
	}
	for k := 0; k < L-1; k++ {
		a, b := pos[k], pos[k+1]
		gap := b - a - 1
		if gap > 10 {
			return false
		}
		if gap > 0 && L <= 5 {
			// Short targets (e.g. 2-3 CJK character names) must not bridge across sentence breaks or newlines.
			for g := a + 1; g < b; g++ {
				switch sRunes[g] {
				case '\n', '\r', '。', '！', '？', '；', '!', '?', ';':
					return false
				}
			}
		}
	}
	return true
}

func (p *accountPrivacyPolicy) scrubUnauthorizedEmails(text string) string {
	if strings.Contains(text, "@") {
		text = emailStdRE.ReplaceAllStringFunc(text, func(m string) string {
			if p.isEmailAllowed(m) {
				return m
			}
			return redactedMarker
		})
	}
	if containsFoldSubstr(text, "at") {
		text = emailObfRE.ReplaceAllStringFunc(text, func(m string) string {
			sub := emailObfRE.FindStringSubmatch(m)
			if len(sub) != 4 {
				return m
			}
			normDom := obfDotSplitRE.ReplaceAllString(strings.TrimSpace(sub[2]), ".")
			normEmail := strings.TrimSpace(sub[1]) + "@" + normDom + "." + strings.TrimSpace(sub[3])
			if p.isEmailAllowed(normEmail) {
				return m
			}
			return redactedMarker
		})
	}
	return text
}

func (p *accountPrivacyPolicy) isEmailAllowed(rawEmail string) bool {
	em := strings.ToLower(strings.TrimSpace(rawEmail))
	local, domain, ok := strings.Cut(em, "@")
	if !ok || local == "" || domain == "" {
		return true
	}
	// If it's the account's own email and wasn't provided by the user, always block.
	if p.acctEmails[em] && !p.userEmails[em] {
		return false
	}
	if p.userEmails[em] {
		return true
	}
	// Ignore asset/file names like "logo@2x.png" or "module@v1.json".
	if dotIdx := strings.LastIndexByte(domain, '.'); dotIdx > 0 {
		tld := domain[dotIdx+1:]
		if nonEmailFileExts[tld] && strings.Count(domain, ".") == 1 {
			return true
		}
	}
	if local == "noreply" || local == "no-reply" || local == "donotreply" {
		return true
	}
	if local == "git" && (domain == "github.com" || domain == "gitlab.com") {
		return true
	}
	if safePlaceholderEmailDomains[domain] {
		return true
	}
	for safeDom := range safePlaceholderEmailDomains {
		if strings.HasSuffix(domain, "."+safeDom) {
			return true
		}
	}
	return false
}

func (p *accountPrivacyPolicy) scrubEncodedSpans(text string, depth int) string {
	// 1. Mixed Unicode (\uXXXX / \UXXXXXXXX), URL (%XX), and HTML (&#...;) escape sequences.
	if strings.Contains(text, `\u`) || strings.Contains(text, `\U`) || strings.Contains(text, "%") || strings.Contains(text, "&#") {
		text = mixedEscSpanRE.ReplaceAllStringFunc(text, func(span string) string {
			if countEscapeMarkers(span) < 2 {
				return span
			}
			decoded := decodeEscapedSpan(span)
			if decoded != span && isMostlyPrintableUTF8(decoded) && p.containsSensitive(decoded, depth) {
				return redactedMarker
			}
			return span
		})
	}

	// 2. Separator-delimited or \x-prefixed hex byte runs (e.g. "61 6c 69..." or "\x61\x6c...").
	text = sepHexRE.ReplaceAllStringFunc(text, func(span string) string {
		if raw, ok := decodeHexLoose(span); ok && isMostlyPrintableUTF8(raw) && p.containsSensitive(raw, depth) {
			return redactedMarker
		}
		return span
	})

	// 3. Contiguous hex runs.
	text = contigHexRE.ReplaceAllStringFunc(text, func(span string) string {
		if len(span) > 2048 || len(span)%2 != 0 {
			return span
		}
		b, err := hex.DecodeString(span)
		if err == nil && len(b) >= 5 {
			raw := string(b)
			if isMostlyPrintableUTF8(raw) && p.containsSensitive(raw, depth) {
				return redactedMarker
			}
		}
		return span
	})

	// 4. Base64 / Base64URL tokens (padded or unpadded, including whole encoded sentences).
	text = base64TokenRE.ReplaceAllStringFunc(text, func(tok string) string {
		if len(tok) > 2048 || strings.EqualFold(tok, "REDACTED") {
			return tok
		}
		for _, decoded := range decodeBase64Candidates(tok) {
			if isMostlyPrintableUTF8(decoded) && p.containsSensitive(decoded, depth) {
				return redactedMarker
			}
		}
		return tok
	})
	return text
}

func countEscapeMarkers(s string) int {
	return strings.Count(s, `\u`) + strings.Count(s, `\U`) + strings.Count(s, "%") + strings.Count(s, "&#")
}

func decodeEscapedSpan(s string) string {
	out := unicodeEsc4RE.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil || !utf8.ValidRune(rune(v)) {
			return m
		}
		return string(rune(v))
	})
	out = unicodeEsc8RE.ReplaceAllStringFunc(out, func(m string) string {
		v, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil || !utf8.ValidRune(rune(v)) {
			return m
		}
		return string(rune(v))
	})
	if strings.Contains(out, "%") {
		if u, err := url.PathUnescape(out); err == nil {
			out = u
		}
	}
	if strings.Contains(out, "&#") {
		out = html.UnescapeString(out)
	}
	return out
}

func decodeHexLoose(span string) (string, bool) {
	s := strings.ReplaceAll(span, "0x", "")
	s = strings.ReplaceAll(s, "0X", "")
	s = strings.ReplaceAll(s, `\x`, "")
	s = strings.ReplaceAll(s, `\X`, "")
	var hexChars strings.Builder
	hexChars.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hexChars.WriteByte(c)
		}
	}
	clean := hexChars.String()
	if len(clean) < 10 || len(clean)%2 != 0 {
		return "", false
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func decodeBase64Candidates(tok string) []string {
	trimmed := strings.TrimRight(tok, "=")
	if len(trimmed) < 6 {
		return nil
	}
	var out []string
	if b, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil && len(b) >= 4 {
		out = append(out, string(b))
	}
	if strings.ContainsAny(trimmed, "-_") {
		if b, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil && len(b) >= 4 {
			s := string(b)
			if len(out) == 0 || out[0] != s {
				out = append(out, s)
			}
		}
	}
	return out
}

func isMostlyPrintableUTF8(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	total, printable := 0, 0
	for _, r := range s {
		if r == utf8.RuneError {
			return false
		}
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	return total >= 3 && printable*10 >= total*9
}

func replaceFoldLiteralBounded(s, target, repl string, requireBound bool) string {
	if s == "" || target == "" {
		return s
	}
	lowS := strings.ToLower(s)
	lowT := strings.ToLower(target)
	if !strings.Contains(lowS, lowT) {
		return s
	}
	sRunes := []rune(s)
	tRunes := []rune(lowT)
	if len(tRunes) == 0 || len(sRunes) < len(tRunes) {
		return s
	}
	markerRunes := []rune(redactedMarker)
	lowRunes := make([]rune, len(sRunes))
	for i, r := range sRunes {
		lowRunes[i] = foldRuneLower(r)
	}
	var sb strings.Builder
	sb.Grow(len(s))
	changed := false
	for i := 0; i < len(sRunes); {
		if i+len(markerRunes) <= len(sRunes) && runesEqual(sRunes[i:i+len(markerRunes)], markerRunes) {
			sb.WriteString(redactedMarker)
			i += len(markerRunes)
			continue
		}
		if i+len(tRunes) <= len(sRunes) && runesEqual(lowRunes[i:i+len(tRunes)], tRunes) {
			boundOK := true
			if requireBound {
				if i > 0 && isASCIIAlphaNum(sRunes[i-1]) {
					boundOK = false
				}
				if i+len(tRunes) < len(sRunes) && isASCIIAlphaNum(sRunes[i+len(tRunes)]) {
					boundOK = false
				}
			}
			if boundOK {
				sb.WriteString(repl)
				i += len(tRunes)
				changed = true
				continue
			}
		}
		sb.WriteRune(sRunes[i])
		i++
	}
	if !changed {
		return s
	}
	return sb.String()
}

func containsFoldSubstr(s, subLower string) bool {
	return strings.Contains(strings.ToLower(s), subLower)
}

func isSkelRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isASCIIAlphaNum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func isPureASCIIAlphaNum(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isASCIIAlphaNum(r) {
			return false
		}
	}
	return true
}

func isPureASCIIRunes(rs []rune) bool {
	for _, r := range rs {
		if r >= 128 {
			return false
		}
	}
	return true
}

func toSkeletonRunes(s string) []rune {
	var out []rune
	for _, r := range s {
		if isSkelRune(r) {
			out = append(out, foldRuneLower(r))
		}
	}
	return out
}

func reverseRunesStr(s string) string {
	rs := []rune(s)
	for i, j := 0, len(rs)-1; i < j; i, j = i+1, j-1 {
		rs[i], rs[j] = rs[j], rs[i]
	}
	return string(rs)
}

func foldRuneLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	if r < 128 {
		return r
	}
	low := strings.ToLower(string(r))
	if first, _ := utf8.DecodeRuneInString(low); first != utf8.RuneError {
		return first
	}
	return r
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

const (
	defaultStreamBaseTail = 48
	maxStreamHoldRunes    = 256
)

// privacyStreamRedactor buffers an adaptive raw sliding tail window so literal, split,
// or encoded account PII split across streaming chunks is never prematurely half-redacted
// or leaked before emission.
type privacyStreamRedactor struct {
	policy        *accountPrivacyPolicy
	baseTailRunes int
	buf           string
	emit          func(string)
}

func newPrivacyPolicyStreamRedactor(policy *accountPrivacyPolicy, emit func(string)) *privacyStreamRedactor {
	baseTail := 0
	if policy != nil && policy.active() {
		if policy.maxSecretLen > 1 {
			baseTail = policy.maxSecretLen - 1
		}
		if policy.strict && baseTail < defaultStreamBaseTail {
			baseTail = defaultStreamBaseTail
		}
	}
	return &privacyStreamRedactor{
		policy:        policy,
		baseTailRunes: baseTail,
		emit:          emit,
	}
}

func newPrivacyStreamRedactor(secrets []string, emit func(string)) *privacyStreamRedactor {
	pol := &accountPrivacyPolicy{}
	for _, s := range secrets {
		if s == "" {
			continue
		}
		n := utf8.RuneCountInString(s)
		if n > pol.maxSecretLen {
			pol.maxSecretLen = n
		}
		pol.literals = append(pol.literals, literalTarget{
			text:         s,
			requireBound: isPureASCIIAlphaNum(s) && n < 8,
		})
	}
	return newPrivacyPolicyStreamRedactor(pol, emit)
}

func (r *privacyStreamRedactor) Push(delta string) {
	if delta == "" {
		return
	}
	if r.policy == nil || !r.policy.active() {
		if r.emit != nil {
			r.emit(delta)
		}
		return
	}
	r.buf += delta
	runes := []rune(r.buf)
	safeFlush := r.computeSafeFlushCount(runes)
	if safeFlush <= 0 {
		return
	}
	out := r.policy.Scrub(string(runes[:safeFlush]))
	r.buf = string(runes[safeFlush:])
	if out != "" && r.emit != nil {
		r.emit(out)
	}
}

func (r *privacyStreamRedactor) computeSafeFlushCount(runes []rune) int {
	n := len(runes)
	if n <= r.baseTailRunes {
		return 0
	}
	safeEnd := n - r.baseTailRunes
	minSafeEnd := 0
	if n > maxStreamHoldRunes {
		minSafeEnd = n - maxStreamHoldRunes
	}

	if r.policy.strict {
		// 1. Do not split an ongoing non-whitespace token at the very end.
		tokStart := n
		for tokStart > minSafeEnd && isTokenContinuationRune(runes[tokStart-1]) {
			tokStart--
		}
		if tokStart < safeEnd {
			safeEnd = tokStart
		}

		// 2. If the tail skeleton ends with a strict prefix of any secret skeleton
		// (and has at most 10 trailing separator chars), hold from its first rune.
		if len(r.policy.skeletons) > 0 {
			tailSlice := runes[minSafeEnd:]
			var tailSkel []rune
			var tailOrig []int
			for i := 0; i < len(tailSlice); i++ {
				if isSkelRune(tailSlice[i]) {
					tailSkel = append(tailSkel, foldRuneLower(tailSlice[i]))
					tailOrig = append(tailOrig, minSafeEnd+i)
				}
			}
			if len(tailSkel) > 0 && (n-1-tailOrig[len(tailOrig)-1]) <= 10 {
				for sIdx := 0; sIdx < len(tailSkel); sIdx++ {
					suffix := tailSkel[sIdx:]
					if r.matchesAnySkeletonPrefix(suffix) {
						if origPos := tailOrig[sIdx]; origPos < safeEnd {
							safeEnd = origPos
						}
						break
					}
				}
			}
		}

		// 3. Hold ongoing spaced hex pairs at the end (e.g. "61 6c 69 ").
		if hexStart := trailingSpacedHexStart(runes, minSafeEnd); hexStart < safeEnd {
			safeEnd = hexStart
		}

		// Snap safeEnd left to avoid cutting inside a word/token.
		for safeEnd > minSafeEnd && isTokenContinuationRune(runes[safeEnd-1]) {
			safeEnd--
		}
	}

	if safeEnd < minSafeEnd {
		safeEnd = minSafeEnd
	}

	// Straddle guard: ensure splitting at safeEnd never bisects an already-complete match.
	winRadius := max(r.baseTailRunes, 48)
	for safeEnd > minSafeEnd {
		wStart := max(0, safeEnd-winRadius)
		wEnd := min(n, safeEnd+winRadius)
		left := string(runes[wStart:safeEnd])
		right := string(runes[safeEnd:wEnd])
		whole := string(runes[wStart:wEnd])
		if r.policy.Scrub(whole) == r.policy.Scrub(left)+r.policy.Scrub(right) {
			break
		}
		safeEnd = max(minSafeEnd, safeEnd-16)
		for safeEnd > minSafeEnd && isTokenContinuationRune(runes[safeEnd-1]) {
			safeEnd--
		}
	}
	return safeEnd
}

func (r *privacyStreamRedactor) matchesAnySkeletonPrefix(suffix []rune) bool {
	if len(suffix) == 0 {
		return false
	}
	for _, tgt := range r.policy.skeletons {
		if len(suffix) < len(tgt.runes) && runesEqual(tgt.runes[:len(suffix)], suffix) {
			return true
		}
	}
	return false
}

func isTokenContinuationRune(r rune) bool {
	if unicode.IsSpace(r) {
		return false
	}
	switch r {
	case '"', '\'', '<', '>', '(', ')', '[', ']', '{', '}', ',':
		return false
	default:
		return true
	}
}

func trailingSpacedHexStart(runes []rune, minIdx int) int {
	i := len(runes) - 1
	steps := 0
	for i >= minIdx {
		c := runes[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		isSep := c == ' ' || c == ':' || c == '-' || c == ',' || c == 'x' || c == 'X' || c == '\\'
		if !isHex && !isSep {
			break
		}
		i--
		steps++
	}
	if steps >= 5 {
		return i + 1
	}
	return len(runes)
}

func (r *privacyStreamRedactor) Finish() {
	if r == nil || r.buf == "" {
		return
	}
	out := r.buf
	if r.policy != nil {
		out = r.policy.Scrub(r.buf)
	}
	r.buf = ""
	if out != "" && r.emit != nil {
		r.emit(out)
	}
}

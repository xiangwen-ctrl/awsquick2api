package upstream

import (
	"encoding/base64"
	"strings"
	"testing"

	"awsquick2api/internal/auth"
)

func dlpTestPolicy(t *testing.T, userText string) *accountPrivacyPolicy {
	t.Helper()
	acct := &auth.Account{
		Email:          "zhangsan88@gmail.com",
		DisplayNameVal: "张三",
		UserName:       "alice",
		AWSAccountID:   "123456789012",
		ActorARN:       "arn:aws:iam::123456789012:user/zhangsan88",
		AccountID:      "qacct-77xy",
		Namespace:      "tenantns42",
	}
	msgs := []map[string]any{{"role": "user", "content": userText}}
	return buildAccountPrivacyPolicy(acct, msgs, true)
}

func dlpStream(pol *accountPrivacyPolicy, input string, chunk int) string {
	var sb strings.Builder
	red := newPrivacyPolicyStreamRedactor(pol, func(s string) { sb.WriteString(s) })
	rs := []rune(input)
	for i := 0; i < len(rs); i += chunk {
		red.Push(string(rs[i:min(len(rs), i+chunk)]))
	}
	red.Finish()
	return sb.String()
}

// P0-1 and P2/P3: benign technical text must pass through untouched.
func TestPrivacyDLPNoFalsePositives(t *testing.T) {
	pol := dlpTestPolicy(t, "Please review my Go code.")
	cases := []string{
		"Look at req.Header for the token.",
		"// Look at ctx.Done() before returning",
		"Error at fmt.Errorf call site",
		"the value at cfg.Server.Port is wrong",
		"Look at req dot Header",
		"<script src=\"jquery@3.6.0.min.js\"></script>",
		"icon@2x.min.png and logo@2x.png",
		"systemctl restart getty@tty1.service user@1000.slice",
		"DSN: mysql://root:secret@db.internal.net:3306/app",
		"export DATABASE_URL=postgres://svc:pw@pg.internal.net/app",
		"git clone git@gitee.com:owner/repo.git",
		"git@bitbucket.org:team/repo.git",
		"my%20file.txt",
	}
	for _, in := range cases {
		if got := pol.Scrub(in); got != in {
			t.Errorf("Scrub false positive:\n in: %q\nout: %q", in, got)
		}
		if got := dlpStream(pol, in, 3); got != in {
			t.Errorf("stream false positive:\n in: %q\nout: %q", in, got)
		}
	}
}

// P0-1 / P1-6 / P1-7 / P2: bypass attempts must be redacted.
func TestPrivacyDLPBypasses(t *testing.T) {
	pol := dlpTestPolicy(t, "I saw some malice in the markdown, max_tokens=100.")
	longTok := strings.Repeat("A", 300) + "zhangsan88@gmail.com" + strings.Repeat("B", 40) + " done"
	veryLongTok := strings.Repeat("Q", 3000) + "zhangsan88@gmail.com" + strings.Repeat("Z", 40) + " end"
	cases := []struct {
		name      string
		input     string
		forbidden []string
	}{
		{"bracket_at", "mail bob [at] corp [dot] com", []string{"bob", "corp"}},
		{"bare_at_dot_marker", "reach bob at corp dot com today", []string{"bob at corp"}},
		{"bare_at_dot_marker_cn", "reach wangwu at example dot cn", []string{"wangwu"}},
		{"single_pct40", "write to wang%40corp.com", []string{"wang", "corp"}},
		{"cjk2_url", "name=%E5%BC%A0%E4%B8%89", []string{"%E5%BC%A0%E4%B8%89"}},
		{"cjk2_unicode", `name: \u5f20\u4e09`, []string{`\u5f20\u4e09`}},
		{"cjk2_base64", "name " + base64.StdEncoding.EncodeToString([]byte("张三")), []string{base64.StdEncoding.EncodeToString([]byte("张三"))}},
		{"substring_exemption_alice", "Ping alice now", []string{"alice"}},
		{"fullwidth_homoglyph", "contact ｚｈａｎｇｓａｎ８８ please", []string{"ｚｈａｎｇｓａｎ８８"}},
		{"account_id", "acct qacct-77xy here", []string{"qacct-77xy"}},
		{"namespace", "ns=tenantns42", []string{"tenantns42"}},
		{"long_token_257", longTok, []string{"zhangsan88", "gmail"}},
		{"long_token_3000", veryLongTok, []string{"zhangsan88", "gmail"}},
		// P1-2 regression: base64 after "=" in key=value assignments (short & long keys, padded & unpadded).
		{"b64_after_eq_short_key", "key=" + base64.StdEncoding.EncodeToString([]byte("zhangsan88@gmail.com")), []string{base64.StdEncoding.EncodeToString([]byte("zhangsan88@gmail.com"))}},
		{"b64_after_eq_long_key", "password=" + base64.StdEncoding.EncodeToString([]byte("zhangsan88@gmail.com")), []string{base64.StdEncoding.EncodeToString([]byte("zhangsan88@gmail.com"))}},
		{"b64_after_eq_unpadded", "token=" + base64.RawStdEncoding.EncodeToString([]byte("alice")), []string{base64.RawStdEncoding.EncodeToString([]byte("alice"))}},
		{"b64_after_eq_cjk2", "name=" + base64.StdEncoding.EncodeToString([]byte("张三")), []string{base64.StdEncoding.EncodeToString([]byte("张三"))}},
		// P1-2 regression: 0x/0X contiguous hex and uppercase 0X/\X separated hex.
		{"hex_0x_lower_contig", "id=0x7a68616e6773616e383840676d61696c2e636f6d", []string{"7a68616e6773"}},
		{"hex_0X_upper_contig", "id=0X7A68616E6773616E383840676D61696C2E636F6D", []string{"7A68616E6773"}},
		{"hex_0X_upper_sep", "Hex: 0X7a 0X68 0X61 0X6e 0X67 0X73 0X61 0X6e 0X38 0X38", []string{"0X7a 0X68"}},
		{"hex_bsX_upper_sep", `Hex: \X7a\X68\X61\X6e\X67\X73\X61\X6e\X38\X38`, []string{`\X7a\X68`}},
		// P1-2 regression: uppercase &#X HTML hex entities.
		{"html_upper_hex_email", "Mail: zhangsan88&#X40;gmail.com", []string{"zhangsan88", "gmail.com"}},
		{"html_upper_hex_cjk", "User: &#X5F20;&#X4E09; ok", []string{"&#X5F20;", "&#X4E09;"}},
		// P1-2 regression: wide spaced skeleton (>48 runes, gap <= 10) across streaming chunks.
		{"wide_spaced_skeleton_96", "intro text here " + "z    h    a    n    g    s    a    n    8    8    @    g    m    a    i    l    .    c    o    m" + " " + strings.Repeat("safe tail word ", 12), []string{"z    h    a", "g    m    a"}},
		{"wide_spaced_skeleton_171", "intro text here " + "z         h         a         n         g         s         a         n         8         8    @    g         m         a         i         l    .    c         o         m" + " " + strings.Repeat("safe tail word ", 12), []string{"z         h", "m         a         i"}},
		// P1-2 regression: long obfuscated emails (>48 runes) across streaming chunks.
		{"long_obf_email_brackets", "Reach very.long.corporate.employee.identifier.name [at] sub.department.enterprise.corpnet [dot] io " + strings.Repeat("safe tail word ", 12), []string{"very.long.corporate", "enterprise.corpnet"}},
		{"long_obf_email_bare_at", "Reach very.long.corporate.employee.identifier.name at sub dot department dot enterprise dot corpnet dot io " + strings.Repeat("safe tail word ", 12), []string{"very.long.corporate", "enterprise dot corpnet"}},
	}
	for _, tc := range cases {
		got := pol.Scrub(tc.input)
		for _, bad := range tc.forbidden {
			if strings.Contains(got, bad) {
				t.Errorf("[%s] Scrub leaked %q in %q", tc.name, bad, got)
			}
		}
		for _, chunk := range []int{1, 3, 7} {
			sGot := dlpStream(pol, tc.input, chunk)
			for _, bad := range tc.forbidden {
				if strings.Contains(sGot, bad) {
					t.Errorf("[%s] stream(chunk=%d) leaked %q in %q", tc.name, chunk, bad, sGot)
				}
			}
		}
	}
}

func TestPrivacyDLPWordBoundedExemption(t *testing.T) {
	// A standalone mention by the user still exempts the value.
	pol := dlpTestPolicy(t, "hi, I am alice")
	if got := pol.Scrub("hello alice"); got != "hello alice" {
		t.Fatalf("user-provided standalone value should be exempt, got %q", got)
	}
	cases := map[string]bool{
		"malice":         false,
		"alice":          true,
		"hi alice!":      true,
		"alice_x":        false,
		"markdown":       false,
		"张三丰":            true,
		"x@alice.com":    true,
		"xalice":         false,
		"alice2":         false,
		"pre alice post": true,
	}
	for hay, want := range cases {
		if got := containsWordBounded(hay, "alice"); hay != "张三丰" && got != want {
			t.Errorf("containsWordBounded(%q, alice)=%v want %v", hay, got, want)
		}
	}
	if !containsWordBounded("张三丰", "张三") {
		t.Errorf("CJK needle should match without word boundary")
	}
	if containsWordBounded("markdown", "mark") || containsWordBounded("max_tokens", "max") {
		t.Errorf("substring inside identifier must not count as exemption")
	}
}

func TestPrivacyDLPStreamBufferBounded(t *testing.T) {
	pol := dlpTestPolicy(t, "hello")
	var emitted int
	red := newPrivacyPolicyStreamRedactor(pol, func(s string) { emitted += len([]rune(s)) })
	tok := strings.Repeat("k", 20000)
	for i := 0; i < len(tok); i += 50 {
		red.Push(tok[i : i+50])
		if held := len([]rune(red.buf)); held > red.holdRunes*streamHardCapFactor+64 {
			t.Fatalf("stream buffer grew unbounded: %d runes", held)
		}
	}
	red.Finish()
	if emitted != len(tok) {
		t.Fatalf("emitted %d runes, want %d", emitted, len(tok))
	}
}

// Web/object-store schemes must not exempt userinfo: "https://bob@corp.com"
// is a known way to smuggle a third-party email past the generic fallback.
func TestPrivacyDLPURIUserinfoScope(t *testing.T) {
	pol := dlpTestPolicy(t, "hello")
	for _, in := range []string{
		"see https://bob@corp.com now",
		"see http://bob@corp.com now",
		"see wss://bob@corp.com now",
		"see ws://bob@corp.com now",
		"see s3://bob@corp.com now",
		"mail alice2@corp.so now",
	} {
		got := pol.Scrub(in)
		if strings.Contains(got, "@corp.") || !strings.Contains(got, redactedMarker) {
			t.Errorf("expected redaction for %q, got %q", in, got)
		}
		if sGot := dlpStream(pol, in, 3); strings.Contains(sGot, "@corp.") {
			t.Errorf("stream leaked for %q, got %q", in, sGot)
		}
	}
	dbURI := "dsn " + "mysql" + "://" + "app" + "@db.internal now"
	if got := pol.Scrub(dbURI); got != dbURI {
		t.Errorf("DB URI userinfo should be kept: in %q out %q", dbURI, got)
	}
	pgURI := "dsn " + "postgres" + "://" + "svc" + "@pg.internal.net/app now"
	if got := pol.Scrub(pgURI); got != pgURI {
		t.Errorf("DB URI userinfo should be kept: in %q out %q", pgURI, got)
	}
}

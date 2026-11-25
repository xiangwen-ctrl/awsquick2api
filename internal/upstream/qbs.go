package upstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/pool"
)

var planLabels = map[string]string{
	"QUICK_LITE_FREE_TRIAL": "Free Trial",
	"FREE_TRIAL":            "Free Trial",
	"FREE":                  "Free",
	"PRO":                   "Pro",
	"TEAM":                  "Team",
	"ENTERPRISE":            "Enterprise",
}

// Attachment represents an uploaded file/image delivered to an Amazon Quick thread.
type Attachment struct {
	Type          string `json:"type"`
	Name          string `json:"name"`
	Size          int    `json:"size"`
	MimeType      string `json:"mimeType"`
	Path          string `json:"path"`
	AttachmentID  string `json:"attachmentId"`
	ContentSHA256 string `json:"contentSha256"`
}

// SpentAllowance describes an exhausted quota window and how long until it resets.
type SpentAllowance struct {
	Window     string // "session" | "monthly"
	RetryAfter time.Duration
}

type settingsCacheEntry struct {
	at       time.Time
	advanced bool
	raw      map[string]any
}

func (c *Client) accountHTTPClient(_ *auth.Account, timeout time.Duration) (*http.Client, error) {
	return c.upstreamHTTPClient(timeout)
}

func (c *Client) tenantBase(acct *auth.Account) (string, error) {
	if acct == nil || strings.TrimSpace(acct.TenantURL) == "" {
		return "", &UpstreamError{Kind: ErrKindHandshake, StatusCode: 401, Message: "账号缺少 tenant_url，请重新授权"}
	}
	base := strings.TrimRight(strings.TrimSpace(acct.TenantURL), "/")
	if _, err := auth.ValidateTrustedURL(base, c.hasCustomEndpoints()); err != nil {
		return "", &UpstreamError{Kind: ErrKindInvalid, StatusCode: 400, Message: err.Error()}
	}
	return base, nil
}

// Gateway discovery cache lifetimes. A successful /v1/discovery answer is reused for
// gwHostTTL. When discovery fails and the tenant host is used as a fallback, the entry
// is only reused for gwHostFallbackTTL (<= 0 disables caching of fallbacks) so a
// transient discovery outage does not pin the wrong cell host for ten minutes.
var (
	gwHostTTL         = 10 * time.Minute
	gwHostFallbackTTL = 30 * time.Second
)

func (c *Client) gatewayHost(ctx context.Context, acct *auth.Account) (string, string, error) {
	base, err := c.tenantBase(acct)
	if err != nil {
		return "", "", err
	}
	c.gwHostMu.Lock()
	cached, ok := c.gwHosts[base]
	c.gwHostMu.Unlock()
	if ok && time.Since(cached.at) < gwHostTTL && cached.host != "" {
		return cached.host, cached.wsPath, nil
	}

	u, err := url.Parse(base)
	if err != nil {
		return "", "", err
	}
	host := u.Host
	wsPath, perr := validateWSPath(acct.WSPath)
	if perr != nil {
		wsPath = ""
	}
	discovered := false

	cl, err := c.accountHTTPClient(acct, 15*time.Second)
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/discovery", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+acct.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-amzn-qs-internal-trace-id", auth.NewUUID())
	resp, err := cl.Do(req)
	if err == nil {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		if resp.StatusCode == http.StatusOK {
			var disc map[string]any
			if json.Unmarshal(raw, &disc) == nil {
				if ch, _ := disc["cellHost"].(string); strings.TrimSpace(ch) != "" {
					host = strings.TrimSpace(ch)
					discovered = true
				} else if wh, _ := disc["wsHost"].(string); strings.TrimSpace(wh) != "" {
					host = strings.TrimSpace(wh)
					discovered = true
				}
				if wp, _ := disc["wsPath"].(string); wp != "" {
					if vp, verr := validateWSPath(wp); verr == nil && vp != "" {
						wsPath = vp
					}
				}
			}
		}
	}

	// Validate discovered host against trusted allowlist.
	checkHost := host
	if !strings.Contains(checkHost, "://") {
		scheme := "https://"
		if u.Scheme == "http" {
			scheme = "http://"
		}
		checkHost = scheme + checkHost
	}
	if _, verr := auth.ValidateTrustedURL(checkHost, c.hasCustomEndpoints()); verr != nil {
		return "", "", &UpstreamError{Kind: ErrKindUpstream, StatusCode: 502, Message: "Gateway 服务发现返回不受信任的主机"}
	}
	if parsed, perr := url.Parse(checkHost); perr == nil && parsed.Host != "" {
		host = parsed.Host
	}

	at := time.Now()
	if !discovered {
		if gwHostFallbackTTL <= 0 {
			return host, wsPath, nil
		}
		// gwHostEntry only records when it was stored; backdate the fallback entry so
		// it expires gwHostFallbackTTL from now instead of after the full gwHostTTL.
		if gwHostFallbackTTL < gwHostTTL {
			at = at.Add(-(gwHostTTL - gwHostFallbackTTL))
		}
	}
	c.gwHostMu.Lock()
	if len(c.gwHosts) >= 256 {
		now := time.Now()
		for k, v := range c.gwHosts {
			if now.Sub(v.at) >= gwHostTTL {
				delete(c.gwHosts, k)
			}
		}
		if len(c.gwHosts) >= 256 {
			c.gwHosts = map[string]gwHostEntry{}
		}
	}
	c.gwHosts[base] = gwHostEntry{host: host, wsPath: wsPath, at: at}
	c.gwHostMu.Unlock()
	return host, wsPath, nil
}

func isLoopbackWSHost(h string) bool {
	switch strings.ToLower(strings.Trim(h, "[]")) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// validateWSHost strictly validates a stored/imported ws_host. Remote hosts must use
// wss (a bare host or https:// is upgraded to wss://), port 443 only, and a trusted AWS
// domain suffix; loopback hosts (ws:// / wss://) are only accepted when allowCustom is
// true (explicit custom endpoint override in dev/tests). The host must not carry userinfo,
// a path, a query or a fragment. An empty value returns "".
func validateWSHost(raw string, allowCustom bool) (string, error) {
	v := strings.TrimRight(strings.TrimSpace(raw), "/")
	if v == "" {
		return "", nil
	}
	for _, r := range v {
		if r <= ' ' || r == 0x7f || r == '\\' {
			return "", fmt.Errorf("ws_host 包含非法字符")
		}
	}
	if strings.Contains(v, "@") {
		return "", fmt.Errorf("ws_host 不得包含 @")
	}
	withScheme := v
	if !strings.Contains(v, "://") {
		withScheme = "wss://" + v
	}
	u, err := url.Parse(withScheme)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("ws_host 格式无效")
	}
	scheme := strings.ToLower(u.Scheme)
	if isLoopbackWSHost(u.Hostname()) {
		if !allowCustom {
			return "", fmt.Errorf("ws_host 不允许环回地址 (%s)", u.Hostname())
		}
		switch scheme {
		case "ws", "http":
			return "ws://" + u.Host, nil
		case "wss", "https":
			return "wss://" + u.Host, nil
		}
		return "", fmt.Errorf("ws_host 协议不受支持 (%s)", scheme)
	}
	if scheme != "wss" && scheme != "https" {
		return "", fmt.Errorf("ws_host 必须使用 wss (%s)", scheme)
	}
	if p := u.Port(); p != "" && p != "443" {
		return "", fmt.Errorf("ws_host 端口不受支持 (%s)", p)
	}
	if _, verr := auth.ValidateTrustedURL("https://"+u.Host, false); verr != nil {
		return "", fmt.Errorf("ws_host 不是受信任的 AWS 域名 (%s)", u.Hostname())
	}
	return "wss://" + u.Host, nil
}

// validateWSPath strictly validates a stored/imported/discovered ws_path: it must be an
// absolute path ("/..."), without scheme, "@", backslash, percent-escapes, query,
// fragment, "//", "." or ".." segments, and only printable ASCII. Empty returns "".
func validateWSPath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", nil
	}
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") {
		return "", fmt.Errorf("ws_path 必须以单个 / 开头")
	}
	if strings.Contains(p, "://") || strings.ContainsAny(p, "@\\%?#") {
		return "", fmt.Errorf("ws_path 包含非法字符")
	}
	for _, r := range p {
		if r <= ' ' || r >= 0x7f {
			return "", fmt.Errorf("ws_path 包含非法字符")
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("ws_path 不得包含 . 或 .. 段")
		}
	}
	return p, nil
}

// accountWSEndpoint returns the account's ws_host / ws_path after strict validation.
// An untrusted ws_host is an error (never downgraded to ws://); an invalid ws_path
// falls back to "" so the caller uses the default stream path.
func accountWSEndpoint(acct *auth.Account, allowCustom bool) (string, string, error) {
	if acct == nil {
		return "", "", nil
	}
	host, err := validateWSHost(acct.WSHost, allowCustom)
	if err != nil {
		return "", "", (&UpstreamError{
			Kind:       ErrKindHandshake,
			StatusCode: http.StatusBadGateway,
			Message:    "账号 ws_host 未通过安全校验（" + err.Error() + "），请重新授权",
		}).Normalize()
	}
	path, perr := validateWSPath(acct.WSPath)
	if perr != nil {
		path = ""
	}
	return host, path, nil
}

// UnwrapQBS unwraps Amazon Quick's double-wrapped qbs-event / invokeAgent response.
func UnwrapQBS(raw []byte) (int, any) {
	var outer map[string]any
	if err := json.Unmarshal(raw, &outer); err != nil {
		return 200, string(raw)
	}
	var inner any = outer
	if er, ok := outer["eventResponse"].(map[string]any); ok {
		if iar, ok := er["invokeAgentResponse"]; ok {
			inner = iar
		}
	} else if iar, ok := outer["invokeAgentResponse"]; ok {
		inner = iar
	}
	if s, ok := inner.(string); ok {
		var parsed any
		if json.Unmarshal([]byte(s), &parsed) == nil {
			inner = parsed
		}
	}
	im, ok := inner.(map[string]any)
	if !ok {
		return 200, inner
	}
	if ar, ok := im["api_response"].(map[string]any); ok {
		im = ar
	}
	status := 200
	if st := asFloat(im["status"]); st > 0 {
		status = int(st)
	} else if st := asFloat(im["statusCode"]); st > 0 {
		status = int(st)
	}
	body, hasBody := im["body"]
	if !hasBody {
		body = im
	}
	if bs, ok := body.(string); ok {
		var parsed any
		if json.Unmarshal([]byte(bs), &parsed) == nil {
			body = parsed
		}
	}
	return status, body
}

// InvokeQBS invokes an Amazon Quick agent backend path (e.g. "profile/usage", "api/ws-rpc", "files/upload/<id>").
func (c *Client) InvokeQBS(ctx context.Context, acct *auth.Account, path, method string, body map[string]any) (any, error) {
	base, err := c.tenantBase(acct)
	if err != nil {
		return nil, err
	}
	path = strings.TrimLeft(strings.TrimSpace(path), "/")
	if method == "" {
		method = http.MethodGet
	}
	if body == nil {
		body = map[string]any{}
	}

	cl, err := c.accountHTTPClient(acct, 20*time.Second)
	if err != nil {
		return nil, err
	}

	var (
		endpoint string
		payload  []byte
	)
	if acct.IsGateway() {
		gwHost, _, gerr := c.gatewayHost(ctx, acct)
		if gerr != nil {
			return nil, gerr
		}
		scheme := "https"
		if strings.HasPrefix(base, "http://") {
			scheme = "http"
		}
		q := url.Values{
			"innerPath": {path},
			"_method":   {method},
		}
		awsAcct := acct.AWSAccountID
		if awsAcct == "" {
			awsAcct = "default"
		}
		endpoint = fmt.Sprintf("%s://%s/accounts/%s/invocations/rpc?%s", scheme, gwHost, url.PathEscape(awsAcct), q.Encode())
		payload, err = json.Marshal(body)
	} else {
		endpoint = base + "/integration/quick-work/qbs-event"
		ev := map[string]any{
			"eventType": "invokeAgent",
			"eventBody": map[string]any{
				"invokeAgent": map[string]any{
					"path":        path,
					"queryParams": map[string]any{"_method": method},
					"body":        body,
				},
			},
		}
		payload, err = json.Marshal(ev)
	}
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+acct.AccessToken)
	req.Header.Set("x-amzn-qs-internal-trace-id", auth.NewUUID())

	resp, err := cl.Do(req)
	if err != nil {
		return nil, &UpstreamError{Kind: ErrKindTransport, StatusCode: 502, Message: fmt.Sprintf("QBS %s failed: %v", path, err)}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, (&UpstreamError{
			Kind:       ErrKindHandshake,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("Amazon Quick QBS %s returned HTTP %d", path, resp.StatusCode),
		}).Normalize()
	}

	status, unwrapped := UnwrapQBS(raw)
	if status >= 400 {
		return nil, (&UpstreamError{
			Kind:       ErrKindUpstream,
			StatusCode: status,
			Message:    fmt.Sprintf("Amazon Quick answered %d for %s", status, path),
		}).Normalize()
	}
	return unwrapped, nil
}

// GetQuota fetches subscription & usage quotas for acct, preferring QBS profile/usage
// and falling back to user-info usageSummary or Gateway agenticmetering.
func (c *Client) GetQuota(ctx context.Context, acct *auth.Account) (pool.QuotaInfo, error) {
	if raw, err := c.InvokeQBS(ctx, acct, "profile/usage", http.MethodGet, nil); err == nil {
		if m, ok := raw.(map[string]any); ok {
			if q := parseProfileUsage(m); q.Known {
				return q, nil
			}
		}
	}

	// Fallback: Gateway agenticmetering or AIDP user-info usageSummary.
	base, err := c.tenantBase(acct)
	if err != nil {
		return pool.QuotaInfo{}, err
	}
	cl, err := c.accountHTTPClient(acct, 12*time.Second)
	if err != nil {
		return pool.QuotaInfo{}, err
	}

	var req *http.Request
	if acct.IsGateway() {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, base+"/agenticmetering/v1/get-available-entitlement-units", nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, base+"/integration/quick-work/user-info", strings.NewReader(`{"excludeUserInfo":true}`))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		return pool.QuotaInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+acct.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := cl.Do(req)
	if err != nil {
		return pool.QuotaInfo{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if resp.StatusCode != http.StatusOK {
		return pool.QuotaInfo{}, fmt.Errorf("quota endpoint HTTP %d", resp.StatusCode)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return pool.QuotaInfo{}, err
	}
	if acct.IsGateway() {
		if q := parseGatewayMetering(data); q.Known {
			return q, nil
		}
	} else if us, ok := data["usageSummary"].(map[string]any); ok {
		if q := parseUsageSummary(us); q.Known {
			return q, nil
		}
	}
	return pool.QuotaInfo{Known: false, UpdatedAt: time.Now().UnixMilli(), UnavailableReason: "上游未提供额度数据"}, nil
}

// CheckSpentAllowance queries profile/usage briefly after an upstream turn refusal
// to determine whether session or monthly quota is spent and how long to rest the account.
func (c *Client) CheckSpentAllowance(ctx context.Context, acct *auth.Account) *SpentAllowance {
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	q, err := c.GetQuota(qctx, acct)
	if err != nil || !q.Known {
		return nil
	}
	return SpentAllowanceFromQuota(q, time.Now())
}

// SpentAllowanceFromQuota computes exhausted window & reset duration from QuotaInfo.
func SpentAllowanceFromQuota(q pool.QuotaInfo, now time.Time) *SpentAllowance {
	if !q.Known {
		return nil
	}
	var found []SpentAllowance
	calcDur := func(resetsAt int64, resumeMin float64) time.Duration {
		if resetsAt > 0 {
			d := time.Until(time.UnixMilli(resetsAt))
			if d > 0 {
				return d
			}
			d2 := time.UnixMilli(resetsAt).Sub(now)
			if d2 > 0 {
				return d2
			}
		}
		if resumeMin > 0 {
			return time.Duration(math.Round(resumeMin*60)) * time.Second
		}
		return 0
	}
	sessionSpent := (q.SessionLimit > 0 && q.SessionUsed >= q.SessionLimit) || (q.SessionLimit == 0 && q.SessionPercent >= 100)
	if sessionSpent {
		found = append(found, SpentAllowance{
			Window:     "session",
			RetryAfter: calcDur(q.SessionResetsAt, q.SessionResumeMin),
		})
	}
	monthlySpent := (q.MonthlyLimit > 0 && q.MonthlyUsed >= q.MonthlyLimit) || (q.MonthlyLimit == 0 && q.MonthlyPercent >= 100)
	hasOverageRoom := q.OverageLimit > 0 && q.OverageUsed < q.OverageLimit
	if monthlySpent && !hasOverageRoom {
		found = append(found, SpentAllowance{
			Window:     "monthly",
			RetryAfter: calcDur(q.MonthlyResetsAt, 0),
		})
	}
	if len(found) == 0 {
		return nil
	}
	best := found[0]
	for _, item := range found[1:] {
		if item.RetryAfter > best.RetryAfter {
			best = item
		}
	}
	return &best
}

// CheckAdvanced checks via api/ws-rpc get_settings (cached 2 min) whether the account has advanced mode enabled.
func (c *Client) CheckAdvanced(ctx context.Context, acct *auth.Account) (bool, error) {
	if acct == nil {
		return false, nil
	}
	key := acct.TenantURL + "|" + acct.UID
	c.settingsMu.Lock()
	if hit, ok := c.settingsCache[key]; ok && time.Since(hit.at) < 2*time.Minute {
		c.settingsMu.Unlock()
		return hit.advanced, nil
	}
	c.settingsMu.Unlock()

	res, err := c.InvokeQBS(ctx, acct, "api/ws-rpc", http.MethodPost, map[string]any{
		"type":    "get_settings",
		"payload": map[string]any{},
	})
	if err != nil {
		return false, err
	}
	var payload map[string]any
	if m, ok := res.(map[string]any); ok {
		if frames, ok := m["frames"].([]any); ok {
			for _, f := range frames {
				if fm, ok := f.(map[string]any); ok && fm["type"] == "settings" {
					if pm, ok := fm["payload"].(map[string]any); ok {
						payload = pm
						break
					}
				}
			}
		}
		if payload == nil {
			if pm, ok := m["payload"].(map[string]any); ok {
				payload = pm
			}
		}
	}
	adv := false
	if payload != nil {
		if v, ok := payload["advanced_mode_enabled"].(bool); ok && v {
			adv = true
		}
		if slots, ok := payload["model_slots"].(map[string]any); ok {
			if _, has := slots["advanced"]; has {
				adv = true
			}
		}
		if modes, ok := payload["agent_modes"].([]any); ok {
			for _, item := range modes {
				if strings.EqualFold(fmt.Sprint(item), "advanced") {
					adv = true
				}
			}
		}
	}
	c.settingsMu.Lock()
	if len(c.settingsCache) > 64 {
		c.settingsCache = map[string]settingsCacheEntry{}
	}
	c.settingsCache[key] = settingsCacheEntry{at: time.Now(), advanced: adv, raw: payload}
	c.settingsMu.Unlock()
	return adv, nil
}

// DLP status polling budget for UploadAttachment (variables so tests can shorten them).
var (
	dlpPollAttempts = 30
	dlpPollInterval = 600 * time.Millisecond
)

// dlpInconclusiveCode marks an UploadAttachment failure where DLP never reached a verdict.
const dlpInconclusiveCode = "dlp_inconclusive"

// UploadAttachment uploads bytes to Amazon Quick, polls DLP status until completed, and delivers
// the attachment to threadID via qbs-event files/upload/<threadId>.
func (c *Client) UploadAttachment(ctx context.Context, acct *auth.Account, threadID, name, mimeType string, data []byte, strictDLP bool) (Attachment, error) {
	if acct.IsGateway() {
		return Attachment{}, &UpstreamError{Kind: ErrKindInvalid, StatusCode: 400, Message: "Gateway 账号暂不支持附件上传"}
	}
	if len(data) == 0 {
		return Attachment{}, &UpstreamError{Kind: ErrKindInvalid, StatusCode: 400, Message: "附件内容为空"}
	}
	base, err := c.tenantBase(acct)
	if err != nil {
		return Attachment{}, err
	}
	mimeType = strings.ToLower(strings.TrimSpace(strings.Split(mimeType, ";")[0]))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	cl, err := c.accountHTTPClient(acct, 60*time.Second)
	if err != nil {
		return Attachment{}, err
	}

	// Step 1: Upload raw bytes.
	q := url.Values{
		"name":          {name},
		"contentType":   {mimeType},
		"contentLength": {strconv.Itoa(len(data))},
	}
	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/integration/quick-work/upload-attachment?"+q.Encode(), bytes.NewReader(data))
	if err != nil {
		return Attachment{}, err
	}
	upReq.Header.Set("Authorization", "Bearer "+acct.AccessToken)
	upReq.Header.Set("Content-Type", "application/octet-stream")
	upReq.Header.Set("x-amzn-qs-internal-trace-id", auth.NewUUID())

	upResp, err := cl.Do(upReq)
	if err != nil {
		return Attachment{}, &UpstreamError{Kind: ErrKindTransport, StatusCode: 502, Message: fmt.Sprintf("上传附件失败: %v", err)}
	}
	upBody, _ := io.ReadAll(io.LimitReader(upResp.Body, 256*1024))
	_ = upResp.Body.Close()
	if upResp.StatusCode != http.StatusOK {
		return Attachment{}, (&UpstreamError{
			Kind:       ErrKindHandshake,
			StatusCode: upResp.StatusCode,
			Message:    fmt.Sprintf("上传附件返回 HTTP %d", upResp.StatusCode),
		}).Normalize()
	}
	var upObj map[string]any
	_ = json.Unmarshal(upBody, &upObj)
	attID, _ := upObj["attachmentId"].(string)
	if strings.TrimSpace(attID) == "" {
		return Attachment{}, &UpstreamError{Kind: ErrKindUpstream, StatusCode: 502, Message: "Amazon Quick 未返回 attachmentId"}
	}

	// Step 2: Poll DLP scan status. Fail closed: without a COMPLETED/SKIPPED/NOT_APPLICABLE
	// verdict inside the polling budget the attachment is never delivered.
	concluded := false
	lastStatus := ""
	for i := 0; i < dlpPollAttempts && !concluded; i++ {
		if ctx.Err() != nil {
			return Attachment{}, ctx.Err()
		}
		dlpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/integration/quick-work/attachment-dlp-status?attachmentId="+url.QueryEscape(attID), nil)
		if err != nil {
			return Attachment{}, err
		}
		dlpReq.Header.Set("Authorization", "Bearer "+acct.AccessToken)
		dlpResp, err := cl.Do(dlpReq)
		if err == nil {
			dlpBody, _ := io.ReadAll(io.LimitReader(dlpResp.Body, 64*1024))
			_ = dlpResp.Body.Close()
			if dlpResp.StatusCode == http.StatusUnauthorized || dlpResp.StatusCode == http.StatusForbidden {
				return Attachment{}, (&UpstreamError{
					Kind:       ErrKindHandshake,
					StatusCode: dlpResp.StatusCode,
					Code:       dlpInconclusiveCode,
					Message:    fmt.Sprintf("附件 DLP 检查返回 HTTP %d", dlpResp.StatusCode),
				}).Normalize()
			}
			if dlpResp.StatusCode == http.StatusOK {
				var dlp map[string]any
				if json.Unmarshal(dlpBody, &dlp) == nil {
					status := strings.ToUpper(strings.TrimSpace(firstMapStr(dlp, "dlpJobStatus", "DlpJobStatus")))
					action := strings.ToUpper(strings.TrimSpace(firstMapStr(dlp, "policyAction", "PolicyAction")))
					lastStatus = status
					if status == "COMPLETED" || status == "SKIPPED" || status == "NOT_APPLICABLE" {
						if action != "" && action != "ALLOW" && (strictDLP || action != "WARN") {
							return Attachment{}, &UpstreamError{
								Kind:       ErrKindBlocked,
								StatusCode: 400,
								Message:    fmt.Sprintf("Amazon Quick DLP 策略拦截了该附件 (%s)", action),
							}
						}
						concluded = true
						break
					}
					if status == "FAILED" || status == "ERROR" {
						return Attachment{}, (&UpstreamError{
							Kind:       ErrKindUpstream,
							StatusCode: 502,
							Code:       dlpInconclusiveCode,
							Message:    fmt.Sprintf("Amazon Quick 附件 DLP 扫描失败 (%s)", status),
						}).Normalize()
					}
				}
			}
		}
		if i+1 < dlpPollAttempts {
			select {
			case <-ctx.Done():
				return Attachment{}, ctx.Err()
			case <-time.After(dlpPollInterval):
			}
		}
	}
	if !concluded {
		if lastStatus == "" {
			lastStatus = "unknown"
		}
		return Attachment{}, (&UpstreamError{
			Kind:    ErrKindTimeout,
			Code:    dlpInconclusiveCode,
			Message: fmt.Sprintf("Amazon Quick 附件 DLP 扫描在 %d 次轮询内未得出结论（最后状态 %s），已按失败关闭处理，附件未发送", dlpPollAttempts, lastStatus),
		}).Normalize()
	}

	// Step 3: Deliver attachment into thread.
	delivered, err := c.InvokeQBS(ctx, acct, "files/upload/"+url.PathEscape(threadID), http.MethodPost, map[string]any{
		"attachmentId": attID,
	})
	if err != nil {
		return Attachment{}, err
	}
	attPath := ""
	if dm, ok := delivered.(map[string]any); ok {
		if p, ok := dm["path"].(string); ok && p != "" {
			attPath = p
		} else if files, ok := dm["files"].([]any); ok && len(files) > 0 {
			if f0, ok := files[0].(map[string]any); ok {
				if p, ok := f0["path"].(string); ok {
					attPath = p
				}
			}
		}
	}
	if attPath == "" {
		attPath = name
	}
	attType := "file"
	if strings.HasPrefix(mimeType, "image/") {
		attType = "image"
	}
	sum := sha256.Sum256(data)
	return Attachment{
		Type:          attType,
		Name:          name,
		Size:          len(data),
		MimeType:      mimeType,
		Path:          attPath,
		AttachmentID:  attID,
		ContentSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

func parseProfileUsage(raw map[string]any) pool.QuotaInfo {
	q := pool.QuotaInfo{
		Unit:      "credits",
		UpdatedAt: time.Now().UnixMilli(),
	}
	if sub, ok := raw["subscription"].(map[string]any); ok {
		st := strings.TrimSpace(fmt.Sprint(sub["subscription_type"]))
		if st != "" && st != "<nil>" {
			if lbl, ok := planLabels[strings.ToUpper(st)]; ok {
				q.Plan = lbl
			} else {
				q.Plan = st
			}
		}
		if ft, ok := sub["free_trial_metadata"].(map[string]any); ok {
			q.TrialUntil = parseEpochMs(ft["expiry_date"])
		}
	}
	if q.Plan == "" {
		q.Plan = "Amazon Quick"
	}

	if m, ok := raw["monthly"].(map[string]any); ok {
		q.MonthlyUsed = asFloat(m["used"])
		q.MonthlyLimit = asFloat(m["limit"])
		q.MonthlyPercent = asFloat(m["percent"])
		if q.MonthlyLimit > 0 && q.MonthlyPercent == 0 {
			q.MonthlyPercent = math.Min(100, q.MonthlyUsed/q.MonthlyLimit*100)
		}
		q.MonthlyResetsAt = parseEpochMs(m["resets_at"])
		if q.MonthlyLimit > 0 || q.MonthlyPercent > 0 || m["used"] != nil {
			q.Known = true
		}
	}
	if ov, ok := raw["overage_monthly"].(map[string]any); ok {
		q.OverageUsed = asFloat(ov["used"])
		q.OverageLimit = asFloat(ov["limit"])
	}
	if s, ok := raw["session"].(map[string]any); ok {
		q.SessionUsed = asFloat(s["used"])
		q.SessionLimit = asFloat(s["limit"])
		q.SessionPercent = asFloat(s["percent"])
		if q.SessionLimit > 0 && q.SessionPercent == 0 {
			q.SessionPercent = math.Min(100, q.SessionUsed/q.SessionLimit*100)
		}
		q.SessionResetsAt = parseEpochMs(s["resets_at"])
		q.SessionResumeMin = asFloat(s["resume_in_minutes"])
		if q.SessionLimit > 0 || q.SessionPercent > 0 || s["used"] != nil {
			q.Known = true
		}
	}
	return q
}

func parseUsageSummary(summary map[string]any) pool.QuotaInfo {
	q := pool.QuotaInfo{
		Plan:      "Amazon Quick",
		Unit:      "agent_minutes",
		UpdatedAt: time.Now().UnixMilli(),
	}
	if m, ok := summary["monthlyUsage"].(map[string]any); ok {
		prov := asFloat(m["provisionedUnits"])
		avail := asFloat(m["availableUnits"])
		pct := asFloat(m["usedPercentage"])
		if prov > 0 {
			q.MonthlyLimit = prov
			q.MonthlyUsed = math.Max(0, prov-avail)
			if pct == 0 {
				pct = q.MonthlyUsed / prov * 100
			}
		}
		q.MonthlyPercent = pct
		q.OverageLimit = asFloat(m["overageUnits"])
		q.MonthlyResetsAt = parseEpochMs(m["resetsAt"])
		if prov > 0 || m["usedPercentage"] != nil {
			q.Known = true
		}
	}
	if s, ok := summary["sessionUsage"].(map[string]any); ok {
		q.SessionPercent = asFloat(s["usedPercentage"])
		q.SessionResumeMin = asFloat(s["resumeInMinutes"])
		q.SessionResetsAt = parseEpochMs(s["resetsAt"])
		if s["usedPercentage"] != nil || q.SessionResumeMin > 0 {
			q.Known = true
		}
	}
	return q
}

func parseGatewayMetering(data map[string]any) pool.QuotaInfo {
	ents, ok := data["entitlements"].([]any)
	if !ok {
		return pool.QuotaInfo{}
	}
	for _, item := range ents {
		em, ok := item.(map[string]any)
		if !ok || em["unitType"] != "AUTOMATION_AGENT_HOUR_UNIT" {
			continue
		}
		prov := asFloat(em["numMinsProvisioned"])
		avail := asFloat(em["numMinsAvailable"])
		q := pool.QuotaInfo{
			Known:        true,
			Plan:         "Enterprise Gateway",
			Unit:         "agent_minutes",
			MonthlyLimit: prov,
			MonthlyUsed:  math.Max(0, prov-avail),
			OverageLimit: asFloat(em["numMinsOverage"]),
			UpdatedAt:    time.Now().UnixMilli(),
		}
		if prov > 0 {
			q.MonthlyPercent = math.Max(0, (prov-avail)/prov*100)
		}
		if rate, ok := em["rateLimitStatus"].(map[string]any); ok {
			q.SessionPercent = asFloat(rate["consumptionPercentage"])
			q.SessionResumeMin = asFloat(rate["estimatedMinutesToResume"])
		}
		return q
	}
	return pool.QuotaInfo{}
}

func parseEpochMs(v any) int64 {
	switch x := v.(type) {
	case float64:
		if x <= 0 || math.IsNaN(x) || math.IsInf(x, 0) {
			return 0
		}
		if x < 1e11 {
			return int64(x * 1000)
		}
		return int64(x)
	case int64:
		if x <= 0 {
			return 0
		}
		if x < 1e11 {
			return x * 1000
		}
		return x
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil && f > 0 {
			if f < 1e11 {
				return int64(f * 1000)
			}
			return int64(f)
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UnixMilli()
		}
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UnixMilli()
		}
	}
	return 0
}

func asFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0
		}
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return f
		}
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
			return f
		}
	}
	return 0
}

func firstMapStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

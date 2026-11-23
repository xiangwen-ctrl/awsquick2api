package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	enterpriseDefaultScope = "openid profile email"
)

var (
	socialDiscoveryURLs = map[string]string{
		"prod":  "https://quick.aws.com/sn",
		"beta":  "https://devtest.quicksuite.aws.dev/sn",
		"integ": "https://devtest.quicksuite.aws.dev/sn",
		"dev":   "https://devtest.quicksuite.aws.dev/sn",
	}
	socialDataPlanes = map[string]string{
		"prod":  "https://cell001.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
		"beta":  "https://cell001.dp.appintegrations.us-west-2.beta.plato.ai.aws.dev",
		"integ": "https://cell001.dp.appintegrations.us-west-2.beta.plato.ai.aws.dev",
		"dev":   "https://cell001.dp.appintegrations.us-west-2.beta.plato.ai.aws.dev",
	}
	socialScopes = map[string][]string{
		"prod":  {"quicksight:read_write"},
		"beta":  {"quicksight_test:read_write"},
		"integ": {"quicksight_test:read_write"},
		"dev":   {"quicksight_test:read_write"},
	}
	enterpriseDiscoveryURLs = map[string]string{
		"prod":  "https://quicksight.aws.amazon.com/sn/start/app-integrations/quickwork-enterprise-login",
		"beta":  "https://spaceneedle-alpha.amazon.com/sn/start/app-integrations/quickwork-enterprise-login",
		"integ": "https://spaceneedle-beta.amazon.com/sn/start/app-integrations/quickwork-enterprise-login",
		"dev":   "https://spaceneedle-alpha.amazon.com/sn/start/app-integrations/quickwork-enterprise-login",
	}

	trustedHostSuffixes = []string{
		".amazonaws.com",
		".amazoncognito.com",
		".aws.amazon.com",
		".quick.aws.com",
		".signin.aws",
		".awsapps.com",
		".api.aws",
		".quicksuite.aws.dev",
		".plato.ai.aws.dev",
		".amazon.com",
	}
	platoCellHostRE = regexp.MustCompile(`^(?:qbs-)?cell[0-9a-f-]+\.dp\.appintegrations\.[a-z]{2}(?:-[a-z]+)+-\d\.(?:prod|beta)\.plato\.ai\.aws\.dev$`)
	regionRE        = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-\d$`)
	refusedOAuthRE  = regexp.MustCompile(`(?i)invalid_(grant|client)|InvalidGrant|InvalidClient|UnauthorizedClient|unauthorized_client|ExpiredToken`)
)

// EndpointOverrides allows overriding AWS endpoints for private stages or local mock tests.
type EndpointOverrides struct {
	OIDCBase     string
	DiscoveryURL string
	DataPlaneURL string
}

func (o EndpointOverrides) hasCustom() bool {
	return strings.TrimSpace(o.OIDCBase) != "" ||
		strings.TrimSpace(o.DiscoveryURL) != "" ||
		strings.TrimSpace(o.DataPlaneURL) != ""
}

// StepError represents an error during OAuth login or token refresh with HTTP status semantics.
type StepError struct {
	Status  int
	Message string
	Expired bool // true when AWS terminally rejected the OAuth grant/client
}

func (e *StepError) Error() string { return e.Message }

// ValidateTrustedURL checks that raw is a valid HTTPS AWS/Quick/Google OAuth endpoint
// to prevent SSRF via forged discovery redirects. When allowCustom is true (local test overrides),
// localhost/127.0.0.1 HTTP URLs are also permitted.
func ValidateTrustedURL(raw string, allowCustom bool) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", &StepError{Status: 400, Message: "授权发现端点为空"}
	}
	for _, r := range v {
		if r < 32 || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return "", &StepError{Status: 400, Message: "授权发现端点包含非法字符"}
		}
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", &StepError{Status: 400, Message: "授权发现端点格式无效"}
	}
	host := strings.ToLower(u.Hostname())
	if allowCustom && (host == "127.0.0.1" || host == "localhost" || host == "::1") && (u.Scheme == "http" || u.Scheme == "https") {
		return v, nil
	}
	if u.Scheme != "https" {
		return "", &StepError{Status: 400, Message: fmt.Sprintf("授权发现端点必须使用 HTTPS (%s)", host)}
	}
	if p := u.Port(); p != "" && p != "443" {
		return "", &StepError{Status: 400, Message: fmt.Sprintf("授权发现端点端口不受支持 (%s:%s)", host, p)}
	}
	if host == "quick.aws.com" || host == "accounts.google.com" || host == "oauth2.googleapis.com" || platoCellHostRE.MatchString(host) {
		return v, nil
	}
	for _, suf := range trustedHostSuffixes {
		if strings.HasSuffix(host, suf) {
			return v, nil
		}
	}
	return "", &StepError{Status: 400, Message: fmt.Sprintf("授权发现返回了不受支持的端点 (%s)", host)}
}

func dataPlaneURL(stage string, ov EndpointOverrides) string {
	if s := strings.TrimRight(strings.TrimSpace(ov.DataPlaneURL), "/"); s != "" {
		return s
	}
	if v, ok := socialDataPlanes[NormalizeStage(stage)]; ok {
		return v
	}
	return socialDataPlanes["prod"]
}

func oidcBaseURL(region string, ov EndpointOverrides) string {
	if s := strings.TrimRight(strings.TrimSpace(ov.OIDCBase), "/"); s != "" {
		return s
	}
	if !regionRE.MatchString(region) {
		region = "us-east-1"
	}
	return fmt.Sprintf("https://oidc.%s.amazonaws.com", region)
}

func scopesForStage(stage string) []string {
	if sc, ok := socialScopes[NormalizeStage(stage)]; ok {
		return sc
	}
	return socialScopes["prod"]
}

// DiscoveryURL builds the initial browser sign-in URL with qwSurface parameters.
func DiscoveryURL(provider, stage, region, nonce string, port int, appVersion string, ov EndpointOverrides) string {
	surface := fmt.Sprintf("desktop:%s:%d:%s", nonce, port, appVersion)
	q := url.Values{}
	q.Set("qwSurface", surface)

	if s := strings.TrimSpace(ov.DiscoveryURL); s != "" {
		sep := "?"
		if strings.Contains(s, "?") {
			sep = "&"
		}
		return s + sep + q.Encode()
	}
	st := NormalizeStage(stage)
	if IsEnterpriseDiscovery(provider) {
		base := enterpriseDiscoveryURLs[st]
		if base == "" {
			base = enterpriseDiscoveryURLs["prod"]
		}
		reg := strings.TrimSpace(region)
		if reg != "" && reg != "dynamic" && reg != "us-east-1" && regionRE.MatchString(reg) {
			if u, err := url.Parse(base); err == nil {
				u.Host = reg + "." + u.Host
				base = u.String()
			}
		}
		return base + "?" + q.Encode()
	}
	base := socialDiscoveryURLs[st]
	if base == "" {
		base = socialDiscoveryURLs["prod"]
	}
	return base + "?" + q.Encode()
}

// RedirectURI returns the OAuth redirect_uri expected for provider on port.
func RedirectURI(provider string, port int) string {
	if IsEnterpriseDiscovery(provider) {
		return fmt.Sprintf("http://localhost:%d", port)
	}
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

// ResourceFor extracts RFC 8707 audience origin (scheme://hostname without port/path) from tenantURL.
func ResourceFor(tenantURL string) string {
	t := strings.TrimSpace(tenantURL)
	if t == "" {
		return ""
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Hostname())
}

// DecodeJWT decodes the payload JSON object of a JWT (without verifying signature; claims are metadata hints only).
func DecodeJWT(token string) map[string]any {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 || parts[1] == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Fallback with padding
		raw, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil
	}
	return claims
}

// UserInfo holds normalized Amazon Quick user-info fields.
type UserInfo struct {
	Email        string
	UserName     string
	DisplayName  string
	UserARN      string
	AWSAccountID string
	AccountName  string
}

func oneLine(v any) string {
	if v == nil {
		return ""
	}
	s := fmt.Sprint(v)
	return strings.Join(strings.Fields(s), " ")
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			if s := oneLine(v); s != "" {
				return s
			}
		}
	}
	return ""
}

// NormalizeUserInfo extracts standard user fields from /integration/quick-work/user-info JSON.
func NormalizeUserInfo(raw map[string]any) UserInfo {
	src := raw
	if sub, ok := raw["userInfo"].(map[string]any); ok && sub != nil {
		src = sub
	}
	return UserInfo{
		Email:        firstString(src, "email", "emailAddress"),
		UserName:     firstString(src, "userName", "user_name", "username"),
		DisplayName:  firstString(src, "displayName", "display_name"),
		UserARN:      firstString(src, "quickSightExternalUserArn", "userArn", "user_arn"),
		AWSAccountID: firstString(src, "awsAccountId", "aws_account_id", "accountId"),
		AccountName:  firstString(src, "accountName", "account_name"),
	}
}

type tokenBundle struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int64
}

func parseTokens(raw map[string]any) tokenBundle {
	var exp int64
	for _, k := range []string{"expires_in", "expiresIn"} {
		if v, ok := raw[k]; ok {
			switch n := v.(type) {
			case float64:
				exp = int64(n)
			case int64:
				exp = n
			case json.Number:
				if parsed, err := n.Int64(); err == nil {
					exp = parsed
				}
			}
			if exp > 0 {
				break
			}
		}
	}
	return tokenBundle{
		AccessToken:  firstString(raw, "access_token", "accessToken"),
		RefreshToken: firstString(raw, "refresh_token", "refreshToken"),
		IDToken:      firstString(raw, "id_token", "idToken"),
		ExpiresIn:    exp,
	}
}

type httpStatusError struct {
	Status int
	Host   string
	Body   string
	Code   string
}

func (e *httpStatusError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("HTTP %d from %s (%s)", e.Status, e.Host, e.Code)
	}
	return fmt.Sprintf("HTTP %d from %s", e.Status, e.Host)
}

func doJSONRequest(ctx context.Context, client *http.Client, method, endpoint string, body any, headers map[string]string) (map[string]any, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return executeJSON(client, req)
}

func doFormRequest(ctx context.Context, client *http.Client, endpoint string, form url.Values) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return executeJSON(client, req)
}

func executeJSON(client *http.Client, req *http.Request) (map[string]any, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	host := req.URL.Host
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(raw))
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		var errObj map[string]any
		code := ""
		if json.Unmarshal(raw, &errObj) == nil {
			code = firstString(errObj, "error", "code", "errorCode")
		}
		return nil, &httpStatusError{Status: resp.StatusCode, Host: host, Body: snippet, Code: code}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return nil, fmt.Errorf("invalid JSON response from %s", host)
	}
	return out, nil
}

func userInfoBase(provider, stage, tenantURL string, ov EndpointOverrides) string {
	if IsEnterpriseDiscovery(provider) {
		return strings.TrimRight(strings.TrimSpace(tenantURL), "/")
	}
	t := strings.TrimRight(strings.TrimSpace(tenantURL), "/")
	if strings.Contains(t, "dp.appintegrations") || (ov.hasCustom() && t != "") {
		return t
	}
	return dataPlaneURL(stage, ov)
}

// FetchUserInfo calls /integration/quick-work/user-info using the account's access token.
func FetchUserInfo(ctx context.Context, client *http.Client, provider, stage, tenantURL, accessToken string, ov EndpointOverrides) (UserInfo, error) {
	if strings.TrimSpace(accessToken) == "" {
		return UserInfo{}, &StepError{Status: 401, Message: "token response has no access_token"}
	}
	base := userInfoBase(provider, stage, tenantURL, ov)
	if base == "" {
		return UserInfo{}, &StepError{Status: 400, Message: "discovery response has no tenant_url"}
	}
	if _, err := ValidateTrustedURL(base, ov.hasCustom()); err != nil {
		return UserInfo{}, err
	}
	raw, err := doJSONRequest(ctx, client, http.MethodPost, base+"/integration/quick-work/user-info", map[string]any{}, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	if err != nil {
		return UserInfo{}, err
	}
	return NormalizeUserInfo(raw), nil
}

func fetchServerMetadata(ctx context.Context, client *http.Client, authEndpoint string) map[string]any {
	u, err := url.Parse(authEndpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	mctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	raw, err := doJSONRequest(mctx, client, http.MethodGet, u.Scheme+"://"+u.Host+"/.well-known/oauth-authorization-server", nil, nil)
	if err != nil {
		return nil
	}
	return raw
}

func enterpriseScopeFromMetadata(meta map[string]any, hasClientSecret bool) string {
	if meta != nil {
		if arr, ok := meta["scopes_supported"].([]any); ok {
			var listed []string
			hasOpenID := false
			for _, item := range arr {
				if s, ok := item.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" {
						listed = append(listed, s)
						if s == "openid" {
							hasOpenID = true
						}
					}
				}
			}
			if len(listed) > 0 && !hasOpenID {
				return strings.Join(listed, " ")
			}
		}
	}
	if !hasClientSecret {
		return "openid profile email offline_access"
	}
	return enterpriseDefaultScope
}

func buildAccountFromTokens(base *Account, tokens tokenBundle, info UserInfo, ov EndpointOverrides) (*Account, error) {
	access := strings.TrimSpace(tokens.AccessToken)
	idToken := strings.TrimSpace(tokens.IDToken)
	if access == "" && idToken == "" {
		return nil, fmt.Errorf("token response has no access_token/id_token")
	}

	stage := NormalizeStage(base.Stage)
	provider := NormalizeProvider(base.Provider)
	tenant := strings.TrimRight(strings.TrimSpace(base.TenantURL), "/")
	if tenant == "" {
		tenant = dataPlaneURL(stage, ov)
	}
	if !strings.Contains(tenant, "://") {
		tenant = "https://" + tenant
	}
	parsed, err := url.Parse(tenant)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("cannot derive ws_host from tenant_url %q", tenant)
	}

	claims := DecodeJWT(idToken)
	if claims == nil {
		claims = DecodeJWT(access)
	}
	sub, _ := claims["sub"].(string)
	actorARN := strings.TrimSpace(info.UserARN)
	if actorARN == "" && strings.HasPrefix(sub, "arn:") {
		actorARN = sub
	}
	if actorARN == "" {
		actorARN = strings.TrimSpace(base.ActorARN)
	}

	region := strings.TrimSpace(base.Region)
	if region == "" {
		if r, ok := claims["region"].(string); ok && strings.TrimSpace(r) != "" {
			region = strings.TrimSpace(r)
		}
	}
	if region == "" {
		region = "us-east-1"
	}

	now := time.Now()
	var expiresAt int64
	if tokens.ExpiresIn > 0 {
		expiresAt = now.Add(time.Duration(tokens.ExpiresIn) * time.Second).UnixMilli()
	}
	if expVal, ok := claims["exp"].(float64); ok && expVal > 0 {
		jwtExpMs := int64(expVal * 1000)
		if expiresAt == 0 || (jwtExpMs > now.UnixMilli() && jwtExpMs < expiresAt) {
			expiresAt = jwtExpMs
		}
	}

	prefer := func(a, b string) string {
		if strings.TrimSpace(a) != "" {
			return strings.TrimSpace(a)
		}
		return strings.TrimSpace(b)
	}

	email := prefer(info.Email, base.Email)
	userName := prefer(info.UserName, base.UserName)
	displayName := prefer(info.DisplayName, base.DisplayNameVal)
	accountName := prefer(info.AccountName, base.AccountName)
	awsClaim, _ := claims["aws_account_id"].(string)
	awsAcctID := prefer(prefer(info.AWSAccountID, awsClaim), base.AWSAccountID)

	acctID := prefer(email, prefer(userName, prefer(displayName, prefer(actorARN, base.AccountID))))
	uid := strings.TrimSpace(base.UID)
	if uid == "" || !ValidUID(uid) {
		uid = MakeUID(provider, prefer(acctID, awsAcctID))
	}

	wsHost := parsed.Host
	if parsed.Scheme == "http" {
		wsHost = "ws://" + parsed.Host
	}
	wsPath := strings.TrimSpace(base.WSPath)
	if wsPath == "" && IsGatewayProvider(provider) {
		wsPath = GatewayWSPath
	}

	refresh := strings.TrimSpace(tokens.RefreshToken)
	if refresh == "" {
		refresh = strings.TrimSpace(base.RefreshToken)
	}

	deviceID := strings.TrimSpace(base.DeviceID)
	if !IsDeviceID(deviceID) {
		deviceID = NewUUID()
	}

	addedAt := base.AddedAt
	if addedAt == 0 {
		addedAt = now.UnixMilli()
	}

	return &Account{
		UID:                   uid,
		AccountID:             acctID,
		Email:                 email,
		UserName:              userName,
		DisplayNameVal:        displayName,
		CustomName:            base.CustomName,
		AccountName:           accountName,
		ActorARN:              actorARN,
		AWSAccountID:          awsAcctID,
		Provider:              provider,
		Stage:                 stage,
		Region:                region,
		IDCRegion:             base.IDCRegion,
		TenantURL:             tenant,
		WSHost:                wsHost,
		WSPath:                wsPath,
		Namespace:             base.Namespace,
		IssuerURL:             base.IssuerURL,
		TokenEndpoint:         base.TokenEndpoint,
		RedirectURI:           base.RedirectURI,
		ClientID:              base.ClientID,
		ClientSecret:          base.ClientSecret,
		ClientSecretExpiresAt: base.ClientSecretExpiresAt,
		AccessToken:           access,
		RefreshToken:          refresh,
		IDToken:               prefer(idToken, base.IDToken),
		ExpiresAt:             expiresAt,
		DeviceID:              deviceID,
		AddedAt:               addedAt,
		UpdatedAt:             now.UnixMilli(),
	}, nil
}

// RefreshTokens exchanges an account's refresh_token for fresh tokens and merges metadata.
// Uses context.WithoutCancel on the upstream token exchange so a caller abort never discards
// a server-rotated refresh_token.
func RefreshTokens(ctx context.Context, client *http.Client, acct *Account, ov EndpointOverrides) (*Account, error) {
	if acct == nil {
		return nil, &StepError{Status: 401, Message: "account is nil", Expired: true}
	}
	rt := strings.TrimSpace(acct.RefreshToken)
	if rt == "" || rt == "none" {
		return nil, &StepError{Status: 401, Message: "缺少 refresh_token，请重新登录授权", Expired: true}
	}

	// Shield token exchange from caller cancel so rotated refresh tokens are never lost.
	shieldCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	provider := NormalizeProvider(acct.Provider)
	var (
		raw map[string]any
		err error
	)
	if IsEnterpriseDiscovery(provider) || (acct.TokenEndpoint != "" && !strings.Contains(acct.TokenEndpoint, "oidc.") && acct.IDCRegion == "") {
		ep := strings.TrimSpace(acct.TokenEndpoint)
		if ep == "" {
			return nil, &StepError{Status: 401, Message: "账号缺少 token_endpoint，请重新授权", Expired: true}
		}
		if _, verr := ValidateTrustedURL(ep, ov.hasCustom()); verr != nil {
			return nil, verr
		}
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rt},
			"client_id":     {acct.ClientID},
		}
		if acct.ClientSecret != "" {
			form.Set("client_secret", acct.ClientSecret)
		}
		if res := ResourceFor(acct.TenantURL); res != "" {
			form.Set("resource", res)
		}
		raw, err = doFormRequest(shieldCtx, client, ep, form)
	} else {
		ep := strings.TrimSpace(acct.TokenEndpoint)
		if ep == "" {
			reg := acct.IDCRegion
			if reg == "" {
				reg = acct.Region
			}
			ep = oidcBaseURL(reg, ov) + "/token"
		}
		if _, verr := ValidateTrustedURL(ep, ov.hasCustom()); verr != nil {
			return nil, verr
		}
		raw, err = doJSONRequest(shieldCtx, client, http.MethodPost, ep, map[string]any{
			"clientId":     acct.ClientID,
			"clientSecret": acct.ClientSecret,
			"grantType":    "refresh_token",
			"refreshToken": rt,
		}, nil)
	}
	if err != nil {
		var he *httpStatusError
		if errors.As(err, &he) {
			transient := he.Code == "temporarily_unavailable" || he.Code == "server_error" || he.Code == "slow_down"
			terminal := !transient && (he.Status == 401 ||
				(he.Status == 400 && (refusedOAuthRE.MatchString(he.Body) || refusedOAuthRE.MatchString(he.Code) || (he.Code != "" && he.Code != "unknown_error"))))
			if terminal {
				return nil, &StepError{
					Status:  401,
					Message: fmt.Sprintf("Amazon Quick 拒绝了授权刷新，需要重新登录 (%s)", he.Error()),
					Expired: true,
				}
			}
			return nil, &StepError{Status: 503, Message: fmt.Sprintf("令牌刷新暂时失败 (%s)", he.Error())}
		}
		return nil, &StepError{Status: 503, Message: fmt.Sprintf("令牌刷新网络异常: %v", err)}
	}

	tokens := parseTokens(raw)
	if tokens.AccessToken == "" {
		return nil, &StepError{Status: 502, Message: "令牌刷新响应缺少 access_token"}
	}

	// Best-effort user-info update; do not fail refresh if user-info temporarily flakes after token rotation.
	info, uiErr := FetchUserInfo(shieldCtx, client, provider, acct.Stage, acct.TenantURL, tokens.AccessToken, ov)
	if uiErr != nil {
		info = UserInfo{}
	}
	return buildAccountFromTokens(acct, tokens, info, ov)
}

func randomURLToken(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sameSecret(a, b string) bool {
	if a == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// DiscoveryData stores the parameters returned in Step 1 of desktop sign-in.
type DiscoveryData struct {
	AuthEndpoint          string
	TokenEndpoint         string
	IssuerURL             string
	TenantURL             string
	Region                string
	IDCRegion             string
	Namespace             string
	ClientSecretExpiresAt int64
}

// LoginFlow represents one user-initiated PKCE desktop sign-in session.
type LoginFlow struct {
	ID            string
	Provider      string
	Stage         string
	Region        string
	Port          int
	AppVersion    string
	Overrides     EndpointOverrides
	RedirectURI   string
	State         string
	Nonce         string
	Verifier      string
	CreatedAt     time.Time
	Status        string // awaiting_discovery | discovering | awaiting_authorization | exchanging | authorized | failed | expired
	ErrorMsg      string
	AuthorizeURL  string
	ClientID      string
	ClientSecret  string
	Resource      string
	Discovery     *DiscoveryData
	ResultAccount *Account
}

// NewLoginFlow initializes a fresh one-time PKCE desktop login flow.
func NewLoginFlow(provider, stage, region string, port int, appVersion string, ov EndpointOverrides) *LoginFlow {
	p := NormalizeProvider(provider)
	st := NormalizeStage(stage)
	reg := strings.TrimSpace(region)
	if reg == "" {
		reg = "us-east-1"
	}
	if strings.TrimSpace(appVersion) == "" {
		appVersion = "1.2.4660"
	}
	return &LoginFlow{
		ID:          "login_" + randomURLToken(12),
		Provider:    p,
		Stage:       st,
		Region:      reg,
		Port:        port,
		AppVersion:  appVersion,
		Overrides:   ov,
		RedirectURI: RedirectURI(p, port),
		State:       randomURLToken(32),
		Nonce:       randomURLToken(32),
		Verifier:    randomURLToken(48),
		CreatedAt:   time.Now(),
		Status:      "awaiting_discovery",
	}
}

// Challenge returns the PKCE S256 code_challenge derived from Verifier.
func (f *LoginFlow) Challenge() string {
	sum := sha256.Sum256([]byte(f.Verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// LoginURL returns the Step 1 Amazon Quick discovery URL to open in a browser.
func (f *LoginFlow) LoginURL() string {
	return DiscoveryURL(f.Provider, f.Stage, f.Region, f.Nonce, f.Port, f.AppVersion, f.Overrides)
}

// ProcessDiscovery validates the Step 1 callback query, registers an IdC public client if needed,
// and returns the Step 2 AWS authorize URL.
func (f *LoginFlow) ProcessDiscovery(ctx context.Context, client *http.Client, q url.Values) (string, error) {
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(q.Get(k)); v != "" {
				return v
			}
		}
		return ""
	}
	if !sameSecret(q.Get("nonce"), f.Nonce) {
		return "", &StepError{Status: 400, Message: "授权发现 nonce 校验失败"}
	}
	if errParam := pick("error"); errParam != "" {
		msg := strings.TrimSpace("登录失败: " + errParam + " " + pick("error_description"))
		f.Status = "failed"
		f.ErrorMsg = msg
		return "", &StepError{Status: 400, Message: msg}
	}
	if f.AuthorizeURL != "" {
		return f.AuthorizeURL, nil
	}
	f.Status = "discovering"

	allowCustom := f.Overrides.hasCustom()
	isGateway := q.Has("namespace") && strings.TrimSpace(q.Get("namespace")) != ""
	issuerURL := pick("issuerUrl", "issuer_url", "issuer")

	// Branch A: Personal Social IdC (dynamic public client registration)
	if !isGateway && !IsEnterpriseDiscovery(f.Provider) && issuerURL != "" {
		if _, err := ValidateTrustedURL(issuerURL, allowCustom); err != nil {
			f.Status = "failed"
			f.ErrorMsg = err.Error()
			return "", err
		}
		idcRegion := pick("idcRegion", "idc_region")
		if idcRegion == "" {
			idcRegion = f.Region
		}
		if idcRegion == "" {
			idcRegion = "us-east-1"
		}
		if !allowCustom && !regionRE.MatchString(idcRegion) {
			f.Status = "failed"
			f.ErrorMsg = "IdC 区域无效"
			return "", &StepError{Status: 400, Message: f.ErrorMsg}
		}
		tenantURL := pick("tenantUrl", "tenant_url")
		if tenantURL != "" {
			if _, err := ValidateTrustedURL(tenantURL, allowCustom); err != nil {
				f.Status = "failed"
				f.ErrorMsg = err.Error()
				return "", err
			}
		}
		f.RedirectURI = fmt.Sprintf("http://127.0.0.1:%d", f.Port)
		oidcEP := oidcBaseURL(idcRegion, f.Overrides)
		regResp, err := doJSONRequest(ctx, client, http.MethodPost, oidcEP+"/client/register", map[string]any{
			"clientName":   "AmazonQuick-Desktop",
			"clientType":   "public",
			"scopes":       scopesForStage(f.Stage),
			"grantTypes":   []string{"authorization_code", "refresh_token"},
			"redirectUris": []string{f.RedirectURI},
			"issuerUrl":    issuerURL,
		}, nil)
		if err != nil {
			f.Status = "failed"
			f.ErrorMsg = fmt.Sprintf("AWS IdC 客户端注册失败: %v", err)
			return "", &StepError{Status: 502, Message: f.ErrorMsg}
		}
		f.ClientID = firstString(regResp, "clientId", "client_id")
		f.ClientSecret = firstString(regResp, "clientSecret", "client_secret")
		if f.ClientID == "" {
			f.Status = "failed"
			f.ErrorMsg = "AWS IdC 客户端注册未返回 clientId"
			return "", &StepError{Status: 502, Message: f.ErrorMsg}
		}
		var secExp int64
		if v, ok := regResp["clientSecretExpiresAt"].(float64); ok {
			secExp = int64(v)
		}
		f.Provider = ProviderSocial
		f.Discovery = &DiscoveryData{
			AuthEndpoint:          oidcEP + "/authorize",
			TokenEndpoint:         oidcEP + "/token",
			IssuerURL:             issuerURL,
			TenantURL:             tenantURL,
			Region:                idcRegion,
			IDCRegion:             idcRegion,
			ClientSecretExpiresAt: secExp,
		}
		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {f.ClientID},
			"redirect_uri":          {f.RedirectURI},
			"scope":                 {strings.Join(scopesForStage(f.Stage), " ")},
			"state":                 {f.State},
			"code_challenge":        {f.Challenge()},
			"code_challenge_method": {"S256"},
			"prompt":                {"login"},
		}
		f.AuthorizeURL = appendQueryParams(f.Discovery.AuthEndpoint, params)
		f.Status = "awaiting_authorization"
		return f.AuthorizeURL, nil
	}

	// Branch B: Enterprise / Gateway / Social Gateway
	authEP := pick("authEndpoint", "auth_endpoint")
	tokenEP := pick("tokenEndpoint", "token_endpoint")
	tenantURL := pick("tenantUrl", "tenant_url")
	if authEP == "" || tokenEP == "" {
		f.Status = "failed"
		f.ErrorMsg = "授权发现缺少 authEndpoint 或 tokenEndpoint"
		return "", &StepError{Status: 400, Message: f.ErrorMsg}
	}
	for _, ep := range []string{authEP, tokenEP} {
		if _, err := ValidateTrustedURL(ep, allowCustom); err != nil {
			f.Status = "failed"
			f.ErrorMsg = err.Error()
			return "", err
		}
	}
	if tenantURL != "" {
		if _, err := ValidateTrustedURL(tenantURL, allowCustom); err != nil {
			f.Status = "failed"
			f.ErrorMsg = err.Error()
			return "", err
		}
	}
	f.ClientID = pick("clientId", "client_id")
	f.ClientSecret = pick("clientSecret", "client_secret")
	if f.ClientID == "" {
		f.Status = "failed"
		f.ErrorMsg = "授权发现缺少 clientId"
		return "", &StepError{Status: 400, Message: f.ErrorMsg}
	}
	if isGateway {
		if f.Provider == ProviderSocial {
			f.Provider = ProviderSocialGateway
		} else {
			f.Provider = ProviderGateway
		}
	} else {
		f.Provider = ProviderEnterprise
	}
	f.RedirectURI = fmt.Sprintf("http://localhost:%d", f.Port)
	f.Resource = pick("resource")
	if f.Resource == "" {
		f.Resource = ResourceFor(tenantURL)
	}
	f.Discovery = &DiscoveryData{
		AuthEndpoint:  authEP,
		TokenEndpoint: tokenEP,
		IssuerURL:     issuerURL,
		TenantURL:     tenantURL,
		Region:        pick("region"),
		Namespace:     pick("namespace"),
	}
	meta := fetchServerMetadata(ctx, client, authEP)
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {f.ClientID},
		"redirect_uri":          {f.RedirectURI},
		"scope":                 {enterpriseScopeFromMetadata(meta, f.ClientSecret != "")},
		"state":                 {f.State},
		"code_challenge":        {f.Challenge()},
		"code_challenge_method": {"S256"},
	}
	if f.ClientSecret != "" {
		params.Set("access_type", "offline")
		params.Set("prompt", "consent")
	}
	if f.Resource != "" {
		params.Set("resource", f.Resource)
	}
	f.AuthorizeURL = appendQueryParams(authEP, params)
	f.Status = "awaiting_authorization"
	return f.AuthorizeURL, nil
}

// Complete validates the Step 2 OAuth callback query, exchanges the authorization code for tokens,
// fetches user-info, and returns the ready-to-save Account.
func (f *LoginFlow) Complete(ctx context.Context, client *http.Client, q url.Values) (*Account, error) {
	if errParam := strings.TrimSpace(q.Get("error")); errParam != "" {
		msg := strings.TrimSpace("授权被取消或失败: " + errParam + " " + q.Get("error_description"))
		f.Status = "failed"
		f.ErrorMsg = msg
		return nil, &StepError{Status: 400, Message: msg}
	}
	if f.AuthorizeURL == "" || f.Discovery == nil {
		return nil, &StepError{Status: 400, Message: "尚未完成第一步授权发现"}
	}
	if !sameSecret(q.Get("state"), f.State) {
		return nil, &StepError{Status: 400, Message: "OAuth state 校验失败"}
	}
	code := strings.TrimSpace(q.Get("code"))
	if code == "" {
		return nil, &StepError{Status: 400, Message: "OAuth 回调缺少 code 参数"}
	}

	f.Status = "exchanging"
	var (
		raw map[string]any
		err error
	)
	if f.Provider == ProviderSocial && f.Discovery.IDCRegion != "" {
		raw, err = doJSONRequest(ctx, client, http.MethodPost, f.Discovery.TokenEndpoint, map[string]any{
			"clientId":     f.ClientID,
			"clientSecret": f.ClientSecret,
			"grantType":    "authorization_code",
			"code":         code,
			"redirectUri":  f.RedirectURI,
			"codeVerifier": f.Verifier,
		}, nil)
	} else {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {f.RedirectURI},
			"client_id":     {f.ClientID},
			"code_verifier": {f.Verifier},
		}
		if f.ClientSecret != "" {
			form.Set("client_secret", f.ClientSecret)
		}
		if f.Resource != "" {
			form.Set("resource", f.Resource)
		}
		raw, err = doFormRequest(ctx, client, f.Discovery.TokenEndpoint, form)
	}
	if err != nil {
		f.Status = "failed"
		f.ErrorMsg = fmt.Sprintf("令牌交换失败: %v", err)
		return nil, &StepError{Status: 502, Message: f.ErrorMsg}
	}
	tokens := parseTokens(raw)
	if tokens.AccessToken == "" && tokens.IDToken == "" {
		f.Status = "failed"
		f.ErrorMsg = "令牌交换未返回 access_token"
		return nil, &StepError{Status: 502, Message: f.ErrorMsg}
	}
	info, err := FetchUserInfo(ctx, client, f.Provider, f.Stage, f.Discovery.TenantURL, tokens.AccessToken, f.Overrides)
	if err != nil {
		f.Status = "failed"
		f.ErrorMsg = fmt.Sprintf("获取用户信息失败: %v", err)
		return nil, &StepError{Status: 502, Message: f.ErrorMsg}
	}
	base := &Account{
		Provider:              f.Provider,
		Stage:                 f.Stage,
		Region:                firstNonEmpty(f.Discovery.Region, f.Region),
		IDCRegion:             f.Discovery.IDCRegion,
		TenantURL:             f.Discovery.TenantURL,
		Namespace:             f.Discovery.Namespace,
		IssuerURL:             f.Discovery.IssuerURL,
		TokenEndpoint:         f.Discovery.TokenEndpoint,
		RedirectURI:           f.RedirectURI,
		ClientID:              f.ClientID,
		ClientSecret:          f.ClientSecret,
		ClientSecretExpiresAt: f.Discovery.ClientSecretExpiresAt,
	}
	acct, err := buildAccountFromTokens(base, tokens, info, f.Overrides)
	if err != nil {
		f.Status = "failed"
		f.ErrorMsg = err.Error()
		return nil, &StepError{Status: 502, Message: err.Error()}
	}
	f.ResultAccount = acct
	f.Status = "authorized"
	f.ErrorMsg = ""
	// Clear one-time secrets promptly after completion.
	f.Verifier = ""
	f.Nonce = ""
	f.State = ""
	return acct, nil
}

func appendQueryParams(endpoint string, params url.Values) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		sep := "?"
		if strings.Contains(endpoint, "?") {
			sep = "&"
		}
		return endpoint + sep + params.Encode()
	}
	q := u.Query()
	for k, vals := range params {
		if len(vals) > 0 {
			q.Set(k, vals[0])
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

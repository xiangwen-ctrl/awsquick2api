package auth

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// --- SSRF hardening -------------------------------------------------------

const maxOAuthRedirects = 5

// guardRedirects returns a shallow copy of c whose redirects may not downgrade from HTTPS
// and may only leave the original host for another trusted AWS/Quick endpoint. This stops
// a trusted-looking endpoint from bouncing credential-bearing requests to arbitrary hosts.
func guardRedirects(c *http.Client) *http.Client {
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	cp := *c
	prev := c.CheckRedirect
	cp.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxOAuthRedirects {
			return fmt.Errorf("stopped after %d redirects", maxOAuthRedirects)
		}
		orig := via[0].URL
		if strings.EqualFold(orig.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
			return fmt.Errorf("refusing redirect that downgrades to %s", req.URL.Scheme)
		}
		if !strings.EqualFold(req.URL.Hostname(), orig.Hostname()) {
			if _, err := ValidateTrustedURL(req.URL.String(), false); err != nil {
				return fmt.Errorf("refusing redirect to untrusted host %s", req.URL.Hostname())
			}
		}
		if prev != nil {
			return prev(req, via)
		}
		return nil
	}
	return &cp
}

// customerHostedAWSLabels are DNS labels of AWS services under trusted suffixes whose
// hostnames serve content controlled by arbitrary AWS customers (buckets, API Gateway,
// load balancers, EC2 public DNS ...). They must never be treated as trusted OAuth/Quick
// endpoints even though they end in .amazonaws.com or .api.aws.
var customerHostedAWSLabels = map[string]bool{
	"s3":                   true,
	"s3-website":           true,
	"s3-accelerate":        true,
	"s3-control":           true,
	"s3-accesspoint":       true,
	"s3-object-lambda":     true,
	"execute-api":          true,
	"elb":                  true,
	"compute":              true,
	"compute-1":            true,
	"appsync-api":          true,
	"awsapprunner":         true,
	"es":                   true,
	"aos":                  true,
	"rds":                  true,
	"iot":                  true,
	"cloudfront":           true,
	"elasticbeanstalk":     true,
	"lambda-url":           true,
	"vpce":                 true,
	"awsglobalaccelerator": true,
	"amplifyapp":           true,
}

func isCustomerHostedAWSHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if !strings.HasSuffix(h, ".amazonaws.com") && !strings.HasSuffix(h, ".api.aws") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if customerHostedAWSLabels[label] ||
			strings.HasPrefix(label, "s3-") ||
			strings.HasPrefix(label, "ec2-") ||
			strings.HasPrefix(label, "dualstack") {
			return true
		}
	}
	return false
}

var (
	importRegionRE = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-\d$`)
	importWSPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~\-/]{0,255}$`)
	importWSHostRE = regexp.MustCompile(`^[A-Za-z0-9.\-]+(?::443)?$`)
)

// ValidateImportedAccountEndpoints strictly checks every endpoint an imported account would
// dial so a crafted migration bundle cannot redirect bearer tokens to a foreign host
// (SSRF / token exfiltration) or downgrade the chat stream to plaintext ws://.
func ValidateImportedAccountEndpoints(acct *Account) error {
	if acct == nil {
		return fmt.Errorf("account is nil")
	}
	for _, f := range []struct{ name, val string }{
		{"region", acct.Region},
		{"idc_region", acct.IDCRegion},
	} {
		if v := strings.TrimSpace(f.val); v != "" && !importRegionRE.MatchString(v) {
			return fmt.Errorf("%s 非法 (%q)", f.name, v)
		}
	}

	for _, f := range []struct{ name, val string }{
		{"tenant_url", acct.TenantURL},
		{"issuer_url", acct.IssuerURL},
		{"token_endpoint", acct.TokenEndpoint},
	} {
		v := strings.TrimSpace(f.val)
		if v == "" {
			continue
		}
		if _, err := ValidateTrustedURL(v, false); err != nil {
			return fmt.Errorf("%s: %v", f.name, err)
		}
	}

	if h := strings.TrimSpace(acct.WSHost); h != "" {
		low := strings.ToLower(h)
		switch {
		case strings.HasPrefix(low, "ws://"), strings.HasPrefix(low, "http://"):
			return fmt.Errorf("ws_host 禁止明文 ws:// / http:// (%q)", h)
		case strings.HasPrefix(low, "wss://"):
			h = h[len("wss://"):]
		case strings.HasPrefix(low, "https://"):
			h = h[len("https://"):]
		case strings.Contains(low, "://"):
			return fmt.Errorf("ws_host 协议不受支持 (%q)", h)
		}
		h = strings.TrimRight(h, "/")
		if !importWSHostRE.MatchString(h) {
			return fmt.Errorf("ws_host 格式非法 (%q)", acct.WSHost)
		}
		if _, err := ValidateTrustedURL("https://"+h, false); err != nil {
			return fmt.Errorf("ws_host: %v", err)
		}
	}

	if pth := strings.TrimSpace(acct.WSPath); pth != "" {
		if !importWSPathRE.MatchString(pth) || strings.HasPrefix(pth, "//") {
			return fmt.Errorf("ws_path 非法 (%q)", pth)
		}
		for _, seg := range strings.Split(pth, "/") {
			if seg == "." || seg == ".." {
				return fmt.Errorf("ws_path 不允许包含 . / .. 段 (%q)", pth)
			}
		}
	}
	return nil
}

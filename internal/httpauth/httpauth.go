// Package httpauth provides constant-time API key verification for OpenAI
// Bearer headers and Anthropic x-api-key headers.
package httpauth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Equal performs constant-time string comparison.
func Equal(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ExtractBearer extracts the token from "Authorization: Bearer <token>".
func ExtractBearer(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) < 7 {
		return ""
	}
	if !strings.EqualFold(h[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// VerifyBearer checks Authorization: Bearer against want. Empty want rejects authentication.
func VerifyBearer(r *http.Request, want string) bool {
	if want == "" {
		return false
	}
	got := ExtractBearer(r)
	return got != "" && Equal(got, want)
}

// VerifyAnthropic checks x-api-key first, then Authorization: Bearer.
func VerifyAnthropic(r *http.Request, want string) bool {
	if want == "" {
		return false
	}
	if k := strings.TrimSpace(r.Header.Get("x-api-key")); k != "" {
		return Equal(k, want)
	}
	return VerifyBearer(r, want)
}

// VerifyDual accepts either Authorization: Bearer or x-api-key (for /v1/models).
func VerifyDual(r *http.Request, want string) bool {
	return VerifyAnthropic(r, want)
}

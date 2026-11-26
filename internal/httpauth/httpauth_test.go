package httpauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEqual(t *testing.T) {
	if !Equal("", "") {
		t.Fatal("empty strings should be equal")
	}
	if !Equal("qk_secret_123", "qk_secret_123") {
		t.Fatal("identical strings should be equal")
	}
	if Equal("qk_secret_123", "qk_secret_124") {
		t.Fatal("different strings of same length must not be equal")
	}
	if Equal("qk_short", "qk_longer_key") {
		t.Fatal("different lengths must not be equal")
	}
}

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"Basic abcdef", ""},
		{"Bearer", ""},
		{"Bearer ", ""},
		{"Bearer qk_abc123", "qk_abc123"},
		{"bearer   qk_abc123  ", "qk_abc123"},
		{"BEARER qk_UPPER", "qk_UPPER"},
		{"  Bearer tok_trimmed  ", "tok_trimmed"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		if got := ExtractBearer(r); got != tc.want {
			t.Errorf("ExtractBearer(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestVerifyBearer(t *testing.T) {
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	if VerifyBearer(reqNoAuth, "") {
		t.Fatal("empty want should reject auth")
	}
	if VerifyBearer(reqNoAuth, "qk_secret") {
		t.Fatal("missing header must be rejected when want is set")
	}

	reqOK := httptest.NewRequest(http.MethodGet, "/", nil)
	reqOK.Header.Set("Authorization", "Bearer qk_secret")
	if !VerifyBearer(reqOK, "qk_secret") {
		t.Fatal("matching bearer token should pass")
	}
	if VerifyBearer(reqOK, "qk_other") {
		t.Fatal("mismatched bearer token must fail")
	}
}

func TestVerifyAnthropicAndDual(t *testing.T) {
	const want = "qk_expected_key"

	// Empty want rejects auth.
	emptyReq := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	if VerifyAnthropic(emptyReq, "") || VerifyDual(emptyReq, "") {
		t.Fatal("empty want should reject auth")
	}

	// Valid x-api-key passes.
	xKeyReq := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	xKeyReq.Header.Set("x-api-key", want)
	if !VerifyAnthropic(xKeyReq, want) || !VerifyDual(xKeyReq, want) {
		t.Fatal("valid x-api-key should pass")
	}

	// Wrong x-api-key must fail even if Authorization Bearer is valid (x-api-key takes precedence).
	conflictReq := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	conflictReq.Header.Set("x-api-key", "qk_wrong")
	conflictReq.Header.Set("Authorization", "Bearer "+want)
	if VerifyAnthropic(conflictReq, want) || VerifyDual(conflictReq, want) {
		t.Fatal("wrong x-api-key must fail even with valid Bearer fallback")
	}

	// Absent x-api-key falls back to Bearer.
	bearerReq := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	bearerReq.Header.Set("Authorization", "Bearer "+want)
	if !VerifyAnthropic(bearerReq, want) || !VerifyDual(bearerReq, want) {
		t.Fatal("Bearer fallback should pass when x-api-key is absent")
	}

	// Missing both headers fails.
	if VerifyAnthropic(emptyReq, want) || VerifyDual(emptyReq, want) {
		t.Fatal("missing headers must fail")
	}
}

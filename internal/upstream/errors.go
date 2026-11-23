package upstream

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	ErrKindHandshake = "handshake"
	ErrKindUpstream  = "upstream"
	ErrKindTooLarge  = "too_large"
	ErrKindBlocked   = "blocked"
	ErrKindTimeout   = "timeout"
	ErrKindTransport = "transport"
	ErrKindInvalid   = "invalid_request"
)

var throttledRE = regexp.MustCompile(`(?i)throttl|rate.?limit|too many requests|quota|limit exceeded|capacity`)

// UpstreamError represents a classified failure from Amazon Quick or the proxy gateway.
type UpstreamError struct {
	Kind       string
	StatusCode int
	Code       string
	Message    string
	RetryAfter time.Duration
	AccountUID string
}

func (e *UpstreamError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("upstream error (%s, HTTP %d)", e.Kind, e.StatusCode)
}

// IsAuthError reports whether the upstream rejected authentication (HTTP 401).
func (e *UpstreamError) IsAuthError() bool {
	return e != nil && e.StatusCode == http.StatusUnauthorized
}

// IsRateLimit reports whether the upstream indicated throttling or quota exhaustion.
func (e *UpstreamError) IsRateLimit() bool {
	if e == nil {
		return false
	}
	return e.StatusCode == http.StatusTooManyRequests || (e.Kind == ErrKindUpstream && throttledRE.MatchString(e.Message))
}

// IsRefusedByQuick reports whether the turn was refused by Amazon Quick itself (candidate for quota check).
func (e *UpstreamError) IsRefusedByQuick() bool {
	if e == nil {
		return false
	}
	return e.Kind == ErrKindUpstream || (e.Kind == ErrKindHandshake && e.StatusCode == http.StatusTooManyRequests)
}

// ShouldSwitchAccount reports whether rotating to another account before streaming starts makes sense.
func (e *UpstreamError) ShouldSwitchAccount() bool {
	if e == nil {
		return false
	}
	switch e.Kind {
	case ErrKindInvalid, ErrKindTooLarge, ErrKindBlocked:
		return false
	}
	switch e.StatusCode {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, 499:
		return false
	default:
		return true
	}
}

// ClassifyHTTPStatus normalizes StatusCode and Code from Kind + upstream status.
func (e *UpstreamError) Normalize() *UpstreamError {
	if e == nil {
		return nil
	}
	switch e.Kind {
	case ErrKindHandshake:
		switch e.StatusCode {
		case http.StatusUnauthorized:
			if e.Code == "" {
				e.Code = "upstream_session_unavailable"
			}
		case http.StatusForbidden:
			if e.Code == "" {
				e.Code = "upstream_forbidden"
			}
		case http.StatusTooManyRequests:
			if e.Code == "" {
				e.Code = "rate_limit_exceeded"
			}
		default:
			if e.StatusCode < 400 {
				e.StatusCode = http.StatusBadGateway
			}
			if e.Code == "" {
				e.Code = "upstream_error"
			}
		}
	case ErrKindTimeout:
		e.StatusCode = http.StatusGatewayTimeout
		if e.Code == "" {
			e.Code = "upstream_timeout"
		}
	case ErrKindTooLarge:
		e.StatusCode = http.StatusBadRequest
		if e.Code == "" {
			e.Code = "context_length_exceeded"
		}
	case ErrKindBlocked:
		e.StatusCode = http.StatusBadRequest
		if e.Code == "" {
			e.Code = "content_filter"
		}
	case ErrKindInvalid:
		if e.StatusCode == 0 {
			e.StatusCode = http.StatusBadRequest
		}
		if e.Code == "" {
			e.Code = "invalid_request_error"
		}
	case ErrKindUpstream:
		if throttledRE.MatchString(e.Message) || e.StatusCode == http.StatusTooManyRequests {
			e.StatusCode = http.StatusTooManyRequests
			if e.Code == "" {
				e.Code = "rate_limit_exceeded"
			}
		} else {
			if e.StatusCode == 0 {
				e.StatusCode = http.StatusBadGateway
			}
			if e.Code == "" {
				e.Code = "upstream_error"
			}
		}
	default:
		if e.StatusCode == 0 {
			e.StatusCode = http.StatusBadGateway
		}
		if e.Code == "" {
			e.Code = "upstream_error"
		}
	}
	if strings.TrimSpace(e.Message) == "" {
		e.Message = "unknown upstream error"
	}
	return e
}

package server

import (
	"fmt"
	"math"
)

// outputTokenLimit reads the protocol's fields in order of precedence.
func outputTokenLimit(body map[string]any, fields ...string) (int, error) {
	limit := 0
	for _, name := range fields {
		raw, exists := body[name]
		if !exists {
			continue
		}
		value, ok := raw.(float64)
		if !ok || value < 1 || value > math.MaxInt32 || value != math.Trunc(value) {
			return 0, fmt.Errorf("%s must be a positive integer", name)
		}
		if limit == 0 {
			limit = int(value)
		}
	}
	return limit, nil
}

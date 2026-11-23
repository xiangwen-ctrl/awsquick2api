package server

import (
	"net/http"
)

func (h *Handler) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	var poolSummary any
	if h.cfg.Pool != nil {
		poolSummary = h.cfg.Pool.Summary()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": ServiceName,
		"version": h.cfg.Version,
		"pool":    poolSummary,
	})
}

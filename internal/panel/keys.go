package panel

import (
	"errors"
	"net/http"
	"strings"

	"awsquick2api/internal/apikeys"
)

func (p *Panel) handleKeysList(w http.ResponseWriter, _ *http.Request) {
	if p.cfg.APIKeys == nil {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []apikeys.KeyView{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": p.cfg.APIKeys.List()})
}

func (p *Panel) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	if p.cfg.APIKeys == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "api key store unavailable"})
		return
	}
	var in apikeys.CreateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	view, plain, err := p.cfg.APIKeys.Create(in)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, apikeys.ErrKeyLimit) {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":        true,
		"key":       view,
		"plaintext": plain,
	})
}

func (p *Panel) handleKeyUpdate(w http.ResponseWriter, r *http.Request) {
	if p.cfg.APIKeys == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "api key store unavailable"})
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing key id"})
		return
	}
	var patch apikeys.UpdatePatch
	if !decodeJSON(w, r, &patch) {
		return
	}
	view, err := p.cfg.APIKeys.Update(id, patch)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, apikeys.ErrKeyNotFound) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": view})
}

func (p *Panel) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	if p.cfg.APIKeys == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "api key store unavailable"})
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing key id"})
		return
	}
	if err := p.cfg.APIKeys.Delete(id); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, apikeys.ErrKeyNotFound) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

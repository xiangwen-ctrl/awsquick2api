// Package panel serves the embedded single-page Web management console and
// its Bearer-authenticated JSON operational APIs under /panel/.
package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
	"awsquick2api/internal/httpauth"
	"awsquick2api/internal/pool"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/scheduler"
	"awsquick2api/internal/session"
	"awsquick2api/internal/upstream"
)

const (
	maxPanelBodyBytes  = 1 << 20  // 1 MiB
	maxImportBodyBytes = 10 << 20 // 10 MiB
)

// SaveConfigResult describes the outcome of persisting and hot-reloading config.json.
type SaveConfigResult struct {
	RestartRequired   []string
	EffectiveAPIKey   string
	EffectiveAdminKey string
	EnvOverrides      []string
}

type Config struct {
	Pool         *pool.Pool
	Vault        *auth.Vault
	Upstream     *upstream.Client
	Scheduler    *scheduler.Scheduler
	Session      *session.Router
	ReqLog       *reqlog.Recorder
	Live         *config.LiveHolder
	CallbackMgr  *auth.CallbackManager
	AuthDir      string
	ConfigPath   string
	ModelsPath   string
	Version      string
	EnvOverrides func() []string
	LoadConfig   func() (*config.Config, error)
	SaveConfig   func(raw []byte) (SaveConfigResult, error)
}

type Panel struct {
	cfg     Config
	mux     *http.ServeMux
	started time.Time
	saveMu  sync.Mutex
}

func New(cfg Config) *Panel {
	p := &Panel{
		cfg:     cfg,
		mux:     http.NewServeMux(),
		started: time.Now(),
	}

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	fileSrv := http.StripPrefix("/panel/", http.FileServer(http.FS(sub)))
	p.mux.Handle("GET /panel/", fileSrv)

	// Overview & Accounts
	p.mux.HandleFunc("GET /panel/api/overview", p.withAuth(p.handleOverview))
	p.mux.HandleFunc("GET /panel/api/accounts", p.withAuth(p.handleAccountsList))
	p.mux.HandleFunc("POST /panel/api/accounts/export-encrypted", p.withAuth(p.handleAccountsExportEncrypted))
	p.mux.HandleFunc("POST /panel/api/accounts/import", p.withAuth(p.handleAccountsImport))
	p.mux.HandleFunc("POST /panel/api/accounts/refresh-quotas", p.withAuth(p.handleRefreshAllQuotas))
	p.mux.HandleFunc("POST /panel/api/accounts/refresh-tokens", p.withAuth(p.handleRefreshAllTokens))
	p.mux.HandleFunc("POST /panel/api/accounts/{uid}/revive", p.withAuth(p.handleAccountRevive))
	p.mux.HandleFunc("POST /panel/api/accounts/{uid}/disable", p.withAuth(p.handleAccountDisable))
	p.mux.HandleFunc("POST /panel/api/accounts/{uid}/refresh", p.withAuth(p.handleAccountRefreshToken))
	p.mux.HandleFunc("POST /panel/api/accounts/{uid}/quota", p.withAuth(p.handleAccountQuota))
	p.mux.HandleFunc("POST /panel/api/accounts/{uid}/test", p.withAuth(p.handleAccountTest))
	p.mux.HandleFunc("PUT /panel/api/accounts/{uid}/name", p.withAuth(p.handleAccountRename))
	p.mux.HandleFunc("DELETE /panel/api/accounts/{uid}", p.withAuth(p.handleAccountDelete))

	// Native Amazon Quick Desktop OAuth Login (Local Auto + Remote Paste)
	p.mux.HandleFunc("POST /panel/api/login/start", p.withAuth(p.handleLoginStart))
	p.mux.HandleFunc("GET /panel/api/login/{id}/status", p.withAuth(p.handleLoginStatus))
	p.mux.HandleFunc("POST /panel/api/login/{id}/callback-url", p.withAuth(p.handleLoginCallbackURL))
	p.mux.HandleFunc("DELETE /panel/api/login/{id}", p.withAuth(p.handleLoginCancel))

	// Models, Config, Requests (metadata-only), Logs
	p.mux.HandleFunc("GET /panel/api/models", p.withAuth(p.handleModels))
	p.mux.HandleFunc("PATCH /panel/api/models/claude-aliases", p.withAuth(p.handleClaudeAliasesToggle))
	p.mux.HandleFunc("PUT /panel/api/models/{slot}/rename", p.withAuth(p.handleModelRename))
	p.mux.HandleFunc("PATCH /panel/api/models/{id}", p.withAuth(p.handleModelVisibilityToggle))
	p.mux.HandleFunc("GET /panel/api/config", p.withAuth(p.handleConfigGet))
	p.mux.HandleFunc("PUT /panel/api/config", p.withAuth(p.handleConfigSave))
	p.mux.HandleFunc("GET /panel/api/requests", p.withAuth(p.handleRequests))
	p.mux.HandleFunc("DELETE /panel/api/requests", p.withAuth(p.handleRequestsClear))
	p.mux.HandleFunc("GET /panel/api/logs", p.withAuth(p.handleLogs))

	return p
}

func (p *Panel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https: http:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if strings.HasPrefix(r.URL.Path, "/panel/api/") {
		w.Header().Set("Cache-Control", "no-store")
	}
	p.mux.ServeHTTP(w, r)
}

func (p *Panel) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := ""
		if p.cfg.Live != nil {
			key = strings.TrimSpace(p.cfg.Live.Load().AdminKey)
		}
		if key == "" {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "panel disabled: admin_key is empty"})
			return
		}
		if !isSameOriginRequest(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-origin request rejected"})
			return
		}
		if !httpauth.VerifyBearer(r, key) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized: valid admin_key required"})
			return
		}
		if isWriteMethod(r.Method) {
			isImport := r.URL.Path == "/panel/api/accounts/import"
			if hasRequestBody(r) {
				ct := strings.TrimSpace(r.Header.Get("Content-Type"))
				mt, _, err := mime.ParseMediaType(ct)
				if err != nil || !strings.EqualFold(mt, "application/json") {
					writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "Content-Type must be application/json"})
					return
				}
			}
			limit := int64(maxPanelBodyBytes)
			if isImport {
				limit = maxImportBodyBytes
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next(w, r)
	}
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func hasRequestBody(r *http.Request) bool {
	return r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}

func isSameOriginRequest(r *http.Request) bool {
	if sfs := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); sfs != "" {
		if !strings.EqualFold(sfs, "same-origin") && !strings.EqualFold(sfs, "none") {
			return false
		}
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if strings.EqualFold(origin, "null") {
			return false
		}
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return false
		}
		if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
			return false
		}
		if !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body exceeds size limit"})
			return false
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return false
	}
	return true
}

func decodeJSONOptional(w http.ResponseWriter, r *http.Request, dst any) bool {
	if !hasRequestBody(r) {
		return true
	}
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return false
	}
	return true
}

func (p *Panel) envOverrides() []string {
	if p.cfg.EnvOverrides != nil {
		if list := p.cfg.EnvOverrides(); len(list) > 0 {
			return list
		}
	}
	return []string{}
}

func (p *Panel) handleOverview(w http.ResponseWriter, _ *http.Request) {
	sticky := 0
	callbackPort := 18080
	appVer := "1.2.4660"
	proxyConfigured := false
	if p.cfg.Live != nil {
		snap := p.cfg.Live.Load()
		callbackPort = snap.Upstream.CallbackPort
		appVer = snap.Upstream.AppVersion
		proxyConfigured = strings.TrimSpace(snap.Upstream.ProxyURL) != ""
	}
	if p.cfg.Session != nil {
		sticky = p.cfg.Session.Count()
	}
	var metrics reqlog.Metrics
	if p.cfg.ReqLog != nil {
		metrics = p.cfg.ReqLog.Metrics()
	}
	var activePorts []int
	if p.cfg.CallbackMgr != nil {
		activePorts = p.cfg.CallbackMgr.ActivePorts()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":          p.cfg.Version,
		"app_version":      appVer,
		"uptime_sec":       int64(time.Since(p.started).Seconds()),
		"callback_port":    callbackPort,
		"active_cb_ports":  activePorts,
		"proxy_configured": proxyConfigured,
		"pool":             p.cfg.Pool.Summary(),
		"sticky_count":     sticky,
		"metrics":          metrics,
	})
}

func (p *Panel) handleAccountsList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"accounts": p.cfg.Pool.Snapshot()})
}

// --- OAuth Login Handlers ---

func (p *Panel) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	if p.cfg.CallbackMgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "login callback manager unavailable"})
		return
	}
	var req struct {
		Provider string `json:"provider"` // "social" | "enterprise"
		Region   string `json:"region"`
		Stage    string `json:"stage"`
	}
	if !decodeJSONOptional(w, r, &req) {
		return
	}
	upCfg := config.Default().Upstream
	if p.cfg.Live != nil {
		upCfg = p.cfg.Live.Load().Upstream
	}
	if req.Region == "" {
		req.Region = upCfg.DefaultRegion
	}
	if req.Stage == "" {
		req.Stage = upCfg.Stage
	}
	ov := auth.EndpointOverrides{
		OIDCBase:     upCfg.OIDCBase,
		DiscoveryURL: upCfg.DiscoveryURL,
		DataPlaneURL: upCfg.DataPlaneURL,
	}
	view, err := p.cfg.CallbackMgr.Start(req.Provider, req.Stage, req.Region, upCfg.CallbackPort, upCfg.AppVersion, ov)
	if err != nil {
		status := http.StatusInternalServerError
		var se *auth.StepError
		if errors.As(err, &se) && se.Status > 0 {
			status = se.Status
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (p *Panel) handleLoginStatus(w http.ResponseWriter, r *http.Request) {
	if p.cfg.CallbackMgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "login callback manager unavailable"})
		return
	}
	id := r.PathValue("id")
	view, ok := p.cfg.CallbackMgr.Status(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "login session not found"})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (p *Panel) handleLoginCallbackURL(w http.ResponseWriter, r *http.Request) {
	if p.cfg.CallbackMgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "login callback manager unavailable"})
		return
	}
	id := r.PathValue("id")
	var req struct {
		URL string `json:"url"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	view, err := p.cfg.CallbackMgr.SubmitCallbackURL(r.Context(), id, strings.TrimSpace(req.URL))
	if err != nil {
		status := http.StatusBadRequest
		var se *auth.StepError
		if errors.As(err, &se) && se.Status > 0 {
			status = se.Status
		}
		writeJSON(w, status, map[string]any{"error": err.Error(), "login": view})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (p *Panel) handleLoginCancel(w http.ResponseWriter, r *http.Request) {
	if p.cfg.CallbackMgr != nil {
		p.cfg.CallbackMgr.Cancel(r.PathValue("id"))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Account Actions ---

func (p *Panel) handleRefreshAllQuotas(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Scheduler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "scheduler unavailable"})
		return
	}
	n := p.cfg.Scheduler.RefreshAllQuotas(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"refreshed": n})
}

func (p *Panel) handleRefreshAllTokens(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Scheduler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "scheduler unavailable"})
		return
	}
	p.cfg.Scheduler.RefreshExpiringTokens(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) handleAccountRevive(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !p.cfg.Pool.Revive(uid) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "account not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) handleAccountDisable(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if p.cfg.Pool.AuthByUID(uid) == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "account not found"})
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSONOptional(w, r, &req)
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "manual_disabled"
	}
	p.cfg.Pool.Disable(uid, req.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) handleAccountRefreshToken(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if p.cfg.Scheduler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "scheduler unavailable"})
		return
	}
	if err := p.cfg.Scheduler.RefreshOneToken(r.Context(), uid); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) handleAccountQuota(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if p.cfg.Scheduler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "scheduler unavailable"})
		return
	}
	q, err := p.cfg.Scheduler.RefreshOneQuota(r.Context(), uid)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "quota": q})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "quota": q})
}

func (p *Panel) handleAccountTest(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	acct := p.cfg.Pool.AuthByUID(uid)
	if acct == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "account not found"})
		return
	}
	if p.cfg.Upstream == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "upstream unavailable"})
		return
	}
	if p.cfg.Scheduler != nil && acct.NeedsRefresh(time.Now(), 2*time.Minute) {
		_ = p.cfg.Scheduler.RefreshOneTokenIfStale(r.Context(), uid, acct.AccessToken)
		if fresh := p.cfg.Pool.AuthByUID(uid); fresh != nil {
			acct = fresh
		}
	}
	res, dur, err := p.cfg.Upstream.TestAccount(r.Context(), acct)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"uid":        uid,
			"latency_ms": dur.Milliseconds(),
			"error":      err.Error(),
		})
		return
	}
	// Refresh quota in background after successful test.
	if p.cfg.Scheduler != nil {
		go func(id string) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_, _ = p.cfg.Scheduler.RefreshOneQuota(ctx, id)
		}(uid)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"uid":            uid,
		"latency_ms":     dur.Milliseconds(),
		"reply":          res.Text,
		"resolved_model": res.Usage.ResolvedModel,
		"prompt_tokens":  res.Usage.PromptTokens,
		"output_tokens":  res.Usage.CompletionTokens,
	})
}

func (p *Panel) handleAccountRename(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	updated := p.cfg.Pool.Rename(uid, req.Name)
	if updated == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "account not found"})
		return
	}
	if p.cfg.AuthDir != "" {
		if err := auth.SaveAccount(p.cfg.AuthDir, p.cfg.Vault, updated); err != nil {
			log.Printf("WARN: [panel] save renamed account %s: %v", uid, err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "display_name": updated.DisplayName(), "custom_name": updated.CustomName})
}

func (p *Panel) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !auth.ValidUID(uid) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid uid"})
		return
	}
	if p.cfg.AuthDir != "" {
		if err := auth.DeleteAccount(p.cfg.AuthDir, uid); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}
	p.cfg.Pool.Remove(uid)
	if p.cfg.Session != nil {
		p.cfg.Session.UnbindAccount(uid)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Models ---

func (p *Panel) handleModels(w http.ResponseWriter, _ *http.Request) {
	cat := upstream.DefaultCatalog()
	if p.cfg.Upstream != nil {
		cat = p.cfg.Upstream.GetCatalog()
	}
	snap := config.LiveSnapshot{}
	if p.cfg.Live != nil {
		snap = p.cfg.Live.Load()
	}
	type modelRow struct {
		upstream.ModelSpec
		Visible bool `json:"visible"`
	}
	rows := make([]modelRow, 0, len(cat.Specs))
	for _, s := range cat.Specs {
		k := strings.ToLower(s.ID)
		vis := !snap.HiddenModels[k] && (!snap.AllowlistEnabled || snap.AllowedModels[k])
		rows = append(rows, modelRow{ModelSpec: s, Visible: vis})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"models":                 rows,
		"claude_aliases":         cat.ClaudeAliases,
		"claude_aliases_enabled": snap.ClaudeAliases,
		"expose_effort_variants": snap.ExposeEffortVariants,
		"api_key":                snap.APIKey,
	})
}

func (p *Panel) handleClaudeAliasesToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := p.patchConfig(map[string]any{"features": map[string]any{"claude_aliases": req.Enabled}}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": req.Enabled})
}

func (p *Panel) handleModelVisibilityToggle(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing model id"})
		return
	}
	var req struct {
		Visible bool `json:"visible"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p.saveMu.Lock()
	defer p.saveMu.Unlock()
	if p.cfg.LoadConfig == nil || p.cfg.SaveConfig == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "config save unavailable"})
		return
	}
	cfg, err := p.cfg.LoadConfig()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	low := strings.ToLower(id)
	var nextHidden []string
	for _, h := range cfg.Models.Hidden {
		if strings.ToLower(strings.TrimSpace(h)) != low {
			nextHidden = append(nextHidden, h)
		}
	}
	if !req.Visible {
		nextHidden = append(nextHidden, id)
	}
	cfg.Models.Hidden = nextHidden
	raw, _ := json.Marshal(cfg)
	if _, err := p.cfg.SaveConfig(raw); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "visible": req.Visible})
}

func (p *Panel) handleModelRename(w http.ResponseWriter, r *http.Request) {
	slot := strings.TrimSpace(r.PathValue("slot"))
	var req struct {
		ID      string `json:"id"`
		Display string `json:"display"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if p.cfg.Upstream == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "upstream unavailable"})
		return
	}
	next, spec, oldID, err := p.cfg.Upstream.GetCatalog().RenameSlot(slot, req.ID, req.Display)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if p.cfg.ModelsPath != "" {
		if serr := upstream.SaveCatalogFile(p.cfg.ModelsPath, next); serr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": serr.Error()})
			return
		}
	}
	p.cfg.Upstream.SetCatalog(next)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "old_id": oldID, "model": spec})
}

// --- Config, Requests (metadata-only), Logs ---

func (p *Panel) handleConfigGet(w http.ResponseWriter, _ *http.Request) {
	if p.cfg.LoadConfig == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "config load unavailable"})
		return
	}
	cfg, err := p.cfg.LoadConfig()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":        cfg,
		"config_path":   p.cfg.ConfigPath,
		"env_overrides": p.envOverrides(),
	})
}

func (p *Panel) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	if p.cfg.SaveConfig == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "config save unavailable"})
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	p.saveMu.Lock()
	res, serr := p.cfg.SaveConfig(raw)
	p.saveMu.Unlock()
	if serr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": serr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                  true,
		"restart_required":    res.RestartRequired,
		"effective_api_key":   res.EffectiveAPIKey,
		"effective_admin_key": res.EffectiveAdminKey,
		"env_overrides":       res.EnvOverrides,
	})
}

func (p *Panel) patchConfig(patch map[string]any) error {
	p.saveMu.Lock()
	defer p.saveMu.Unlock()
	if p.cfg.LoadConfig == nil || p.cfg.SaveConfig == nil {
		return fmt.Errorf("config save unavailable")
	}
	cfg, err := p.cfg.LoadConfig()
	if err != nil {
		return err
	}
	baseBytes, _ := json.Marshal(cfg)
	var base map[string]any
	_ = json.Unmarshal(baseBytes, &base)
	merged := mergeMap(base, patch)
	out, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	_, err = p.cfg.SaveConfig(out)
	return err
}

func mergeMap(dst, src map[string]any) map[string]any {
	out := make(map[string]any, len(dst)+len(src))
	for k, v := range dst {
		out[k] = v
	}
	for k, v := range src {
		if vm, ok := v.(map[string]any); ok {
			if dm, ok2 := out[k].(map[string]any); ok2 {
				out[k] = mergeMap(dm, vm)
				continue
			}
		}
		out[k] = v
	}
	return out
}

func (p *Panel) handleRequests(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	entries := []reqlog.Entry{}
	if p.cfg.ReqLog != nil {
		entries = p.cfg.ReqLog.Recent(limit)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"requests": entries,
	})
}

func (p *Panel) handleRequestsClear(w http.ResponseWriter, _ *http.Request) {
	if p.cfg.ReqLog != nil {
		if err := p.cfg.ReqLog.Clear(true); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	logs := []reqlog.LogLine{}
	if p.cfg.ReqLog != nil {
		logs = p.cfg.ReqLog.RecentLogs(limit)
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
}

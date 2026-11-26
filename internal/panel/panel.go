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
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"awsquick2api/internal/apikeys"
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
	Pool           *pool.Pool
	Vault          *auth.Vault
	Upstream       *upstream.Client
	Scheduler      *scheduler.Scheduler
	Session        *session.Router
	ReqLog         *reqlog.Recorder
	APIKeys        *apikeys.Store
	Live           *config.LiveHolder
	CallbackMgr    *auth.CallbackManager
	AuthDir        string
	ConfigPath     string
	ModelsPath     string
	LogFilePath    string
	Version        string
	UpstreamHealth func() any
	EnvOverrides   func() []string
	LoadConfig     func() (*config.Config, error)
	SaveConfig     func(raw []byte) (SaveConfigResult, error)

	// ListenAddr is the effective listen address (after env overrides). When empty the
	// panel falls back to config.json "listen" via LoadConfig. When it binds a loopback
	// host the panel only accepts Host headers naming 127.0.0.1/localhost/[::1], the
	// listen host or TrustedHosts (anti DNS rebinding); non-loopback binds are unaffected.
	ListenAddr string
	// TrustedHosts lists extra Host header hostnames accepted on loopback binds, e.g. the
	// public hostname of a reverse proxy that preserves the Host header.
	TrustedHosts []string
	// OnAccountsImported, when non-nil, is invoked asynchronously (in its own goroutine)
	// with the UIDs persisted by a successful encrypted import, e.g. to sync quota and
	// AdvancedEnabled for the new accounts.
	OnAccountsImported func(uids []string)
}

type Panel struct {
	cfg     Config
	mux     *http.ServeMux
	started time.Time
	saveMu  sync.Mutex
	authLim *authLimiter

	// hostGuard is true when the effective listen address binds a loopback host;
	// listenHost is that host (lower-cased, without port/brackets).
	hostGuard  bool
	listenHost string

	trustedMu    sync.RWMutex
	trustedHosts []string
	trustedSet   bool
}

// resolveListenHost determines the listen host used for the Host header guard:
// Config.ListenAddr first, else config.json "listen" via LoadConfig (listen changes
// require a restart, so reading it once is sufficient).
func resolveListenHost(cfg Config) (string, bool) {
	listen := strings.TrimSpace(cfg.ListenAddr)
	if listen == "" && cfg.LoadConfig != nil {
		if c, err := cfg.LoadConfig(); err == nil && c != nil {
			listen = strings.TrimSpace(c.Listen)
		}
	}
	if listen == "" {
		return "", false
	}
	h := hostOnly(listen)
	return h, isLoopbackHost(h)
}

func New(cfg Config) *Panel {
	p := &Panel{
		cfg:          cfg,
		mux:          http.NewServeMux(),
		started:      time.Now(),
		authLim:      newAuthLimiter(),
		trustedHosts: append([]string(nil), cfg.TrustedHosts...),
	}
	p.listenHost, p.hostGuard = resolveListenHost(cfg)

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

	// Models, Scoped API Keys, Playground, Config, Requests (metadata-only), Logs
	p.mux.HandleFunc("GET /panel/api/models", p.withAuth(p.handleModels))
	p.mux.HandleFunc("PUT /panel/api/models/{slot}/rename", p.withAuth(p.handleModelRename))
	p.mux.HandleFunc("PATCH /panel/api/models/{id}", p.withAuth(p.handleModelVisibilityToggle))
	p.mux.HandleFunc("PATCH /panel/api/features/claude-aliases", p.withAuth(p.handleClaudeAliasesToggle))
	p.mux.HandleFunc("PATCH /panel/api/features/strict-privacy-dlp", p.withAuth(p.handleStrictPrivacyToggle))
	p.mux.HandleFunc("GET /panel/api/keys", p.withAuth(p.handleKeysList))
	p.mux.HandleFunc("POST /panel/api/keys", p.withAuth(p.handleKeyCreate))
	p.mux.HandleFunc("PATCH /panel/api/keys/{id}", p.withAuth(p.handleKeyUpdate))
	p.mux.HandleFunc("DELETE /panel/api/keys/{id}", p.withAuth(p.handleKeyDelete))
	p.mux.HandleFunc("POST /panel/api/playground", p.withAuth(p.handlePlayground))
	p.mux.HandleFunc("GET /panel/api/config", p.withAuth(p.handleConfigGet))
	p.mux.HandleFunc("PUT /panel/api/config", p.withAuth(p.handleConfigSave))
	p.mux.HandleFunc("GET /panel/api/requests", p.withAuth(p.handleRequests))
	p.mux.HandleFunc("DELETE /panel/api/requests", p.withAuth(p.handleRequestsClear))
	p.mux.HandleFunc("GET /panel/api/logs", p.withAuth(p.handleLogs))
	p.mux.HandleFunc("GET /panel/api/logs/export", p.withAuth(p.handleLogsExport))

	return p
}

func (p *Panel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https: http:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if strings.HasPrefix(r.URL.Path, "/panel/api/") {
		w.Header().Set("Cache-Control", "no-store")
	}
	if !p.hostAllowed(r.Host) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "host not allowed"})
		return
	}
	p.mux.ServeHTTP(w, r)
}

func (p *Panel) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := ""
		if p.cfg.Live != nil {
			key = strings.TrimSpace(p.cfg.Live.Load().AdminKey)
		}
		if !config.ValidAdminKey(key) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "panel disabled: set a valid admin_key"})
			return
		}
		if !isSameOriginRequest(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-origin request rejected"})
			return
		}
		ip := clientIP(r)
		if blocked, wait := p.authLim.blocked(ip); blocked {
			secs := int(wait/time.Second) + 1
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": fmt.Sprintf("too many failed admin_key attempts, retry in %ds", secs)})
			return
		}
		if !httpauth.VerifyBearer(r, key) {
			p.authLim.fail(ip)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized: valid admin_key required"})
			return
		}
		p.authLim.reset(ip)
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

// --- Host allowlist (anti DNS rebinding) ---

// UpdateTrustedHosts replaces the active Host-header allowlist used on loopback binds.
func (p *Panel) UpdateTrustedHosts(hosts []string) {
	if p == nil {
		return
	}
	cp := append([]string(nil), hosts...)
	p.trustedMu.Lock()
	p.trustedHosts = cp
	p.trustedSet = true
	p.trustedMu.Unlock()
}

// hostAllowed reports whether the request Host header is acceptable. Only loopback
// binds are restricted; wildcard / LAN binds are left to network-level controls.
func (p *Panel) hostAllowed(reqHost string) bool {
	if !p.hostGuard {
		return true
	}
	lh := p.listenHost
	h := hostOnly(reqHost)
	if h == "" {
		return false
	}
	if isLoopbackHost(h) || h == lh {
		return true
	}
	p.trustedMu.RLock()
	hosts := p.trustedHosts
	explicit := p.trustedSet
	p.trustedMu.RUnlock()
	for _, t := range hosts {
		if th := hostOnly(t); th != "" && th == h {
			return true
		}
	}
	if !explicit && p.cfg.Live != nil {
		for _, t := range p.cfg.Live.Load().TrustedHosts {
			if th := hostOnly(t); th != "" && th == h {
				return true
			}
		}
	}
	return false
}

// hostOnly strips the port and IPv6 brackets and lower-cases a host[:port] value.
func hostOnly(s string) string {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// --- admin_key failure rate limiting (per source IP, fixed window, bounded memory) ---

var (
	authFailLimit      = 10
	authFailWindow     = 5 * time.Minute
	authLimiterMaxKeys = 4096
)

type authFailEntry struct {
	count int
	start time.Time
}

type authLimiter struct {
	mu  sync.Mutex
	m   map[string]*authFailEntry
	now func() time.Time
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{m: make(map[string]*authFailEntry), now: time.Now}
}

// blocked reports whether ip exhausted its failure budget and how long until the window resets.
func (l *authLimiter) blocked(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[ip]
	if e == nil {
		return false, 0
	}
	elapsed := l.now().Sub(e.start)
	if elapsed >= authFailWindow {
		delete(l.m, ip)
		return false, 0
	}
	if e.count >= authFailLimit {
		return true, authFailWindow - elapsed
	}
	return false, 0
}

func (l *authLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.m[ip]
	if e != nil && now.Sub(e.start) >= authFailWindow {
		e = nil
	}
	if e == nil {
		if _, exists := l.m[ip]; !exists && len(l.m) >= authLimiterMaxKeys {
			for k, v := range l.m {
				if now.Sub(v.start) >= authFailWindow {
					delete(l.m, k)
				}
			}
			for len(l.m) >= authLimiterMaxKeys {
				var (
					oldestKey  string
					oldestTime time.Time
					first      = true
				)
				for k, v := range l.m {
					if first || v.start.Before(oldestTime) || (v.start.Equal(oldestTime) && k < oldestKey) {
						oldestKey = k
						oldestTime = v.start
						first = false
					}
				}
				if first {
					break
				}
				delete(l.m, oldestKey)
			}
		}
		e = &authFailEntry{start: now}
		l.m[ip] = e
	}
	e.count++
}

func (l *authLimiter) reset(ip string) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}

func (l *authLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}

// clientIP uses the TCP peer address only; forwarding headers are spoofable.
func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
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
	privacyDLP := false
	if p.cfg.Live != nil {
		snap := p.cfg.Live.Load()
		callbackPort = snap.Upstream.CallbackPort
		appVer = snap.Upstream.AppVersion
		proxyConfigured = strings.TrimSpace(snap.Upstream.ProxyURL) != ""
		privacyDLP = snap.StrictPrivacyDLP
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
	var upHealth any
	if p.cfg.UpstreamHealth != nil {
		upHealth = p.cfg.UpstreamHealth()
	}
	scopedKeysCount := 0
	if p.cfg.APIKeys != nil {
		scopedKeysCount = len(p.cfg.APIKeys.List())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":            p.cfg.Version,
		"app_version":        appVer,
		"uptime_sec":         int64(time.Since(p.started).Seconds()),
		"callback_port":      callbackPort,
		"active_cb_ports":    activePorts,
		"proxy_configured":   proxyConfigured,
		"strict_privacy_dlp": privacyDLP,
		"pool":               p.cfg.Pool.Summary(),
		"sticky_count":       sticky,
		"metrics":            metrics,
		"upstream_health":    upHealth,
		"scoped_keys_count":  scopedKeysCount,
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
	if !decodeJSONOptional(w, r, &req) {
		return
	}
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
	store := pool.CredentialStore{Pool: p.cfg.Pool, Dir: p.cfg.AuthDir, Vault: p.cfg.Vault}
	updated, err := store.Rename(uid, req.Name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if updated == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "account not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "display_name": updated.DisplayName(), "custom_name": updated.CustomName})
}

func (p *Panel) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !auth.ValidUID(uid) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid uid"})
		return
	}
	store := pool.CredentialStore{Pool: p.cfg.Pool, Dir: p.cfg.AuthDir, Vault: p.cfg.Vault}
	if err := store.Delete(uid); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
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
	if len(cfg.Models.Allowed) > 0 {
		if req.Visible {
			found := false
			for _, a := range cfg.Models.Allowed {
				if strings.ToLower(strings.TrimSpace(a)) == low {
					found = true
					break
				}
			}
			if !found {
				cfg.Models.Allowed = append(cfg.Models.Allowed, id)
			}
		} else {
			var nextAllowed []string
			for _, a := range cfg.Models.Allowed {
				if strings.ToLower(strings.TrimSpace(a)) != low {
					nextAllowed = append(nextAllowed, a)
				}
			}
			// Only drop from models.allowed when other allowed entries remain; emptying
			// models.allowed would disable the allowlist and expose every other model.
			if len(nextAllowed) > 0 {
				cfg.Models.Allowed = nextAllowed
			}
		}
	}
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
	p.saveMu.Lock()
	defer p.saveMu.Unlock()
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
	resp := map[string]any{"ok": true, "old_id": oldID, "model": spec, "config_migrated": 0}
	if newID := strings.TrimSpace(spec.ID); strings.TrimSpace(oldID) != "" && newID != "" && !strings.EqualFold(strings.TrimSpace(oldID), newID) {
		n, merr := p.migrateModelRefsLocked(strings.TrimSpace(oldID), newID)
		resp["config_migrated"] = n
		if merr != nil {
			log.Printf("WARN: [panel] model rename %s -> %s: config.json sync failed: %v", oldID, newID, merr)
			resp["config_sync_error"] = merr.Error()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// modelVariantSuffixRE matches the effort / context suffixes a model reference may carry.
var modelVariantSuffixRE = regexp.MustCompile(`^(?:-(?:off|minimal|low|medium|high|xhigh|max))?(?:\[1m\])?$`)

// renameModelRef rewrites entry when it names oldID (case-insensitive), optionally with
// an effort/[1m] variant suffix, preserving that suffix.
func renameModelRef(entry, oldID, newID string) (string, bool) {
	t := strings.TrimSpace(entry)
	if oldID == "" || len(t) < len(oldID) || !strings.EqualFold(t[:len(oldID)], oldID) {
		return entry, false
	}
	suffix := t[len(oldID):]
	if !modelVariantSuffixRE.MatchString(strings.ToLower(suffix)) {
		return entry, false
	}
	return newID + suffix, true
}

func renameModelList(list []string, oldID, newID string) ([]string, int) {
	if len(list) == 0 {
		return list, 0
	}
	changed := 0
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, e := range list {
		v, ok := renameModelRef(e, oldID, newID)
		if ok {
			changed++
		}
		k := strings.ToLower(strings.TrimSpace(v))
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out, changed
}

func renameModelKeys(m map[string]string, oldID, newID string) (map[string]string, int) {
	if len(m) == 0 {
		return m, 0
	}
	out := make(map[string]string, len(m))
	seenLower := make(map[string]bool, len(m))
	renamed := map[string]string{}
	for k, v := range m {
		if nk, ok := renameModelRef(k, oldID, newID); ok {
			renamed[nk] = v
			continue
		}
		out[k] = v
		seenLower[strings.ToLower(strings.TrimSpace(k))] = true
	}
	rkeys := make([]string, 0, len(renamed))
	for nk := range renamed {
		rkeys = append(rkeys, nk)
	}
	sort.Strings(rkeys)
	for _, nk := range rkeys {
		low := strings.ToLower(strings.TrimSpace(nk))
		if seenLower[low] {
			continue
		}
		seenLower[low] = true
		out[nk] = renamed[nk]
	}
	return out, len(renamed)
}

// migrateModelRefs rewrites references to a renamed model ID in config.json:
// models.hidden, models.allowed and thinking.model_overrides keys.
func (p *Panel) migrateModelRefs(oldID, newID string) (int, error) {
	p.saveMu.Lock()
	defer p.saveMu.Unlock()
	return p.migrateModelRefsLocked(oldID, newID)
}

func (p *Panel) migrateModelRefsLocked(oldID, newID string) (int, error) {
	if p.cfg.LoadConfig == nil || p.cfg.SaveConfig == nil {
		return 0, nil
	}
	cfg, err := p.cfg.LoadConfig()
	if err != nil {
		return 0, err
	}
	var c1, c2, c3 int
	cfg.Models.Hidden, c1 = renameModelList(cfg.Models.Hidden, oldID, newID)
	cfg.Models.Allowed, c2 = renameModelList(cfg.Models.Allowed, oldID, newID)
	cfg.Thinking.ModelOverrides, c3 = renameModelKeys(cfg.Thinking.ModelOverrides, oldID, newID)
	n := c1 + c2 + c3
	if n == 0 {
		return 0, nil
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return 0, err
	}
	if _, err := p.cfg.SaveConfig(raw); err != nil {
		return 0, err
	}
	return n, nil
}

func (p *Panel) handleStrictPrivacyToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing enabled"})
		return
	}
	if err := p.patchConfig(map[string]any{"features": map[string]any{"strict_privacy_dlp": *req.Enabled}}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": *req.Enabled})
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

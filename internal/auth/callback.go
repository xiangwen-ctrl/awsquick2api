package auth

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	loginFlowTTL = 15 * time.Minute
	// callbackExchangeTimeout bounds discovery/token exchange triggered by a browser callback.
	// The work is detached from the browser request so closing the tab mid-exchange cannot
	// waste the one-time authorization code.
	callbackExchangeTimeout = 60 * time.Second
)

// LoginResultHandler is invoked once a browser or pasted-URL login succeeds.
// It runs while the flow is locked so that Cancel cannot race an in-flight save;
// it must not call back into the CallbackManager.
type LoginResultHandler func(acct *Account) error

// LoginStatusView is the sanitized login progress returned to the Web panel.
type LoginStatusView struct {
	SessionID    string `json:"session_id"`
	Provider     string `json:"provider"`
	Region       string `json:"region"`
	CallbackPort int    `json:"callback_port"`
	LoginURL     string `json:"login_url"`
	AuthorizeURL string `json:"authorize_url,omitempty"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	ExpiresAt    int64  `json:"expires_at"`
	AccountUID   string `json:"account_uid,omitempty"`
	AccountLabel string `json:"account_label,omitempty"`
}

// CallbackManager manages active PKCE login flows, local loopback callback HTTP servers,
// and manual pasted-callback progression for headless/remote Linux servers.
//
// Locking: m.mu guards the maps only. Flow state is guarded by each LoginFlow's own
// mutex. m.mu is never held while a flow lock is taken, so there is no lock ordering
// to get wrong.
type CallbackManager struct {
	mu           sync.Mutex
	flows        map[string]*LoginFlow
	servers      map[int]*http.Server
	servers6     map[int]*http.Server
	clientGetter func() *http.Client
	onComplete   LoginResultHandler
}

func NewCallbackManager(clientGetter func() *http.Client, onComplete LoginResultHandler) *CallbackManager {
	return &CallbackManager{
		flows:        map[string]*LoginFlow{},
		servers:      map[int]*http.Server{},
		servers6:     map[int]*http.Server{},
		clientGetter: clientGetter,
		onComplete:   onComplete,
	}
}

func (m *CallbackManager) ActivePorts() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]int, 0, len(m.servers))
	for p := range m.servers {
		out = append(out, p)
	}
	return out
}

func (m *CallbackManager) Start(provider, stage, region string, callbackPort int, appVersion string, ov EndpointOverrides) (LoginStatusView, error) {
	p := NormalizeProvider(provider)
	st := NormalizeStage(stage)
	reg := region
	if reg == "" {
		reg = "us-east-1"
	}

	m.mu.Lock()
	stale := m.pruneLocked(time.Now())
	port, err := m.ensureListenerLocked(callbackPort, IsEnterpriseDiscovery(p))
	if err != nil {
		m.mu.Unlock()
		cancelFlows(stale)
		return LoginStatusView{}, err
	}
	flow := NewLoginFlow(p, st, reg, port, appVersion, ov)
	m.flows[flow.ID] = flow
	m.mu.Unlock()
	cancelFlows(stale)
	return viewFromFlow(flow), nil
}

func (m *CallbackManager) lookup(sessionID string) *LoginFlow {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flows[sessionID]
}

func (m *CallbackManager) Status(sessionID string) (LoginStatusView, bool) {
	f := m.lookup(sessionID)
	if f == nil {
		return LoginStatusView{}, false
	}
	f.expireIfStale(time.Now())
	return viewFromFlow(f), true
}

// Cancel forgets the session and marks the flow cancelled. A discovery or token exchange
// that is still in flight will observe the cancellation and will not save the account.
func (m *CallbackManager) Cancel(sessionID string) {
	m.mu.Lock()
	f := m.flows[sessionID]
	delete(m.flows, sessionID)
	m.mu.Unlock()
	if f != nil {
		f.cancel()
	}
}

func (m *CallbackManager) SubmitCallbackURL(ctx context.Context, sessionID, rawURL string) (LoginStatusView, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return LoginStatusView{}, &StepError{Status: 400, Message: "粘贴的回调地址格式无效"}
	}
	q := u.Query()
	flow := m.lookup(sessionID)
	if flow == nil {
		return LoginStatusView{}, &StepError{Status: 404, Message: "登录会话不存在或已过期"}
	}
	if flow.expireIfStale(time.Now()) {
		v := viewFromFlow(flow)
		return v, &StepError{Status: 410, Message: v.Error}
	}

	client := m.httpClient()
	switch {
	case q.Get("nonce") != "":
		_, err := flow.ProcessDiscovery(ctx, client, q)
		return viewFromFlow(flow), err
	case q.Get("code") != "" || q.Get("error") != "" || q.Get("state") != "":
		_, err := flow.complete(ctx, client, q, m.onComplete)
		return viewFromFlow(flow), err
	}
	return LoginStatusView{}, &StepError{Status: 400, Message: "回调地址缺少 nonce 或 code/state 参数"}
}

func (m *CallbackManager) Close() {
	m.mu.Lock()
	srvs := make([]*http.Server, 0, len(m.servers)+len(m.servers6))
	for _, s := range m.servers {
		srvs = append(srvs, s)
	}
	for _, s := range m.servers6 {
		srvs = append(srvs, s)
	}
	flows := make([]*LoginFlow, 0, len(m.flows))
	for _, f := range m.flows {
		flows = append(flows, f)
	}
	m.servers = map[int]*http.Server{}
	m.servers6 = map[int]*http.Server{}
	m.flows = map[string]*LoginFlow{}
	m.mu.Unlock()

	cancelFlows(flows)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, s := range srvs {
		_ = s.Shutdown(ctx)
	}
}

func cancelFlows(flows []*LoginFlow) {
	for _, f := range flows {
		f.cancel()
	}
}

func (m *CallbackManager) httpClient() *http.Client {
	if m.clientGetter != nil {
		if cl := m.clientGetter(); cl != nil {
			return cl
		}
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// pruneLocked drops flows older than 30 minutes and returns them so the caller can
// cancel them after releasing m.mu.
func (m *CallbackManager) pruneLocked(now time.Time) []*LoginFlow {
	var stale []*LoginFlow
	for id, f := range m.flows {
		if now.Sub(f.CreatedAt) > 30*time.Minute {
			delete(m.flows, id)
			stale = append(stale, f)
		}
	}
	return stale
}

func (m *CallbackManager) ensureListenerLocked(preferred int, strictPort bool) (int, error) {
	if preferred > 0 {
		if _, ok := m.servers[preferred]; ok {
			return preferred, nil
		}
	}
	candidates := []int{preferred}
	if !strictPort && preferred > 0 {
		candidates = append(candidates, preferred+1, preferred+2, preferred+3, 0)
	}
	var (
		ln   net.Listener
		err  error
		port int
	)
	for _, cand := range candidates {
		if cand > 0 {
			if _, ok := m.servers[cand]; ok {
				return cand, nil
			}
		}
		ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cand))
		if err == nil {
			port = ln.Addr().(*net.TCPAddr).Port
			break
		}
	}
	if ln == nil {
		return 0, &StepError{
			Status:  409,
			Message: fmt.Sprintf("本机授权回调端口 %d 已被占用（如官方 Quick 客户端正在运行），请关闭后重试或修改 upstream.callback_port", preferred),
		}
	}

	srv := &http.Server{
		Handler:           http.HandlerFunc(m.handleCallbackHTTP),
		ReadHeaderTimeout: 10 * time.Second,
	}
	m.servers[port] = srv
	go func() {
		_ = srv.Serve(ln)
	}()

	ln6, err6 := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port))
	if err6 != nil {
		if strictPort {
			// Enterprise/Gateway logins redirect to http://localhost:<port>. Browsers that resolve
			// localhost to ::1 first cannot reach the IPv4-only listener; make that visible.
			log.Printf("WARN: [auth] IPv6 loopback callback [::1]:%d unavailable (%v); if the browser resolves localhost to ::1 the login callback may fail", port, err6)
		}
		return port, nil
	}
	srv6 := &http.Server{
		Handler:           http.HandlerFunc(m.handleCallbackHTTP),
		ReadHeaderTimeout: 10 * time.Second,
	}
	m.servers6[port] = srv6
	go func() {
		_ = srv6.Serve(ln6)
	}()
	return port, nil
}

func (m *CallbackManager) findFlowBySecret(secret string, isNonce bool) *LoginFlow {
	if secret == "" {
		return nil
	}
	m.mu.Lock()
	flows := make([]*LoginFlow, 0, len(m.flows))
	for _, f := range m.flows {
		flows = append(flows, f)
	}
	m.mu.Unlock()
	now := time.Now()
	for _, f := range flows {
		if now.Sub(f.CreatedAt) > loginFlowTTL {
			continue
		}
		if f.matchesSecret(secret, isNonce) {
			return f
		}
	}
	return nil
}

func detachedCallbackContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), callbackExchangeTimeout)
}

func (m *CallbackManager) handleCallbackHTTP(w http.ResponseWriter, r *http.Request) {
	sendHTML := func(status int, ok bool, title, detail string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		w.WriteHeader(status)
		color := "#991b1b"
		if ok {
			color = "#14532d"
		}
		_, _ = fmt.Fprintf(w,
			`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>%s</title>`+
				`<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1.25rem;color:%s;line-height:1.6}h2{margin-bottom:.5rem}</style></head>`+
				`<body><h2>%s</h2><p>%s</p></body></html>`,
			html.EscapeString(title), color, html.EscapeString(title), html.EscapeString(detail),
		)
	}
	statusOf := func(err error) int {
		var se *StepError
		if errors.As(err, &se) && se.Status > 0 {
			return se.Status
		}
		return http.StatusBadGateway
	}

	if r.Method != http.MethodGet {
		sendHTML(http.StatusMethodNotAllowed, false, "不支持的请求方法", "请使用浏览器完成 Amazon Quick 授权。")
		return
	}
	q := r.URL.Query()
	switch r.URL.Path {
	case "/callback":
		flow := m.findFlowBySecret(q.Get("nonce"), true)
		if flow == nil {
			sendHTML(http.StatusBadRequest, false, "授权发现已失效", "此授权发现回调已过期或已被使用，请返回 AWSQuick2API 面板重新发起登录。")
			return
		}
		ctx, cancel := detachedCallbackContext(r.Context())
		defer cancel()
		nextURL, err := flow.ProcessDiscovery(ctx, m.httpClient(), q)
		if err != nil {
			sendHTML(statusOf(err), false, "授权发现失败", err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, nextURL, http.StatusFound)
		return

	case "/", "/index.html":
		// The flow is located by its one-time state, so state is validated before any
		// error= parameter is honoured.
		flow := m.findFlowBySecret(q.Get("state"), false)
		if flow == nil {
			sendHTML(http.StatusBadRequest, false, "授权回调无效", "未找到匹配的登录会话或会话已过期，请返回 AWSQuick2API 面板重新登录。")
			return
		}
		ctx, cancel := detachedCallbackContext(r.Context())
		defer cancel()
		acct, err := flow.complete(ctx, m.httpClient(), q, m.onComplete)
		if err != nil {
			status := statusOf(err)
			title := "登录授权失败"
			if status == http.StatusInternalServerError {
				title = "保存账号失败"
			}
			sendHTML(status, false, title, err.Error())
			return
		}
		sendHTML(http.StatusOK, true, "Amazon Quick 登录成功", fmt.Sprintf("账号 %s 已加密保存并加入账号池，现在可以关闭此标签页并返回管理面板。", acct.DisplayName()))
		return

	default:
		sendHTML(http.StatusNotFound, false, "未找到回调路径", "此地址不属于 AWSQuick2API 登录回调。")
	}
}

func viewFromFlow(f *LoginFlow) LoginStatusView {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := LoginStatusView{
		SessionID:    f.ID,
		Provider:     f.Provider,
		Region:       f.Region,
		CallbackPort: f.Port,
		LoginURL:     f.loginURLLocked(),
		AuthorizeURL: f.AuthorizeURL,
		Status:       f.Status,
		Error:        f.ErrorMsg,
		ExpiresAt:    f.CreatedAt.Add(loginFlowTTL).UnixMilli(),
	}
	if f.ResultAccount != nil {
		v.AccountUID = f.ResultAccount.UID
		v.AccountLabel = f.ResultAccount.DisplayName()
	}
	return v
}

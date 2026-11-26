// awsquick2api — Cross-platform pure-Go multi-account OpenAI / Anthropic / Codex
// gateway & embedded Web management panel for Amazon Quick (QuickWork).
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/config"
	"awsquick2api/internal/panel"
	"awsquick2api/internal/pool"
	"awsquick2api/internal/reqlog"
	"awsquick2api/internal/safefile"
	"awsquick2api/internal/scheduler"
	"awsquick2api/internal/server"
	"awsquick2api/internal/session"
	"awsquick2api/internal/tray"
	"awsquick2api/internal/upstream"
)

var appVersion = "0.1.4"

func formatStartupErrorDialog(err error, logFileHint string) string {
	msg := fmt.Sprintf("启动失败：%s", reqlog.ScrubCredentials(err.Error()))
	if logFileHint != "" {
		msg += fmt.Sprintf("\n\n详细日志：%s", logFileHint)
	}
	return msg
}

func main() {
	var (
		showGUIError bool
		logFileHint  string
		closeLog     func()
	)
	err := run(&showGUIError, &logFileHint, &closeLog)
	if err != nil {
		log.Printf("FATAL: %s", reqlog.ScrubCredentials(err.Error()))
	}
	if closeLog != nil {
		closeLog()
	}
	if err != nil {
		if showGUIError {
			tray.ShowErrorDialog("AWSQuick2API 启动失败", formatStartupErrorDialog(err, logFileHint))
		}
		os.Exit(1)
	}
}

func run(showGUIError *bool, logFileHint *string, closeLog *func()) error {
	cfgFlag := flag.String("config", "", "Path to config.json (defaults to config.json in current dir or next to executable)")
	noTrayFlag := flag.Bool("no-tray", false, "Disable Windows system tray icon and GUI dialogs (headless / CLI mode)")
	openFlag := flag.Bool("open", false, "Open the Web panel in default browser once listening")
	exportEncFlag := flag.String("export-encrypted", "", "Export all accounts in auth_dir to an AES-256-GCM encrypted file and exit")
	importEncFlag := flag.String("import-encrypted", "", "Import accounts from an AES-256-GCM encrypted file into auth_dir and exit")
	overwriteFlag := flag.Bool("overwrite", false, "Overwrite existing accounts when using -import-encrypted")
	flag.Parse()

	exePath, _ := os.Executable()
	if exePath != "" {
		if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
			exePath = resolved
		}
		if abs, err := filepath.Abs(exePath); err == nil {
			exePath = abs
		}
	}
	absCfgPath := resolveConfigPath(*cfgFlag, exePath)
	cfgDir := filepath.Dir(absCfgPath)

	// Offline CLI migration commands.
	if outPath := strings.TrimSpace(*exportEncFlag); outPath != "" {
		if showGUIError != nil {
			*showGUIError = false
		}
		return runExportEncrypted(absCfgPath, cfgDir, outPath)
	}
	if inPath := strings.TrimSpace(*importEncFlag); inPath != "" {
		if showGUIError != nil {
			*showGUIError = false
		}
		return runImportEncrypted(absCfgPath, cfgDir, inPath, *overwriteFlag)
	}

	noTray := *noTrayFlag || isEnvTruthy("AWSQUICK_NO_TRAY")
	if showGUIError != nil {
		*showGUIError = !noTray
	}

	// Single-instance protection in tray mode.
	if !noTray {
		releaseInst, alreadyRunning := tray.AcquireSingleInstance(absCfgPath)
		if alreadyRunning {
			listen := config.Default().Listen
			if existing, lerr := config.Load(absCfgPath); lerr == nil && existing.Listen != "" {
				listen = existing.Listen
			}
			_ = tray.OpenTarget("http://" + displayHost(listen) + "/panel/")
			return nil
		}
		defer releaseInst()
	}

	cfg, created, err := config.LoadOrCreate(absCfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if !config.ValidAPIKey(cfg.APIKey) {
		return fmt.Errorf("set a valid api_key in config or AWSQUICK_API_KEY")
	}
	if !config.ValidAdminKey(cfg.AdminKey) {
		return fmt.Errorf("set a valid admin_key in config or AWSQUICK_ADMIN_KEY")
	}
	anchorRelativePaths(cfg, cfgDir)

	if err := os.MkdirAll(cfg.AuthDir, 0o700); err != nil {
		return fmt.Errorf("mkdir auth_dir: %w", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("mkdir data_dir: %w", err)
	}

	vault, err := auth.OpenOrCreateVault(cfg.EncryptionKeyFile(), os.Getenv("AWSQUICK_ENCRYPTION_KEY"))
	if err != nil {
		return fmt.Errorf("init credential vault: %w", err)
	}

	rec := reqlog.New(cfg.RequestLogDir(), cfg.Features.RequestArchive)
	if cfg.Features.RequestArchive {
		if loaded := rec.LoadFromArchive(); loaded > 0 {
			log.Printf("[reqlog] restored %d archived metadata record(s) from %s", loaded, cfg.RequestLogDir())
		}
	}

	logFilePath := filepath.Join(cfg.DataDir, "awsquick2api.log")
	if logFileHint != nil {
		*logFileHint = logFilePath
	}
	fileLog, flErr := reqlog.NewRotatingFileWriter(logFilePath, 5<<20)
	if flErr != nil {
		log.SetOutput(&bestEffortLogWriter{writers: []io.Writer{rec, os.Stderr}})
		log.Printf("WARN: [log] failed to open rotating log %s: %v", logFilePath, flErr)
	} else {
		log.SetOutput(&bestEffortLogWriter{writers: []io.Writer{fileLog, rec, os.Stderr}})
		if closeLog != nil {
			*closeLog = sync.OnceFunc(func() { _ = fileLog.Close() })
		} else {
			defer func() { _ = fileLog.Close() }()
		}
	}
	if created {
		log.Printf("[config] %s not found; generated default config with independent api_key and admin_key (read them from %s)", absCfgPath, absCfgPath)
	}

	accts, err := auth.LoadDir(cfg.AuthDir, vault)
	if err != nil {
		rec.Close()
		return fmt.Errorf("load auths from %s: %w", cfg.AuthDir, err)
	}
	log.Printf("[auth] loaded %d encrypted Amazon Quick account(s) from %s", len(accts), cfg.AuthDir)

	p := pool.New(pool.Config{
		StateFile:       cfg.StateFile(),
		MaxInFlight:     cfg.Pool.MaxInFlight,
		SoftCooldown:    time.Duration(cfg.Pool.SoftCooldownSec) * time.Second,
		SoftCooldownMax: time.Duration(cfg.Pool.SoftCooldownMaxSec) * time.Second,
		BreakerThresh:   cfg.Pool.BreakerThreshold,
		BreakerCooldown: time.Duration(cfg.Pool.BreakerCooldownSec) * time.Second,
		Strategy:        cfg.Pool.SelectionStrategy,
	})
	p.SyncAccounts(accts)

	modelsPath := filepath.Join(cfgDir, "models.json")
	cat := upstream.LoadCatalogFile(modelsPath)
	up := upstream.NewClient(cfg.Upstream, cat)

	sess := session.New(time.Duration(cfg.Session.TTLMinutes) * time.Minute)
	sess.UpdateConfig(cfg.Session.Enabled, time.Duration(cfg.Session.TTLMinutes)*time.Minute)
	sess.StartGC()
	defer sess.StopGC()

	sch := scheduler.New(scheduler.Config{
		Pool:                p,
		Upstream:            up,
		Vault:               vault,
		AuthDir:             cfg.AuthDir,
		QuotaEnabled:        cfg.Schedule.QuotaRefreshEnabled,
		QuotaInterval:       time.Duration(cfg.Schedule.QuotaRefreshMinutes) * time.Minute,
		TokenRefreshEnabled: cfg.Schedule.TokenRefreshEnabled,
		TokenCheckInterval:  time.Duration(cfg.Schedule.TokenRefreshCheckMinutes) * time.Minute,
		TokenRefreshAdvance: time.Duration(cfg.Schedule.TokenRefreshAdvanceMinute) * time.Minute,
	})

	cbMgr := auth.NewCallbackManager(
		func() *http.Client {
			return up.HTTPClient(30 * time.Second)
		},
		func(acct *auth.Account) error {
			store := pool.CredentialStore{Pool: p, Dir: cfg.AuthDir, Vault: vault}
			if _, err := store.Put(acct, true, true); err != nil {
				return err
			}
			log.Printf("[auth] added/updated account uid=%s provider=%s", acct.UID, acct.Provider)
			go func(uid string) {
				qctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				_, _ = sch.RefreshOneQuota(qctx, uid)
			}(acct.UID)
			return nil
		},
	)
	// The OAuth callback servers are closed explicitly during shutdown, after
	// in-flight requests have drained; the deferred call covers early returns.
	closeCallbacks := sync.OnceFunc(cbMgr.Close)
	defer closeCallbacks()

	live := config.NewLiveHolder(cfg)
	var cfgMu sync.Mutex
	bootCfg := *cfg
	currentCfg := cfg

	var pn *panel.Panel
	pn = panel.New(panel.Config{
		Pool:         p,
		Vault:        vault,
		Upstream:     up,
		Scheduler:    sch,
		Session:      sess,
		ReqLog:       rec,
		Live:         live,
		CallbackMgr:  cbMgr,
		AuthDir:      cfg.AuthDir,
		ConfigPath:   absCfgPath,
		ModelsPath:   modelsPath,
		Version:      appVersion,
		EnvOverrides: config.ActiveEnvOverrides,
		// Effective listen address (after AWSQUICK_LISTEN) for the panel's Host-header guard.
		ListenAddr:   cfg.Listen,
		TrustedHosts: cfg.Server.TrustedHosts,
		// Imported accounts get their quota / AdvancedEnabled synced right away instead
		// of waiting for the next scheduled refresh. Panel already calls this in its own goroutine.
		OnAccountsImported: func(uids []string) {
			for _, uid := range uids {
				qctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				if _, err := sch.RefreshOneQuota(qctx, uid); err != nil {
					log.Printf("WARN: [panel] quota sync after import uid=%s: %v", uid, err)
				}
				cancel()
			}
		},
		LoadConfig: func() (*config.Config, error) {
			cfgMu.Lock()
			defer cfgMu.Unlock()
			return config.LoadFileOnly(absCfgPath)
		},
		SaveConfig: func(raw []byte) (panel.SaveConfigResult, error) {
			cfgMu.Lock()
			defer cfgMu.Unlock()
			next, _, err := config.SaveFull(absCfgPath, raw, currentCfg)
			if err != nil {
				return panel.SaveConfigResult{}, err
			}
			restartFields := config.DiffRestartFields(&bootCfg, next)
			currentCfg = next
			live.UpdateFrom(next)
			pn.UpdateTrustedHosts(next.Server.TrustedHosts)
			p.UpdateConfig(pool.Config{
				MaxInFlight:     next.Pool.MaxInFlight,
				SoftCooldown:    time.Duration(next.Pool.SoftCooldownSec) * time.Second,
				SoftCooldownMax: time.Duration(next.Pool.SoftCooldownMaxSec) * time.Second,
				BreakerThresh:   next.Pool.BreakerThreshold,
				BreakerCooldown: time.Duration(next.Pool.BreakerCooldownSec) * time.Second,
				Strategy:        next.Pool.SelectionStrategy,
			})
			sch.UpdateConfig(
				next.Schedule.QuotaRefreshEnabled,
				next.Schedule.QuotaRefreshMinutes,
				next.Schedule.TokenRefreshEnabled,
				next.Schedule.TokenRefreshCheckMinutes,
				next.Schedule.TokenRefreshAdvanceMinute,
			)
			up.UpdateConfig(next.Upstream)
			sess.UpdateConfig(next.Session.Enabled, time.Duration(next.Session.TTLMinutes)*time.Minute)
			rec.SetArchive(next.Features.RequestArchive)
			log.Printf("[config] saved hot-reloaded configuration (restart_required=%v)", restartFields)
			return panel.SaveConfigResult{
				RestartRequired:   restartFields,
				EffectiveAPIKey:   next.APIKey,
				EffectiveAdminKey: next.AdminKey,
				EnvOverrides:      config.ActiveEnvOverrides(),
			}, nil
		},
	})

	gw := server.NewHandler(server.Config{
		Pool:                    p,
		Upstream:                up,
		Scheduler:               sch,
		Session:                 sess,
		Live:                    live,
		ReqLog:                  rec,
		Panel:                   pn,
		MaxPayloadBytes:         cfg.Server.MaxPayloadBytes,
		MaxInflightPayloadBytes: cfg.Server.MaxInflightPayloadBytes,
		MaxRotate:               cfg.Pool.MaxRotate,
		Version:                 appVersion,
	})

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancelApp := context.WithCancel(sigCtx)
	defer cancelApp()

	reqCtx, cancelReqs := context.WithCancel(context.Background())
	defer cancelReqs()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		rec.Close()
		return fmt.Errorf("http listen %s: %w", cfg.Listen, err)
	}

	// The scheduler has its own context so token refresh keeps serving in-flight
	// requests until the HTTP server has drained during shutdown.
	schCtx, cancelSch := context.WithCancel(context.Background())
	defer cancelSch()
	var bgWG sync.WaitGroup
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		sch.Run(schCtx)
	}()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           gw,
		BaseContext:       func(net.Listener) context.Context { return reqCtx },
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	hostAddr := displayHost(cfg.Listen)
	panelURL := "http://" + hostAddr + "/panel/"
	openAIBase := "http://" + hostAddr + "/v1"

	if !noTray {
		trayCtrl, terr := tray.Start(tray.Config{
			Tooltip:      fmt.Sprintf("AWSQuick2API · %s", hostAddr),
			PanelURL:     func() string { return panelURL },
			OpenAIBase:   func() string { return openAIBase },
			APIKey:       func() string { return live.Load().APIKey },
			AdminKey:     func() string { return live.Load().AdminKey },
			ConfigDir:    cfgDir,
			LogFile:      logFilePath,
			ExePath:      exePath,
			ConfigPath:   absCfgPath,
			ShowStartup:  created,
			StartupTitle: "AWSQuick2API 已在后台运行",
			StartupBody:  fmt.Sprintf("管理面板：%s\n右键托盘图标可一键复制 admin_key / api_key 或开启开机自启", panelURL),
			OnQuit: func() {
				log.Printf("[tray] quit requested by user")
				cancelApp()
			},
		})
		if terr != nil {
			log.Printf("WARN: [tray] failed to initialize system tray: %v", terr)
		} else {
			defer trayCtrl.Stop()
		}
		if created || *openFlag {
			go func() { _ = tray.OpenTarget(panelURL) }()
		}
	} else if *openFlag {
		go func() { _ = tray.OpenTarget(panelURL) }()
	}

	if warn := insecureKeyWarning(cfg.Listen, cfg.APIKey, cfg.AdminKey); warn != "" {
		log.Printf("WARN: %s", warn)
	}
	log.Printf("================================================================")
	log.Printf("AWSQuick2API v%s listening on http://%s", appVersion, hostAddr)
	log.Printf("Web Panel : %s", panelURL)
	log.Printf("API Key   : %s (inference /v1/* — see %s)", maskKey(cfg.APIKey), absCfgPath)
	log.Printf("Admin Key : %s (panel /panel/*  — see %s)", maskKey(cfg.AdminKey), absCfgPath)
	log.Printf("Log File  : %s", logFilePath)
	log.Printf("Endpoints : /v1/chat/completions | /v1/messages | /v1/responses | /v1/models")
	log.Printf("================================================================")

	// finishShutdown runs once the HTTP server has drained (or been force-closed):
	// OAuth callback servers -> scheduler -> pool state flush. rec.Close() runs last.
	finishShutdown := func() {
		closeCallbacks()
		cancelSch()
		bgWG.Wait()
		if ferr := p.Flush(); ferr != nil {
			log.Printf("WARN: pool flush on shutdown: %v", ferr)
		}
	}

	shutdownTimeout := time.Duration(cfg.Server.ShutdownTimeoutSeconds) * time.Second
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		// Restore default signal handling so a second Ctrl+C / SIGTERM force-exits.
		stop()
		log.Printf("[shutdown] no longer accepting connections; waiting up to %s for in-flight requests", shutdownTimeout)
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		// Shutdown closes the listener first, then waits for active requests
		// (including long SSE streams). Request contexts are cancelled only when
		// that exceeds shutdown_timeout_seconds.
		if err := srv.Shutdown(sctx); err != nil {
			log.Printf("WARN: graceful shutdown timed out after %s: %v; cancelling in-flight requests", shutdownTimeout, err)
			cancelReqs()
			_ = srv.Close()
		}
	}()

	listenErr := srv.Serve(ln)
	if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
		cancelReqs()
		cancelApp()
		<-shutdownDone
		finishShutdown()
		rec.Close()
		return fmt.Errorf("http serve: %w", listenErr)
	}

	// Serve returns ErrServerClosed as soon as Shutdown starts; wait for the drain.
	<-shutdownDone
	cancelReqs()
	finishShutdown()
	log.Printf("awsquick2api exited cleanly")
	rec.Close()
	return nil
}

func loadConfigOrEnvDefaults(absCfgPath string) (*config.Config, error) {
	cfg, err := config.Load(absCfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.Load("")
		}
		return nil, err
	}
	return cfg, nil
}

func runExportEncrypted(absCfgPath, cfgDir, outPath string) error {
	cfg, err := loadConfigOrEnvDefaults(absCfgPath)
	if err != nil {
		return err
	}
	anchorRelativePaths(cfg, cfgDir)
	vault, err := auth.OpenOrCreateVault(cfg.EncryptionKeyFile(), os.Getenv("AWSQUICK_ENCRYPTION_KEY"))
	if err != nil {
		return err
	}
	accts, err := auth.LoadDir(cfg.AuthDir, vault)
	if err != nil {
		return err
	}
	if len(accts) == 0 {
		return fmt.Errorf("no accounts found in %s", cfg.AuthDir)
	}
	fmt.Printf("Found %d account(s) in %s.\nEnter export passphrase (>= 12 chars): ", len(accts), cfg.AuthDir)
	pass, err := readLineStdin()
	if err != nil {
		return err
	}
	sealed, err := auth.EncryptAccounts(accts, pass)
	if err != nil {
		return err
	}
	if err := safefile.WriteAtomic(outPath, sealed, 0o600); err != nil {
		return err
	}
	fmt.Printf("Exported %d account(s) to %s\n", len(accts), outPath)
	return nil
}

func runImportEncrypted(absCfgPath, cfgDir, inPath string, overwrite bool) error {
	cfg, err := loadConfigOrEnvDefaults(absCfgPath)
	if err != nil {
		return err
	}
	anchorRelativePaths(cfg, cfgDir)
	vault, err := auth.OpenOrCreateVault(cfg.EncryptionKeyFile(), os.Getenv("AWSQUICK_ENCRYPTION_KEY"))
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	fmt.Printf("Enter passphrase to decrypt %s: ", inPath)
	pass, err := readLineStdin()
	if err != nil {
		return err
	}
	accts, err := auth.DecryptAccounts(raw, pass)
	if err != nil {
		return err
	}
	imported, skipped, err := importEncryptedAccounts(cfg.AuthDir, vault, accts, overwrite)
	if err != nil {
		return err
	}
	fmt.Printf("Imported %d account(s) into %s (skipped %d existing)\n", imported, cfg.AuthDir, skipped)
	return nil
}

func importEncryptedAccounts(authDir string, vault *auth.Vault, accts []*auth.Account, overwrite bool) (int, int, error) {
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		return 0, 0, err
	}
	// Validate every account before persisting any so a tampered bundle fails cleanly.
	for _, a := range accts {
		if a == nil || (strings.TrimSpace(a.AccessToken) == "" && strings.TrimSpace(a.RefreshToken) == "") {
			return 0, 0, fmt.Errorf("imported account missing tokens")
		}
		if verr := auth.ValidateImportedAccountEndpoints(a); verr != nil {
			label := a.UID
			if !auth.ValidUID(label) {
				label = "(invalid uid)"
			}
			return 0, 0, fmt.Errorf("imported account %s failed endpoint validation: %w", label, verr)
		}
	}
	existing, _ := auth.LoadDir(authDir, vault)
	hasUID := map[string]bool{}
	for _, a := range existing {
		hasUID[a.UID] = true
	}
	imported, skipped := 0, 0
	for _, a := range accts {
		a.Provider = auth.NormalizeProvider(a.Provider)
		a.Stage = auth.NormalizeStage(a.Stage)
		if !auth.ValidUID(a.UID) {
			ident := a.Email
			if ident == "" {
				ident = a.AccountID
			}
			a.UID = auth.MakeUID(a.Provider, ident)
		}
		if !auth.IsDeviceID(a.DeviceID) {
			a.DeviceID = auth.NewUUID()
		}
		if !overwrite && hasUID[a.UID] {
			skipped++
			continue
		}
		if err := auth.SaveAccount(authDir, vault, a); err != nil {
			return imported, skipped, err
		}
		hasUID[a.UID] = true
		imported++
	}
	return imported, skipped, nil
}

func readLineStdin() (string, error) {
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func resolveConfigPath(flagPath, exePath string) string {
	p := strings.TrimSpace(flagPath)
	if p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return p
	}
	if _, err := os.Stat("config.json"); err == nil {
		if abs, aerr := filepath.Abs("config.json"); aerr == nil {
			return abs
		}
	}
	if exePath != "" {
		return filepath.Join(filepath.Dir(exePath), "config.json")
	}
	if abs, err := filepath.Abs("config.json"); err == nil {
		return abs
	}
	return "config.json"
}

func anchorRelativePaths(cfg *config.Config, baseDir string) {
	if cfg == nil {
		return
	}
	cfg.AnchorPaths(baseDir)
}

func isEnvTruthy(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes"
}

func displayHost(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "127.0.0.1" + listen
	}
	if strings.HasPrefix(listen, "0.0.0.0:") {
		return "127.0.0.1:" + strings.TrimPrefix(listen, "0.0.0.0:")
	}
	return listen
}

func maskKey(k string) string {
	if len(k) <= 8 {
		if k == "" {
			return "<empty>"
		}
		return "****"
	}
	return k[:5] + "..." + k[len(k)-4:]
}

type bestEffortLogWriter struct {
	writers []io.Writer
}

func (w *bestEffortLogWriter) Write(p []byte) (int, error) {
	scrubbed := []byte(reqlog.ScrubCredentials(string(p)))
	for _, dst := range w.writers {
		if dst != nil {
			_, _ = dst.Write(scrubbed)
		}
	}
	return len(p), nil
}

func insecureKeyWarning(listen, apiKey, adminKey string) string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost") {
		return ""
	}
	if apiKey == "" || apiKey == "replace_with_your_api_key" || adminKey == "" || adminKey == "replace_with_your_admin_key" {
		return fmt.Sprintf("api_key or admin_key is empty/default while listening on non-loopback %s; set strong keys in config.json", listen)
	}
	return ""
}

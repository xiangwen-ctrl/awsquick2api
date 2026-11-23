package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"awsquick2api/internal/auth"
)

func (p *Panel) handleAccountsExportEncrypted(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	accts := p.cfg.Pool.AllAccounts(true)
	if len(accts) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "当前没有可导出的账号"})
		return
	}
	sealed, err := auth.EncryptAccounts(accts, req.Passphrase)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="awsquick2api-accounts.enc.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

func (p *Panel) handleAccountsImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Payload    json.RawMessage `json:"payload"`
		Passphrase string          `json:"passphrase"`
		Overwrite  bool            `json:"overwrite"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	raw := req.Payload
	if len(raw) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少导入数据 payload"})
		return
	}
	if !auth.IsEncryptedBundle(raw) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请导入有效的加密账号迁移包（.enc.json）"})
		return
	}

	parsed, err := auth.DecryptAccounts(raw, req.Passphrase)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if len(parsed) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "未在加密迁移包中解析到有效账号"})
		return
	}

	imported := 0
	skipped := 0
	var errs []string
	for _, a := range parsed {
		if a == nil || (strings.TrimSpace(a.AccessToken) == "" && strings.TrimSpace(a.RefreshToken) == "") {
			errs = append(errs, "跳过缺少 token 的记录")
			continue
		}
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
		if !req.Overwrite && p.cfg.Pool.AuthByUID(a.UID) != nil {
			skipped++
			continue
		}
		if p.cfg.AuthDir != "" {
			if err := auth.SaveAccount(p.cfg.AuthDir, p.cfg.Vault, a); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", a.UID, err))
				continue
			}
		}
		p.cfg.Pool.AddOrUpdate(a)
		imported++
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"imported": imported,
		"skipped":  skipped,
		"errors":   errs,
	})
}

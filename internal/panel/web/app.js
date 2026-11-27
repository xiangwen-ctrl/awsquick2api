(() => {
  "use strict";

  const KEY_STORAGE = "awsquick2api_panel_admin_key";
  const REMEMBER_STORAGE = "awsquick2api_panel_remember";
  const THEME_STORAGE = "awsquick2api_panel_theme";

  let rememberLogin = localStorage.getItem(REMEMBER_STORAGE) === "1";
  let adminKey = sessionStorage.getItem(KEY_STORAGE) || (rememberLogin ? localStorage.getItem(KEY_STORAGE) || "" : "");
  let inferenceApiKey = "";
  let showPlainKey = false;
  let requestsCache = [];
  let keysCache = [];
  let logsCache = [];
  let activeLoginId = "";
  let loginPollTimer = null;

  function saveAdminKey(key, remember) {
    sessionStorage.setItem(KEY_STORAGE, key);
    if (remember) {
      localStorage.setItem(REMEMBER_STORAGE, "1");
      localStorage.setItem(KEY_STORAGE, key);
    } else {
      localStorage.removeItem(REMEMBER_STORAGE);
      localStorage.removeItem(KEY_STORAGE);
    }
  }

  function clearAdminKey() {
    sessionStorage.removeItem(KEY_STORAGE);
    localStorage.removeItem(KEY_STORAGE);
    localStorage.removeItem(REMEMBER_STORAGE);
  }

  const $ = (id) => document.getElementById(id);

  function showToast(msg, isErr = false) {
    const el = $("toast");
    el.textContent = msg;
    el.style.borderColor = isErr ? "var(--err)" : "var(--border)";
    el.classList.remove("hidden");
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => el.classList.add("hidden"), 3200);
  }

  function reportAsyncError(err) {
    if (err?.message && err.message !== "unauthorized") {
      showToast(err.message, true);
    }
  }

  function copyText(text, successMsg) {
    if (!navigator.clipboard?.writeText) {
      showToast("当前浏览器环境不支持一键复制，请手动复制", true);
      return;
    }
    navigator.clipboard
      .writeText(text)
      .then(() => showToast(successMsg))
      .catch(() => showToast("复制失败，请手动复制", true));
  }

  function esc(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // safeExternalURL only lets absolute http(s) URLs through to an <a>.href;
  // anything else (javascript:, data:, vbscript:, relative junk) becomes "#".
  function safeExternalURL(raw) {
    if (typeof raw !== "string" || !raw.trim()) return "#";
    try {
      const u = new URL(raw.trim());
      if (u.protocol === "http:" || u.protocol === "https:") return u.href;
    } catch {
      /* invalid URL */
    }
    return "#";
  }

  async function api(path, opts = {}) {
    const headers = { ...(opts.headers || {}), Authorization: `Bearer ${adminKey}` };
    if (opts.body !== undefined && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const res = await fetch(path, {
      ...opts,
      headers,
      body: opts.body !== undefined && typeof opts.body !== "string" ? JSON.stringify(opts.body) : opts.body,
    });
    if (res.status === 401) {
      clearAdminKey();
      adminKey = "";
      showAuthGate("面板管理密钥 (admin_key) 无效或已更改，请重新输入。");
      throw new Error("unauthorized");
    }
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  }

  function fmtTime(ms) {
    if (!ms) return "-";
    const d = new Date(ms);
    return d.toLocaleTimeString("zh-CN", { hour12: false });
  }

  function fmtDateTime(ms) {
    if (!ms) return "-";
    const d = new Date(ms);
    return d.toLocaleString("zh-CN", { hour12: false });
  }

  function toLocalDateTimeInput(ms) {
    if (!ms) return "";
    const d = new Date(ms);
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function fmtExpiry(ms) {
    if (!ms) return "未知";
    const diff = Math.floor((ms - Date.now()) / 1000);
    if (diff <= 0) return "已过期";
    if (diff < 3600) return `${Math.ceil(diff / 60)} 分钟`;
    if (diff < 86400) return `${(diff / 3600).toFixed(1)} 小时`;
    return `${(diff / 86400).toFixed(1)} 天`;
  }

  function fmtUptime(sec) {
    sec = Number(sec) || 0;
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m`;
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    return `${h}h ${m}m`;
  }

  function fmtNum(n) {
    n = Number(n) || 0;
    if (n >= 1e6) return (n / 1e6).toFixed(2) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
    return String(Math.round(n));
  }

  function applyTheme(light) {
    document.body.classList.toggle("light", !!light);
    localStorage.setItem(THEME_STORAGE, light ? "light" : "dark");
  }
  applyTheme(localStorage.getItem(THEME_STORAGE) === "light");
  if ($("auth-remember")) $("auth-remember").checked = rememberLogin;

  function showAuthGate(errText = "") {
    $("app").classList.add("hidden");
    $("auth-gate").classList.remove("hidden");
    const errEl = $("auth-err");
    if (errText) {
      errEl.textContent = errText;
      errEl.classList.remove("hidden");
    } else {
      errEl.classList.add("hidden");
    }
    $("auth-key-input").focus();
  }

  function showApp() {
    $("auth-gate").classList.add("hidden");
    $("app").classList.remove("hidden");
  }

  async function initSession() {
    if (!adminKey) {
      showAuthGate();
      return;
    }
    try {
      await loadAll();
      showApp();
    } catch {
      clearAdminKey();
      adminKey = "";
      showAuthGate("请先输入正确的 admin_key");
    }
  }

  $("auth-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const val = $("auth-key-input").value.trim();
    if (!val) return;
    rememberLogin = !!$("auth-remember")?.checked;
    adminKey = val;
    try {
      await loadAll();
      saveAdminKey(adminKey, rememberLogin);
      $("auth-key-input").value = "";
      showApp();
    } catch (err) {
      adminKey = "";
      showAuthGate("解锁失败：" + err.message);
    }
  });

  $("btn-logout").addEventListener("click", () => {
    clearAdminKey();
    adminKey = "";
    inferenceApiKey = "";
    showAuthGate();
  });

  $("btn-theme").addEventListener("click", () => {
    applyTheme(!document.body.classList.contains("light"));
  });

  // Tab navigation
  const tabTitles = {
    overview: "总览与账号池",
    models: "模型与接入",
    keys: "访问密钥",
    requests: "请求统计",
    config: "配置（热生效）",
    logs: "运行日志",
  };
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab;
      document.querySelectorAll(".nav-item").forEach((b) => {
        b.classList.toggle("active", b === btn);
        b.setAttribute("aria-selected", b === btn ? "true" : "false");
      });
      document.querySelectorAll(".tab-panel").forEach((sec) => {
        sec.classList.toggle("active", sec.id === `tab-${tab}`);
      });
      $("page-title").textContent = tabTitles[tab] || tab;
      const tabLoaders = {
        models: loadModels,
        keys: loadKeys,
        requests: loadRequests,
        config: loadConfig,
        logs: loadLogs,
      };
      if (tabLoaders[tab]) {
        tabLoaders[tab]().catch(reportAsyncError);
      }
    });
  });

  // Modal close handlers
  document.querySelectorAll("[data-close-modal]").forEach((btn) => {
    btn.addEventListener("click", () => closeModal(btn.dataset.closeModal));
  });
  function openModal(id) {
    $(id).classList.remove("hidden");
  }
  function closeModal(id) {
    $(id).classList.add("hidden");
    if (id === "modal-login") {
      cancelActiveLogin();
    }
  }

  async function loadAll() {
    await Promise.all([loadOverview(), loadAccounts()]);
    renderSnippets();
  }

  $("btn-refresh-now").addEventListener("click", () => {
    loadAll().then(() => showToast("已刷新")).catch((e) => showToast(e.message, true));
  });

  async function loadOverview() {
    const data = await api("/panel/api/overview");
    $("version-badge").textContent = data.version ? "v" + data.version : "";
    $("proto-pill").textContent = `Quick ${data.app_version || "1.2.4660"}`;

    const uh = data.upstream_health;
    const warnPill = $("health-warn-pill");
    if (warnPill) {
      if (uh && uh.degraded) {
        warnPill.textContent = `上游劣化 (${uh.slow_percent || 0}%慢 / ${uh.fail_percent || 0}%5xx)`;
        warnPill.title = `近 5 分钟样本 ${uh.samples || 0} 条：慢响应(>=8s) ${uh.slow_count || 0} (${uh.slow_percent || 0}%)，最慢 TTFB ${uh.worst_ttfb_ms || 0}ms，5xx ${uh.fail_count || 0} (${uh.fail_percent || 0}%)`;
        warnPill.classList.remove("hidden");
      } else {
        warnPill.classList.add("hidden");
      }
    }

    const pool = data.pool || {};
    $("stat-accounts").textContent = `${pool.healthy || 0} / ${pool.total || 0}`;
    $("stat-accounts-sub").textContent = `在途 ${pool.in_flight || 0} · 冷却 ${pool.cooling || 0} · 禁用 ${pool.disabled || 0} · 粘性 ${data.sticky_count || 0}`;

    if ((pool.total_monthly_limit || 0) > 0) {
      $("stat-quota").textContent = `${Math.round(pool.total_monthly_avail || 0)} / ${Math.round(pool.total_monthly_limit || 0)}`;
      $("stat-quota-sub").textContent = `已同步 ${pool.quota_known_count || 0} 个账号月度额度`;
    } else {
      $("stat-quota").textContent = pool.quota_known_count ? `${pool.quota_known_count} 账号已同步` : "未同步";
      $("stat-quota-sub").textContent = "点击“刷新全部额度”拉取官方余额";
    }

    const m = data.metrics || {};
    const rate = m.total_requests > 0 ? `${(m.success_rate || 0).toFixed(1)}%` : "-";
    $("stat-reqs").textContent = `${rate} / ${m.total_requests || 0}`;
    $("stat-ttfb").textContent = `平均 TTFB ${m.avg_ttfb_ms || 0} ms · 线程复用 ${m.thread_reused || 0}`;

    $("stat-uptime").textContent = fmtUptime(data.uptime_sec);
    const activePorts = Array.isArray(data.active_cb_ports) && data.active_cb_ports.length ? data.active_cb_ports.join(",") : `${data.callback_port || 18080} (按需)`;
    const proxyLabel = data.proxy_configured ? " · 已配置出口代理" : " · 直连";
    $("stat-cb").textContent = `OAuth 回调 :${activePorts}${proxyLabel}`;
    renderPrivacyToggle(!!data.strict_privacy_dlp);
  }

  function renderPrivacyToggle(on) {
    const btn = $("btn-toggle-privacy-dlp");
    if (!btn) return;
    btn.classList.toggle("on", on);
    btn.classList.toggle("off", !on);
    btn.dataset.enabled = on ? "1" : "0";
    btn.setAttribute("aria-checked", on ? "true" : "false");
    btn.querySelector(".switch-label").textContent = on ? "已启用" : "已关闭";
  }

  function renderQuotaCell(q) {
    if (!q || !q.known) {
      return `<span class="muted">${esc(q?.unavailable_reason || "暂未同步")}</span>`;
    }
    const parts = [];
    if (q.plan) {
      parts.push(`<span class="badge">${esc(q.plan)}</span>${q.advanced_enabled ? ' <span class="pill ok" style="font-size:10px;padding:1px 5px;">Advanced</span>' : ""}`);
    }
    if (q.monthly_limit > 0 || q.monthly_percent > 0) {
      const pct = Math.min(100, Math.round(q.monthly_percent || (q.monthly_limit > 0 ? (q.monthly_used / q.monthly_limit) * 100 : 0)));
      const cls = pct >= 90 ? "err" : pct >= 70 ? "warn" : "";
      const label = q.monthly_limit > 0 ? `月度 ${Math.round(q.monthly_used)} / ${Math.round(q.monthly_limit)} (${pct}%)` : `月度 ${pct}%`;
      parts.push(`<div style="font-size:12px;margin-top:3px;">${esc(label)}</div><div class="progress ${cls}"><span style="width:${pct}%"></span></div>`);
    }
    if (q.session_limit > 0 || q.session_percent > 0) {
      const spct = Math.min(100, Math.round(q.session_percent || (q.session_limit > 0 ? (q.session_used / q.session_limit) * 100 : 0)));
      parts.push(`<div class="muted" style="font-size:11.5px;margin-top:3px;">会话 ${spct}%${q.session_resume_min > 0 ? ` · ${Math.round(q.session_resume_min)}m 后恢复` : ""}</div>`);
    }
    return parts.join("");
  }

  async function loadAccounts() {
    const data = await api("/panel/api/accounts");
    const tbody = $("accounts-tbody");
    const list = data.accounts || [];
    if (!list.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty">暂无 Amazon Quick 账号，点击右上角「+ 添加账号」完成浏览器登录。</td></tr>`;
      return;
    }
    tbody.innerHTML = list.map((a) => {
      let statusHtml = `<span class="pill ok">健康</span>`;
      if (a.disabled) {
        statusHtml = `<span class="pill err" title="${esc(a.disabled_reason)}">已禁用</span><div class="muted" style="font-size:11px;max-width:140px;overflow:hidden;text-overflow:ellipsis;">${esc(a.disabled_reason || "")}</div>`;
      } else if (a.cooldown_until && a.cooldown_until > Date.now()) {
        statusHtml = `<span class="pill warn" title="${esc(a.cooldown_reason)}">冷却 ${fmtExpiry(a.cooldown_until)}</span>`;
      }
      return `
        <tr data-uid="${esc(a.uid)}">
          <td>
            <div class="acct-name-row">
              <strong>${esc(a.display_name || a.uid)}</strong>
              <span class="pill info" style="font-size:11px;">${esc(a.provider_label || a.provider)}</span>
              <button type="button" class="btn-inline-edit" data-act="rename" data-uid="${esc(a.uid)}" data-name="${esc(a.custom_name || "")}">改名</button>
            </div>
            <div class="muted" style="font-size:11.5px;">${esc(a.email || a.uid)} · ${esc(a.region || "us-east-1")}</div>
          </td>
          <td>${statusHtml}${a.in_flight > 0 ? `<div class="muted" style="font-size:11px;">在途 ${a.in_flight}</div>` : ""}</td>
          <td>${renderQuotaCell(a.quota)}</td>
          <td>
            <div>${fmtExpiry(a.expires_at)}</div>
            <div class="muted" style="font-size:11px;">${a.has_refresh_token ? "含 Refresh" : "无 Refresh"}</div>
          </td>
          <td>
            <div>${a.total_reqs || 0} 次</div>
            <div class="muted" style="font-size:11px;">${fmtNum(a.total_tokens || 0)} tok</div>
          </td>
          <td>
            <div class="btn-group">
              <button type="button" class="btn small" data-act="test" data-uid="${esc(a.uid)}">测试</button>
              <button type="button" class="btn small" data-act="quota" data-uid="${esc(a.uid)}">额度</button>
              <button type="button" class="btn small" data-act="refresh" data-uid="${esc(a.uid)}">续期</button>
              ${a.disabled || (a.cooldown_until && a.cooldown_until > Date.now())
                ? `<button type="button" class="btn small" data-act="revive" data-uid="${esc(a.uid)}">恢复</button>`
                : `<button type="button" class="btn small" data-act="disable" data-uid="${esc(a.uid)}">禁用</button>`}
              <button type="button" class="btn danger small" data-act="delete" data-uid="${esc(a.uid)}">删除</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  $("accounts-tbody").addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const act = btn.dataset.act;
    const uid = btn.dataset.uid;
    btn.disabled = true;
    try {
      if (act === "test") {
        const res = await api(`/panel/api/accounts/${encodeURIComponent(uid)}/test`, { method: "POST" });
        if (res.ok) {
          showToast(`测试通过 (${res.latency_ms}ms · ${res.resolved_model || "Quick"}): ${String(res.reply || "").slice(0, 40)}`);
        } else {
          showToast(`测试失败: ${res.error}`, true);
        }
      } else if (act === "quota") {
        await api(`/panel/api/accounts/${encodeURIComponent(uid)}/quota`, { method: "POST" });
        showToast("额度已更新");
      } else if (act === "refresh") {
        await api(`/panel/api/accounts/${encodeURIComponent(uid)}/refresh`, { method: "POST" });
        showToast("Token 刷新成功");
      } else if (act === "revive") {
        await api(`/panel/api/accounts/${encodeURIComponent(uid)}/revive`, { method: "POST" });
        showToast("已恢复账号");
      } else if (act === "disable") {
        await api(`/panel/api/accounts/${encodeURIComponent(uid)}/disable`, { method: "POST", body: { reason: "manual_disabled" } });
        showToast("已禁用账号");
      } else if (act === "rename") {
        const next = prompt("输入自定义备注名（留空恢复默认）:", btn.dataset.name || "");
        if (next !== null) {
          await api(`/panel/api/accounts/${encodeURIComponent(uid)}/name`, { method: "PUT", body: { name: next } });
          showToast("备注已更新");
        }
      } else if (act === "delete") {
        if (confirm(`确认删除账号 ${uid} 吗？本地加密凭据文件将被移除。`)) {
          await api(`/panel/api/accounts/${encodeURIComponent(uid)}`, { method: "DELETE" });
          showToast("已删除账号");
        }
      }
      await loadOverview();
      await loadAccounts();
    } catch (err) {
      showToast(err.message, true);
    } finally {
      btn.disabled = false;
    }
  });

  // Bulk pool actions
  $("btn-sync-quotas").addEventListener("click", async () => {
    try {
      const r = await api("/panel/api/accounts/refresh-quotas", { method: "POST" });
      showToast(`已刷新 ${r.refreshed || 0} 个账号额度`);
      await loadAll();
    } catch (e) { showToast(e.message, true); }
  });
  $("btn-sync-tokens").addEventListener("click", async () => {
    try {
      await api("/panel/api/accounts/refresh-tokens", { method: "POST" });
      showToast("已完成临期续期检查");
      await loadAll();
    } catch (e) { showToast(e.message, true); }
  });

  // --- OAuth Login Modal ---
  function stopLoginPoll() {
    if (loginPollTimer) {
      clearInterval(loginPollTimer);
      loginPollTimer = null;
    }
  }

  function cancelActiveLogin() {
    stopLoginPoll();
    const id = activeLoginId;
    activeLoginId = "";
    if (id) {
      api(`/panel/api/login/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
    }
  }

  function updateLoginUI(view) {
    $("login-active-box").classList.remove("hidden");
    $("login-url-input").value = view.login_url || "";
    $("login-url-open").href = safeExternalURL(view.login_url);
    const statusMap = {
      awaiting_discovery: ["等待第 1 步：打开登录链接并在浏览器完成账号登录...", "warn"],
      discovering: ["正在与 AWS OIDC 交换发现信息...", "info"],
      awaiting_authorization: ["等待第 2 步：在浏览器中确认 AWS 授权...", "info"],
      exchanging: ["正在交换 OAuth Token 并拉取用户信息...", "info"],
      authorized: [`登录成功：${view.account_label || view.account_uid}`, "ok"],
      failed: [`登录失败：${view.error || "未知错误"}`, "err"],
      expired: ["授权链接已过期，请重新生成", "err"],
      cancelled: ["登录会话已取消", "warn"],
    };
    const [txt, cls] = statusMap[view.status] || [view.status, "warn"];
    $("login-status-text").textContent = txt;
    const pill = $("login-status-pill");
    pill.textContent = view.status;
    pill.className = `pill ${cls}`;

    if (view.authorize_url) {
      $("login-authz-wrap").classList.remove("hidden");
      $("login-authz-input").value = view.authorize_url;
      $("login-authz-open").href = safeExternalURL(view.authorize_url);
    } else {
      $("login-authz-wrap").classList.add("hidden");
    }

    if (view.status === "authorized") {
      stopLoginPoll();
      activeLoginId = "";
      $("login-msg").textContent = `账号 ${view.account_label || view.account_uid} 已加密保存并加入账号池！建议点击“测试”验证连通性。`;
      $("login-msg").classList.remove("hidden");
      $("login-err").classList.add("hidden");
      loadAll().catch(reportAsyncError);
    } else if (view.status === "failed" || view.status === "expired" || view.status === "cancelled") {
      stopLoginPoll();
      activeLoginId = "";
      $("login-err").textContent = view.error || txt;
      $("login-err").classList.remove("hidden");
    }
  }

  $("btn-add-account").addEventListener("click", () => {
    $("login-msg").classList.add("hidden");
    $("login-err").classList.add("hidden");
    $("login-active-box").classList.add("hidden");
    $("login-paste-url").value = "";
    openModal("modal-login");
  });

  $("btn-login-start").addEventListener("click", async () => {
    cancelActiveLogin();
    $("login-msg").classList.add("hidden");
    $("login-err").classList.add("hidden");
    try {
      const view = await api("/panel/api/login/start", {
        method: "POST",
        body: {
          provider: $("login-provider").value,
          region: $("login-region").value.trim() || "us-east-1",
        },
      });
      activeLoginId = view.session_id;
      updateLoginUI(view);
      loginPollTimer = setInterval(async () => {
        if (!activeLoginId) return;
        try {
          const st = await api(`/panel/api/login/${encodeURIComponent(activeLoginId)}/status`);
          updateLoginUI(st);
        } catch {
          stopLoginPoll();
        }
      }, 2000);
    } catch (e) {
      $("login-err").textContent = e.message;
      $("login-err").classList.remove("hidden");
    }
  });

  $("btn-login-copy").addEventListener("click", () => {
    copyText($("login-url-input").value, "已复制登录链接");
  });
  $("btn-login-authz-copy").addEventListener("click", () => {
    copyText($("login-authz-input").value, "已复制第 2 步授权链接");
  });

  $("btn-login-paste-submit").addEventListener("click", async () => {
    if (!activeLoginId) return;
    const rawUrl = $("login-paste-url").value.trim();
    if (!rawUrl) return;
    $("login-err").classList.add("hidden");
    try {
      const view = await api(`/panel/api/login/${encodeURIComponent(activeLoginId)}/callback-url`, {
        method: "POST",
        body: { url: rawUrl },
      });
      $("login-paste-url").value = "";
      updateLoginUI(view);
      if (view.status === "awaiting_authorization") {
        showToast("第 1 步发现完成！请打开第 2 步授权链接并在完成后再次粘贴回调 URL");
      }
    } catch (e) {
      $("login-err").textContent = e.message;
      $("login-err").classList.remove("hidden");
    }
  });

  // --- Encrypted Import / Export ---
  $("btn-open-import").addEventListener("click", () => {
    $("import-msg").classList.add("hidden");
    $("import-err").classList.add("hidden");
    $("import-pass").value = "";
    openModal("modal-import");
  });
  $("import-file").addEventListener("change", (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => { $("import-json").value = String(reader.result || ""); };
    reader.readAsText(f);
  });
  $("btn-do-import").addEventListener("click", async () => {
    $("import-msg").classList.add("hidden");
    $("import-err").classList.add("hidden");
    try {
      const payload = JSON.parse($("import-json").value.trim());
      const res = await api("/panel/api/accounts/import", {
        method: "POST",
        body: {
          payload,
          passphrase: $("import-pass").value,
          overwrite: $("import-overwrite").checked,
        },
      });
      $("import-msg").textContent = `导入成功 ${res.imported} 个，跳过 ${res.skipped} 个` + (res.errors?.length ? `，错误：${res.errors.join("; ")}` : "");
      $("import-msg").classList.remove("hidden");
      await loadAll();
    } catch (e) {
      $("import-err").textContent = e.message;
      $("import-err").classList.remove("hidden");
    }
  });

  $("btn-open-export-enc").addEventListener("click", () => {
    $("export-enc-err").classList.add("hidden");
    $("export-pass").value = "";
    openModal("modal-export-enc");
  });
  $("btn-do-export-enc").addEventListener("click", async () => {
    $("export-enc-err").classList.add("hidden");
    try {
      const data = await api("/panel/api/accounts/export-encrypted", {
        method: "POST",
        body: { passphrase: $("export-pass").value },
      });
      downloadJSON(data, "awsquick2api-accounts.enc.json");
      closeModal("modal-export-enc");
      showToast("已下载加密迁移文件");
    } catch (e) {
      $("export-enc-err").textContent = e.message;
      $("export-enc-err").classList.remove("hidden");
    }
  });

  function downloadJSON(obj, filename) {
    const blob = new Blob([JSON.stringify(obj, null, 2) + "\n"], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  // --- Models & Snippets ---
  async function loadModels() {
    const data = await api("/panel/api/models");
    if (typeof data.api_key === "string") {
      inferenceApiKey = data.api_key;
    }
    const tbody = $("models-tbody");
    tbody.innerHTML = (data.models || []).map((m) => {
      const caps = [
        m.caps?.text ? "文本" : "",
        m.caps?.image ? "视觉" : "",
        m.caps?.tools ? "工具" : "",
        m.caps?.reasoning ? "思考" : "",
      ].filter(Boolean).join(" · ");
      return `
        <tr>
          <td>
            <div class="acct-name-row">
              <code>${esc(m.name)}</code>
              <button type="button" class="btn-inline-edit" data-rename-slot="${esc(m.slot)}" data-cur-id="${esc(m.name)}" data-cur-disp="${esc(m.display)}">改名</button>
            </div>
            <div class="muted" style="font-size:11.5px;">${esc(m.display || "")}</div>
          </td>
          <td>
            <button type="button" class="switch-btn ${m.visible ? "on" : "off"}" data-vis-id="${esc(m.name)}" data-vis="${m.visible ? "1" : "0"}">
              <span class="switch-track"><span class="switch-thumb"></span></span>
              <span class="switch-label">${m.visible ? "显示" : "隐藏"}</span>
            </button>
          </td>
          <td><code>${esc(m.slot)}</code></td>
          <td>${fmtNum(m.context_window)} / ${fmtNum(m.max_output_tokens)}</td>
          <td>${esc(caps)}</td>
          <td class="muted">${(m.alts || []).map((x) => `<code>${esc(x)}</code>`).join(" ")}</td>
        </tr>
      `;
    }).join("");

    const caBtn = $("btn-toggle-claude-aliases");
    const caOn = !!data.claude_aliases_enabled;
    caBtn.classList.toggle("on", caOn);
    caBtn.classList.toggle("off", !caOn);
    caBtn.dataset.enabled = caOn ? "1" : "0";
    caBtn.querySelector(".switch-label").textContent = caOn ? "已启用" : "已关闭";

    $("claude-aliases-tbody").innerHTML = (data.claude_aliases || []).map((ca) => `
      <tr><td><code>${esc(ca.name)}</code></td><td><code>${esc(ca.slot)}</code></td></tr>
    `).join("");
    renderSnippets();
  }

  $("models-tbody").addEventListener("click", async (e) => {
    const visBtn = e.target.closest("button[data-vis-id]");
    if (visBtn) {
      const next = visBtn.dataset.vis !== "1";
      try {
        await api(`/panel/api/models/${encodeURIComponent(visBtn.dataset.visId)}`, { method: "PATCH", body: { visible: next } });
        await loadModels();
      } catch (err) { showToast(err.message, true); }
      return;
    }
    const renBtn = e.target.closest("button[data-rename-slot]");
    if (renBtn) {
      const newID = prompt("新的对外模型 ID:", renBtn.dataset.curId || "");
      if (!newID) return;
      const newDisp = prompt("新的展示名称（可选）:", renBtn.dataset.curDisp || newID);
      try {
        const res = await api(`/panel/api/models/${encodeURIComponent(renBtn.dataset.renameSlot)}/rename`, {
          method: "PUT",
          body: { id: newID, display: newDisp || newID },
        });
        if (res.config_sync_error) {
          showToast(`模型名称已保存至 models.json，但同步 config.json 失败：${res.config_sync_error}`, true);
        } else {
          showToast("模型名称已保存至 models.json");
        }
        await loadModels();
      } catch (err) { showToast(err.message, true); }
    }
  });

  $("btn-toggle-claude-aliases").addEventListener("click", async () => {
    const next = $("btn-toggle-claude-aliases").dataset.enabled !== "1";
    try {
      await api("/panel/api/features/claude-aliases", { method: "PATCH", body: { enabled: next } });
      await loadModels();
    } catch (e) { showToast(e.message, true); }
  });

  $("btn-toggle-privacy-dlp").addEventListener("click", async () => {
    const next = $("btn-toggle-privacy-dlp").dataset.enabled !== "1";
    if (!next && !confirm("关闭严格隐私脱敏后，上游回复中的账号邮箱等信息可能直接返回给调用方，确定关闭？")) return;
    try {
      await api("/panel/api/features/strict-privacy-dlp", { method: "PATCH", body: { enabled: next } });
      renderPrivacyToggle(next);
      showToast(next ? "已启用严格隐私脱敏" : "已关闭严格隐私脱敏");
    } catch (e) { showToast(e.message, true); }
  });

  function renderSnippets() {
    const origin = window.location.origin;
    const rawKey = inferenceApiKey || "";
    const keyDisplay = !rawKey
      ? "<见 config.json 中的 api_key>"
      : showPlainKey
        ? rawKey
        : (rawKey.length > 10 ? rawKey.slice(0, 6) + "••••••••" + rawKey.slice(-4) : "••••••••");
    $("snippet-openai").textContent =
`Base URL: ${origin}/v1
API Key : ${keyDisplay}
推荐模型: amazon-smart / amazon-balanced / amazon-fast
思考后缀: amazon-smart-high / amazon-balanced-medium`;

    $("snippet-claude").textContent =
`# PowerShell (Claude Code)
$env:ANTHROPIC_BASE_URL = "${origin}"
$env:ANTHROPIC_AUTH_TOKEN = "${keyDisplay}"
claude`;

    $("snippet-codex").textContent =
`# ~/.codex/config.toml
model_provider = "awsquick"
model = "amazon-smart"

[model_providers.awsquick]
name = "AWSQuick2API"
base_url = "${origin}/v1"
env_key = "AWSQUICK_API_KEY"
wire_api = "responses"`;
  }

  $("btn-toggle-key").addEventListener("click", () => {
    showPlainKey = !showPlainKey;
    $("btn-toggle-key").textContent = showPlainKey ? "隐藏明文 api_key" : "显示明文 api_key";
    renderSnippets();
  });
  ["openai", "claude", "codex"].forEach((name) => {
    $(`btn-copy-${name}`).addEventListener("click", () => {
      copyText($(`snippet-${name}`).textContent, "已复制接入片段");
    });
  });

  // --- Scoped API Keys ---
  function splitCSV(raw) {
    return String(raw || "")
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function loadKeys() {
    const data = await api("/panel/api/keys");
    keysCache = data.keys || [];
    renderKeys();
  }

  function renderKeys() {
    const tbody = $("keys-tbody");
    if (!keysCache.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty">暂无访问密钥。点击右上角「+ 新建访问密钥」创建带模型/额度限制的子密钥（主密钥 api_key 仍可继续使用）。</td></tr>`;
      return;
    }
    tbody.innerHTML = keysCache.map((k) => {
      let statusHtml = `<span class="pill ok">启用</span>`;
      if (!k.enabled) {
        statusHtml = `<span class="pill err">已禁用</span>`;
      } else if (k.expired) {
        statusHtml = `<span class="pill err">已过期</span>`;
      }
      const modelsHtml = Array.isArray(k.allowed_models) && k.allowed_models.length
        ? k.allowed_models.map((m) => `<code>${esc(m)}</code>`).join(" ")
        : `<span class="muted">全部可见模型</span>`;
      const expHtml = k.expires_at
        ? `<div>${esc(fmtExpiry(k.expires_at))}</div><div class="muted" style="font-size:11px;">${esc(fmtDateTime(k.expires_at))}</div>`
        : `<span class="muted">永不过期</span>`;
      const dailyLimit = k.max_daily_requests > 0 ? ` / ${k.max_daily_requests}` : "";
      const tokLimit = k.max_total_tokens > 0 ? ` / ${fmtNum(k.max_total_tokens)}` : "";
      return `
        <tr data-kid="${esc(k.id)}">
          <td>
            <div><strong>${esc(k.name)}</strong></div>
            <div class="muted" style="font-size:11.5px;"><code>${esc(k.mask)}</code></div>
          </td>
          <td>${statusHtml}</td>
          <td>${modelsHtml}</td>
          <td>${expHtml}</td>
          <td>
            <div>今日 ${k.daily_requests || 0}${esc(dailyLimit)} · 累计 ${k.total_requests || 0} 次</div>
            <div class="muted" style="font-size:11px;">${fmtNum(k.total_tokens || 0)}${esc(tokLimit)} tok</div>
          </td>
          <td>
            <div class="btn-group">
              <button type="button" class="btn small" data-kact="edit" data-kid="${esc(k.id)}">编辑</button>
              <button type="button" class="btn small" data-kact="toggle" data-kid="${esc(k.id)}">${k.enabled ? "禁用" : "启用"}</button>
              <button type="button" class="btn danger small" data-kact="delete" data-kid="${esc(k.id)}">删除</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  function openKeyModal(existing = null) {
    $("key-edit-err").classList.add("hidden");
    $("key-edit-id").value = existing ? existing.id : "";
    $("key-modal-title").textContent = existing ? "编辑访问密钥" : "新建访问密钥";
    $("key-edit-name").value = existing ? existing.name : "";
    $("key-edit-models").value = existing && Array.isArray(existing.allowed_models) ? existing.allowed_models.join(", ") : "";
    $("key-edit-daily").value = existing ? String(existing.max_daily_requests || 0) : "0";
    $("key-edit-tokens").value = existing ? String(existing.max_total_tokens || 0) : "0";
    $("key-edit-expires").value = existing && existing.expires_at ? toLocalDateTimeInput(existing.expires_at) : "";
    openModal("modal-key-edit");
    $("key-edit-name").focus();
  }

  $("btn-create-key").addEventListener("click", () => openKeyModal(null));

  $("btn-key-save").addEventListener("click", async () => {
    $("key-edit-err").classList.add("hidden");
    const id = $("key-edit-id").value.trim();
    const name = $("key-edit-name").value.trim();
    const allowedModels = splitCSV($("key-edit-models").value);
    const maxDaily = Math.max(0, Number.parseInt($("key-edit-daily").value, 10) || 0);
    const maxTokens = Math.max(0, Number.parseInt($("key-edit-tokens").value, 10) || 0);
    const expRaw = $("key-edit-expires").value.trim();
    let expiresAt = 0;
    if (expRaw) {
      const parsed = Date.parse(expRaw);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        $("key-edit-err").textContent = "过期时间格式无效";
        $("key-edit-err").classList.remove("hidden");
        return;
      }
      expiresAt = parsed;
    }
    try {
      if (!name) throw new Error("请输入密钥名称");
      if (!id) {
        const res = await api("/panel/api/keys", {
          method: "POST",
          body: {
            name,
            allowed_models: allowedModels,
            expires_at: expiresAt,
            max_daily_requests: maxDaily,
            max_total_tokens: maxTokens,
          },
        });
        closeModal("modal-key-edit");
        $("key-secret-value").value = res.plaintext || "";
        openModal("modal-key-secret");
        await loadKeys();
        await loadOverview();
      } else {
        await api(`/panel/api/keys/${encodeURIComponent(id)}`, {
          method: "PATCH",
          body: {
            name,
            allowed_models: allowedModels,
            expires_at: expiresAt,
            max_daily_requests: maxDaily,
            max_total_tokens: maxTokens,
          },
        });
        closeModal("modal-key-edit");
        showToast("访问密钥已更新");
        await loadKeys();
      }
    } catch (err) {
      $("key-edit-err").textContent = err.message;
      $("key-edit-err").classList.remove("hidden");
    }
  });

  $("btn-key-secret-copy").addEventListener("click", () => {
    copyText($("key-secret-value").value, "已复制访问密钥明文");
  });

  $("keys-tbody").addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-kact]");
    if (!btn) return;
    const act = btn.dataset.kact;
    const id = btn.dataset.kid;
    const rec = keysCache.find((k) => k.id === id);
    if (!rec) return;
    if (act === "edit") {
      openKeyModal(rec);
      return;
    }
    btn.disabled = true;
    try {
      if (act === "toggle") {
        await api(`/panel/api/keys/${encodeURIComponent(id)}`, {
          method: "PATCH",
          body: { enabled: !rec.enabled },
        });
        showToast(rec.enabled ? "已禁用访问密钥" : "已启用访问密钥");
      } else if (act === "delete") {
        if (!confirm(`确认永久删除访问密钥「${rec.name}」(${rec.mask}) 吗？`)) return;
        await api(`/panel/api/keys/${encodeURIComponent(id)}`, { method: "DELETE" });
        showToast("已删除访问密钥");
      }
      await loadKeys();
      await loadOverview();
    } catch (err) {
      showToast(err.message, true);
    } finally {
      btn.disabled = false;
    }
  });

  // --- Requests (Metadata Only) ---
  async function loadRequests() {
    const data = await api("/panel/api/requests?limit=150");
    requestsCache = data.requests || [];
    renderRequests();
  }

  function renderRequests() {
    const q = $("requests-filter").value.trim().toLowerCase();
    const filtered = q ? requestsCache.filter((r) =>
      `${r.path} ${r.requested_model} ${r.actual_model} ${r.key_name || "主密钥"} ${r.account_label} ${r.status} ${r.error_code} ${r.error_message}`.toLowerCase().includes(q)
    ) : requestsCache;
    const tbody = $("requests-tbody");
    if (!filtered.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="empty">暂无匹配请求</td></tr>`;
      return;
    }
    tbody.innerHTML = filtered.map((r) => `
      <tr>
        <td>${fmtTime(r.ts)}</td>
        <td><code>${esc(r.path)}</code>${r.thread_reused ? ' <span class="badge">复用</span>' : ""}</td>
        <td>
          <div><code>${esc(r.requested_model || r.model_slot)}</code></div>
          ${r.actual_model ? `<div class="muted" style="font-size:11px;">${esc(r.actual_model)}</div>` : ""}
        </td>
        <td>${r.key_name ? `<span class="badge">${esc(r.key_name)}</span>` : `<span class="muted">主密钥</span>`}</td>
        <td>${esc(r.account_label || r.account_uid || "-")}</td>
        <td>
          <span class="pill ${r.status >= 200 && r.status < 300 ? "ok" : "err"}">${r.status}</span>
          ${r.error_code || r.error_message ? `<div class="muted" style="font-size:11px;max-width:220px;overflow:hidden;text-overflow:ellipsis;" title="${esc(r.error_message || r.error_code)}">${esc(r.error_code || r.error_message)}</div>` : ""}
        </td>
        <td>${r.ttfb_ms || 0} / ${r.total_ms || 0} ms</td>
        <td>${fmtNum(r.prompt_tokens)} / ${fmtNum(r.completion_tokens)}</td>
      </tr>
    `).join("");
  }

  $("requests-filter").addEventListener("input", renderRequests);
  $("btn-reload-reqs").addEventListener("click", loadRequests);
  $("btn-clear-reqs").addEventListener("click", async () => {
    if (!confirm("确认清空全部内存和本地归档的请求元数据吗？")) return;
    await api("/panel/api/requests", { method: "DELETE" });
    showToast("已清空请求记录");
    await loadRequests();
  });

  // --- Config ---
  function fillQuickConfig(cfg) {
    if (!cfg || typeof cfg !== "object") return;
    const srv = cfg.server || {};
    const up = cfg.upstream || {};
    const pl = cfg.pool || {};
    const th = cfg.thinking || {};
    $("qcfg-proxy").value = up.proxy_url || "";
    $("qcfg-default-model").value = up.default_model || "smart";
    $("qcfg-thinking-policy").value = th.policy || "client";
    $("qcfg-thinking-effort").value = th.default_effort || "off";
    $("qcfg-strategy").value = pl.selection_strategy || "weighted";
    $("qcfg-trusted-hosts").value = Array.isArray(srv.trusted_hosts) ? srv.trusted_hosts.join(", ") : "";
    $("qcfg-cors-origins").value = Array.isArray(srv.cors_allowed_origins) ? srv.cors_allowed_origins.join(", ") : "";
    $("qcfg-thread-reuse").checked = !!up.single_client_thread_reuse;
    $("qcfg-web-search").checked = !!up.web_search;
  }

  async function loadConfig() {
    const data = await api("/panel/api/config");
    $("config-editor").value = JSON.stringify(data.config, null, 2) + "\n";
    fillQuickConfig(data.config);
    const banner = $("config-env-banner");
    if (data.env_overrides?.length) {
      banner.textContent = "以下环境变量正在覆盖配置值：" + data.env_overrides.join(", ");
      banner.classList.remove("hidden");
    } else {
      banner.classList.add("hidden");
    }
    $("config-msg").classList.add("hidden");
    $("config-err").classList.add("hidden");
  }

  async function saveConfigRaw(raw) {
    $("config-msg").classList.add("hidden");
    $("config-err").classList.add("hidden");
    try {
      const parsed = JSON.parse(raw);
      const res = await api("/panel/api/config", { method: "PUT", body: raw });
      if (res.effective_admin_key && res.effective_admin_key !== adminKey) {
        adminKey = res.effective_admin_key;
        saveAdminKey(adminKey, rememberLogin);
      }
      if (typeof res.effective_api_key === "string") {
        inferenceApiKey = res.effective_api_key;
        renderSnippets();
      }
      fillQuickConfig(parsed);
      const restartNote = res.restart_required?.length ? `（以下字段需重启后生效：${res.restart_required.join(", ")}）` : "（已全部即时热生效）";
      $("config-msg").textContent = "配置已保存 " + restartNote;
      $("config-msg").classList.remove("hidden");
      showToast("配置已保存");
      await loadOverview();
    } catch (e) {
      $("config-err").textContent = e.message;
      $("config-err").classList.remove("hidden");
    }
  }

  $("btn-reload-config").addEventListener("click", loadConfig);
  $("btn-save-config").addEventListener("click", () => saveConfigRaw($("config-editor").value));
  $("btn-save-quick-cfg").addEventListener("click", async () => {
    try {
      const cfg = JSON.parse($("config-editor").value);
      cfg.server = cfg.server || {};
      cfg.upstream = cfg.upstream || {};
      cfg.pool = cfg.pool || {};
      cfg.thinking = cfg.thinking || {};
      cfg.upstream.proxy_url = $("qcfg-proxy").value.trim();
      cfg.upstream.default_model = $("qcfg-default-model").value;
      cfg.upstream.single_client_thread_reuse = $("qcfg-thread-reuse").checked;
      cfg.upstream.web_search = $("qcfg-web-search").checked;
      cfg.thinking.policy = $("qcfg-thinking-policy").value;
      cfg.thinking.default_effort = $("qcfg-thinking-effort").value;
      cfg.pool.selection_strategy = $("qcfg-strategy").value;
      cfg.server.trusted_hosts = splitCSV($("qcfg-trusted-hosts").value);
      cfg.server.cors_allowed_origins = splitCSV($("qcfg-cors-origins").value);
      const formatted = JSON.stringify(cfg, null, 2) + "\n";
      $("config-editor").value = formatted;
      await saveConfigRaw(formatted);
    } catch (e) {
      $("config-err").textContent = "解析当前配置 JSON 失败：" + e.message;
      $("config-err").classList.remove("hidden");
    }
  });

  // --- Logs & ZIP Export ---
  async function loadLogs() {
    const data = await api("/panel/api/logs?limit=400");
    logsCache = data.logs || [];
    renderLogs();
  }
  function renderLogs() {
    const q = $("logs-filter").value.trim().toLowerCase();
    const lines = q ? logsCache.filter((l) => l.text.toLowerCase().includes(q)) : logsCache;
    $("logs-box").textContent = lines.length ? lines.map((l) => `[${fmtTime(l.ts)}] ${l.text}`).join("\n") : "暂无日志";
  }
  $("logs-filter").addEventListener("input", renderLogs);
  $("btn-reload-logs").addEventListener("click", loadLogs);
  $("btn-export-logs").addEventListener("click", async () => {
    const btn = $("btn-export-logs");
    btn.disabled = true;
    try {
      const res = await fetch("/panel/api/logs/export", {
        headers: { Authorization: `Bearer ${adminKey}` },
      });
      if (res.status === 401) {
        clearAdminKey();
        adminKey = "";
        showAuthGate("面板管理密钥 (admin_key) 无效或已更改，请重新输入。");
        return;
      }
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          const j = await res.json();
          if (j?.error) msg = j.error;
        } catch {
          /* ignore */
        }
        throw new Error(msg);
      }
      const blob = await res.blob();
      const cd = res.headers.get("Content-Disposition") || "";
      const m = cd.match(/filename="([^"]+)"/i);
      const filename = m ? m[1] : "awsquick2api-logs.zip";
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = filename;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1500);
      showToast("已开始下载脱敏日志 ZIP");
    } catch (e) {
      showToast("导出失败：" + e.message, true);
    } finally {
      btn.disabled = false;
    }
  });

  // --- Online Playground ---
  $("btn-open-playground").addEventListener("click", async () => {
    $("pg-err").classList.add("hidden");
    try {
      const data = await api("/panel/api/models");
      const sel = $("pg-model");
      const prev = sel.value;
      const models = (data.models || []).filter((m) => m.name);
      if (models.length) {
        sel.innerHTML = models.map((m) => `<option value="${esc(m.name)}">${esc(m.name)}${m.visible ? "" : " (隐藏)"}</option>`).join("");
        if (models.some((m) => m.name === prev)) sel.value = prev;
      }
    } catch {
      /* keep default model list */
    }
    openModal("modal-playground");
  });

  $("btn-pg-run").addEventListener("click", async () => {
    const btn = $("btn-pg-run");
    $("pg-err").classList.add("hidden");
    $("pg-result").classList.add("hidden");
    const prompt = $("pg-prompt").value.trim();
    if (!prompt) {
      $("pg-err").textContent = "请输入测试提示词";
      $("pg-err").classList.remove("hidden");
      return;
    }
    btn.disabled = true;
    const prevLabel = btn.textContent;
    btn.textContent = "请求中...";
    try {
      const body = {
        model: $("pg-model").value,
        effort: $("pg-effort").value,
        prompt,
      };
      if ($("pg-web-search").checked) {
        body.web_search = true;
      }
      const res = await api("/panel/api/playground", { method: "POST", body });
      $("pg-meta").innerHTML = `
        <div><span class="muted">账号：</span><strong>${esc(res.account || "-")}</strong></div>
        <div><span class="muted">档位 / 实际模型：</span><code>${esc(res.slot || "-")}</code> / <code>${esc(res.actual_model || "-")}</code></div>
        <div><span class="muted">TTFB / 总耗时：</span><strong>${res.ttfb_ms || 0} / ${res.total_ms || 0} ms</strong></div>
        <div><span class="muted">Token：</span>${res.prompt_tokens || 0} + ${res.completion_tokens || 0} = ${res.total_tokens || 0}</div>
      `;
      const rw = $("pg-reasoning-wrap");
      if (res.reasoning && String(res.reasoning).trim()) {
        $("pg-reasoning").textContent = res.reasoning;
        rw.classList.remove("hidden");
      } else {
        rw.classList.add("hidden");
      }
      $("pg-output").textContent = res.text || "(空回复)";
      $("pg-result").classList.remove("hidden");
    } catch (e) {
      $("pg-err").textContent = e.message;
      $("pg-err").classList.remove("hidden");
    } finally {
      btn.disabled = false;
      btn.textContent = prevLabel;
    }
  });

  initSession().catch(reportAsyncError);
})();

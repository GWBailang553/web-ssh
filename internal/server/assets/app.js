(() => {
  "use strict";

  const state = {
    user: null,
    csrf: "",
    terminal: null,
    socket: null,
    terminalOpen: false,
    mode: "login",
  };

  const $ = (selector) => document.querySelector(selector);
  const authShell = $("#auth-shell");
  const consoleShell = $("#console-shell");
  const authView = $("#auth-view");
  const notice = $("#notice");
  const setupLabel = $("#setup-label");

  async function api(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.body) {
      headers["Content-Type"] = "application/json";
    }
    if (state.csrf && options.method && options.method !== "GET") {
      headers["X-CSRF-Token"] = state.csrf;
    }
    const response = await fetch(path, {
      credentials: "same-origin",
      ...options,
      headers,
    });
    const contentType = response.headers.get("content-type") || "";
    const body = contentType.includes("application/json") ? await response.json() : null;
    if (!response.ok) {
      throw new Error(body?.error || `Request failed (${response.status})`);
    }
    if (body?.csrf_token) {
      state.csrf = body.csrf_token;
    }
    return body;
  }

  function showNotice(message, kind = "error") {
    notice.textContent = message;
    notice.className = `notice ${kind}`;
    notice.hidden = false;
    window.clearTimeout(showNotice.timer);
    showNotice.timer = window.setTimeout(() => {
      notice.hidden = true;
    }, 5000);
  }

  function setBusy(form, busy) {
    for (const element of form.querySelectorAll("button, input, select")) {
      element.disabled = busy;
    }
  }

  function passwordField(name = "password", label = "Password") {
    return `
      <label>
        ${label}
        <input name="${name}" type="password" required minlength="16" maxlength="128" autocomplete="current-password">
      </label>
      <p class="policy">16–128 characters. Spaces are allowed internally.</p>
    `;
  }

  function renderAuth() {
    const setup = state.mode === "bootstrap";
    const register = state.mode === "register";
    const reset = state.mode === "reset";
    const title = setup ? "Claim this installation" : register ? "Join this machine" : reset ? "Use a reset code" : "Welcome back";
    const copy = setup
      ? "Create the first account. It becomes the administrator, and this setup path closes immediately."
      : register
        ? "Enter the one-time invitation from the administrator."
        : reset
          ? "Set a new password using the one-time code."
          : "Sign in to open your terminal.";

    authView.innerHTML = `
      <h2>${title}</h2>
      <p class="muted">${copy}</p>
      <form id="auth-form" class="stack" novalidate>
        ${setup || register ? `
          <label>
            Username
            <input name="username" required minlength="3" maxlength="32" pattern="[A-Za-z0-9_-]+" autocomplete="username">
          </label>
        ` : ""}
        ${register ? `
          <label>
            Invitation code
            <input name="invite" required autocomplete="one-time-code">
          </label>
        ` : ""}
        ${reset ? `
          <label>
            Reset code
            <input name="code" required autocomplete="one-time-code">
          </label>
          <label>
            New password
            <input name="password" type="password" required minlength="16" maxlength="128" autocomplete="new-password">
          </label>
          <p class="policy">16–128 characters. Spaces are allowed internally.</p>
        ` : setup || register ? `
          <label>
            Password
            <input name="password" type="password" required minlength="16" maxlength="128" autocomplete="new-password">
          </label>
          <p class="policy">16–128 characters. Spaces are allowed internally.</p>
        ` : passwordField()}
        <p id="form-error" class="form-error" hidden></p>
        <button class="primary-button" type="submit">
          ${setup ? "Create administrator" : register ? "Create account" : reset ? "Set new password" : "Sign in"}
        </button>
      </form>
      ${!setup && !register && !reset ? `
        <button id="go-register" class="link-button" type="button">I have an invitation</button>
        <br>
        <button id="go-reset" class="link-button" type="button">I have a reset code</button>
      ` : `
        ${!setup ? `<button id="go-login" class="link-button" type="button">Return to sign in</button>` : ""}
      `}
    `;

    $("#auth-form").addEventListener("submit", submitAuth);
    $("#go-register")?.addEventListener("click", () => {
      state.mode = "register";
      renderAuth();
    });
    $("#go-reset")?.addEventListener("click", () => {
      state.mode = "reset";
      renderAuth();
    });
    $("#go-login")?.addEventListener("click", () => {
      state.mode = "login";
      renderAuth();
    });
  }

  async function submitAuth(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const error = $("#form-error");
    const data = Object.fromEntries(new FormData(form));
    error.hidden = true;
    setBusy(form, true);
    try {
      if (state.mode === "bootstrap") {
        const result = await api("/api/bootstrap", {
          method: "POST",
          body: JSON.stringify({ username: data.username, password: data.password }),
        });
        enterConsole(result.user);
      } else if (state.mode === "register") {
        const result = await api("/api/register", {
          method: "POST",
          body: JSON.stringify(data),
        });
        enterConsole(result.user);
      } else if (state.mode === "reset") {
        await api("/api/password-reset", {
          method: "POST",
          body: JSON.stringify({ code: data.code, password: data.password }),
        });
        showNotice("Password changed. Sign in with the new password.", "success");
        state.mode = "login";
        renderAuth();
      } else {
        const result = await api("/api/login", {
          method: "POST",
          body: JSON.stringify({ username: data.username, password: data.password }),
        });
        enterConsole(result.user);
      }
    } catch (requestError) {
      error.textContent = requestError.message;
      error.hidden = false;
    } finally {
      setBusy(form, false);
    }
  }

  function enterConsole(user) {
    state.user = user;
    authShell.hidden = true;
    consoleShell.hidden = false;
    $("#account-name").textContent = user.username;
    $("#admin-tab").hidden = user.role !== "admin";
    switchView("terminal");
    connectTerminal();
  }

  function switchView(view) {
    const admin = view === "admin";
    $("#terminal-view").hidden = admin;
    $("#admin-view").hidden = !admin;
    $("#terminal-tab").classList.toggle("active", !admin);
    $("#admin-tab").classList.toggle("active", admin);
    if (admin) {
      loadAdmin();
      resizeTerminal();
    } else {
      resizeTerminal();
      state.terminal?.focus();
    }
  }

  function terminalTheme() {
    return {
      background: "#080b09",
      foreground: "#e8eadf",
      cursor: "#b8ef74",
      cursorAccent: "#080b09",
      selectionBackground: "#3f5d2c",
      black: "#111512",
      red: "#ff8b78",
      green: "#b8ef74",
      yellow: "#f3b95f",
      blue: "#8db9e8",
      magenta: "#d8a7d8",
      cyan: "#83d9cc",
      white: "#e8eadf",
      brightBlack: "#657066",
      brightRed: "#ffb0a3",
      brightGreen: "#d2ff9c",
      brightYellow: "#ffd594",
      brightBlue: "#b1d1f2",
      brightMagenta: "#edc7ed",
      brightCyan: "#a9eee4",
      brightWhite: "#ffffff",
    };
  }

  function connectTerminal() {
    if (state.socket || !state.user) {
      return;
    }
    if (!state.terminal) {
      state.terminal = new Terminal({
        cursorBlink: true,
        cursorStyle: "bar",
        fontFamily: '"IBM Plex Mono", "Cascadia Code", monospace',
        fontSize: window.innerWidth < 600 ? 12 : 14,
        lineHeight: 1.15,
        scrollback: 5000,
        allowProposedApi: false,
        theme: terminalTheme(),
      });
      state.terminal.open($("#terminal"));
      state.terminal.onData((data) => {
        if (state.socket?.readyState === WebSocket.OPEN) {
          state.socket.send(new TextEncoder().encode(data));
        }
      });
      state.terminal.onResize(({ cols, rows }) => {
        if (state.socket?.readyState === WebSocket.OPEN) {
          state.socket.send(JSON.stringify({ type: "resize", cols, rows }));
        }
      });
    }

    const dimensions = fitTerminal();
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${location.host}/ws/terminal?cols=${dimensions.cols}&rows=${dimensions.rows}`);
    socket.binaryType = "arraybuffer";
    state.socket = socket;
    setTerminalStatus("connecting");

    socket.addEventListener("open", () => {
      state.terminalOpen = true;
      setTerminalStatus("connected", true);
      state.terminal.focus();
    });
    socket.addEventListener("message", (event) => {
      if (typeof event.data === "string") {
        try {
          const message = JSON.parse(event.data);
          if (message.error) {
            showNotice(message.error);
          }
        } catch {
          state.terminal.write(event.data);
        }
        return;
      }
      state.terminal.write(new Uint8Array(event.data));
    });
    socket.addEventListener("close", () => {
      state.socket = null;
      state.terminalOpen = false;
      setTerminalStatus("disconnected");
      if (state.user && !consoleShell.hidden) {
        state.terminal.writeln("\r\n\x1b[38;2;243;185;95m[connection closed]\x1b[0m");
      }
    });
    socket.addEventListener("error", () => {
      setTerminalStatus("connection error");
    });
  }

  function setTerminalStatus(value, connected = false) {
    const status = $("#terminal-status");
    status.textContent = value;
    status.classList.toggle("connected", connected);
  }

  function fitTerminal() {
    const host = $("#terminal");
    const dimensions = state.terminal?._core?._renderService?.dimensions;
    const cellWidth = dimensions?.css?.cell?.width || 8.5;
    const cellHeight = dimensions?.css?.cell?.height || 17;
    const cols = Math.max(20, Math.floor((host.clientWidth - 28) / cellWidth));
    const rows = Math.max(5, Math.floor((host.clientHeight - 28) / cellHeight));
    if (state.terminal && (state.terminal.cols !== cols || state.terminal.rows !== rows)) {
      state.terminal.resize(cols, rows);
    }
    return { cols, rows };
  }

  function resizeTerminal() {
    window.requestAnimationFrame(() => {
      if (!state.terminal || $("#terminal-view").hidden) {
        return;
      }
      fitTerminal();
    });
  }

  function closeTerminal() {
    state.socket?.close();
    state.terminal?.clear();
    state.terminal?.write("Press “New session” to reconnect.\r\n");
  }

  async function logout() {
    try {
      await api("/api/logout", { method: "POST", body: "{}" });
    } catch {
      // Clearing local state is still safer than leaving the page open.
    }
    state.socket?.close();
    state.socket = null;
    state.user = null;
    state.csrf = "";
    state.terminal?.dispose();
    state.terminal = null;
    consoleShell.hidden = true;
    authShell.hidden = false;
    state.mode = "login";
    renderAuth();
  }

  async function loadAdmin() {
    await Promise.allSettled([loadInvites(), loadUsers(), loadAudit()]);
  }

  async function loadInvites() {
    const invites = await api("/api/admin/invites");
    renderRecordList("#invite-list", invites, (invite) => ({
      title: invite.used_at ? "Used invitation" : "Active invitation",
      subtitle: `${formatDate(invite.created_at)} · expires ${formatDate(invite.expires_at)}`,
      actions: invite.used_at ? "" : `<button data-delete-invite="${invite.id}" class="quiet-button danger" type="button">Revoke</button>`,
    }));
  }

  async function loadUsers() {
    const users = await api("/api/admin/users");
    renderRecordList("#user-list", users, (user) => {
      const self = user.id === state.user.id;
      const role = user.role === "admin" ? `<span class="badge admin">admin</span>` : `<span class="badge">user</span>`;
      const access = user.enabled ? "enabled" : "disabled";
      return {
        title: `${escapeHTML(user.username)}${role}`,
        subtitle: `${access} · joined ${formatDate(user.created_at)}`,
        actions: `
          <button data-reset-user="${user.id}" data-username="${escapeAttribute(user.username)}" class="quiet-button" type="button">Reset</button>
          ${self ? "" : `
            <button data-toggle-user="${user.id}" data-enabled="${!user.enabled}" class="quiet-button" type="button">${user.enabled ? "Disable" : "Enable"}</button>
            ${user.role === "user"
              ? `<button data-role-user="${user.id}" data-role="admin" class="quiet-button" type="button">Make admin</button>`
              : `<button data-role-user="${user.id}" data-role="user" class="quiet-button" type="button">Make user</button>`}
            <button data-revoke-user="${user.id}" class="quiet-button danger" type="button">Revoke</button>
          `}
        `,
      };
    });
  }

  async function loadAudit() {
    const events = await api("/api/admin/audit?limit=200");
    renderRecordList("#audit-list", events, (event) => ({
      title: escapeHTML(event.event),
      subtitle: `${formatDate(event.time)} · ${escapeHTML(event.username || "system")} · ${escapeHTML(event.ip || "local")}`,
      actions: event.details ? `<small>${escapeHTML(event.details)}</small>` : "",
    }));
  }

  function renderRecordList(selector, records, mapper) {
    const target = $(selector);
    if (!records.length) {
      target.innerHTML = `<div class="empty">Nothing to show yet.</div>`;
      return;
    }
    target.innerHTML = records.map((record) => {
      const item = mapper(record);
      return `
        <div class="record">
          <div>
            <strong>${item.title}</strong>
            <small>${item.subtitle}</small>
          </div>
          <div class="record-actions">${item.actions}</div>
        </div>
      `;
    }).join("");
  }

  async function createInvite(event) {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(form, true);
    try {
      const result = await api("/api/admin/invites", {
        method: "POST",
        body: JSON.stringify({ expires_in_minutes: Number($("#invite-expiry").value) }),
      });
      $("#invite-code").textContent = result.code;
      $("#invite-result").hidden = false;
      await loadInvites();
    } catch (error) {
      showNotice(error.message);
    } finally {
      setBusy(form, false);
    }
  }

  async function handleAdminClick(event) {
    const target = event.target.closest("button");
    if (!target) {
      return;
    }
    try {
      if (target.dataset.deleteInvite) {
        await api(`/api/admin/invites/${target.dataset.deleteInvite}`, { method: "DELETE" });
        await loadInvites();
      } else if (target.dataset.toggleUser) {
        await api(`/api/admin/users/${target.dataset.toggleUser}`, {
          method: "PATCH",
          body: JSON.stringify({ enabled: target.dataset.enabled === "true" }),
        });
        await loadUsers();
      } else if (target.dataset.roleUser) {
        await api(`/api/admin/users/${target.dataset.roleUser}`, {
          method: "PATCH",
          body: JSON.stringify({ role: target.dataset.role }),
        });
        await loadUsers();
      } else if (target.dataset.revokeUser) {
        await api(`/api/admin/users/${target.dataset.revokeUser}/revoke`, {
          method: "POST",
          body: "{}",
        });
        showNotice("Sessions revoked.", "success");
      } else if (target.dataset.resetUser) {
        const result = await api(`/api/admin/users/${target.dataset.resetUser}/reset`, {
          method: "POST",
          body: "{}",
        });
        $("#reset-title").textContent = `Reset for ${target.dataset.username}`;
        $("#reset-code").textContent = result.code;
        $("#reset-dialog").showModal();
      }
    } catch (error) {
      showNotice(error.message);
    }
  }

  function formatDate(value) {
    if (!value || value.startsWith("0001-")) {
      return "never";
    }
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(new Date(value));
  }

  function escapeHTML(value) {
    const element = document.createElement("span");
    element.textContent = value;
    return element.innerHTML;
  }

  function escapeAttribute(value) {
    return escapeHTML(value).replaceAll('"', "&quot;");
  }

  async function initialize() {
    renderAuth();
    try {
      const status = await api("/api/status");
      state.mode = status.bootstrap ? "bootstrap" : "login";
      setupLabel.textContent = status.bootstrap ? "Installation has no administrator" : "Administrator account is configured";
      renderAuth();
    } catch (error) {
      setupLabel.textContent = "Server status unavailable";
      showNotice(error.message);
    }

    try {
      const me = await api("/api/me");
      enterConsole(me);
    } catch {
      // Unauthenticated is the normal first-visit state.
    }
  }

  $("#invite-form").addEventListener("submit", createInvite);
  $("#admin-view").addEventListener("click", handleAdminClick);
  $("#refresh-invites").addEventListener("click", () => loadInvites().catch((error) => showNotice(error.message)));
  $("#refresh-users").addEventListener("click", () => loadUsers().catch((error) => showNotice(error.message)));
  $("#refresh-audit").addEventListener("click", () => loadAudit().catch((error) => showNotice(error.message)));
  $("#copy-invite").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("#invite-code").textContent);
    showNotice("Invitation copied.", "success");
  });
  $("#terminal-tab").addEventListener("click", () => switchView("terminal"));
  $("#admin-tab").addEventListener("click", () => switchView("admin"));
  $("#new-terminal").addEventListener("click", connectTerminal);
  $("#close-terminal").addEventListener("click", closeTerminal);
  $("#logout-button").addEventListener("click", logout);
  window.addEventListener("resize", resizeTerminal);
  new ResizeObserver(resizeTerminal).observe($("#terminal"));

  initialize();
})();

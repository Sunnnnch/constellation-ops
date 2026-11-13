(() => {
  "use strict";

  const workspace = byId("tunnel-workspace");
  if (!workspace) return;

  const panel = element("div", "tunnel-workspace-body");
  panel.innerHTML = `
    <div class="tunnel-toolbar">
      <label class="form-fields"><span>VPS</span><select id="tunnel-vps-filter"></select></label>
      <button class="button secondary" type="button" id="tunnel-refresh">刷新状态</button>
      <button class="button primary" type="button" id="tunnel-new">新建隧道</button>
    </div>
    <p id="tunnel-status" class="connection-result" role="status" hidden></p>
    <form id="tunnel-form" class="tunnel-editor form-fields" aria-labelledby="tunnel-form-title" hidden>
      <h2 id="tunnel-form-title">新建隧道</h2>
      <p class="field-hint" id="tunnel-automation-target" hidden></p>
      <fieldset class="tunnel-connection-fields form-fields" id="tunnel-connection-fields">
        <div class="field-grid">
          <label>VPS<select name="host_id" required></select></label>
          <label>隧道名称<input name="name" maxlength="80" required></label>
        </div>
        <div class="field-grid tunnel-endpoint-fields">
          <label>本机端口<input name="local_port" type="number" min="1" max="65535" step="1" required aria-describedby="tunnel-port-hint"></label>
          <label>远端地址<input name="remote_host" placeholder="127.0.0.1" required></label>
          <label>远端端口<input name="remote_port" type="number" min="1" max="65535" step="1" required></label>
        </div>
        <p class="field-hint" id="tunnel-port-hint" role="status"></p>
        <p class="field-hint">本机应用连接 127.0.0.1 的指定端口，VPS 负责连接远端地址和端口。</p>
      </fieldset>
      <div class="field-grid tunnel-automation">
        <label class="tunnel-option">
          <input name="auto_start" type="checkbox" aria-describedby="tunnel-auto-start-hint">
          <span>自动启动</span>
          <small class="field-hint" id="tunnel-auto-start-hint">星图启动时尝试连接。手动停止后，可再次点击启动或等星图下次启动。</small>
        </label>
        <label class="tunnel-option">
          <input name="auto_reconnect" type="checkbox" aria-describedby="tunnel-auto-reconnect-hint">
          <span>断线重连</span>
          <small class="field-hint" id="tunnel-auto-reconnect-hint">意外断线后自动重试。点击停止或关闭此选项可取消重连。</small>
        </label>
      </div>
      <p class="field-hint" id="tunnel-automation-password-hint" hidden>此 VPS 使用密码认证。请在设备设置中记住 SSH 密码，供自动启动和断线重连使用。</p>
      <div class="tunnel-actions">
        <button class="button secondary" type="button" id="tunnel-form-cancel">取消</button>
        <button class="button primary" type="button" id="tunnel-form-save">保存隧道</button>
      </div>
    </form>
    <p id="tunnel-empty" class="tunnel-empty" hidden></p>
    <div id="tunnel-groups" class="tunnel-groups"></div>
    <dialog id="tunnel-password-dialog" class="dialog" aria-labelledby="tunnel-password-title">
      <header class="dialog-header"><div><h2 id="tunnel-password-title">输入 SSH 密码</h2><p id="tunnel-password-description"></p></div></header>
      <form id="tunnel-password-form">
        <div class="dialog-body form-fields">
          <label>SSH 密码<input name="password" type="password" autocomplete="off" required autofocus></label>
          <p id="tunnel-password-error" class="connection-result" data-kind="error" role="alert" hidden></p>
        </div>
        <div class="dialog-actions">
          <button class="button secondary" type="button" id="tunnel-password-cancel">取消</button>
          <button class="button primary" type="button" id="tunnel-password-start">启动隧道</button>
        </div>
      </form>
    </dialog>
    <dialog id="tunnel-delete-dialog" class="dialog" aria-labelledby="tunnel-delete-title">
      <header class="dialog-header"><div><h2 id="tunnel-delete-title">删除隧道</h2><p id="tunnel-delete-description"></p></div></header>
      <div class="dialog-actions">
        <button class="button secondary" type="button" id="tunnel-delete-cancel" autofocus>取消</button>
        <button class="button danger" type="button" id="tunnel-delete-confirm">删除</button>
      </div>
    </dialog>`;
  workspace.append(panel);

  const filter = byId("tunnel-vps-filter");
  const refreshButton = byId("tunnel-refresh");
  const newButton = byId("tunnel-new");
  const editor = byId("tunnel-form");
  const saveButton = byId("tunnel-form-save");
  const connectionFields = byId("tunnel-connection-fields");
  const automationTarget = byId("tunnel-automation-target");
  const editHost = editor.elements.host_id;
  const port = editor.elements.local_port;
  const autoStart = editor.elements.auto_start;
  const autoReconnect = editor.elements.auto_reconnect;
  const portHint = byId("tunnel-port-hint");
  const passwordDialog = byId("tunnel-password-dialog");
  const passwordForm = byId("tunnel-password-form");
  const passwordInput = passwordForm.elements.password;
  const passwordError = byId("tunnel-password-error");
  const passwordStart = byId("tunnel-password-start");
  const deleteDialog = byId("tunnel-delete-dialog");
  const groups = byId("tunnel-groups");
  const empty = byId("tunnel-empty");
  const result = byId("tunnel-status");
  const statusLabels = {
    stopped: "已停止", starting: "启动中", running: "运行中", reconnecting: "重连中", stopping: "停止中",
    error: "连接异常", other_panel: "由另一个面板运行",
  };
  const statusStyles = {
    running: "online", starting: "auth_required", reconnecting: "auth_required", stopping: "auth_required",
    error: "unreachable", other_panel: "auth_required",
  };
  const portLabels = {available: "本机端口可用", occupied: "本机端口已占用", tunnel: "由隧道使用"};
  let selectedHost = "";
  let profiles = [];
  let loaded = false;
  let loadError = "";
  let loading = false;
  let pending = false;
  let visible = false;
  let revision = 0;
  let pollTimer = 0;
  let portTimer = 0;
  let portRevision = 0;
  let hostsStamp = "";
  let listStamp = "";
  let editing = null;
  let automationOnly = false;
  let passwordTarget = null;
  let deleteTarget = null;

  function hosts() {
    return state?.demo ? [] : state?.hosts ?? [];
  }

  function canPoll() {
    return !workspace.hidden && Boolean(state) && !state.demo;
  }

  function showResult(message = "", kind = "") {
    result.textContent = message;
    result.dataset.kind = kind;
    result.hidden = !message;
  }

  function syncHosts(items) {
    const stamp = JSON.stringify(items.map(({id, name, host, port, username}) => [id, name, host, port, username]));
    if (stamp === hostsStamp) {
      filter.value = selectedHost;
      return;
    }
    hostsStamp = stamp;
    const draftHost = editHost.value;
    filter.replaceChildren(new Option("全部 VPS", ""));
    editHost.replaceChildren(new Option("选择 VPS", ""));
    for (const host of items) {
      const label = `${host.name || host.host} · ${address(host)}`;
      filter.add(new Option(label, host.id));
      editHost.add(new Option(label, host.id));
    }
    filter.value = selectedHost;
    editHost.value = items.some(({id}) => id === draftHost) ? draftHost : selectedHost;
  }

  function makeStatus(label, tone = "") {
    const pill = element("span", `status-pill ${tone}`);
    pill.append(element("span", "dot"), document.createTextNode(label));
    return pill;
  }

  function endpoint(host, portNumber) {
    return `${host.includes(":") ? `[${host}]` : host}:${portNumber}`;
  }

  function addAction(container, profile, kind, label, tone, handler, disabled = false) {
    const action = button(label, `button ${tone}`, handler);
    action.dataset.tunnelAction = `${profile.id}:${kind}`;
    action.disabled = pending || disabled;
    container.append(action);
  }

  function renderProfile(profile) {
    const row = element("li", "tunnel-row");
    const summary = element("div", "tunnel-summary");
    const title = element("div", "tunnel-row-title");
    title.append(element("strong", "", profile.name),
      makeStatus(statusLabels[profile.status] || statusLabels.stopped, statusStyles[profile.status]));
    if (profile.auto_start === true) title.append(element("span", "status-pill tunnel-policy", "自动启动"));
    if (profile.auto_reconnect === true) title.append(element("span", "status-pill tunnel-policy", "断线重连"));
    const route = element("div", "tunnel-route");
    const arrow = element("span", "", "→");
    arrow.setAttribute("aria-label", "转发到");
    route.append(element("code", "", `127.0.0.1:${profile.local_port}`), arrow,
      element("code", "", endpoint(profile.remote_host, profile.remote_port)));
    summary.append(title, route);
    if (profile.message) summary.append(element("p", "tunnel-message", profile.message));

    const availability = element("div", "tunnel-availability");
    const portLabel = profile.status === "reconnecting" && profile.port_state === "tunnel" ?
      "端口已为隧道保留" : portLabels[profile.port_state] || "端口状态待确认";
    availability.append(makeStatus(portLabel,
      profile.port_state === "occupied" ? "unreachable" : profile.port_state === "available" ? "online" : ""));

    const actions = element("div", "tunnel-actions");
    const running = profile.can_stop || ["starting", "running", "reconnecting", "stopping", "other_panel"].includes(profile.status);
    if (running) {
      if (profile.can_stop || profile.status === "stopping") {
        addAction(actions, profile, "stop", "停止", "secondary", () => perform({action: "stop", id: profile.id}),
          profile.status === "stopping");
      }
      addAction(actions, profile, "automation", "自动化设置", "secondary", () => openEditor(profile, true));
    } else {
      addAction(actions, profile, "start", "启动", "primary", () => startProfile(profile), profile.port_state !== "available");
      addAction(actions, profile, "edit", "编辑", "secondary", () => openEditor(profile));
      addAction(actions, profile, "delete", "删除", "secondary", () => openDelete(profile));
    }
    row.append(summary, availability, actions);
    return row;
  }

  function renderList(items) {
    const shown = items.filter(({id}) => !selectedHost || selectedHost === id);
    const stamp = JSON.stringify([hostsStamp, selectedHost, loaded, pending, profiles]);
    if (stamp === listStamp) return;
    listStamp = stamp;
    const focusedAction = document.activeElement?.dataset.tunnelAction;
    groups.replaceChildren();
    if (loaded) {
      for (const host of shown) {
        const tunnels = profiles.filter(({host_id}) => host_id === host.id);
        if (!tunnels.length && !selectedHost) continue;
        const group = element("section", "tunnel-group");
        const header = element("header", "tunnel-group-header");
        header.append(element("h2", "", host.name || host.host), element("span", "", address(host)));
        group.append(header);
        if (tunnels.length) {
          const list = element("ul", "tunnel-rows");
          list.append(...tunnels.map(renderProfile));
          group.append(list);
        } else {
          group.append(element("p", "tunnel-empty", "这台 VPS 还没有隧道。"));
        }
        groups.append(group);
      }
    }
    if (focusedAction) {
      const match = Array.from(groups.querySelectorAll("[data-tunnel-action]")).find(
        (action) => action.dataset.tunnelAction === focusedAction && !action.disabled,
      );
      (match || filter).focus();
    }
  }

  function render() {
    if (workspace.hidden) {
      visible = false;
      clearTimeout(pollTimer);
      pollTimer = 0;
      if (passwordDialog.open) closePassword();
      if (deleteDialog.open) closeDelete();
      if (!editor.hidden) closeEditor();
      return;
    }
    const opened = !visible;
    visible = true;
    const items = hosts();
    if (!items.some(({id}) => id === selectedHost)) selectedHost = "";
    syncHosts(items);
    if (!editor.hidden) renderAutomationHint();
    filter.disabled = !items.length;
    newButton.disabled = !items.length || pending;
    refreshButton.disabled = !canPoll() || loading || pending;
    saveButton.disabled = pending;
    passwordStart.disabled = pending;
    if (state?.demo) {
      closeEditor();
      if (passwordDialog.open) closePassword();
      if (deleteDialog.open) closeDelete();
    }
    renderList(items);
    const message = !state ? byId("connection-error")?.textContent || "正在读取设备…" : state.demo ? "退出示例后可管理隧道。" :
      !items.length ? "添加 VPS 后可为设备新建隧道。" : !loaded ? loadError || "正在读取隧道…" :
        !groups.childElementCount ? "还没有隧道。" : "";
    empty.hidden = !message;
    empty.textContent = message;
    if (canPoll() && !loading && !pollTimer && !pending) {
      schedulePoll(opened || (!loaded && !loadError) ? 0 : pollDelay());
    }
  }

  function pollDelay() {
    if (profiles.some(({status}) => status === "starting" || status === "stopping")) return 900;
    return profiles.some(({status}) => status === "reconnecting") ? 2500 : 5000;
  }

  function schedulePoll(delay) {
    clearTimeout(pollTimer);
    pollTimer = 0;
    if (canPoll()) pollTimer = setTimeout(() => {
      pollTimer = 0;
      refresh();
    }, delay);
  }

  function acceptState(data) {
    if (!Array.isArray(data.tunnels)) throw new Error("面板返回的隧道列表格式无效。");
    profiles = data.tunnels;
    loaded = true;
    if (loadError && result.textContent === loadError) showResult();
    loadError = "";
    if (passwordTarget) {
      const current = profiles.find(({id}) => id === passwordTarget.id);
      if (current?.connection_revision !== passwordTarget.connectionRevision) {
        closePassword();
        showResult("隧道或 VPS 的连接信息已更改，请重新启动隧道。", "error");
      }
    }
  }

  async function refresh() {
    if (!canPoll() || loading || pending) return;
    const version = revision;
    loading = true;
    render();
    try {
      const data = await request("/api/tunnels", "POST", {action: "state"});
      if (version === revision) acceptState(data);
    } catch (error) {
      if (version === revision) {
        loadError = error.message || "无法读取隧道状态。";
        if (loaded && result.hidden) showResult(loadError, "error");
      }
    } finally {
      loading = false;
      render();
    }
  }

  function closeEditor() {
    editor.hidden = true;
    editing = null;
    automationOnly = false;
    clearTimeout(portTimer);
    portRevision += 1;
    editor.reset();
  }

  function openEditor(profile = null, editAutomationOnly = false) {
    if (pending) return;
    editing = profile;
    automationOnly = editAutomationOnly;
    clearTimeout(portTimer);
    portRevision += 1;
    editor.reset();
    editHost.value = profile?.host_id || selectedHost || (hosts().length === 1 ? hosts()[0].id : "");
    editor.elements.name.value = profile?.name || "";
    port.value = profile?.local_port ?? "";
    editor.elements.remote_host.value = profile?.remote_host || "127.0.0.1";
    editor.elements.remote_port.value = profile?.remote_port ?? "";
    autoStart.checked = profile?.auto_start === true;
    autoReconnect.checked = profile?.auto_reconnect === true;
    byId("tunnel-form-title").textContent = automationOnly ? "自动化设置" : profile ? "编辑隧道" : "新建隧道";
    connectionFields.hidden = connectionFields.disabled = automationOnly;
    automationTarget.hidden = !automationOnly;
    automationTarget.textContent = automationOnly ? `${profile.name} · 127.0.0.1:${profile.local_port}` : "";
    showResult();
    editor.hidden = false;
    renderAutomationHint();
    (automationOnly ? autoStart : editHost.value ? editor.elements.name : editHost).focus();
    if (!automationOnly) checkPort();
  }

  function renderAutomationHint() {
    const host = hosts().find(({id}) => id === editHost.value);
    byId("tunnel-automation-password-hint").hidden = host?.auth_mode !== "password" || host.password_saved === true ||
      (!autoStart.checked && !autoReconnect.checked);
  }

  function checkPort() {
    clearTimeout(portTimer);
    const version = ++portRevision;
    const number = port.valueAsNumber;
    if (!Number.isInteger(number) || !port.validity.valid) {
      portHint.textContent = "填写端口后会检查当前占用情况。";
      portHint.dataset.kind = "";
      return;
    }
    portHint.textContent = "正在检查本机端口…";
    portHint.dataset.kind = "";
    portTimer = setTimeout(async () => {
      try {
        const data = await request("/api/tunnels", "POST", {action: "check", local_port: number});
        if (version !== portRevision) return;
        portHint.textContent = portLabels[data.port_state] || "端口状态待确认";
        portHint.dataset.kind = data.port_state === "available" ? "success" : "warning";
      } catch (error) {
        if (version !== portRevision) return;
        portHint.textContent = error.message || "无法检查本机端口。";
        portHint.dataset.kind = "warning";
      }
    }, 250);
  }

  function closePassword() {
    passwordInput.value = "";
    passwordTarget = null;
    passwordDialog.close();
  }

  function startProfile(profile) {
    if (!profile.password_required) {
      perform({action: "start", id: profile.id});
      return;
    }
    passwordTarget = {id: profile.id, connectionRevision: profile.connection_revision};
    passwordInput.value = "";
    passwordError.hidden = true;
    byId("tunnel-password-description").textContent = `${profile.name} · 密码用于本次 SSH 连接。`;
    passwordDialog.showModal();
  }

  function openDelete(profile) {
    deleteTarget = profile.id;
    byId("tunnel-delete-description").textContent = `确认删除「${profile.name}」？`;
    deleteDialog.showModal();
  }

  function closeDelete() {
    deleteTarget = null;
    deleteDialog.close();
  }

  function bindForm(form, submitButton, submit) {
    const apply = () => {
      if (!submitButton.disabled && form.reportValidity()) submit();
    };
    submitButton.addEventListener("click", apply);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      apply();
    });
    // MCP App hosts can omit allow-forms from their iframe sandbox.
    form.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.isComposing && event.target instanceof HTMLInputElement) {
        event.preventDefault();
        apply();
      }
    });
  }

  async function perform(payload, {password = "", passwordProfile = null} = {}) {
    if (pending) return false;
    revision += 1;
    pending = true;
    clearTimeout(pollTimer);
    pollTimer = 0;
    showResult();
    render();
    try {
      if (passwordProfile) {
        payload.password_box = await sealPassword(password, {
          host: "tunnels", username: payload.id, port: null, auth_mode: "password",
          known_hosts: passwordProfile.connectionRevision,
        }, "tunnel-start");
        if (!passwordDialog.open || passwordTarget !== passwordProfile || workspace.hidden) return;
      }
      const data = await request("/api/tunnels", "POST", payload);
      if (passwordProfile && passwordTarget === passwordProfile) closePassword();
      acceptState(data);
      if (["create", "update", "automation"].includes(payload.action)) {
        if (selectedHost && payload.host_id) selectedHost = payload.host_id;
        closeEditor();
      }
    } catch (error) {
      if (passwordProfile && passwordTarget === passwordProfile && passwordDialog.open) {
        passwordError.textContent = error.message || "无法启动隧道。";
        passwordError.hidden = false;
      } else {
        showResult(error.message || "隧道操作失败。", "error");
      }
    } finally {
      pending = false;
      render();
      schedulePoll(pollDelay());
    }
  }

  filter.addEventListener("change", () => {
    selectedHost = filter.value;
    closeEditor();
    showResult();
    render();
  });
  refreshButton.addEventListener("click", refresh);
  newButton.addEventListener("click", () => openEditor());
  byId("tunnel-form-cancel").addEventListener("click", () => {
    closeEditor();
    newButton.focus();
  });
  port.addEventListener("input", checkPort);
  for (const field of [editHost, autoStart, autoReconnect]) field.addEventListener("change", renderAutomationHint);
  bindForm(editor, saveButton, () => {
    if (automationOnly) {
      const changes = {};
      if (autoStart.checked !== (editing.auto_start === true)) changes.auto_start = autoStart.checked;
      if (autoReconnect.checked !== (editing.auto_reconnect === true)) changes.auto_reconnect = autoReconnect.checked;
      if (Object.keys(changes).length) perform({action: "automation", id: editing.id, ...changes});
      else closeEditor();
      return;
    }
    const name = editor.elements.name.value.trim();
    const remoteHost = editor.elements.remote_host.value.trim();
    if (!name || !remoteHost) {
      showResult("请填写隧道名称和远端地址。", "error");
      (name ? editor.elements.remote_host : editor.elements.name).focus();
      return;
    }
    perform({
      action: editing ? "update" : "create", id: editing?.id, host_id: editHost.value, name,
      local_port: port.valueAsNumber, remote_host: remoteHost, remote_port: editor.elements.remote_port.valueAsNumber,
      auto_start: autoStart.checked, auto_reconnect: autoReconnect.checked,
    });
  });
  byId("tunnel-password-cancel").addEventListener("click", closePassword);
  passwordDialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    closePassword();
  });
  bindForm(passwordForm, passwordStart, () => {
    if (!passwordTarget || pending) return;
    const password = passwordInput.value;
    passwordInput.value = "";
    passwordError.hidden = true;
    perform({action: "start", id: passwordTarget.id}, {password, passwordProfile: passwordTarget});
  });
  byId("tunnel-delete-cancel").addEventListener("click", closeDelete);
  deleteDialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    closeDelete();
  });
  byId("tunnel-delete-confirm").addEventListener("click", () => {
    const id = deleteTarget;
    closeDelete();
    if (id) perform({action: "delete", id});
  });

  window.vpsRenderTunnels = render;
  window.vpsOpenTunnels = (hostId = "") => {
    selectedHost = hostId;
    closeEditor();
    showResult();
    render();
    if (!loading && !pending) schedulePoll(0);
  };
})();

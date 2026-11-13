(() => {
  "use strict";

  const template = document.createElement("template");
  template.innerHTML = `
    <section id="webdav-panel" class="webdav-panel" aria-labelledby="webdav-title" hidden>
      <header class="dialog-header">
        <div>
          <h2 id="webdav-title">WebDAV 加密同步</h2>
          <p>两台电脑使用同一 WebDAV 文件夹和同步密码。下载后可先预览变化。</p>
        </div>
      </header>
      <div class="dialog-body form-fields">
        <label>WebDAV 文件夹地址
          <input id="webdav-url" type="url" required maxlength="1200" autocomplete="off" spellcheck="false"
                 placeholder="https://nas.example.com/webdav/">
        </label>
        <label class="password-option">
          <input id="webdav-dedicated-folder" type="checkbox">使用专用子文件夹
        </label>
        <p class="field-hint">首次上传时按需创建该子文件夹。备份已在填写的目录中时，可取消勾选。</p>
        <div class="field-grid">
          <label>WebDAV 用户名
            <input id="webdav-user" maxlength="100" autocomplete="off" spellcheck="false" placeholder="如需登录">
          </label>
          <label>WebDAV 密码
            <input id="webdav-password" type="password" maxlength="256" autocomplete="new-password">
          </label>
        </div>
        <div class="field-grid">
          <label>同步密码
            <input id="webdav-passphrase" type="password" maxlength="256" autocomplete="new-password"
                   aria-describedby="webdav-passphrase-help">
          </label>
          <label>确认同步密码（上传或保存定时设置时）
            <input id="webdav-confirm-passphrase" type="password" maxlength="256" autocomplete="new-password">
          </label>
        </div>
        <p class="field-hint" id="webdav-passphrase-help">至少 12 个字符。文件在本机加密后上传，同步密码用于解密。</p>
        <details id="webdav-key-options" hidden>
          <summary>随配置同步 SSH 私钥</summary>
          <p class="field-hint">勾选要加入备份的本机私钥。已备份且仍关联同一 SSH 连接的私钥会保留。</p>
          <p class="field-hint">重新保存定时设置时，请重新勾选要授权的本机私钥。</p>
          <div id="webdav-keys" class="outbound-bulk-list"></div>
        </details>
        <p id="webdav-status" class="connection-result" role="status" hidden></p>
        <ul id="webdav-conflicts" class="inventory-targets" aria-label="同步冲突" hidden></ul>
        <label id="webdav-resolution-field" hidden>冲突处理
          <select id="webdav-resolution">
            <option value="">请选择</option>
            <option value="local">冲突项使用本机设置</option>
            <option value="remote">冲突项使用 WebDAV 设置</option>
          </select>
        </label>
      </div>
      <footer class="dialog-actions">
        <button id="webdav-test" type="button" class="button secondary">测试连接</button>
        <button id="webdav-preview" type="button" class="button secondary">下载并预览</button>
        <button id="webdav-apply" type="button" class="button primary" disabled>应用预览</button>
        <button id="webdav-upload" type="button" class="button primary">加密上传</button>
      </footer>
      <div class="dialog-body form-fields">
        <h2>定时同步</h2>
        <div class="field-grid">
          <label>运行方式
            <select id="webdav-auto-mode">
              <option value="off">关闭</option>
              <option value="upload">自动上传</option>
              <option value="sync">双向同步</option>
            </select>
          </label>
          <label>检查间隔
            <select id="webdav-auto-interval">
              <option value="5">5 分钟</option>
              <option value="15" selected>15 分钟</option>
              <option value="30">30 分钟</option>
              <option value="60">60 分钟</option>
            </select>
          </label>
        </div>
        <p class="field-hint">定时任务在本机面板运行时执行，所需密码由 Windows 凭据管理器保管。双向同步只应用可确定的修改，首次发现差异、遇到冲突或删除时请手动预览处理。</p>
        <p id="webdav-auto-status" class="connection-result" role="status"></p>
        <div class="dialog-actions">
          <button id="webdav-auto-save" type="button" class="button primary">保存定时设置</button>
          <button id="webdav-auto-run" type="button" class="button secondary">立即运行</button>
          <button id="webdav-auto-disable" type="button" class="button secondary">关闭定时同步</button>
        </div>
      </div>
    </section>
  `;
  const workspace = byId("sync-workspace");
  workspace.append(template.content);

  const panel = byId("webdav-panel");
  const unavailable = byId("sync-unavailable");
  const url = byId("webdav-url");
  const dedicatedFolder = byId("webdav-dedicated-folder");
  const user = byId("webdav-user");
  const password = byId("webdav-password");
  const passphrase = byId("webdav-passphrase");
  const confirmation = byId("webdav-confirm-passphrase");
  const status = byId("webdav-status");
  const conflicts = byId("webdav-conflicts");
  const resolutionField = byId("webdav-resolution-field");
  const resolution = byId("webdav-resolution");
  const keys = byId("webdav-keys");
  const keyOptions = byId("webdav-key-options");
  const test = byId("webdav-test");
  const preview = byId("webdav-preview");
  const apply = byId("webdav-apply");
  const upload = byId("webdav-upload");
  const autoMode = byId("webdav-auto-mode");
  const autoInterval = byId("webdav-auto-interval");
  const autoStatus = byId("webdav-auto-status");
  const autoSave = byId("webdav-auto-save");
  const autoRun = byId("webdav-auto-run");
  const autoDisable = byId("webdav-auto-disable");

  let pending = false;
  let visible = false;
  let session = 0;
  let keySignature = "";
  let listedKeys = new Map();
  let chosenKeys = new Set();
  let previewResult = null;
  let applied = false;

  function showStatus(message = "", kind = "") {
    status.textContent = message;
    status.dataset.kind = kind;
    status.hidden = !message;
  }

  function updateButtons() {
    const available = visible && !pending && !busy && Boolean(state?.password_public_key);
    for (const control of [test, preview]) control.disabled = !available;
    for (const field of [url, dedicatedFolder, user, password, passphrase, confirmation, resolution, ...keys.querySelectorAll("input")]) {
      field.disabled = pending || busy;
    }
    const hasConflicts = Boolean(previewResult?.conflicts?.length);
    const changes = previewResult && (previewResult.added || previewResult.updated ||
      previewResult.keys || previewResult.settings || hasConflicts);
    apply.disabled = !available || !changes || applied || (hasConflicts && !resolution.value);
    upload.disabled = !available || Boolean(changes && !applied);
    const auto = state?.webdav_auto;
    const autoAvailable = available && auto?.available === true;
    const autoEnabled = auto?.mode === "upload" || auto?.mode === "sync";
    autoMode.disabled = !autoAvailable;
    autoInterval.disabled = !autoAvailable || autoMode.value === "off";
    autoSave.disabled = !autoAvailable || autoMode.value === "off";
    autoRun.disabled = !autoAvailable || !autoEnabled || auto?.kind === "running";
    autoDisable.disabled = !visible || pending || busy || !autoEnabled || auto?.running === true;
    panel.setAttribute("aria-busy", String(pending));
  }

  function renderAutoStatus() {
    const auto = state?.webdav_auto;
    let message = "定时同步已关闭。";
    if (auto?.available === false) message = "当前环境无法保存定时同步所需的凭据。";
    if (auto?.mode === "upload" || auto?.mode === "sync") {
      const parts = [
        (auto.mode === "upload" ? "自动上传" : "双向同步") + " · 每 " + auto.interval_minutes + " 分钟",
      ];
      if (auto.last_at) parts.push("上次 " + formattedDate(auto.last_at));
      if (auto.next_at) parts.push("下次 " + formattedDate(auto.next_at));
      if (auto.key_ids?.length) parts.push("已授权私钥 " + auto.key_ids.length + " 把");
      message = parts.join(" · ") + "。";
      if (auto.url) {
        message += " 目录 " + (auto.dedicated_folder ? auto.url.replace(/\/?$/, "/") + "VPS-Ops/" : auto.url) + "。";
      }
    }
    if (auto?.message) message += " " + auto.message;
    if (autoStatus.textContent !== message) autoStatus.textContent = message;
    autoStatus.dataset.kind = auto?.kind === "conflict" ? "error" : auto?.kind || "";
  }

  function clearPreview() {
    previewResult = null;
    applied = false;
    conflicts.replaceChildren();
    conflicts.hidden = true;
    resolutionField.hidden = true;
    resolution.value = "";
    updateButtons();
  }

  function renderKeys() {
    if (pending) return;
    const hosts = (state?.hosts ?? []).filter((host) => host.auth_mode === "key" && host.identity_file);
    const signature = JSON.stringify(hosts.map((host) => [host.id, host.name, address(host), host.identity_file]));
    if (signature === keySignature) return;
    keySignature = signature;
    const currentPaths = new Map(hosts.map((host) => [host.id, host.identity_file]));
    for (const id of chosenKeys) {
      if (!currentPaths.has(id) || listedKeys.has(id) && listedKeys.get(id) !== currentPaths.get(id)) {
        chosenKeys.delete(id);
      }
    }
    const rows = hosts.map((host) => {
      const row = document.createElement("label");
      row.className = "outbound-bulk-option";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = host.id;
      checkbox.checked = chosenKeys.has(host.id);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) chosenKeys.add(host.id);
        else chosenKeys.delete(host.id);
      });
      const label = document.createElement("span");
      label.textContent = host.name;
      const subtitle = document.createElement("small");
      subtitle.textContent = address(host);
      label.append(subtitle);
      row.append(checkbox, label);
      return row;
    });
    listedKeys = currentPaths;
    keys.replaceChildren(...rows);
    keyOptions.open = rows.length > 0 && keyOptions.open;
    keyOptions.hidden = !rows.length;
  }

  function summary(result) {
    return [
      "新增 " + (result.added ?? 0) + " 台",
      "更新 " + (result.updated ?? 0) + " 台",
      "相同 " + (result.unchanged ?? 0) + " 台",
      "私钥 " + (result.keys ?? 0) + " 把",
      ...(result.skipped_keys ? ["保留本机私钥 " + result.skipped_keys + " 把"] : []),
      ...(result.settings ? ["设置变更 " + result.settings + " 项"] : []),
    ].join(" · ");
  }

  function showPreview(result) {
    previewResult = result;
    applied = false;
    const rows = (result.conflicts ?? []).map((description) => {
      const row = document.createElement("li");
      row.textContent = description;
      return row;
    });
    conflicts.replaceChildren(...rows);
    conflicts.hidden = !rows.length;
    resolutionField.hidden = !rows.length;
    resolution.value = "";
    showStatus(summary(result) + (rows.length ? "。请为以下冲突选择使用哪一边的设置。" : "。"), rows.length ? "" : "success");
  }

  function safeFolder(value) {
    try {
      const destination = new URL(value);
      return destination.protocol === "https:" && !destination.username && !destination.password &&
        !destination.search && !destination.hash;
    } catch {
      return false;
    }
  }

  function checkInputs(action) {
    url.setCustomValidity("");
    password.setCustomValidity("");
    passphrase.setCustomValidity("");
    confirmation.setCustomValidity("");
    if (!url.reportValidity()) return false;
    if (!safeFolder(url.value)) {
      url.setCustomValidity("请输入 HTTPS 文件夹地址，账号信息请填写在下方。");
      return url.reportValidity();
    }
    if (password.value && !user.value) {
      password.setCustomValidity("请填写 WebDAV 用户名。");
      return password.reportValidity();
    }
    if (action !== "test" && Array.from(passphrase.value).length < 12) {
      passphrase.setCustomValidity("请输入至少 12 个字符的同步密码。");
      return passphrase.reportValidity();
    }
    if ((action === "upload" || action === "auto_save") && confirmation.value !== passphrase.value) {
      confirmation.setCustomValidity("两次输入的同步密码不一致。");
      return confirmation.reportValidity();
    }
    return true;
  }

  async function requestBody(action) {
    if (action === "apply") return {action, ticket: previewResult.ticket, resolution: resolution.value || "local"};
    if (action === "auto_run" || action === "auto_disable") return {action};
    const endpoint = url.value;
    const ticket = previewResult?.ticket;
    const useDedicatedFolder = dedicatedFolder.checked;
    const keyIds = [...keys.querySelectorAll("input:checked")].map((checkbox) => checkbox.value);
    const mode = autoMode.value;
    const intervalMinutes = Number(autoInterval.value);
    const passwordBox = await sealPassword(JSON.stringify({
      username: user.value, password: password.value, passphrase: action === "test" ? "" : passphrase.value,
    }), {host: "webdav", username: endpoint, port: null, auth_mode: "password", known_hosts: ""}, "webdav-" + action);
    const body = {action, url: endpoint, password_box: passwordBox, dedicated_folder: useDedicatedFolder};
    if (action === "upload") {
      body.key_ids = keyIds;
      if (ticket) body.ticket = ticket;
    }
    if (action === "auto_save") {
      body.mode = mode;
      body.interval_minutes = intervalMinutes;
      body.key_ids = keyIds;
    }
    return body;
  }

  async function run(action) {
    if (pending || !visible || busy) return;
    if (action === "apply" && apply.disabled) return;
    if (!["apply", "auto_run", "auto_disable"].includes(action) && !checkInputs(action)) return;
    if (action === "preview") clearPreview();
    const current = session;
    pending = true;
    updateButtons();
    showStatus({
      test: "正在连接 WebDAV…", preview: "正在读取并解密文件…",
      apply: "正在应用预览…", upload: "正在加密并上传…",
      auto_save: "正在保存定时设置…", auto_run: "正在启动同步…", auto_disable: "正在关闭定时同步…",
    }[action]);
    try {
      const body = await requestBody(action);
      if (current !== session) return;
      const result = await request("/api/webdav", "POST", body);
      if (current !== session) {
        if (action === "apply" || action.startsWith("auto_")) {
          await loadState(true);
          if (action === "apply") notice("已应用 WebDAV 同步。");
        }
        if (action === "upload") notice("已完成 WebDAV 加密上传。");
        return;
      }
      if (action === "test") {
        state.webdav_folder = url.value;
        state.webdav_dedicated_folder = dedicatedFolder.checked;
        const message = result.exists
          ? (result.can_update ? "已连接。文件夹内有加密文件，可下载并预览。" : "已连接，可以读取现有文件。服务器未提供安全更新所需的信息。")
          : result.folder_exists === false ? "已连接。首次上传时将尝试创建 VPS-Ops/。" : "已连接。此文件夹还没有星图加密文件。";
        showStatus(message, "success");
      } else if (action === "preview") {
        state.webdav_folder = url.value;
        state.webdav_dedicated_folder = dedicatedFolder.checked;
        showPreview(result);
      } else if (action === "apply") {
        if (result.ticket) previewResult.ticket = result.ticket;
        applied = true;
        conflicts.hidden = true;
        resolutionField.hidden = true;
        showStatus("已应用。 " + summary(result) + "。", "success");
        await loadState(true);
      } else if (action === "upload") {
        state.webdav_folder = url.value;
        state.webdav_dedicated_folder = dedicatedFolder.checked;
        clearPreview();
        confirmation.value = "";
        showStatus("已加密上传 " + result.devices + " 台设备的配置和 " + result.keys + " 把私钥。", "success");
      } else {
        await loadState(true);
        if (current !== session) return;
        if (action === "auto_save") {
          password.value = passphrase.value = confirmation.value = "";
          clearPreview();
          showStatus("已保存定时设置，首轮同步已排队。", "success");
        } else if (action === "auto_disable") {
          autoMode.value = "off";
          showStatus("已关闭定时同步。", "success");
        } else {
          showStatus("本轮同步已排队。", "success");
        }
      }
    } catch (error) {
      if (current === session) showStatus(error.message, "error");
      else if (action === "apply" || action === "upload" || action.startsWith("auto_")) notice(error.message, true);
    } finally {
      pending = false;
      if (visible) renderKeys();
      updateButtons();
    }
  }

  function resetKeySelection() {
    chosenKeys.clear();
    for (const checkbox of keys.querySelectorAll("input:checked")) checkbox.checked = false;
  }

  function fillSavedFolder() {
    const auto = state?.webdav_auto;
    url.value = state?.webdav_folder || auto?.url || "";
    if (typeof state?.webdav_dedicated_folder === "boolean") {
      dedicatedFolder.checked = state.webdav_dedicated_folder;
    } else if (auto?.url && auto.url === url.value) {
      dedicatedFolder.checked = auto.dedicated_folder === true;
    } else {
      dedicatedFolder.checked = !url.value;
    }
  }

  for (const field of [url, dedicatedFolder, user, password, passphrase]) {
    field.addEventListener("input", () => {
      field.setCustomValidity("");
      if (field === url || field === dedicatedFolder) resetKeySelection();
      clearPreview();
      showStatus();
    });
  }
  confirmation.addEventListener("input", () => confirmation.setCustomValidity(""));
  resolution.addEventListener("change", updateButtons);
  test.addEventListener("click", () => run("test"));
  preview.addEventListener("click", () => run("preview"));
  apply.addEventListener("click", () => run("apply"));
  upload.addEventListener("click", () => run("upload"));
  autoMode.addEventListener("change", updateButtons);
  autoSave.addEventListener("click", () => run("auto_save"));
  autoRun.addEventListener("click", () => run("auto_run"));
  autoDisable.addEventListener("click", () => run("auto_disable"));

  function clearSession() {
    session += 1;
    user.value = password.value = passphrase.value = confirmation.value = "";
    if (!safeFolder(url.value)) fillSavedFolder();
    for (const field of [url, password, passphrase, confirmation]) field.setCustomValidity("");
    clearPreview();
    keys.replaceChildren();
    keySignature = "";
    listedKeys.clear();
    chosenKeys.clear();
    keyOptions.open = false;
    showStatus();
  }

  window.vpsRenderWebDav = () => {
    const showPanel = !workspace.hidden && Boolean(state) && !state.demo;
    panel.hidden = !showPanel;
    unavailable.hidden = showPanel;
    if (!showPanel) {
      const message = state?.demo ? "退出示例后即可使用 WebDAV 同步。" :
        byId("connection-error").textContent || "正在读取本机设备清单…";
      if (unavailable.textContent !== message) unavailable.textContent = message;
      if (visible) {
        visible = false;
        clearSession();
      }
      return;
    }
    if (!visible) {
      visible = true;
      const auto = state.webdav_auto;
      autoMode.value = auto?.mode || "off";
      autoInterval.value = String(auto?.interval_minutes || 15);
      if (!url.value) fillSavedFolder();
      if (!state.password_public_key) showStatus("本机加密组件不可用，请先安装星图依赖。", "error");
    }
    renderKeys();
    renderAutoStatus();
    updateButtons();
  };
  window.vpsRenderWebDav();
})();

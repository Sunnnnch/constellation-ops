(() => {
  "use strict";

  const browser = byId("files-browser");
  const browserEmpty = byId("files-browser-empty");
  const hostName = byId("files-host");
  const hostAddress = byId("files-host-address");
  const auth = byId("files-auth");
  const password = byId("files-password");
  const connect = byId("files-connect");
  const navigation = byId("files-navigation");
  const path = byId("files-path");
  const openPath = byId("files-open-path");
  const home = byId("files-home");
  const parent = byId("files-parent");
  const refresh = byId("files-refresh");
  const filter = byId("files-filter");
  const status = byId("files-status");
  const truncated = byId("files-truncated");
  const table = byId("files-table-wrap");
  const entries = byId("files-entries");
  const retry = byId("files-retry");
  const upload = byId("files-upload");
  const typeNames = {directory: "目录", symlink: "符号链接", link: "符号链接", other: "特殊文件"};
  const pendingJobs = new Map();
  let view = null;

  function active(current) {
    return current !== null && view === current;
  }

  function feedback(message, kind = "") {
    status.textContent = message;
    status.dataset.kind = kind;
    status.hidden = !message;
  }

  function updateControls() {
    const busy = Boolean(view?.busy);
    const listing = view?.listing;
    auth.hidden = !view?.passwordRequired;
    connect.hidden = Boolean(listing);
    password.disabled = connect.disabled = busy;
    navigation.hidden = table.hidden = !listing;
    openPath.disabled = home.disabled = refresh.disabled = upload.disabled = busy || !listing;
    parent.disabled = busy || !listing?.parent;
    path.disabled = busy || !listing;
    retry.hidden = !view?.retry;
    retry.disabled = busy;
    truncated.hidden = !listing?.truncated;
    for (const control of entries.querySelectorAll("button")) control.disabled = busy;
  }

  function renderEntries() {
    const listing = view?.listing;
    if (!listing) return;
    const query = filter.value.trim().toLocaleLowerCase();
    const matches = listing.entries.filter(({name}) => !query || name.toLocaleLowerCase().includes(query));
    if (!matches.length) {
      const row = element("tr");
      const cell = element("td", "files-empty", query ? "没有匹配的项目。" : "这个目录为空。");
      cell.colSpan = 4;
      row.append(cell);
      entries.replaceChildren(row);
      return;
    }
    const rows = matches.map((entry) => {
      const row = element("tr");
      const name = element("th");
      name.scope = "row";
      if (entry.kind === "directory") {
        const open = button(entry.name, "text-button", () => list(entry.path));
        open.setAttribute("aria-label", "打开目录 " + entry.name);
        name.append(open);
      } else {
        name.textContent = entry.name;
      }
      if (typeNames[entry.kind]) name.append(element("small", "", typeNames[entry.kind]));
      const action = element("td");
      if (entry.kind === "file") {
        const download = button("下载", "text-button", () => transfer("download", entry.path));
        download.setAttribute("aria-label", "下载 " + entry.name);
        action.append(download);
      }
      row.append(name, element("td", "", entry.kind === "file" ? bytes(entry.size) : "—"),
        element("td", "files-modified", formattedDate(entry.modified_at)), action);
      return row;
    });
    entries.replaceChildren(...rows);
    updateControls();
  }

  function setListing(current, result) {
    if (result.path !== current.listing?.path) filter.value = "";
    current.listing = result;
    path.value = result.path;
    updateControls();
    renderEntries();
  }

  function send(current, action, fields) {
    return request("/api/files", "POST", {action, host_id: current.host.id, ...fields});
  }

  async function runJob(current, action, target) {
    const fields = target === undefined ? {} : {path: target};
    if (current.passwordRequired) {
      const secret = password.value;
      if (!secret) throw new Error("请输入这台设备的 SSH 密码。");
      fields.password_box = await sealPassword(secret, {
        host: "file-manager", username: current.host.id, port: null, auth_mode: "password", known_hosts: "",
      }, "files");
    }
    if (!active(current)) return null;
    const {ticket} = await send(current, action, fields);
    if (!ticket) throw new Error("面板未能启动文件操作。");
    const deadline = performance.now() + 420000;
    while (performance.now() < deadline) {
      const response = await send(current, "poll", {ticket});
      if (!response.pending) return response.result;
      if (active(current) && response.stage === "transfer") {
        feedback(action === "upload" ? "正在上传文件…" : "正在下载文件…");
      }
      await new Promise((resolve) => setTimeout(resolve, 800));
    }
    throw new Error("等待文件操作结果超时。请刷新目录确认操作状态。");
  }

  async function job(current, action, target) {
    const hostId = current.host.id;
    const previous = pendingJobs.get(hostId);
    if (previous) await previous.catch(() => {});
    if (!active(current)) return null;
    const pending = runJob(current, action, target);
    pendingJobs.set(hostId, pending);
    try {
      return await pending;
    } finally {
      if (pendingJobs.get(hostId) === pending) pendingJobs.delete(hostId);
    }
  }

  async function list(target, current = view) {
    if (!active(current) || current.busy) return;
    if (current.passwordRequired && !password.value) {
      feedback("请输入这台设备的 SSH 密码。", "error");
      password.focus();
      return;
    }
    current.busy = true;
    current.retry = null;
    updateControls();
    feedback("正在读取目录…");
    try {
      const result = await job(current, "list", target);
      if (!active(current) || !result) return;
      setListing(current, result);
      feedback("");
    } catch (error) {
      if (!active(current)) return;
      feedback(error.message, "error");
      if (!current.passwordRequired) current.retry = () => list(target, current);
    } finally {
      if (active(current)) {
        current.busy = false;
        updateControls();
      }
    }
  }

  function transferFeedback(current, message, kind = "") {
    if (active(current)) feedback(message, kind);
    if (!active(current) || !browser.getClientRects().length) {
      notice(current.host.name + " · " + message, kind === "error");
    }
  }

  async function transfer(action, target) {
    const current = view;
    if (!active(current) || !current.listing || current.busy) return;
    current.busy = true;
    current.retry = null;
    updateControls();
    const uploading = action === "upload";
    feedback(uploading ? "请在本机窗口选择要上传的文件…" : "请在本机窗口选择保存位置…");
    try {
      const result = await job(current, action, target);
      if (!result) return;
      if (result.cancelled) {
        transferFeedback(current, "文件选择已取消。");
        return;
      }
      const message = (uploading ? "已上传 " : "已下载 ") + result.name;
      const size = number(result.size) == null ? "" : "（" + bytes(result.size) + "）";
      transferFeedback(current, message + size, "success");
      if (uploading && active(current)) {
        try {
          const refreshed = await job(current, "list", target);
          if (active(current) && refreshed) setListing(current, refreshed);
        } catch {
          if (active(current)) feedback(message + "。请刷新目录以查看文件。", "success");
        }
      }
    } catch (error) {
      transferFeedback(current, error.message, "error");
    } finally {
      if (active(current)) {
        current.busy = false;
        updateControls();
      }
    }
  }

  async function initialize(current) {
    const originalFocus = document.activeElement;
    current.busy = true;
    current.retry = null;
    updateControls();
    feedback("正在读取连接设置…");
    try {
      const result = await send(current, "state");
      if (!active(current)) return;
      current.passwordRequired = result.password_required;
    } catch (error) {
      if (!active(current)) return;
      current.retry = () => initialize(current);
      feedback(error.message, "error");
    } finally {
      if (active(current)) {
        current.busy = false;
        updateControls();
      }
    }
    if (!active(current) || current.retry) return;
    if (current.passwordRequired) {
      feedback("");
      if (document.activeElement === originalFocus && password.getClientRects().length) password.focus();
    } else {
      list(undefined, current);
    }
  }

  function navigateToInput() {
    const target = path.value;
    if (!target.startsWith("/")) {
      feedback("请输入以 / 开头的远程目录。", "error");
      path.focus();
      return;
    }
    list(target);
  }

  connect.addEventListener("click", () => list());
  password.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.isComposing && !view?.listing) connect.click();
  });
  path.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.isComposing) openPath.click();
  });
  openPath.addEventListener("click", navigateToInput);
  home.addEventListener("click", () => list());
  parent.addEventListener("click", () => list(view?.listing?.parent));
  refresh.addEventListener("click", () => list(view?.listing?.path));
  retry.addEventListener("click", () => view?.retry?.());
  upload.addEventListener("click", () => transfer("upload", view?.listing?.path));
  filter.addEventListener("input", renderEntries);

  function reset() {
    view = null;
    password.value = path.value = filter.value = "";
    hostName.textContent = "";
    if (hostAddress) hostAddress.textContent = "";
    entries.replaceChildren();
    feedback("");
    updateControls();
    browser.hidden = true;
    browserEmpty.hidden = false;
  }

  window.vpsResetFiles = reset;
  window.vpsOpenFiles = (host) => {
    if (view?.host.id === host.id) {
      view.host = host;
      hostName.textContent = host.name;
      if (hostAddress) hostAddress.textContent = address(host);
      return;
    }
    reset();
    const current = {host, listing: null, passwordRequired: false, busy: false, retry: null};
    view = current;
    hostName.textContent = host.name;
    if (hostAddress) hostAddress.textContent = address(host);
    browser.hidden = false;
    browserEmpty.hidden = true;
    initialize(current);
  };
})();

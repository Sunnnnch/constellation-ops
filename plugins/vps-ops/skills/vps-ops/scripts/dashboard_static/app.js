"use strict";

const byId = (id) => document.getElementById(id);
const csrf = document.querySelector('meta[name="vps-csrf"]').content;
const statuses = {
  online: "在线",
  unreachable: "不可达",
  auth_required: "认证失败",
  password_required: "待输入密码",
  unknown: "待检查",
};
const connectionFields = ["host", "port", "username", "auth_mode", "identity_file", "known_hosts"];
const hostFields = ["name", ...connectionFields, "group", "note", "traffic_limit_gb", "expires_on"];
const authLabels = {alias: "SSH 配置 / 别名", key: "本机私钥", password: "密码"};
const dateFormat = new Intl.DateTimeFormat("zh-CN", {dateStyle: "medium", timeStyle: "medium"});
const clockFormat = new Intl.DateTimeFormat("zh-CN", {hour: "2-digit", minute: "2-digit", second: "2-digit"});
const numberFormat = new Intl.NumberFormat("zh-CN", {maximumFractionDigits: 1});
const countryNames = new Intl.DisplayNames(["zh-CN"], {type: "region"});
const sshLatencyHint = "由面板自动采集，包含 SSH 连接、认证和结果传输等耗时，已扣除服务器端巡检脚本的运行时间。";
const dayMs = 24 * 60 * 60 * 1000;
const maxInventoryFileBytes = 512 * 1024;
const historyMetrics = [
  {key: "cpu_pct", title: "CPU", color: "#1558ce", unit: "%", scale: 100},
  {key: "memory_pct", title: "内存", color: "#087d58", unit: "%", scale: 100},
  {key: "latency_ms", title: "SSH 巡检延迟", color: "#7447ba", unit: " ms", scale: 0},
];

let state = null;
let metricDisplayMode = "gauges";
let savingMetricDisplay = false;
let focusedHostId = null;
let editedHostId = null;
let savedPasswordTarget = null;
let hostFormSession = 0;
let hostFormAction = "";
let deletingHostId = null;
let cardStamp = "";
let detailStamp = "";
let fileDevicesStamp = "";
let selectedFileHost = null;
const pendingDetailTerminals = new Set();
const terminalSessions = new Map();
const terminalEncoder = new TextEncoder();
const terminalInputLimit = 64 * 1024;
const terminalExchangeSize = 4096;
let activeTerminalId = null;
let terminalExchangeTimer = 0;
let terminalExchangeActive = false;
let historyRequest = 0;
let historyStamp = "";
let inventorySession = 0;
let inventoryBusy = false;
let inventoryPreview = null;
let readSequence = 0;
let readsInProgress = 0;
let toastTimer = 0;
let busy = false;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function button(label, className, onClick) {
  const node = element("button", className, label);
  node.type = "button";
  node.addEventListener("click", onClick);
  return node;
}

function number(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function bytes(value) {
  const n = number(value);
  if (n == null || n < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let scaled = n;
  let i = 0;
  while (scaled >= 1000 && i < units.length - 1) {
    scaled /= 1000;
    i += 1;
  }
  return numberFormat.format(scaled) + " " + units[i];
}

function rate(value) {
  return number(value) == null ? "—" : bytes(value) + "/s";
}

function percentage(value) {
  const n = number(value);
  return n == null ? "—" : numberFormat.format(n) + "%";
}

function ratio(used, total) {
  const n = number(used);
  const capacity = number(total);
  return n == null || capacity == null || capacity <= 0 ? null : n / capacity * 100;
}

function usage(used, total, format = bytes) {
  return number(used) == null && number(total) == null ? "—" : format(used) + " / " + format(total);
}

function sumTraffic(sample) {
  const rx = number(sample.rx_bytes);
  const tx = number(sample.tx_bytes);
  return rx == null && tx == null ? null : (rx ?? 0) + (tx ?? 0);
}

function formattedDate(value, format = dateFormat) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : format.format(date);
}

function duration(value) {
  const n = number(value);
  if (n == null || n < 0) return "—";
  const days = Math.floor(n / 86400);
  const hours = Math.floor(n / 3600) % 24;
  const minutes = Math.floor(n / 60) % 60;
  return [days ? days + " 天" : "", hours ? hours + " 小时" : "", minutes ? minutes + " 分钟" : ""].filter(Boolean).join(" ") || "不足 1 分钟";
}

function daysUntil(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || "")) return null;
  const today = new Date();
  const midnight = Date.UTC(today.getFullYear(), today.getMonth(), today.getDate());
  const target = Date.parse(value + "T00:00:00Z");
  return Number.isFinite(target) ? Math.round((target - midnight) / 86400000) : null;
}

function expiring(host) {
  const days = daysUntil(host.expires_on);
  return days != null && days >= 0 && days <= 30;
}

function sampleFor(id) {
  return state?.samples?.[id] ?? {};
}

function canCollect(host) {
  return host.auth_mode !== "password" || host.password_saved === true;
}

function statusOf(sample) {
  return Object.hasOwn(statuses, sample.status) ? sample.status : "unknown";
}

function address(host) {
  const user = host.username && !host.host.includes("@") ? host.username + "@" : "";
  return user + host.host + (host.port ? ":" + host.port : "");
}

function notice(message, isError = false) {
  const toast = byId("toast");
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.hidden = false;
  toastTimer = setTimeout(() => { toast.hidden = true; }, isError ? 6500 : 3300);
}

function embeddedTerminal(mode) {
  const modes = state?.embedded_terminal_modes;
  return typeof window.Terminal === "function" && Array.isArray(modes) && modes.includes(mode);
}

function chooseWorkspace(id = null, {focus = false} = {}) {
  activeTerminalId = terminalSessions.has(id) ? id : null;
  for (const [tab, workspace] of workspaceTabs()) {
    const selected = id === workspace;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    byId(tab.getAttribute("aria-controls")).hidden = !selected;
  }
  if (id === "files-tab") renderFileDevices();
  window.vpsRenderWebDav?.();
  window.vpsRenderTunnels?.();
  byId("ssh-workspace").hidden = activeTerminalId === null;
  for (const session of terminalSessions.values()) {
    const active = activeTerminalId === session.id;
    session.tab.setAttribute("aria-selected", String(active));
    session.tab.tabIndex = active ? 0 : -1;
    session.panel.hidden = !active;
  }
  const selected = terminalSessions.get(activeTerminalId);
  if (selected) {
    selected.nextPoll = 0;
    selected.tab.scrollIntoView({block: "nearest", inline: "nearest"});
    requestAnimationFrame(() => {
      if (activeTerminalId !== selected.id) return;
      fitTerminal(selected);
      if (focus) selected.terminal.focus();
    });
    scheduleTerminalExchange(0);
  }
}

function workspaceTabs() {
  return [
    [byId("overview-tab"), null], [byId("files-tab"), "files-tab"],
    [byId("sync-tab"), "sync-tab"], [byId("tunnel-tab"), "tunnel-tab"],
  ];
}

function fitTerminal(session) {
  if (!session.fit || session.panel.hidden) return;
  session.fit.fit();
}

function updateTerminalStatus(session, message, disconnected = false) {
  if (session.status.textContent !== message) session.status.textContent = message;
  const status = String(disconnected);
  if (session.panel.dataset.disconnected !== status) {
    session.panel.dataset.disconnected = status;
    session.tab.dataset.disconnected = status;
  }
}

function closeTerminalRequest(id) {
  return request("/api/terminal/close", "POST", {id});
}

function closeTerminal(id) {
  const session = terminalSessions.get(id);
  if (!session) return;
  const ids = [...terminalSessions.keys()];
  const index = ids.indexOf(id);
  terminalSessions.delete(id);
  session.observer?.disconnect();
  session.terminal.dispose();
  session.item.remove();
  session.panel.remove();
  if (activeTerminalId === id) {
    chooseWorkspace(ids[index + 1] ?? ids[index - 1] ?? null);
    (terminalSessions.get(activeTerminalId)?.tab ?? byId("overview-tab")).focus();
  }
  if (!session.closed) closeTerminalRequest(id).catch((error) => notice(error.message, true));
}

function queueTerminalInput(session, bytes) {
  if (session.closed || !bytes.length) return;
  if (session.input.length + bytes.length > terminalInputLimit) {
    notice("待发送的终端输入已满，请分段粘贴。", true);
    return;
  }
  const combined = new Uint8Array(session.input.length + bytes.length);
  combined.set(session.input);
  combined.set(bytes, session.input.length);
  session.input = combined;
  session.nextPoll = 0;
  scheduleTerminalExchange(15);
}

function openTerminalTab(result, label) {
  try {
    mountTerminalTab(result, label);
  } catch (error) {
    if (terminalSessions.has(result.id)) closeTerminal(result.id);
    else closeTerminalRequest(result.id).catch(() => {});
    throw error;
  }
}

function mountTerminalTab(result, label) {
  const terminal = new window.Terminal({
    cols: 80, rows: 24, scrollback: 2500, cursorBlink: true, fontSize: 13, lineHeight: 1.15,
    fontFamily: '"Cascadia Mono", Consolas, "Microsoft YaHei UI", monospace',
    theme: {background: "#0c1423", foreground: "#e2ebf7", cursor: "#9fb8ff", selectionBackground: "#3e5b8d"},
  });
  // The remote terminal cannot set browser clipboard data or register clickable hyperlinks.
  terminal.parser.registerOscHandler(52, () => true);
  terminal.parser.registerOscHandler(8, () => true);
  const fit = typeof window.FitAddon?.FitAddon === "function" ? new window.FitAddon.FitAddon() : null;
  if (fit) terminal.loadAddon(fit);
  const panel = element("section", "ssh-panel");
  panel.id = "ssh-panel-" + result.id;
  panel.hidden = true;
  panel.setAttribute("role", "tabpanel");
  const status = element("span", "ssh-status");
  status.setAttribute("role", "status");
  const chrome = element("header", "ssh-panel-header");
  chrome.append(status);
  const screen = element("div", "ssh-screen");
  panel.append(chrome, screen);
  const item = element("div", "ssh-tab-item");
  item.setAttribute("role", "presentation");
  const tab = button(label, "workspace-tab ssh-tab", () => chooseWorkspace(result.id, {focus: true}));
  tab.id = "ssh-tab-" + result.id;
  tab.title = label;
  tab.setAttribute("role", "tab");
  tab.setAttribute("aria-controls", panel.id);
  tab.setAttribute("aria-keyshortcuts", "Delete");
  panel.setAttribute("aria-labelledby", tab.id);
  const close = button("×", "ssh-tab-close", () => closeTerminal(result.id));
  close.setAttribute("aria-label", "关闭 " + label);
  close.title = "关闭终端";
  close.tabIndex = -1;
  item.append(tab, close);
  byId("ssh-tabs").append(item);
  byId("ssh-workspace").append(panel);
  const session = {
    id: result.id, terminal, fit, panel, status, item, tab, offset: result.offset || 0,
    input: new Uint8Array(), resize: null, nextPoll: 0, closed: false, failures: 0,
  };
  terminalSessions.set(result.id, session);
  updateTerminalStatus(session, "已连接");
  chooseWorkspace(result.id);
  terminal.open(screen);
  terminal.onData((data) => queueTerminalInput(session, terminalEncoder.encode(data)));
  terminal.onBinary((data) => queueTerminalInput(session, Uint8Array.from(data, (character) => character.charCodeAt(0))));
  terminal.onResize(({cols, rows}) => {
    if (session.closed) return;
    session.resize = {cols, rows};
    session.nextPoll = 0;
    scheduleTerminalExchange(25);
  });
  if (typeof ResizeObserver === "function") {
    session.observer = new ResizeObserver(() => fitTerminal(session));
    session.observer.observe(screen);
  }
  fitTerminal(session);
  if (result.data) terminal.write(Uint8Array.from(atob(result.data), (character) => character.charCodeAt(0)));
  chooseWorkspace(result.id, {focus: true});
}

function scheduleTerminalExchange(delay) {
  clearTimeout(terminalExchangeTimer);
  if (terminalExchangeActive || ![...terminalSessions.values()].some((session) => !session.closed)) return;
  terminalExchangeTimer = setTimeout(exchangeTerminals, Math.max(0, delay));
}

async function exchangeTerminals() {
  const available = [...terminalSessions.values()].filter((session) => !session.closed);
  if (!available.length || terminalExchangeActive) return;
  available.sort((left, right) => left.nextPoll - right.nextPoll);
  const session = available[0];
  const wait = session.nextPoll - performance.now();
  if (wait > 0) {
    scheduleTerminalExchange(wait);
    return;
  }
  terminalExchangeActive = true;
  const data = {id: session.id, offset: session.offset};
  if (session.input.length) {
    const batch = session.input.slice(0, terminalExchangeSize);
    session.input = session.input.slice(terminalExchangeSize);
    data.input_data = btoa(String.fromCharCode(...batch));
  }
  if (session.resize) {
    Object.assign(data, session.resize);
    session.resize = null;
  }
  try {
    const result = await request("/api/terminal/exchange", "POST", data);
    if (!terminalSessions.has(session.id)) return;
    session.failures = 0;
    session.offset = result.offset;
    if (result.lost) session.terminal.write("\r\n[星图] 部分终端输出已超出缓存。\r\n");
    if (result.data) session.terminal.write(Uint8Array.from(atob(result.data), (character) => character.charCodeAt(0)));
    if (result.status === "closed") {
      session.closed = true;
      const message = result.error || (result.exit_code == null ? "连接已关闭" : "会话已退出（退出码 " + result.exit_code + "）");
      updateTerminalStatus(session, message, true);
      session.terminal.write("\r\n[星图] " + message + "\r\n");
    } else {
      updateTerminalStatus(session, "已连接");
      const active = session.id === activeTerminalId;
      session.nextPoll = session.input.length || session.resize ? 0 : performance.now() + (active ? (result.data ? 90 : 250) : 1000);
    }
  } catch (error) {
    if (!terminalSessions.has(session.id)) return;
    session.failures += 1;
    if (data.input_data) notice("本次输入未能确认送达。请先查看终端，避免重复执行。", true);
    session.closed = session.failures >= 3;
    if (session.closed) closeTerminalRequest(session.id).catch(() => {});
    updateTerminalStatus(session, session.closed ? error.message : "正在恢复面板连接…", session.closed);
    session.nextPoll = performance.now() + 1000;
  } finally {
    terminalExchangeActive = false;
    scheduleTerminalExchange(0);
  }
}

async function request(path, method = "GET", data) {
  if (window.vpsOpsRequest) return window.vpsOpsRequest(path, method, data);
  const headers = {Accept: "application/json"};
  if (method !== "GET") headers["X-VPS-CSRF"] = csrf;
  if (data !== undefined) headers["Content-Type"] = "application/json";
  const timeout = path === "/api/ssh/key-file" ? 100000 : path === "/api/webdav" ? 80000 : 25000;
  const response = await fetch(path, {
    method,
    headers,
    body: data === undefined ? undefined : JSON.stringify(data),
    cache: "no-store",
    signal: AbortSignal.timeout(timeout),
  });
  let payload = {};
  try {
    payload = await response.json();
  } catch {
    if (response.ok) throw new Error("面板返回了无法读取的数据。");
  }
  if (!response.ok || (payload.error && !["/api/terminal/exchange", "/api/outbound-probes"].includes(path))) {
    throw new Error(payload.error || "请求失败 (HTTP " + response.status + ")。");
  }
  return payload;
}

function connectionError(message) {
  const banner = byId("connection-error");
  banner.hidden = !message;
  banner.textContent = message || "";
}

async function loadState(force = false) {
  if (readsInProgress && !force) return;
  const sequence = ++readSequence;
  readsInProgress += 1;
  try {
    const next = await request("/api/state");
    if (sequence !== readSequence) return;
    if (!Array.isArray(next.hosts)) throw new Error("设备列表格式无效。");
    state = next;
    if (!savingMetricDisplay) {
      metricDisplayMode = state.metric_display === "text" ? "text" : "gauges";
      byId("metric-display").value = metricDisplayMode;
      byId("metric-display").disabled = false;
    }
    connectionError("");
    render();
  } catch (error) {
    if (sequence !== readSequence) return;
    connectionError("无法读取本地面板。" + (state ? " 已保留上次采集结果。" : "") + " " + error.message);
    if (!state) {
      byId("cards").setAttribute("aria-busy", "false");
      byId("empty-title").textContent = "等待本地面板连接";
      byId("empty-description").textContent = "确认星图还在运行，页面会自动重试。";
      renderFileDevices();
      window.vpsRenderWebDav?.();
      window.vpsRenderTunnels?.();
    }
  } finally {
    readsInProgress -= 1;
  }
}

function updateSummary() {
  const samples = state.hosts.map((host) => sampleFor(host.id));
  const online = samples.filter((sample) => statusOf(sample) === "online").length;
  const pending = samples.filter((sample) => statusOf(sample) === "unknown").length;
  const traffic = samples.map(sumTraffic).filter((value) => value != null);
  const high = samples.filter((sample) => statusOf(sample) === "online" &&
    ((number(sample.cpu_pct) ?? -1) >= 85 || (ratio(sample.memory_used, sample.memory_total) ?? -1) >= 85)).length;
  byId("online-count").textContent = online;
  byId("host-total").textContent = "/ " + state.hosts.length;
  const issues = state.hosts.length - online - pending;
  byId("online-note").textContent = state.hosts.length ? issues + " 台异常 · " + pending + " 台待检查" : "添加设备后自动采集";
  byId("high-count").textContent = high;
  byId("traffic-total").textContent = traffic.length ? bytes(traffic.reduce((total, value) => total + value, 0)) : "—";
  byId("expiry-count").textContent = state.hosts.filter(expiring).length;
}

function statusBadge(sample) {
  const status = statusOf(sample);
  const badge = element("span", "status-pill " + status);
  badge.append(element("span", "dot"), document.createTextNode(statuses[status]));
  return badge;
}

function deviceFlag(host) {
  if (!/^[A-Z]{2}$/.test(host.country_code ?? "")) return null;
  const flag = element("span", "device-flag");
  const country = countryNames.of(host.country_code) || host.country_code;
  flag.dataset.country = host.country_code;
  flag.title = country;
  flag.setAttribute("role", "img");
  flag.setAttribute("aria-label", country);
  return flag;
}

function metric(label, value, hint, color = "", missingReason = "") {
  const reading = number(value);
  const node = element("div", "metric");
  if (color) node.classList.add(color);
  if (reading >= 85) node.classList.add("hot");
  const heading = element("span", "metric-label", label);
  const display = element("strong", "metric-value", percentage(reading));
  display.title = missingReason || display.textContent;
  const caption = element("p", "metric-caption", hint || "—");
  node.append(heading);
  if (metricDisplayMode === "gauges") {
    const gauge = element("div", "metric-gauge");
    const namespace = "http://www.w3.org/2000/svg";
    const drawing = document.createElementNS(namespace, "svg");
    drawing.setAttribute("viewBox", "0 0 54 31");
    drawing.setAttribute("aria-hidden", "true");
    const track = document.createElementNS(namespace, "path");
    track.setAttribute("d", "M 5 27 A 22 22 0 0 1 49 27");
    track.setAttribute("class", reading == null ? "metric-gauge-track is-empty" : "metric-gauge-track");
    drawing.append(track);
    if (reading > 0) {
      const arc = track.cloneNode();
      arc.setAttribute("class", "metric-gauge-arc");
      arc.setAttribute("pathLength", "100");
      arc.setAttribute("stroke-dasharray", Math.min(reading, 100) + " 100");
      drawing.append(arc);
    }
    gauge.append(drawing, display);
    node.append(gauge);
  } else {
    node.append(display);
  }
  node.append(caption);
  return node;
}

function trafficMetric(host, sample) {
  const traffic = sumTraffic(sample);
  const limitGb = number(host.traffic_limit_gb);
  const limit = limitGb == null || limitGb <= 0 ? null : limitGb * 1e9;
  return metric("累计流量", ratio(traffic, limit), limit == null ? bytes(traffic) : usage(traffic, limit),
    "green", limit == null ? "未设置流量配额" : "");
}

function deviceCardTitle(id) {
  return [...byId("cards").querySelectorAll('[data-action="title"]')].find((title) => title.dataset.host === id);
}

function updateSelectedCard() {
  const selected = byId("detail-dialog").open ? focusedHostId : null;
  for (const card of byId("cards").querySelectorAll("[data-device-card]")) {
    card.classList.toggle("is-selected", card.dataset.deviceCard === selected);
  }
}

function deviceCard(host) {
  const sample = sampleFor(host.id);
  const checking = state.refreshing?.includes(host.id);
  const card = element("article", "card");
  card.dataset.deviceCard = host.id;
  card.classList.toggle("is-selected", byId("detail-dialog").open && focusedHostId === host.id);
  const head = element("div", "card-head");
  const title = element("div", "card-title");
  const h3 = element("h3");
  const titleButton = button(host.name, "", () => openDetail(host.id));
  titleButton.dataset.host = host.id;
  titleButton.dataset.action = "title";
  titleButton.setAttribute("aria-haspopup", "dialog");
  titleButton.setAttribute("aria-controls", "detail-dialog");
  titleButton.title = host.name;
  const flag = deviceFlag(host);
  if (flag) h3.append(flag);
  h3.append(titleButton);
  const destination = element("p", "card-address", address(host));
  destination.title = address(host);
  title.append(h3, destination);
  head.append(title, statusBadge(sample));
  const tags = element("div", "card-tags");
  tags.append(element("span", "tag", host.group || "未分组"));
  const until = daysUntil(host.expires_on);
  if (until != null && until <= 30) {
    const caption = until < 0 ? "已到期" : (until === 0 ? "今日到期" : until + " 天到期");
    tags.append(element("span", "tag " + (until <= 7 ? "device-alert" : "expiring"), caption));
  }
  const trafficUsed = ratio(sumTraffic(sample), number(host.traffic_limit_gb) * 1e9);
  if (trafficUsed >= 80) {
    const traffic = element("span", "tag " + (trafficUsed >= 100 ? "device-alert" : "expiring"),
      "流量已用 " + percentage(trafficUsed));
    traffic.title = "按 VPS 网卡累计流量和设备配置的配额计算";
    tags.append(traffic);
  }
  const metrics = element("div", "metrics");
  const gpu = sample.gpus?.[0];
  const cpuScope = sample.cpu_scope === "cgroup" ? "容器 CPU" : "CPU";
  metrics.append(
    metric(cpuScope, number(sample.cpu_pct), number(sample.uptime_seconds) == null ? "—" : "运行 " + duration(sample.uptime_seconds)),
    metric("内存", ratio(sample.memory_used, sample.memory_total), usage(sample.memory_used, sample.memory_total)),
    metric("根磁盘", ratio(sample.disk_used, sample.disk_total), usage(sample.disk_used, sample.disk_total), "green"),
    gpu ? metric("GPU", number(gpu.utilization_pct), gpu.name, "violet") : trafficMetric(host, sample),
  );
  const network = element("div", "network");
  network.append(
    element("span", "", "↓ " + rate(sample.rx_bps)),
    element("span", "", "↑ " + rate(sample.tx_bps)),
  );
  if (gpu) network.append(element("span", "", bytes(sumTraffic(sample))));
  const footer = element("footer", "card-foot");
  const check = element("small", "", !canCollect(host) ? "尚未保存密码" :
    checking ? "正在检查" : (sample.checked_at ? "检查于 " + formattedDate(sample.checked_at, clockFormat) : "尚未采集"));
  if (sample.error) check.title = sample.error;
  const actions = element("div");
  const refresh = button("↻", "icon-button" + (checking ? " is-refreshing" : ""), () => refreshHosts(host.id));
  refresh.title = "刷新设备";
  refresh.setAttribute("aria-label", "刷新 " + host.name);
  refresh.dataset.host = host.id;
  refresh.dataset.action = "refresh";
  refresh.disabled = Boolean(checking || busy);
  if (checking) refresh.replaceChildren(element("span", "refresh-glyph", "↻"));
  if (canCollect(host)) actions.append(refresh);
  footer.append(check, actions);
  card.append(head, tags, metrics, network);
  const trend = window.vpsLatencyChart(state.latency_history?.[host.id] ?? [], {
    interval: state.interval_seconds, latest: number(sample.latency_ms), hostId: host.id,
  });
  trend.querySelector(".latency-chart-caption").title = sshLatencyHint;
  const ping = state.ping_history?.[host.id];
  const pingTrend = window.vpsPingChart(ping?.series ?? [], {
    hostId: host.id,
    scheduled: ping?.scheduled === true,
    onConfigure: state.demo ? undefined : () => openNetworkCheck(host, 1),
  });
  card.append(trend, pingTrend);
  const monitoring = window.vpsMonitoringSummary?.(state.komari?.[host.id]);
  if (monitoring) card.append(monitoring);
  card.append(footer);
  return card;
}

function groupOptions() {
  const select = byId("group-filter");
  const prior = select.value;
  const names = [...new Set(state.hosts.map((host) => host.group || "未分组"))].sort((a, b) => a.localeCompare(b, "zh"));
  if (JSON.stringify([...select.options].slice(1).map((option) => option.value)) === JSON.stringify(names)) return;
  select.replaceChildren(new Option("全部分组", ""));
  for (const name of names) select.add(new Option(name, name));
  select.value = names.includes(prior) ? prior : "";
}

function visibleHosts() {
  const query = byId("search").value.trim().toLowerCase();
  const group = byId("group-filter").value;
  const selectedStatus = byId("status-filter").value;
  return state.hosts.filter((host) => {
    const status = statusOf(sampleFor(host.id));
    if (group && group !== (host.group || "未分组")) return false;
    if (selectedStatus === "attention") {
      if (status === "online") return false;
    } else if (selectedStatus === "expiring") {
      if (!expiring(host)) return false;
    } else if (selectedStatus && selectedStatus !== status) {
      return false;
    }
    return !query || [host.name, address(host), host.group, host.note].some((value) => String(value || "").toLowerCase().includes(query));
  });
}

function renderCards() {
  const hosts = visibleHosts();
  const cards = byId("cards");
  const stamp = JSON.stringify([busy, metricDisplayMode, Math.floor(Date.now() / 60000), state.interval_seconds,
    hosts.map((host) => [host, sampleFor(host.id), state.refreshing?.includes(host.id),
      state.latency_history?.[host.id], state.ping_history?.[host.id], state.komari?.[host.id]])]);
  if (stamp !== cardStamp) {
    cardStamp = stamp;
    const focused = cards.contains(document.activeElement) ? document.activeElement.dataset : null;
    const replacement = document.createDocumentFragment();
    for (const host of hosts) replacement.append(deviceCard(host));
    cards.replaceChildren(replacement);
    if (focused?.host) {
      [...cards.querySelectorAll("[data-host]")].find((node) => node.dataset.host === focused.host && node.dataset.action === focused.action)?.focus({preventScroll: true});
    }
  }
  byId("filtered-count").textContent = hosts.length;
  cards.setAttribute("aria-busy", "false");
  byId("empty-state").hidden = hosts.length > 0;
  byId("empty-actions").hidden = state.hosts.length > 0 || state.demo;
  if (!hosts.length) {
    byId("empty-title").textContent = state.hosts.length ? "没有匹配的设备" : "还没有添加设备";
    byId("empty-description").textContent = state.hosts.length ? "试试调整搜索词、分组或状态。" : "填写 Linux 主机的 SSH 连接信息，即可添加设备。";
  }
}

async function changeMetricDisplay() {
  if (!state || savingMetricDisplay) return;
  const selector = byId("metric-display");
  const previous = metricDisplayMode;
  const mode = selector.value;
  savingMetricDisplay = selector.disabled = true;
  metricDisplayMode = mode;
  renderCards();
  try {
    await request("/api/metric-display", "POST", {mode});
    await loadState(true);
  } catch (error) {
    metricDisplayMode = selector.value = previous;
    renderCards();
    notice("无法保存指标显示。 " + error.message, true);
  } finally {
    savingMetricDisplay = selector.disabled = false;
  }
}

function renderFileDevices() {
  const search = byId("files-device-search");
  const list = byId("files-device-list");
  const hosts = state?.demo ? [] : (state?.hosts ?? []);
  const query = search.value.trim().toLocaleLowerCase();
  const matches = hosts.filter((host) => [host.name, address(host), host.group || "未分组"]
    .some((value) => value.toLocaleLowerCase().includes(query)));
  let message = "没有匹配的设备。";
  if (!state) message = byId("connection-error").hidden ? "正在读取设备…" : "正在重新连接本地面板…";
  else if (state.demo) message = "示例模式下无法浏览 VPS 文件。";
  else if (!hosts.length) message = "添加 VPS 后即可管理文件。";
  byId("files-device-search-wrap").hidden = !hosts.length;
  byId("files-device-empty").hidden = matches.length > 0;
  const status = byId("files-device-message");
  const description = matches.length ? "" : message;
  if (status.textContent !== description) status.textContent = description;
  const add = byId("files-device-add");
  add.hidden = !state || state.demo || hosts.length > 0;
  add.disabled = busy;
  const exitDemo = byId("files-device-demo-exit");
  exitDemo.hidden = !state?.demo;
  exitDemo.disabled = busy;

  const stamp = JSON.stringify(matches.map((host) => [host.id, host.name, address(host), host.group, host.country_code,
    statusOf(sampleFor(host.id))]));
  if (stamp === fileDevicesStamp) return;
  fileDevicesStamp = stamp;
  const focusedHost = list.contains(document.activeElement) ? document.activeElement.dataset.fileHost : null;
  const groups = new Map();
  for (const host of matches) {
    const group = host.group || "未分组";
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(host);
  }
  const sections = [];
  for (const group of [...groups.keys()].sort((a, b) => a.localeCompare(b, "zh"))) {
    const section = element("section", "files-device-group");
    const items = element("ul");
    for (const host of groups.get(group).sort((a, b) => a.name.localeCompare(b.name, "zh") || address(a).localeCompare(address(b)))) {
      const item = element("li");
      const open = button("", "files-device-row", () => {
        const current = state?.hosts.find(({id}) => id === host.id);
        if (current && !state.demo) selectFileHost(current);
      });
      open.dataset.fileHost = host.id;
      open.setAttribute("aria-pressed", String(selectedFileHost?.id === host.id));
      open.setAttribute("aria-controls", "files-browser");
      open.setAttribute("aria-label", "浏览 " + host.name + "，" + address(host));
      const details = element("span", "files-device-identity");
      const title = element("strong", "files-device-title");
      const flag = deviceFlag(host);
      if (flag) title.append(flag);
      title.append(document.createTextNode(host.name));
      details.append(title, element("span", "files-device-address", address(host)));
      open.append(details, statusBadge(sampleFor(host.id)));
      item.append(open);
      items.append(item);
    }
    section.append(element("h3", "", group), items);
    sections.push(section);
  }
  list.replaceChildren(...sections);
  if (focusedHost) {
    const target = [...list.querySelectorAll("[data-file-host]")].find((node) => node.dataset.fileHost === focusedHost);
    (target ?? (hosts.length ? search : byId("files-tab"))).focus({preventScroll: true});
  }
}

function selectFileHost(host) {
  selectedFileHost = host;
  for (const row of byId("files-device-list").querySelectorAll("[data-file-host]")) {
    row.setAttribute("aria-pressed", String(row.dataset.fileHost === host?.id));
  }
  if (host) window.vpsOpenFiles(host);
  else window.vpsResetFiles();
}

function render() {
  const refreshing = state.refreshing?.length > 0;
  byId("refresh-all").disabled = busy || refreshing || !state.hosts.some(canCollect);
  byId("refresh-all").classList.toggle("is-refreshing", refreshing);
  byId("refresh-all").lastElementChild.textContent = refreshing ? "采集中" : "刷新";
  byId("add-host").disabled = busy || state.demo;
  byId("inventory-open").disabled = busy || state.demo;
  byId("komari-open").disabled = busy || state.demo;
  byId("outbound-bulk-open").disabled = busy || state.demo || !state.hosts.length;
  byId("empty-add").disabled = busy;
  byId("demo-toggle").disabled = busy;
  byId("demo-exit").disabled = busy;
  byId("demo-banner").hidden = !state.demo;
  byId("demo-label").textContent = state.demo ? "退出示例" : "查看示例";
  byId("poll-caption").textContent = state.demo ? "模拟采集数据" : (number(state.interval_seconds) ? "每 " + state.interval_seconds + " 秒采集" : "");
  updateSummary();
  groupOptions();
  renderCards();
  if (selectedFileHost) {
    const current = state.demo ? null : state.hosts.find(({id}) => id === selectedFileHost.id);
    const connectionChanged = current && [...connectionFields, "password_saved"]
      .some((key) => current[key] !== selectedFileHost[key]);
    if (!current || connectionChanged) {
      selectFileHost(null);
      if (current && !byId("device-files").hidden) selectFileHost(current);
    } else if (current.name !== selectedFileHost.name) {
      selectFileHost(current);
    }
  }
  if (!byId("device-files").hidden) renderFileDevices();
  window.vpsRenderWebDav?.();
  window.vpsRenderTunnels?.();
  if (byId("detail-dialog").open) renderDetail();
}

function openForm(host = null, {focusPassword = false} = {}) {
  if (state?.demo) return;
  const form = byId("host-form");
  hostFormSession += 1;
  hostFormAction = "";
  editedHostId = host?.id ?? null;
  form.reset();
  savedPasswordTarget = host?.auth_mode === "password" && host.password_saved ? passwordTarget(host) : null;
  form.elements.remember_password.checked = savedPasswordTarget !== null;
  setPasswordVisibility(false);
  byId("host-dialog-title").textContent = editedHostId ? "编辑设备" : "添加设备";
  byId("host-form-error").hidden = true;
  for (const field of hostFields) form.elements[field].value = host?.[field] ?? "";
  form.elements.auth_mode.value = host?.auth_mode || "alias";
  const legacyAddress = form.elements.host.value.split("@");
  if (legacyAddress.length === 2 && (!form.elements.username.value || form.elements.username.value === legacyAddress[0])) {
    form.elements.username.value = legacyAddress[0];
    form.elements.host.value = legacyAddress[1];
  }
  form.querySelector("details").open = Boolean(host?.known_hosts || host?.traffic_limit_gb || host?.expires_on || host?.note);
  updateAuthFields(form);
  updateFormActions();
  showConnectionResult("");
  byId("host-dialog").showModal();
  const focus = focusPassword && !form.elements.password.disabled ? form.elements.password : form.elements.name;
  focus.focus();
}

function passwordTarget({host, username, port, known_hosts}) {
  const [first, second] = host.trim().split("@", 2);
  return JSON.stringify([second ? first : username?.trim() ?? "", (second || first).toLowerCase(), Number(port) || 22, known_hosts?.trim() ?? ""]);
}

function setPasswordVisibility(visible) {
  byId("host-form").elements.password.type = visible ? "text" : "password";
  const toggle = byId("host-password-toggle");
  toggle.textContent = visible ? "隐藏" : "显示";
  toggle.setAttribute("aria-label", visible ? "隐藏密码" : "显示密码");
  toggle.setAttribute("aria-pressed", String(visible));
}

function updatePasswordFields(form, enabled) {
  const {password, remember_password: remember} = form.elements;
  const storage = state?.password_storage_available === true;
  const terminal = embeddedTerminal("password") || state?.password_terminal_available === true;
  const canEncrypt = Boolean(window.crypto?.subtle && state?.password_public_key);
  const sameTarget = savedPasswordTarget !== null && savedPasswordTarget === passwordTarget(readHostForm(form, connectionFields));
  byId("password-fields").hidden = !enabled;
  password.disabled = !enabled || !canEncrypt;
  byId("host-password-toggle").disabled = !canEncrypt;
  remember.disabled = !enabled || !storage;
  password.placeholder = sameTarget ? "已保存密码，留空沿用" : "输入服务器 SSH 密码";
  if (!enabled) {
    password.value = "";
    setPasswordVisibility(false);
  }
  const hint = byId("password-hint");
  if (!window.crypto?.subtle) hint.textContent = "当前面板无法加密输入的密码。请使用本机浏览器面板输入。";
  else if (!state?.password_public_key) hint.textContent = "密码登录服务暂不可用，可在 SSH 终端输入密码。";
  else if (!storage) hint.textContent = terminal ? "密码可用于本次连接。本机密码存储不可用。" : "密码可用于测试连接。本机密码存储不可用。";
  else if (savedPasswordTarget && !remember.checked) hint.textContent = "保存后将从本机移除此设备的已存密码。";
  else if (sameTarget && !password.value) hint.textContent = terminal ? "已记住密码，可直接连接。输入新密码可替换。" : "已保存在本机。可留空测试，输入新密码可替换。";
  else if (savedPasswordTarget && !sameTarget) hint.textContent = "连接信息已变更，请为新连接输入密码。";
  else if (terminal) hint.textContent = remember.checked ? "保存后可直接连接，也可自动巡检。" : "可直接用这个密码连接。勾选后保存可供下次使用。";
  else hint.textContent = remember.checked ? "保存后，此设备可用本机保存的密码自动巡检。" : "密码只用于本次测试。勾选记住密码后可自动巡检。";
}

function updateAuthFields(form) {
  const mode = form.elements.auth_mode.value;
  const {host, username} = form.elements;
  const hasEmbeddedUser = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}@[^@\s]+$/.test(host.value.trim());
  username.required = mode !== "alias" && !hasEmbeddedUser;
  username.setCustomValidity(username.required && username.value && !username.value.trim() ? "请输入服务器用户名。" : "");
  byId("identity-file-row").hidden = mode !== "key";
  form.elements.identity_file.disabled = mode !== "key";
  form.elements.identity_file.required = mode === "key";
  updatePasswordFields(form, mode === "password");
  const embedded = embeddedTerminal(mode);
  const nativePassword = state?.password_terminal_available === true;
  const terminalButton = byId("host-terminal");
  terminalButton.textContent = embedded || (mode === "password" && nativePassword) ? "打开 SSH 终端" : "打开系统终端";
  terminalButton.classList.toggle("primary", Boolean(embedded));
  terminalButton.classList.toggle("secondary", !embedded);
  byId("host-terminal-manual").hidden = !(embedded || (mode === "password" && nativePassword));
  form.elements.port.placeholder = mode === "alias" ? "使用配置" : "22";
  const hints = {
    alias: "用户名和端口留空时沿用 OpenSSH 配置。",
    key: "填写服务器用户名并选择本机私钥。首次连接时，可在终端核对服务器指纹。",
    password: embedded || nativePassword ? "输入密码后可直接打开 SSH 终端。" : "可直接在下面输入密码并测试连接。",
  };
  byId("auth-mode-hint").textContent = hints[mode];
}

function updateFormActions() {
  for (const id of ["host-test", "host-terminal", "host-terminal-manual", "host-key-file", "host-save"]) {
    byId(id).disabled = Boolean(hostFormAction);
  }
}

function currentForm(session) {
  return session === hostFormSession && byId("host-dialog").open;
}

function readHostForm(form, fields) {
  const data = Object.fromEntries(fields.map((name) => [name, form.elements[name].value.trim()]));
  for (const field of ["port", "traffic_limit_gb"]) {
    if (Object.hasOwn(data, field)) data[field] = data[field] ? Number(data[field]) : null;
  }
  if (data.auth_mode !== "key") data.identity_file = "";
  return data;
}

function showConnectionResult(message, kind = "", command = "") {
  const result = byId("host-connection-result");
  result.textContent = message;
  result.dataset.kind = kind;
  result.hidden = !message;
  const terminalCommand = byId("host-terminal-command");
  terminalCommand.textContent = command;
  terminalCommand.hidden = !command;
  if (!message) setTerminalFallback(false);
}

function resultMessage(result) {
  const latency = number(result.latency_ms);
  return result.message + (result.status === "connected" && latency != null ? "（" + numberFormat.format(latency) + " ms）" : "") +
    (result.fingerprint ? " 指纹 " + result.fingerprint : "");
}

function readSshDraft(form, usePassword) {
  const draft = readHostForm(form, connectionFields);
  if (usePassword && draft.auth_mode === "password" && !form.elements.password.value &&
      savedPasswordTarget && savedPasswordTarget === passwordTarget(draft)) {
    draft.credential_id = editedHostId;
  }
  return draft;
}

async function sealPassword(password, draft, action) {
  const subtle = window.crypto?.subtle;
  if (!subtle) throw new Error("当前面板无法加密输入的密码。请使用本机浏览器面板输入。");
  if (!state?.password_public_key) throw new Error("密码登录服务暂不可用，可在 SSH 终端输入密码。");
  const encoder = new TextEncoder();
  const plain = encoder.encode(password);
  try {
    const keyBytes = Uint8Array.from(atob(state.password_public_key), (char) => char.charCodeAt(0));
    const recipient = await subtle.importKey("spki", keyBytes, {name: "RSA-OAEP", hash: "SHA-256"}, false, ["encrypt"]);
    const sessionKey = await subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt"]);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const binding = [draft.host, draft.username, draft.port, draft.auth_mode, draft.known_hosts, action];
    const additionalData = encoder.encode(JSON.stringify(binding));
    const [ciphertext, rawKey] = await Promise.all([
      subtle.encrypt({name: "AES-GCM", iv, additionalData}, sessionKey, plain),
      subtle.exportKey("raw", sessionKey),
    ]);
    try {
      const wrappedKey = await subtle.encrypt({name: "RSA-OAEP"}, recipient, rawKey);
      const toBase64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
      return {wrapped_key: toBase64(wrappedKey), iv: toBase64(iv), ciphertext: toBase64(ciphertext)};
    } finally {
      new Uint8Array(rawKey).fill(0);
    }
  } catch {
    throw new Error("无法加密 SSH 密码，请刷新面板后重试。");
  } finally {
    plain.fill(0);
  }
}

async function runFormSsh(action, {manual = false, verifyHost = false} = {}) {
  if (hostFormAction) return;
  const form = byId("host-form");
  if (!connectionFields.every((field) => form.elements[field].reportValidity())) return;
  const mode = form.elements.auth_mode.value;
  const passwordMode = mode === "password";
  const embedded = action === "terminal" && !manual && !verifyHost && embeddedTerminal(mode);
  const usePassword = passwordMode && (action === "test" || embedded || (!manual && !verifyHost && state?.password_terminal_available === true));
  const draft = readSshDraft(form, usePassword);
  const password = usePassword ? form.elements.password.value : "";
  if (usePassword && !password && !draft.credential_id) {
    const field = form.elements.password;
    showConnectionResult(field.disabled ? byId("password-hint").textContent : "请先输入 SSH 密码。", "error");
    if (!field.disabled) field.focus();
    return;
  }
  const session = hostFormSession;
  const unchanged = () => currentForm(session) && (!usePassword || password === form.elements.password.value) &&
    JSON.stringify(draft) === JSON.stringify(readSshDraft(form, usePassword));
  hostFormAction = action;
  updateFormActions();
  showConnectionResult(action === "test" ? "正在测试 SSH 连接…" : "正在打开 SSH 终端…");
  try {
    const payload = {...draft};
    if (password) payload.password_box = await sealPassword(password, draft, action);
    if (action === "terminal" && passwordMode && !usePassword) {
      if (verifyHost) payload.verify_host = true;
      else payload.manual = true;
    }
    if (!unchanged()) return;
    const result = embedded ? await request("/api/terminal/open", "POST", {host: payload, cols: 80, rows: 24}) :
      await request("/api/ssh/" + action, "POST", payload);
    if (!unchanged()) {
      if (embedded && result.id) closeTerminalRequest(result.id).catch(() => {});
      return;
    }
    if (embedded && result.id) {
      openTerminalTab(result, form.elements.name.value.trim() || address(draft));
      byId("host-dialog").close();
    } else showSshResult(result);
  } catch (error) {
    if (unchanged()) showConnectionResult(error.message, "error");
  } finally {
    if (currentForm(session)) {
      hostFormAction = "";
      updateFormActions();
    }
  }
}

function showSshResult(result) {
  const informational = result.status === "manual_terminal" || result.status === "password_required";
  const kind = informational ? "" : result.ok ? "success" : "error";
  showConnectionResult(resultMessage(result), kind, result.command || "");
  setTerminalFallback(result.status === "host_key_unknown");
}

function setTerminalFallback(verifyHost) {
  const fallback = byId("host-terminal-manual");
  const password = byId("host-form").elements.auth_mode.value === "password";
  fallback.dataset.verifyHost = String(verifyHost && password);
  fallback.textContent = verifyHost ? "核对指纹" : "系统终端";
  if (verifyHost) fallback.hidden = false;
}

async function chooseIdentityFile() {
  if (hostFormAction) return;
  const form = byId("host-form");
  const field = form.elements.identity_file;
  const previousPath = field.value;
  const session = hostFormSession;
  hostFormAction = "key-file";
  updateFormActions();
  showConnectionResult("请在系统文件选择窗口中选择私钥…");
  try {
    const result = await request("/api/ssh/key-file", "POST", {});
    if (currentForm(session)) {
      if (result.path && !field.disabled && field.value === previousPath) field.value = result.path;
      showConnectionResult("");
    }
  } catch (error) {
    if (currentForm(session)) showConnectionResult(error.message, "error");
  } finally {
    if (currentForm(session)) {
      hostFormAction = "";
      updateFormActions();
    }
  }
}

async function saveHost(event) {
  event.preventDefault();
  if (hostFormAction) return;
  const form = event.currentTarget;
  const data = readHostForm(form, hostFields);
  const id = editedHostId;
  const session = hostFormSession;
  const errorNode = byId("host-form-error");
  errorNode.hidden = true;
  let passwordToSave = "";
  if (data.auth_mode === "password" && !form.elements.remember_password.disabled) {
    const password = form.elements.password.value;
    if (form.elements.remember_password.checked) {
      if (!password && savedPasswordTarget !== passwordTarget(data)) {
        errorNode.textContent = "请输入要保存在本机的 SSH 密码。";
        errorNode.hidden = false;
        form.elements.password.focus();
        return;
      }
      data.remember_password = true;
      passwordToSave = password;
    } else if (savedPasswordTarget) {
      data.clear_password = true;
    }
  }
  hostFormAction = "save";
  updateFormActions();
  if (passwordToSave) showConnectionResult("正在验证并保存 SSH 密码…");
  try {
    if (passwordToSave) {
      data.password_box = await sealPassword(passwordToSave, data, "save");
      const currentDraft = readHostForm(form, hostFields);
      const sameDraft = hostFields.every((field) => data[field] === currentDraft[field]);
      if (!currentForm(session) || !form.elements.remember_password.checked || !sameDraft ||
          form.elements.password.value !== passwordToSave) return;
    }
    const path = id ? "/api/hosts/" + encodeURIComponent(id) : "/api/hosts";
    await request(path, id ? "PUT" : "POST", data);
    if (currentForm(session)) byId("host-dialog").close();
    notice(id ? "设备已更新" : "设备已添加");
    await loadState(true);
  } catch (error) {
    if (currentForm(session)) {
      if (passwordToSave) showConnectionResult("");
      errorNode.textContent = error.message;
      errorNode.hidden = false;
    } else {
      notice(error.message, true);
    }
  } finally {
    if (currentForm(session)) {
      hostFormAction = "";
      updateFormActions();
    }
  }
}

function detailPoint(label, value, hint) {
  const node = element("div");
  const reading = element("dd", "", value);
  if (hint) reading.append(element("small", "", hint));
  node.append(element("dt", "", label), reading);
  return node;
}

function detailSection(title, ...readings) {
  const node = element("section", "detail-section");
  const points = element("dl", "detail-points");
  points.append(...readings);
  node.append(element("h3", "", title), points);
  return node;
}

function historyPlot(points, metric, end, gapMs) {
  const figure = element("figure", "trend");
  const caption = element("figcaption");
  const values = points.map((point) => {
    const value = point.status === "online" ? number(point[metric.key]) : null;
    return value != null && value >= 0 ? value : null;
  });
  const samples = values.filter((value) => value != null);
  const last = samples.at(-1);
  const label = last == null ? "无有效采样" : "最近有效 " + numberFormat.format(last) + metric.unit;
  caption.append(element("strong", "", metric.title), element("span", "", label));
  figure.append(caption);
  if (!samples.length) return figure;

  const width = 1024;
  const height = 84;
  const padding = 6;
  const maximum = Math.max(metric.scale, 1, ...samples);
  const canvas = element("canvas");
  canvas.width = width;
  canvas.height = height;
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", metric.title + "最近 24 小时，" + samples.length + " 个有效样本，" + label);
  const time = element("div", "trend-time");
  time.append(
    element("span", "", "24 小时前"),
    element("span", "", "0–" + numberFormat.format(maximum) + metric.unit),
    element("span", "", "现在"),
  );
  figure.append(canvas, time);
  const context = canvas.getContext("2d");
  if (!context) return figure;

  const start = end - dayMs;
  context.strokeStyle = "#d9e3ef";
  context.lineWidth = 2;
  context.beginPath();
  for (const fraction of [0, 0.25, 0.5, 0.75, 1]) {
    const x = padding + (width - padding * 2) * fraction;
    context.moveTo(x, padding);
    context.lineTo(x, height - padding);
  }
  context.stroke();

  context.strokeStyle = metric.color;
  context.fillStyle = metric.color;
  context.lineWidth = 4;
  context.lineCap = "round";
  const visible = [];
  let previous = null;
  context.beginPath();
  for (const [index, point] of points.entries()) {
    const value = values[index];
    if (value == null) {
      previous = null;
      continue;
    }
    const x = padding + (point.time - start) / dayMs * (width - padding * 2);
    const y = height - padding - value / maximum * (height - padding * 2);
    if (previous != null && point.time - previous <= gapMs) context.lineTo(x, y);
    else context.moveTo(x, y);
    visible.push([x, y]);
    previous = point.time;
  }
  context.stroke();
  for (const [x, y] of visible) {
    context.beginPath();
    context.arc(x, y, 3, 0, Math.PI * 2);
    context.fill();
  }
  return figure;
}

function drawHistory(points, demo) {
  const charts = byId("history-charts");
  charts.replaceChildren();
  const end = Date.now();
  const windowPoints = points.map((point) => ({...point, time: Date.parse(point.checked_at)}))
    .filter((point) => point.time >= end - dayMs && point.time <= end)
    .sort((first, second) => first.time - second.time);
  const online = windowPoints.filter((point) => point.status === "online").length;
  const status = byId("history-status");
  if (!windowPoints.length) {
    status.textContent = "最近 24 小时暂无采样。";
    return;
  }
  const prefix = demo ? "模拟数据 · " : "";
  const total = windowPoints.length;
  status.textContent = prefix + total + " 次采样，" + online + " 次在线。" +
    (online > 1 ? "断线或缺少采样时保留空白。" : "有效采样不足，暂时无法判断趋势。");
  const gapMs = 3000 * Math.max(60, number(state.interval_seconds) ?? 60);
  charts.replaceChildren(...historyMetrics.map((metric) => historyPlot(windowPoints, metric, end, gapMs)));
}

async function loadHistory(host, checkedAt, demo) {
  const stamp = JSON.stringify([host.id, host.auth_mode, host.password_saved, checkedAt, demo]);
  if (historyStamp === stamp) return;
  historyStamp = stamp;
  const sequence = ++historyRequest;
  const status = byId("history-status");
  if (!canCollect(host)) {
    byId("history-charts").replaceChildren();
    status.textContent = "记住设备密码后可自动采样。";
    return;
  }
  if (!byId("history-charts").childElementCount) status.textContent = "正在读取本地采样…";
  try {
    const result = await request("/api/hosts/" + encodeURIComponent(host.id) + "/history");
    if (sequence !== historyRequest || !byId("detail-dialog").open) return;
    if (!Array.isArray(result.points)) throw new Error("采样数据格式无效。");
    drawHistory(result.points, demo);
  } catch (error) {
    if (sequence === historyRequest && byId("detail-dialog").open) {
      status.textContent = "无法读取采样。" + (byId("history-charts").childElementCount ? "保留上次结果。" : "") + " " + error.message;
    }
  }
}

const openNetworkCheck = (() => {
  const dialog = byId("network-check-dialog");
  const tabList = byId("network-check-tabs");
  const tabs = Array.from(tabList.querySelectorAll('[role="tab"]'));
  const openPane = [
    (host) => window.vpsOpenNetworkProbes(host),
    (host) => window.vpsOpenOutboundProbes(host),
  ];
  let device = null;
  let openedPanes;

  function selectTab(index) {
    if (!dialog.open) return;
    tabs.forEach((tab, position) => {
      const selected = position === index;
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
      byId(tab.getAttribute("aria-controls")).hidden = !selected;
    });
    if (!openedPanes.has(index)) {
      openedPanes.add(index);
      openPane[index](device);
    }
    tabs[index].focus();
  }

  tabs.forEach((tab, index) => tab.addEventListener("click", () => selectTab(index)));
  tabList.addEventListener("keydown", (event) => {
    const index = tabs.indexOf(event.target);
    if (index < 0) return;
    let next;
    if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
    else if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    else return;
    event.preventDefault();
    selectTab(next);
  });

  return (host, initialTab = 0) => {
    device = host;
    openedPanes = new Set();
    byId("network-check-host").textContent = host.name;
    dialog.dispatchEvent(new Event("network-check-open"));
    dialog.showModal();
    selectTab(initialTab);
  };
})();

function renderDetail() {
  const host = state.hosts.find((item) => item.id === focusedHostId);
  if (!host) {
    byId("detail-dialog").close();
    return;
  }
  const sample = sampleFor(host.id);
  loadHistory(host, sample.checked_at, state.demo);
  const checking = state.refreshing?.includes(host.id);
  const openingTerminal = pendingDetailTerminals.has(host.id);
  const embedded = embeddedTerminal(host.auth_mode || "alias");
  const ping = state.ping_history?.[host.id];
  const monitor = state.komari?.[host.id];
  const stamp = JSON.stringify([host, sample, checking, state.demo, busy, embedded, state.password_terminal_available,
    openingTerminal, ping, monitor]);
  if (stamp === detailStamp) return;
  detailStamp = stamp;
  const title = byId("detail-title");
  title.title = host.name;
  title.replaceChildren(host.name);
  const flag = deviceFlag(host);
  if (flag) title.prepend(flag);
  const sshAddress = address(host);
  const subtitle = byId("detail-address");
  subtitle.textContent = sshAddress + " · " + (host.group || "未分组");
  subtitle.title = subtitle.textContent;
  byId("detail-status").replaceChildren(checking ? element("span", "status-pill", "正在检查") : statusBadge(sample));

  const cpuModel = detailPoint("CPU 型号", sample.cpu_model || "—");
  cpuModel.className = "detail-wide";
  const cpuCount = number(sample.cpu_logical_count);
  const availableCpus = number(sample.cpu_available_count);
  const cpuAvailability = availableCpus != null && availableCpus !== cpuCount
    ? "SSH 可用 " + numberFormat.format(availableCpus) + " 个"
    : "";
  const hardware = detailSection("硬件与资源",
    cpuModel,
    detailPoint("系统在线逻辑 CPU", cpuCount == null ? "—" : numberFormat.format(cpuCount) + " 个", cpuAvailability),
    detailPoint(sample.cpu_scope === "cgroup" ? "容器 CPU 使用率" : "CPU 使用率", percentage(sample.cpu_pct)),
    detailPoint("内存", usage(sample.memory_used, sample.memory_total), "已用 / 总量"),
    detailPoint("根磁盘", usage(sample.disk_used, sample.disk_total), "已用 / 总量"),
  );

  const latency = number(sample.latency_ms);
  const latencyReading = detailPoint("SSH 巡检延迟", latency == null ? "—" : numberFormat.format(latency) + " ms");
  latencyReading.title = sshLatencyHint;
  const deviceName = detailPoint("设备名称", host.name);
  const deviceAddress = detailPoint("SSH 地址", sshAddress);
  deviceName.className = deviceAddress.className = "detail-wide";
  const inspection = detailSection("SSH 巡检",
    latencyReading,
    detailPoint("最后检查", formattedDate(sample.checked_at)),
    detailPoint("SSH 认证", authLabels[host.auth_mode] || authLabels.alias),
    detailPoint("主机名", sample.hostname || "—"),
    detailPoint("运行时长", duration(sample.uptime_seconds)),
    detailPoint("到期日期", host.expires_on || "—"),
    deviceName,
    deviceAddress,
  );
  if (host.auth_mode === "password") {
    const credential = host.password_saved ? "密码已保存在本机。" : "可编辑设备并在本机记住密码，以启用自动采集。";
    inspection.append(element("p", "detail-line", credential));
  }
  if (sample.error) inspection.append(element("p", "detail-alert", sample.error));

  for (const gpu of sample.gpus || []) {
    const detail = [gpu.name || "GPU"];
    if (number(gpu.utilization_pct) != null) detail.push("使用率 " + percentage(gpu.utilization_pct));
    if (number(gpu.total_mib) != null) detail.push("显存 " + usage(gpu.used_mib, gpu.total_mib, (n) => number(n) == null ? "—" : numberFormat.format(n) + " MiB"));
    if (number(gpu.temperature_c) != null) detail.push(gpu.temperature_c + " °C");
    hardware.append(element("p", "detail-line", detail.join(" · ")));
  }
  const network = detailSection("网络",
    detailPoint("累计接收", bytes(sample.rx_bytes), "当前 " + rate(sample.rx_bps)),
    detailPoint("累计发送", bytes(sample.tx_bytes), "当前 " + rate(sample.tx_bps)),
  );
  network.classList.add("detail-wide");
  const body = byId("detail-body");
  const active = document.activeElement;
  const pingFocused = body.contains(active) && active.dataset.action === "ping-chart";
  if (ping?.series?.length || ping?.scheduled) {
    network.append(window.vpsPingChart(ping.series ?? [], {
      scheduled: ping.scheduled === true,
      hostId: host.id,
      selectedTime: pingFocused ? Number(active.dataset.sampleTime) : undefined,
    }));
  }
  const blocks = [hardware, inspection, network];
  const monitoring = window.vpsMonitoringSummary?.(monitor);
  if (monitoring) {
    monitoring.classList.add("detail-wide");
    blocks.push(monitoring);
  }
  if (host.note) blocks.push(element("p", "detail-line detail-wide", "备注 · " + host.note));
  body.replaceChildren(...blocks);
  if (pingFocused) {
    const next = body.querySelector('[data-action="ping-chart"]') ?? byId("detail-scroll");
    next.focus({preventScroll: true});
  }

  const footer = byId("detail-actions");
  const focusedAction = footer.contains(document.activeElement) ? document.activeElement.dataset.detailAction : null;
  const controls = [];
  if (!state.demo) {
    const remove = button("移除", "text-button danger-text", () => openDelete(host));
    remove.dataset.detailAction = "delete";
    controls.push(remove);
    const edit = button("编辑设备", "button secondary", () => {
      byId("detail-dialog").close();
      openForm(host);
    });
    edit.dataset.detailAction = "edit";
    controls.push(edit);
    if (typeof window.vpsOpenNetworkProbes === "function" && typeof window.vpsOpenOutboundProbes === "function") {
      const networkCheck = button("网络检测", "button secondary", () => {
        byId("detail-dialog").close();
        openNetworkCheck(host);
      });
      networkCheck.dataset.detailAction = "network-check";
      controls.push(networkCheck);
    }
    if (typeof window.vpsOpenFiles === "function") {
      const fileManager = button("文件管理", "button secondary", () => {
        byId("detail-dialog").close();
        chooseWorkspace("files-tab");
        if (![...byId("files-device-list").querySelectorAll("[data-file-host]")].some((row) => row.dataset.fileHost === host.id)) {
          byId("files-device-search").value = "";
          renderFileDevices();
        }
        selectFileHost(host);
        byId("files-host").focus();
      });
      fileManager.dataset.detailAction = "files";
      controls.push(fileManager);
    }
    if (typeof window.vpsOpenTunnels === "function") {
      const tunnels = button("隧道", "button secondary", () => {
        byId("detail-dialog").close();
        chooseWorkspace("tunnel-tab");
        window.vpsOpenTunnels(host.id);
        byId("tunnel-tab").focus();
      });
      tunnels.dataset.detailAction = "tunnels";
      controls.push(tunnels);
    }
    if (typeof window.vpsOpenMonitoring === "function") {
      const komari = button(monitor ? "监控历史" : "绑定监控", "button secondary", () => {
        byId("detail-dialog").close();
        if (state.komari?.[host.id]) window.vpsOpenMonitoringHistory(host.id);
        else window.vpsOpenMonitoring(host.id);
      });
      komari.dataset.detailAction = "komari";
      controls.push(komari);
    }
    if (host.auth_mode !== "key" || host.identity_file) {
      const passwordTerminal = host.auth_mode === "password" && state.password_terminal_available === true;
      const terminal = button(openingTerminal ? "正在打开…" : embedded || passwordTerminal ? "打开 SSH 终端" : "打开系统终端",
        "button " + (host.auth_mode === "password" ? "primary" : "secondary"), () => openDetailTerminal(host));
      terminal.dataset.detailAction = "terminal";
      terminal.disabled = openingTerminal;
      controls.push(terminal);
    }
  }
  if (canCollect(host)) {
    const refresh = button(checking ? "采集中" : "刷新设备", "button primary", () => refreshHosts(host.id));
    refresh.dataset.detailAction = "refresh";
    refresh.disabled = Boolean(checking || busy);
    controls.push(refresh);
  }
  footer.replaceChildren(...controls);
  if (focusedAction) controls.find((control) => control.dataset.detailAction === focusedAction)?.focus({preventScroll: true});
}

async function openDetailTerminal(host) {
  const dialog = byId("detail-dialog");
  const mode = host.auth_mode || "alias";
  const embedded = embeddedTerminal(mode);
  if (!embedded && (mode !== "password" || state?.password_terminal_available !== true)) {
    dialog.close();
    openForm(host);
    await runFormSsh("terminal");
    return;
  }
  if (mode === "password" && !host.password_saved) {
    dialog.close();
    openForm(host, {focusPassword: true});
    return;
  }
  if (pendingDetailTerminals.has(host.id)) return;
  const showFailure = (result) => {
    const current = state?.hosts.find((item) => item.id === host.id);
    if (!dialog.open || focusedHostId !== host.id || !current) {
      notice(resultMessage(result), true);
      return;
    }
    dialog.close();
    openForm(current, {focusPassword: true});
    showSshResult(result);
  };
  const draft = Object.fromEntries(connectionFields.map((field) => [field, host[field] ?? (field === "port" ? null : "")]));
  draft.auth_mode = mode;
  if (mode === "password") draft.credential_id = host.id;
  pendingDetailTerminals.add(host.id);
  renderDetail();
  try {
    const result = embedded ? await request("/api/terminal/open", "POST", {host: draft, cols: 80, rows: 24}) :
      await request("/api/ssh/terminal", "POST", draft);
    if (embedded && result.id) {
      if (!dialog.open || focusedHostId !== host.id) {
        closeTerminalRequest(result.id).catch(() => {});
        return;
      }
      openTerminalTab(result, host.name);
      dialog.close();
    } else if (result.ok && !result.command) notice(resultMessage(result));
    else showFailure(result);
  } catch (error) {
    showFailure({message: error.message, ok: false});
  } finally {
    pendingDetailTerminals.delete(host.id);
    if (dialog.open) renderDetail();
  }
}

function openDetail(id) {
  const dialog = byId("detail-dialog");
  if (dialog.open || !state?.hosts.some((host) => host.id === id)) return;
  deviceCardTitle(id)?.focus({preventScroll: true});
  focusedHostId = id;
  detailStamp = "";
  historyStamp = "";
  byId("history-charts").replaceChildren();
  renderDetail();
  dialog.showModal();
  updateSelectedCard();
  byId("detail-scroll").scrollTop = 0;
}

function openDelete(host) {
  deletingHostId = host.id;
  byId("detail-dialog").close();
  byId("delete-description").textContent = "将“" + host.name + "”从本地设备列表移除。";
  byId("delete-dialog").showModal();
}

function inventoryStatus(message, kind = "") {
  const status = byId("inventory-status");
  status.textContent = message;
  status.dataset.kind = kind;
  status.hidden = !message;
}

function updateInventoryActions() {
  const value = byId("inventory-json").value;
  byId("inventory-browse").disabled = inventoryBusy;
  byId("inventory-export").disabled = inventoryBusy;
  byId("inventory-select").disabled = !value;
  byId("inventory-preview").disabled = inventoryBusy || !value.trim();
  byId("inventory-import").disabled = inventoryBusy || !inventoryPreview?.added || inventoryPreview.source !== value;
  const list = byId("inventory-targets");
  list.hidden = !inventoryPreview?.inventory.hosts.length;
  if (list.hidden) list.replaceChildren();
}

function openInventory() {
  if (!state || state.demo) return;
  inventorySession += 1;
  inventoryBusy = false;
  inventoryPreview = null;
  byId("inventory-json").value = "";
  byId("inventory-file").value = "";
  inventoryStatus("");
  updateInventoryActions();
  byId("inventory-dialog").showModal();
  byId("inventory-json").focus();
}

function selectInventory() {
  const input = byId("inventory-json");
  input.focus();
  input.select();
}

async function readInventoryFile(event) {
  const picker = event.currentTarget;
  const file = picker.files[0];
  picker.value = "";
  if (!file || inventoryBusy) return;
  const input = byId("inventory-json");
  const source = input.value;
  const session = inventorySession;
  const current = () => session === inventorySession && byId("inventory-dialog").open;
  inventoryPreview = null;
  if (file.size > maxInventoryFileBytes) {
    inventoryStatus("请选择不超过 512 KB 的 JSON 文件。", "error");
    updateInventoryActions();
    return;
  }
  inventoryBusy = true;
  updateInventoryActions();
  inventoryStatus("正在读取 JSON 文件…");
  try {
    const text = await file.text();
    if (current() && input.value === source) {
      input.value = text.replace(/^\uFEFF/, "");
      inventoryStatus("已读取文件，可预览导入。", "success");
    }
  } catch {
    if (current() && input.value === source) inventoryStatus("无法读取此文件。可复制 JSON 内容后粘贴到上方。", "error");
  } finally {
    if (current()) {
      inventoryBusy = false;
      updateInventoryActions();
    }
  }
}

async function runInventory(action) {
  if (inventoryBusy) return;
  const input = byId("inventory-json");
  const source = input.value;
  const session = inventorySession;
  const current = () => session === inventorySession && byId("inventory-dialog").open;
  let body = {};
  if (action === "import") {
    if (!inventoryPreview?.added || inventoryPreview.source !== source) return;
    body = {inventory: inventoryPreview.inventory};
  }
  inventoryPreview = null;
  if (action === "preview") {
    try {
      body = {inventory: JSON.parse(source)};
    } catch {
      inventoryStatus("JSON 格式无效，请检查内容后重试。", "error");
      updateInventoryActions();
      return;
    }
  }

  inventoryBusy = true;
  updateInventoryActions();
  inventoryStatus({export: "正在生成导出…", preview: "正在检查设备清单…", import: "正在导入设备…"}[action]);
  try {
    const result = await request("/api/inventory/" + action, "POST", body);
    if (action === "import") {
      const summary = "已添加 " + result.added + " 台，跳过 " + result.skipped + " 台重复设备。";
      if (current()) {
        const keyHint = result.added && body.inventory.hosts.some((host) => host.auth_mode === "key")
          ? " 如有新增私钥设备，请在设备详情中编辑并选择本机私钥。" : "";
        inventoryStatus(summary + keyHint, "success");
      } else {
        notice(summary);
      }
      await loadState(true);
    } else if (current() && input.value === source) {
      if (action === "export") {
        input.value = JSON.stringify(result.inventory, null, 2);
        inventoryStatus("已生成 " + result.inventory.hosts.length + " 台设备的清单，可选中后复制保存。", "success");
        selectInventory();
      } else {
        inventoryPreview = {source, inventory: body.inventory, added: result.added};
        const summary = "将添加 " + result.added + " 台，跳过 " + result.skipped + " 台重复设备。";
        inventoryStatus(summary + (result.added ? " 已有设备保留原配置。确认后才会写入。" : " 没有可添加的设备。"));
        const hosts = body.inventory.hosts;
        const items = hosts.slice(0, 8).map((host) => element("li", "", host.name + " · " + address(host)));
        if (hosts.length > items.length) items.push(element("li", "", "另有 " + (hosts.length - items.length) + " 台设备"));
        byId("inventory-targets").replaceChildren(...items);
      }
    }
  } catch (error) {
    if (current() && (action === "import" || input.value === source)) inventoryStatus(error.message, "error");
    else if (action === "import") notice(error.message, true);
  } finally {
    if (current()) {
      inventoryBusy = false;
      updateInventoryActions();
    }
  }
}

async function deleteHost() {
  const id = deletingHostId;
  if (!id) return;
  byId("delete-confirm").disabled = true;
  try {
    await request("/api/hosts/" + encodeURIComponent(id), "DELETE");
    byId("delete-dialog").close();
    notice("设备已移除");
    await loadState(true);
  } catch (error) {
    byId("delete-dialog").close();
    notice(error.message, true);
  } finally {
    byId("delete-confirm").disabled = false;
  }
}

async function runStateAction(path, data, success) {
  if (busy || !state) return;
  busy = true;
  render();
  try {
    await request(path, "POST", data);
    if (path === "/api/demo") {
      byId("search").value = "";
      byId("group-filter").value = "";
      byId("status-filter").value = "";
    }
    await loadState(true);
    if (success) notice(success);
  } catch (error) {
    notice(error.message, true);
  } finally {
    busy = false;
    render();
  }
}

function refreshHosts(id) {
  return runStateAction("/api/refresh", id ? {id} : {}, "已提交采集请求");
}

function toggleDemo(enabled) {
  return runStateAction("/api/demo", {enabled});
}

byId("add-host").addEventListener("click", () => openForm());
byId("inventory-open").addEventListener("click", openInventory);
byId("komari-open").addEventListener("click", () => window.vpsOpenMonitoring());
byId("inventory-browse").addEventListener("click", () => byId("inventory-file").click());
byId("inventory-file").addEventListener("change", readInventoryFile);
byId("inventory-export").addEventListener("click", () => runInventory("export"));
byId("inventory-select").addEventListener("click", selectInventory);
byId("inventory-preview").addEventListener("click", () => runInventory("preview"));
byId("inventory-import").addEventListener("click", () => runInventory("import"));
byId("inventory-json").addEventListener("input", () => {
  inventoryPreview = null;
  inventoryStatus("");
  updateInventoryActions();
});
byId("empty-add").addEventListener("click", () => openForm());
byId("demo-toggle").addEventListener("click", () => toggleDemo(!state?.demo));
byId("empty-demo").addEventListener("click", () => toggleDemo(true));
byId("demo-exit").addEventListener("click", () => toggleDemo(false));
byId("refresh-all").addEventListener("click", () => refreshHosts());
byId("host-form").addEventListener("submit", saveHost);
byId("host-form").addEventListener("input", (event) => {
  const field = event.target.name || event.target.id;
  if (![...connectionFields, "password", "remember_password"].includes(field)) return;
  updateAuthFields(event.currentTarget);
  showConnectionResult("");
});
byId("host-dialog").addEventListener("close", () => {
  if (byId("host-dialog").open) return;
  byId("host-form").elements.password.value = "";
  setPasswordVisibility(false);
});
byId("host-password-toggle").addEventListener("click", () => setPasswordVisibility(byId("host-form").elements.password.type === "password"));
byId("host-test").addEventListener("click", () => runFormSsh("test"));
byId("host-terminal").addEventListener("click", () => runFormSsh("terminal"));
byId("host-terminal-manual").addEventListener("click", (event) => {
  const verifyHost = event.currentTarget.dataset.verifyHost === "true";
  runFormSsh("terminal", {manual: !verifyHost, verifyHost});
});
for (const [tab, workspace] of workspaceTabs()) {
  tab.addEventListener("click", () => chooseWorkspace(workspace));
}
byId("files-device-search").addEventListener("input", renderFileDevices);
byId("files-device-add").addEventListener("click", () => openForm());
byId("files-device-demo-exit").addEventListener("click", () => toggleDemo(false));
byId("workspace-tabs").addEventListener("keydown", (event) => {
  if (event.target.getAttribute("role") !== "tab") return;
  const tabs = [...workspaceTabs(),
    ...[...terminalSessions.values()].map(({tab, id}) => [tab, id])];
  const index = tabs.findIndex(([tab]) => tab === event.target);
  if (index < 0) return;
  const [, workspace] = tabs[index];
  if (event.key === "Delete" && terminalSessions.has(workspace)) {
    event.preventDefault();
    closeTerminal(workspace);
    return;
  }
  let next = index;
  if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
  else if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = tabs.length - 1;
  else return;
  event.preventDefault();
  const [target, id] = tabs[next];
  chooseWorkspace(id);
  target.focus();
});
window.addEventListener("pagehide", (event) => {
  if (event.persisted || window.vpsOpsRequest) return;
  for (const session of terminalSessions.values()) {
    if (session.closed) continue;
    fetch("/api/terminal/close", {method: "POST", keepalive: true,
      headers: {"X-VPS-CSRF": csrf, "Content-Type": "application/json"}, body: JSON.stringify({id: session.id}),
    }).catch(() => {});
  }
});
byId("host-key-file").addEventListener("click", chooseIdentityFile);
byId("delete-confirm").addEventListener("click", deleteHost);
byId("cards").addEventListener("click", (event) => {
  const card = event.target.closest("[data-device-card]");
  if (!card || event.defaultPrevented ||
      event.target.closest('button, a, input, select, textarea, label, summary, [tabindex], .latency-chart-plot')) return;
  if (window.getSelection()?.isCollapsed === false) return;
  openDetail(card.dataset.deviceCard);
});
byId("detail-dialog").addEventListener("close", (event) => {
  const dialog = event.currentTarget;
  if (dialog.open) return;
  const id = focusedHostId;
  focusedHostId = null;
  updateSelectedCard();
  // Let the browser restore focus and allow any follow-up workspace or dialog to take focus first.
  requestAnimationFrame(() => {
    const active = document.activeElement;
    if ((active === document.body || dialog.contains(active)) && !document.querySelector("dialog[open]") &&
        byId("overview-tab").getAttribute("aria-selected") === "true") {
      const title = deviceCardTitle(id);
      if (title) title.focus({preventScroll: true});
      else byId("status-filter").focus();
    }
  });
});
byId("search").addEventListener("input", () => { if (state) renderCards(); });
for (const id of ["group-filter", "status-filter"]) {
  byId(id).addEventListener("change", () => { if (state) renderCards(); });
}
byId("metric-display").addEventListener("change", changeMetricDisplay);
for (const control of document.querySelectorAll("[data-close]")) {
  control.addEventListener("click", () => byId(control.dataset.close).close());
}

loadState();
setInterval(() => loadState(), 3000);

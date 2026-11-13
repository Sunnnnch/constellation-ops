"""Bundle the dashboard as a self-contained MCP Apps HTML resource."""

from base64 import b64encode

from dashboard import BRAND_ICON, BRAND_ICON_URL, STATIC


BRAND_ICON_DATA_URL = "data:image/png;base64," + b64encode(BRAND_ICON.read_bytes()).decode("ascii")

# MCP Apps UI protocol: https://developers.openai.com/plugins/build/app-quickstart
BRIDGE = r"""
(() => {
  "use strict";

  const host = window.parent;
  const pending = new Map();
  let targetOrigin = "*";
  let nextId = 0;
  let ready;
  let closed = false;
  let observer;
  let displayMode = "inline";
  let lastSize = "";

  function post(message) {
    host.postMessage({jsonrpc: "2.0", ...message}, targetOrigin);
  }

  function rpc(method, params, timeout = 12000) {
    return new Promise((resolve, reject) => {
      const id = ++nextId;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error("Codex 面板响应超时。"));
      }, timeout);
      pending.set(id, {resolve, reject, timer});
      try {
        post({id, method, params});
      } catch (error) {
        clearTimeout(timer);
        pending.delete(id);
        reject(error);
      }
    });
  }

  function applyContext(context) {
    if (context?.displayMode === "inline" || context?.displayMode === "fullscreen") {
      displayMode = context.displayMode;
    }
    document.documentElement.dataset.vpsDisplayMode = displayMode;
  }

  function reportSize() {
    if (closed || displayMode !== "inline") return;
    const bounds = document.body.getBoundingClientRect();
    const width = Math.ceil(bounds.width);
    const height = Math.ceil(bounds.height);
    const size = width + ":" + height;
    if (size !== lastSize) {
      lastSize = size;
      post({method: "ui/notifications/size-changed", params: {width, height}});
    }
  }

  function close() {
    closed = true;
    observer?.disconnect();
    window.removeEventListener("message", receive);
    for (const call of pending.values()) {
      clearTimeout(call.timer);
      call.reject(new Error("Codex 面板已关闭。"));
    }
    pending.clear();
  }

  function receive(event) {
    if (event.source !== host || (targetOrigin !== "*" && event.origin !== targetOrigin)) return;
    const message = event.data;
    if (message?.jsonrpc !== "2.0") return;
    if (message.method === "ui/resource-teardown" && message.id != null) {
      post({id: message.id, result: {}});
      close();
      return;
    }
    if (message.method === "ping" && message.id != null) {
      post({id: message.id, result: {}});
      return;
    }
    if (message.method === "ui/notifications/host-context-changed") {
      applyContext(message.params);
      reportSize();
      return;
    }
    if (message.method || !pending.has(message.id)) return;
    const call = pending.get(message.id);
    pending.delete(message.id);
    clearTimeout(call.timer);
    if (message.error) {
      call.reject(new Error(message.error.message || "Codex 面板请求失败。"));
    } else {
      call.resolve({result: message.result, origin: event.origin});
    }
  }

  window.addEventListener("message", receive);
  window.addEventListener("pagehide", close, {once: true});

  async function connect() {
    if (host === window) throw new Error("请从 Codex 打开此面板。");
    const {result, origin} = await rpc("ui/initialize", {
      appInfo: {name: "星图", version: "0.24.10"},
      appCapabilities: {availableDisplayModes: ["inline", "fullscreen"]},
      protocolVersion: "2026-01-26",
    });
    if (typeof result?.protocolVersion !== "string") throw new Error("Codex 面板初始化失败。");
    // An opaque sandbox origin requires '*'; receive() still checks the source window.
    if (/^https?:\/\//.test(origin)) targetOrigin = origin;
    applyContext(result.hostContext);
    post({method: "ui/notifications/initialized", params: {}});
    if ("ResizeObserver" in window) {
      observer = new ResizeObserver(reportSize);
      observer.observe(document.body);
    }
    reportSize();
  }

  function requestArgs(path, method, data) {
    if (method === "GET" && path === "/api/state") return {action: "state"};
    if (method === "POST" && path === "/api/metric-display") return {action: "metric_display", mode: data?.mode};
    if (method === "POST" && path === "/api/hosts") return {action: "add", host: data};
    if (method === "POST" && path === "/api/refresh") {
      return data?.id === undefined ? {action: "refresh"} : {action: "refresh", id: data.id};
    }
    if (method === "POST" && path === "/api/demo") return {action: "demo", enabled: data?.enabled};
    const match = /^\/api\/hosts\/([^/]+)$/.exec(path);
    if (match && method === "PUT") return {action: "update", id: decodeURIComponent(match[1]), host: data};
    if (match && method === "DELETE") return {action: "remove", id: decodeURIComponent(match[1])};
    throw new Error("不支持的面板操作。");
  }

  async function callTool(args) {
    if (closed) throw new Error("Codex 面板已关闭。");
    ready ??= connect().catch((error) => { ready = undefined; throw error; });
    await ready;
    if (closed) throw new Error("Codex 面板已关闭。");
    const timeout = args.action === "webdav" ? 80000 :
      args.action === "komari" || args.action === "terminal_open" || args.host?.password_box || args.host?.credential_id ? 25000 : 12000;
    const {result} = await rpc("tools/call", {name: "vps_ops_ui_request", arguments: args}, timeout);
    const state = result?.structuredContent;
    if (result?.isError) throw new Error(state?.error || "星图请求失败。");
    if (!state || typeof state !== "object") throw new Error("星图返回了无法读取的数据。");
    return state;
  }

  async function chooseKeyFile() {
    const {ticket} = await callTool({action: "key_file_start"});
    if (typeof ticket !== "string") throw new Error("无法打开系统文件选择器。");
    const deadline = Date.now() + 95000;
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      const result = await callTool({action: "key_file_poll", ticket});
      if (!result.pending) return result;
    }
    throw new Error("文件选择已超时，可以重试或手动填写私钥路径。");
  }

  window.vpsOpsRequest = async (path, method, data) => {
    if (method === "POST" && path === "/api/ssh/key-file") return chooseKeyFile();
    if (method === "POST" && path === "/api/ssh/test") return callTool({action: "ssh_test", host: data});
    if (method === "POST" && path === "/api/ssh/terminal") return callTool({action: "ssh_terminal", host: data});
    const terminal = /^\/api\/terminal\/(open|exchange|close)$/.exec(path);
    if (method === "POST" && terminal) return callTool({action: "terminal_" + terminal[1], payload: data});
    if (method === "POST" && path === "/api/probes") return callTool({action: "network_probes", payload: data});
    if (method === "POST" && path === "/api/outbound-probes") return callTool({action: "outbound_probes", payload: data});
    if (method === "POST" && path === "/api/files") return callTool({action: "files", payload: data});
    if (method === "POST" && ["/api/webdav", "/api/komari", "/api/tunnels"].includes(path)) {
      return callTool({action: path.slice(5), payload: data});
    }
    const history = /^\/api\/hosts\/([^/]+)\/history$/.exec(path);
    if (method === "GET" && history) return callTool({action: "history", id: decodeURIComponent(history[1])});
    const inventory = /^\/api\/inventory\/(export|preview|import)$/.exec(path);
    if (method === "POST" && inventory) {
      const action = "inventory_" + inventory[1];
      return callTool(inventory[1] === "export" ? {action} : {action, inventory: data?.inventory});
    }
    const state = await callTool(requestArgs(path, method, data));
    if (!Array.isArray(state.hosts)) throw new Error("星图返回了无法读取的数据。");
    return state;
  };

  // MCP App hosts can sandbox the iframe without allow-forms.
  const form = document.getElementById("host-form");
  const save = document.getElementById("host-save");
  function saveForm() {
    if (!save.disabled && form.reportValidity()) {
      form.dispatchEvent(new Event("submit", {cancelable: true}));
    }
  }
  save.type = "button";
  save.addEventListener("click", saveForm);
  form.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.isComposing && event.target instanceof HTMLInputElement) {
      event.preventDefault();
      saveForm();
    }
  });
})();
"""


def build_ui() -> str:
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    vendor_css = (STATIC / "vendor/xterm.css").read_text(encoding="utf-8")
    flags_css = (STATIC / "flags.css").read_text(encoding="utf-8")
    tunnels_css = (STATIC / "tunnels.css").read_text(encoding="utf-8")
    script_files = ("vendor/xterm.js", "vendor/xterm-fit.js", "latency-chart.js", "app.js",
                    "probes.js", "outbound-probes.js", "outbound-bulk.js", "files.js", "komari.js", "webdav.js",
                    "tunnels.js")
    javascript = [(STATIC / filename).read_text(encoding="utf-8") for filename in script_files]
    inline_layout = "html[data-vps-display-mode=inline] .layout {min-height: 0;}\n"
    if any("</script" in source.lower() for source in javascript) or any(
        "</style" in source.lower() for source in (css, vendor_css, flags_css, tunnels_css)
    ):
        raise ValueError("Dashboard assets contain an inline HTML closing tag.")
    scripts = "\n".join(f"<script>\n{source}\n</script>" for source in [*javascript[:2], BRIDGE, *javascript[2:]])
    for filename in script_files:
        html = html.replace(f'<script src="/{filename}" defer></script>', "")
    return (
        html.replace("__VPS_CSRF_TOKEN__", "")
        .replace(f'<link rel="icon" href="{BRAND_ICON_URL}" type="image/png">\n', "")
        .replace(f'src="{BRAND_ICON_URL}"', f'src="{BRAND_ICON_DATA_URL}"')
        .replace('<link rel="stylesheet" href="/vendor/xterm.css">', f"<style>\n{vendor_css}\n</style>")
        .replace('<link rel="stylesheet" href="/flags.css">', f"<style>\n{flags_css}\n</style>")
        .replace('<link rel="stylesheet" href="/tunnels.css">', f"<style>\n{tunnels_css}\n</style>")
        .replace('<link rel="stylesheet" href="/style.css">', f"<style>\n{css}\n{inline_layout}</style>")
        .replace("</body>", f"{scripts}\n</body>")
    )

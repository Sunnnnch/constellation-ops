(() => {
  "use strict";

  const dialog = document.getElementById("network-check-dialog");
  const panel = document.getElementById("network-check-local");
  const form = document.getElementById("network-probe-form");
  const rows = document.getElementById("network-probe-list");
  const status = document.getElementById("network-probe-status");
  const history = document.getElementById("network-probe-history");
  const save = document.getElementById("network-probe-save");
  const types = {tcp: "TCP", http: "HTTP / HTTPS", icmp: "ICMP Ping"};
  let host = null;
  let editing = null;
  let view = 0;
  let reading = null;
  let busy = false;
  let listRequest = 0;
  let lastList = "";

  function api(action, fields = {}) {
    return request("/api/probes", "POST", {action, host_id: host.id, ...fields});
  }

  function feedback(message, error = false) {
    status.textContent = message;
    status.dataset.kind = error ? "error" : "";
    status.hidden = !message;
  }

  function targetFields() {
    const type = form.elements.type.value;
    const tcp = type === "tcp";
    form.elements.port.required = tcp;
    form.elements.port.disabled = !tcp;
    form.elements.port.closest("label").hidden = !tcp;
    form.elements.target.placeholder = type === "http" ? "https://example.com/health" : "服务器地址或 IP";
  }

  function edit(probe = null) {
    editing = probe?.id ?? null;
    form.reset();
    form.elements.target.value = host.host.split("@").at(-1);
    form.elements.port.value = host.port || 22;
    if (probe) {
      for (const key of ["name", "type", "target", "port", "interval_seconds"]) form.elements[key].value = probe[key] ?? "";
      form.elements.enabled.checked = probe.enabled;
    }
    save.textContent = probe ? "保存修改" : "添加探针";
    document.getElementById("network-probe-reset").hidden = !probe;
    targetFields();
  }

  function pointLabel(point) {
    const time = formattedDate(point.checked_at, clockFormat);
    const elapsed = number(point.latency_ms);
    return `${time} · ${point.message}${elapsed == null || point.message.endsWith(" ms") ? "" : ` · ${numberFormat.format(elapsed)} ms`}`;
  }

  function render(probes) {
    if (!probes.length) {
      rows.replaceChildren(element("p", "field-hint", "还没有网络探针。"));
      return;
    }
    rows.replaceChildren(...probes.map((probe) => {
      const row = element("article", "network-probe-card");
      const title = element("strong", "", probe.name);
      const hostname = probe.target.includes(":") ? `[${probe.target}]` : probe.target;
      const target = probe.type === "tcp" ? `${hostname}:${probe.port}` : probe.target;
      const meta = element("p", "field-hint", `${types[probe.type]} · ${target} · ${probe.enabled ? `每 ${probe.interval_seconds} 秒` : "仅手动"}`);
      const summary = probe.running ? "正在检测…" : probe.latest ? pointLabel(probe.latest) : "尚未检测";
      const result = element("p", probe.latest && !probe.latest.ok ? "network-probe-failure" : "", summary);
      const controls = element("div", "inventory-actions");
      const run = button("立即检测", "text-button", () => perform(async () => {
        const current = view;
        const result = await api("run", {id: probe.id});
        if (!result.queued && current === view && dialog.open) feedback("探针正在检测或检测队列暂满，请稍后重试。");
      }));
      run.disabled = probe.running;
      controls.append(run, button("记录", "text-button", () => showHistory(probe)),
        button("编辑", "text-button", () => edit(probe)), button("删除", "text-button danger-text", () => {
          const confirm = document.getElementById("network-probe-delete");
          confirm.hidden = false;
          document.getElementById("network-probe-delete-name").textContent = `删除「${probe.name}」及其记录？`;
          document.getElementById("network-probe-delete-confirm").onclick = () => perform(async () => {
            const current = view;
            await api("delete", {id: probe.id});
            if (current !== view || !dialog.open) return;
            confirm.hidden = true;
            if (editing === probe.id) edit();
            if (reading === probe.id) { reading = null; history.hidden = true; }
          });
        }));
      row.append(title, meta, result, controls);
      return row;
    }));
  }

  async function load() {
    if (!dialog.open || !host) return;
    const current = view;
    const requestId = ++listRequest;
    const result = await api("list");
    if (current !== view || requestId !== listRequest || !dialog.open) return;
    const snapshot = JSON.stringify(result.probes);
    if (snapshot === lastList) return;
    lastList = snapshot;
    render(result.probes);
  }

  async function showHistory(probe) {
    const current = view;
    reading = probe.id;
    history.hidden = false;
    history.replaceChildren(element("p", "field-hint", "正在读取检测记录…"));
    try {
      const result = await api("history", {id: probe.id});
      if (current !== view || !dialog.open || reading !== probe.id) return;
      const list = element("ol", "network-probe-history-list");
      for (const point of result.points.slice().reverse()) list.append(element("li", "", pointLabel(point)));
      history.replaceChildren(element("h3", "", `${probe.name} · 检测记录`), list.childElementCount ? list : element("p", "field-hint", "还没有检测记录。"));
    } catch (error) {
      if (current === view && reading === probe.id) feedback(error.message, true);
    }
  }

  async function perform(action) {
    if (busy || !dialog.open) return;
    const current = view;
    busy = true;
    save.disabled = true;
    feedback("");
    try {
      await action();
      if (view === current) await load();
    } catch (error) {
      if (view === current) feedback(error.message, true);
    } finally {
      if (view === current) { busy = false; save.disabled = false; }
    }
  }

  form.elements.type.addEventListener("change", targetFields);
  save.addEventListener("click", () => {
    if (!form.reportValidity()) return;
    const config = {
      name: form.elements.name.value.trim(), type: form.elements.type.value, target: form.elements.target.value.trim(),
      interval_seconds: Number(form.elements.interval_seconds.value), enabled: form.elements.enabled.checked,
    };
    if (config.type === "tcp") config.port = Number(form.elements.port.value);
    perform(async () => {
      const current = view;
      const probeId = editing;
      await api("save", probeId ? {id: probeId, config} : {config});
      if (view !== current || !dialog.open) return;
      if (reading && reading === probeId) { reading = null; history.hidden = true; }
      edit();
      feedback("探针已保存。");
    });
  });
  form.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.isComposing && event.target instanceof HTMLInputElement) {
      event.preventDefault();
      save.click();
    }
  });
  form.addEventListener("submit", (event) => event.preventDefault());
  document.getElementById("network-probe-reset").addEventListener("click", () => edit());
  document.getElementById("network-probe-delete-cancel").addEventListener("click", () => {
    document.getElementById("network-probe-delete").hidden = true;
  });
  dialog.addEventListener("close", () => {
    if (dialog.open) return;
    view += 1;
    host = null;
  });
  window.vpsOpenNetworkProbes = (device) => {
    host = device;
    view += 1;
    busy = false;
    save.disabled = false;
    reading = null;
    lastList = "";
    rows.replaceChildren();
    history.hidden = true;
    document.getElementById("network-probe-delete").hidden = true;
    feedback("");
    edit();
    const current = view;
    load().catch((error) => { if (dialog.open && current === view) feedback(error.message, true); });
  };
  window.setInterval(() => {
    if (dialog.open && !panel.hidden && !busy) load().catch(() => {});
  }, 3000);
})();

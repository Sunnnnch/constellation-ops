(() => {
  "use strict";

  const providerNames = {komari: "Komari", beszel: "Beszel"};
  const providerOf = (record) => record?.provider === "beszel" ? "beszel" : "komari";

  function openDialog(title, description) {
    const dialog = element("dialog", "dialog detail-dialog komari-dialog");
    const header = element("header", "dialog-header");
    const heading = element("div");
    const label = element("h2", "", title);
    label.id = "komari-dialog-title";
    heading.append(label);
    if (description) heading.append(element("p", "", description));
    const close = button("×", "icon-button", () => dialog.close());
    close.setAttribute("aria-label", "关闭");
    header.append(heading, close);
    const body = element("div", "dialog-body form-fields");
    const footer = element("footer", "dialog-actions");
    dialog.setAttribute("aria-labelledby", label.id);
    dialog.append(header, body, footer);
    dialog.addEventListener("close", () => dialog.remove(), {once: true});
    document.body.append(dialog);
    return {dialog, body, footer};
  }

  function field(label, input) {
    const wrapper = element("label", "", label);
    wrapper.append(input);
    return wrapper;
  }

  function feedback(target, message, kind = "") {
    target.hidden = !message;
    target.dataset.kind = kind;
    target.textContent = message;
  }

  function rpc(provider, action, values = {}) {
    return request("/api/komari", "POST", {action, provider, ...values});
  }

  function metricPair(label, content) {
    const metric = element("div");
    metric.append(element("dt", "", label), element("dd", "", content));
    return metric;
  }

  function liveValue(used, total, reportedPercent) {
    const fraction = ratio(used, total);
    if (fraction !== null) return percentage(fraction) + " · " + usage(used, total);
    return number(reportedPercent) === null ? bytes(used) : percentage(reportedPercent);
  }

  window.vpsMonitoringSummary = window.vpsKomariSummary = (record) => {
    if (!record) return null;
    const section = element("section", "latency-chart komari-summary");
    const header = element("div", "latency-chart-head");
    const source = element("strong", "latency-chart-caption", providerNames[providerOf(record)]);
    source.title = record.name;
    const status = record.stale ? "连接失败" : record.online === true ? "在线" :
      record.online === false ? "离线" : "等待上报";
    header.append(source, element("span", "", status));
    section.append(header);
    const values = element("dl", "komari-readings");
    values.append(metricPair("CPU", percentage(record.cpu_pct)),
      metricPair("内存", liveValue(record.memory_used, record.memory_total, record.memory_pct)),
      metricPair("磁盘", liveValue(record.disk_used, record.disk_total, record.disk_pct)));
    if (providerOf(record) === "komari" || number(record.rx_bps) !== null || number(record.tx_bps) !== null) {
      values.append(metricPair("网络", "↓ " + rate(record.rx_bps) + " · ↑ " + rate(record.tx_bps)));
    }
    section.append(values);
    if (record.checked_at) section.append(element("p", "field-hint", "上次上报 " + formattedDate(record.checked_at, clockFormat)));
    return section;
  };

  window.vpsOpenMonitoring = window.vpsOpenKomari = async (hostId = "") => {
    if (document.getElementById("komari-dialog-title")) return;
    const host = state?.hosts?.find((entry) => entry.id === hostId);
    const binding = host ? state.komari?.[host.id] : null;
    const {dialog, body, footer} = openDialog(host ? "绑定监控节点" : "监控集成", host?.name);
    const provider = element("select");
    for (const [id, label] of Object.entries(providerNames)) provider.append(new Option(label, id));
    provider.value = providerOf(binding);
    const endpoint = element("input");
    endpoint.type = "url";
    endpoint.required = true;
    endpoint.maxLength = 400;
    endpoint.placeholder = "https://monitor.example.com";
    endpoint.spellcheck = false;
    const identity = element("input");
    identity.type = "text";
    identity.maxLength = 320;
    identity.autocomplete = "off";
    identity.spellcheck = false;
    const token = element("input");
    token.type = "password";
    token.maxLength = 512;
    token.autocomplete = "off";
    const forget = element("input");
    forget.type = "checkbox";
    const forgetLabel = element("label", "password-option");
    const forgetText = document.createTextNode("");
    forgetLabel.append(forget, forgetText);
    const target = element("select");
    target.autocomplete = "off";
    const targetField = field("监控节点", target);
    const configuration = element("div", "form-fields");
    const endpointField = field("Komari 地址", endpoint);
    const identityField = field("Beszel 账号（邮箱）", identity);
    const tokenField = field("Bearer API 令牌（可选）", token);
    const credentialHelp = element("p", "field-hint");
    const bindingHelp = element("p", "field-hint");
    bindingHelp.hidden = true;
    configuration.append(endpointField, identityField, tokenField, credentialHelp, forgetLabel);
    const status = element("p", "connection-result");
    status.setAttribute("role", "status");
    body.append(field("监控来源", provider), configuration, targetField, bindingHelp, status);

    let config = null;
    let nodes = null;
    let busy = false;
    function labels() {
      const beszel = provider.value === "beszel";
      endpointField.firstChild.nodeValue = providerNames[provider.value] + " 地址";
      endpoint.placeholder = beszel ? "https://beszel.example.com" : "https://monitor.example.com";
      identityField.hidden = !beszel;
      tokenField.firstChild.nodeValue = beszel ? "Beszel 密码" : "Bearer API 令牌（可选）";
      forgetText.nodeValue = beszel ? "移除已保存的 Beszel 登录信息" : "移除已保存令牌";
      credentialHelp.textContent = beszel
        ? "使用能查看目标设备的普通账号。保存后凭据保存在本机。"
        : "公开节点可留空。Komari 的管理员令牌应妥善保管，保存后只留在本机。";
    }
    function isSavedEndpoint() {
      return !!config?.endpoint && endpoint.value === config.endpoint;
    }
    function update() {
      const ready = config !== null && !busy;
      provider.disabled = busy;
      endpoint.disabled = forget.disabled = !ready;
      identity.disabled = token.disabled = !ready || forget.checked;
      forgetLabel.hidden = !config?.token_saved || !isSavedEndpoint();
      const useSaved = config?.token_saved && isSavedEndpoint() && !forget.checked;
      token.placeholder = useSaved ? provider.value === "beszel" ? "留空保留现有密码" : "留空保留现有令牌" : "";
      identity.placeholder = useSaved ? "留空保留现有账号" : "";
      targetField.hidden = !host || nodes === null;
      target.disabled = !ready;
      const currentBinding = host && state?.komari?.[host.id];
      bindingHelp.hidden = targetField.hidden || !target.value || !currentBinding ||
        providerOf(currentBinding) === provider.value;
      if (!bindingHelp.hidden) {
        bindingHelp.textContent = "保存绑定后，设备会改用 " + providerNames[provider.value] + " 监控。";
      }
      test.disabled = save.disabled = !ready;
      bind.disabled = !ready || nodes === null || !isSavedEndpoint() || identity.value !== "" || token.value !== "" || forget.checked ||
        target.value === (config?.bindings?.[host?.id]?.uuid ?? "");
    }
    function loadNodes(list) {
      nodes = list;
      target.replaceChildren();
      target.append(new Option("解除绑定 / 未绑定", ""));
      const selected = config?.bindings?.[host?.id];
      if (selected && !list.some((node) => node.uuid === selected.uuid)) {
        target.append(new Option(selected.name + "（当前不可见）", selected.uuid));
      }
      for (const node of list) {
        const name = [node.group, node.name].filter(Boolean).join(" · ");
        target.append(new Option(name + " · " + node.uuid.slice(0, 8), node.uuid));
      }
      if (selected) target.value = selected.uuid;
    }
    async function handle(action) {
      if (!config || busy) return;
      if (action !== "bind" && !endpoint.reportValidity()) return;
      const selectedProvider = provider.value;
      const beszel = selectedProvider === "beszel";
      const source = providerNames[selectedProvider];
      if (action !== "bind" && beszel && !forget.checked && Boolean(identity.value.trim()) !== Boolean(token.value)) {
        feedback(status, "请同时填写 Beszel 账号和密码。", "error");
        (identity.value.trim() ? token : identity).focus();
        return;
      }
      busy = true;
      update();
      feedback(status, action === "bind" ? "正在保存绑定…" : "正在读取 " + source + " 节点…");
      try {
        let result;
        if (action === "bind") {
          result = await rpc(selectedProvider, action, {host_id: host.id, node_uuid: target.value || null});
        } else {
          const values = {endpoint: endpoint.value};
          if (forget.checked) values.forget_token = true;
          else if (token.value) {
            const secret = beszel ? JSON.stringify({identity: identity.value.trim(), password: token.value}) : token.value;
            values.token_box = await sealPassword(secret, {
              host: endpoint.value, username: "", port: null, auth_mode: selectedProvider, known_hosts: "",
            }, selectedProvider);
          }
          if (!dialog.open) return;
          result = await rpc(selectedProvider, action, values);
        }
        if (!dialog.open) return;
        if (action === "save") {
          config = result;
          endpoint.value = result.endpoint;
          identity.value = "";
          token.value = "";
          forget.checked = false;
          loadNodes(result.nodes);
          feedback(status, source + " 设置已保存，可见节点 " + result.nodes.length + " 个。", "success");
          await loadState(true);
        } else if (action === "test") {
          loadNodes(result.nodes);
          const visible = "已连接，可见节点 " + result.nodes.length + " 个。";
          feedback(status, host && (!isSavedEndpoint() || identity.value || token.value || forget.checked)
            ? visible + " 保存连接后即可绑定。" : visible, "success");
        } else {
          config = result;
          const bound = config.bindings[host.id];
          loadNodes(nodes);
          feedback(status, bound ? "已绑定到 " + source + " 的 " + bound.name + "。" : "已解除绑定。", "success");
          await loadState(true);
        }
      } catch (error) {
        if (dialog.open) feedback(status, error.message, "error");
      } finally {
        busy = false;
        if (dialog.open) update();
      }
    }

    const test = button("测试连接", "button secondary", () => handle("test"));
    const save = button("保存连接", host ? "button secondary" : "button primary", () => handle("save"));
    const bind = button("保存绑定", "button primary", () => handle("bind"));
    footer.append(test, save);
    if (host) footer.append(bind);
    target.addEventListener("change", update);
    for (const control of [endpoint, identity, token, forget]) control.addEventListener("input", () => {
      if (control === endpoint && !isSavedEndpoint()) forget.checked = false;
      nodes = null;
      feedback(status, "");
      update();
    });
    async function loadProvider() {
      const selectedProvider = provider.value;
      config = nodes = null;
      endpoint.value = identity.value = token.value = "";
      forget.checked = false;
      labels();
      busy = true;
      update();
      feedback(status, "正在读取本机设置…");
      try {
        const result = await rpc(selectedProvider, "state");
        if (!dialog.open) return;
        config = result;
        endpoint.value = config.endpoint;
        feedback(status, "");
      } catch (error) {
        if (dialog.open) feedback(status, error.message, "error");
      } finally {
        busy = false;
        if (dialog.open) update();
      }
      if (dialog.open && host && config?.endpoint) await handle("test");
    }
    dialog.addEventListener("close", () => { identity.value = token.value = ""; });
    provider.addEventListener("change", loadProvider);
    dialog.showModal();
    await loadProvider();
  };

  function appendLoad(body, rows, source) {
    body.append(element("h3", "komari-history-title", "资源历史 · 最近 24 小时"));
    const now = Date.now();
    const points = rows.map((row) => ({
      time: Date.parse(row.time), status: "online", cpu: row.cpu_pct,
      memory: ratio(row.memory_used, row.memory_total) ?? number(row.memory_pct),
      disk: ratio(row.disk_used, row.disk_total) ?? number(row.disk_pct),
    })).filter((point) => point.time >= now - dayMs && point.time <= now).sort((a, b) => a.time - b.time);
    if (!points.length) {
      body.append(element("p", "field-hint", source + " 暂无资源历史。"));
      return;
    }
    const intervals = points.slice(1).map((point, index) => point.time - points[index].time).sort((a, b) => a - b);
    const gap = Math.max(180000, 2.5 * (intervals[Math.floor(intervals.length / 2)] || 0));
    for (const [key, title, color] of [["cpu", "CPU", "#1558ce"], ["memory", "内存", "#087d58"], ["disk", "磁盘", "#7447ba"]]) {
      body.append(historyPlot(points, {key, title, color, unit: "%", scale: 100}, now, gap));
    }
  }

  function appendPing(body, series) {
    body.append(element("h3", "komari-history-title", "Ping 任务历史 · 最近 1 小时"));
    if (!series.length) {
      body.append(element("p", "field-hint", "Komari 暂无 Ping 任务采样。"));
      return;
    }
    const chart = window.vpsPingChart(series, {scheduled: true});
    chart.querySelector("strong").textContent = "Komari Ping";
    const plot = chart.querySelector("[aria-label*='VPS 出网 Ping']");
    if (plot) plot.setAttribute("aria-label", plot.getAttribute("aria-label").replace("VPS 出网 Ping", "Komari Ping"));
    body.append(chart);
  }

  window.vpsOpenMonitoringHistory = window.vpsOpenKomariHistory = async (hostId) => {
    if (document.getElementById("komari-dialog-title")) return;
    const host = state?.hosts?.find((entry) => entry.id === hostId);
    if (!host) return;
    const provider = providerOf(state.komari?.[hostId]);
    const source = providerNames[provider];
    const {dialog, body, footer} = openDialog(source + " 监控历史", host.name);
    const status = element("p", "connection-result", "正在读取 " + source + " 历史…");
    status.setAttribute("role", "status");
    body.append(status);
    footer.append(button("更改节点绑定", "button secondary", () => {
      dialog.close();
      dialog.remove();
      window.vpsOpenMonitoring(hostId);
    }));
    dialog.showModal();
    try {
      const result = await rpc(provider, "history", {host_id: hostId});
      if (!dialog.open) return;
      const errors = Object.values(result.errors);
      feedback(status, errors.join(" "), errors.length ? "error" : "");
      if (!result.errors.load) appendLoad(body, result.load, source);
      if (provider === "komari" && !result.errors.ping) appendPing(body, result.ping);
    } catch (error) {
      if (dialog.open) feedback(status, error.message, "error");
    }
  };
})();

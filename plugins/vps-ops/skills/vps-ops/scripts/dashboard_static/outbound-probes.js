(() => {
  "use strict";

  const dialog = byId("network-check-dialog");
  const passwordField = byId("outbound-probe-password-field");
  const password = byId("outbound-probe-password");
  const status = byId("outbound-probe-status");
  const run = byId("outbound-probe-run");
  const retest = byId("outbound-probe-retest");
  const regionOptions = byId("outbound-probe-regions");
  const selectionNote = byId("outbound-selection-note");
  const saveSelection = byId("outbound-selection-save");
  const scheduleEnabled = byId("outbound-schedule-enabled");
  const scheduleInterval = byId("outbound-schedule-interval");
  const schedulePackets = byId("outbound-schedule-packets");
  const scheduleRecommend = byId("outbound-schedule-recommend");
  const scheduleSave = byId("outbound-schedule-save");
  const scheduleStatus = byId("outbound-schedule-status");
  const scheduleError = byId("outbound-schedule-error");
  const historyDialog = byId("outbound-history-dialog");
  const historySource = byId("outbound-history-source");
  const historyRefresh = byId("outbound-history-refresh");
  const historyStatus = byId("outbound-history-status");
  const historyResults = byId("outbound-history-results");
  const manageRegion = byId("outbound-region-manage");
  const regionAdd = byId("outbound-region-add");
  const regionEdit = byId("outbound-region-edit");
  const regionDelete = byId("outbound-region-delete");
  const editor = byId("outbound-region-editor");
  const regionName = byId("outbound-region-name");
  const targets = byId("outbound-region-targets");
  const addTarget = byId("outbound-region-add-target");
  const saveRegion = byId("outbound-region-save");
  const cancelRegion = byId("outbound-region-cancel");
  const confirmation = byId("outbound-region-confirmation");
  const confirmDelete = byId("outbound-region-confirm-delete");
  const keepRegion = byId("outbound-region-keep");
  const statusNames = {success: "全部收到", partial: "部分收到", no_reply: "无应答", unavailable: "无法检测"};
  const maxRegions = 8;
  const maxTargets = 6;
  let view = null;

  function scheduleDraft() {
    return {enabled: scheduleEnabled.checked, interval_seconds: scheduleInterval.valueAsNumber,
      packets: schedulePackets.valueAsNumber};
  }

  function scheduleChanged() {
    const saved = view.data?.schedule;
    const draft = scheduleDraft();
    return Boolean(saved && (draft.enabled !== saved.enabled || draft.interval_seconds !== saved.interval_seconds ||
      draft.packets !== saved.packets));
  }

  function updateScheduleDraft() {
    view.scheduleRequestError = false;
    renderSchedule(view.data?.schedule, false);
    updateControls();
  }

  function scheduleFeedback(message, kind = "") {
    if (scheduleError.textContent !== message) scheduleError.textContent = message;
    scheduleError.dataset.kind = kind;
    scheduleError.hidden = !message;
  }

  function renderSchedule(schedule, resetInputs) {
    if (!schedule) return;
    if (resetInputs) {
      scheduleEnabled.checked = schedule.enabled;
      scheduleInterval.value = schedule.interval_seconds;
      schedulePackets.value = schedule.packets;
    }
    const parts = [schedule.enabled ? "已开启 · 每 " + schedule.interval_seconds + " 秒，每目标 " +
      schedule.packets + " 包" : "定时测速未开启"];
    if (schedule.last_at) parts.push("上次 " + formattedDate(schedule.last_at));
    if (schedule.enabled && schedule.next_at) parts.push("下次 " + formattedDate(schedule.next_at));
    const summary = parts.join(" · ");
    if (scheduleStatus.textContent !== summary) scheduleStatus.textContent = summary;
    scheduleStatus.hidden = false;
    if (schedule.error) scheduleFeedback(schedule.error, "error");
    else if (view.data.password_required && !schedule.enabled) {
      scheduleFeedback("此设备需要先在设备设置中保存 SSH 密码，或配置 SSH 密钥。");
    } else if (resetInputs || scheduleError.dataset.kind === "error" && !view.scheduleRequestError) {
      scheduleFeedback("");
    }
  }

  function feedback(message, kind = "") {
    status.textContent = message;
    status.dataset.kind = kind;
    status.hidden = !message;
  }

  function managedRegion() {
    return view.data?.regions.find((region) => region.id === manageRegion.value);
  }

  function updateControls() {
    const running = view.data?.batch_running && !view.retryState;
    const editing = !editor.hidden || !confirmation.hidden;
    const blocked = Boolean(view.busy || editing || running);
    const scheduleBusy = Boolean(!view.data?.schedule || editing || (view.busy && view.busy !== "state"));
    const needsSavedPassword = view.data?.password_required && !view.data?.schedule?.enabled;
    scheduleEnabled.disabled = scheduleBusy || Boolean(needsSavedPassword);
    scheduleInterval.disabled = schedulePackets.disabled = scheduleBusy;
    scheduleRecommend.disabled = scheduleBusy;
    scheduleSave.disabled = scheduleBusy || !scheduleChanged() || Boolean(scheduleEnabled.checked && needsSavedPassword);
    const saved = view.data?.selected_region_ids ?? [];
    const selected = view.selected ?? [];
    const changed = saved.length !== selected.length || !saved.every((id) => selected.includes(id));
    for (const checkbox of regionOptions.querySelectorAll("input")) {
      checkbox.checked = selected.includes(checkbox.value);
      checkbox.disabled = Boolean(editing || running || view.busy && view.busy !== "state" ||
        !checkbox.checked && selected.length >= maxRegions);
    }
    const note = view.data ? "已选 " + selected.length + " 个地区，最多 " + maxRegions + " 个" +
      (changed ? "。更改尚未保存。" : "。") : "";
    if (selectionNote.textContent !== note) selectionNote.textContent = note;
    saveSelection.disabled = blocked || !view.data || !selected.length || !changed;
    regionAdd.disabled = blocked || !view.data;
    manageRegion.disabled = regionEdit.disabled = regionDelete.disabled = blocked;
    run.disabled = blocked || (!selected.length && !view.retryState);
    run.textContent = view.retryState ? "重新读取状态" : running ? "正在检测…" : "开始检测";
    retest.disabled = blocked || !selected.length || view.retryState;
    passwordField.hidden = !view.data?.password_required || editing;
    password.disabled = view.busy || Boolean(running);
    saveRegion.disabled = cancelRegion.disabled = confirmDelete.disabled = keepRegion.disabled = view.busy;
    addTarget.disabled = view.busy || targets.childElementCount >= maxTargets;
    for (const remove of targets.querySelectorAll("button")) {
      remove.disabled = view.busy || targets.childElementCount <= 1;
    }
  }

  function renderRegions(regions, preferred) {
    const signature = JSON.stringify(regions.map(({id, name}) => [id, name]));
    if (view.regionSignature !== signature) {
      view.regionSignature = signature;
      regionOptions.replaceChildren(...regions.map((region) => {
        const label = element("label", "");
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.value = region.id;
        label.append(checkbox, element("span", "", region.name));
        return label;
      }));
      const previous = manageRegion.value;
      const custom = regions.filter((region) => region.custom);
      manageRegion.replaceChildren(...custom.map((region) => {
        const option = element("option", "", region.name);
        option.value = region.id;
        return option;
      }));
      byId("outbound-region-custom").hidden = !custom.length;
      if (custom.some((region) => region.id === previous)) manageRegion.value = previous;
    }
    if ([...manageRegion.options].some((option) => option.value === preferred)) manageRegion.value = preferred;
  }

  function resultCard(region, result) {
    const card = element("section", "outbound-result-card");
    const heading = element("div", "outbound-result-heading");
    const title = element("h3", "", region.name);
    title.id = "outbound-result-" + region.id;
    const checked = result?.running ? "检测中…" :
      result?.checked_at ? "上次检测 " + formattedDate(result.checked_at) : "尚未检测";
    const history = button("测速历史", "text-button outbound-history-open", () => openHistory(region));
    history.setAttribute("aria-label", region.name + "测速历史");
    heading.append(title, element("p", "field-hint", checked), history);
    card.append(heading);
    if (result?.error) {
      const error = element("p", "connection-result outbound-result-error", result.error);
      error.dataset.kind = "error";
      card.append(error);
    }
    card.append(resultsTable(result?.rows ?? region.targets, title.id));
    return card;
  }

  function resultsTable(rows, titleId) {
    const wrap = element("div", "outbound-probe-table-wrap");
    wrap.tabIndex = 0;
    wrap.setAttribute("role", "region");
    wrap.setAttribute("aria-labelledby", titleId);
    const table = element("table", "outbound-probe-table");
    const columnHeaders = document.createElement("tr");
    for (const label of ["测速目标", "平均延迟", "丢包率", "收包 / 发包"]) {
      const header = element("th", "", label);
      header.scope = "col";
      columnHeaders.append(header);
    }
    const head = document.createElement("thead");
    head.append(columnHeaders);
    const body = document.createElement("tbody");
    for (const row of rows) {
      const line = element("tr");
      const carrier = element("th", "", row.carrier);
      carrier.scope = "row";
      carrier.append(element("small", "", row.target));
      const latency = number(row.latency_ms) == null ? "—" : numberFormat.format(row.latency_ms) + " ms";
      const packets = number(row.received) == null || number(row.sent) == null ? "—" : row.received + " / " + row.sent;
      const outcome = element("td", "outbound-probe-outcome", packets);
      outcome.dataset.status = row.status ?? "";
      if (row.status) outcome.append(element("small", "outbound-probe-result-note", row.message ?? statusNames[row.status]));
      line.append(carrier, element("td", "", latency), element("td", "", percentage(row.loss_percent)), outcome);
      body.append(line);
    }
    table.append(head, body);
    wrap.append(table);
    return wrap;
  }

  function renderHistory(entry) {
    const points = entry.points.filter((point) => historySource.value === "all" || point.source === historySource.value);
    const expanded = new Set([...historyResults.querySelectorAll("details[open]")].map((detail) => detail.dataset.round));
    historyResults.replaceChildren();
    if (!points.length) {
      historyResults.append(element("p", "field-hint", "这个地区还没有符合条件的测速记录。"));
      return;
    }
    const totals = new Map(entry.region.targets.map((target) => [target.target,
      {...target, sent: 0, received: 0, rtt: 0, timedReplies: 0}]));
    for (const point of points) {
      for (const row of point.rows ?? []) {
        const total = totals.get(row.target);
        const sent = number(row.sent);
        const received = number(row.received);
        if (!total || sent == null || received == null || sent <= 0 || received < 0 || received > sent) continue;
        total.sent += sent;
        total.received += received;
        if (received && number(row.latency_ms) != null) {
          total.rtt += row.latency_ms * received;
          total.timedReplies += received;
        }
      }
    }
    const aggregate = [...totals.values()].map((row) => ({
      ...row, sent: row.sent || null, received: row.sent ? row.received : null,
      latency_ms: row.timedReplies ? row.rtt / row.timedReplies : null,
      loss_percent: row.sent ? 100 * (row.sent - row.received) / row.sent : null,
    }));
    const summary = element("h3", "", "最近 " + points.length + " 轮汇总");
    summary.id = "outbound-history-summary";
    historyResults.append(summary, resultsTable(aggregate, summary.id));
    const latest = points.slice(-20).reverse();
    historyResults.append(element("h3", "", "最近 " + latest.length + " 轮明细"));
    const details = element("div", "outbound-history-details");
    latest.forEach((point, index) => {
      const round = element("details", "outbound-history-round");
      round.dataset.round = point.checked_at + ":" + (point.source ?? "manual");
      round.open = expanded.has(round.dataset.round);
      const name = element("summary", "", formattedDate(point.checked_at) +
        (point.source === "scheduled" ? " · 定时" : " · 手动") + (point.error ? " · 未完成" : ""));
      name.id = "outbound-history-round-" + index;
      round.append(name);
      if (point.error) round.append(element("p", "", point.error));
      if (point.rows?.length) round.append(resultsTable(point.rows, name.id));
      details.append(round);
    });
    historyResults.append(details);
  }

  async function loadHistory(entry, silent = false) {
    const current = view;
    if (!entry || current?.history !== entry || !historyDialog.open || entry.loading) return;
    entry.loading = true;
    historyRefresh.disabled = true;
    if (!silent) {
      historyStatus.textContent = "正在读取测速历史…";
      historyStatus.dataset.kind = "";
      historyStatus.hidden = false;
    }
    try {
      const data = await request("/api/outbound-probes", "POST", {
        action: "history", host_id: current.host.id, region_id: entry.region.id,
      });
      if (view !== current || current.history !== entry || !historyDialog.open) return;
      entry.points = data.points;
      entry.checkedAt = data.points.at(-1)?.checked_at;
      historyStatus.hidden = true;
      renderHistory(entry);
    } catch (error) {
      if (view === current && current.history === entry && historyDialog.open) {
        historyStatus.textContent = error.message;
        historyStatus.dataset.kind = "error";
        historyStatus.hidden = false;
      }
    } finally {
      entry.loading = false;
      if (view === current && current.history === entry && historyDialog.open) historyRefresh.disabled = false;
    }
  }

  function openHistory(region) {
    if (historyDialog.open) return;
    view.history = {region, points: []};
    byId("outbound-history-host").textContent = view.host.name + " · " + region.name;
    historySource.value = "all";
    historyResults.replaceChildren();
    historyDialog.showModal();
    loadHistory(view.history);
  }

  function renderResults() {
    const results = byId("outbound-probe-results");
    const selected = (view.selected ?? []).map((id) => view.data?.regions.find((region) => region.id === id)).filter(Boolean);
    results.hidden = !selected.length;
    const cards = selected.map((region) => [region, view.results.get(region.id)]);
    const signature = JSON.stringify(cards);
    if (signature === view.resultSignature) return;
    view.resultSignature = signature;
    results.replaceChildren(...cards.map(([region, result]) => resultCard(region, result)));
  }

  function targetField(label, name, value, length, placeholder) {
    const wrapper = element("label", "", label);
    const input = document.createElement("input");
    input.name = name;
    input.value = value;
    input.maxLength = length;
    input.placeholder = placeholder;
    input.required = true;
    input.spellcheck = false;
    wrapper.append(input);
    return wrapper;
  }

  function appendTarget({carrier = "", target = ""} = {}) {
    const row = element("div", "outbound-region-target");
    const remove = button("移除", "text-button", () => {
      row.remove();
      updateControls();
      addTarget.focus();
    });
    row.append(targetField("目标名称", "carrier", carrier, 60, "例如 电信"),
      targetField("IP 地址", "target", target, 45, "例如 1.1.1.1"), remove);
    targets.append(row);
    return row.querySelector("input");
  }

  function openEditor(region) {
    view.editing = region?.id ?? null;
    byId("outbound-region-editor-title").textContent = region ? "编辑地区" : "添加地区";
    regionName.value = region?.name ?? "";
    targets.replaceChildren();
    for (const target of region?.targets ?? [{}]) appendTarget(target);
    editor.hidden = false;
    feedback("");
    updateControls();
    regionName.focus();
  }

  function closeEditor() {
    editor.hidden = true;
    confirmation.hidden = true;
    view.editing = null;
    updateControls();
    if (!regionAdd.disabled) regionAdd.focus();
  }

  function regionDraft() {
    const inputs = [regionName, ...targets.querySelectorAll("input")];
    if (inputs.some((input) => !input.reportValidity())) return null;
    const result = {name: regionName.value.trim(), targets: []};
    for (const row of targets.children) {
      const carrier = row.querySelector('[name="carrier"]').value.trim();
      const target = row.querySelector('[name="target"]').value.trim();
      result.targets.push({carrier, target});
    }
    if (view.editing) result.region_id = view.editing;
    return result;
  }

  async function perform(action, fields = {}) {
    const current = view;
    if (!current || current.busy || !dialog.open) return;
    const payload = {action, host_id: current.host.id, ...fields};
    if ((action === "state" || action === "run_batch" || action === "selection_save") && current.selected?.length) {
      payload.region_ids = current.selected.slice();
    }
    const needsPassword = action === "run_batch" && current.data?.password_required;
    if (needsPassword && !password.value) {
      feedback("请输入这台设备的 SSH 密码。", "error");
      password.focus();
      return;
    }
    clearTimeout(current.timer);
    current.busy = action;
    current.retryState = false;
    if (action === "schedule_save") {
      current.scheduleRequestError = false;
      scheduleFeedback("");
    }
    updateControls();
    let sent = false;
    let focusRegion = false;
    try {
      if (needsPassword) {
        const entered = password.value;
        password.value = "";
        payload.password_box = await sealPassword(entered, {
          host: "outbound-probes", username: current.host.id, port: null, auth_mode: "password", known_hosts: "",
        }, "outbound-probes");
      }
      if (view !== current || !dialog.open) return;
      sent = true;
      const data = await request("/api/outbound-probes", "POST", payload);
      if (view !== current || !dialog.open) return;
      const previousSaved = current.data?.selected_region_ids ?? [];
      const followedSaved = current.selected?.length === previousSaved.length &&
        previousSaved.every((id) => current.selected.includes(id));
      const resetSchedule = action === "schedule_save" || !current.data?.schedule ||
        !scheduleChanged() && ![scheduleEnabled, scheduleInterval, schedulePackets].includes(document.activeElement);
      current.data = data;
      renderSchedule(data.schedule, resetSchedule);
      if (current.selected == null || action === "selection_save" ||
        (followedSaved && !current.trackingRun && !current.selectionChangedWhileReading)) {
        current.selected = (data.selected_region_ids ?? []).slice();
      }
      const regionIds = new Set(data.regions.map(({id}) => id));
      current.selected = current.selected.filter((id) => regionIds.has(id));
      if (data.batch_running && !current.trackingRun && data.active_region_ids?.length && !data.schedule?.enabled) {
        current.selected = data.active_region_ids.filter((id) => regionIds.has(id));
      }
      current.trackingRun = Boolean(data.batch_running || action === "run_batch");
      for (const result of data.region_results ?? []) current.results.set(result.region_id, result);
      const latest = current.history && current.results.get(current.history.region.id)?.checked_at;
      if (latest && latest !== current.history.checkedAt) loadHistory(current.history, true);
      const preferred = action === "region_save" ? data.region_id : "";
      if (action === "region_save" && !payload.region_id && regionIds.has(preferred) &&
        !current.selected.includes(preferred) && current.selected.length < maxRegions) {
        current.selected.push(preferred);
      }
      renderRegions(data.regions, preferred);
      renderResults();
      if (action === "region_save" || action === "region_delete") {
        closeEditor();
        focusRegion = true;
      }
      feedback(data.batch_running ? "服务器正在检测…" : action === "selection_save" ? "已保存为这台设备的常用地区。" : "");
    } catch (error) {
      if (view === current && dialog.open) {
        current.retryState = sent && (action === "state" || action === "run_batch") && !current.data?.schedule?.enabled;
        if (error.message === "这个测速地区已不存在，请重新选择地区。") {
          current.selected = null;
          renderResults();
        }
        if (action === "schedule_save") {
          current.scheduleRequestError = true;
          scheduleFeedback(error.message, "error");
        } else {
          feedback(error.message, "error");
        }
      }
    } finally {
      if (view === current && dialog.open) {
        current.busy = false;
        updateControls();
        if (current.selectionChangedWhileReading && !current.retryState && !current.data?.batch_running && current.selected?.length) {
          current.selectionChangedWhileReading = false;
          perform("state");
        } else {
          current.selectionChangedWhileReading = false;
          if (!current.retryState && (current.data?.batch_running || current.data?.schedule?.enabled)) {
            const delay = current.data.batch_running ? 1500 : 5000;
            current.timer = setTimeout(() => perform("state"), delay);
          }
        }
        if (focusRegion && !regionAdd.disabled) regionAdd.focus();
      }
    }
  }

  regionOptions.addEventListener("change", (event) => {
    const checkbox = event.target;
    if (!view?.selected || checkbox.type !== "checkbox") return;
    view.trackingRun = false;
    if (checkbox.checked && !view.selected.includes(checkbox.value) && view.selected.length < maxRegions) {
      view.selected.push(checkbox.value);
    } else if (!checkbox.checked) {
      view.selected = view.selected.filter((id) => id !== checkbox.value);
    }
    updateControls();
    renderResults();
    if (view.busy === "state") view.selectionChangedWhileReading = true;
    else if (view.selected.length) perform("state");
  });
  saveSelection.addEventListener("click", () => perform("selection_save"));
  for (const input of [scheduleEnabled, scheduleInterval, schedulePackets]) {
    input.addEventListener("input", updateScheduleDraft);
  }
  scheduleRecommend.addEventListener("click", () => {
    scheduleInterval.value = 60;
    schedulePackets.value = 3;
    updateScheduleDraft();
  });
  scheduleSave.addEventListener("click", () => {
    if (!scheduleInterval.reportValidity() || !schedulePackets.reportValidity()) return;
    perform("schedule_save", scheduleDraft());
  });
  byId("outbound-history-close").addEventListener("click", () => historyDialog.close());
  historyDialog.addEventListener("close", () => { if (view) view.history = null; });
  historySource.addEventListener("change", () => { if (view?.history) renderHistory(view.history); });
  historyRefresh.addEventListener("click", () => loadHistory(view?.history));
  regionAdd.addEventListener("click", () => openEditor(null));
  regionEdit.addEventListener("click", () => openEditor(managedRegion()));
  regionDelete.addEventListener("click", () => {
    const region = managedRegion();
    byId("outbound-region-confirmation-text").textContent = "删除「" + region.name + "」及其检测结果？";
    confirmation.hidden = false;
    feedback("");
    updateControls();
    keepRegion.focus();
  });
  keepRegion.addEventListener("click", closeEditor);
  confirmDelete.addEventListener("click", () => perform("region_delete", {region_id: managedRegion().id}));
  cancelRegion.addEventListener("click", closeEditor);
  addTarget.addEventListener("click", () => {
    appendTarget().focus();
    updateControls();
  });
  saveRegion.addEventListener("click", () => {
    const draft = regionDraft();
    if (draft) perform("region_save", draft);
  });
  editor.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.isComposing && event.target.tagName === "INPUT") {
      event.preventDefault();
      saveRegion.click();
    }
  });
  run.addEventListener("click", () => view?.retryState ? perform("state") : perform("run_batch", {packets: 5}));
  retest.addEventListener("click", () => perform("run_batch", {packets: 20}));
  password.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.isComposing) {
      event.preventDefault();
      run.click();
    }
  });
  function resetView() {
    clearTimeout(view?.timer);
    if (historyDialog.open) historyDialog.close();
    view = null;
    password.value = "";
  }

  dialog.addEventListener("network-check-open", resetView);
  dialog.addEventListener("close", () => {
    if (!dialog.open) resetView();
  });

  window.vpsOpenOutboundProbes = (host) => {
    clearTimeout(view?.timer);
    view = {host, data: null, selected: null, results: new Map(), busy: false, retryState: false,
      timer: 0, editing: null, trackingRun: false, selectionChangedWhileReading: false,
      regionSignature: null, resultSignature: null, history: null, scheduleRequestError: false};
    password.value = "";
    scheduleEnabled.checked = false;
    scheduleInterval.value = 900;
    schedulePackets.value = 5;
    scheduleStatus.hidden = true;
    scheduleFeedback("");
    regionOptions.replaceChildren();
    manageRegion.replaceChildren();
    byId("outbound-region-custom").hidden = true;
    editor.hidden = confirmation.hidden = true;
    renderResults();
    feedback("正在读取检测状态…");
    perform("state");
  };
})();

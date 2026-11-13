(() => {
  "use strict";

  const dialog = byId("outbound-bulk-dialog");
  const search = byId("outbound-bulk-search");
  const devices = byId("outbound-bulk-devices");
  const regions = byId("outbound-bulk-regions");
  const selectVisible = byId("outbound-bulk-select-visible");
  const clearHosts = byId("outbound-bulk-clear-hosts");
  const save = byId("outbound-bulk-save");
  const retry = byId("outbound-bulk-retry");
  let view = null;

  function feedback(message, error = false) {
    const status = byId("outbound-bulk-status");
    status.textContent = message;
    status.dataset.kind = error ? "error" : "";
    status.hidden = !message;
  }

  function filteredHosts() {
    const query = search.value.trim().toLocaleLowerCase();
    return view.hosts.filter((host) => [host.name, address(host), host.group].some(
      (value) => (value ?? "").toLocaleLowerCase().includes(query),
    ));
  }

  function updateControls() {
    const visible = filteredHosts();
    const hostCount = view.selectedHosts.size;
    const regionCount = view.selectedRegions.size;
    selectVisible.disabled = view.saving || !visible.some((host) => !view.selectedHosts.has(host.id));
    clearHosts.disabled = view.saving || !hostCount;
    retry.disabled = view.loading || view.saving;
    search.disabled = view.saving;
    save.disabled = view.loading || view.saving || !hostCount || !regionCount;
    save.textContent = view.saving ? "正在保存…" : "应用到所选设备";
    for (const input of devices.querySelectorAll("input")) input.disabled = view.saving;
    for (const input of regions.querySelectorAll("input")) {
      input.disabled = view.saving || (!input.checked && regionCount >= view.maxRegions);
    }
    for (const close of dialog.querySelectorAll("[data-close]")) close.disabled = view.saving;
    byId("outbound-bulk-count").textContent = "已选 " + hostCount + " 台设备 · " + regionCount + " 个地区";
  }

  function option(id, title, detail, selection) {
    const label = element("label", "outbound-bulk-option");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = selection.has(id);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) selection.add(id);
      else selection.delete(id);
      updateControls();
    });
    const text = element("span", "", title);
    if (detail) text.append(element("small", "", detail));
    label.append(checkbox, text);
    return label;
  }

  function renderHosts() {
    const visible = filteredHosts();
    devices.replaceChildren(...visible.map((host) => {
      const detail = [address(host), host.group].filter(Boolean).join(" · ");
      return option(host.id, host.name, detail, view.selectedHosts);
    }));
    if (!visible.length) devices.append(element("p", "field-hint", "没有匹配的设备。"));
  }

  function renderRegions() {
    regions.replaceChildren(...view.regions.map((region) =>
      option(region.id, region.name, region.custom ? "自定义地区" : "", view.selectedRegions)));
    byId("outbound-bulk-limit").textContent = view.maxRegions ? "最多选择 " + view.maxRegions + " 个地区。" : "";
  }

  async function loadRegions() {
    const current = view;
    current.loading = true;
    retry.hidden = true;
    updateControls();
    feedback("正在读取测速地区…");
    try {
      const data = await request("/api/outbound-probes", "POST", {action: "selection_options"});
      if (view !== current || !dialog.open) return;
      if (!Array.isArray(data.regions) || !Number.isInteger(data.max_selected_regions) || data.max_selected_regions < 1) {
        throw new Error("面板未返回可用的测速地区。");
      }
      current.regions = data.regions;
      current.maxRegions = data.max_selected_regions;
      renderRegions();
      feedback(data.regions.length ? "" : "没有可用的测速地区。");
    } catch (error) {
      if (view === current && dialog.open) {
        retry.hidden = false;
        feedback(error.message, true);
      }
    } finally {
      if (view === current && dialog.open) {
        current.loading = false;
        updateControls();
      }
    }
  }

  async function saveSelection() {
    const current = view;
    if (save.disabled || !current) return;
    const hostIds = [...current.selectedHosts];
    const regionIds = [...current.selectedRegions];
    current.saving = true;
    updateControls();
    feedback("正在保存常用地区…");
    try {
      const data = await request("/api/outbound-probes", "POST", {
        action: "selection_bulk_save", host_ids: hostIds, region_ids: regionIds,
      });
      if (view !== current || !dialog.open) return;
      if (data.updated_count !== hostIds.length) throw new Error("面板未确认全部设备的设置，请核对后重试。");
      current.saving = false;
      dialog.close();
      notice("已为 " + data.updated_count + " 台设备设置 " + regionIds.length + " 个常用地区。");
    } catch (error) {
      if (view === current && dialog.open) feedback(error.message, true);
    } finally {
      if (view === current && dialog.open) {
        current.saving = false;
        updateControls();
      }
    }
  }

  byId("outbound-bulk-open").addEventListener("click", () => {
    if (!state?.hosts.length || state.demo || busy || dialog.open) return;
    view = {
      hosts: state.hosts.slice(), regions: [], maxRegions: 0, loading: false, saving: false,
      selectedHosts: new Set(), selectedRegions: new Set(),
    };
    search.value = "";
    renderHosts();
    renderRegions();
    dialog.showModal();
    search.focus();
    loadRegions();
  });
  search.addEventListener("input", () => {
    renderHosts();
    updateControls();
  });
  selectVisible.addEventListener("click", () => {
    for (const host of filteredHosts()) view.selectedHosts.add(host.id);
    renderHosts();
    updateControls();
  });
  clearHosts.addEventListener("click", () => {
    view.selectedHosts.clear();
    renderHosts();
    updateControls();
  });
  retry.addEventListener("click", loadRegions);
  save.addEventListener("click", saveSelection);
  dialog.addEventListener("cancel", (event) => { if (view?.saving) event.preventDefault(); });
  dialog.addEventListener("close", () => { if (!dialog.open) view = null; });
})();

(() => {
  "use strict";

  const svgNamespace = "http://www.w3.org/2000/svg";
  const windowMs = 60 * 60 * 1000;
  const width = 320;
  const height = 54;
  const padding = 4;
  const timeFormat = new Intl.DateTimeFormat("zh-CN", {hour: "2-digit", minute: "2-digit", hourCycle: "h23"});
  const valueFormat = new Intl.NumberFormat("zh-CN", {maximumFractionDigits: 1});
  const pingColors = {
    telecom: "#1558ce", unicom: "#b54810", mobile: "#087d58",
    edis: "#7c49ad", psychz: "#ae285e", speedypage: "#097a88",
  };
  const carrierAliases = {
    "电信": "telecom", "中国电信": "telecom", "china telecom": "telecom",
    "联通": "unicom", "中国联通": "unicom", "china unicom": "unicom",
    "移动": "mobile", "中国移动": "mobile", "china mobile": "mobile",
  };
  const customColors = ["#805c0e", "#4152a3", "#894146", "#3e7024", "#9c4500", "#646b82"];
  const linePatterns = ["", "5 3", "2 3", "7 3 2 3", "1 3", "8 3", "4 2 1 2", "7 2 1 2 1 2"];

  function html(tag, className, text = "") {
    const node = document.createElement(tag);
    node.className = className;
    node.textContent = text;
    return node;
  }

  function svg(tag, attributes) {
    const node = document.createElementNS(svgNamespace, tag);
    for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, String(value));
    return node;
  }

  function isLatency(value) {
    return Number.isFinite(value) && value >= 0;
  }

  function latencyText(value) {
    return valueFormat.format(value) + " ms";
  }

  function collectPoints(points, end) {
    return points.map(({checked_at, latency_ms}) => ({
      time: Date.parse(checked_at),
      value: isLatency(latency_ms) ? latency_ms : null,
    })).filter(({time}) => time >= end - windowMs && time <= end)
      .sort((first, second) => first.time - second.time);
  }

  function xPosition(time, end) {
    return padding + (time - (end - windowMs)) / windowMs * (width - padding * 2);
  }

  function placePoints(points, end, minimum, maximum) {
    const margin = Math.max(10, maximum * 0.08);
    const lower = Math.max(0, minimum - margin);
    const upper = maximum + margin;
    for (const point of points) {
      point.x = xPosition(point.time, end);
      point.y = point.value === null ? null : height - padding - (point.value - lower) / (upper - lower) * (height - padding * 2);
    }
  }

  function latencyRange(minimum, maximum) {
    return minimum === maximum ? latencyText(minimum) : valueFormat.format(minimum) + "–" + latencyText(maximum);
  }

  function plotFrame(rangeText) {
    const times = html("div", "latency-chart-times");
    const range = html("span", "latency-chart-range", rangeText);
    range.title = "近 1 小时采样范围";
    times.append(html("span", "", "1 小时前"), range, html("span", "", "现在"));
    const plot = svg("svg", {
      class: "latency-chart-plot", viewBox: "0 0 " + width + " " + height, preserveAspectRatio: "none",
    });
    grid(plot);
    return {times, range, plot};
  }

  function grid(plot) {
    const lines = svg("g", {class: "latency-chart-grid", stroke: "#dbe5f1", "stroke-width": 1});
    for (const y of [padding, height / 2, height - padding]) {
      lines.append(svg("line", {x1: padding, x2: width - padding, y1: y, y2: y}));
    }
    for (const fraction of [0, 0.25, 0.5, 0.75, 1]) {
      const x = padding + fraction * (width - padding * 2);
      lines.append(svg("line", {x1: x, x2: x, y1: padding, y2: height - padding}));
    }
    plot.append(lines);
  }

  function addSeries(plot, points, gapMs, {prefix = "latency-chart", color = "#1558ce", dash = ""} = {}) {
    const segments = [];
    let segment = [];
    let previous = null;
    for (const point of points) {
      if (point.y === null || (previous && point.time - previous.time > gapMs)) {
        if (segment.length) segments.push(segment);
        segment = [];
      }
      if (point.y !== null) segment.push(point);
      previous = point;
    }
    if (segment.length) segments.push(segment);

    for (const group of segments) {
      if (group.length > 1) {
        plot.append(svg("polyline", {
          class: prefix + "-line",
          points: group.map(({x, y}) => x.toFixed(1) + "," + y.toFixed(1)).join(" "),
          fill: "none", stroke: color, "stroke-width": 1.7, "stroke-dasharray": dash || "none",
          "stroke-linecap": "round", "stroke-linejoin": "round", "vector-effect": "non-scaling-stroke",
        }));
      }
    }
    const markers = segments.filter((group) => group.length === 1).map(([point]) => point);
    const latest = segments.at(-1)?.at(-1);
    if (latest && !markers.includes(latest)) markers.push(latest);
    for (const point of markers) {
      plot.append(svg("circle", {class: prefix + "-dot", cx: point.x, cy: point.y, r: 2.4, fill: color}));
    }
  }

  function addInspection(plot, points, range, rangeText, summary, hostId) {
    const guide = inspectionGuide();
    const dot = svg("circle", {class: "latency-chart-selected", r: 3.2, fill: "#1558ce", stroke: "white"});
    plot.append(guide, dot);
    function show({time, value, x, y}) {
      const sample = timeFormat.format(time) + " · " + (value === null ? "无有效延迟" : latencyText(value));
      range.textContent = sample;
      showGuide(guide, x);
      dot.setAttribute("visibility", y === null ? "hidden" : "visible");
      if (y !== null) {
        dot.setAttribute("cx", x);
        dot.setAttribute("cy", y);
      }
      return sample;
    }

    function clear() {
      range.textContent = rangeText;
      guide.setAttribute("visibility", "hidden");
      dot.setAttribute("visibility", "hidden");
    }
    inspectTimeline(plot, points, summary, hostId, "latency-chart", show, clear);
  }

  function inspectionGuide() {
    return svg("line", {
      class: "latency-chart-cursor", y1: padding, y2: height - padding, "visibility": "hidden",
      stroke: "#52647c", "stroke-width": 1, "stroke-dasharray": "2 2",
    });
  }

  function showGuide(guide, x) {
    guide.setAttribute("x1", x);
    guide.setAttribute("x2", x);
    guide.setAttribute("visibility", "visible");
  }

  function inspectTimeline(plot, points, summary, hostId, action, showPoint, clear, selectedTime) {
    const restoredIndex = points.findIndex(({time}) => time >= selectedTime);
    let index = restoredIndex < 0 ? points.length - 1 : restoredIndex;
    function show(selected) {
      plot.setAttribute("aria-valuenow", selected + 1);
      plot.dataset.sampleTime = points[selected].time;
      plot.setAttribute("aria-valuetext", showPoint(points[selected]));
    }

    plot.setAttribute("role", "slider");
    plot.setAttribute("tabindex", "0");
    plot.setAttribute("aria-label", summary + "。用方向键查看采样");
    plot.setAttribute("aria-valuemin", "1");
    plot.setAttribute("aria-valuemax", points.length);
    if (hostId) {
      plot.dataset.host = hostId;
      plot.dataset.action = action;
    }
    show(index);
    clear();
    plot.addEventListener("focus", () => show(index));
    plot.addEventListener("blur", clear);
    plot.addEventListener("pointermove", (event) => {
      const bounds = plot.getBoundingClientRect();
      if (!bounds.width) return;
      const x = (event.clientX - bounds.left) / bounds.width * width;
      let nearest = 0;
      for (let i = 1; i < points.length; i += 1) {
        if (Math.abs(points[i].x - x) < Math.abs(points[nearest].x - x)) nearest = i;
      }
      show(nearest);
    });
    plot.addEventListener("pointerleave", () => {
      if (document.activeElement === plot) show(index);
      else clear();
    });
    plot.addEventListener("keydown", (event) => {
      switch (event.key) {
        case "ArrowLeft":
        case "ArrowDown":
          index = Math.max(0, index - 1);
          break;
        case "ArrowRight":
        case "ArrowUp":
          index = Math.min(points.length - 1, index + 1);
          break;
        case "Home":
          index = 0;
          break;
        case "End":
          index = points.length - 1;
          break;
        default:
          return;
      }
      event.preventDefault();
      show(index);
    });
  }

  window.vpsLatencyChart = (series, {end = Date.now(), interval = 60, latest, hostId} = {}) => {
    const figure = html("figure", "latency-chart");
    const caption = html("figcaption", "latency-chart-head");
    const current = isLatency(latest) ? latencyText(latest) : "—";
    caption.append(html("strong", "latency-chart-caption", "SSH 巡检延迟"),
      html("span", "latency-chart-current", "当前 " + current));
    figure.append(caption);

    const points = collectPoints(series ?? [], end);
    const samples = points.map(({value}) => value).filter((value) => value !== null);
    if (!samples.length) {
      figure.append(html("p", "latency-chart-empty", points.length ? "近 1 小时无有效采样" : "近 1 小时暂无采样"));
      return figure;
    }

    const minimum = Math.min(...samples);
    const maximum = Math.max(...samples);
    placePoints(points, end, minimum, maximum);
    const rangeText = latencyRange(minimum, maximum);
    const {times, range, plot} = plotFrame(rangeText);
    const summary = "SSH 巡检延迟，近 1 小时 " + samples.length + " 个有效采样，范围 " + rangeText;
    addSeries(plot, points, 1750 * Math.max(60, interval || 60));
    if (points.length > 1) addInspection(plot, points, range, rangeText, summary, hostId);
    else {
      plot.setAttribute("role", "img");
      plot.setAttribute("aria-label", summary);
    }
    figure.append(plot, times);
    return figure;
  };

  function pingSeries(series, end) {
    const carriers = new Map();
    const repeats = new Map();
    return series.map(({id, label, carrier, interval_seconds, points}) => {
      const key = String(carrier || label || id).trim().toLowerCase();
      const carrierKey = Object.hasOwn(carrierAliases, key) ? carrierAliases[key] : key;
      let color = Object.hasOwn(pingColors, carrierKey) ? pingColors[carrierKey] : carriers.get(carrierKey);
      if (!color) {
        color = customColors[carriers.size % customColors.length];
        carriers.set(carrierKey, color);
      }
      const repeat = repeats.get(color) || 0;
      repeats.set(color, repeat + 1);
      const interval = Number.isFinite(interval_seconds) && interval_seconds > 0 ? interval_seconds : 60;
      return {
        label: label || carrier || id, color, dash: linePatterns[repeat % linePatterns.length],
        gapMs: 1750 * Math.max(60, interval), points: collectPoints(points ?? [], end),
      };
    });
  }

  function pingLegend(series) {
    const legend = html("ul", "ping-chart-legend");
    legend.setAttribute("aria-label", "线路及最近一次测速");
    for (const line of series) {
      const row = html("li", "ping-chart-series");
      const label = html("span", "ping-chart-series-label", line.label);
      label.title = line.label;
      const sample = line.points.at(-1);
      line.latestText = sample?.value != null ? latencyText(sample.value) : "—";
      line.valueLabel = html("span", "ping-chart-series-value", line.latestText);
      line.valueLabel.title = sample ? "最近采样 " + timeFormat.format(sample.time) : "暂无采样";
      const swatch = svg("svg", {
        class: "ping-chart-swatch", viewBox: "0 0 20 10", width: 20, height: 10, "aria-hidden": true,
      });
      swatch.append(svg("line", {
        x1: 1, y1: 5, x2: 19, y2: 5, stroke: line.color, "stroke-width": 2,
        "stroke-linecap": "round", "stroke-dasharray": line.dash || "none",
      }));
      row.append(swatch, label, line.valueLabel);
      legend.append(row);
    }
    return legend;
  }

  function inspectPing(plot, series, end, range, rangeText, hostId, selectedTime) {
    const rounds = new Map();
    const guide = inspectionGuide();
    plot.append(guide);
    for (const line of series) {
      for (const point of line.points) {
        if (!rounds.has(point.time)) rounds.set(point.time, {time: point.time, x: point.x, values: new Map()});
        rounds.get(point.time).values.set(line, point.value);
      }
    }
    const points = Array.from(rounds.values()).sort((first, second) => first.time - second.time);
    const summary = "VPS 出网 Ping，近 1 小时 " + points.length + " 轮，范围 " + rangeText;
    function show({time, values}) {
      const clock = timeFormat.format(time);
      range.textContent = clock;
      showGuide(guide, xPosition(time, end));
      const readings = [];
      for (const line of series) {
        const value = values.get(line);
        const label = value != null ? latencyText(value) : "—";
        line.valueLabel.textContent = label;
        if (values.has(line)) readings.push(line.label + " " + (value != null ? label : "无有效延迟"));
      }
      return clock + " · " + readings.join("，");
    }
    function clear() {
      range.textContent = rangeText;
      guide.setAttribute("visibility", "hidden");
      for (const line of series) line.valueLabel.textContent = line.latestText;
    }
    if (points.length > 1) inspectTimeline(plot, points, summary, hostId, "ping-chart", show, clear, selectedTime);
    else {
      plot.setAttribute("role", "img");
      plot.setAttribute("aria-label", summary);
    }
  }

  window.vpsPingChart = (series, {end = Date.now(), hostId, scheduled = false, onConfigure, selectedTime} = {}) => {
    const figure = html("figure", "latency-chart ping-chart");
    const caption = html("figcaption", "latency-chart-head");
    caption.append(html("strong", "latency-chart-caption", "VPS 出网 Ping"));
    if (typeof onConfigure === "function") {
      const configure = html("button", "text-button ping-chart-configure", "测速设置");
      configure.type = "button";
      configure.addEventListener("click", onConfigure);
      if (hostId) {
        configure.dataset.host = hostId;
        configure.dataset.action = "ping-configure";
      }
      caption.append(configure);
    }
    figure.append(caption);
    const lines = pingSeries(series ?? [], end);
    const legend = pingLegend(lines);
    const samples = lines.flatMap(({points}) => points.map(({value}) => value).filter((value) => value !== null));
    if (samples.length) {
      const minimum = Math.min(...samples);
      const maximum = Math.max(...samples);
      const rangeText = latencyRange(minimum, maximum);
      const {times, range, plot} = plotFrame(rangeText);
      for (const {points, color, dash, gapMs} of lines) {
        placePoints(points, end, minimum, maximum);
        addSeries(plot, points, gapMs, {prefix: "ping-chart", color, dash});
      }
      inspectPing(plot, lines, end, range, rangeText, hostId, selectedTime);
      figure.append(plot, times);
    } else {
      let message = "暂无采样。可开始检测，或启用定时测速。";
      if (lines.some(({points}) => points.length)) message = "近 1 小时无有效采样。";
      else if (scheduled) message = "等待定时测速采样。";
      figure.append(html("p", "latency-chart-empty", message));
    }
    if (lines.length) figure.append(legend);
    return figure;
  };
})();

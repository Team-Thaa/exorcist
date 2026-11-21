const state = {
  devices: [],
  alerts: [],
  api: "connecting",
  live: "waiting",
  error: "",
  search: "",
  statusFilter: "all",
  socket: null,
  reconnectTimer: null,
  toastTimer: null
};

const $ = (selector) => document.querySelector(selector);
const page = $("#page-content");
const command = $("#current-command");
const macPattern = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}

function safeScore(value) {
  if (value === undefined || value === null || value === "") return null;
  const score = Number(value);
  return Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : null;
}

function formatScore(value) {
  return value === null ? "—" : `${value}/100`;
}

function normalizeDevice(device) {
  if (!device || typeof device !== "object" || typeof device.mac !== "string" || typeof device.ip !== "string") {
    return null;
  }
  return {
    ...device,
    mac: device.mac.toLowerCase(),
    label: typeof device.label === "string" && device.label.trim()
      ? device.label
      : `${device.type || "Device"} at ${device.ip}`,
    type: device.type || "network_device",
    status: ["safe", "at_risk", "infected"].includes(device.status) ? device.status : "unknown",
    exposure_score: safeScore(device.exposure_score),
    infection_score: safeScore(device.infection_score),
    open_ports: Array.isArray(device.open_ports) ? device.open_ports.filter(Number.isInteger) : [],
    findings: Array.isArray(device.findings) ? device.findings.filter((item) => typeof item === "string") : [],
    quarantined: device.quarantined === true
  };
}

function route() {
  let decoded;
  try {
    decoded = decodeURIComponent((location.hash || "#/overview").slice(2));
  } catch {
    return { page: "overview" };
  }
  const parts = decoded.split("/").filter(Boolean);
  if (parts[0] === "device" && parts[1]) return { page: "device", mac: parts.slice(1).join("/") };
  const valid = ["overview", "radar", "devices", "alerts", "settings"];
  return { page: valid.includes(parts[0]) ? parts[0] : "overview" };
}

function setApiStatus(status) {
  state.api = status;
  const element = $("#api-state");
  element.className = `api-state ${status}`;
  $("#api-state-label").textContent = status === "online"
    ? "API connected"
    : status === "offline" ? "API offline" : "connecting";
}

function updateLiveStatus() {
  $("#live-state").textContent = `WebSocket · ${state.live}`;
}

function requestPage(title, subtitle) {
  page.replaceChildren();
  const heading = node("header", "page-heading");
  const text = node("div");
  text.append(node("h1", "", title), node("p", "", subtitle));
  heading.append(text);
  page.append(heading);
  if (state.error) {
    const error = node("div", "error", state.error);
    const retry = node("button", "button", "retry");
    retry.type = "button";
    retry.addEventListener("click", loadData);
    error.append(retry);
    page.append(error);
  }
}

function statusClass(status) {
  return ["safe", "at_risk", "infected"].includes(status) ? status : "unknown";
}

function statusBadge(status) {
  const label = status === "at_risk" ? "at risk" : status || "unknown";
  return node("span", `status ${statusClass(status)}`, label);
}

function formatTime(alert) {
  const date = alert.time ? new Date(alert.time) : new Date(Number(alert.ts || 0) * 1000);
  if (Number.isNaN(date.getTime())) return "unknown";
  const minutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60_000));
  if (minutes < 1) return "now";
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
  return date.toLocaleDateString();
}

function createAlertRow(alert) {
  const row = node("article", "alert-row");
  row.append(node("i", `alert-indicator ${String(alert.severity || "medium").toLowerCase()}`));
  const content = node("div");
  const title = node("div", "alert-title", String(alert.type || "alert").replaceAll("_", " "));
  const evidence = node("div", "alert-evidence", alert.evidence || `${alert.ip || "Unknown device"} · ${alert.status || ""}`);
  const device = state.devices.find((item) => item.mac === String(alert.mac || "").toLowerCase());
  if (device) {
    const link = node("a", "action-link", ` ${device.label}`);
    link.href = `#/device/${encodeURIComponent(device.mac)}`;
    title.append(link);
  }
  content.append(title, evidence);
  row.append(content, node("time", "alert-time", formatTime(alert)));
  return row;
}

function createDeviceRow(device) {
  const row = node("a", "device-row");
  row.href = `#/device/${encodeURIComponent(device.mac)}`;
  const details = node("span", "device-main");
  details.append(
    node("span", "device-label", device.label),
    node("span", "device-address", `${device.ip} · ${device.mac}`)
  );
  row.append(details, statusBadge(device.status), node("span", "score", formatScore(device.infection_score)));
  return row;
}

function renderOverview() {
  command.textContent = "neofetch";
  requestPage("network overview", "One terminal. Every device. Clear evidence.");
  const fetchPanel = node("section", "overview-fetch");
  const identity = node("div", "identity");
  identity.append(node("h2", "", "thaa@botnet"), node("div", "identity-divider", "----------------"));
  const facts = node("div", "identity-facts");
  [
    ["OS", "Exorcist Network Monitor"],
    ["Host", "Pi 5 Gateway"],
    ["Kernel", "Zeek + Detection Engine"],
    ["Network", "192.168.50.0/24"],
    ["Identity", "MAC-first"],
    ["API", state.api === "online" ? "connected" : state.api === "offline" ? "offline" : "connecting"]
  ].forEach(([label, value]) => {
    const fact = node("div", "identity-fact");
    fact.append(node("span", "identity-label", label), node("span", "identity-value", value));
    facts.append(fact);
  });
  identity.append(facts);
  const cat = node("pre", "cat");
  cat.setAttribute("role", "img");
  cat.setAttribute("aria-label", "ASCII cat");
  cat.append(" /\\_/\\\n( ");
  cat.append(node("span", "eyes", "o.o"));
  cat.append(" )\n > ^ <");
  fetchPanel.append(identity, cat);
  page.append(fetchPanel);

  const infected = state.devices.filter((device) => device.status === "infected").length;
  const atRisk = state.devices.filter((device) => device.status === "at_risk").length;
  const exposureScores = state.devices
    .map((device) => device.exposure_score)
    .filter((score) => score !== null);
  const average = exposureScores.length
    ? Math.round(exposureScores.reduce((sum, score) => sum + score, 0) / exposureScores.length)
    : null;
  const metrics = node("section", "metric-grid");
  [
    ["Devices", state.devices.length],
    ["At risk", atRisk],
    ["Infected", infected],
    ["Avg. exposure", average === null ? "—" : `${average}/100`]
  ].forEach(([label, value]) => {
    const card = node("article", "metric");
    card.append(node("div", "metric-label", label), node("div", "metric-value", value));
    metrics.append(card);
  });
  page.append(metrics);

  const columns = node("div", "overview-columns");
  const devicePanel = node("section", "panel");
  const deviceHeading = node("div", "panel-heading");
  deviceHeading.append(
    node("h2", "section-title", "devices"),
    makeLink("#/devices", "view all")
  );
  devicePanel.append(deviceHeading);
  const deviceList = node("div", "device-list");
  if (state.devices.length) {
    state.devices.slice(0, 5).forEach((device) => deviceList.append(createDeviceRow(device)));
  } else {
    deviceList.append(node("p", "empty", "No devices reported by the API yet."));
  }
  devicePanel.append(deviceList);

  const alertPanel = node("section", "panel");
  const alertHeading = node("div", "panel-heading");
  alertHeading.append(node("h2", "section-title", "live activity"), makeLink("#/alerts", "all alerts"));
  alertPanel.append(alertHeading);
  const alerts = node("div", "alert-list");
  if (state.alerts.length) {
    state.alerts.slice(0, 5).forEach((alert) => alerts.append(createAlertRow(alert)));
  } else {
    alerts.append(node("p", "empty", "No alerts received yet."));
  }
  alertPanel.append(alerts);
  columns.append(devicePanel, alertPanel);
  page.append(columns);
}

function makeLink(href, label) {
  const link = node("a", "text-link", label);
  link.href = href;
  return link;
}

function renderDeviceTable() {
  const query = state.search.toLowerCase();
  const devices = state.devices.filter((device) => {
    const matchesText = [device.label, device.ip, device.mac, device.type, device.vendor]
      .some((value) => String(value || "").toLowerCase().includes(query));
    const matchesStatus = state.statusFilter === "all" || device.status === state.statusFilter;
    return matchesText && matchesStatus;
  });
  const wrap = node("div", "table-wrap");
  const table = node("table", "device-table");
  const head = node("thead");
  const header = node("tr");
  ["Device", "Type", "Status", "Exposure", "Infection"].forEach((value) => header.append(node("th", "", value)));
  head.append(header);
  const body = node("tbody");
  devices.forEach((device) => {
    const row = node("tr");
    const deviceCell = node("td");
    const link = node("a", "", device.label);
    link.href = `#/device/${encodeURIComponent(device.mac)}`;
    deviceCell.append(link, node("div", "device-address", `${device.ip} · ${device.mac}`));
    row.append(
      deviceCell,
      node("td", "", device.type.replaceAll("_", " ")),
      node("td", "", ""),
      node("td", "", formatScore(device.exposure_score)),
      node("td", "", formatScore(device.infection_score))
    );
    row.children[2].append(statusBadge(device.status));
    body.append(row);
  });
  table.append(head, body);
  wrap.append(table);
  return { wrap, count: devices.length };
}

function renderDevices() {
  command.textContent = "ls devices";
  requestPage("devices", `${state.devices.length} device${state.devices.length === 1 ? "" : "s"} · sorted by network address`);
  const toolbar = node("div", "toolbar");
  const search = node("input", "search-input");
  search.type = "search";
  search.placeholder = "Search label, IP, MAC, type…";
  search.value = state.search;
  search.setAttribute("aria-label", "Search devices");
  search.addEventListener("input", () => {
    state.search = search.value;
    const result = renderDeviceTable();
    tableContainer.replaceChildren(result.count ? result.wrap : node("p", "empty", "No matching devices."));
  });
  const filter = node("select", "select-input");
  filter.setAttribute("aria-label", "Filter by status");
  [["all", "All statuses"], ["safe", "Safe"], ["at_risk", "At risk"], ["infected", "Infected"]]
    .forEach(([value, label]) => {
      const option = node("option", "", label);
      option.value = value;
      filter.append(option);
    });
  filter.value = state.statusFilter;
  filter.addEventListener("change", () => {
    state.statusFilter = filter.value;
    const result = renderDeviceTable();
    tableContainer.replaceChildren(result.count ? result.wrap : node("p", "empty", "No matching devices."));
  });
  toolbar.append(search, filter);
  const tableContainer = node("div");
  const result = renderDeviceTable();
  tableContainer.append(result.count ? result.wrap : node("p", "empty", "No devices reported by the API."));
  page.append(toolbar, tableContainer);
}

function renderRadar() {
  command.textContent = "scan --passive";
  requestPage("network radar", "Passive device map · click a node to inspect it.");
  const layout = node("div", "radar-layout");
  const mapPanel = node("section", "panel");
  const map = node("div", "radar");
  ["r1", "r2", "r3"].forEach((value) => map.append(node("span", `radar-ring ${value}`)));
  map.append(node("span", "radar-axis"), node("span", "radar-axis vertical"), node("span", "radar-center", "⌂"));
  const devices = state.devices.slice(0, 20);
  devices.forEach((device, index) => {
    const angle = 2 * Math.PI * index / Math.max(devices.length, 1) - Math.PI / 2;
    const radius = index % 2 ? 39 : 30;
    const button = node("a", `radar-node ${statusClass(device.status)}`);
    button.href = `#/device/${encodeURIComponent(device.mac)}`;
    button.style.left = `${50 + Math.cos(angle) * radius}%`;
    button.style.top = `${50 + Math.sin(angle) * radius}%`;
    button.title = `${device.label} · ${device.status}`;
    button.setAttribute("aria-label", `Open ${device.label}, ${device.status}`);
    map.append(button);
  });
  mapPanel.append(map, node("p", "radar-caption", `${devices.length} of ${state.devices.length} devices shown`));
  const legend = node("div", "legend");
  [["safe-dot", "safe"], ["risk-dot", "at risk"], ["infected-dot", "infected"]].forEach(([className, label]) => {
    const item = node("span");
    item.append(node("i", className), label);
    legend.append(item);
  });
  mapPanel.append(legend);

  const listPanel = node("section", "panel");
  listPanel.append(node("h2", "section-title", "network devices"));
  if (state.devices.length) {
    const list = node("div", "device-list");
    state.devices.forEach((device) => list.append(createDeviceRow(device)));
    listPanel.append(list);
  } else {
    listPanel.append(node("p", "empty", "No devices reported by the API yet."));
  }
  layout.append(mapPanel, listPanel);
  page.append(layout);
}

function detailFact(label, value) {
  const item = node("div", "detail-fact");
  item.append(node("dt", "", label), node("dd", "", value ?? "Unknown"));
  return item;
}

async function setQuarantine(device, action, button) {
  const quarantine = action === "quarantine";
  if (quarantine && !window.confirm(`Quarantine ${device.label}? Its internet traffic will be blocked.`)) return;
  button.disabled = true;
  button.textContent = quarantine ? "quarantining…" : "releasing…";
  try {
    const response = await fetch(`/devices/${encodeURIComponent(device.mac)}/${action}`, { method: "POST" });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
    upsertDevice(payload);
    render();
    showToast(quarantine ? "Device quarantined." : "Device released.");
  } catch (error) {
    button.disabled = false;
    button.textContent = quarantine ? "quarantine device" : "release device";
    showToast(error.message || "Quarantine request failed.", true);
  }
}

function renderDevice(mac) {
  command.textContent = `cat device/${mac}`;
  const device = state.devices.find((item) => item.mac === mac.toLowerCase());
  requestPage(device ? device.label : "device not found", device ? `${device.ip} · ${device.mac}` : "This device is not in the API inventory.");
  if (!device) {
    page.append(node("p", "empty", "Return to the device list and select a known MAC address."));
    return;
  }

  const heading = page.querySelector(".page-heading");
  const button = node("button", `quarantine-button ${device.quarantined ? "release" : "danger"}`,
    device.quarantined ? "release device" : "quarantine device");
  button.type = "button";
  button.disabled = !macPattern.test(device.mac) || state.api !== "online";
  button.title = !macPattern.test(device.mac) ? "A real MAC address is required." : "";
  button.addEventListener("click", () => setQuarantine(device, device.quarantined ? "release" : "quarantine", button));
  heading.append(button);

  const details = node("div", "detail-grid");
  const overview = node("section", "detail-card");
  overview.append(node("h2", "", "status & identity"));
  const facts = node("dl", "detail-facts");
  facts.append(
    detailFact("Status", device.quarantined ? "quarantined" : device.status),
    detailFact("Vendor", device.vendor),
    detailFact("Type", device.type.replaceAll("_", " ")),
    detailFact("Firmware", device.firmware),
    detailFact("Infection score", formatScore(device.infection_score)),
    detailFact("Exposure score", formatScore(device.exposure_score))
  );
  overview.append(facts);

  const ports = node("section", "detail-card");
  ports.append(node("h2", "", "observed services"));
  const chips = node("div", "chip-list");
  if (device.open_ports.length) {
    device.open_ports.forEach((port) => chips.append(node("span", "chip", `TCP ${port}`)));
  } else {
    chips.append(node("span", "muted", "No service data reported."));
  }
  ports.append(chips);
  details.append(overview, ports);

  const findings = node("section", "detail-card");
  findings.append(node("h2", "", "exposure findings"));
  if (device.findings.length) {
    device.findings.forEach((finding) => findings.append(node("p", "finding", finding)));
  } else {
    findings.append(node("p", "muted", "No exposure findings reported."));
  }
  if (device.explanation) findings.append(node("p", "explanation", device.explanation));

  const activity = node("section", "detail-card");
  activity.append(node("h2", "", "recent alerts"));
  const related = state.alerts.filter((alert) => String(alert.mac || "").toLowerCase() === device.mac).slice(0, 5);
  if (related.length) {
    related.forEach((alert) => activity.append(createAlertRow(alert)));
  } else {
    activity.append(node("p", "muted", "No alerts for this device."));
  }
  details.append(findings, activity);
  page.append(details);
}

function renderAlerts() {
  command.textContent = "tail -f alerts.log";
  requestPage("live alerts", `${state.alerts.length} recent event${state.alerts.length === 1 ? "" : "s"}`);
  if (!state.alerts.length) {
    page.append(node("p", "empty", "No alerts received yet."));
    return;
  }
  const list = node("section", "panel alert-list");
  state.alerts.forEach((alert) => list.append(createAlertRow(alert)));
  page.append(list);
}

function renderSettings() {
  command.textContent = "cat settings";
  requestPage("settings", "API connection and available endpoints.");
  const cards = node("div", "detail-grid");
  const connection = node("section", "detail-card");
  connection.append(node("h2", "", "connection"));
  const facts = node("dl", "detail-facts");
  facts.append(
    detailFact("API origin", location.origin),
    detailFact("Health", state.api),
    detailFact("Live feed", state.live),
    detailFact("WebSocket", `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/live`)
  );
  connection.append(facts);
  const button = node("button", "button", "refresh data");
  button.type = "button";
  button.addEventListener("click", loadData);
  connection.append(button);

  const endpoints = node("section", "detail-card");
  endpoints.append(node("h2", "", "API routes"));
  const list = node("div", "endpoint-list");
  [
    ["GET", "/devices"],
    ["GET", "/alerts?limit=100"],
    ["WS", "/live"],
    ["POST", "/devices/{mac}/quarantine"],
    ["POST", "/devices/{mac}/release"]
  ].forEach(([method, path]) => {
    const row = node("div", "endpoint-row");
    row.append(node("span", "endpoint-method", method), node("span", "endpoint-path", path));
    list.append(row);
  });
  endpoints.append(list);
  cards.append(connection, endpoints);
  page.append(cards);
  if (state.api !== "online") page.append(node("p", "error", "The dashboard expects the API to serve this page from the same origin."));
}

function render() {
  const current = route();
  document.querySelectorAll(".nav a").forEach((link) => {
    const active = link.dataset.route === current.page || (current.page === "device" && link.dataset.route === "devices");
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  if (current.page === "overview") renderOverview();
  else if (current.page === "radar") renderRadar();
  else if (current.page === "devices") renderDevices();
  else if (current.page === "device") renderDevice(current.mac);
  else if (current.page === "alerts") renderAlerts();
  else renderSettings();
}

function upsertDevice(payload) {
  const device = normalizeDevice(payload);
  if (!device) return;
  const index = state.devices.findIndex((item) => item.mac === device.mac);
  if (index >= 0) state.devices[index] = { ...state.devices[index], ...device };
  else state.devices.push(device);
}

function handleLiveEvent(event) {
  if (!event || typeof event !== "object") return;
  if (event.event === "device.updated") {
    upsertDevice(event.device);
    render();
  } else if (event.event === "alert.created" && event.alert) {
    const alert = event.alert;
    state.alerts = [alert, ...state.alerts.filter((item) =>
      !(item.mac === alert.mac && item.ts === alert.ts && item.type === alert.type)
    )].slice(0, 100);
    render();
  }
}

function connectLive() {
  if (state.socket || state.api !== "online" || !["http:", "https:"].includes(location.protocol)) return;
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${protocol}//${location.host}/live`);
  state.socket = socket;
  socket.addEventListener("open", () => {
    state.live = "connected";
    updateLiveStatus();
  });
  socket.addEventListener("message", (message) => {
    try {
      handleLiveEvent(JSON.parse(message.data));
    } catch (error) {
      console.error("Could not read live API event:", error);
    }
  });
  socket.addEventListener("close", () => {
    if (state.socket === socket) state.socket = null;
    state.live = "disconnected";
    updateLiveStatus();
    if (state.api === "online" && !state.reconnectTimer) {
      state.reconnectTimer = window.setTimeout(() => {
        state.reconnectTimer = null;
        connectLive();
      }, 3000);
    }
  });
  socket.addEventListener("error", () => socket.close());
}

async function loadData() {
  state.error = "";
  setApiStatus("connecting");
  try {
    const healthResponse = await fetch("/health", { headers: { Accept: "application/json" } });
    if (!healthResponse.ok) throw new Error(`API health check failed (${healthResponse.status})`);
    const [deviceResponse, alertResponse] = await Promise.all([
      fetch("/devices", { headers: { Accept: "application/json" } }),
      fetch("/alerts?limit=100", { headers: { Accept: "application/json" } })
    ]);
    if (!deviceResponse.ok || !alertResponse.ok) {
      throw new Error(`API request failed (${!deviceResponse.ok ? deviceResponse.status : alertResponse.status})`);
    }
    const [devices, alerts] = await Promise.all([deviceResponse.json(), alertResponse.json()]);
    if (!Array.isArray(devices) || !Array.isArray(alerts)) throw new Error("API returned an unexpected response.");
    state.devices = devices.map(normalizeDevice).filter(Boolean);
    state.alerts = alerts;
    state.api = "online";
    setApiStatus("online");
    state.error = "";
    render();
    connectLive();
  } catch (error) {
    state.api = "offline";
    state.error = error.message || "Could not connect to the API.";
    state.live = "unavailable";
    setApiStatus("offline");
    updateLiveStatus();
    render();
  }
}

function showToast(message, isError = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  clearTimeout(state.toastTimer);
  state.toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 3500);
}

window.addEventListener("hashchange", render);
render();
loadData();

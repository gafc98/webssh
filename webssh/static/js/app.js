"use strict";

const styleNonce = document.currentScript ? document.currentScript.nonce : "";
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
const $ = id => document.getElementById(id);

const loginView = $("loginView");
const appView = $("appView");
const loginError = $("loginError");
const fileList = $("fileList");
const fileStatus = $("fileStatus");
const pathInput = $("pathInput");
const terminalTabs = $("terminalTabs");
const terminalStack = $("terminalStack");
const statsBar = $("stats");
const versionButton = $("versionButton");
const updateButton = $("updateButton");

const STATS_INTERVAL_MS = 5000;
const UPDATE_CHECK_INTERVAL_MS = 30 * 60 * 1000;
const RESTART_TIMEOUT_MS = 5 * 60 * 1000;
const INPUT_CHUNK_CHARS = 8192;
const ACTIVE_TERMINAL_KEY = "webssh.activeTerminal";
const FILES_WIDTH_KEY = "webssh.filesWidth";
// Keep in sync with the clamp() in .workspace (app.css).
const MIN_FILES_WIDTH = 200;
const MIN_TERMINAL_WIDTH = 320;
const SPLITTER_KEY_STEP = 24;

const TERMINAL_OPTIONS = {
  fontFamily: '"JetBrains Mono", monospace',
  fontSize: 14,
  lineHeight: 1.25,
  scrollback: 5000,
  theme: {
    background: "#080d16",
    foreground: "#dbe4f0",
    cursor: "#ffffff",
    cursorAccent: "#080d16",
    selectionBackground: "#2864a3",
    selectionForeground: "#ffffff",
    selectionInactiveBackground: "#2864a3"
  }
};

const state = {
  currentPath: "/",
  homePath: "/",
  clipboard: null,
  statsTimer: 0,
  updateTimer: 0,
  updateStatus: null
};
const terminals = new Map();
let activeTerminalId = null;

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/* ---------- API helpers ---------- */

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function api(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { ...(options.headers || {}) };
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(url, { credentials: "same-origin", ...options, headers });
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch {}
    if (response.status === 401 && url !== "/api/login") handleSignedOut();
    throw new ApiError(detail, response.status);
  }
  return response;
}

const getJSON = url => api(url).then(response => response.json());

const postJSON = (url, body = {}) =>
  api(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }).then(response => response.json());

function formatSize(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 ** 2) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 ** 3) return `${(size / 1024 ** 2).toFixed(1)} MB`;
  return `${(size / 1024 ** 3).toFixed(1)} GB`;
}

/* ---------- Views ---------- */

function showLogin(message = "") {
  appView.classList.add("hidden");
  loginView.classList.remove("hidden");
  loginError.textContent = message;
  $("username").focus();
}

async function showApp(info) {
  loginView.classList.add("hidden");
  appView.classList.remove("hidden");
  $("userLabel").textContent = info.username;
  state.homePath = info.home || "/";
  startPolling();
  await loadFiles(state.homePath).catch(error => setFileStatus(error.message));
  await initTerminals().catch(error => showMessage("Terminal unavailable", error.message));
}

function handleSignedOut(message = "") {
  settleModal(null);
  stopPolling();
  disposeAllTerminals();
  setClipboard(null);
  showLogin(message);
}

function showOverlay(message) {
  $("overlayMessage").textContent = message;
  $("overlay").classList.remove("hidden");
}

function hideOverlay() {
  $("overlay").classList.add("hidden");
}

/* ---------- Dialogs ---------- */

const modal = $("modal");
const modalInput = $("modalInput");
let modalState = null;

function openModal({
  title,
  message = "",
  items = [],
  input = null,
  placeholder = "",
  validate = null,
  confirmLabel = "OK",
  cancelLabel = "Cancel",
  danger = false
}) {
  settleModal(null);
  $("modalTitle").textContent = title;
  $("modalMessage").textContent = message;
  $("modalMessage").classList.toggle("hidden", !message);
  $("modalList").replaceChildren(
    ...items.map(text => {
      const item = document.createElement("li");
      item.textContent = text;
      item.title = text;
      return item;
    })
  );
  $("modalList").classList.toggle("hidden", !items.length);
  modalInput.classList.toggle("hidden", input === null);
  modalInput.value = input ?? "";
  modalInput.placeholder = placeholder;
  $("modalError").textContent = "";
  $("modalConfirm").textContent = confirmLabel;
  $("modalConfirm").classList.toggle("danger", danger);
  $("modalCancel").textContent = cancelLabel || "";
  $("modalCancel").classList.toggle("hidden", !cancelLabel);

  modal.showModal();
  if (input !== null) {
    modalInput.focus();
    // Preselect the base name so typing replaces it but keeps the extension.
    const dot = modalInput.value.lastIndexOf(".");
    modalInput.setSelectionRange(0, dot > 0 ? dot : modalInput.value.length);
  } else {
    (danger ? $("modalCancel") : $("modalConfirm")).focus();
  }
  return new Promise(resolve => {
    modalState = { resolve, withInput: input !== null, validate };
  });
}

function settleModal(value) {
  const current = modalState;
  modalState = null;
  if (modal.open) modal.close();
  if (current) current.resolve(value);
}

const confirmDialog = options => openModal(options).then(Boolean);
const promptDialog = ({ value = "", ...options }) => openModal({ ...options, input: value });

function showMessage(title, message = "") {
  hideOverlay();
  return openModal({ title, message, cancelLabel: null });
}

function nameError(name) {
  if (!name) return "Enter a name.";
  if (name === "." || name === "..") return "That name is reserved.";
  if (name.includes("/")) return "Names cannot contain “/”.";
  return "";
}

/* ---------- File manager ---------- */

function setFileStatus(message, info = false) {
  fileStatus.textContent = message;
  fileStatus.classList.toggle("info", info);
  fileStatus.classList.toggle("hidden", !message);
}

function iconButton(label, title, onClick, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `icon-button ${className}`.trim();
  button.textContent = label;
  button.title = title;
  button.setAttribute("aria-label", title);
  button.addEventListener("click", onClick);
  return button;
}

function buildFileRow(entry) {
  const isDirectory = entry.type === "directory";
  const row = document.createElement("div");
  row.className = "file-row";

  const icon = document.createElement("span");
  icon.className = "file-icon";
  icon.textContent = isDirectory ? "▰" : entry.type === "link" ? "↗" : "·";
  icon.setAttribute("aria-hidden", "true");

  const name = document.createElement("button");
  name.type = "button";
  name.className = `file-name${isDirectory ? " dir" : ""}`;
  name.textContent = entry.name;
  name.title = entry.name;
  if (isDirectory) name.addEventListener("click", () => navigate(entry.path));

  const size = document.createElement("span");
  size.className = "file-size";
  size.textContent = entry.type === "file" ? formatSize(entry.size) : "";

  const actions = document.createElement("div");
  actions.className = "row-actions";
  if (entry.type === "file") {
    actions.append(iconButton("↓", `Download ${entry.name}`, () => downloadFile(entry)));
  }
  actions.append(
    iconButton("✎", `Rename ${entry.name}`, () => renameEntry(entry)),
    iconButton("✂", `Move ${entry.name}`, () => setClipboard({ mode: "move", ...entry })),
    iconButton("⧉", `Copy ${entry.name}`, () => setClipboard({ mode: "copy", ...entry })),
    iconButton("✕", `Delete ${entry.name}`, () => deleteEntry(entry), "danger")
  );

  row.append(icon, name, size, actions);
  return row;
}

async function loadFiles(path = state.currentPath) {
  const result = await getJSON(`/api/files?path=${encodeURIComponent(path)}`);
  state.currentPath = result.path;
  pathInput.value = result.path;
  if (!result.entries.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "This directory is empty.";
    fileList.replaceChildren(empty);
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const entry of result.entries) fragment.append(buildFileRow(entry));
  fileList.replaceChildren(fragment);
}

function navigate(path) {
  setFileStatus("");
  loadFiles(path).catch(error => setFileStatus(error.message));
}

async function runFileAction(action, successMessage = "") {
  try {
    await action();
    setFileStatus(successMessage, true);
  } catch (error) {
    setFileStatus(error.message);
  }
  await loadFiles().catch(error => setFileStatus(error.message));
}

function downloadFile(entry) {
  const link = document.createElement("a");
  link.href = `/api/download?path=${encodeURIComponent(entry.path)}`;
  link.download = entry.name;
  link.click();
}

async function renameEntry(entry) {
  const name = await promptDialog({
    title: `Rename ${entry.type === "directory" ? "folder" : "file"}`,
    value: entry.name,
    validate: nameError,
    confirmLabel: "Rename"
  });
  if (!name || name === entry.name) return;
  runFileAction(() => postJSON("/api/files/rename", { path: entry.path, name }));
}

async function deleteEntry(entry) {
  const isDirectory = entry.type === "directory";
  const confirmed = await confirmDialog({
    title: `Delete ${isDirectory ? "folder" : "file"}?`,
    message: isDirectory
      ? `“${entry.name}” and everything inside it will be permanently deleted.`
      : `“${entry.name}” will be permanently deleted.`,
    confirmLabel: "Delete",
    danger: true
  });
  if (!confirmed) return;
  if (state.clipboard && state.clipboard.path === entry.path) setClipboard(null);
  runFileAction(() => postJSON("/api/files/delete", { path: entry.path }), `Deleted ${entry.name}`);
}

async function createFolder() {
  const name = await promptDialog({
    title: "New folder",
    message: `Create a folder in ${state.currentPath}`,
    placeholder: "Folder name",
    validate: nameError,
    confirmLabel: "Create"
  });
  if (!name) return;
  runFileAction(() => postJSON("/api/files/mkdir", { path: state.currentPath, name }));
}

function setClipboard(item) {
  state.clipboard = item;
  $("clipboardBar").classList.toggle("hidden", !item);
  if (item) $("clipboardLabel").textContent = `${item.mode === "move" ? "Move" : "Copy"} “${item.name}”`;
}

function pasteClipboard() {
  const item = state.clipboard;
  if (!item) return;
  setClipboard(null);
  runFileAction(
    () => postJSON(`/api/files/${item.mode}`, { source: item.path, destination: state.currentPath }),
    `${item.mode === "move" ? "Moved" : "Copied"} ${item.name}`
  );
}

async function uploadOne(file, overwrite) {
  const data = new FormData();
  data.append("file", file);
  const query = `path=${encodeURIComponent(state.currentPath)}${overwrite ? "&overwrite=true" : ""}`;
  await api(`/api/upload?${query}`, { method: "POST", body: data });
}

async function uploadFiles(files) {
  let uploaded = 0;
  try {
    for (const [index, file] of files.entries()) {
      setFileStatus(`Uploading ${file.name} (${index + 1} of ${files.length})…`, true);
      try {
        await uploadOne(file, false);
      } catch (error) {
        if (error.status !== 409) throw error;
        const replace = await confirmDialog({
          title: "Replace file?",
          message: `“${file.name}” already exists in this folder.`,
          confirmLabel: "Replace",
          cancelLabel: "Skip",
          danger: true
        });
        if (!replace) continue;
        await uploadOne(file, true);
      }
      uploaded += 1;
    }
    setFileStatus(uploaded ? `Uploaded ${uploaded} file${uploaded === 1 ? "" : "s"}` : "", true);
  } catch (error) {
    setFileStatus(error.message);
  }
  await loadFiles().catch(error => setFileStatus(error.message));
}

/* ---------- Terminals ---------- */

function withStyleNonce(callback) {
  const createElement = document.createElement;
  document.createElement = function (tagName, options) {
    const element = createElement.call(this, tagName, options);
    if (element instanceof HTMLStyleElement) element.setAttribute("nonce", styleNonce);
    return element;
  };
  try {
    callback();
  } finally {
    document.createElement = createElement;
  }
}

function updateTerminalEmptyState() {
  $("terminalEmpty").classList.toggle("hidden", terminals.size > 0);
}

function setTabState(entry, status) {
  entry.dot.className = `tab-state ${status}`;
  entry.dot.title = { online: "Connected", connecting: "Connecting…", offline: "Disconnected" }[status] || "";
}

function createTerminalEntry(info) {
  const container = document.createElement("div");
  container.className = "terminal-view";
  terminalStack.append(container);

  const term = new Terminal(TERMINAL_OPTIONS);
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  withStyleNonce(() => term.open(container));
  container.addEventListener("pointerdown", () => term.focus());

  const tab = document.createElement("div");
  tab.className = "tab";
  const dot = document.createElement("span");
  const label = document.createElement("button");
  label.type = "button";
  label.className = "tab-label";
  label.textContent = info.title;
  const entry = {
    id: info.id,
    title: info.title,
    term,
    fit,
    container,
    tab,
    dot,
    socket: null,
    retries: 0,
    retryTimer: 0,
    disposed: false,
    replaced: false
  };
  label.addEventListener("click", () => activateTerminal(entry.id));
  tab.append(dot, label, iconButton("✕", `Close ${info.title}`, () => closeTerminal(entry), "danger"));
  terminalTabs.append(tab);

  term.onData(data => sendInput(entry, data));
  term.onResize(({ cols, rows }) => sendMessage(entry, { type: "resize", cols, rows }));

  terminals.set(entry.id, entry);
  updateTerminalEmptyState();
  connectTerminal(entry);
  return entry;
}

function connectTerminal(entry) {
  clearTimeout(entry.retryTimer);
  if (entry.disposed) return;
  entry.replaced = false;
  setTabState(entry, "connecting");

  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${scheme}//${location.host}/ws/terminals/${encodeURIComponent(entry.id)}`);
  socket.binaryType = "arraybuffer";
  entry.socket = socket;

  socket.addEventListener("open", () => {
    entry.retries = 0;
    setTabState(entry, "online");
    // The server replays recent output on every attach.
    entry.term.reset();
    entry.fit.fit();
    sendMessage(entry, { type: "resize", cols: entry.term.cols, rows: entry.term.rows });
  });
  socket.addEventListener("message", event => {
    if (event.data instanceof ArrayBuffer) entry.term.write(new Uint8Array(event.data));
  });
  socket.addEventListener("close", event => {
    if (entry.socket !== socket) return;
    entry.socket = null;
    if (entry.disposed) return;
    if (event.code === 1000 || event.code === 4404) {
      removeTerminal(entry);
    } else if (event.code === 4401) {
      handleSignedOut("Your session ended. Please sign in again.");
    } else if (event.code === 4409) {
      entry.replaced = true;
      setTabState(entry, "offline");
      entry.term.write("\r\n\x1b[2m[Opened in another window. Select this tab to take it back.]\x1b[0m\r\n");
    } else {
      scheduleReconnect(entry);
    }
  });
}

function scheduleReconnect(entry) {
  setTabState(entry, "connecting");
  const delay = Math.min(15000, 1000 * 2 ** entry.retries);
  entry.retries += 1;
  entry.retryTimer = setTimeout(() => connectTerminal(entry), delay);
}

function sendMessage(entry, message) {
  if (entry.socket && entry.socket.readyState === WebSocket.OPEN) {
    entry.socket.send(JSON.stringify(message));
  }
}

function sendInput(entry, data) {
  // Large pastes are split so each message stays under the server's input limit.
  for (let start = 0; start < data.length;) {
    let end = Math.min(start + INPUT_CHUNK_CHARS, data.length);
    if (end < data.length && /[\uD800-\uDBFF]/.test(data[end - 1])) end -= 1;
    sendMessage(entry, { type: "input", data: data.slice(start, end) });
    start = end;
  }
}

function activateTerminal(id) {
  const entry = terminals.get(id);
  if (!entry) return;
  activeTerminalId = id;
  for (const other of terminals.values()) {
    const active = other === entry;
    other.container.classList.toggle("active", active);
    other.tab.classList.toggle("active", active);
  }
  sessionStorage.setItem(ACTIVE_TERMINAL_KEY, id);
  entry.fit.fit();
  if (entry.replaced) connectTerminal(entry);
  entry.term.focus();
  entry.tab.scrollIntoView({ block: "nearest", inline: "nearest" });
}

async function openNewTerminal() {
  try {
    const info = await postJSON("/api/terminals");
    createTerminalEntry(info);
    activateTerminal(info.id);
  } catch (error) {
    showMessage("Could not open a terminal", error.message);
  }
}

async function closeTerminal(entry) {
  const confirmed = await confirmDialog({
    title: `Close ${entry.title}?`,
    message: "Programs running in this terminal will be stopped.",
    confirmLabel: "Close",
    danger: true
  });
  if (!confirmed) return;
  try {
    await api(`/api/terminals/${encodeURIComponent(entry.id)}`, { method: "DELETE" });
  } catch (error) {
    if (error.status !== 404) {
      showMessage("Could not close the terminal", error.message);
      return;
    }
  }
  removeTerminal(entry);
}

function disposeTerminal(entry) {
  entry.disposed = true;
  clearTimeout(entry.retryTimer);
  if (entry.socket) entry.socket.close();
  entry.socket = null;
  entry.term.dispose();
  entry.container.remove();
  entry.tab.remove();
  terminals.delete(entry.id);
}

function removeTerminal(entry) {
  const ids = [...terminals.keys()];
  const index = ids.indexOf(entry.id);
  const wasActive = activeTerminalId === entry.id;
  disposeTerminal(entry);
  if (wasActive) {
    activeTerminalId = null;
    const next = ids[index + 1] ?? ids[index - 1];
    if (next) activateTerminal(next);
  }
  updateTerminalEmptyState();
}

function disposeAllTerminals() {
  for (const entry of [...terminals.values()]) disposeTerminal(entry);
  activeTerminalId = null;
  updateTerminalEmptyState();
}

async function initTerminals() {
  await document.fonts.load('14px "JetBrains Mono"').catch(() => {});
  const { terminals: list } = await getJSON("/api/terminals");
  if (!list.length) list.push(await postJSON("/api/terminals"));
  for (const info of list) {
    if (!terminals.has(info.id)) createTerminalEntry(info);
  }
  const remembered = sessionStorage.getItem(ACTIVE_TERMINAL_KEY);
  activateTerminal(terminals.has(remembered) ? remembered : list[0].id);
}

/* ---------- System stats ---------- */

function statChip(label, value, title, level) {
  const chip = document.createElement("span");
  chip.className = `stat ${level}`.trim();
  chip.title = title;
  const name = document.createElement("span");
  name.className = "stat-label";
  name.textContent = label;
  chip.append(name, value);
  return chip;
}

const level = (value, warn, hot) => (value >= hot ? "hot" : value >= warn ? "warn" : "");

function renderStats(stats) {
  const chips = [];
  if (stats.cpu != null) {
    const title = stats.load != null ? `1-minute load average: ${stats.load}` : "CPU usage";
    chips.push(statChip("CPU", `${Math.round(stats.cpu)}%`, title, level(stats.cpu, 75, 90)));
  }
  if (stats.memory) {
    const { used, total, percent } = stats.memory;
    chips.push(statChip("RAM", `${Math.round(percent)}%`, `${formatSize(used)} of ${formatSize(total)} used`, level(percent, 80, 92)));
  }
  if (stats.disk) {
    const { used, total, percent, path } = stats.disk;
    chips.push(statChip("Disk", `${Math.round(percent)}%`, `${formatSize(used)} of ${formatSize(total)} used (${path})`, level(percent, 85, 95)));
  }
  if (stats.temperature != null) {
    chips.push(statChip("Temp", `${Math.round(stats.temperature)}°C`, "SoC temperature", level(stats.temperature, 70, 80)));
  }
  statsBar.replaceChildren(...chips);
}

async function refreshStats() {
  if (document.hidden || appView.classList.contains("hidden")) return;
  try {
    renderStats(await getJSON("/api/stats"));
  } catch {}
}

function startPolling() {
  stopPolling();
  refreshStats();
  checkForUpdates();
  state.statsTimer = setInterval(refreshStats, STATS_INTERVAL_MS);
  state.updateTimer = setInterval(checkForUpdates, UPDATE_CHECK_INTERVAL_MS);
}

function stopPolling() {
  clearInterval(state.statsTimer);
  clearInterval(state.updateTimer);
  statsBar.replaceChildren();
}

/* ---------- Updates ---------- */

async function checkForUpdates(refresh = false) {
  let status;
  try {
    status = await getJSON(`/api/update${refresh ? "?refresh=true" : ""}`);
  } catch {
    return null;
  }
  state.updateStatus = status;
  versionButton.classList.toggle("hidden", !status.enabled);
  const available = Boolean(status.enabled && status.behind > 0);
  updateButton.classList.toggle("hidden", !available);
  if (status.enabled) {
    versionButton.textContent = status.current;
    versionButton.title = `Running ${status.current} tracking ${status.upstream}. Click to check for updates.`;
  }
  if (available) {
    updateButton.textContent = `Update available (${status.behind})`;
    updateButton.title = status.commits.join("\n");
  }
  return status;
}

async function manualUpdateCheck() {
  versionButton.disabled = true;
  try {
    const status = await checkForUpdates(true);
    if (status && status.enabled && !status.behind) {
      if (status.error) showMessage("Update check failed", status.error);
      else showMessage("Up to date", `WebSSH ${status.current} is the latest version on ${status.upstream}.`);
    }
  } finally {
    versionButton.disabled = false;
  }
}

async function startUpdate() {
  const status = state.updateStatus;
  if (!status || !status.behind) return;
  const plural = status.behind === 1 ? "" : "s";
  const confirmed = await confirmDialog({
    title: "Update WebSSH",
    message:
      `${status.behind} new commit${plural} from ${status.upstream}.\n` +
      "The service will restart. Open terminals will close and you will need to sign in again.",
    items: status.commits,
    confirmLabel: "Update and restart"
  });
  if (!confirmed) return;

  let boot;
  try {
    ({ boot } = await postJSON("/api/update"));
  } catch (error) {
    showMessage("Update failed", error.message);
    return;
  }
  showOverlay("Updating WebSSH… This page will reload when the service is back.");
  waitForRestart(boot);
}

async function waitForRestart(previousBoot) {
  const deadline = Date.now() + RESTART_TIMEOUT_MS;
  for (let attempt = 1; Date.now() < deadline; attempt += 1) {
    await sleep(2000);
    try {
      const response = await fetch("/api/health", { cache: "no-store" });
      if (!response.ok) continue;
      const { boot } = await response.json();
      if (boot !== previousBoot) {
        location.reload();
        return;
      }
      // Still the old process: surface a failed update instead of waiting for the timeout.
      if (attempt % 5 === 0) {
        const status = await checkForUpdates();
        if (status && !status.updating && status.error) {
          showMessage("Update failed", status.error);
          return;
        }
      }
    } catch {}
  }
  showMessage("Update timed out", "The update did not finish in time. Check update.log on the server.");
}

/* ---------- Event wiring ---------- */

$("loginForm").addEventListener("submit", async event => {
  event.preventDefault();
  loginError.textContent = "";
  const form = new FormData(event.currentTarget);
  try {
    const info = await postJSON("/api/login", { username: form.get("username"), password: form.get("password") });
    $("password").value = "";
    await showApp(info);
  } catch (error) {
    loginError.textContent = error.message;
  }
});

$("logoutButton").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST" });
  } catch {}
  handleSignedOut();
});

$("upButton").addEventListener("click", () => {
  if (state.currentPath !== "/") navigate(state.currentPath.slice(0, state.currentPath.lastIndexOf("/")) || "/");
});
$("homeButton").addEventListener("click", () => navigate(state.homePath));
$("newFolderButton").addEventListener("click", createFolder);
$("uploadButton").addEventListener("click", () => $("uploadInput").click());
$("uploadInput").addEventListener("change", async event => {
  const files = Array.from(event.target.files || []);
  event.target.value = "";
  if (files.length) await uploadFiles(files);
});
$("pasteButton").addEventListener("click", pasteClipboard);
$("clearClipboardButton").addEventListener("click", () => setClipboard(null));

$("pathForm").addEventListener("submit", event => {
  event.preventDefault();
  let path = pathInput.value.trim();
  if (!path) {
    pathInput.value = state.currentPath;
    return;
  }
  if (path === "~") path = state.homePath;
  else if (path.startsWith("~/")) path = `${state.homePath}/${path.slice(2)}`;
  else if (!path.startsWith("/")) path = `${state.currentPath.replace(/\/$/, "")}/${path}`;
  navigate(path.replace(/\/{2,}/g, "/"));
});

$("newTerminalButton").addEventListener("click", openNewTerminal);
$("emptyNewTerminalButton").addEventListener("click", openNewTerminal);
versionButton.addEventListener("click", manualUpdateCheck);
updateButton.addEventListener("click", startUpdate);
$("modalForm").addEventListener("submit", event => {
  event.preventDefault();
  if (!modalState) return;
  if (!modalState.withInput) {
    settleModal(true);
    return;
  }
  const value = modalInput.value.trim();
  const error = modalState.validate ? modalState.validate(value) : "";
  if (error) {
    $("modalError").textContent = error;
    modalInput.focus();
    return;
  }
  settleModal(value);
});
$("modalCancel").addEventListener("click", () => settleModal(null));
modalInput.addEventListener("input", () => {
  $("modalError").textContent = "";
});
// Escape key and backdrop clicks cancel the dialog.
modal.addEventListener("cancel", event => {
  event.preventDefault();
  settleModal(null);
});
modal.addEventListener("click", event => {
  if (event.target === modal) settleModal(null);
});

let resizeFrame = 0;
// Refits on window resizes and splitter drags alike.
new ResizeObserver(() => {
  if (resizeFrame) return;
  resizeFrame = requestAnimationFrame(() => {
    resizeFrame = 0;
    for (const entry of terminals.values()) entry.fit.fit();
  });
}).observe(terminalStack);

/* ---------- Panel splitter ---------- */

const workspace = $("workspace");
const splitter = $("splitter");
const filesPanel = $("filesPanel");

function setFilesWidth(width) {
  const max = workspace.clientWidth - splitter.offsetWidth - MIN_TERMINAL_WIDTH;
  const clamped = Math.round(Math.max(MIN_FILES_WIDTH, Math.min(width, max)));
  workspace.style.setProperty("--files-width", `${clamped}px`);
}

function saveFilesWidth() {
  localStorage.setItem(FILES_WIDTH_KEY, String(Math.round(filesPanel.getBoundingClientRect().width)));
}

splitter.addEventListener("pointerdown", event => {
  if (event.button !== 0) return;
  event.preventDefault();
  splitter.setPointerCapture(event.pointerId);
  const grabOffset = event.clientX - splitter.getBoundingClientRect().left;
  const onMove = moveEvent => {
    setFilesWidth(moveEvent.clientX - workspace.getBoundingClientRect().left - grabOffset);
  };
  document.body.classList.add("resizing");
  splitter.addEventListener("pointermove", onMove);
  splitter.addEventListener(
    "lostpointercapture",
    () => {
      splitter.removeEventListener("pointermove", onMove);
      document.body.classList.remove("resizing");
      saveFilesWidth();
    },
    { once: true }
  );
});

splitter.addEventListener("keydown", event => {
  const delta = { ArrowLeft: -SPLITTER_KEY_STEP, ArrowRight: SPLITTER_KEY_STEP }[event.key];
  if (!delta) return;
  event.preventDefault();
  setFilesWidth(filesPanel.getBoundingClientRect().width + delta);
  saveFilesWidth();
});

splitter.addEventListener("dblclick", () => {
  workspace.style.removeProperty("--files-width");
  localStorage.removeItem(FILES_WIDTH_KEY);
});

const savedFilesWidth = Number(localStorage.getItem(FILES_WIDTH_KEY));
if (savedFilesWidth > 0) workspace.style.setProperty("--files-width", `${savedFilesWidth}px`);

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refreshStats();
});

getJSON("/api/session")
  .then(showApp)
  .catch(() => showLogin());

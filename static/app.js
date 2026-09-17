const STORAGE_KEYS = {
  activeJob: "unzip-allinone:activeJob",
  lastRoot: "unzip-allinone:lastRoot",
  scanCache: "unzip-allinone:scanCache",
};

const state = {
  root: "",
  parent: "",
  archives: [],
  currentJob: "",
  events: new Map(),
  scanDepth: 5,
  includeHidden: false,
  lastJob: null,
  retryArchives: [],
  searchQuery: "",
  filterMode: "all",
  socket: null,
  eventSource: null,
  reconnectTimer: null,
  reconnectAttempts: 0,
  jobTotal: 0,
  resuming: false,
  hasScanned: false,
  jobStartedAt: 0,
  elapsedTimer: null,
  searchTimer: null,
  extracting: false,
};

const $ = (id) => document.getElementById(id);

const els = {
  serverState: $("serverState"),
  rootPath: $("rootPath"),
  upButton: $("upButton"),
  openPathButton: $("openPathButton"),
  dirList: $("dirList"),
  scanButton: $("scanButton"),
  scanDepth: $("scanDepth"),
  includeHidden: $("includeHidden"),
  recommendedButton: $("recommendedButton"),
  selectAllButton: $("selectAllButton"),
  extractButton: $("extractButton"),
  deleteOriginal: $("deleteOriginal"),
  globalPassword: $("globalPassword"),
  globalPasswordHint: $("globalPasswordHint"),
  conflictPolicy: $("conflictPolicy"),
  applyPasswordButton: $("applyPasswordButton"),
  togglePasswordVisibility: $("togglePasswordVisibility"),
  summaryText: $("summaryText"),
  searchInput: $("searchInput"),
  filterMode: $("filterMode"),
  resultList: $("resultList"),
  jobResult: $("jobResult"),
  retryPanel: $("retryPanel"),
  progressPanel: $("progressPanel"),
  jobSummary: $("jobSummary"),
  overallBar: $("overallBar"),
  overallBarHost: $("overallBarHost"),
  overallPercent: $("overallPercent"),
  overallRingValue: $("overallRingValue"),
  eventLog: $("eventLog"),
  cancelButton: $("cancelButton"),
  resumeBanner: $("resumeBanner"),
  toastHost: $("toastHost"),
  statsRow: $("statsRow"),
  controlsBar: $("controlsBar"),
  passwordPanel: $("passwordPanel"),
  actionDock: $("actionDock"),
  dockCount: $("dockCount"),
  dockHint: $("dockHint"),
  dockSelectAll: $("dockSelectAll"),
  dockExtract: $("dockExtract"),
  statTotal: $("statTotal"),
  statSelected: $("statSelected"),
  statMultipart: $("statMultipart"),
  statSize: $("statSize"),
  breadcrumbs: $("breadcrumbs"),
  copyPathButton: $("copyPathButton"),
  searchClear: $("searchClear"),
  progressMeta: $("progressMeta"),
  progressCounts: $("progressCounts"),
  progressElapsed: $("progressElapsed"),
  content: document.querySelector(".content"),
};

const RING_CIRCUMFERENCE = 2 * Math.PI * 18;

/* Terminal job statuses. "partial"/"failed" join "done"/"cancelled" so a job
   where some or all archives failed is reported as such instead of a green ✓. */
const TERMINAL_JOB_STATUSES = ["done", "partial", "failed", "cancelled"];

const isTerminalJobStatus = (status) => TERMINAL_JOB_STATUSES.includes(status);

const JOB_OUTCOME = {
  done: { pill: "全部成功", kind: "done", title: "全部成功", icon: "✓", toast: "success" },
  partial: { pill: "部分失败", kind: "warn", title: "部分完成", icon: "!", toast: "info" },
  failed: { pill: "全部失败", kind: "error", title: "全部失败", icon: "✕", toast: "error" },
  cancelled: { pill: "已取消", kind: "warn", title: "处理已取消", icon: "–", toast: "info" },
};

const outcomeOf = (status) => JOB_OUTCOME[status] || JOB_OUTCOME.done;

/* ── Status & feedback ── */

function setStateText(text, kind = "idle") {
  const statusEl = els.serverState;
  if (!statusEl) return;
  const label = statusEl.querySelector(".status-text") || statusEl;
  label.textContent = text;
  // Callers always pass an explicit kind. Inferring it from the label text used
  // to mis-tag states — "已取消" matched the "取消" busy rule and never reached warn.
  statusEl.dataset.state = kind;
}

function toast(message, type = "info", duration = 3800) {
  if (!els.toastHost) return;
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  const icon = type === "error" ? "!" : type === "success" ? "✓" : "i";
  el.innerHTML = `<span class="toast-icon">${icon}</span><span>${escapeHtml(message)}</span>`;
  els.toastHost.appendChild(el);
  window.setTimeout(() => {
    el.classList.add("is-leaving");
    window.setTimeout(() => el.remove(), 240);
  }, duration);
}

function showError(err) {
  console.error(err);
  const msg = err?.message || String(err);
  setStateText("错误", "error");
  toast(msg, "error", 5200);
  if (els.summaryText && !state.archives.length) {
    els.summaryText.textContent = msg;
  }
}

function setButtonLoading(button, loading) {
  if (!button) return;
  button.classList.toggle("is-loading", loading);
  if (loading) button.setAttribute("aria-busy", "true");
  else button.removeAttribute("aria-busy");
}

function updateStepRail() {
  const steps = document.querySelectorAll(".step-rail .step");
  if (!steps.length) return;
  let active = 1;
  if (state.currentJob) active = 3;
  else if (state.archives.length || state.hasScanned) active = 2;

  steps.forEach((step) => {
    const n = Number(step.dataset.step);
    step.classList.toggle("is-active", n === active);
    step.classList.toggle("is-done", n < active);
  });
}

/* ── API & storage ── */

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function saveActiveJob(payload) {
  try {
    localStorage.setItem(STORAGE_KEYS.activeJob, JSON.stringify(payload));
  } catch (_) {}
}

function loadActiveJob() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.activeJob);
    return raw ? JSON.parse(raw) : null;
  } catch (_) {
    return null;
  }
}

function clearActiveJob() {
  try {
    localStorage.removeItem(STORAGE_KEYS.activeJob);
  } catch (_) {}
}

function saveLastRoot(path) {
  try {
    if (path) localStorage.setItem(STORAGE_KEYS.lastRoot, path);
  } catch (_) {}
}

function loadLastRoot() {
  try {
    return localStorage.getItem(STORAGE_KEYS.lastRoot) || "";
  } catch (_) {
    return "";
  }
}

function saveScanCache() {
  try {
    sessionStorage.setItem(
      STORAGE_KEYS.scanCache,
      JSON.stringify({
        root: state.root,
        scanDepth: state.scanDepth,
        includeHidden: state.includeHidden,
        archives: state.archives,
        hasScanned: state.hasScanned,
      })
    );
  } catch (_) {}
}

function loadScanCache() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEYS.scanCache);
    return raw ? JSON.parse(raw) : null;
  } catch (_) {
    return null;
  }
}

/* ── Password slang ── */

const PASSWORD_SLANG = [
  ["点斜点", "./."],
  ["点斜杠点", "./."],
  ["点反斜点", ".\\."],
  ["点斜杠", "./"],
  ["斜杠点", "/."],
  ["星号", "*"],
  ["星星", "*"],
  ["下划线", "_"],
  ["中划线", "-"],
  ["横杠", "-"],
  ["减号", "-"],
  ["加号", "+"],
  ["等号", "="],
  ["井号", "#"],
  ["井", "#"],
  ["百分号", "%"],
  ["感叹号", "!"],
  ["叹号", "!"],
  ["问号", "?"],
  ["艾特", "@"],
  ["小老鼠", "@"],
  ["美元", "$"],
  ["与号", "&"],
  ["空格", " "],
  ["左括号", "("],
  ["右括号", ")"],
  ["左方括号", "["],
  ["右方括号", "]"],
  ["反斜杠", "\\"],
  ["斜杠", "/"],
  ["斜", "/"],
  ["星", "*"],
  ["点", "."],
  ["杠", "-"],
];

function decodePasswordSlang(password) {
  if (!password) return password;
  let out = String(password);
  for (const [from, to] of PASSWORD_SLANG) {
    if (out.includes(from)) out = out.split(from).join(to);
  }
  return out;
}

function updatePasswordHint() {
  if (!els.globalPasswordHint) return;
  const raw = els.globalPassword.value;
  if (!raw) {
    els.globalPasswordHint.hidden = true;
    els.globalPasswordHint.textContent = "";
    return;
  }
  const decoded = decodePasswordSlang(raw);
  if (decoded !== raw) {
    els.globalPasswordHint.hidden = false;
    els.globalPasswordHint.textContent = `黑话转换后：${decoded}`;
  } else {
    els.globalPasswordHint.hidden = true;
    els.globalPasswordHint.textContent = "";
  }
}

/* ── Directory browser ── */

function showDirSkeleton() {
  if (!els.dirList) return;
  els.dirList.innerHTML = `
    <div class="dir-skeleton" aria-hidden="true">
      <div class="skel-line"></div>
      <div class="skel-line"></div>
      <div class="skel-line"></div>
      <div class="skel-line"></div>
      <div class="skel-line"></div>
    </div>`;
}

function renderBreadcrumbs(path) {
  if (!els.breadcrumbs) return;
  const raw = String(path || "").trim();
  if (!raw) {
    els.breadcrumbs.innerHTML = "";
    return;
  }
  const isAbs = raw.startsWith("/");
  const parts = raw.split("/").filter(Boolean);
  const items = [];
  if (isAbs) items.push({ label: "根目录", path: "/" });
  let built = "";
  for (const part of parts) {
    built = isAbs ? `${built}/${part}` : built ? `${built}/${part}` : part;
    items.push({ label: part, path: built });
  }

  els.breadcrumbs.innerHTML = items
    .map((item, i) => {
      const isLast = i === items.length - 1;
      const btn = isLast
        ? `<button type="button" class="is-current" disabled title="${escapeAttr(item.path)}">${escapeHtml(item.label)}</button>`
        : `<button type="button" data-path="${escapeAttr(item.path)}" title="${escapeAttr(item.path)}">${escapeHtml(item.label)}</button>`;
      const sep = i < items.length - 1 ? `<span class="crumb-sep">/</span>` : "";
      return `<span class="crumb">${btn}</span>${sep}`;
    })
    .join("");

  els.breadcrumbs.querySelectorAll("button[data-path]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (state.currentJob) return;
      loadDirs(btn.dataset.path).catch(showError);
    });
  });
}

async function loadDirs(path = "") {
  setStateText("读取目录", "busy");
  showDirSkeleton();
  const query = path ? `?path=${encodeURIComponent(path)}` : "";
  try {
    const data = await api(`/api/dirs${query}`, { method: "GET", headers: {} });
    state.root = data.path;
    state.parent = data.parent || "";
    els.rootPath.value = data.path;
    els.upButton.disabled = !state.parent || Boolean(state.currentJob);
    renderBreadcrumbs(data.path);
    renderDirs(data.dirs);
    saveLastRoot(data.path);
    setStateText(state.currentJob ? "解压中" : "就绪", state.currentJob ? "busy" : "idle");
    updateStepRail();
  } catch (err) {
    els.dirList.innerHTML = `<div class="dir-empty">无法读取目录<br>${escapeHtml(err.message || String(err))}</div>`;
    throw err;
  }
}

function renderDirs(dirs) {
  els.dirList.innerHTML = "";
  if (!dirs.length) {
    els.dirList.innerHTML = `<div class="dir-empty">没有下一级文件夹<br>若压缩包就在当前路径，可直接扫描</div>`;
    return;
  }
  const frag = document.createDocumentFragment();
  for (const dir of dirs) {
    const button = document.createElement("button");
    button.className = "dir-item";
    button.type = "button";
    button.title = dir.path;
    button.disabled = Boolean(state.currentJob);
    button.innerHTML = `<span class="folder-glyph"></span><span>${escapeHtml(dir.name)}</span>`;
    button.addEventListener("click", () => loadDirs(dir.path).catch(showError));
    frag.appendChild(button);
  }
  els.dirList.appendChild(frag);
}

async function copyCurrentPath() {
  const path = els.rootPath?.value?.trim() || state.root;
  if (!path) {
    toast("没有可复制的路径", "info");
    return;
  }
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(path);
    } else {
      const ta = document.createElement("textarea");
      ta.value = path;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    toast("路径已复制", "success", 1800);
  } catch (_) {
    toast("复制失败，请手动选择路径", "error");
  }
}

/* ── Scan ── */

async function scan() {
  const root = els.rootPath.value.trim();
  if (!root) {
    toast("请先选择或输入文件夹路径", "info");
    els.rootPath.focus();
    return;
  }
  if (state.currentJob) {
    toast("解压进行中，请等待完成或取消后再扫描", "error");
    return;
  }

  setBusy(true);
  setButtonLoading(els.scanButton, true);
  setStateText("扫描中", "busy");
  hideJobResult();
  hideRetryPanel();

  try {
    const data = await api("/api/scan", {
      method: "POST",
      body: JSON.stringify({
        root,
        depth: Number.parseInt(els.scanDepth.value, 10) || 5,
        includeHidden: els.includeHidden.checked,
      }),
    });
    state.root = data.root;
    state.scanDepth = data.depth;
    state.includeHidden = data.includeHidden;
    state.hasScanned = true;
    state.archives = data.archives.map((archive) => ({
      ...archive,
      selected: true,
      password: "",
    }));
    state.events.clear();
    state.searchQuery = "";
    state.filterMode = "all";
    if (els.searchInput) els.searchInput.value = "";
    if (els.filterMode) els.filterMode.value = "all";
    syncSegmented();
    els.rootPath.value = data.root;
    saveLastRoot(data.root);
    saveScanCache();
    renderArchives();
    setStateText(data.archives.length ? "扫描完成" : "就绪", data.archives.length ? "done" : "idle");
    if (data.archives.length) {
      toast(`找到 ${data.archives.length} 个可解压文件`, "success");
      // Soft-scroll results into view on small screens
      els.resultList?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } else {
      toast("未找到 zip / 7z / 分卷文件", "info");
    }
  } catch (err) {
    showError(err);
  } finally {
    setButtonLoading(els.scanButton, false);
    setBusy(false);
  }
}

/* ── Archive list ── */

function renderArchives() {
  const count = state.archives.length;
  updateChromeVisibility(count > 0);

  if (!count) {
    els.summaryText.textContent = state.hasScanned
      ? `未找到可解压文件（深度 ${state.scanDepth} 层${state.includeHidden ? "，含隐藏项" : ""}）`
      : "在左侧选择文件夹并扫描";
    els.resultList.innerHTML = state.hasScanned
      ? emptyMarkup(
          "没有找到文件",
          `已扫描当前路径及最多 ${state.scanDepth} 层子目录${state.includeHidden ? "，并包含隐藏项" : ""}。支持 zip、7z 与分卷压缩包。`
        )
      : emptyMarkup(
          "准备开始",
          "在左侧进入存放压缩包的文件夹，点击「扫描此文件夹」。支持 zip、7z 与分卷。"
        );
    updateButtons();
    updateStats();
    updateDock();
    updateStepRail();
    return;
  }

  els.summaryText.textContent = `找到 ${count} 个可解压文件${state.includeHidden ? " · 含隐藏项" : ""}`;
  els.resultList.innerHTML = "";

  const visible = getVisibleArchives();
  if (!visible.length) {
    els.resultList.innerHTML = emptyMarkup("没有匹配结果", "试试清空搜索，或切换筛选条件。");
    updateButtons();
    updateStats();
    updateDock();
    updateStepRail();
    return;
  }

  const frag = document.createDocumentFragment();
  visible.forEach((archive, i) => {
    frag.appendChild(buildArchiveRow(archive, i));
  });
  els.resultList.appendChild(frag);

  updateButtons();
  updateStats();
  updateDock();
  updateStepRail();
}

function emptyMarkup(title, body) {
  return `
    <div class="empty-state">
      <div class="empty-icon" aria-hidden="true">
        <svg viewBox="0 0 80 80" width="64" height="64" fill="none">
          <rect x="14" y="22" width="52" height="40" rx="10" stroke="currentColor" stroke-width="2" opacity=".35"/>
          <path d="M28 22v-2a8 8 0 0 1 8-8h8a8 8 0 0 1 8 8v2" stroke="currentColor" stroke-width="2" opacity=".35"/>
          <path d="M40 36v16m0 0-6-6m6 6 6-6" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <h3>${escapeHtml(title)}</h3>
      <p>${escapeHtml(body)}</p>
    </div>`;
}

function buildArchiveRow(archive, index) {
  const row = document.createElement("article");
  const event = state.events.get(archive.id) || {};
  const status = event.status || "";
  const percent = progressOf(event);
  row.className = `archive-row ${status}`.trim();
  row.dataset.id = archive.id;
  row.style.animationDelay = `${Math.min(index, 12) * 28}ms`;

  const suggested = archive.defaultPassword || "";
  const suggestedDecoded = decodePasswordSlang(suggested);
  const suggestedLabel =
    suggestedDecoded !== suggested && suggested ? `${suggested} → ${suggestedDecoded}` : suggested || "—";
  const hasDecode = suggestedDecoded !== suggested && suggested;

  const pwdDisplay = archive.password || "";
  const pwdDecoded = decodePasswordSlang(pwdDisplay);
  const pwdHint =
    pwdDisplay && pwdDecoded !== pwdDisplay
      ? `<div class="pwd-decode-hint">将使用：${escapeHtml(pwdDecoded)}</div>`
      : "";

  const format = String(archive.format || "file").toUpperCase();
  const isMulti = archive.partCount > 1;

  row.innerHTML = `
    <label class="archive-check">
      <input type="checkbox" ${archive.selected ? "checked" : ""} ${state.currentJob ? "disabled" : ""} aria-label="选择 ${escapeHtml(archive.name)}">
      <span class="check-ui">
        <svg viewBox="0 0 12 12" width="12" height="12" fill="none" aria-hidden="true">
          <path d="M2.5 6.2 5 8.7 9.5 3.5" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </span>
    </label>
    <div class="archive-main">
      <div class="archive-name-row">
        <div class="archive-name" title="${escapeHtml(archive.relativeFile)}">${escapeHtml(archive.name)}</div>
        <span class="format-badge ${isMulti ? "multipart" : ""}">${isMulti ? `${archive.partCount} 分卷` : format}</span>
      </div>
      <div class="archive-meta">${formatLabel(archive)} · ${formatBytes(archive.totalBytes)}</div>
      <div class="archive-dir" title="${escapeHtml(archive.directory)}">${escapeHtml(archive.relativeDir)}</div>
      ${
        status
          ? `<div class="archive-status-line"><span class="status-chip ${status}">${escapeHtml(statusLabelFor(status, percent))}</span></div>
             <div class="archive-progress row-progress"><span style="width:${clamp(percent)}%"></span></div>`
          : ""
      }
    </div>
    <div class="metric">
      <span class="metric-label">建议密码</span>
      <span class="metric-value ${hasDecode ? "decoded" : ""}" title="${escapeHtml(suggestedDecoded || suggested)}">${escapeHtml(suggestedLabel)}</span>
    </div>
    <div class="archive-password-wrap">
      <input class="control archive-password" type="password" placeholder="留空使用建议密码" value="${escapeAttr(archive.password)}" ${state.currentJob ? "disabled" : ""}>
      ${pwdHint}
    </div>
  `;

  const checkbox = row.querySelector('input[type="checkbox"]');
  const password = row.querySelector(".archive-password");
  checkbox.addEventListener("change", () => {
    archive.selected = checkbox.checked;
    updateStats();
    updateButtons();
    updateDock();
    saveScanCache();
  });
  password.addEventListener("input", () => {
    archive.password = password.value;
    saveScanCache();
    const wrap = password.closest(".archive-password-wrap");
    const decoded = decodePasswordSlang(password.value);
    let hint = wrap.querySelector(".pwd-decode-hint");
    if (password.value && decoded !== password.value) {
      if (!hint) {
        hint = document.createElement("div");
        hint.className = "pwd-decode-hint";
        wrap.appendChild(hint);
      }
      hint.textContent = `将使用：${decoded}`;
    } else if (hint) {
      hint.remove();
    }
  });

  return row;
}

function progressOf(event) {
  if (!event) return 0;
  if (event.status === "done" || event.status === "warning") return 100;
  return Number.isFinite(event.percent) ? event.percent : 0;
}

function statusLabelFor(status, percent) {
  switch (status) {
    case "running":
      return `解压中 ${percent || 0}%`;
    case "done":
      return "已完成";
    case "failed":
      return "失败";
    case "warning":
      return "完成（告警）";
    case "cancelled":
      return "已取消";
    default:
      return status || "";
  }
}

function updateChromeVisibility(hasArchives) {
  if (els.statsRow) els.statsRow.hidden = !hasArchives;
  if (els.controlsBar) els.controlsBar.hidden = !hasArchives;
  if (els.passwordPanel) els.passwordPanel.hidden = !hasArchives;
}

function updateStats() {
  if (!els.statsRow || els.statsRow.hidden) return;
  const selected = state.archives.filter((a) => a.selected);
  const multi = state.archives.filter((a) => a.partCount > 1).length;
  const totalBytes = state.archives.reduce((s, a) => s + (a.totalBytes || 0), 0);
  if (els.statTotal) els.statTotal.textContent = String(state.archives.length);
  if (els.statSelected) els.statSelected.textContent = String(selected.length);
  if (els.statMultipart) els.statMultipart.textContent = String(multi);
  if (els.statSize) els.statSize.textContent = formatBytes(totalBytes);
  updateSegmentCounts();
}

function updateSegmentCounts() {
  const counts = { all: state.archives.length, selected: 0, pending: 0, done: 0, failed: 0 };
  for (const archive of state.archives) {
    if (archive.selected) counts.selected += 1;
    const event = state.events.get(archive.id) || {};
    if (!event.status || event.status === "running") counts.pending += 1;
    if (event.status === "done" || event.status === "warning") counts.done += 1;
    if (event.status === "failed") counts.failed += 1;
  }
  document.querySelectorAll(".seg-count").forEach((el) => {
    const key = el.dataset.count;
    const n = counts[key];
    el.textContent = n ? String(n) : "";
  });
}

function updateDock() {
  const selected = state.archives.filter((a) => a.selected).length;
  const show = state.archives.length > 0 && !state.currentJob;
  if (els.actionDock) {
    els.actionDock.hidden = !show;
    document.body.classList.toggle("has-dock", show);
  }
  document.body.classList.toggle("is-extracting", Boolean(state.currentJob));
  if (els.content) els.content.classList.toggle("is-working", Boolean(state.currentJob));
  if (els.progressPanel) els.progressPanel.classList.toggle("is-live", Boolean(state.currentJob));
  if (els.dockCount) els.dockCount.textContent = `已选 ${selected} / ${state.archives.length}`;
  if (els.dockHint) {
    const bytes = state.archives.filter((a) => a.selected).reduce((s, a) => s + (a.totalBytes || 0), 0);
    els.dockHint.textContent =
      selected === 0
        ? "请至少选择一个文件"
        : `约 ${formatBytes(bytes)} · 输出到各压缩包所在目录`;
  }
  if (els.dockExtract) els.dockExtract.disabled = selected === 0;
  if (els.dockSelectAll) {
    const all = state.archives.length > 0 && state.archives.every((a) => a.selected);
    els.dockSelectAll.textContent = all ? "取消全选" : "全选";
  }
}

function startElapsedTimer() {
  stopElapsedTimer();
  state.jobStartedAt = Date.now();
  if (els.progressMeta) els.progressMeta.hidden = false;
  tickElapsed();
  state.elapsedTimer = window.setInterval(tickElapsed, 1000);
}

function stopElapsedTimer() {
  if (state.elapsedTimer) {
    clearInterval(state.elapsedTimer);
    state.elapsedTimer = null;
  }
}

function tickElapsed() {
  if (!els.progressElapsed) return;
  const ms = Math.max(0, Date.now() - (state.jobStartedAt || Date.now()));
  els.progressElapsed.textContent = formatDuration(ms);
  updateProgressCounts();
}

function updateProgressCounts() {
  if (!els.progressCounts) return;
  const total = state.jobTotal || state.events.size || 0;
  let finished = 0;
  let running = 0;
  for (const event of state.events.values()) {
    if (["done", "failed", "warning", "cancelled"].includes(event.status)) finished += 1;
    if (event.status === "running") running += 1;
  }
  els.progressCounts.textContent =
    running > 0 ? `${finished} 完成 · ${running} 进行中 / ${total}` : `${finished} / ${total} 完成`;
}

function formatDuration(ms) {
  const totalSec = Math.floor(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  if (m >= 60) {
    const h = Math.floor(m / 60);
    const mm = m % 60;
    return `${h}:${String(mm).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function updateButtons() {
  const selected = state.archives.filter((a) => a.selected).length;
  const busy = Boolean(state.currentJob);
  els.extractButton.disabled = selected === 0 || busy;
  els.selectAllButton.disabled = state.archives.length === 0 || busy;
  els.recommendedButton.hidden = state.archives.length === 0;
  els.recommendedButton.disabled = busy;
  els.selectAllButton.textContent =
    selected === state.archives.length && state.archives.length > 0 ? "取消全选" : "全选";
  if (els.cancelButton) els.cancelButton.disabled = !busy;
}

function toggleSelectAll() {
  if (state.currentJob) return;
  const allSelected = state.archives.length > 0 && state.archives.every((a) => a.selected);
  for (const a of state.archives) a.selected = !allSelected;
  renderArchives();
  saveScanCache();
}

function applyGlobalPassword() {
  if (state.currentJob) return;
  const password = els.globalPassword.value;
  let n = 0;
  for (const a of state.archives) {
    if (a.selected) {
      a.password = password;
      n += 1;
    }
  }
  renderArchives();
  saveScanCache();
  if (n) toast(`已将密码应用到 ${n} 个已选文件`, "success", 2400);
  else toast("请先选择文件", "info");
}

function applyRecommendedSelection() {
  if (state.currentJob) return;
  for (const a of state.archives) {
    a.selected = a.partCount > 1 || a.totalBytes > 0;
  }
  renderArchives();
  saveScanCache();
  toast("已按建议选择文件", "success", 2200);
}

/* ── Extract & job streaming ── */

async function extract() {
  const selected = state.archives.filter((a) => a.selected);
  if (!selected.length) {
    toast("请至少选择一个文件", "info");
    return;
  }
  if (state.currentJob || state.extracting) return;
  state.extracting = true;

  const conflictPolicy = els.conflictPolicy.value;
  if (els.deleteOriginal.checked) {
    const ok = window.confirm(
      "你已开启「解压成功后删除原始分卷」。\n\n这是高风险操作，删除后无法自动恢复。是否继续？"
    );
    if (!ok) {
      state.extracting = false;
      return;
    }
  }
  if (conflictPolicy === "overwrite") {
    const ok = window.confirm(
      "当前策略是「覆盖已有文件」。\n\n目标目录中的同名文件会被覆盖。是否继续？"
    );
    if (!ok) {
      state.extracting = false;
      return;
    }
  }

  setBusy(true);
  setButtonLoading(els.extractButton, true);
  if (els.dockExtract) setButtonLoading(els.dockExtract, true);

  state.events.clear();
  state.lastJob = null;
  state.retryArchives = [];
  state.jobTotal = selected.length;
  els.eventLog.innerHTML = "";
  setOverallProgress(0);
  els.progressPanel.hidden = false;
  hideJobResult();
  hideRetryPanel();
  hideResumeBanner();
  els.jobSummary.textContent = `准备解压 ${selected.length} 个文件…`;
  setStateText("解压中", "busy");
  startElapsedTimer();
  updateStepRail();
  updateDock();
  els.progressPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });

  try {
    const data = await api("/api/extract", {
      method: "POST",
      body: JSON.stringify({
        root: state.root || els.rootPath.value.trim(),
        deleteOriginal: els.deleteOriginal.checked,
        conflictPolicy,
        archives: selected.map((a) => ({
          id: a.id,
          path: a.path,
          password: a.password,
        })),
      }),
    });
    state.currentJob = data.jobId;
    saveActiveJob({
      jobId: data.jobId,
      root: state.root || els.rootPath.value.trim(),
      archives: state.archives,
      scanDepth: state.scanDepth,
      includeHidden: state.includeHidden,
      startedAt: Date.now(),
    });
    updateButtons();
    updateDock();
    connectJobProgress(data.jobId);
  } catch (err) {
    showError(err);
    setBusy(false);
    state.currentJob = "";
    stopElapsedTimer();
    updateDock();
  } finally {
    state.extracting = false;
    setButtonLoading(els.extractButton, false);
    if (els.dockExtract) setButtonLoading(els.dockExtract, false);
  }
}

function connectJobProgress(jobId) {
  closeJobStreams();
  state.reconnectAttempts = 0;
  openJobSocket(jobId);
}

function openJobSocket(jobId) {
  closeJobSocketOnly();
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${scheme}//${window.location.host}/api/jobs/${encodeURIComponent(jobId)}/ws`);
  state.socket = socket;

  socket.addEventListener("open", () => {
    state.reconnectAttempts = 0;
    setStateText("解压中", "busy");
  });

  socket.addEventListener("message", (msg) => {
    try {
      const event = JSON.parse(msg.data);
      handleJobEvent(event);
      if (event.type === "job" && isTerminalJobStatus(event.status)) {
        finishJobClient(event.status);
      }
    } catch (err) {
      console.error("bad job event", err);
    }
  });

  socket.addEventListener("error", () => {});
  socket.addEventListener("close", () => {
    if (state.socket === socket) state.socket = null;
    if (state.currentJob === jobId) scheduleReconnect(jobId);
  });
}

function openJobSSE(jobId) {
  closeEventSourceOnly();
  const es = new EventSource(`/api/jobs/${encodeURIComponent(jobId)}/events`);
  state.eventSource = es;
  es.onmessage = (msg) => {
    try {
      const event = JSON.parse(msg.data);
      handleJobEvent(event);
      if (event.type === "job" && isTerminalJobStatus(event.status)) {
        finishJobClient(event.status);
      }
    } catch (err) {
      console.error("bad sse event", err);
    }
  };
  es.onerror = () => {
    if (state.currentJob === jobId) {
      es.close();
      if (state.eventSource === es) state.eventSource = null;
      scheduleReconnect(jobId);
    }
  };
}

function scheduleReconnect(jobId) {
  if (state.reconnectTimer || !state.currentJob || state.currentJob !== jobId) return;
  state.reconnectAttempts += 1;
  if (state.reconnectAttempts > 12) {
    toast("进度连接多次失败，可刷新页面继续查看", "error");
    return;
  }
  const delay = Math.min(8000, 500 * state.reconnectAttempts);
  setStateText("重连进度…", "busy");
  state.reconnectTimer = setTimeout(async () => {
    state.reconnectTimer = null;
    if (state.currentJob !== jobId) return;
    try {
      const snap = await api(`/api/jobs/${encodeURIComponent(jobId)}`, { method: "GET", headers: {} });
      applyJobSnapshot(snap);
      if (snap.done) {
        const terminal = snap.events.find((e) => e.type === "job" && isTerminalJobStatus(e.status));
        finishJobClient(terminal?.status || snap.status || "done");
        return;
      }
      if (state.reconnectAttempts >= 2) openJobSSE(jobId);
      else openJobSocket(jobId);
    } catch (err) {
      const msg = String(err.message || "");
      if (msg.includes("not found") || msg.includes("404")) {
        clearActiveJob();
        state.currentJob = "";
        setBusy(false);
        setStateText("任务已失效", "error");
        if (els.jobSummary) els.jobSummary.textContent = "服务端已无此任务（可能已重启）。请重新开始解压。";
        updateButtons();
        updateDock();
        return;
      }
      scheduleReconnect(jobId);
    }
  }, delay);
}

function finishJobClient(status) {
  closeJobStreams();
  state.currentJob = "";
  clearActiveJob();
  setBusy(false);
  tickElapsed();
  stopElapsedTimer();
  const outcome = outcomeOf(status);
  setStateText(outcome.pill, outcome.kind);
  updateButtons();
  updateDock();
  updateStepRail();
  updateSegmentCounts();
  hideResumeBanner();

  const failed = Array.from(state.events.values()).filter((e) => e.status === "failed").length;
  if (status === "cancelled") {
    toast("任务已取消", "info");
  } else if (status === "failed") {
    toast(`全部 ${failed || state.jobTotal} 项均失败，请检查密码或文件完整性`, "error", 5200);
  } else if (failed) {
    toast(`${failed} 项失败，可修改密码后重试`, "info", 4200);
  } else {
    toast("全部任务处理完成", "success");
  }
}

function closeJobSocketOnly() {
  if (!state.socket) return;
  const socket = state.socket;
  state.socket = null;
  try {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) socket.close();
  } catch (_) {}
}

function closeEventSourceOnly() {
  if (!state.eventSource) return;
  try {
    state.eventSource.close();
  } catch (_) {}
  state.eventSource = null;
}

function closeJobStreams() {
  if (state.reconnectTimer) {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }
  closeJobSocketOnly();
  closeEventSourceOnly();
}

function handleJobEvent(event) {
  if (event.type === "job") {
    if (event.message) els.jobSummary.textContent = event.message;
    if (event.total) state.jobTotal = event.total;
    if (isTerminalJobStatus(event.status) && event.status !== "cancelled") setOverallProgress(100);
    if (isTerminalJobStatus(event.status)) {
      state.lastJob = event;
      renderJobResult();
      renderRetryPanel();
    }
    updateOverall();
    updateProgressCounts();
    updateSegmentCounts();
    return;
  }

  const key = event.archiveId || event.path;
  if (!key) return;
  const prev = state.events.get(key) || {};
  let next = { ...prev, ...event };
  if (
    prev.status === "running" &&
    event.status === "running" &&
    Number(prev.percent) > Number(event.percent || 0) &&
    !event.message
  ) {
    next.percent = prev.percent;
  }
  if (["done", "failed", "warning"].includes(prev.status) && event.status === "running") {
    next = prev;
  } else {
    state.events.set(key, next);
  }
  renderEventLog();
  updateOverall();
  updateProgressCounts();
  updateSegmentCounts();
  patchArchiveRow(key);
}

function patchArchiveRow(archiveId) {
  let row;
  try {
    row = els.resultList.querySelector(`[data-id="${CSS.escape(archiveId)}"]`);
  } catch (_) {
    row = els.resultList.querySelector(`[data-id="${archiveId}"]`);
  }
  if (!row) {
    if (state.archives.length <= 40) renderArchives();
    return;
  }
  const event = state.events.get(archiveId) || {};
  const status = event.status || "";
  const percent = progressOf(event);
  row.className = `archive-row ${status}`.trim();

  let statusLine = row.querySelector(".archive-status-line");
  let progress = row.querySelector(".row-progress");
  if (status) {
    if (!statusLine) {
      const main = row.querySelector(".archive-main");
      statusLine = document.createElement("div");
      statusLine.className = "archive-status-line";
      statusLine.innerHTML = `<span class="status-chip ${status}"></span>`;
      progress = document.createElement("div");
      progress.className = "archive-progress row-progress";
      progress.innerHTML = "<span></span>";
      main.appendChild(statusLine);
      main.appendChild(progress);
    }
    const chip = statusLine.querySelector(".status-chip");
    chip.className = `status-chip ${status}`;
    chip.textContent = statusLabelFor(status, percent);
    const bar = progress?.querySelector("span");
    if (bar) bar.style.width = `${clamp(percent)}%`;
  }
}

function applyJobSnapshot(snap) {
  if (!snap) return;
  state.jobTotal = snap.total || state.jobTotal || 0;
  if (snap.message) els.jobSummary.textContent = snap.message;
  els.progressPanel.hidden = false;

  for (const event of snap.events || []) {
    if (event.type === "job") {
      if (event.message) els.jobSummary.textContent = event.message;
      if (event.total) state.jobTotal = event.total;
      if (isTerminalJobStatus(event.status)) state.lastJob = event;
      continue;
    }
    const key = event.archiveId || event.path;
    if (key) state.events.set(key, event);
  }
  renderEventLog();
  updateOverall();
  renderArchives();
  if (state.lastJob) {
    renderJobResult();
    renderRetryPanel();
  }
}

function renderJobResult() {
  if (!state.lastJob) return;
  const event = state.lastJob;
  const modeText = {
    skip: "跳过已有文件",
    rename: "保留两份并自动改名",
    overwrite: "覆盖已有文件",
  }[event.conflictPolicy || "skip"];

  const failedItems = Array.from(state.events.values()).filter((item) => item.status === "failed");
  const outcome = outcomeOf(event.status);

  const errorSummary = failedItems.length
    ? `<details class="error-summary" ${event.status === "failed" ? "open" : ""}><summary>查看失败原因（${failedItems.length}）</summary>${failedItems
        .map(
          (item) =>
            `<div class="error-item"><strong>${escapeHtml(item.archiveName || item.path || "文件")}</strong><span>${escapeHtml(
              item.error || item.message || "处理失败"
            )}</span></div>`
        )
        .join("")}</details>`
    : "";

  els.jobResult.hidden = false;
  els.jobResult.className = `job-result ${event.status || ""}`;
  els.jobResult.innerHTML = `
    <div class="job-result-head">
      <div class="result-icon" aria-hidden="true">${outcome.icon}</div>
      <div>
        <h3>${escapeHtml(outcome.title)}</h3>
      </div>
    </div>
    <p>${escapeHtml(event.message || "")}</p>
    <div class="result-metrics">
      <span class="result-metric ${event.successCount ? "ok" : ""}">成功 ${event.successCount || 0}</span>
      <span class="result-metric ${event.failedCount ? "bad" : ""}">失败 ${event.failedCount || 0}</span>
      ${event.warningCount ? `<span class="result-metric warn">告警 ${event.warningCount}</span>` : ""}
    </div>
    <p>输出位置：每个压缩包所在文件夹 · 冲突处理：${escapeHtml(modeText)} · ${
      event.deleteOriginal ? "已删除原始压缩包（校验通过后）" : "原始压缩包已保留"
    }</p>
    ${errorSummary}
  `;
  els.jobResult.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function hideJobResult() {
  els.jobResult.hidden = true;
  els.jobResult.innerHTML = "";
  els.jobResult.className = "job-result";
}

function renderRetryPanel() {
  const failedItems = Array.from(state.events.values()).filter((item) => item.status === "failed");
  state.retryArchives = state.archives.filter((a) => failedItems.some((item) => item.archiveId === a.id));
  if (!failedItems.length) {
    hideRetryPanel();
    return;
  }
  els.retryPanel.hidden = false;
  els.retryPanel.innerHTML = `
    <h3>重试失败项</h3>
    <p>有 ${failedItems.length} 个文件失败。常见原因是密码错误或分卷不完整。可修改密码后只重试失败项（黑话会自动转换）。</p>
    <button id="retryFailedButton" class="btn btn-primary" type="button">只重试失败项</button>
  `;
  $("retryFailedButton")?.addEventListener("click", retryFailedItems);
}

function hideRetryPanel() {
  els.retryPanel.hidden = true;
  els.retryPanel.innerHTML = "";
}

function retryFailedItems() {
  if (!state.retryArchives.length || state.currentJob) return;
  const failedIDs = new Set(state.retryArchives.map((a) => a.id));
  for (const a of state.archives) a.selected = failedIDs.has(a.id);
  renderArchives();
  extract();
}

function getVisibleArchives() {
  return state.archives.filter((archive) => {
    const query = state.searchQuery.trim().toLowerCase();
    const text = `${archive.name} ${archive.relativeFile} ${archive.relativeDir}`.toLowerCase();
    if (query && !text.includes(query)) return false;
    const event = state.events.get(archive.id) || {};
    switch (state.filterMode) {
      case "selected":
        return archive.selected;
      case "pending":
        return !event.status || event.status === "running";
      case "failed":
        return event.status === "failed";
      case "done":
        return event.status === "done" || event.status === "warning";
      default:
        return true;
    }
  });
}

function renderEventLog() {
  if (!els.eventLog) return;
  const events = Array.from(state.events.values()).sort((a, b) => (a.index || 0) - (b.index || 0));
  const html = events
    .map((event) => {
      const percent = progressOf(event);
      const detail = event.error || event.message || event.path || "";
      return `
      <div class="event-item ${event.status || ""}">
        <div class="event-title">
          <span>${escapeHtml(event.archiveName || event.path || "任务")}</span>
          <span>${percent}%</span>
        </div>
        <div class="archive-progress"><span style="width:${clamp(percent)}%"></span></div>
        <div class="event-text">${escapeHtml(detail)}</div>
      </div>`;
    })
    .join("");
  els.eventLog.innerHTML = html;
  const running = els.eventLog.querySelector(".event-item.running");
  if (running) running.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function setOverallProgress(percent) {
  const clamped = clamp(percent);
  if (els.overallBar) els.overallBar.style.width = `${clamped}%`;
  if (els.overallPercent) els.overallPercent.textContent = `${clamped}%`;
  if (els.overallBarHost) els.overallBarHost.setAttribute("aria-valuenow", String(clamped));
  if (els.overallRingValue) {
    const offset = RING_CIRCUMFERENCE * (1 - clamped / 100);
    els.overallRingValue.style.strokeDashoffset = String(offset);
  }
}

function updateOverall() {
  const events = Array.from(state.events.values());
  const total = state.jobTotal || (events[0] && events[0].total) || events.length || 0;
  if (!total) {
    setOverallProgress(0);
    return;
  }
  let sum = 0;
  for (const event of events) {
    let p = Number(event.percent) || 0;
    // A finished archive contributes a full slice regardless of outcome —
    // otherwise failures pin the overall bar below 100% after the job ends.
    if (["done", "warning", "failed"].includes(event.status)) p = 100;
    sum += clamp(p);
  }
  setOverallProgress(Math.round(sum / total));
}

async function cancelJob() {
  if (!state.currentJob) return;
  try {
    await api(`/api/jobs/${encodeURIComponent(state.currentJob)}/cancel`, { method: "POST", body: "{}" });
    setStateText("取消中", "busy");
    toast("正在取消任务…", "info", 2000);
  } catch (err) {
    showError(err);
  }
}

function setBusy(busy) {
  const jobBusy = busy || Boolean(state.currentJob);
  els.scanButton.disabled = jobBusy;
  els.openPathButton.disabled = jobBusy;
  els.upButton.disabled = jobBusy || !state.parent;
  els.scanDepth.disabled = jobBusy;
  els.includeHidden.disabled = jobBusy;
  els.conflictPolicy.disabled = jobBusy;
  els.deleteOriginal.disabled = jobBusy;
  els.applyPasswordButton.disabled = jobBusy;
  els.extractButton.disabled = jobBusy || state.archives.every((a) => !a.selected);
  updateButtons();
  updateStepRail();
}

function showResumeBanner(text) {
  if (!els.resumeBanner) return;
  els.resumeBanner.hidden = false;
  els.resumeBanner.innerHTML = `
    <span class="banner-icon" aria-hidden="true">
      <svg viewBox="0 0 20 20" width="16" height="16" fill="none">
        <path d="M10 4v6l3.5 2" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
        <circle cx="10" cy="10" r="7.25" stroke="currentColor" stroke-width="1.5"/>
      </svg>
    </span>
    <div><strong>任务恢复</strong> · ${escapeHtml(text)}</div>
    <button type="button" class="resume-dismiss" aria-label="关闭提示">×</button>`;
  els.resumeBanner.querySelector(".resume-dismiss")?.addEventListener("click", hideResumeBanner);
}

function hideResumeBanner() {
  if (!els.resumeBanner) return;
  els.resumeBanner.hidden = true;
  els.resumeBanner.innerHTML = "";
}

/* ── Utils ── */

function clamp(n) {
  return Math.max(0, Math.min(100, Number(n) || 0));
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatLabel(archive) {
  if (archive.partCount > 1) {
    return `${archive.partCount} 个分卷 · ${String(archive.format || "split").toUpperCase()}`;
  }
  return `单个 ${String(archive.format || "archive").toUpperCase()} 文件`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value);
}

/* ── Resume ── */

async function resumeFromStorage() {
  const saved = loadActiveJob();
  if (!saved || !saved.jobId) {
    try {
      const list = await api("/api/jobs?active=1", { method: "GET", headers: {} });
      if (list.jobs && list.jobs.length === 1) {
        return resumeJob(list.jobs[0].id, { root: list.jobs[0].root, archives: null });
      }
    } catch (_) {}
    return false;
  }
  return resumeJob(saved.jobId, saved);
}

async function resumeJob(jobId, saved) {
  state.resuming = true;
  try {
    const snap = await api(`/api/jobs/${encodeURIComponent(jobId)}`, { method: "GET", headers: {} });

    if (saved && Array.isArray(saved.archives) && saved.archives.length) {
      state.archives = saved.archives;
      state.root = saved.root || snap.root || state.root;
      state.scanDepth = saved.scanDepth || state.scanDepth;
      state.includeHidden = Boolean(saved.includeHidden);
      state.hasScanned = true;
      if (state.root) els.rootPath.value = state.root;
      saveScanCache();
    } else if (snap.root) {
      state.root = snap.root;
      els.rootPath.value = snap.root;
    }

    state.events.clear();
    applyJobSnapshot(snap);
    els.progressPanel.hidden = false;

    if (snap.done) {
      const terminal =
        snap.events.find((e) => e.type === "job" && isTerminalJobStatus(e.status)) || {
          type: "job",
          status: snap.status || "done",
          message: snap.message,
        };
      state.lastJob = { ...terminal, jobId };
      renderJobResult();
      renderRetryPanel();
      clearActiveJob();
      state.currentJob = "";
      setBusy(false);
      const restoredOutcome = outcomeOf(terminal.status);
      setStateText(restoredOutcome.pill, restoredOutcome.kind);
      showResumeBanner("已恢复上次任务的最终结果。");
      renderArchives();
      return true;
    }

    state.currentJob = jobId;
    state.hasScanned = true;
    const startedAt = saved?.startedAt || Date.now();
    saveActiveJob({
      jobId,
      root: state.root || saved?.root || "",
      archives: state.archives,
      scanDepth: state.scanDepth,
      includeHidden: state.includeHidden,
      startedAt,
    });
    setBusy(true);
    setStateText("解压中", "busy");
    startElapsedTimer();
    state.jobStartedAt = startedAt;
    tickElapsed();
    showResumeBanner("检测到进行中的任务，已自动恢复进度。刷新不会丢失。");
    renderArchives();
    connectJobProgress(jobId);
    return true;
  } catch (err) {
    clearActiveJob();
    if (saved?.archives?.length) {
      state.archives = saved.archives;
      state.root = saved.root || state.root;
      state.hasScanned = true;
      if (state.root) els.rootPath.value = state.root;
      renderArchives();
    }
    showResumeBanner("上次任务已不可用（服务可能已重启），请重新扫描并解压。");
    return false;
  } finally {
    state.resuming = false;
    updateStepRail();
  }
}

function restoreScanCacheIfAny() {
  const cache = loadScanCache();
  if (!cache || !Array.isArray(cache.archives) || !cache.archives.length) return false;
  state.root = cache.root || state.root;
  state.scanDepth = cache.scanDepth || state.scanDepth;
  state.includeHidden = Boolean(cache.includeHidden);
  state.archives = cache.archives;
  state.hasScanned = Boolean(cache.hasScanned) || cache.archives.length > 0;
  if (state.root) els.rootPath.value = state.root;
  if (els.scanDepth) els.scanDepth.value = String(state.scanDepth);
  if (els.includeHidden) els.includeHidden.checked = state.includeHidden;
  renderArchives();
  return true;
}

function toggleGlobalPasswordVisibility() {
  const input = els.globalPassword;
  if (!input) return;
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  if (els.togglePasswordVisibility) {
    els.togglePasswordVisibility.textContent = show ? "隐藏" : "显示";
  }
}

function syncSegmented() {
  document.querySelectorAll(".segment").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.filter === state.filterMode);
  });
  if (els.filterMode) els.filterMode.value = state.filterMode;
}

/* ── Bindings ── */

els.openPathButton.addEventListener("click", () => loadDirs(els.rootPath.value.trim()).catch(showError));
els.rootPath.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    if (event.metaKey || event.ctrlKey) scan();
    else loadDirs(els.rootPath.value.trim()).catch(showError);
  }
});
els.upButton.addEventListener("click", () => state.parent && loadDirs(state.parent).catch(showError));
els.scanButton.addEventListener("click", scan);
els.recommendedButton.addEventListener("click", applyRecommendedSelection);
els.selectAllButton.addEventListener("click", toggleSelectAll);
els.applyPasswordButton.addEventListener("click", applyGlobalPassword);
els.extractButton.addEventListener("click", extract);
els.cancelButton.addEventListener("click", cancelJob);
els.copyPathButton?.addEventListener("click", () => copyCurrentPath());

if (els.dockSelectAll) els.dockSelectAll.addEventListener("click", toggleSelectAll);
if (els.dockExtract) els.dockExtract.addEventListener("click", extract);

els.searchInput?.addEventListener("input", () => {
  if (els.searchClear) els.searchClear.hidden = !els.searchInput.value;
  if (state.searchTimer) clearTimeout(state.searchTimer);
  state.searchTimer = window.setTimeout(() => {
    state.searchQuery = els.searchInput.value;
    renderArchives();
  }, 120);
});
els.searchClear?.addEventListener("click", () => {
  if (!els.searchInput) return;
  els.searchInput.value = "";
  state.searchQuery = "";
  els.searchClear.hidden = true;
  els.searchInput.focus();
  renderArchives();
});

document.querySelectorAll(".segment").forEach((btn) => {
  btn.addEventListener("click", () => {
    state.filterMode = btn.dataset.filter || "all";
    syncSegmented();
    renderArchives();
  });
});

els.globalPassword?.addEventListener("input", updatePasswordHint);
els.globalPassword?.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    applyGlobalPassword();
  }
});
els.togglePasswordVisibility?.addEventListener("click", toggleGlobalPasswordVisibility);

document.addEventListener("keydown", (event) => {
  const tag = (event.target && event.target.tagName) || "";
  const typing = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || event.target?.isContentEditable;

  if (event.key === "Escape" && state.currentJob) {
    event.preventDefault();
    cancelJob();
    return;
  }

  // Ctrl/Cmd + Enter: scan when idle, extract when list ready
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
    event.preventDefault();
    if (state.currentJob) return;
    if (state.archives.length && !typing) extract();
    else scan();
    return;
  }

  // Ctrl/Cmd + A on list area: toggle select all (when not typing)
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "a" && !typing && state.archives.length) {
    // only when focus is body/content — avoid fighting browser select-all in path field
    if (event.target === document.body || event.target === document.documentElement || event.target?.closest?.(".content")) {
      event.preventDefault();
      toggleSelectAll();
    }
  }
});

window.addEventListener("beforeunload", (event) => {
  closeJobStreams();
  if (state.currentJob) {
    event.preventDefault();
    event.returnValue = "";
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && state.currentJob) {
    api(`/api/jobs/${encodeURIComponent(state.currentJob)}`, { method: "GET", headers: {} })
      .then((snap) => {
        applyJobSnapshot(snap);
        if (snap.done) {
          const terminal = snap.events.find((e) => e.type === "job" && isTerminalJobStatus(e.status));
          finishJobClient(terminal?.status || snap.status || "done");
        } else if (!state.socket && !state.eventSource) {
          connectJobProgress(state.currentJob);
        }
      })
      .catch(() => {});
  }
});

async function boot() {
  setStateText("就绪", "idle");
  updateStepRail();
  const lastRoot = loadLastRoot();
  try {
    await loadDirs(lastRoot || "");
  } catch (err) {
    if (lastRoot) {
      try {
        await loadDirs("");
      } catch (err2) {
        showError(err2);
      }
    } else {
      showError(err);
    }
  }
  restoreScanCacheIfAny();
  await resumeFromStorage();
  updateStepRail();
}

boot();

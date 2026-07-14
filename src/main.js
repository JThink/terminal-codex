import {
  buildDefaultHotkeyDefinitions,
  detectPlatform,
  hotkeyStorageKeyForPlatform,
  modifierTokensForPlatform,
} from "./platform.mjs";
import {
  beginSingleFlight,
  buildProfilePayload,
  cloneLaunchSpec,
  filterSshProfiles,
  formatSshEndpoint,
  getSshLauncherActiveProfileId,
  getSshLauncherProfiles,
  isSshLauncherAddActionId,
  normalizeLaunchSpec,
  normalizeRecentProfileIds,
  pushRecentProfileId,
  removeSshProfileById,
  resolveSshLauncherKeyAction,
  resolveSshLaunchProfile,
  serializeLaunchSpec,
  terminalBytes,
  finishSingleFlight,
  invalidateSingleFlight,
  isSingleFlightCurrent,
  withAuthType,
} from "./ssh-connections.mjs";

const APP_PLATFORM = detectPlatform(
  navigator.userAgentData?.platform || navigator.platform,
  navigator.userAgent
);
document.documentElement.dataset.platform = APP_PLATFORM;

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const resolveAppWindow = () => {
  const win = window.__TAURI__?.window;
  if (!win) {
    return Promise.resolve(null);
  }
  const candidates = [];
  if (typeof win.getCurrentWindow === "function") {
    candidates.push(() => win.getCurrentWindow());
  }
  if (typeof win.getCurrentWebviewWindow === "function") {
    candidates.push(() => win.getCurrentWebviewWindow());
  }
  if (typeof win.getCurrent === "function") {
    candidates.push(() => win.getCurrent());
  }
  if (win.appWindow) {
    return Promise.resolve(win.appWindow);
  }
  if (win.WebviewWindow?.getCurrent) {
    candidates.push(() => win.WebviewWindow.getCurrent());
  }
  for (const getCandidate of candidates) {
    try {
      return Promise.resolve(getCandidate());
    } catch {
      continue;
    }
  }
  return Promise.resolve(null);
};

const withAppWindow = (action) =>
  resolveAppWindow()
    .then((win) => {
      if (!win) {
        return null;
      }
      return action(win);
    })
    .catch(() => {});

const startWindowDragging = () =>
  withAppWindow((win) => {
    if (typeof win.startDragging === "function") {
      return win.startDragging();
    }
    return null;
  });

const toggleWindowMaximize = () =>
  withAppWindow(async (win) => {
    if (typeof win.toggleMaximize === "function") {
      const result = await win.toggleMaximize();
      applyWindowBackground();
      ensureWebviewAutoResize();
      scheduleFit({ immediate: true, refreshTexture: true, resizePty: true });
      return result;
    }
    if (typeof win.isMaximized === "function") {
      const isMaximized = await win.isMaximized();
      if (isMaximized) {
        if (typeof win.unmaximize === "function") {
          const result = await win.unmaximize();
          applyWindowBackground();
          ensureWebviewAutoResize();
          scheduleFit({ immediate: true, refreshTexture: true, resizePty: true });
          return result;
        }
        if (typeof win.setMaximized === "function") {
          const result = await win.setMaximized(false);
          applyWindowBackground();
          ensureWebviewAutoResize();
          scheduleFit({ immediate: true, refreshTexture: true, resizePty: true });
          return result;
        }
        return null;
      }
      if (typeof win.maximize === "function") {
        const result = await win.maximize();
        applyWindowBackground();
        ensureWebviewAutoResize();
        scheduleFit({ immediate: true, refreshTexture: true, resizePty: true });
        return result;
      }
      if (typeof win.setMaximized === "function") {
        const result = await win.setMaximized(true);
        applyWindowBackground();
        ensureWebviewAutoResize();
        scheduleFit({ immediate: true, refreshTexture: true, resizePty: true });
        return result;
      }
    }
    if (typeof win.maximize === "function") {
      const result = await win.maximize();
      applyWindowBackground();
      ensureWebviewAutoResize();
      scheduleFit({ immediate: true, refreshTexture: true, resizePty: true });
      return result;
    }
    return null;
  });

const applyWindowBackground = () => {
  const webviewWindow = window.__TAURI__?.webviewWindow?.getCurrentWebviewWindow?.();
  if (webviewWindow?.setBackgroundColor) {
    webviewWindow.setBackgroundColor(APP_BACKGROUND_RGBA).catch(() => {});
  }
  withAppWindow((win) => {
    if (typeof win.setBackgroundColor === "function") {
      return win.setBackgroundColor(APP_BACKGROUND_RGBA);
    }
    return null;
  });
  const webview = window.__TAURI__?.webview?.getCurrentWebview?.();
  webview?.setBackgroundColor?.(APP_BACKGROUND_RGBA)?.catch?.(() => {});
  invoke("plugin:webview|set_webview_background_color", { value: APP_BACKGROUND_RGBA }).catch(
    () => {}
  );
  invoke("plugin:webview|set_webview_background_color", {
    label: "main",
    value: APP_BACKGROUND_RGBA,
  }).catch(() => {});
};

const ensureWebviewAutoResize = () => {
  const webview = window.__TAURI__?.webview?.getCurrentWebview?.();
  if (webview?.setAutoResize) {
    webview.setAutoResize(true).catch(() => {});
  }
  const webviewWindow = window.__TAURI__?.webviewWindow?.getCurrentWebviewWindow?.();
  if (webviewWindow?.setAutoResize) {
    webviewWindow.setAutoResize(true).catch(() => {});
  }
  invoke("plugin:webview|set_webview_auto_resize", { value: true }).catch(() => {});
  invoke("plugin:webview|set_webview_auto_resize", { label: "main", value: true }).catch(
    () => {}
  );
  setTimeout(() => {
    invoke("plugin:webview|set_webview_auto_resize", { value: true }).catch(() => {});
  }, 120);
};

let copyToastTimer = null;
let editFlashTimer = null;
const triggerCopyFeedback = () => {
  if (copyToastTimer) {
    clearTimeout(copyToastTimer);
  }
  if (editFlashTimer) {
    clearTimeout(editFlashTimer);
  }
  copyToast.classList.add("show");
  editFlash.classList.add("show");
  copyToastTimer = setTimeout(() => {
    copyToastTimer = null;
    copyToast.classList.remove("show");
  }, 900);
  editFlashTimer = setTimeout(() => {
    editFlashTimer = null;
    editFlash.classList.remove("show");
  }, 360);
};

const copyTextToClipboard = async (text) => {
  if (!text) {
    return false;
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {}
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    textarea.style.pointerEvents = "none";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
    return true;
  } catch {}
  return false;
};

const buildResumeCommand = (sessionId) => {
  if (!sessionId) {
    return "";
  }
  return `codex resume ${sessionId} --yolo`;
};

const openFinderForSession = async (sessionId) => {
  if (!sessionId) {
    return;
  }
  try {
    await invoke("open_session_cwd_in_finder", { sessionId });
  } catch {}
};

const focusActiveTerminal = () => {
  if (!activeTabId) {
    return;
  }
  const tab = tabs.get(activeTabId);
  const sessionId = tab?.activeSessionId || tab?.leftSessionId;
  const session = sessionId ? sessions.get(sessionId) : null;
  session?.terminal?.focus();
};

const sessions = new Map();
const tabs = new Map();
const terminalViews = new WeakMap();
const paneRestartStates = new WeakMap();
const pendingTerminalOutput = new Map();
const pendingTerminalLifecycle = new Map();
let activeTabId = null;
let tabCounter = 0;
let resizeTimer = null;
let cwdRefreshTimer = null;
let cwdRefreshInFlight = false;

const FONT_SIZE_KEY = "codex-terminal-font-size";
const DEFAULT_FONT_SIZE = 20;
const MIN_FONT_SIZE = 10;
const MAX_FONT_SIZE = 22;

const APP_BACKGROUND_COLOR = "#212121";
const APP_BACKGROUND_RGBA = { r: 33, g: 33, b: 33, a: 255 };

const TERMINAL_THEME = {
  background: APP_BACKGROUND_COLOR,
  foreground: "#D0D0D0",
};

const RESERVED_BOTTOM_ROWS = 1;
const DEFAULT_TAB_LABEL_BASE = "LeviQian专属Codex";
const DEFAULT_OVERLAY_TEXT = "LeviQian专属Codex";
const TABS_STATE_KEY = "codex-terminal-tabs-state";
const OVERLAY_DEFAULT_POSITION = { top: 44, right: 16 };
const CWD_REFRESH_INTERVAL = 2000;

const SPLIT_GUTTER_SIZE = 8;
const SPLIT_MIN_SIZE = 200;
const PENDING_OUTPUT_MAX_SESSIONS = 32;
const PENDING_OUTPUT_MAX_BYTES = 64 * 1024;

const HOTKEYS_STORAGE_KEY = hotkeyStorageKeyForPlatform(APP_PLATFORM);
const SSH_RECENT_PROFILE_IDS_KEY = "codex-terminal-ssh-recent-profile-ids";
const SSH_RECENT_PROFILE_LIMIT = 8;
const DEFAULT_HOTKEYS = buildDefaultHotkeyDefinitions(APP_PLATFORM);
const HOTKEY_MODIFIER_TOKENS = modifierTokensForPlatform(APP_PLATFORM);

const tabsContainer = document.getElementById("tabs");
const panelsContainer = document.getElementById("tab-panels");
const newTabButton = document.getElementById("new-tab");

const contextMenu = document.createElement("div");
contextMenu.className = "context-menu";
document.body.appendChild(contextMenu);

const copyToast = document.createElement("div");
copyToast.className = "copy-toast";
copyToast.textContent = "已复制";
document.body.appendChild(copyToast);

const editFlash = document.createElement("div");
editFlash.className = "edit-flash";
editFlash.textContent = "Edit";
document.body.appendChild(editFlash);

const tabsBar = document.querySelector(".tabs-bar");
const brandOverlay = document.getElementById("brand-overlay");


const hotkeyModal = document.createElement("div");
hotkeyModal.className = "hotkey-modal";
const hotkeyModalContent = document.createElement("div");
hotkeyModalContent.className = "hotkey-modal-content";
const hotkeyModalHeader = document.createElement("div");
hotkeyModalHeader.className = "hotkey-modal-header";
const hotkeyModalTitle = document.createElement("div");
hotkeyModalTitle.textContent = "快捷键设置";
const hotkeyModalActions = document.createElement("div");
hotkeyModalActions.className = "hotkey-modal-actions";
const hotkeyResetButton = document.createElement("button");
hotkeyResetButton.type = "button";
hotkeyResetButton.textContent = "恢复默认";
const hotkeyCloseButton = document.createElement("button");
hotkeyCloseButton.type = "button";
hotkeyCloseButton.textContent = "关闭";
hotkeyModalActions.appendChild(hotkeyResetButton);
hotkeyModalActions.appendChild(hotkeyCloseButton);
hotkeyModalHeader.appendChild(hotkeyModalTitle);
hotkeyModalHeader.appendChild(hotkeyModalActions);
const hotkeyModalBody = document.createElement("div");
hotkeyModalBody.className = "hotkey-modal-body";
const hotkeyList = document.createElement("div");
hotkeyList.className = "hotkey-list";
const hotkeyHint = document.createElement("div");
hotkeyHint.className = "hotkey-hint";
hotkeyHint.textContent = "点击快捷键后按下新的组合键，Esc 取消，Delete 清除。";
hotkeyModalBody.appendChild(hotkeyList);
hotkeyModalBody.appendChild(hotkeyHint);
hotkeyModalContent.appendChild(hotkeyModalHeader);
hotkeyModalContent.appendChild(hotkeyModalBody);
hotkeyModal.appendChild(hotkeyModalContent);
document.body.appendChild(hotkeyModal);

const sshConnectionsModal = document.createElement("div");
sshConnectionsModal.className = "ssh-connections-modal";
const sshConnectionsDialog = document.createElement("div");
sshConnectionsDialog.className = "ssh-connections-dialog";
sshConnectionsDialog.setAttribute("role", "dialog");
sshConnectionsDialog.setAttribute("aria-modal", "true");
sshConnectionsDialog.setAttribute("aria-labelledby", "ssh-connections-title");
const sshConnectionsHeader = document.createElement("div");
sshConnectionsHeader.className = "ssh-connections-header";
const sshConnectionsHeaderMain = document.createElement("div");
sshConnectionsHeaderMain.className = "ssh-connections-header-main";
const sshConnectionsBackButton = document.createElement("button");
sshConnectionsBackButton.type = "button";
sshConnectionsBackButton.className = "ssh-connections-icon-button";
sshConnectionsBackButton.textContent = "←";
sshConnectionsBackButton.title = "返回最近连接";
sshConnectionsBackButton.setAttribute("aria-label", "返回最近连接");
sshConnectionsBackButton.hidden = true;
const sshConnectionsTitle = document.createElement("div");
sshConnectionsTitle.id = "ssh-connections-title";
sshConnectionsTitle.className = "ssh-connections-title";
sshConnectionsTitle.textContent = "SSH 连接";
sshConnectionsHeaderMain.appendChild(sshConnectionsBackButton);
sshConnectionsHeaderMain.appendChild(sshConnectionsTitle);
const sshConnectionsHeaderActions = document.createElement("div");
sshConnectionsHeaderActions.className = "ssh-connections-header-actions";
const sshConnectionsCloseButton = document.createElement("button");
sshConnectionsCloseButton.type = "button";
sshConnectionsCloseButton.className = "ssh-connections-icon-button";
sshConnectionsCloseButton.textContent = "×";
sshConnectionsCloseButton.title = "关闭";
sshConnectionsCloseButton.setAttribute("aria-label", "关闭 SSH 连接中心");
sshConnectionsHeaderActions.appendChild(sshConnectionsCloseButton);
sshConnectionsHeader.appendChild(sshConnectionsHeaderMain);
sshConnectionsHeader.appendChild(sshConnectionsHeaderActions);

const sshConnectionsBody = document.createElement("div");
sshConnectionsBody.className = "ssh-connections-body";
const sshConnectionsListPane = document.createElement("div");
sshConnectionsListPane.className = "ssh-connections-list-pane";
const sshConnectionsListTitle = document.createElement("div");
sshConnectionsListTitle.className = "ssh-connections-list-title";
sshConnectionsListTitle.textContent = "最近";
const sshConnectionsSearchInput = document.createElement("input");
sshConnectionsSearchInput.type = "search";
sshConnectionsSearchInput.className = "ssh-connections-search";
sshConnectionsSearchInput.placeholder = "选择配置或输入地址";
sshConnectionsSearchInput.spellcheck = false;
const sshConnectionsList = document.createElement("div");
sshConnectionsList.className = "ssh-connections-list";
sshConnectionsList.setAttribute("role", "list");
sshConnectionsListPane.appendChild(sshConnectionsListTitle);
sshConnectionsListPane.appendChild(sshConnectionsSearchInput);
sshConnectionsListPane.appendChild(sshConnectionsList);

const sshConnectionsFormPane = document.createElement("div");
sshConnectionsFormPane.className = "ssh-connections-form-pane";
const sshConnectionsForm = document.createElement("form");
sshConnectionsForm.className = "ssh-connections-form";
sshConnectionsForm.noValidate = true;

const createSshField = ({ label, type = "text", className = "", inputMode }) => {
  const field = document.createElement("label");
  field.className = `ssh-connections-field${className ? ` ${className}` : ""}`;
  const fieldLabel = document.createElement("span");
  fieldLabel.textContent = label;
  const input = document.createElement("input");
  input.type = type;
  input.spellcheck = false;
  if (inputMode) {
    input.inputMode = inputMode;
  }
  field.appendChild(fieldLabel);
  field.appendChild(input);
  sshConnectionsForm.appendChild(field);
  return { field, input };
};

const sshNameField = createSshField({ label: "名称", className: "wide" });
const sshHostField = createSshField({ label: "主机", className: "wide" });
const sshPortField = createSshField({ label: "端口", type: "number", inputMode: "numeric" });
sshPortField.input.min = "1";
sshPortField.input.max = "65535";
const sshUsernameField = createSshField({ label: "用户名" });
const sshTimeoutField = createSshField({
  label: "连接超时（秒）",
  type: "number",
  inputMode: "numeric",
});
sshTimeoutField.input.min = "1";
sshTimeoutField.input.max = "120";

const sshAuthField = document.createElement("fieldset");
sshAuthField.className = "ssh-connections-auth-field wide";
const sshAuthLegend = document.createElement("legend");
sshAuthLegend.textContent = "认证方式";
const sshAuthSegmented = document.createElement("div");
sshAuthSegmented.className = "ssh-connections-auth-segmented";
const sshAuthButtons = new Map();
for (const [authType, label] of [
  ["agent", "Agent"],
  ["key", "私钥"],
  ["password", "密码"],
]) {
  const button = document.createElement("button");
  button.type = "button";
  button.dataset.authType = authType;
  button.textContent = label;
  button.setAttribute("aria-pressed", "false");
  sshAuthSegmented.appendChild(button);
  sshAuthButtons.set(authType, button);
}
sshAuthField.appendChild(sshAuthLegend);
sshAuthField.appendChild(sshAuthSegmented);
sshConnectionsForm.appendChild(sshAuthField);

const sshIdentityField = createSshField({ label: "私钥文件", className: "wide" });
const sshPasswordField = createSshField({
  label: "密码",
  type: "password",
  className: "wide",
});
sshPasswordField.input.autocomplete = "new-password";

const sshConnectionsStatus = document.createElement("div");
sshConnectionsStatus.className = "ssh-connections-status wide";
sshConnectionsStatus.setAttribute("role", "status");
sshConnectionsStatus.setAttribute("aria-live", "polite");
sshConnectionsForm.appendChild(sshConnectionsStatus);

const sshConnectionsFooter = document.createElement("div");
sshConnectionsFooter.className = "ssh-connections-footer wide";
const sshDeleteButton = document.createElement("button");
sshDeleteButton.type = "button";
sshDeleteButton.className = "danger";
sshDeleteButton.textContent = "删除";
const sshConnectionsPrimaryActions = document.createElement("div");
sshConnectionsPrimaryActions.className = "ssh-connections-primary-actions";
const sshTestButton = document.createElement("button");
sshTestButton.type = "button";
sshTestButton.textContent = "测试连接";
const sshSaveButton = document.createElement("button");
sshSaveButton.type = "button";
sshSaveButton.textContent = "保存";
const sshSaveAndConnectButton = document.createElement("button");
sshSaveAndConnectButton.type = "submit";
sshSaveAndConnectButton.className = "primary";
sshSaveAndConnectButton.textContent = "保存并连接";
sshConnectionsPrimaryActions.appendChild(sshTestButton);
sshConnectionsPrimaryActions.appendChild(sshSaveButton);
sshConnectionsPrimaryActions.appendChild(sshSaveAndConnectButton);
sshConnectionsFooter.appendChild(sshDeleteButton);
sshConnectionsFooter.appendChild(sshConnectionsPrimaryActions);
sshConnectionsForm.appendChild(sshConnectionsFooter);
sshConnectionsFormPane.appendChild(sshConnectionsForm);
sshConnectionsBody.appendChild(sshConnectionsListPane);
sshConnectionsBody.appendChild(sshConnectionsFormPane);
sshConnectionsDialog.appendChild(sshConnectionsHeader);
sshConnectionsDialog.appendChild(sshConnectionsBody);
sshConnectionsModal.appendChild(sshConnectionsDialog);
document.body.appendChild(sshConnectionsModal);

let sshProfiles = [];
let sshProfilesLoaded = false;
let selectedSshProfileId = null;
let sshFormAuthType = "agent";
let sshConnectionOperationInFlight = false;
let sshConnectionOperationState = null;
let sshProfilesRequestGeneration = 0;
let sshConnectionsRequestGeneration = 0;
let sshConnectionsView = "recent";
let sshRecentProfileIds = [];
let sshRecentActiveProfileId = null;

const loadRecentSshProfileIds = () => {
  try {
    return normalizeRecentProfileIds(
      JSON.parse(localStorage.getItem(SSH_RECENT_PROFILE_IDS_KEY) || "[]"),
      SSH_RECENT_PROFILE_LIMIT
    );
  } catch {
    return [];
  }
};

const saveRecentSshProfileIds = () => {
  localStorage.setItem(
    SSH_RECENT_PROFILE_IDS_KEY,
    JSON.stringify(sshRecentProfileIds)
  );
};

const rememberRecentSshProfile = (profileId) => {
  sshRecentProfileIds = pushRecentProfileId(
    sshRecentProfileIds,
    profileId,
    SSH_RECENT_PROFILE_LIMIT
  );
  saveRecentSshProfileIds();
};

const forgetRecentSshProfile = (profileId) => {
  sshRecentProfileIds = normalizeRecentProfileIds(
    sshRecentProfileIds.filter((candidate) => candidate !== profileId),
    SSH_RECENT_PROFILE_LIMIT
  );
  saveRecentSshProfileIds();
};

const getVisibleSshProfiles = () =>
  sshConnectionsView === "recent"
    ? getSshLauncherProfiles(
        sshProfiles,
        sshConnectionsSearchInput.value,
        sshRecentProfileIds
      )
    : filterSshProfiles(sshProfiles, sshConnectionsSearchInput.value);

const syncSshRecentActiveProfile = (visibleProfiles) => {
  sshRecentActiveProfileId = getSshLauncherActiveProfileId(
    visibleProfiles,
    sshRecentActiveProfileId
  );
};

const scrollSshRecentActiveProfileIntoView = () => {
  if (sshConnectionsView !== "recent" || !sshRecentActiveProfileId) {
    return;
  }
  const activeElement = isSshLauncherAddActionId(sshRecentActiveProfileId)
    ? sshConnectionsList.querySelector(".ssh-connections-add-row")
    : sshConnectionsList.querySelector(
        `[data-profile-id="${CSS.escape(sshRecentActiveProfileId)}"]`
      );
  activeElement?.scrollIntoView({ block: "nearest" });
};

const getSshProfilesFromResponse = (response) => {
  if (Array.isArray(response)) {
    return response;
  }
  return Array.isArray(response?.profiles) ? response.profiles : [];
};

const setSshConnectionsStatus = (message = "", type = "") => {
  sshConnectionsStatus.textContent = message;
  sshConnectionsStatus.classList.toggle("error", type === "error");
  sshConnectionsStatus.classList.toggle("success", type === "success");
};

const readSshConnectionForm = () => ({
  id: selectedSshProfileId || "",
  name: sshNameField.input.value,
  host: sshHostField.input.value,
  port: sshPortField.input.value,
  username: sshUsernameField.input.value,
  authType: sshFormAuthType,
  identityFile: sshIdentityField.input.value,
  connectTimeout: sshTimeoutField.input.value,
  password: sshPasswordField.input.value,
});

const setSshAuthType = (authType) => {
  const next = withAuthType(readSshConnectionForm(), authType);
  sshFormAuthType = next.authType;
  sshIdentityField.input.value = next.identityFile;
  sshPasswordField.input.value = next.password;
  for (const [candidate, button] of sshAuthButtons) {
    const active = candidate === sshFormAuthType;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  }
  sshIdentityField.field.hidden = sshFormAuthType !== "key";
  sshPasswordField.field.hidden = sshFormAuthType !== "password";
};

const setSshConnectionBusy = (busy) => {
  sshConnectionOperationInFlight = busy;
  const controls = [
    sshConnectionsBackButton,
    sshDeleteButton,
    sshTestButton,
    sshSaveButton,
    sshSaveAndConnectButton,
    ...sshAuthButtons.values(),
  ];
  for (const control of controls) {
    control.disabled = busy;
  }
  for (const input of sshConnectionsForm.querySelectorAll("input")) {
    input.disabled = busy;
  }
  sshConnectionsSearchInput.disabled = busy;
  for (const button of sshConnectionsList.querySelectorAll("button")) {
    button.disabled = busy;
  }
};

const isSshConnectionsVisible = () =>
  sshConnectionsModal.classList.contains("show");

const invalidateSshConnectionOperation = () => {
  sshConnectionOperationState = invalidateSingleFlight(
    sshConnectionOperationState
  );
};

const beginSshConnectionOperation = () => {
  if (sshConnectionOperationInFlight || !isSshConnectionsVisible()) {
    return null;
  }
  const started = beginSingleFlight(sshConnectionOperationState);
  if (!started) {
    return null;
  }
  sshConnectionOperationState = started.state;
  setSshConnectionBusy(true);
  return started.generation;
};

const isSshConnectionOperationCurrent = (generation) =>
  isSshConnectionsVisible() &&
  isSingleFlightCurrent(sshConnectionOperationState, generation);

const finishSshConnectionOperation = (generation) => {
  if (!isSshConnectionOperationCurrent(generation)) {
    return false;
  }
  sshConnectionOperationState = finishSingleFlight(
    sshConnectionOperationState,
    generation
  );
  setSshConnectionBusy(false);
  sshDeleteButton.disabled = !selectedSshProfileId;
  return true;
};

const renderSshConnectionsPlaceholder = (message) => {
  const empty = document.createElement("div");
  empty.className = "ssh-connections-empty";
  empty.textContent = message;
  sshConnectionsList.replaceChildren(empty);
};

const setSshConnectionsView = (view) => {
  sshConnectionsView = view === "form" ? "form" : "recent";
  const isFormView = sshConnectionsView === "form";
  sshConnectionsDialog.classList.toggle("form-view", isFormView);
  sshConnectionsDialog.classList.toggle("recent-view", !isFormView);
  sshConnectionsBackButton.hidden = !isFormView;
  sshConnectionsListTitle.textContent = isFormView ? "已保存连接" : "最近";
  sshConnectionsSearchInput.placeholder = isFormView
    ? "搜索已保存连接"
    : "选择配置或输入地址";
  sshConnectionsTitle.textContent = isFormView
    ? selectedSshProfileId
      ? "编辑 SSH 连接"
      : "添加 SSH 连接"
    : "最近登录过的";
};

const populateSshConnectionForm = (profile = null) => {
  selectedSshProfileId = profile?.id || null;
  sshNameField.input.value = profile?.name || "";
  sshHostField.input.value = profile?.host || "";
  sshPortField.input.value = String(profile?.port || 22);
  sshUsernameField.input.value = profile?.username || "";
  sshTimeoutField.input.value = String(profile?.connectTimeout || 10);
  sshIdentityField.input.value = profile?.identityFile || "";
  sshPasswordField.input.value = "";
  sshPasswordField.input.placeholder = profile?.hasPassword
    ? "留空则保留已保存密码"
    : "";
  sshFormAuthType = profile?.authType || "agent";
  setSshAuthType(sshFormAuthType);
  sshDeleteButton.disabled = !selectedSshProfileId || sshConnectionOperationInFlight;
  setSshConnectionsStatus();
};

const renderSshConnectionForm = (profile = null) => {
  populateSshConnectionForm(profile);
  setSshConnectionsView("form");
};

const openSshConnectionForm = (profile = null) => {
  if (sshConnectionOperationInFlight) {
    return;
  }
  if (sshConnectionsView === "recent") {
    sshConnectionsSearchInput.value = "";
  }
  renderSshConnectionForm(profile);
  renderSshConnectionsList();
  requestAnimationFrame(() => {
    if (!isSshConnectionsVisible() || sshConnectionsView !== "form") {
      return;
    }
    (profile ? sshHostField.input : sshNameField.input).focus();
  });
};

const showSshConnectionsRecentView = ({ resetSearch = false } = {}) => {
  if (resetSearch) {
    sshConnectionsSearchInput.value = "";
  }
  sshRecentActiveProfileId = null;
  setSshConnectionsView("recent");
  setSshConnectionsStatus();
  renderSshConnectionsList();
  requestAnimationFrame(() => {
    if (!isSshConnectionsVisible() || sshConnectionsView !== "recent") {
      return;
    }
    sshConnectionsSearchInput.focus();
  });
};

const renderSshConnectionsList = () => {
  const isRecentView = sshConnectionsView === "recent";
  const visibleProfiles = getVisibleSshProfiles();
  if (isRecentView) {
    syncSshRecentActiveProfile(visibleProfiles);
  }
  const fragment = document.createDocumentFragment();
  for (const profile of visibleProfiles) {
    if (isRecentView) {
      const row = document.createElement("div");
      row.className = "ssh-connections-row";
      row.classList.toggle("active", profile.id === sshRecentActiveProfileId);
      row.dataset.profileId = profile.id;

      const main = document.createElement("button");
      main.type = "button";
      main.className = "ssh-connections-row-main";
      main.disabled = sshConnectionOperationInFlight;
      main.setAttribute("aria-label", `连接到 ${profile.name}`);

      const icon = document.createElement("span");
      icon.className = "ssh-connections-row-icon";
      icon.textContent = "↻";

      const summary = document.createElement("span");
      summary.className = "ssh-connections-row-summary";

      const name = document.createElement("span");
      name.className = "ssh-connections-row-name";
      name.textContent = profile.name;
      const endpoint = document.createElement("span");
      endpoint.className = "ssh-connections-row-endpoint";
      endpoint.textContent = formatSshEndpoint(profile);
      summary.appendChild(name);
      summary.appendChild(endpoint);
      main.appendChild(icon);
      main.appendChild(summary);
      main.addEventListener("click", () => {
        if (!sshConnectionOperationInFlight) {
          sshRecentActiveProfileId = profile.id;
          void connectSshProfile(profile);
        }
      });

      const editButton = document.createElement("button");
      editButton.type = "button";
      editButton.className = "ssh-connections-row-edit";
      editButton.textContent = "编辑";
      editButton.disabled = sshConnectionOperationInFlight;
      editButton.addEventListener("click", () => openSshConnectionForm(profile));

      row.appendChild(main);
      row.appendChild(editButton);
      fragment.appendChild(row);
      continue;
    }

    const row = document.createElement("button");
    row.type = "button";
    row.className = "ssh-connections-saved-row";
    row.disabled = sshConnectionOperationInFlight;
    row.dataset.profileId = profile.id;
    row.classList.toggle("active", profile.id === selectedSshProfileId);

    const name = document.createElement("span");
    name.className = "ssh-connections-saved-row-name";
    name.textContent = profile.name;
    const endpoint = document.createElement("span");
    endpoint.className = "ssh-connections-saved-row-endpoint";
    endpoint.textContent = formatSshEndpoint(profile);
    row.appendChild(name);
    row.appendChild(endpoint);
    row.addEventListener("click", () => {
      if (!sshConnectionOperationInFlight) {
        renderSshConnectionForm(profile);
        renderSshConnectionsList();
      }
    });
    fragment.appendChild(row);
  }
  if (!visibleProfiles.length) {
    const empty = document.createElement("div");
    empty.className = "ssh-connections-empty";
    empty.textContent = sshProfiles.length
      ? "没有匹配的连接"
      : isRecentView
        ? "暂无最近连接"
        : "暂无已保存连接";
    fragment.appendChild(empty);
  }
  const addRow = document.createElement("button");
  addRow.type = "button";
  addRow.className = isRecentView
    ? "ssh-connections-add-row"
    : "ssh-connections-saved-add-row";
  if (isRecentView) {
    addRow.classList.toggle("active", isSshLauncherAddActionId(sshRecentActiveProfileId));
  }
  addRow.textContent = isRecentView ? "+ 添加 SSH 连接" : "+ 新建 SSH 连接";
  addRow.disabled = sshConnectionOperationInFlight;
  addRow.addEventListener("click", () => openSshConnectionForm(null));
  fragment.appendChild(addRow);
  sshConnectionsList.replaceChildren(fragment);
  if (isRecentView) {
    scrollSshRecentActiveProfileIntoView();
  }
};

const refreshSshProfiles = async ({ render = true, canApply = () => true } = {}) => {
  const requestGeneration = ++sshProfilesRequestGeneration;
  try {
    const response = await invoke("list_ssh_profiles");
    if (requestGeneration !== sshProfilesRequestGeneration || !canApply()) {
      return sshProfiles;
    }
    sshProfiles = getSshProfilesFromResponse(response);
    sshProfilesLoaded = true;
    if (render) {
      renderSshConnectionsList();
    }
    return sshProfiles;
  } catch (error) {
    if (requestGeneration !== sshProfilesRequestGeneration || !canApply()) {
      return sshProfiles;
    }
    sshProfilesLoaded = false;
    if (render) {
      setSshConnectionsStatus(String(error), "error");
      renderSshConnectionsList();
    }
    throw error;
  }
};

const openSshConnections = async ({ profileId = null } = {}) => {
  const requestGeneration = ++sshConnectionsRequestGeneration;
  sshProfilesRequestGeneration += 1;
  invalidateSshConnectionOperation();
  hideContextMenu();
  sshRecentProfileIds = loadRecentSshProfileIds();
  sshRecentActiveProfileId = null;
  sshConnectionsModal.classList.add("show");
  setSshConnectionsView("recent");
  setSshConnectionBusy(true);
  sshConnectionsSearchInput.value = "";
  populateSshConnectionForm(null);
  renderSshConnectionsPlaceholder("正在加载连接...");
  const canApply = () =>
    requestGeneration === sshConnectionsRequestGeneration &&
    isSshConnectionsVisible();
  try {
    await refreshSshProfiles({ render: false, canApply });
    if (!canApply()) {
      return;
    }
    const requestedProfileId = profileId || selectedSshProfileId;
    const selectedProfile = requestedProfileId
      ? sshProfiles.find((profile) => profile.id === requestedProfileId) ||
        (profileId ? null : sshProfiles[0] || null)
      : sshProfiles[0] || null;
    setSshConnectionBusy(false);
    requestAnimationFrame(() => {
      if (!canApply()) {
        return;
      }
      if (profileId && selectedProfile) {
        openSshConnectionForm(selectedProfile);
      } else {
        showSshConnectionsRecentView({ resetSearch: true });
      }
    });
  } catch {
    if (!canApply()) {
      return;
    }
    renderSshConnectionsPlaceholder("无法加载 SSH 连接。");
    setSshConnectionBusy(false);
  }
};

const closeSshConnections = () => {
  const requestGeneration = ++sshConnectionsRequestGeneration;
  sshProfilesRequestGeneration += 1;
  invalidateSshConnectionOperation();
  sshPasswordField.input.value = "";
  sshConnectionsModal.classList.remove("show");
  setSshConnectionsView("recent");
  setSshConnectionBusy(false);
  sshDeleteButton.disabled = !selectedSshProfileId;
  setTimeout(() => {
    if (
      requestGeneration === sshConnectionsRequestGeneration &&
      !sshConnectionsModal.classList.contains("show")
    ) {
      focusActiveTerminal();
    }
  }, 0);
};

const saveCurrentSshProfile = async () => {
  const operationGeneration = beginSshConnectionOperation();
  if (operationGeneration == null) {
    return null;
  }
  setSshConnectionsStatus("正在保存...");
  try {
    const payload = buildProfilePayload(readSshConnectionForm());
    sshPasswordField.input.value = "";
    const response = await invoke("save_ssh_profile", payload);
    if (!isSshConnectionOperationCurrent(operationGeneration)) {
      return null;
    }
    const savedProfile = response?.profile || response;
    await refreshSshProfiles({
      render: false,
      canApply: () => isSshConnectionOperationCurrent(operationGeneration),
    });
    if (!isSshConnectionOperationCurrent(operationGeneration)) {
      return null;
    }
    const resolvedProfile =
      sshProfiles.find((profile) => profile.id === savedProfile?.id) || savedProfile;
    if (!resolvedProfile?.id) {
      throw new Error("保存完成，但未返回 SSH 连接 ID。");
    }
    renderSshConnectionForm(resolvedProfile);
    renderSshConnectionsList();
    setSshConnectionsStatus("已保存。", "success");
    return resolvedProfile;
  } catch (error) {
    if (isSshConnectionOperationCurrent(operationGeneration)) {
      sshPasswordField.input.value = "";
      setSshConnectionsStatus(String(error), "error");
    }
    return null;
  } finally {
    finishSshConnectionOperation(operationGeneration);
  }
};

const connectSshProfile = async (profile) => {
  if (!profile?.id || sshConnectionOperationInFlight) {
    return;
  }
  rememberRecentSshProfile(profile.id);
  closeSshConnections();
  await createTab({
    label: profile.name,
    leftLaunchSpec: { kind: "ssh", profileId: profile.id },
  });
};

const testCurrentSshProfile = async () => {
  const savedProfile = await saveCurrentSshProfile();
  if (!savedProfile) {
    return;
  }
  const operationGeneration = beginSshConnectionOperation();
  if (operationGeneration == null) {
    return;
  }
  setSshConnectionsStatus("正在测试连接...");
  try {
    const result = await invoke("test_ssh_profile", {
      profileId: savedProfile.id,
    });
    if (!isSshConnectionOperationCurrent(operationGeneration)) {
      return;
    }
    const message = typeof result === "string" && result.trim() ? result : "连接测试成功。";
    setSshConnectionsStatus(message, "success");
  } catch (error) {
    if (isSshConnectionOperationCurrent(operationGeneration)) {
      setSshConnectionsStatus(String(error), "error");
    }
  } finally {
    finishSshConnectionOperation(operationGeneration);
  }
};

const deleteCurrentSshProfile = async () => {
  if (!selectedSshProfileId || sshConnectionOperationInFlight) {
    return;
  }
  const profileId = selectedSshProfileId;
  const operationGeneration = beginSshConnectionOperation();
  if (operationGeneration == null) {
    return;
  }
  setSshConnectionsStatus("正在删除...");
  try {
    await invoke("delete_ssh_profile", { profileId });
    if (!isSshConnectionOperationCurrent(operationGeneration)) {
      return;
    }
    sshProfiles = removeSshProfileById(sshProfiles, profileId);
    selectedSshProfileId = null;
    forgetRecentSshProfile(profileId);
    renderSshConnectionForm(null);
    renderSshConnectionsList();
    setSshConnectionsStatus("已删除。", "success");
  } catch (error) {
    if (isSshConnectionOperationCurrent(operationGeneration)) {
      setSshConnectionsStatus(String(error), "error");
    }
  } finally {
    finishSshConnectionOperation(operationGeneration);
  }
};

for (const [authType, button] of sshAuthButtons) {
  button.addEventListener("click", () => setSshAuthType(authType));
}
sshConnectionsSearchInput.addEventListener("input", () => {
  if (sshConnectionsView === "recent") {
    sshRecentActiveProfileId = null;
  }
  renderSshConnectionsList();
});
const shouldHandleSshConnectionsLauncherKeyDown = (event) => {
  if (
    !isSshConnectionsVisible() ||
    sshConnectionsView !== "recent" ||
    sshConnectionOperationInFlight ||
    event.defaultPrevented ||
    event.metaKey ||
    event.ctrlKey ||
    event.altKey
  ) {
    return false;
  }
  if (
    event.key !== "ArrowDown" &&
    event.key !== "ArrowUp" &&
    event.key !== "Enter"
  ) {
    return false;
  }
  if (event.key !== "Enter") {
    return true;
  }
  if (!(event.target instanceof Element)) {
    return true;
  }
  return !event.target.closest(
    ".ssh-connections-row-edit, .ssh-connections-icon-button"
  );
};
const handleSshConnectionsLauncherKeyDown = (event) => {
  if (!shouldHandleSshConnectionsLauncherKeyDown(event)) {
    return;
  }
  const visibleProfiles = getVisibleSshProfiles();
  const action = resolveSshLauncherKeyAction(
    visibleProfiles,
    sshRecentActiveProfileId,
    event.key
  );
  if (action.kind === "ignore") {
    return;
  }
  event.preventDefault();
  event.stopPropagation();
  sshRecentActiveProfileId = action.activeProfileId;
  if (action.kind === "select") {
    renderSshConnectionsList();
    return;
  }
  if (action.kind === "add") {
    openSshConnectionForm(null);
    return;
  }
  if (action.kind === "connect" && action.profile) {
    void connectSshProfile(action.profile);
  }
};
document.addEventListener("keydown", handleSshConnectionsLauncherKeyDown);
sshConnectionsBackButton.addEventListener("click", () =>
  showSshConnectionsRecentView({ resetSearch: true })
);
sshConnectionsCloseButton.addEventListener("click", closeSshConnections);
sshConnectionsModal.addEventListener("click", (event) => {
  if (event.target === sshConnectionsModal) {
    closeSshConnections();
  }
});
sshDeleteButton.addEventListener("click", () => void deleteCurrentSshProfile());
sshTestButton.addEventListener("click", () => void testCurrentSshProfile());
sshSaveButton.addEventListener("click", () => void saveCurrentSshProfile());
sshConnectionsForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void saveCurrentSshProfile().then((profile) => {
    if (profile) {
      return connectSshProfile(profile);
    }
    return null;
  });
});

const SESSION_HISTORY_PAGE_SIZE = 30;
const SESSION_HISTORY_UNKNOWN_GROUP_KEY = "__unknown__";
const sessionHistoryState = {
  items: [],
  total: 0,
  nextOffset: 0,
  hasMore: false,
  loading: false,
  selectedKey: null,
  selectedSessionId: "",
};
const sessionHistoryDetailsCache = new Map();
const sessionHistoryCollapsedGroups = new Set();
let sessionHistoryDetailLoading = false;
let sessionHistoryDetailRequestSeq = 0;
let sessionHistoryListRequestSeq = 0;
let sessionHistorySearchQuery = "";
let sessionHistorySearchTimer = null;

const sessionHistoryModal = document.createElement("div");
sessionHistoryModal.className = "session-history-modal";
const sessionHistoryDialog = document.createElement("div");
sessionHistoryDialog.className = "session-history-dialog";
const sessionHistoryHeader = document.createElement("div");
sessionHistoryHeader.className = "session-history-header";
const sessionHistoryTitle = document.createElement("div");
sessionHistoryTitle.className = "session-history-title";
sessionHistoryTitle.textContent = "Codex 会话历史";
const sessionHistoryCloseButton = document.createElement("button");
sessionHistoryCloseButton.type = "button";
sessionHistoryCloseButton.className = "session-history-close";
sessionHistoryCloseButton.textContent = "关闭";
sessionHistoryHeader.appendChild(sessionHistoryTitle);
sessionHistoryHeader.appendChild(sessionHistoryCloseButton);

const sessionHistoryBody = document.createElement("div");
sessionHistoryBody.className = "session-history-body";

const sessionHistoryListPane = document.createElement("div");
sessionHistoryListPane.className = "session-history-list-pane";
const sessionHistoryListHead = document.createElement("div");
sessionHistoryListHead.className = "session-history-list-head";
sessionHistoryListHead.textContent = "项目";
const sessionHistorySearchInput = document.createElement("input");
sessionHistorySearchInput.type = "search";
sessionHistorySearchInput.className = "session-history-search";
sessionHistorySearchInput.placeholder = "搜索目录";
sessionHistorySearchInput.spellcheck = false;
const sessionHistoryList = document.createElement("div");
sessionHistoryList.className = "session-history-list";
const sessionHistoryListStatus = document.createElement("div");
sessionHistoryListStatus.className = "session-history-list-status";
const sessionHistoryLoadMoreButton = document.createElement("button");
sessionHistoryLoadMoreButton.type = "button";
sessionHistoryLoadMoreButton.className = "session-history-load-more";
sessionHistoryLoadMoreButton.textContent = "加载更多";
sessionHistoryListPane.appendChild(sessionHistoryListHead);
sessionHistoryListPane.appendChild(sessionHistorySearchInput);
sessionHistoryListPane.appendChild(sessionHistoryList);
sessionHistoryListPane.appendChild(sessionHistoryListStatus);
sessionHistoryListPane.appendChild(sessionHistoryLoadMoreButton);
const sessionHistoryListSpinner = document.createElement("div");
sessionHistoryListSpinner.className = "session-history-spinner";
sessionHistoryListPane.appendChild(sessionHistoryListSpinner);

const sessionHistoryDetailPane = document.createElement("div");
sessionHistoryDetailPane.className = "session-history-detail-pane";
const sessionHistoryDetailHead = document.createElement("div");
sessionHistoryDetailHead.className = "session-history-detail-head";
const sessionHistoryDetailTop = document.createElement("div");
sessionHistoryDetailTop.className = "session-history-detail-top";
const sessionHistoryDetailTitle = document.createElement("div");
sessionHistoryDetailTitle.className = "session-history-detail-title";
sessionHistoryDetailTitle.textContent = "会话提问";
const sessionHistoryCopyButton = document.createElement("button");
sessionHistoryCopyButton.type = "button";
sessionHistoryCopyButton.className = "session-history-copy-session";
sessionHistoryCopyButton.textContent = "复制 Session";
sessionHistoryCopyButton.disabled = true;
const sessionHistoryDetailMeta = document.createElement("div");
sessionHistoryDetailMeta.className = "session-history-detail-meta";
sessionHistoryDetailTop.appendChild(sessionHistoryDetailTitle);
sessionHistoryDetailTop.appendChild(sessionHistoryCopyButton);
sessionHistoryDetailHead.appendChild(sessionHistoryDetailTop);
sessionHistoryDetailHead.appendChild(sessionHistoryDetailMeta);
const sessionHistoryQuestionList = document.createElement("div");
sessionHistoryQuestionList.className = "session-history-questions";
sessionHistoryDetailPane.appendChild(sessionHistoryDetailHead);
sessionHistoryDetailPane.appendChild(sessionHistoryQuestionList);
const sessionHistoryDetailSpinner = document.createElement("div");
sessionHistoryDetailSpinner.className = "session-history-spinner";
sessionHistoryDetailPane.appendChild(sessionHistoryDetailSpinner);

sessionHistoryBody.appendChild(sessionHistoryListPane);
sessionHistoryBody.appendChild(sessionHistoryDetailPane);
sessionHistoryDialog.appendChild(sessionHistoryHeader);
sessionHistoryDialog.appendChild(sessionHistoryBody);
sessionHistoryModal.appendChild(sessionHistoryDialog);
document.body.appendChild(sessionHistoryModal);

const trimSingleLine = (value, max = 90) => {
  if (typeof value !== "string") {
    return "";
  }
  const text = value.replace(/\s+/g, " ").trim();
  if (!text) {
    return "";
  }
  if (text.length <= max) {
    return text;
  }
  return `${text.slice(0, max)}…`;
};

const normalizeSessionHistoryCwd = (value) => {
  if (typeof value !== "string") {
    return "";
  }
  return value.replace(/\\/g, "/").trim().replace(/\/+$/g, "");
};

const getSessionHistoryGroupKey = (cwd) =>
  normalizeSessionHistoryCwd(cwd) || SESSION_HISTORY_UNKNOWN_GROUP_KEY;

const getSessionHistoryGroupTitle = (cwd) => {
  const normalized = normalizeSessionHistoryCwd(cwd);
  if (!normalized) {
    return "(未记录目录)";
  }
  const segments = normalized.split("/").filter(Boolean);
  return segments.at(-1) || normalized;
};

const countSessionHistoryGroups = (items) =>
  new Set(items.map((item) => getSessionHistoryGroupKey(item.cwd))).size;

const buildSessionHistoryGroups = (items) => {
  const groups = [];
  const groupMap = new Map();
  for (const item of items) {
    const normalizedCwd = normalizeSessionHistoryCwd(item.cwd);
    const key = getSessionHistoryGroupKey(item.cwd);
    let group = groupMap.get(key);
    if (!group) {
      group = {
        key,
        cwd: normalizedCwd,
        title: getSessionHistoryGroupTitle(item.cwd),
        items: [],
      };
      groupMap.set(key, group);
      groups.push(group);
    }
    group.items.push(item);
  }
  return groups;
};

const buildSessionHistoryDetailMeta = (sessionId = "", cwd = "") => {
  const parts = [];
  if (sessionId) {
    parts.push(`Session: ${sessionId}`);
  }
  if (cwd) {
    parts.push(cwd);
  }
  return parts.join(" · ");
};

const getSessionHistoryStatusText = () => {
  const groupCount = countSessionHistoryGroups(sessionHistoryState.items);
  if (sessionHistorySearchQuery) {
    return `搜索“${sessionHistorySearchQuery}”命中 ${sessionHistoryState.total} 条会话 / ${groupCount} 个目录`;
  }
  return `共 ${sessionHistoryState.total} 条会话 / ${groupCount} 个目录`;
};

const resolveSessionHistoryTitle = (item) => {
  const candidates = [item.first_question, item.last_question];
  for (const candidate of candidates) {
    const normalized = trimSingleLine(candidate || "", 90);
    if (normalized && normalized !== "(暂无提问记录)") {
      return normalized;
    }
  }
  const sessionId =
    typeof item.session_id === "string" ? item.session_id.trim() : "";
  return sessionId ? `Session ${sessionId}` : "未命名会话";
};

const formatSessionTimestampUtc8 = (rawValue) => {
  if (rawValue == null) {
    return "未知时间";
  }

  const value = String(rawValue).trim();
  if (!value) {
    return "未知时间";
  }

  let parsedDate = null;
  if (/^\d+$/.test(value)) {
    let timestamp = Number(value);
    if (Number.isFinite(timestamp)) {
      if (value.length <= 10) {
        timestamp *= 1000;
      }
      parsedDate = new Date(timestamp);
    }
  } else {
    parsedDate = new Date(value);
  }

  if (!(parsedDate instanceof Date) || Number.isNaN(parsedDate.getTime())) {
    return value;
  }

  const utc8Date = new Date(parsedDate.getTime() + 8 * 60 * 60 * 1000);
  const pad = (num) => String(num).padStart(2, "0");
  const year = utc8Date.getUTCFullYear();
  const month = pad(utc8Date.getUTCMonth() + 1);
  const day = pad(utc8Date.getUTCDate());
  const hours = pad(utc8Date.getUTCHours());
  const minutes = pad(utc8Date.getUTCMinutes());
  const seconds = pad(utc8Date.getUTCSeconds());
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
};

const resetSessionHistoryState = () => {
  sessionHistoryState.items = [];
  sessionHistoryState.total = 0;
  sessionHistoryState.nextOffset = 0;
  sessionHistoryState.hasMore = false;
  sessionHistoryState.selectedKey = null;
  sessionHistoryState.selectedSessionId = "";
  sessionHistoryCollapsedGroups.clear();
};

const setSessionHistoryCopyState = (sessionId = "") => {
  const normalizedSessionId = typeof sessionId === "string" ? sessionId.trim() : "";
  sessionHistoryState.selectedSessionId = normalizedSessionId;
  const command = buildResumeCommand(normalizedSessionId);
  sessionHistoryCopyButton.disabled = !command;
  sessionHistoryCopyButton.dataset.command = command;
  sessionHistoryCopyButton.title = command || "请选择会话后复制";
};

const setSessionHistoryDetailLoading = (loading) => {
  sessionHistoryDetailLoading = loading;
  sessionHistoryDetailPane.classList.toggle("loading", loading);
};

const renderSessionHistoryList = () => {
  sessionHistoryListPane.classList.toggle("loading", sessionHistoryState.loading);
  const fragment = document.createDocumentFragment();

  for (const group of buildSessionHistoryGroups(sessionHistoryState.items)) {
    const section = document.createElement("section");
    section.className = "session-history-group";
    if (sessionHistoryCollapsedGroups.has(group.key)) {
      section.classList.add("collapsed");
    }

    const header = document.createElement("button");
    header.type = "button";
    header.className = "session-history-group-toggle";
    header.dataset.groupKey = group.key;
    header.title = group.cwd || "(未记录目录)";

    const icon = document.createElement("span");
    icon.className = "session-history-folder-icon";
    icon.setAttribute("aria-hidden", "true");

    const titleWrap = document.createElement("div");
    titleWrap.className = "session-history-group-title-wrap";
    const title = document.createElement("div");
    title.className = "session-history-group-title";
    title.textContent = group.title;
    const path = document.createElement("div");
    path.className = "session-history-group-path";
    path.textContent = group.cwd || "(未记录目录)";
    titleWrap.appendChild(title);
    titleWrap.appendChild(path);

    const groupCount = document.createElement("span");
    groupCount.className = "session-history-group-count";
    groupCount.textContent = `${group.items.length} 条`;

    header.appendChild(icon);
    header.appendChild(titleWrap);
    header.appendChild(groupCount);
    header.addEventListener("click", () => {
      if (sessionHistoryCollapsedGroups.has(group.key)) {
        sessionHistoryCollapsedGroups.delete(group.key);
      } else {
        sessionHistoryCollapsedGroups.add(group.key);
      }
      renderSessionHistoryList();
    });
    section.appendChild(header);

    const sessionsWrap = document.createElement("div");
    sessionsWrap.className = "session-history-group-sessions";

    for (const item of group.items) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "session-history-row";
      row.dataset.sessionKey = item.session_key;
      if (item.session_key === sessionHistoryState.selectedKey) {
        row.classList.add("active");
      }

      const top = document.createElement("div");
      top.className = "session-history-row-top";
      const sessionTitle = document.createElement("div");
      sessionTitle.className = "session-history-session-title";
      sessionTitle.textContent = resolveSessionHistoryTitle(item);
      const time = document.createElement("span");
      time.className = "session-history-time";
      time.textContent = formatSessionTimestampUtc8(item.timestamp);
      top.appendChild(sessionTitle);
      top.appendChild(time);

      const meta = document.createElement("div");
      meta.className = "session-history-session-meta";
      meta.textContent = `${item.question_count || 0} 条提问`;

      row.appendChild(top);
      row.appendChild(meta);
      row.addEventListener("click", () => {
        void selectSessionHistoryItem(item.session_key);
      });
      sessionsWrap.appendChild(row);
    }

    section.appendChild(sessionsWrap);
    fragment.appendChild(section);
  }

  sessionHistoryList.replaceChildren(fragment);

  if (!sessionHistoryState.items.length && !sessionHistoryState.loading) {
    sessionHistoryListStatus.textContent = "暂无会话记录。";
  }

  if (sessionHistoryState.loading) {
    sessionHistoryLoadMoreButton.disabled = true;
    sessionHistoryLoadMoreButton.textContent = "加载中...";
  } else {
    sessionHistoryLoadMoreButton.disabled = !sessionHistoryState.hasMore;
    sessionHistoryLoadMoreButton.textContent = sessionHistoryState.hasMore
      ? "加载更多"
      : "没有更多了";
  }
};

const renderSessionQuestionList = (session) => {
  const questions = Array.isArray(session.questions) ? session.questions : [];
  const sessionId = typeof session.session_id === "string" ? session.session_id : "";
  const cwd = typeof session.cwd === "string" ? session.cwd.trim() : "";
  sessionHistoryDetailTitle.textContent = `我的提问（${questions.length}）`;
  sessionHistoryDetailMeta.textContent = buildSessionHistoryDetailMeta(sessionId, cwd);
  setSessionHistoryCopyState(sessionId);

  if (!questions.length) {
    const empty = document.createElement("div");
    empty.className = "session-history-empty";
    empty.textContent = "该会话暂无提问记录。";
    sessionHistoryQuestionList.replaceChildren(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  questions.forEach((question, index) => {
    const item = document.createElement("div");
    item.className = "session-history-question-item";

    const indexNode = document.createElement("div");
    indexNode.className = "session-history-question-index";
    indexNode.textContent = `Q${index + 1}`;

    const textNode = document.createElement("div");
    textNode.className = "session-history-question-text";
    textNode.textContent = question;

    item.appendChild(indexNode);
    item.appendChild(textNode);
    fragment.appendChild(item);
  });

  sessionHistoryQuestionList.replaceChildren(fragment);
};

const renderSessionHistoryLoading = ({ resetMeta = true } = {}) => {
  sessionHistoryQuestionList.innerHTML = "";
  sessionHistoryDetailTitle.textContent = "我的提问";
  if (resetMeta) {
    sessionHistoryDetailMeta.textContent = "";
    setSessionHistoryCopyState("");
  }
};

const renderSessionHistoryPlaceholder = (message = "请选择左侧会话查看提问。") => {
  sessionHistoryDetailTitle.textContent = "我的提问";
  sessionHistoryDetailMeta.textContent = "";
  setSessionHistoryCopyState("");
  const empty = document.createElement("div");
  empty.className = "session-history-empty";
  empty.textContent = message;
  sessionHistoryQuestionList.replaceChildren(empty);
};

const renderSessionHistoryError = (message) => {
  sessionHistoryDetailTitle.textContent = "会话提问";
  sessionHistoryDetailMeta.textContent = "";
  setSessionHistoryCopyState("");
  const error = document.createElement("div");
  error.className = "session-history-empty";
  error.textContent = message;
  sessionHistoryQuestionList.replaceChildren(error);
};

const queueSessionHistorySearch = () => {
  if (sessionHistorySearchTimer) {
    clearTimeout(sessionHistorySearchTimer);
  }
  sessionHistorySearchTimer = setTimeout(() => {
    sessionHistorySearchTimer = null;
    const nextQuery = sessionHistorySearchInput.value.trim();
    sessionHistorySearchQuery = nextQuery;
    void loadSessionHistoryPage({ reset: true });
  }, 120);
};

const ensureSessionHistorySelection = () => {
  if (!sessionHistoryState.items.length) {
    sessionHistoryState.selectedKey = null;
    setSessionHistoryCopyState("");
    renderSessionHistoryPlaceholder(
      sessionHistorySearchQuery ? "未找到匹配目录。" : "暂无会话记录。"
    );
    return;
  }

  const hasSelected = sessionHistoryState.items.some(
    (item) => item.session_key === sessionHistoryState.selectedKey
  );
  if (hasSelected) {
    void selectSessionHistoryItem(sessionHistoryState.selectedKey);
    return;
  }

  const firstSessionKey = sessionHistoryState.items[0]?.session_key;
  if (!firstSessionKey) {
    return;
  }
  sessionHistoryState.selectedKey = null;
  void selectSessionHistoryItem(firstSessionKey);
};

const selectSessionHistoryItem = async (sessionKey) => {
  const requestSeq = ++sessionHistoryDetailRequestSeq;
  sessionHistoryState.selectedKey = sessionKey;

  const selectedSummary = sessionHistoryState.items.find(
    (item) => item.session_key === sessionKey
  );
  const selectedSessionId = selectedSummary?.session_id || "";
  const selectedCwd =
    typeof selectedSummary?.cwd === "string" ? selectedSummary.cwd.trim() : "";
  sessionHistoryDetailMeta.textContent = buildSessionHistoryDetailMeta(
    selectedSessionId,
    selectedCwd
  );
  setSessionHistoryCopyState(selectedSessionId);

  renderSessionHistoryList();

  const cached = sessionHistoryDetailsCache.get(sessionKey);
  if (cached) {
    setSessionHistoryDetailLoading(false);
    renderSessionQuestionList(cached);
    return;
  }

  renderSessionHistoryLoading({ resetMeta: false });
  setSessionHistoryDetailLoading(true);
  try {
    const detail = await invoke("get_codex_session_questions", { sessionKey });
    sessionHistoryDetailsCache.set(sessionKey, detail);
    if (
      sessionHistoryState.selectedKey !== sessionKey ||
      requestSeq !== sessionHistoryDetailRequestSeq
    ) {
      return;
    }
    renderSessionQuestionList(detail);
  } catch (error) {
    if (
      sessionHistoryState.selectedKey !== sessionKey ||
      requestSeq !== sessionHistoryDetailRequestSeq
    ) {
      return;
    }
    renderSessionHistoryError(`加载失败：${String(error)}`);
  } finally {
    if (requestSeq === sessionHistoryDetailRequestSeq) {
      setSessionHistoryDetailLoading(false);
    }
  }
};

const loadSessionHistoryPage = async ({ reset = false } = {}) => {
  if (sessionHistoryState.loading && !reset) {
    return;
  }

  const requestSeq = ++sessionHistoryListRequestSeq;
  const query = sessionHistorySearchQuery;
  const previousSelectedKey = sessionHistoryState.selectedKey;

  if (reset) {
    resetSessionHistoryState();
    sessionHistoryState.selectedKey = previousSelectedKey;
    sessionHistoryListStatus.textContent = query
      ? `正在搜索“${query}”...`
      : "正在加载会话...";
    renderSessionHistoryList();
  }

  sessionHistoryState.loading = true;
  sessionHistoryListPane.classList.add("loading");
  renderSessionHistoryList();

  try {
    const page = await invoke("list_codex_session_history", {
      offset: sessionHistoryState.nextOffset,
      limit: SESSION_HISTORY_PAGE_SIZE,
      query: query || null,
    });
    if (requestSeq !== sessionHistoryListRequestSeq) {
      return;
    }
    const incoming = Array.isArray(page.sessions) ? page.sessions : [];
    if (incoming.length) {
      sessionHistoryState.items.push(...incoming);
    }
    sessionHistoryState.total = Number.isFinite(page.total)
      ? page.total
      : sessionHistoryState.items.length;
    sessionHistoryState.nextOffset = Number.isFinite(page.next_offset)
      ? page.next_offset
      : sessionHistoryState.items.length;
    sessionHistoryState.hasMore = Boolean(page.has_more);

    if (!sessionHistoryState.items.length) {
      sessionHistoryListStatus.textContent = query ? "未找到匹配目录。" : "暂无会话记录。";
      setSessionHistoryDetailLoading(false);
      sessionHistoryState.selectedKey = null;
      setSessionHistoryCopyState("");
      renderSessionHistoryPlaceholder(query ? "未找到匹配目录。" : "暂无会话记录。");
    } else {
      sessionHistoryListStatus.textContent = getSessionHistoryStatusText();
      ensureSessionHistorySelection();
    }
  } catch (error) {
    if (requestSeq !== sessionHistoryListRequestSeq) {
      return;
    }
    sessionHistoryListStatus.textContent = `加载失败：${String(error)}`;
    setSessionHistoryDetailLoading(false);
    renderSessionHistoryError(`加载失败：${String(error)}`);
  } finally {
    if (requestSeq === sessionHistoryListRequestSeq) {
      sessionHistoryState.loading = false;
      sessionHistoryListPane.classList.remove("loading");
      renderSessionHistoryList();
    }
  }
};

const openSessionHistoryModal = () => {
  hideContextMenu();
  sessionHistoryModal.classList.add("show");
  sessionHistoryListPane.classList.add("loading");
  sessionHistoryListStatus.textContent = sessionHistorySearchQuery
    ? `正在搜索“${sessionHistorySearchQuery}”...`
    : "正在加载会话...";
  renderSessionHistoryLoading();
  setSessionHistoryDetailLoading(true);
  requestAnimationFrame(() => {
    sessionHistorySearchInput.focus();
    void loadSessionHistoryPage({ reset: true });
  });
};

const closeSessionHistoryModal = () => {
  sessionHistoryModal.classList.remove("show");
  setTimeout(focusActiveTerminal, 0);
};

sessionHistoryCloseButton.addEventListener("click", closeSessionHistoryModal);
sessionHistoryModal.addEventListener("click", (event) => {
  if (event.target === sessionHistoryModal) {
    closeSessionHistoryModal();
  }
});
sessionHistorySearchInput.addEventListener("input", queueSessionHistorySearch);
sessionHistorySearchInput.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && sessionHistorySearchInput.value) {
    sessionHistorySearchInput.value = "";
    queueSessionHistorySearch();
  }
});
sessionHistoryCopyButton.addEventListener("click", () => {
  const command = sessionHistoryCopyButton.dataset.command || "";
  if (!command) {
    return;
  }
  void copyTextToClipboard(command).then((copied) => {
    if (copied) {
      triggerCopyFeedback();
    }
  });
});
sessionHistoryLoadMoreButton.addEventListener("click", () => {
  void loadSessionHistoryPage({ reset: false });
});

const clampFontSize = (value) =>
  Math.min(MAX_FONT_SIZE, Math.max(MIN_FONT_SIZE, value));

const applyReservedRows = (terminal) => {
  if (!terminal || !RESERVED_BOTTOM_ROWS) {
    return;
  }
  const targetRows = Math.max(1, terminal.rows - RESERVED_BOTTOM_ROWS);
  if (targetRows !== terminal.rows) {
    terminal.resize(terminal.cols, targetRows);
  }
};

const loadFontSize = () => {
  const stored = localStorage.getItem(FONT_SIZE_KEY);
  const parsed = Number(stored);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_FONT_SIZE;
  }
  return clampFontSize(parsed);
};

const buildDefaultHotkeys = () => {
  const hotkeys = {};
  for (const def of DEFAULT_HOTKEYS) {
    hotkeys[def.id] = def.defaultKey || "";
  }
  return hotkeys;
};

const loadHotkeys = () => {
  let stored = null;
  try {
    stored = JSON.parse(localStorage.getItem(HOTKEYS_STORAGE_KEY) || "{}");
  } catch {
    stored = {};
  }
  const hotkeys = buildDefaultHotkeys();
  for (const def of DEFAULT_HOTKEYS) {
    const value = stored[def.id];
    if (typeof value === "string") {
      hotkeys[def.id] = value;
    }
  }
  return hotkeys;
};

const saveHotkeys = (hotkeys) => {
  localStorage.setItem(HOTKEYS_STORAGE_KEY, JSON.stringify(hotkeys));
};

let fontSize = loadFontSize();
let hotkeys = loadHotkeys();
let hotkeyIndex = new Map();
let hotkeyCapture = null;

const loadOverlayText = () => DEFAULT_OVERLAY_TEXT;

const clampValue = (value, min, max) => Math.max(min, Math.min(max, value));

const resolveOverlayPosition = (position) => {
  if (!brandOverlay) {
    return null;
  }
  const rect = brandOverlay.getBoundingClientRect();
  const min = 8;
  const maxX = Math.max(min, window.innerWidth - rect.width - min);
  const maxY = Math.max(min, window.innerHeight - rect.height - min);
  if (position && Number.isFinite(position.rx) && Number.isFinite(position.ry)) {
    const rx = clampValue(position.rx, 0, 1);
    const ry = clampValue(position.ry, 0, 1);
    const left = min + (maxX - min) * rx;
    const top = min + (maxY - min) * ry;
    return { left, top, rx, ry };
  }
  if (position && Number.isFinite(position.x) && Number.isFinite(position.y)) {
    const left = clampValue(position.x, min, maxX);
    const top = clampValue(position.y, min, maxY);
    const rangeX = Math.max(1, maxX - min);
    const rangeY = Math.max(1, maxY - min);
    const rx = rangeX ? (left - min) / rangeX : 0;
    const ry = rangeY ? (top - min) / rangeY : 0;
    return { left, top, rx, ry };
  }
  return null;
};

const applyOverlayPosition = (position) => {
  if (!brandOverlay) {
    return null;
  }
  const resolved = resolveOverlayPosition(position);
  if (!resolved) {
    brandOverlay.style.left = "auto";
    brandOverlay.style.top = `${OVERLAY_DEFAULT_POSITION.top}px`;
    brandOverlay.style.right = `${OVERLAY_DEFAULT_POSITION.right}px`;
    brandOverlay.style.bottom = "auto";
    return null;
  }
  brandOverlay.style.left = `${Math.round(resolved.left)}px`;
  brandOverlay.style.top = `${Math.round(resolved.top)}px`;
  brandOverlay.style.right = "auto";
  brandOverlay.style.bottom = "auto";
  return { rx: resolved.rx, ry: resolved.ry };
};

const updateOverlayForTab = (tabId) => {
  if (!brandOverlay) {
    return;
  }
  if (brandOverlay.classList.contains("editing")) {
    setOverlayEditing(false);
  }
  const tab = tabId ? tabs.get(tabId) : null;
  const text = tab?.overlayText || loadOverlayText();
  brandOverlay.textContent = text;
  const normalized = applyOverlayPosition(tab?.overlayPos || null);
  if (
    normalized &&
    tab &&
    (!tab.overlayPos ||
      !Number.isFinite(tab.overlayPos.rx) ||
      !Number.isFinite(tab.overlayPos.ry))
  ) {
    tab.overlayPos = normalized;
    saveTabsState();
  }
};

const commitOverlayText = () => {
  if (!brandOverlay) {
    return;
  }
  const value = brandOverlay.textContent?.trim() || "";
  if (!value) {
    return;
  }
  if (activeTabId) {
    const tab = tabs.get(activeTabId);
    if (tab) {
      tab.overlayText = value;
      saveTabsState();
    }
  }
};

const setOverlayEditing = (editing, position) => {
  if (!brandOverlay) {
    return;
  }
  brandOverlay.setAttribute("contenteditable", editing ? "true" : "false");
  brandOverlay.classList.toggle("editing", editing);
  if (editing) {
    brandOverlay.focus();
    const selection = window.getSelection();
    if (selection) {
      let range = null;
      if (position && typeof document.caretPositionFromPoint === "function") {
        const caret = document.caretPositionFromPoint(position.x, position.y);
        if (caret?.offsetNode && brandOverlay.contains(caret.offsetNode)) {
          range = document.createRange();
          range.setStart(caret.offsetNode, caret.offset);
          range.collapse(true);
        }
      } else if (
        position &&
        typeof document.caretRangeFromPoint === "function"
      ) {
        const caretRange = document.caretRangeFromPoint(
          position.x,
          position.y
        );
        if (caretRange && brandOverlay.contains(caretRange.startContainer)) {
          range = caretRange;
          range.collapse(true);
        }
      }
      if (!range) {
        range = document.createRange();
        range.selectNodeContents(brandOverlay);
        range.collapse(false);
      }
      selection.removeAllRanges();
      selection.addRange(range);
    }
  } else {
    brandOverlay.blur();
  }
};

const updateTabCwdForSession = (tab, sessionId, cwd) => {
  if (!tab || !sessionId || !cwd) {
    return;
  }
  if (tab.leftSessionId === sessionId) {
    if (tab.leftLaunchSpec?.kind === "local") {
      tab.leftLaunchSpec = { kind: "local", cwd };
    }
    return;
  }
  if (tab.rightSessionId === sessionId) {
    if (tab.rightLaunchSpec?.kind === "local") {
      tab.rightLaunchSpec = { kind: "local", cwd };
    }
  }
};

const refreshActiveTabCwd = async () => {
  if (cwdRefreshInFlight || !activeTabId) {
    return;
  }
  const tab = tabs.get(activeTabId);
  const sessionId = tab?.activeSessionId || tab?.leftSessionId;
  if (!sessionId) {
    return;
  }
  const session = sessions.get(sessionId);
  if (session?.kind !== "local") {
    return;
  }
  cwdRefreshInFlight = true;
  try {
    const cwd = await invoke("get_session_cwd_by_id", { sessionId });
    if (cwd && tab) {
      updateTabCwdForSession(tab, sessionId, cwd);
      saveTabsState();
    }
  } catch {
    // 忽略读取失败，等待下次刷新
  } finally {
    cwdRefreshInFlight = false;
  }
};

const refreshAllTabsCwd = async () => {
  if (cwdRefreshInFlight) {
    return;
  }
  const tasks = [];
  for (const tab of tabs.values()) {
    if (tab.leftSessionId && sessions.get(tab.leftSessionId)?.kind === "local") {
      tasks.push({ tab, sessionId: tab.leftSessionId });
    }
    if (tab.rightSessionId && sessions.get(tab.rightSessionId)?.kind === "local") {
      tasks.push({ tab, sessionId: tab.rightSessionId });
    }
  }
  if (!tasks.length) {
    return;
  }
  cwdRefreshInFlight = true;
  try {
    await Promise.allSettled(
      tasks.map(async ({ tab, sessionId }) => {
        const cwd = await invoke("get_session_cwd_by_id", { sessionId });
        if (cwd) {
          updateTabCwdForSession(tab, sessionId, cwd);
        }
      })
    );
    saveTabsState();
  } finally {
    cwdRefreshInFlight = false;
  }
};

const startCwdRefreshLoop = () => {
  if (cwdRefreshTimer) {
    return;
  }
  cwdRefreshTimer = setInterval(() => {
    refreshAllTabsCwd();
  }, CWD_REFRESH_INTERVAL);
};

const setFontSize = (value) => {
  fontSize = clampFontSize(value);
  localStorage.setItem(FONT_SIZE_KEY, String(fontSize));
  for (const session of sessions.values()) {
    session.terminal.options.fontSize = fontSize;
  }
  scheduleFit();
};

const applyTerminalTheme = () => {
  for (const session of sessions.values()) {
    session.terminal.options.theme = TERMINAL_THEME;
  }
};

const adjustFontSize = (delta) => {
  setFontSize(fontSize + delta);
};

const isDragBlockedTarget = (event) =>
  Boolean(
    event.target?.closest(
      ".tab-close, .tab-add, .tab-rename-input, .context-menu, .hotkey-modal"
    )
  );

const isMaximizeBlockedTarget = (event) =>
  Boolean(
    event.target?.closest(
      ".tab, .tab-close, .tab-add, .tab-rename-input, .context-menu, .hotkey-modal"
    )
  );

const fitTab = (tabId, options = {}) => {
  const tab = tabs.get(tabId);
  if (!tab) {
    return;
  }
  const { resizePty = true, refreshTexture = false } = options;
  const sessionIds = [tab.leftSessionId, tab.rightSessionId];
  for (const sessionId of sessionIds) {
    if (!sessionId) {
      continue;
    }
    const session = sessions.get(sessionId);
    if (!session) {
      continue;
    }
    if (refreshTexture && typeof session.terminal.clearTextureAtlas === "function") {
      session.terminal.clearTextureAtlas();
    }
    session.fitAddon.fit();
    applyReservedRows(session.terminal);
    if (resizePty && !session.ended) {
      invoke("resize_session", {
        sessionId,
        cols: session.terminal.cols,
        rows: session.terminal.rows,
      }).catch(() => {});
    }
  }
};

let resizeRaf = null;
let dprWatcher = null;
const scheduleFit = (options = {}) => {
  if (!activeTabId) {
    return;
  }
  const { immediate = false, resizePty = true, refreshTexture = false } = options;
  if (resizeTimer) {
    clearTimeout(resizeTimer);
    resizeTimer = null;
  }
  if (resizeRaf) {
    cancelAnimationFrame(resizeRaf);
    resizeRaf = null;
  }
  if (immediate) {
    const tabId = activeTabId;
    resizeRaf = requestAnimationFrame(() => {
      resizeRaf = null;
      fitTab(tabId, { resizePty, refreshTexture });
    });
    return;
  }
  resizeTimer = setTimeout(() => {
    resizeTimer = null;
    fitTab(activeTabId, { resizePty, refreshTexture });
  }, 80);
};

const watchDevicePixelRatio = () => {
  if (dprWatcher) {
    return;
  }
  let currentDpr = window.devicePixelRatio || 1;
  const handleChange = () => {
    const nextDpr = window.devicePixelRatio || 1;
    if (nextDpr !== currentDpr) {
      currentDpr = nextDpr;
      scheduleFit({ immediate: true, refreshTexture: true, resizePty: true });
    }
    watch();
  };
  const watch = () => {
    const query = `(resolution: ${window.devicePixelRatio || 1}dppx)`;
    const mql = window.matchMedia(query);
    if (typeof mql.addEventListener === "function") {
      mql.addEventListener("change", handleChange, { once: true });
    } else if (typeof mql.addListener === "function") {
      const listener = () => {
        mql.removeListener(listener);
        handleChange();
      };
      mql.addListener(listener);
    }
  };
  dprWatcher = { handleChange };
  watch();
  window.addEventListener("focus", () => {
    scheduleFit({ immediate: true, refreshTexture: true, resizePty: true });
  });
};

const handleWindowResize = () => {
  const tab = activeTabId ? tabs.get(activeTabId) : null;
  if (tab?.split) {
    refreshSplitLayout(tab);
  }
  if (tab) {
    applyOverlayPosition(tab.overlayPos || null);
  }
  applyWindowBackground();
  ensureWebviewAutoResize();
  scheduleFit({ immediate: true, refreshTexture: true, resizePty: true });
};

const bufferTerminalOutput = (sessionId, data) => {
  const bytes = terminalBytes(data);
  if (!sessionId || !bytes.byteLength) {
    return;
  }
  if (!pendingTerminalOutput.has(sessionId)) {
    while (pendingTerminalOutput.size >= PENDING_OUTPUT_MAX_SESSIONS) {
      const oldestSessionId = pendingTerminalOutput.keys().next().value;
      pendingTerminalOutput.delete(oldestSessionId);
    }
    pendingTerminalOutput.set(sessionId, { chunks: [], byteLength: 0 });
  }
  const entry = pendingTerminalOutput.get(sessionId);
  let next = new Uint8Array(bytes);
  if (next.byteLength >= PENDING_OUTPUT_MAX_BYTES) {
    next = next.slice(next.byteLength - PENDING_OUTPUT_MAX_BYTES);
    entry.chunks = [next];
    entry.byteLength = next.byteLength;
    return;
  }
  while (
    entry.chunks.length &&
    entry.byteLength + next.byteLength > PENDING_OUTPUT_MAX_BYTES
  ) {
    const removed = entry.chunks.shift();
    entry.byteLength -= removed.byteLength;
  }
  entry.chunks.push(next);
  entry.byteLength += next.byteLength;
};

const flushTerminalOutput = (sessionId, terminal) => {
  const entry = pendingTerminalOutput.get(sessionId);
  if (!entry) {
    return;
  }
  pendingTerminalOutput.delete(sessionId);
  for (const chunk of entry.chunks) {
    terminal.write(chunk);
  }
};

const rememberTerminalLifecycle = (sessionId, lifecycle) => {
  if (!sessionId) {
    return;
  }
  while (pendingTerminalLifecycle.size >= PENDING_OUTPUT_MAX_SESSIONS) {
    const oldestSessionId = pendingTerminalLifecycle.keys().next().value;
    pendingTerminalLifecycle.delete(oldestSessionId);
  }
  pendingTerminalLifecycle.set(sessionId, lifecycle);
};

const hidePaneSessionStatus = (container) => {
  container?.closest(".pane")?.querySelector(".pane-session-status")?.remove();
};

const beginPaneRestart = (container) => {
  const started = beginSingleFlight(paneRestartStates.get(container));
  if (!started) {
    return null;
  }
  paneRestartStates.set(container, started.state);
  return started.generation;
};

const isPaneRestartCurrent = (container, generation) =>
  paneRestartStates.get(container)?.generation === generation;

const finishPaneRestart = (container, generation) => {
  const current = paneRestartStates.get(container);
  paneRestartStates.set(container, finishSingleFlight(current, generation));
};

const invalidatePaneRestart = (container) => {
  paneRestartStates.set(
    container,
    invalidateSingleFlight(paneRestartStates.get(container))
  );
};

const disposePaneTerminal = (pane) => {
  const container = pane?.querySelector(".terminal");
  if (!container) {
    return;
  }
  invalidatePaneRestart(container);
  terminalViews.get(container)?.dispose();
  terminalViews.delete(container);
};

const showPaneSessionStatus = (
  container,
  {
    message,
    reconnect = null,
    openConnections = false,
    profileId = null,
    error = false,
  }
) => {
  const pane = container?.closest(".pane");
  if (!pane) {
    return;
  }
  hidePaneSessionStatus(container);
  const status = document.createElement("div");
  status.className = "pane-session-status";
  status.classList.toggle("error", error);
  const text = document.createElement("span");
  text.textContent = message;
  const actions = document.createElement("div");
  actions.className = "pane-session-status-actions";
  if (reconnect) {
    const reconnectButton = document.createElement("button");
    reconnectButton.type = "button";
    reconnectButton.textContent = "重新连接";
    reconnectButton.addEventListener("click", () => {
      if (reconnectButton.disabled) {
        return;
      }
      reconnectButton.disabled = true;
      reconnectButton.textContent = "连接中...";
      reconnectButton.setAttribute("aria-busy", "true");
      void Promise.resolve(reconnect()).catch(() => {});
    });
    actions.appendChild(reconnectButton);
  }
  if (openConnections) {
    const openButton = document.createElement("button");
    openButton.type = "button";
    openButton.textContent = "打开连接中心";
    openButton.addEventListener("click", () =>
      void openSshConnections({ profileId })
    );
    actions.appendChild(openButton);
  }
  status.appendChild(text);
  if (actions.childElementCount) {
    status.appendChild(actions);
  }
  pane.appendChild(status);
};

const createPane = () => {
  const pane = document.createElement("div");
  pane.className = "pane";
  const terminal = document.createElement("div");
  terminal.className = "terminal";
  pane.appendChild(terminal);
  return { pane, terminal };
};

const startTerminal = async (container, tabId, options = {}) => {
  if (!container) {
    return null;
  }
  const launchSpec = normalizeLaunchSpec(options.launchSpec, options.cwd);
  const sessionKind = launchSpec.kind;
  const canUpdatePaneStatus = () =>
    options.paneGeneration == null ||
    isPaneRestartCurrent(container, options.paneGeneration);
  const terminal = new Terminal({
    cursorBlink: true,
    allowTransparency: true,
    fontSize,
    fontWeight: "bold",
    fontWeightBold: "bold",
    fontFamily: "Menlo, monospace",
    lineHeight: 1,
    letterSpacing: 0,
    drawBoldTextInBrightColors: false,
    theme: TERMINAL_THEME,
  });
  const fitAddon = new FitAddon.FitAddon();
  terminal.loadAddon(fitAddon);
  terminal.open(container);
  terminalViews.set(container, terminal);
  terminal.options.theme = TERMINAL_THEME;
  fitAddon.fit();
  applyReservedRows(terminal);

  const copySelectionToClipboard = async () => {
    const selection = terminal.getSelection();
    if (!selection) {
      return false;
    }
    return copyTextToClipboard(selection);
  };

  terminal.attachCustomKeyEventHandler((event) => {
    if (event.key === "Meta") {
      event.preventDefault();
      return false;
    }
    if (
      terminal.hasSelection() &&
      (event.metaKey || event.ctrlKey) &&
      !event.altKey &&
      !event.shiftKey &&
      event.key?.toLowerCase() === "c"
    ) {
      event.preventDefault();
      void copySelectionToClipboard().then((copied) => {
        if (copied) {
          triggerCopyFeedback();
        }
      });
      return false;
    }
    return true;
  });

  let sessionId = null;
  let cloneError = null;
  if (sessionKind === "ssh") {
    if (sshProfilesLoaded) {
      const resolution = resolveSshLaunchProfile(launchSpec, sshProfiles);
      if (resolution.error) {
        terminal.writeln(resolution.error);
        if (canUpdatePaneStatus()) {
          showPaneSessionStatus(container, {
            message: resolution.error,
            openConnections: true,
            profileId: launchSpec.profileId,
            error: true,
          });
        }
        return null;
      }
    }
    try {
      sessionId = await invoke("start_ssh_session", {
        profileId: launchSpec.profileId,
        cols: terminal.cols,
        rows: terminal.rows,
      });
    } catch (error) {
      terminal.writeln("无法启动 SSH 会话。");
      terminal.writeln(String(error));
      if (canUpdatePaneStatus()) {
        showPaneSessionStatus(container, {
          message: String(error),
          reconnect: () =>
            restartTerminalPane({
              tabId,
              side: options.side || "left",
              container,
              launchSpec,
              previousSessionId: null,
            }),
          openConnections: true,
          profileId: launchSpec.profileId,
          error: true,
        });
      }
      return null;
    }
  } else {
    if (options.cloneFromSessionId) {
      try {
        sessionId = await invoke("clone_session", {
          sessionId: options.cloneFromSessionId,
          cols: terminal.cols,
          rows: terminal.rows,
        });
      } catch (error) {
        cloneError = error;
      }
    }

    if (!sessionId) {
      try {
        sessionId = await invoke("start_session", {
          cols: terminal.cols,
          rows: terminal.rows,
          cwd: launchSpec.cwd || null,
        });
      } catch (error) {
        terminal.writeln("无法启动终端会话，请确认系统 Shell 可用。");
        terminal.writeln(String(error));
        return null;
      }
    }
  }

  const session = {
    terminal,
    fitAddon,
    tabId,
    side: options.side || "left",
    kind: sessionKind,
    profileId: sessionKind === "ssh" ? launchSpec.profileId : null,
    launchSpec,
    container,
    ended: false,
  };
  sessions.set(sessionId, session);
  if (canUpdatePaneStatus()) {
    hidePaneSessionStatus(container);
  }
  flushTerminalOutput(sessionId, terminal);
  const pendingLifecycle = pendingTerminalLifecycle.get(sessionId);
  if (pendingLifecycle) {
    pendingTerminalLifecycle.delete(sessionId);
    queueMicrotask(() => handleTerminalLifecycle(sessionId, pendingLifecycle));
  }
  const sendInput = (data) => {
    if (!sessionId || sessions.get(sessionId)?.ended) {
      return;
    }
    invoke("send_input", { sessionId, data }).catch(() => {});
  };

  const pendingInputs = new Map();
  let pendingInputId = 0;
  const recentInputs = [];
  const RECENT_INPUT_TTL = 80;
  const BEFORE_INPUT_WINDOW = 60;
  const lastBeforeInput = { data: null, time: 0 };

  const recordRecentInput = (data) => {
    const now = Date.now();
    recentInputs.push({ data, time: now });
    while (recentInputs.length && now - recentInputs[0].time > RECENT_INPUT_TTL) {
      recentInputs.shift();
    }
  };

  const wasRecentlySent = (text) => {
    const now = Date.now();
    return recentInputs.some(
      (entry) => entry.data === text && now - entry.time <= RECENT_INPUT_TTL
    );
  };

  const clearPendingByText = (text) => {
    for (const [id, entry] of pendingInputs) {
      if (entry.text === text) {
        clearTimeout(entry.timer);
        pendingInputs.delete(id);
        return;
      }
    }
  };

  const enqueueInputFallback = (text) => {
    if (!text || wasRecentlySent(text)) {
      return;
    }
    const id = pendingInputId++;
    const entry = {
      text,
      timer: setTimeout(() => {
        pendingInputs.delete(id);
        if (wasRecentlySent(text)) {
          return;
        }
        sendInput(text);
      }, 0),
    };
    pendingInputs.set(id, entry);
  };

  const seenBeforeInputRecently = (text) =>
    text &&
    lastBeforeInput.data === text &&
    Date.now() - lastBeforeInput.time <= BEFORE_INPUT_WINDOW;

  let quickCommandBuffer = "";
  const resetQuickCommandBuffer = () => {
    quickCommandBuffer = "";
  };
  const recordQuickCommandInput = (data) => {
    if (sessionKind !== "local") {
      return false;
    }
    if (terminal.buffer?.active !== terminal.buffer?.normal) {
      resetQuickCommandBuffer();
      return false;
    }
    if (data === "\r" || data === "\n") {
      const command = quickCommandBuffer;
      resetQuickCommandBuffer();
      if (command === "o") {
        sendInput("\u0015");
        void openFinderForSession(sessionId);
        return true;
      }
      if (command === "cx") {
        sendInput("\u0015");
        void openSessionHistoryModal();
        return true;
      }
      return false;
    }
    if (data === "\u007f" || data === "\b") {
      quickCommandBuffer = quickCommandBuffer.slice(0, -1);
      return false;
    }
    if (data.length === 1 && data >= " " && data <= "~") {
      if (quickCommandBuffer.length < 32) {
        quickCommandBuffer += data;
      } else {
        resetQuickCommandBuffer();
      }
      return false;
    }
    resetQuickCommandBuffer();
    return false;
  };

  terminal.onData((data) => {
    recordRecentInput(data);
    clearPendingByText(data);
    if (recordQuickCommandInput(data)) {
      return;
    }
    sendInput(data);
  });

  if (terminal.textarea) {
    terminal.textarea.addEventListener(
      "beforeinput",
      (event) => {
        if (!event.data) {
          return;
        }
        if (
          event.inputType !== "insertText" &&
          event.inputType !== "insertCompositionText"
        ) {
          return;
        }
        if (event.isComposing) {
          return;
        }
        lastBeforeInput.data = event.data;
        lastBeforeInput.time = Date.now();
        enqueueInputFallback(event.data);
      },
      true
    );
    terminal.textarea.addEventListener(
      "input",
      (event) => {
        if (!event.data) {
          return;
        }
        if (
          event.inputType !== "insertText" &&
          event.inputType !== "insertCompositionText"
        ) {
          return;
        }
        if (event.isComposing || seenBeforeInputRecently(event.data)) {
          return;
        }
        enqueueInputFallback(event.data);
      },
      true
    );
    terminal.textarea.addEventListener("compositionend", (event) => {
      if (!event.data || seenBeforeInputRecently(event.data)) {
        return;
      }
      enqueueInputFallback(event.data);
    });
    terminal.textarea.addEventListener("focus", () => {
      if (brandOverlay?.isContentEditable) {
        setOverlayEditing(false);
      }
      const tab = tabs.get(tabId);
      if (tab) {
        tab.activeSessionId = sessionId;
      }
      setActiveTab(tabId);
    });
  }

  if (cloneError) {
    terminal.writeln("克隆失败，已使用默认环境启动。");
    terminal.writeln(String(cloneError));
  }

  if (sessionKind === "local" && launchSpec.cwd) {
    const tab = tabs.get(tabId);
    if (tab) {
      if (options.side === "right") {
        tab.rightLaunchSpec = launchSpec;
      } else {
        tab.leftLaunchSpec = launchSpec;
      }
    }
  }

  return sessionId;
};

const restartTerminalPane = async ({
  tabId,
  side,
  container,
  launchSpec,
  previousSessionId,
}) => {
  const tab = tabs.get(tabId);
  if (!tab || !container) {
    return;
  }
  const sessionKey = side === "right" ? "rightSessionId" : "leftSessionId";
  if (previousSessionId && tab[sessionKey] !== previousSessionId) {
    return;
  }
  const paneGeneration = beginPaneRestart(container);
  if (paneGeneration == null) {
    return;
  }
  try {
    const wasActive = tab.activeSessionId === previousSessionId;
    if (previousSessionId) {
      closeSession(previousSessionId);
    } else {
      terminalViews.get(container)?.dispose();
      terminalViews.delete(container);
    }
    hidePaneSessionStatus(container);
    container.replaceChildren();
    const nextSessionId = await startTerminal(container, tabId, {
      launchSpec,
      side,
      paneGeneration,
    });
    const paneStillMounted =
      side === "right"
        ? tab.rightPane?.contains(container) && Boolean(tab.split)
        : tab.leftPane?.contains(container);
    if (
      !isPaneRestartCurrent(container, paneGeneration) ||
      !tabs.has(tabId) ||
      !paneStillMounted
    ) {
      closeSession(nextSessionId);
      terminalViews.get(container)?.dispose();
      terminalViews.delete(container);
      return;
    }
    tab[sessionKey] = nextSessionId;
    if (wasActive || (!tab.activeSessionId && side === "left")) {
      tab.activeSessionId = nextSessionId;
    }
    saveTabsState();
    scheduleFit({ immediate: true, resizePty: true });
    if (nextSessionId && activeTabId === tabId) {
      sessions.get(nextSessionId)?.terminal?.focus();
    }
  } finally {
    finishPaneRestart(container, paneGeneration);
  }
};

const getTerminalLifecycleMessage = (lifecycle) => {
  const payload = lifecycle?.payload;
  if (typeof payload?.error === "string" && payload.error.trim()) {
    return payload.error;
  }
  if (typeof payload?.message === "string" && payload.message.trim()) {
    return payload.message;
  }
  return lifecycle?.type === "error" ? "SSH 会话读取失败。" : "SSH 连接已断开。";
};

const handleTerminalLifecycle = (sessionId, lifecycle) => {
  const session = sessions.get(sessionId);
  if (!session) {
    rememberTerminalLifecycle(sessionId, lifecycle);
    return;
  }
  session.ended = true;
  pendingTerminalOutput.delete(sessionId);
  if (session.kind !== "ssh") {
    return;
  }
  const message = getTerminalLifecycleMessage(lifecycle);
  showPaneSessionStatus(session.container, {
    message,
    reconnect: () =>
      void restartTerminalPane({
        tabId: session.tabId,
        side: session.side,
        container: session.container,
        launchSpec: session.launchSpec,
        previousSessionId: sessionId,
      }),
    openConnections: lifecycle?.type === "error",
    profileId: session.profileId,
    error: lifecycle?.type === "error",
  });
};

const closeSession = (sessionId) => {
  if (!sessionId) {
    return;
  }
  const session = sessions.get(sessionId);
  if (session) {
    session.terminal.dispose();
    if (terminalViews.get(session.container) === session.terminal) {
      terminalViews.delete(session.container);
    }
    sessions.delete(sessionId);
  }
  pendingTerminalOutput.delete(sessionId);
  pendingTerminalLifecycle.delete(sessionId);
  invoke("close_session", { sessionId }).catch(() => {});
};

const setActiveTab = (tabId) => {
  if (activeTabId === tabId) {
    return;
  }
  if (activeTabId) {
    const prev = tabs.get(activeTabId);
    if (prev) {
      prev.tabButton.classList.remove("active");
      prev.panel.classList.remove("active");
    }
  }
  activeTabId = tabId;
  const next = tabs.get(tabId);
  if (next) {
    next.tabButton.classList.add("active");
    next.panel.classList.add("active");
    if (!next.activeSessionId) {
      next.activeSessionId = next.leftSessionId;
    }
    requestAnimationFrame(() => refreshSplitLayout(next));
  }
  updateOverlayForTab(tabId);
  scheduleFit();
  refreshActiveTabCwd();
  requestAnimationFrame(() => {
    if (activeTabId !== tabId) {
      return;
    }
    focusActiveTerminal();
  });
  saveTabsState();
};

const hideContextMenu = () => {
  contextMenu.style.display = "none";
  contextMenu.innerHTML = "";
};

const showContextMenu = (items, x, y) => {
  contextMenu.innerHTML = "";
  for (const item of items) {
    if (item.type === "separator") {
      const separator = document.createElement("div");
      separator.className = "separator";
      contextMenu.appendChild(separator);
      continue;
    }
    const button = document.createElement("button");
    button.type = "button";

    const label = document.createElement("span");
    label.textContent = item.label;
    button.appendChild(label);

    if (item.shortcut) {
      const shortcut = document.createElement("span");
      shortcut.className = "shortcut";
      shortcut.textContent = item.shortcut;
      button.appendChild(shortcut);
    }

    button.addEventListener("click", () => {
      hideContextMenu();
      item.onClick?.();
    });
    contextMenu.appendChild(button);
  }
  contextMenu.style.display = "block";
  contextMenu.style.left = `${x}px`;
  contextMenu.style.top = `${y}px`;

  const rect = contextMenu.getBoundingClientRect();
  const maxLeft = window.innerWidth - rect.width - 8;
  const maxTop = window.innerHeight - rect.height - 8;
  const left = Math.max(8, Math.min(x, maxLeft));
  const top = Math.max(8, Math.min(y, maxTop));
  contextMenu.style.left = `${left}px`;
  contextMenu.style.top = `${top}px`;
};

const renameTab = (tabId) => {
  const tab = tabs.get(tabId);
  if (!tab || tab.renameInput) {
    return;
  }
  const currentLabel = tab.labelSpan.textContent || "";
  const input = document.createElement("input");
  input.type = "text";
  input.className = "tab-rename-input";
  input.value = currentLabel;

  const finish = (apply) => {
    const value = input.value.trim();
    if (apply && value) {
      tab.labelSpan.textContent = value;
    }
    input.remove();
    tab.labelSpan.style.display = "";
    tab.renameInput = null;
    saveTabsState();
  };

  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      finish(true);
    } else if (event.key === "Escape") {
      event.preventDefault();
      finish(false);
    }
  });
  input.addEventListener("blur", () => finish(true));
  input.addEventListener("mousedown", (event) => event.stopPropagation());
  input.addEventListener("click", (event) => event.stopPropagation());

  tab.labelSpan.style.display = "none";
  tab.tabButton.insertBefore(input, tab.labelSpan);
  tab.renameInput = input;
  input.focus();
  input.select();
};

const getTabButtons = () =>
  Array.from(tabsContainer.querySelectorAll(".tab[data-tab-id]"));

const createTabButton = (tabId, label) => {
  const tabButton = document.createElement("button");
  tabButton.type = "button";
  tabButton.className = "tab";
  tabButton.dataset.tabId = tabId;

  const labelSpan = document.createElement("span");
  labelSpan.className = "tab-label";
  labelSpan.textContent = label;

  const closeButton = document.createElement("button");
  closeButton.type = "button";
  closeButton.className = "tab-close";
  closeButton.textContent = "×";
  closeButton.addEventListener("click", (event) => {
    event.stopPropagation();
    closeTab(tabId);
  });

  tabButton.appendChild(labelSpan);
  tabButton.appendChild(closeButton);

  let suppressClick = false;
  tabButton.addEventListener("click", (event) => {
    if (suppressClick) {
      suppressClick = false;
      event.preventDefault();
      event.stopPropagation();
      return;
    }
    setActiveTab(tabId);
  });
  tabButton.addEventListener("mousedown", (event) => {
    if (event.button !== 0) {
      return;
    }
    if (event.target?.closest(".tab-close, .tab-rename-input")) {
      return;
    }
    event.stopPropagation();
    const startRect = tabButton.getBoundingClientRect();
    let startX = event.clientX;
    const startY = event.clientY;
    let dragging = false;
    let moved = false;

    const cleanup = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      if (dragging) {
        tabButton.classList.remove("tab-dragging");
        tabButton.style.transform = "";
        tabButton.style.width = "";
        tabButton.style.zIndex = "";
        tabButton.style.pointerEvents = "";
        suppressClick = true;
        setTimeout(focusActiveTerminal, 0);
      }
      if (moved) {
        saveTabsState();
      }
    };

    const reorder = (clientX) => {
      const buttons = getTabButtons();
      const candidates = buttons.filter((button) => button !== tabButton);
      const before = candidates.find((button) => {
        const rect = button.getBoundingClientRect();
        return clientX < rect.left + rect.width / 2;
      });
      const prevRect = tabButton.getBoundingClientRect();
      if (before) {
        if (tabButton.nextElementSibling !== before) {
          tabsContainer.insertBefore(tabButton, before);
        }
      } else if (newTabButton) {
        if (tabButton.nextElementSibling !== newTabButton) {
          tabsContainer.insertBefore(tabButton, newTabButton);
        }
      } else {
        tabsContainer.appendChild(tabButton);
      }
      const nextRect = tabButton.getBoundingClientRect();
      if (Math.round(prevRect.left) !== Math.round(nextRect.left)) {
        startX += nextRect.left - prevRect.left;
        moved = true;
      }
    };

    const onMove = (moveEvent) => {
      const dx = moveEvent.clientX - startX;
      const dy = moveEvent.clientY - startY;
      if (!dragging && Math.abs(dx) + Math.abs(dy) < 4) {
        return;
      }
      if (!dragging) {
        dragging = true;
        tabButton.classList.add("tab-dragging");
        tabButton.style.width = `${startRect.width}px`;
        tabButton.style.zIndex = "5";
        tabButton.style.pointerEvents = "none";
      }
      tabButton.style.transform = `translateX(${dx}px)`;
      reorder(moveEvent.clientX);
    };

    const onUp = () => cleanup();

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  });
  return { tabButton, labelSpan };
};

const getOrderedTabIds = () =>
  Array.from(tabsContainer.querySelectorAll(".tab[data-tab-id]")).map(
    (button) => button.dataset.tabId
  );

let isRestoringTabs = false;

const serializeTabsState = () => {
  const ids = getOrderedTabIds();
  const tabsState = ids
    .map((id) => {
      const tab = tabs.get(id);
      if (!tab) {
        return null;
      }
      return {
        label: tab.labelSpan.textContent || "",
        overlayText: tab.overlayText || DEFAULT_OVERLAY_TEXT,
        overlayPos: tab.overlayPos || null,
        split: Boolean(tab.split),
        leftLaunchSpec: serializeLaunchSpec(tab.leftLaunchSpec),
        rightLaunchSpec:
          tab.split && tab.rightLaunchSpec
            ? serializeLaunchSpec(tab.rightLaunchSpec)
            : null,
      };
    })
    .filter(Boolean);
  const activeIndex = activeTabId ? ids.indexOf(activeTabId) : 0;
  return { tabs: tabsState, activeIndex };
};

const saveTabsState = () => {
  if (isRestoringTabs) {
    return;
  }
  localStorage.setItem(TABS_STATE_KEY, JSON.stringify(serializeTabsState()));
};

const loadTabsState = () => {
  try {
    const parsed = JSON.parse(localStorage.getItem(TABS_STATE_KEY) || "{}");
    if (!Array.isArray(parsed.tabs) || !parsed.tabs.length) {
      return null;
    }
    return {
      tabs: parsed.tabs.filter((tab) => tab && typeof tab === "object"),
      activeIndex:
        Number.isInteger(parsed.activeIndex) && parsed.activeIndex >= 0
          ? parsed.activeIndex
          : 0,
    };
  } catch {
    return null;
  }
};

const switchTabByOffset = (offset) => {
  const ids = getOrderedTabIds();
  if (!ids.length) {
    return;
  }
  const currentIndex = ids.indexOf(activeTabId);
  if (currentIndex === -1) {
    setActiveTab(ids[0]);
    return;
  }
  const nextIndex = (currentIndex + offset + ids.length) % ids.length;
  const nextTabId = ids[nextIndex];
  if (nextTabId) {
    setActiveTab(nextTabId);
  }
};

const switchSplitPane = (direction) => {
  if (!activeTabId) {
    return false;
  }
  const tab = tabs.get(activeTabId);
  if (!tab?.split) {
    return false;
  }
  const targetSessionId =
    direction === "left" ? tab.leftSessionId : tab.rightSessionId;
  if (!targetSessionId) {
    return false;
  }
  tab.activeSessionId = targetSessionId;
  const session = sessions.get(targetSessionId);
  session?.terminal?.focus();
  return true;
};

const getNextTabId = (tabId) => {
  const buttons = Array.from(
    tabsContainer.querySelectorAll(".tab[data-tab-id]")
  );
  const index = buttons.findIndex((button) => button.dataset.tabId === tabId);
  if (index === -1) {
    return null;
  }
  const nextButton = buttons[index + 1] || buttons[index - 1];
  return nextButton?.dataset.tabId || null;
};

const closeTab = (tabId) => {
  const tab = tabs.get(tabId);
  if (!tab) {
    return;
  }
  const nextTabId = tabId === activeTabId ? getNextTabId(tabId) : null;

  closeSession(tab.leftSessionId);
  closeSession(tab.rightSessionId);
  disposePaneTerminal(tab.leftPane);
  disposePaneTerminal(tab.rightPane);

  tab.panel.remove();
  tab.tabButton.remove();
  tabs.delete(tabId);

  if (nextTabId) {
    setActiveTab(nextTabId);
  } else if (tabs.size) {
    const firstTabId = tabs.keys().next().value;
    if (firstTabId) {
      setActiveTab(firstTabId);
    }
  } else {
    createTab();
  }
  saveTabsState();
};

const createSplitGutter = () => {
  const gutter = document.createElement("div");
  gutter.className = "gutter gutter-horizontal split-gutter";
  return gutter;
};

const setSplitLayout = (tab, leftPx, options = {}) => {
  if (!tab?.panel || !tab.leftPane || !tab.rightPane) {
    return;
  }
  const total = tab.panel.clientWidth - SPLIT_GUTTER_SIZE;
  if (total <= 0) {
    return;
  }
  const minSize = Math.min(SPLIT_MIN_SIZE, total / 2);
  const clampedLeft = Math.max(minSize, Math.min(total - minSize, leftPx));
  const rightPx = total - clampedLeft;
  tab.panel.style.gridTemplateColumns = `${clampedLeft}px ${SPLIT_GUTTER_SIZE}px ${rightPx}px`;
  if (options.updateRatio !== false) {
    tab.splitRatio = total > 0 ? clampedLeft / total : 0.5;
  }
};

const ensureSplitLayout = (tab, ratio = 0.5) => {
  if (!tab?.panel || !tab.leftPane || !tab.rightPane) {
    return;
  }
  if (!tab.panel.clientWidth) {
    requestAnimationFrame(() => ensureSplitLayout(tab, ratio));
    return;
  }
  const total = tab.panel.clientWidth - SPLIT_GUTTER_SIZE;
  if (total <= 0) {
    return;
  }
  const leftPx = Math.round(total * ratio);
  setSplitLayout(tab, leftPx);
  scheduleFit({ immediate: true });
};

const refreshSplitLayout = (tab) => {
  if (!tab?.split) {
    return;
  }
  const ratio = Number.isFinite(tab.splitRatio) ? tab.splitRatio : 0.5;
  ensureSplitLayout(tab, ratio);
};

const enableSplit = async (tabId, options = {}) => {
  const tab = tabs.get(tabId);
  if (!tab || tab.split) {
    return;
  }

  const { pane: rightPane, terminal: rightTerminal } = createPane();
  const gutter = createSplitGutter();
  tab.panel.appendChild(rightPane);
  tab.panel.insertBefore(gutter, rightPane);
  tab.panel.classList.add("split");
  tab.rightPane = rightPane;
  const cloneTab = options.cloneFromTabId
    ? tabs.get(options.cloneFromTabId)
    : null;
  tab.splitRatio =
    cloneTab && Number.isFinite(cloneTab.splitRatio) ? cloneTab.splitRatio : 0.5;
  if (!tab.rightLaunchSpec) {
    tab.rightLaunchSpec = cloneLaunchSpec(
      cloneTab?.rightLaunchSpec || cloneTab?.leftLaunchSpec || tab.leftLaunchSpec
    );
  }

  const startDrag = (event) => {
    if (event.button !== undefined && event.button !== 0) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    tab.userResized = true;

    const startX = event.clientX;
    const startLeft = tab.leftPane.getBoundingClientRect().width;
    const onMove = (moveEvent) => {
      setSplitLayout(tab, startLeft + (moveEvent.clientX - startX));
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      scheduleFit({ immediate: true, resizePty: true });
    };
    document.body.style.cursor = "col-resize";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const resetSplit = (event) => {
    event.preventDefault();
    event.stopPropagation();
    tab.userResized = true;
    tab.splitRatio = 0.5;
    ensureSplitLayout(tab, 0.5);
  };

  gutter.addEventListener("mousedown", startDrag);
  gutter.addEventListener("dblclick", resetSplit);
  tab.split = {
    gutter,
    cleanup: () => {
      gutter.removeEventListener("mousedown", startDrag);
      gutter.removeEventListener("dblclick", resetSplit);
    },
  };
  ensureSplitLayout(tab, tab.splitRatio);

  const cloneSessionId =
    cloneTab?.rightSessionId || cloneTab?.leftSessionId || null;
  const rightSessionId = await startTerminal(rightTerminal, tabId, {
    cloneFromSessionId:
      tab.rightLaunchSpec?.kind === "local" &&
      sessions.get(cloneSessionId)?.kind === "local"
        ? cloneSessionId
        : null,
    launchSpec: tab.rightLaunchSpec,
    side: "right",
  });

  if (!tabs.has(tabId) || tab.rightPane !== rightPane || !tab.split) {
    closeSession(rightSessionId);
    disposePaneTerminal(rightPane);
    return;
  }

  tab.rightSessionId = rightSessionId;
  ensureSplitLayout(tab, tab.splitRatio);
  scheduleFit();
  saveTabsState();
};

const disableSplit = (tabId) => {
  const tab = tabs.get(tabId);
  if (!tab || !tab.split) {
    return;
  }

  tab.split?.cleanup?.();
  if (tab.split?.gutter) {
    tab.split.gutter.remove();
  }
  tab.split = null;
  tab.panel.classList.remove("split");

  closeSession(tab.rightSessionId);
  disposePaneTerminal(tab.rightPane);
  tab.rightSessionId = null;
  tab.rightLaunchSpec = null;

  if (tab.rightPane) {
    tab.rightPane.remove();
  }
  tab.rightPane = null;
  if (tab.leftPane) {
    tab.leftPane.style.width = "";
    tab.leftPane.style.flexBasis = "";
  }
  tab.userResized = false;
  tab.initialSplitApplied = false;
  tab.splitRatio = null;
  tab.panel.style.gridTemplateColumns = "";

  scheduleFit();
  saveTabsState();
};

const getHotkeyDisplay = (id) => hotkeys[id] || "未设置";

const showTabContextMenu = (tabId, x, y) => {
  const tab = tabs.get(tabId);
  if (!tab) {
    return;
  }
  const splitItem = tab.split
    ? {
        label: "关闭分屏",
        shortcut: getHotkeyDisplay("closeSplit"),
        onClick: () => disableSplit(tabId),
      }
    : {
        label: "左右分屏",
        shortcut: getHotkeyDisplay("splitRight"),
        onClick: () => enableSplit(tabId),
      };

  const items = [
    {
      label: "重命名标签",
      shortcut: getHotkeyDisplay("renameTab"),
      onClick: () => renameTab(tabId),
    },
    {
      label: "克隆标签",
      shortcut: getHotkeyDisplay("cloneTab"),
      onClick: () => cloneTab(tabId),
    },
    { type: "separator" },
    splitItem,
    { type: "separator" },
    {
      label: "字体增大",
      shortcut: getHotkeyDisplay("fontIncrease"),
      onClick: () => adjustFontSize(1),
    },
    {
      label: "字体减小",
      shortcut: getHotkeyDisplay("fontDecrease"),
      onClick: () => adjustFontSize(-1),
    },
    {
      label: "字体重置",
      shortcut: getHotkeyDisplay("fontReset"),
      onClick: () => setFontSize(DEFAULT_FONT_SIZE),
    },
    { type: "separator" },
    {
      label: "快捷键设置",
      shortcut: getHotkeyDisplay("openHotkeySettings"),
      onClick: () => openHotkeySettings(),
    },
    { type: "separator" },
    {
      label: "关闭标签",
      shortcut: getHotkeyDisplay("closeTab"),
      onClick: () => closeTab(tabId),
    },
  ];

  showContextMenu(items, x, y);
};

const createTab = async ({
  label,
  labelSuffix,
  cloneFromTabId,
  overlayText,
  overlayPos,
  split,
  leftLaunchSpec,
  rightLaunchSpec,
  leftCwd,
  rightCwd,
  activate = true,
} = {}) => {
  tabCounter += 1;
  const tabId = `tab-${tabCounter}`;
  const baseLabel = `${DEFAULT_TAB_LABEL_BASE}${tabCounter}`;
  const tabLabel =
    label || (labelSuffix ? `${baseLabel}（${labelSuffix}）` : baseLabel);

  const { tabButton, labelSpan } = createTabButton(tabId, tabLabel);
  if (newTabButton) {
    tabsContainer.insertBefore(tabButton, newTabButton);
  } else {
    tabsContainer.appendChild(tabButton);
  }

  const panel = document.createElement("div");
  panel.className = "tab-panel";
  panel.dataset.tabId = tabId;

  const { pane: leftPane, terminal: leftTerminal } = createPane();
  panel.appendChild(leftPane);
  panelsContainer.appendChild(panel);

  const tabData = {
    tabButton,
    labelSpan,
    panel,
    leftPane,
    leftSessionId: null,
    leftLaunchSpec: null,
    rightPane: null,
    rightSessionId: null,
    rightLaunchSpec: null,
    split: null,
    activeSessionId: null,
    overlayText: null,
    overlayPos: null,
    renameInput: null,
    userResized: false,
    initialSplitApplied: false,
    splitRatio: null,
  };

  tabs.set(tabId, tabData);

  const cloneTab = cloneFromTabId ? tabs.get(cloneFromTabId) : null;
  const cloneSessionId = cloneTab?.activeSessionId || cloneTab?.leftSessionId;
  const cloneSession = cloneSessionId ? sessions.get(cloneSessionId) : null;
  const cloneSourceLaunchSpec = cloneSession
    ? cloneSession.side === "right"
      ? cloneTab?.rightLaunchSpec
      : cloneTab?.leftLaunchSpec
    : cloneTab?.leftLaunchSpec;
  tabData.leftLaunchSpec = normalizeLaunchSpec(
    leftLaunchSpec ??
      (cloneSourceLaunchSpec ? cloneLaunchSpec(cloneSourceLaunchSpec) : null),
    leftCwd
  );
  tabData.rightLaunchSpec = rightLaunchSpec
    ? normalizeLaunchSpec(rightLaunchSpec, rightCwd)
    : cloneTab?.rightLaunchSpec
      ? cloneLaunchSpec(cloneTab.rightLaunchSpec)
      : rightCwd
        ? normalizeLaunchSpec(null, rightCwd)
        : null;
  tabData.overlayText =
    overlayText ?? cloneTab?.overlayText ?? loadOverlayText();
  tabData.overlayPos = overlayPos ?? cloneTab?.overlayPos ?? null;
  if (activate) {
    setActiveTab(tabId);
  }

  const leftSessionId = await startTerminal(leftTerminal, tabId, {
    cloneFromSessionId:
      tabData.leftLaunchSpec.kind === "local" && cloneSession?.kind === "local"
        ? cloneSessionId
        : null,
    launchSpec: tabData.leftLaunchSpec,
    side: "left",
  });

  const tab = tabs.get(tabId);
  if (!tab) {
    closeSession(leftSessionId);
    disposePaneTerminal(leftPane);
    return;
  }
  tab.leftSessionId = leftSessionId;
  tab.activeSessionId = leftSessionId;

  if (cloneTab?.split || split) {
    await enableSplit(tabId, { cloneFromTabId });
  }

  if (leftSessionId) {
    const session = sessions.get(leftSessionId);
    if (session) {
      session.terminal.focus();
    }
  }

  scheduleFit();
  saveTabsState();
};

const cloneTab = async (tabId) => {
  const tab = tabs.get(tabId);
  if (!tab) {
    return;
  }
  const label = tab.labelSpan.textContent || DEFAULT_TAB_LABEL_BASE;
  await createTab({
    label,
    cloneFromTabId: tabId,
  });
};

const normalizeKey = (event) => {
  let key = event.key;
  if (!key) {
    return null;
  }
  if (key === " ") {
    key = "Space";
  }
  if (key === "Escape") {
    key = "Esc";
  }
  if (key === "ArrowLeft") {
    key = "Left";
  }
  if (key === "ArrowRight") {
    key = "Right";
  }
  if (key === "ArrowUp") {
    key = "Up";
  }
  if (key === "ArrowDown") {
    key = "Down";
  }
  if (key === "+") {
    key = "=";
  }
  if (key === "_") {
    key = "-";
  }
  if (key.length === 1) {
    key = key.toUpperCase();
  }
  return key;
};

const isModifierKey = (key) =>
  key === "Shift" || key === "Control" || key === "Alt" || key === "Meta";

const eventToHotkey = (event) => {
  if (event.isComposing || event.key === "Process" || event.keyCode === 229) {
    return null;
  }
  const key = normalizeKey(event);
  if (!key || isModifierKey(key)) {
    return null;
  }

  const ignoreShift = event.key === "+" || event.key === "_";
  const modifiers = [];
  if (event.ctrlKey) {
    modifiers.push(HOTKEY_MODIFIER_TOKENS.ctrl);
  }
  if (event.metaKey) {
    modifiers.push(HOTKEY_MODIFIER_TOKENS.meta);
  }
  if (event.shiftKey && !ignoreShift) {
    modifiers.push(HOTKEY_MODIFIER_TOKENS.shift);
  }
  if (event.altKey) {
    modifiers.push(HOTKEY_MODIFIER_TOKENS.alt);
  }

  if (!modifiers.length) {
    return null;
  }
  return [...modifiers, key].join("-");
};

const rebuildHotkeyIndex = () => {
  hotkeyIndex = new Map();
  for (const def of DEFAULT_HOTKEYS) {
    const value = hotkeys[def.id];
    if (value) {
      hotkeyIndex.set(value, def.id);
    }
  }
};

const runHotkeyAction = (id) => {
  if (!id) {
    return false;
  }
  switch (id) {
    case "renameTab":
      if (activeTabId) {
        renameTab(activeTabId);
        return true;
      }
      return false;
    case "cloneTab":
      if (activeTabId) {
        cloneTab(activeTabId);
        return true;
      }
      return false;
    case "newTab":
      createTab();
      return true;
    case "tabPrev":
      switchTabByOffset(-1);
      return true;
    case "tabNext":
      switchTabByOffset(1);
      return true;
    case "paneLeft":
      return switchSplitPane("left");
    case "paneRight":
      return switchSplitPane("right");
    case "splitRight":
      if (activeTabId) {
        enableSplit(activeTabId);
        return true;
      }
      return false;
    case "closeSplit":
      if (activeTabId) {
        disableSplit(activeTabId);
        return true;
      }
      return false;
    case "closeTab":
      if (activeTabId) {
        closeTab(activeTabId);
        return true;
      }
      return false;
    case "fontIncrease":
      adjustFontSize(1);
      return true;
    case "fontDecrease":
      adjustFontSize(-1);
      return true;
    case "fontReset":
      setFontSize(DEFAULT_FONT_SIZE);
      return true;
    case "openSshConnections":
      void openSshConnections();
      return true;
    case "openHotkeySettings":
      openHotkeySettings();
      return true;
    default:
      return false;
  }
};

const setHotkey = (id, value) => {
  hotkeys = { ...hotkeys, [id]: value || "" };
  saveHotkeys(hotkeys);
  rebuildHotkeyIndex();
};

const resetHotkeys = () => {
  hotkeys = buildDefaultHotkeys();
  saveHotkeys(hotkeys);
  rebuildHotkeyIndex();
  renderHotkeySettings();
};

const stopHotkeyCapture = () => {
  if (!hotkeyCapture) {
    return;
  }
  hotkeyCapture.cleanup();
  hotkeyCapture = null;
};

const startHotkeyCapture = (id, button) => {
  stopHotkeyCapture();

  button.classList.add("capturing");
  button.textContent = "按下新快捷键";

  const onKeyDown = (event) => {
    event.preventDefault();
    event.stopPropagation();

    if (event.key === "Escape") {
      stopHotkeyCapture();
      renderHotkeySettings();
      return;
    }

    if (event.key === "Backspace" || event.key === "Delete") {
      setHotkey(id, "");
      stopHotkeyCapture();
      renderHotkeySettings();
      return;
    }

    const hotkey = eventToHotkey(event);
    if (!hotkey) {
      return;
    }

    setHotkey(id, hotkey);
    stopHotkeyCapture();
    renderHotkeySettings();
  };

  const cleanup = () => {
    window.removeEventListener("keydown", onKeyDown, true);
    button.classList.remove("capturing");
  };

  hotkeyCapture = { cleanup };
  window.addEventListener("keydown", onKeyDown, true);
};

const renderHotkeySettings = () => {
  hotkeyList.innerHTML = "";
  for (const def of DEFAULT_HOTKEYS) {
    const row = document.createElement("div");
    row.className = "hotkey-row";

    const name = document.createElement("div");
    name.className = "hotkey-name";
    name.textContent = def.label;

    const keyButton = document.createElement("button");
    keyButton.type = "button";
    keyButton.className = "hotkey-key";
    keyButton.textContent = getHotkeyDisplay(def.id);
    keyButton.addEventListener("click", () =>
      startHotkeyCapture(def.id, keyButton)
    );

    row.appendChild(name);
    row.appendChild(keyButton);
    hotkeyList.appendChild(row);
  }
};

const openHotkeySettings = () => {
  renderHotkeySettings();
  hotkeyModal.classList.add("show");
};

const closeHotkeySettings = () => {
  stopHotkeyCapture();
  hotkeyModal.classList.remove("show");
};

hotkeyCloseButton.addEventListener("click", closeHotkeySettings);
hotkeyResetButton.addEventListener("click", resetHotkeys);
hotkeyModal.addEventListener("click", (event) => {
  if (event.target === hotkeyModal) {
    closeHotkeySettings();
  }
});

rebuildHotkeyIndex();

window.addEventListener("DOMContentLoaded", async () => {
  if (!tabsContainer || !panelsContainer) {
    return;
  }

  if (brandOverlay) {
    brandOverlay.textContent = loadOverlayText();
    setOverlayEditing(false);
    brandOverlay.addEventListener("input", () => {
      commitOverlayText();
    });
    brandOverlay.addEventListener("blur", () => {
      commitOverlayText();
      setOverlayEditing(false);
      updateOverlayForTab(activeTabId);
    });
    brandOverlay.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        setOverlayEditing(false);
      }
    });
    brandOverlay.addEventListener("paste", (event) => {
      event.preventDefault();
      const text = (event.clipboardData || window.clipboardData)
        ?.getData("text")
        .replace(/\s+/g, " ")
        .trim();
      if (text) {
        brandOverlay.textContent = text;
        commitOverlayText();
      }
    });
    brandOverlay.addEventListener("selectstart", (event) => {
      if (!brandOverlay.isContentEditable) {
        event.preventDefault();
      }
    });
    brandOverlay.addEventListener("dblclick", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const selection = window.getSelection();
      selection?.removeAllRanges();
      setOverlayEditing(true, { x: event.clientX, y: event.clientY });
    });
    brandOverlay.addEventListener("mousedown", (event) => {
      if (event.button !== 0) {
        return;
      }
      if (event.detail > 1 || brandOverlay.isContentEditable) {
        return;
      }
      const rect = brandOverlay.getBoundingClientRect();
      const startX = event.clientX;
      const startY = event.clientY;
      const startLeft = rect.left;
      const startTop = rect.top;
      let dragging = false;
      const min = 8;
      const maxX = Math.max(min, window.innerWidth - rect.width - min);
      const maxY = Math.max(min, window.innerHeight - rect.height - min);
      const rangeX = Math.max(1, maxX - min);
      const rangeY = Math.max(1, maxY - min);

      const onMove = (moveEvent) => {
        const dx = moveEvent.clientX - startX;
        const dy = moveEvent.clientY - startY;
        if (!dragging && Math.abs(dx) + Math.abs(dy) < 4) {
          return;
        }
        if (!dragging) {
          dragging = true;
          brandOverlay.classList.add("dragging");
          brandOverlay.blur();
        }
        moveEvent.preventDefault();
        const nextX = clampValue(startLeft + dx, min, maxX);
        const nextY = clampValue(startTop + dy, min, maxY);
        brandOverlay.style.left = `${nextX}px`;
        brandOverlay.style.top = `${nextY}px`;
        brandOverlay.style.right = "auto";
        if (activeTabId) {
          const tab = tabs.get(activeTabId);
          if (tab) {
            tab.overlayPos = {
              rx: rangeX ? (nextX - min) / rangeX : 0,
              ry: rangeY ? (nextY - min) / rangeY : 0,
            };
          }
        }
      };

      const onUp = () => {
        cleanup();
        if (dragging) {
          saveTabsState();
        }
      };

      const cleanup = () => {
        window.removeEventListener("mousemove", onMove);
        window.removeEventListener("mouseup", onUp);
        brandOverlay.classList.remove("dragging");
      };

      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    });
  }

  document.addEventListener("mousedown", (event) => {
    if (!brandOverlay?.isContentEditable) {
      return;
    }
    if (event.target === brandOverlay || brandOverlay.contains(event.target)) {
      return;
    }
    setOverlayEditing(false);
  });

  newTabButton?.addEventListener("click", () => createTab());

  document.addEventListener("contextmenu", (event) => {
    const tabButton = event.target?.closest(".tab[data-tab-id]");
    if (tabButton) {
      event.preventDefault();
      showTabContextMenu(tabButton.dataset.tabId, event.clientX, event.clientY);
      return;
    }
    event.preventDefault();
    hideContextMenu();
  });

  tabsBar?.addEventListener("mousedown", (event) => {
    if (event.button !== 0) {
      return;
    }
    if (isDragBlockedTarget(event)) {
      return;
    }
    event.preventDefault();
    focusActiveTerminal();
    document.body.classList.add("window-dragging");
    const startX = event.clientX;
    const startY = event.clientY;
    let dragged = false;

    const onMove = (moveEvent) => {
      if (dragged) {
        return;
      }
      const dx = Math.abs(moveEvent.clientX - startX);
      const dy = Math.abs(moveEvent.clientY - startY);
      if (dx + dy < 4) {
        return;
      }
      dragged = true;
      startWindowDragging();
      cleanup();
    };

    const onUp = () => cleanup();

    const cleanup = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.classList.remove("window-dragging");
      setTimeout(focusActiveTerminal, 0);
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  });

  tabsBar?.addEventListener("dblclick", (event) => {
    if (isDragBlockedTarget(event)) {
      return;
    }
    event.preventDefault();
    toggleWindowMaximize();
  });

  document.addEventListener("click", () => {
    if (contextMenu.style.display === "block") {
      hideContextMenu();
    }
  });
  window.addEventListener("blur", hideContextMenu);
  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      hideContextMenu();
      if (hotkeyModal.classList.contains("show")) {
        closeHotkeySettings();
      }
      if (sessionHistoryModal.classList.contains("show")) {
        closeSessionHistoryModal();
      }
      if (sshConnectionsModal.classList.contains("show")) {
        closeSshConnections();
      }
    }
  });

  document.addEventListener(
    "keydown",
    (event) => {
      if (
        hotkeyCapture ||
        hotkeyModal.classList.contains("show") ||
        sessionHistoryModal.classList.contains("show") ||
        sshConnectionsModal.classList.contains("show")
      ) {
        return;
      }
      const hotkey = eventToHotkey(event);
      if (!hotkey) {
        return;
      }
      const actionId = hotkeyIndex.get(hotkey);
      if (!actionId) {
        return;
      }
      const handled = runHotkeyAction(actionId);
      if (!handled) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
    },
    true
  );

  await listen("terminal-output", (event) => {
    const { session_id: sessionId, data } = event.payload;
    const session = sessions.get(sessionId);
    if (session) {
      session.terminal.write(terminalBytes(data));
    } else {
      bufferTerminalOutput(sessionId, data);
    }
  });

  await listen("terminal-exit", (event) => {
    const sessionId = event.payload?.session_id;
    handleTerminalLifecycle(sessionId, { type: "exit", payload: event.payload });
  });

  await listen("terminal-error", (event) => {
    const sessionId = event.payload?.session_id;
    handleTerminalLifecycle(sessionId, { type: "error", payload: event.payload });
  });

  try {
    await refreshSshProfiles({ render: false });
  } catch {
    // SSH 子系统错误会在连接中心或对应窗格中显示。
  }

  const storedTabs = loadTabsState();
  if (storedTabs?.tabs?.length) {
    isRestoringTabs = true;
    for (const tabState of storedTabs.tabs) {
      await createTab({
        label: tabState.label || undefined,
        overlayText: tabState.overlayText || DEFAULT_OVERLAY_TEXT,
        overlayPos: tabState.overlayPos || null,
        split: tabState.split,
        leftLaunchSpec: tabState.leftLaunchSpec || null,
        rightLaunchSpec: tabState.rightLaunchSpec || null,
        leftCwd: tabState.leftCwd || null,
        rightCwd: tabState.rightCwd || null,
        activate: false,
      });
    }
    isRestoringTabs = false;
    const ordered = getOrderedTabIds();
    const activeIndex = Math.min(
      storedTabs.activeIndex || 0,
      ordered.length - 1
    );
    const activeId = ordered[activeIndex] || ordered[0];
    if (activeId) {
      setActiveTab(activeId);
    }
    saveTabsState();
  } else {
    await createTab();
  }
  ensureWebviewAutoResize();
  applyWindowBackground();
  applyTerminalTheme();
  startCwdRefreshLoop();
  watchDevicePixelRatio();
  window.addEventListener("resize", handleWindowResize);
  scheduleFit();
});

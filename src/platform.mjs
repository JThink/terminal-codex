const MACOS_HOTKEY_STORAGE_KEY = "codex-terminal-hotkeys";
const WINDOWS_HOTKEY_STORAGE_KEY = "codex-terminal-hotkeys-windows-v1";

const HOTKEY_DEFINITIONS = [
  {
    id: "renameTab",
    label: "重命名标签",
    macos: "⌘-R",
    windows: "Ctrl-Shift-R",
  },
  {
    id: "cloneTab",
    label: "克隆标签",
    macos: "⌘-D",
    windows: "Ctrl-Shift-D",
  },
  {
    id: "newTab",
    label: "新建标签",
    macos: "⌘-T",
    windows: "Ctrl-Shift-T",
  },
  {
    id: "tabPrev",
    label: "切换到上一个标签",
    macos: "⌘-Shift-Left",
    windows: "Ctrl-Shift-Left",
  },
  {
    id: "tabNext",
    label: "切换到下一个标签",
    macos: "⌘-Shift-Right",
    windows: "Ctrl-Shift-Right",
  },
  {
    id: "paneLeft",
    label: "切换到左侧分屏",
    macos: "⌘-Left",
    windows: "Ctrl-Alt-Left",
  },
  {
    id: "paneRight",
    label: "切换到右侧分屏",
    macos: "⌘-Right",
    windows: "Ctrl-Alt-Right",
  },
  {
    id: "splitRight",
    label: "左右分屏",
    macos: "⌘-Shift-D",
    windows: "Ctrl-Alt-D",
  },
  {
    id: "closeSplit",
    label: "关闭分屏",
    macos: "⌘-Shift-S",
    windows: "Ctrl-Alt-S",
  },
  {
    id: "closeTab",
    label: "关闭标签",
    macos: "⌘-W",
    windows: "Ctrl-Shift-W",
  },
  {
    id: "fontIncrease",
    label: "字体增大",
    macos: "⌘-=",
    windows: "Ctrl-=",
  },
  {
    id: "fontDecrease",
    label: "字体减小",
    macos: "⌘--",
    windows: "Ctrl--",
  },
  {
    id: "fontReset",
    label: "字体重置",
    macos: "⌘-0",
    windows: "Ctrl-0",
  },
  {
    id: "openSshConnections",
    label: "SSH 连接",
    macos: "⌘-E",
    windows: "Ctrl-Shift-E",
  },
  {
    id: "openHotkeySettings",
    label: "快捷键设置",
    macos: "⌘-Shift-P",
    windows: "Ctrl-Shift-P",
  },
];

export const detectPlatform = (navigatorPlatform, userAgent) => {
  const platformSignal = `${String(navigatorPlatform || "")} ${String(userAgent || "")}`;
  if (/\b(?:Win32|Win64|Windows(?: NT)?)\b/i.test(platformSignal)) {
    return "windows";
  }
  if (/\b(?:MacIntel|Macintosh|macOS|Mac OS X)\b/i.test(platformSignal)) {
    return "macos";
  }
  return "unknown";
};

export const buildDefaultHotkeyDefinitions = (platform) => {
  const keyPlatform = platform === "macos" ? "macos" : "windows";
  return HOTKEY_DEFINITIONS.map(({ id, label, [keyPlatform]: defaultKey }) => ({
    id,
    label,
    defaultKey,
  }));
};

export const hotkeyStorageKeyForPlatform = (platform) =>
  platform === "macos" ? MACOS_HOTKEY_STORAGE_KEY : WINDOWS_HOTKEY_STORAGE_KEY;

export const modifierTokensForPlatform = (platform) => {
  const isMacos = platform === "macos";
  return {
    ctrl: "Ctrl",
    meta: isMacos ? "⌘" : "Meta",
    shift: "Shift",
    alt: isMacos ? "⌥" : "Alt",
  };
};

import test from "node:test";
import assert from "node:assert/strict";

import {
  buildDefaultHotkeyDefinitions,
  detectPlatform,
  hotkeyStorageKeyForPlatform,
  modifierTokensForPlatform,
} from "./platform.mjs";

const macHotkeys = [
  { id: "renameTab", label: "重命名标签", defaultKey: "⌘-R" },
  { id: "cloneTab", label: "克隆标签", defaultKey: "⌘-D" },
  { id: "newTab", label: "新建标签", defaultKey: "⌘-T" },
  { id: "tabPrev", label: "切换到上一个标签", defaultKey: "⌘-Shift-Left" },
  { id: "tabNext", label: "切换到下一个标签", defaultKey: "⌘-Shift-Right" },
  { id: "paneLeft", label: "切换到左侧分屏", defaultKey: "⌘-Left" },
  { id: "paneRight", label: "切换到右侧分屏", defaultKey: "⌘-Right" },
  { id: "splitRight", label: "左右分屏", defaultKey: "⌘-Shift-D" },
  { id: "closeSplit", label: "关闭分屏", defaultKey: "⌘-Shift-S" },
  { id: "closeTab", label: "关闭标签", defaultKey: "⌘-W" },
  { id: "fontIncrease", label: "字体增大", defaultKey: "⌘-=" },
  { id: "fontDecrease", label: "字体减小", defaultKey: "⌘--" },
  { id: "fontReset", label: "字体重置", defaultKey: "⌘-0" },
  { id: "openSshConnections", label: "SSH 连接", defaultKey: "⌘-E" },
  { id: "openHotkeySettings", label: "快捷键设置", defaultKey: "⌘-Shift-P" },
];

const windowsHotkeys = [
  { id: "renameTab", label: "重命名标签", defaultKey: "Ctrl-Shift-R" },
  { id: "cloneTab", label: "克隆标签", defaultKey: "Ctrl-Shift-D" },
  { id: "newTab", label: "新建标签", defaultKey: "Ctrl-Shift-T" },
  { id: "tabPrev", label: "切换到上一个标签", defaultKey: "Ctrl-Shift-Left" },
  { id: "tabNext", label: "切换到下一个标签", defaultKey: "Ctrl-Shift-Right" },
  { id: "paneLeft", label: "切换到左侧分屏", defaultKey: "Ctrl-Alt-Left" },
  { id: "paneRight", label: "切换到右侧分屏", defaultKey: "Ctrl-Alt-Right" },
  { id: "splitRight", label: "左右分屏", defaultKey: "Ctrl-Alt-D" },
  { id: "closeSplit", label: "关闭分屏", defaultKey: "Ctrl-Alt-S" },
  { id: "closeTab", label: "关闭标签", defaultKey: "Ctrl-Shift-W" },
  { id: "fontIncrease", label: "字体增大", defaultKey: "Ctrl-=" },
  { id: "fontDecrease", label: "字体减小", defaultKey: "Ctrl--" },
  { id: "fontReset", label: "字体重置", defaultKey: "Ctrl-0" },
  { id: "openSshConnections", label: "SSH 连接", defaultKey: "Ctrl-Shift-E" },
  { id: "openHotkeySettings", label: "快捷键设置", defaultKey: "Ctrl-Shift-P" },
];

test("detects Windows, macOS, and unknown platforms without assuming macOS", () => {
  assert.equal(detectPlatform("Win32", ""), "windows");
  assert.equal(detectPlatform("Win64", ""), "windows");
  assert.equal(detectPlatform("", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "windows");
  assert.equal(detectPlatform("Windows", ""), "windows");
  assert.equal(detectPlatform("MacIntel", ""), "macos");
  assert.equal(detectPlatform("", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"), "macos");
  assert.equal(detectPlatform("", "Mozilla/5.0 (Intel Mac OS X 14_5)"), "macos");
  assert.equal(detectPlatform("macOS", ""), "macos");
  assert.equal(detectPlatform("Linux x86_64", "Mozilla/5.0 (X11; Linux x86_64)"), "unknown");
  assert.equal(detectPlatform("", ""), "unknown");
  assert.equal(detectPlatform("FreeBSD", "Mozilla/5.0"), "unknown");
});

test("keeps every existing macOS hotkey definition unchanged", () => {
  const definitions = buildDefaultHotkeyDefinitions("macos");

  assert.equal(definitions.length, 15);
  assert.deepEqual(definitions, macHotkeys);
  assert.equal(
    definitions.find(({ id }) => id === "openSshConnections")?.defaultKey,
    "⌘-E"
  );
});

test("builds Windows defaults that preserve terminal control characters", () => {
  const definitions = buildDefaultHotkeyDefinitions("windows");

  assert.deepEqual(definitions, windowsHotkeys);
  assert.equal(definitions.find(({ id }) => id === "openSshConnections")?.defaultKey, "Ctrl-Shift-E");
  assert.equal(definitions.find(({ id }) => id === "paneLeft")?.defaultKey, "Ctrl-Alt-Left");
  assert.equal(definitions.find(({ id }) => id === "paneRight")?.defaultKey, "Ctrl-Alt-Right");
  assert.equal(definitions.find(({ id }) => id === "newTab")?.defaultKey, "Ctrl-Shift-T");
  assert.equal(definitions.find(({ id }) => id === "closeTab")?.defaultKey, "Ctrl-Shift-W");
});

test("uses Windows defaults for an unknown platform", () => {
  assert.deepEqual(buildDefaultHotkeyDefinitions("unknown"), windowsHotkeys);
});

test("keeps macOS hotkeys on the legacy storage key only", () => {
  assert.equal(hotkeyStorageKeyForPlatform("macos"), "codex-terminal-hotkeys");
  assert.equal(
    hotkeyStorageKeyForPlatform("windows"),
    "codex-terminal-hotkeys-windows-v1"
  );
  assert.equal(
    hotkeyStorageKeyForPlatform("unknown"),
    "codex-terminal-hotkeys-windows-v1"
  );
});

test("uses platform-specific Meta and Alt modifier tokens", () => {
  assert.deepEqual(modifierTokensForPlatform("macos"), {
    ctrl: "Ctrl",
    meta: "⌘",
    shift: "Shift",
    alt: "⌥",
  });
  assert.deepEqual(modifierTokensForPlatform("windows"), {
    ctrl: "Ctrl",
    meta: "Meta",
    shift: "Shift",
    alt: "Alt",
  });
  assert.deepEqual(modifierTokensForPlatform("unknown"), {
    ctrl: "Ctrl",
    meta: "Meta",
    shift: "Shift",
    alt: "Alt",
  });
});

test("returns fresh arrays and objects for every caller", () => {
  const first = buildDefaultHotkeyDefinitions("windows");
  const second = buildDefaultHotkeyDefinitions("windows");
  const firstTokens = modifierTokensForPlatform("windows");
  const secondTokens = modifierTokensForPlatform("windows");

  assert.notEqual(first, second);
  assert.notEqual(first[0], second[0]);
  assert.notEqual(firstTokens, secondTokens);

  first[0].defaultKey = "changed";
  firstTokens.alt = "changed";
  assert.equal(second[0].defaultKey, "Ctrl-Shift-R");
  assert.equal(secondTokens.alt, "Alt");
});

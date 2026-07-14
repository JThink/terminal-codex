# portable-pty 本地补丁

本目录基于 crates.io 的 `portable-pty 0.9.0`，保留上游 MIT 许可证。

- 回移 WezTerm 提交 `8afe0ad30739c5aa106c19e8a75b1dfc83bcfb56`：修复 Windows
  `TerminateProcess` 返回值判断反向的问题。该修复尚未进入 crates.io 发行版。

上游修复：<https://github.com/wezterm/wezterm/commit/8afe0ad30739c5aa106c19e8a75b1dfc83bcfb56>

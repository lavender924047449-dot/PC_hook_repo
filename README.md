# PC_hook_repo — 企微客户自动化管理工具 · 逆向经验存档

本仓库是 [Automated-Management-of-WeCom-Customers](https://github.com/lavender924047449-dot/Automated-Management-of-WeCom-Customers) 主项目在开发过程中沉淀下来的**逆向工程 / spike / 弃用 GUI**等经验存档，不参与 exe 打包，不被主项目 import。

主项目的活代码路径可以正常运行，本仓库仅用于以后翻阅"当初为什么这么做 / 有什么其他尝试 / 抓包字节长什么样"。

---

## 目录说明

| 目录 | 来自主项目哪里 | 内容 |
|------|----------------|------|
| `wecom_re_scripts/` | `Test-Voice/runtime/wecom_re/` | PC 企业微信（Windows 端）Frida hook 脚本、反汇编分析脚本、抓包解析脚本。约 720 个小文件（<1 MB），保留 `.py` / `.js` / `.md` / `.json`（小于 1 MB 的 json）。大抓包 (`.ndjson` / 大 `.json` / `_msgdb_copy.db`) 放在 **Releases 附件** 里（见下方）。 |
| `wecom_re_captures_manifest/MANIFEST.md` | 同上 | 大抓包文件清单（大小 + 相对路径），方便按需从 Release 里挑单个文件下载。 |
| `scripts_wecom_re/` | `Test-Voice/scripts/wecom_re/` | 更早期的 PC 企微 RE 一次性脚本（`ipc_pipe_*`、`forward_hook*`、`hook_call_1023810` 等）。 |
| `spikes/` | `Test-Voice/spikes/` | Stage 1–5 主流程确立之前的探索脚本：VB-CABLE 播放、UI 动作发现、Full-Auto、缓存扫描 watcher、native hijack dryrun 等。含 `SPIKE1_MANUAL_GUIDE.md`。 |
| `legacy/` | `Test-Voice/legacy/` | 老的 PySide GUI（`app_gui_pc/`）和标签器窗口（`gui/tagger_window.py`）。已被主项目 `gui/` 取代。 |
| `docs/` | `Test-Voice/docs/` 复制 | `REVERSE_ENGINEERING_HANDOFF.md` + `ANDROID_RE_HANDOFF.md`——主项目也保留了这两份，这里存一份便于 clone 本 repo 就能自洽阅读。 |
| `vendor/` | 预留 | 目前空。见下方 Releases 里的 `base.apk`。 |

---

## Releases 里的大二进制附件

因为 GitHub 单文件 100 MB 上限，以下大文件不入 git，走 **Releases 附件**：

- `wecom_re_captures.tar.zst`（Windows 端企微 Frida 抓包 + 反汇编中间产物，压缩后约 ~200 MB，未压前 ~560 MB）
- `wework_apk_base.tar.zst`（企业微信 Android APK 原包 `base.apk`，压缩后约 ~430 MB）

**如何取回：**
1. 进 https://github.com/lavender924047449-dot/PC_hook_repo/releases
2. 找 tag `assets-2026-09-22` (或最新 tag)
3. 下载对应 tar
4. 解压到 clone 出来的对应目录：
   ```bash
   # 解压抓包
   mkdir -p wecom_re_scripts/_captures
   tar -x --zstd -f wecom_re_captures.tar.zst -C wecom_re_scripts/_captures
   # 解压 apk
   mkdir -p vendor/wework_apk
   tar -x --zstd -f wework_apk_base.tar.zst -C vendor/wework_apk
   ```

---

## 和主项目的关系

- 主项目：https://github.com/lavender924047449-dot/Automated-Management-of-WeCom-Customers
- 主链路（PC 企微 FTA 转发）在 2026-09 转成 Android 端 + Frida 后，本仓库里的 PC 端 hook 探索**不再参与运行时**，仅作为经验。
- 如果主项目的 `runtime/wework_re_android/` 里的 Frida 探针需要参考类名 / 方法签名，可以下载 `wework_apk_base.tar.zst`，用 jadx 打开 `base.apk` 查看。

## 归档时间

2026-09-22 · 主项目"已打包 exe，进入清理阶段"节点。

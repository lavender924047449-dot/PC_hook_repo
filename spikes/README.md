# spikes/ — 探索期脚本归档

本目录收纳 Stage 1–4 期间用于**验证可行性**的独立脚本 (spike)，
它们是历史遗产：所有能力已经被 `app/` 下的正式模块吸收，
主流程走 `python main.py plan-run ...` 或 `python main.py gui`。

保留原因：调试新机型 / 新版本企微 UI 时，spike 更方便重现某一步骤。

| 脚本 | 阶段 | 目的 |
|------|------|------|
| `spike1_vbcable_playback.py` | 1 | 验证虚拟麦克风回放路径 |
| `SPIKE1_MANUAL_GUIDE.md` | 1 | 纯手工验证指南（历史，编码略乱） |
| `spike2a_discover_ui.py` | 2a | dump UI，找到"按住说话"控件 |
| `spike2b_full_auto.py` | 2b | 首次完整发送闭环 |
| `spike3_contact_switch.py` | 3 | 联系人搜索/切换 |
| `spike4_forward_flow.py` | 4 | 「转发 → 多选」路径探测 |
| `spike5_cache_scan_watch.py` | 5 | 企微媒体缓存扫描 |

## 运行方式

**一律在项目根目录**（不是 `spikes/` 内）执行，
这样 `from app.*` 才能被 Python 解析到：

```powershell
python spikes\spike5_cache_scan_watch.py --list
```

## artifacts/

`spikes/artifacts/`、`spikes/spike4_dumps/` 保存的是 UI dump、截图、
按钮坐标记录等一次性产物。已经被 `.gitignore` 排除，不入库。

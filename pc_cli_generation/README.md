# PC 企微命令行一代（经验存档）

这一目录是更早的可运行入口：`python main.py`，主操作是在电脑版企业微信里，把文件传输助手中的素材长按转发。

它和现在的模拟器图形界面（`python -m gui.main`）不是同一条链。这里只留作以后翻阅，不参与当前产品打包。

包含：

- `main.py`：命令行（`plan-run` / `batch` / `scan-cache` 等）
- `app/messaging/`、`app/pc_wecom/`、`app/automation/`、`app/orchestrator/`
- `app/device/`、`app/audio/`：这一代依赖的 ADB 手势与 VB-CABLE 播放
- `tests/`：只覆盖上述模块的用例
- `scripts/native_router_smoke.py`

当前产品在另一个仓库：Automated-Management-of-WeCom-Customers。

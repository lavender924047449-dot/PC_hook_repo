"""
app.gui — PySide6 图形界面 (Stage 5).

模块结构:
    main_window.py           主窗口 (菜单 / 侧栏 / 中心区 / 状态栏)
    widgets/plan_tree.py     BatchPlan 树形可视化 (Stage 5.1)
    widgets/plan_editor_panel.py   Plan 编辑器 (Stage 5.2)
    workers/plan_run_worker.py  后台执行 PlanRunner (Stage 5.3)
    widgets/asset_library_panel.py  素材库管理面板 (Stage 5.4)
    widgets/settings_panel.py       运行时配置编辑 (Stage 5.6)

入口:
    python main.py gui                    以空 plan 打开
    python main.py gui path/to/plan.json  直接加载 plan

开发说明:
    * 仅在 cmd_gui 内部 import, 避免非 GUI 场景强依赖 PySide6.
    * 后台任务 (PlanRunner 执行) 一律走 QThread + Signal, 不阻塞主线程.
"""

from __future__ import annotations

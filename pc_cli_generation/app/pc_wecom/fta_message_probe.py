"""只读查看 FTA 当前会话附近的文件气泡（文件名 / 大小）。

默认监听路径不再调用本模块：uiautomation 读企微 Qt 窗口会卡死主线程，
导致 Ctrl+C 失效、第二次启动也无输出。
仅保留给显式注入 `message_file_locator` 的测试或实验。
"""

from __future__ import annotations

from app.messaging.file_locator import FileHint, parse_file_hints

_MAX_NODES = 80
_CLIMB = 4


def peek_recent_file_hints() -> list[FileHint]:
    try:
        import uiautomation as auto
    except Exception:
        return []
    setter = getattr(auto, "SetGlobalSearchTimeout", None)
    old_timeout = getattr(auto, "TIME_OUT_SECOND", 10)
    if setter is not None:
        setter(0.25)
    try:
        focused = auto.GetFocusedControl()
        if focused is None:
            return []
        names = _collect_names(focused)
        return parse_file_hints(names)
    except Exception:
        return []
    finally:
        if setter is not None:
            try:
                setter(old_timeout)
            except Exception:
                pass


def _collect_names(start) -> list[str]:
    node = start
    for _ in range(_CLIMB):
        parent = None
        try:
            parent = node.GetParentControl()
        except Exception:
            parent = None
        if parent is None:
            break
        node = parent
        try:
            if (node.ClassName or "") == "WeWorkWindow":
                break
        except Exception:
            break

    names: list[str] = []
    queue = [node]
    seen = 0
    while queue and seen < _MAX_NODES:
        ctrl = queue.pop(0)
        seen += 1
        try:
            label = (ctrl.Name or "").strip()
        except Exception:
            label = ""
        if label:
            names.append(label)
        try:
            children = ctrl.GetChildren() or []
        except Exception:
            children = []
        remain = _MAX_NODES - seen - len(queue)
        if remain > 0:
            queue.extend(children[:remain])
    return names


__all__ = ["peek_recent_file_hints"]

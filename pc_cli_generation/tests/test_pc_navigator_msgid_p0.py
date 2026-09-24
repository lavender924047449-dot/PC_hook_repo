"""P0 msgid 精确匹配单元测试。

覆盖 `PyWinAutoBackend._right_click_by_msgid` 的三条路径：
  A. `child_window(auto_id=...)` 精确命中
  B. `child_window(auto_id_re=...)` 通配命中
  C. `descendants()` 全扫描按 automation_id / window_text / help_text 命中

以及集成 `right_click_bubble` 的 Phase 0 → 短路返回。
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.pc_wecom.locators import default_locators
from app.pc_wecom.pc_navigator import BubbleAnchor, PyWinAutoBackend


def _wrapper_ok():
    """返回一个 right_click_input 成功的 wrapper mock。"""
    w = MagicMock()
    w.right_click_input.return_value = None
    return w


def _child_result(wrapper):
    """模拟 pywinauto WindowSpecification: .wrapper_object() → wrapper。"""
    r = MagicMock()
    r.wrapper_object.return_value = wrapper
    return r


class _FakeWin:
    """模拟 pywinauto UIA Window 的最小接口。"""

    def __init__(self) -> None:
        # kwargs → (result | Exception)
        self.child_window_map: list[tuple[dict, object]] = []
        self.descendants_list: list = []
        self.raise_on_descendants: Exception | None = None
        self.calls: list[dict] = []

    def child_window(self, **kwargs):
        self.calls.append(dict(kwargs))
        for expect, result in self.child_window_map:
            if all(kwargs.get(k) == v for k, v in expect.items()):
                if isinstance(result, Exception):
                    raise result
                return result
        raise LookupError(f"no match: {kwargs}")

    def descendants(self):
        if self.raise_on_descendants is not None:
            raise self.raise_on_descendants
        return list(self.descendants_list)


# ── Path A: auto_id 精确匹配 ─────────────────────────────────────────────────
def test_msgid_p0_matches_by_exact_auto_id():
    backend = PyWinAutoBackend()
    fake_win = _FakeWin()
    wrapper = _wrapper_ok()
    fake_win.child_window_map = [({"auto_id": "461"}, _child_result(wrapper))]
    backend._win = fake_win  # type: ignore[assignment]

    assert backend._right_click_by_msgid(461) is True
    wrapper.right_click_input.assert_called_once()


# ── Path B: auto_id_re 通配匹配（当精确失败时命中）───────────────────────────
def test_msgid_p0_matches_by_auto_id_regex():
    backend = PyWinAutoBackend()
    fake_win = _FakeWin()
    wrapper = _wrapper_ok()
    # 精确 auto_id 都不匹配；仅 auto_id_re 命中
    fake_win.child_window_map = [
        ({"auto_id_re": ".*461.*"}, _child_result(wrapper)),
    ]
    backend._win = fake_win  # type: ignore[assignment]

    assert backend._right_click_by_msgid(461) is True
    wrapper.right_click_input.assert_called_once()
    # 至少尝试过一次精确 auto_id
    assert any("auto_id" in c and "auto_id_re" not in c for c in fake_win.calls)


# ── Path C: descendants 全扫描命中 ───────────────────────────────────────────
def test_msgid_p0_matches_via_descendants_scan():
    backend = PyWinAutoBackend()
    fake_win = _FakeWin()
    # child_window 全部失败
    fake_win.child_window_map = []

    # 造两个 descendant，第 2 个的 automation_id 含 msgid
    hit = MagicMock()
    hit.element_info.automation_id = "bubble-461-content"
    hit.element_info.help_text = ""
    hit.window_text = MagicMock(return_value="")
    hit.right_click_input = MagicMock()
    miss = MagicMock()
    miss.element_info.automation_id = "sidebar-nav"
    miss.element_info.help_text = ""
    miss.window_text = MagicMock(return_value="")
    fake_win.descendants_list = [miss, hit]

    backend._win = fake_win  # type: ignore[assignment]

    assert backend._right_click_by_msgid(461) is True
    hit.right_click_input.assert_called_once()
    miss.right_click_input.assert_not_called()


# ── 全部失败 → False，走后续 P1/P2/P3 兜底 ───────────────────────────────────
def test_msgid_p0_all_paths_miss_returns_false():
    backend = PyWinAutoBackend()
    fake_win = _FakeWin()
    fake_win.child_window_map = []
    fake_win.descendants_list = []
    backend._win = fake_win  # type: ignore[assignment]

    assert backend._right_click_by_msgid(999999) is False


# ── 边界：msgid=0 / _win 未连接 直接 False ─────────────────────────────────
@pytest.mark.parametrize("mid", [0, -1])
def test_msgid_p0_zero_or_negative_returns_false(mid):
    backend = PyWinAutoBackend()
    backend._win = _FakeWin()  # type: ignore[assignment]
    assert backend._right_click_by_msgid(mid) is False


def test_msgid_p0_no_window_returns_false():
    backend = PyWinAutoBackend()
    assert backend._win is None
    assert backend._right_click_by_msgid(461) is False


# ── 集成：right_click_bubble 优先走 P0，不落到 P1 之后 ──────────────────────
def test_right_click_bubble_phase0_short_circuits():
    backend = PyWinAutoBackend()
    fake_win = _FakeWin()
    wrapper = _wrapper_ok()
    fake_win.child_window_map = [({"auto_id": "461"}, _child_result(wrapper))]
    backend._win = fake_win  # type: ignore[assignment]

    anchor = BubbleAnchor(
        material_code="voice-abc",
        fingerprint_snippet="fp-xyz",
        send_time_ms=1789137936000,
        wecom_message_id=461,
    )
    assert backend.right_click_bubble(anchor, default_locators()) is True
    wrapper.right_click_input.assert_called_once()


def test_right_click_bubble_no_msgid_skips_phase0(monkeypatch):
    """wecom_message_id=0 时 P0 直接跳过，_right_click_by_msgid 不应被调用。"""
    backend = PyWinAutoBackend()
    backend._win = _FakeWin()  # type: ignore[assignment]

    called = {"n": 0}

    def _spy(self, msgid: int) -> bool:  # type: ignore[no-redef]
        called["n"] += 1
        return False

    monkeypatch.setattr(PyWinAutoBackend, "_right_click_by_msgid", _spy)

    anchor = BubbleAnchor(
        material_code="voice-abc",
        fingerprint_snippet="fp-xyz",
        wecom_message_id=0,
    )
    # 不关心最终 True/False（P1/P2/P3 可能因假 win 全部失败）
    backend.right_click_bubble(anchor, default_locators())
    assert called["n"] == 0, "P0 应因 msgid<=0 被跳过，不应调用 _right_click_by_msgid"


def test_right_click_bubble_with_msgid_invokes_phase0(monkeypatch):
    """wecom_message_id>0 时 P0 必被调用（无论成功/失败）。"""
    backend = PyWinAutoBackend()
    backend._win = _FakeWin()  # type: ignore[assignment]

    called = {"n": 0, "mid": None}

    def _spy(self, msgid: int) -> bool:  # type: ignore[no-redef]
        called["n"] += 1
        called["mid"] = msgid
        return True  # 短路，避免落到后续 phase

    monkeypatch.setattr(PyWinAutoBackend, "_right_click_by_msgid", _spy)

    anchor = BubbleAnchor(
        material_code="voice-abc",
        fingerprint_snippet="fp-xyz",
        wecom_message_id=461,
    )
    assert backend.right_click_bubble(anchor, default_locators()) is True
    assert called == {"n": 1, "mid": 461}

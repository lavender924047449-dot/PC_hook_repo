from app.messaging.asset_library import AssetLibrary
from app.messaging.types import MessageType
from app.pc_wecom.bubble_anchor import BubbleAnchorService
from app.pc_wecom.forward_executor import ForwardExecutor, PreparedForward
from app.pc_wecom.locators import LocatorSet
from app.pc_wecom.pc_navigator import BubbleAnchor, NullBackend, PCWeComNavigator
import pytest


def test_forward_success(tmp_path):
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.MINIPROGRAM, "商品A")
    anchor = BubbleAnchorService(lib)
    anchor.bind(entry.material_code or "", entry.fingerprint or "", echo_message_id="e1")

    nav = PCWeComNavigator(backend=NullBackend())
    fwd = ForwardExecutor(nav, anchor)
    res = fwd.forward(entry.material_code or "", "张三")
    assert res.ok is True
    assert res.via_native is False


class _CaptureBubbleBackend(NullBackend):
    """记录 right_click_bubble 收到的 BubbleAnchor（用于校验字段透传）。"""

    def __init__(self) -> None:
        super().__init__()
        self.last_bubble: BubbleAnchor | None = None

    def right_click_bubble(self, anchor: BubbleAnchor, locators: LocatorSet) -> bool:
        self.last_bubble = anchor
        return super().right_click_bubble(anchor, locators)


def test_forward_propagates_wecom_message_id(tmp_path):
    """anchor 里的真实 wecom_message_id 应被透传到 BubbleAnchor（P0 精确匹配依赖）。"""
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.MINIPROGRAM, "商品A")
    anchor_svc = BubbleAnchorService(lib)
    # 直接注入完整三元组 + native msgid（模拟 SQLite bind hook 已抓到 msgid=461）
    anchor_svc.bind(
        entry.material_code or "",
        entry.fingerprint or "",
        echo_message_id="e1",
        send_time_ms=1789137936000,
        sequence=42,
        wecom_message_id=461,
    )

    backend = _CaptureBubbleBackend()
    nav = PCWeComNavigator(backend=backend)
    fwd = ForwardExecutor(nav, anchor_svc)
    res = fwd.forward(entry.material_code or "", "张三")

    assert res.ok is True
    assert backend.last_bubble is not None
    assert backend.last_bubble.wecom_message_id == 461
    assert backend.last_bubble.send_time_ms == 1789137936000
    assert backend.last_bubble.sequence == 42


def test_forward_missing_anchor(tmp_path):
    lib = AssetLibrary(tmp_path / "lib.json")
    nav = PCWeComNavigator(backend=NullBackend())
    anchor = BubbleAnchorService(lib)
    fwd = ForwardExecutor(nav, anchor)
    res = fwd.forward("voice-not-exists", "张三", retries=0)
    assert res.ok is False


def _wired(tmp_path):
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.MINIPROGRAM, "商品A")
    anchor = BubbleAnchorService(lib)
    anchor.bind(entry.material_code or "", entry.fingerprint or "", echo_message_id="e1")
    backend = NullBackend()
    nav = PCWeComNavigator(backend=backend)
    return entry.material_code or "", backend, ForwardExecutor(nav, anchor), anchor, nav


def test_prepare_stops_before_pick_contact(tmp_path):
    code, backend, fwd, _, _ = _wired(tmp_path)
    prepared = fwd.prepare(code)
    assert isinstance(prepared, PreparedForward)
    assert prepared.material_code == code
    assert any(x.startswith("right_click_bubble:") for x in backend.logs)
    assert any(x.startswith("click_menu:转发") for x in backend.logs)
    assert not any(x.startswith("pick_contact:") for x in backend.logs)
    assert not any(x.startswith("click_menu:发送") for x in backend.logs)


def test_send_to_target_requires_prepare(tmp_path):
    _, _, fwd, _, _ = _wired(tmp_path)
    with pytest.raises(RuntimeError, match="prepare"):
        fwd.send_to_target("张三")


def test_send_to_target_uia_picks_and_confirms(tmp_path):
    code, backend, fwd, _, _ = _wired(tmp_path)
    fwd.prepare(code)
    res = fwd.send_to_target("张三")
    assert res.ok is True
    assert any(x == "pick_contact:张三" for x in backend.logs)
    assert any(x.startswith("click_menu:发送") for x in backend.logs)


class _FakeHijackHandle:
    def __init__(self, patched: bool = True) -> None:
        self.patched = patched
        self.stop_calls = 0

    def wait_for_patch(self, timeout=None) -> bool:
        return self.patched

    def stop(self, timeout=None):
        self.stop_calls += 1
        return None


class _FakeNativeRouter:
    def __init__(self, timeline: list[str], *, patched: bool = True) -> None:
        self.timeline = timeline
        self.arm_calls: list[tuple[str, str]] = []
        self._attached = False
        self._patched = patched
        self.last_handle: _FakeHijackHandle | None = None

    @property
    def is_attached(self) -> bool:
        return self._attached

    def attach(self) -> None:
        self._attached = True
        self.timeline.append("router.attach")

    def arm(self, from_conv_id: str, to_conv_id: str, **_kw):
        self.timeline.append(f"arm:{from_conv_id}->{to_conv_id}")
        self.arm_calls.append((from_conv_id, to_conv_id))
        self.last_handle = _FakeHijackHandle(patched=self._patched)
        return self.last_handle


class _TimelineBackend(NullBackend):
    def __init__(self, timeline: list[str]) -> None:
        super().__init__()
        self.timeline = timeline

    def click_menu(self, names: tuple[str, ...], locators: LocatorSet | None = None) -> bool:
        label = "|".join(names)
        self.timeline.append(f"click_menu:{label}")
        return super().click_menu(names, locators)

    def pick_contact(self, keyword: str, locators: LocatorSet) -> bool:
        self.timeline.append(f"pick_contact:{keyword}")
        return super().pick_contact(keyword, locators)


DECOY_CONV = "S:1688855042791155_7881300363276969"
REAL_CONV = "S:1688855042791155_7881299845935418"


def test_native_path_arms_between_menu_and_pick(tmp_path):
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.MINIPROGRAM, "商品A")
    anchor = BubbleAnchorService(lib)
    anchor.bind(entry.material_code or "", entry.fingerprint or "", echo_message_id="e1")

    timeline: list[str] = []
    backend = _TimelineBackend(timeline)
    nav = PCWeComNavigator(backend=backend)
    router = _FakeNativeRouter(timeline)
    fwd = ForwardExecutor(
        nav,
        anchor,
        native_router=router,
        decoy_target="占位同事",
        decoy_conv_id=DECOY_CONV,
    )
    res = fwd.forward(entry.material_code or "", "张三", conv_id=REAL_CONV)

    assert res.ok is True
    assert res.via_native is True
    assert res.conv_id == REAL_CONV
    assert router.arm_calls == [(DECOY_CONV, REAL_CONV)]
    assert router.last_handle is not None
    assert router.last_handle.stop_calls == 1

    arm_i = timeline.index(f"arm:{DECOY_CONV}->{REAL_CONV}")
    menu_i = next(i for i, x in enumerate(timeline) if x.startswith("click_menu:转发"))
    pick_i = timeline.index("pick_contact:占位同事")
    assert menu_i < arm_i < pick_i
    assert "pick_contact:张三" not in timeline


def test_native_path_without_router_falls_back_to_uia(tmp_path):
    code, backend, fwd, _, _ = _wired(tmp_path)
    res = fwd.forward(code, "张三", conv_id=REAL_CONV, retries=0)
    assert res.ok is True
    assert res.via_native is False
    assert any(x == "pick_contact:张三" for x in backend.logs)


def test_native_path_same_from_to_skips_hijack(tmp_path):
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.MINIPROGRAM, "商品A")
    anchor = BubbleAnchorService(lib)
    anchor.bind(entry.material_code or "", entry.fingerprint or "", echo_message_id="e1")

    timeline: list[str] = []
    backend = _TimelineBackend(timeline)
    nav = PCWeComNavigator(backend=backend)
    router = _FakeNativeRouter(timeline)
    fwd = ForwardExecutor(
        nav,
        anchor,
        native_router=router,
        decoy_conv_id=REAL_CONV,
    )
    res = fwd.forward(entry.material_code or "", "张三", conv_id=REAL_CONV)
    assert res.ok is True
    assert res.via_native is False
    assert router.arm_calls == []
    assert "pick_contact:张三" in timeline


def test_native_path_missed_patch_fails(tmp_path):
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.MINIPROGRAM, "商品A")
    anchor = BubbleAnchorService(lib)
    anchor.bind(entry.material_code or "", entry.fingerprint or "", echo_message_id="e1")

    timeline: list[str] = []
    backend = _TimelineBackend(timeline)
    nav = PCWeComNavigator(backend=backend)
    router = _FakeNativeRouter(timeline, patched=False)
    fwd = ForwardExecutor(
        nav,
        anchor,
        native_router=router,
        decoy_target="占位同事",
        decoy_conv_id=DECOY_CONV,
        hijack_wait_sec=0.01,
    )
    res = fwd.forward(entry.material_code or "", "张三", conv_id=REAL_CONV, retries=0)
    assert res.ok is False
    assert "未命中" in (res.reason or "")
    assert router.last_handle is not None
    assert router.last_handle.stop_calls >= 1

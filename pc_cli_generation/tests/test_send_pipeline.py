"""SendPipeline 装配器单元测试（不连企微 / 不 attach Frida）。"""

from __future__ import annotations

from app.messaging.asset_library import AssetLibrary
from app.messaging.send_queue import QueueItem, SendQueue
from app.messaging.types import MessageType
from app.pc_wecom.bubble_anchor import BubbleAnchorService
from app.pc_wecom.contact_conv_resolver import ContactConvResolver
from app.pc_wecom.pc_navigator import NullBackend, PCWeComNavigator
from app.pc_wecom.send_pipeline import SendPipeline, build_send_pipeline, parse_vtable_offset


CONV = "S:1688855042791155_7881300363276969"


def _lib_with_anchor(tmp_path):
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.MINIPROGRAM, "商品A")
    anchor = BubbleAnchorService(lib)
    anchor.bind(entry.material_code or "", entry.fingerprint or "", echo_message_id="e1")
    nav = PCWeComNavigator(backend=NullBackend())
    return lib, entry.material_code or "", nav, anchor


def test_parse_vtable_offset():
    assert parse_vtable_offset("0xabbb210") == 0xABBB210
    assert parse_vtable_offset(0xABBB210) == 0xABBB210
    assert parse_vtable_offset(None) == 0xABBB210


def test_build_pipeline_uia_only(tmp_path):
    lib, code, nav, anchor = _lib_with_anchor(tmp_path)
    pipe = build_send_pipeline(
        lib,
        navigator=nav,
        anchor=anchor,
        enable_native=False,
        find_pid=lambda: None,
    )
    assert pipe.native_enabled is False
    assert pipe.router is None
    res = pipe.send(code, "张三")
    assert res.ok is True
    assert res.via_native is False
    pipe.close()


def test_build_pipeline_native_without_pid_falls_back(tmp_path):
    lib, code, nav, anchor = _lib_with_anchor(tmp_path)
    pipe = build_send_pipeline(
        lib,
        navigator=nav,
        anchor=anchor,
        enable_native=True,
        find_pid=lambda: None,
    )
    assert pipe.native_enabled is False
    res = pipe.send(code, "张三")
    assert res.ok is True


def test_send_resolves_target_via_seeded_resolver(tmp_path):
    lib, code, nav, anchor = _lib_with_anchor(tmp_path)
    resolver = ContactConvResolver(pid=0, frida_module=object(), cache_path=tmp_path / "map.json")
    resolver.seed("张三", CONV)
    pipe = build_send_pipeline(
        lib,
        navigator=nav,
        anchor=anchor,
        enable_native=False,
        conv_resolver=resolver,
        find_pid=lambda: None,
    )
    res = pipe.send(code, "张三")
    assert res.ok is True
    # 无 NativeRouter 时 conv_id 解析后仍回退 UIA
    assert res.via_native is False


class _FakeHandle:
    def wait_for_patch(self, timeout=None) -> bool:
        return True

    def stop(self, timeout=None):
        return None


class _FakeRouter:
    def __init__(self) -> None:
        self.arm_calls: list[tuple[str, str]] = []

    @property
    def is_attached(self) -> bool:
        return True

    def attach(self) -> None:
        return None

    def detach(self) -> None:
        return None

    def arm(self, from_id: str, to_id: str, **_kw):
        self.arm_calls.append((from_id, to_id))
        return _FakeHandle()


def test_pipeline_native_path_with_decoy(tmp_path, monkeypatch):
    from app.config import PCWeComConfig

    lib, code, nav, anchor = _lib_with_anchor(tmp_path)
    router = _FakeRouter()
    resolver = ContactConvResolver(pid=0, frida_module=object(), cache_path=tmp_path / "map.json")
    dest = "S:1688855042791155_7881299845935418"
    resolver.seed("李四", dest)
    cfg = PCWeComConfig(
        decoy_target="占位同事",
        decoy_conv_id=CONV,
        native_hijack=True,
    )
    pipe = build_send_pipeline(
        lib,
        cfg=cfg,
        navigator=nav,
        anchor=anchor,
        enable_native=True,
        native_router=router,
        conv_resolver=resolver,
        pid=1,
    )
    assert pipe.native_enabled is True
    res = pipe.send(code, "李四")
    assert res.ok is True
    assert res.via_native is True
    assert router.arm_calls == [(CONV, dest)]
    logs = nav._backend.logs  # noqa: SLF001
    assert any(x == "pick_contact:占位同事" for x in logs)


def test_make_queue_executor_resolves_items(tmp_path):
    lib, code, nav, anchor = _lib_with_anchor(tmp_path)
    resolver = ContactConvResolver(pid=0, frida_module=object(), cache_path=tmp_path / "map.json")
    resolver.seed("张三", CONV)
    pipe = build_send_pipeline(
        lib, navigator=nav, anchor=anchor, enable_native=False,
        conv_resolver=resolver, find_pid=lambda: None,
    )
    q = SendQueue(tmp_path / "q.json")
    q.add(QueueItem(id="1", material_code=code, target="张三"))
    ex = pipe.make_queue_executor(q, history_path=str(tmp_path / "h.json"))
    out = ex.run()
    assert out[0]["status"] == "sent"


def test_pipeline_context_manager_detaches(tmp_path):
    lib, _, nav, anchor = _lib_with_anchor(tmp_path)
    router = _FakeRouter()
    detached = {"n": 0}

    def _detach():
        detached["n"] += 1

    router.detach = _detach  # type: ignore[method-assign]
    with build_send_pipeline(
        lib, navigator=nav, anchor=anchor, native_router=router,
        enable_native=True, pid=1, find_pid=lambda: 1,
    ) as pipe:
        assert isinstance(pipe, SendPipeline)
    assert detached["n"] == 1


def test_send_is_type_agnostic_for_file_backed_materials(tmp_path):
    """图片/视频/语音走同一条 forward 路径，只靠 material_code + 锚点。"""
    lib = AssetLibrary(tmp_path / "lib.json")
    nav = PCWeComNavigator(backend=NullBackend())
    anchor = BubbleAnchorService(lib)
    specs = [
        ("a.jpg", MessageType.IMAGE, "img-"),
        ("a.mp4", MessageType.VIDEO, "vid-"),
        ("a.silk", MessageType.VOICE, "voice-"),
        ("a.bin", MessageType.FILE, "file-"),
    ]
    codes: list[str] = []
    for name, mtype, prefix in specs:
        p = tmp_path / name
        p.write_bytes(b"payload-" + name.encode() + b"\x00" * 32)
        entry = lib.register_local(p, mtype, display_name=name)
        code = entry.material_code or ""
        assert code.startswith(prefix)
        anchor.bind(code, entry.fingerprint or "", echo_message_id="e1")
        codes.append(code)
    pipe = build_send_pipeline(
        lib, navigator=nav, anchor=anchor, enable_native=False, find_pid=lambda: None,
    )
    for code in codes:
        res = pipe.send(code, "张三")
        assert res.ok is True, res.reason
        assert res.via_native is False

"""ContactConvResolver 单元测试：fake frida 完全隔离进程 attach。"""

from __future__ import annotations

from collections import Counter
from typing import Any, Callable

import pytest

from app.pc_wecom.contact_conv_resolver import (
    FILEASSIST_CONV_ID,
    ContactConvResolver,
    ConvMapping,
    ResolverFridaUnavailableError,
    ResolverNotAttachedError,
    extract_strings_from_hex,
    is_noise_name,
    looks_like_conv_id,
    pick_display_name,
    split_single_conv_id,
)
from app.pc_wecom.contact_indexer import ContactHit, ContactIndexer
from app.pc_wecom.pc_navigator import NullBackend, PCWeComNavigator


SELF = "1688855042791155"
PEER_A = "7881300363276969"
PEER_B = "7881299845935418"
CONV_A = f"S:{SELF}_{PEER_A}"
CONV_B = f"S:{SELF}_{PEER_B}"
ROOM = "R:10839797135036051"


class _FakeExports:
    def __init__(
        self,
        conv_impl: Callable[[], dict],
        uin_impl: Callable[[str, int, int], list[dict]],
    ) -> None:
        self._conv = conv_impl
        self._uin = uin_impl
        self.find_conv_calls = 0
        self.find_uin_calls: list[str] = []

    def find_conv_ids(self) -> dict:
        self.find_conv_calls += 1
        return self._conv()

    def find_uin(self, uin: str, context_before: int, context_after: int) -> list[dict]:
        self.find_uin_calls.append(uin)
        return self._uin(uin, context_before, context_after)


class _FakeScript:
    def __init__(self, js: str, exports: _FakeExports, auto_ready: bool = True) -> None:
        self.js = js
        self.exports_sync = exports
        self._on_message: Callable[[dict, Any], None] | None = None
        self.loaded = False
        self.unloaded = False
        self.auto_ready = auto_ready

    def on(self, event: str, cb: Callable[[dict, Any], None]) -> None:
        assert event == "message"
        self._on_message = cb

    def load(self) -> None:
        self.loaded = True
        if self.auto_ready and self._on_message is not None:
            self._on_message({"type": "send", "payload": {"t": "info", "msg": "attached, base=0x970000"}}, None)
            self._on_message({"type": "send", "payload": {"t": "ready"}}, None)

    def unload(self) -> None:
        self.unloaded = True


class _FakeSession:
    def __init__(self, script: _FakeScript) -> None:
        self._script = script
        self.detached = False

    def create_script(self, js: str) -> _FakeScript:
        self._script.js = js
        return self._script

    def detach(self) -> None:
        self.detached = True


class _FakeDevice:
    def __init__(self, script: _FakeScript) -> None:
        self._script = script
        self.attach_calls: list[int] = []

    def attach(self, pid: int) -> _FakeSession:
        self.attach_calls.append(pid)
        return _FakeSession(self._script)


class _FakeFrida:
    def __init__(self, script: _FakeScript) -> None:
        self._device = _FakeDevice(script)

    def get_local_device(self) -> _FakeDevice:
        return self._device


def _hex_utf8(s: str) -> str:
    return s.encode("utf-8").hex()


def _fake(
    singles: list[str] | None = None,
    rooms: list[str] | None = None,
    fileassist: int = 0,
    neighbors: dict[str, str] | None = None,
) -> tuple[_FakeFrida, _FakeExports]:
    singles = singles or []
    rooms = rooms or []
    neighbors = neighbors or {}

    def conv_impl() -> dict:
        return {"S": singles, "R": rooms, "FILEASSIST": fileassist}

    def uin_impl(uin: str, _b: int, _a: int) -> list[dict]:
        name = neighbors.get(uin)
        if not name:
            return []
        return [{"addr": "0x1", "before_hex": "", "after_hex": _hex_utf8(name)}]

    exports = _FakeExports(conv_impl, uin_impl)
    script = _FakeScript(js="", exports=exports)
    return _FakeFrida(script), exports


def test_extract_utf8_and_utf16_chinese():
    utf8 = "张三".encode("utf-8").hex()
    assert "张三" in extract_strings_from_hex(utf8, min_len=2)
    li_si = extract_strings_from_hex("李四".encode("utf-8").hex(), min_len=2)
    assert "李四" in li_si
    chinese = [s for s in li_si if any("\u4e00" <= ch <= "\u9fff" for ch in s)]
    assert chinese == ["李四"]
    utf16 = ("李四" + "\x00").encode("utf-16-le").hex()
    assert "李四" in extract_strings_from_hex(utf16, min_len=2)


def test_looks_like_conv_id_and_split():
    assert looks_like_conv_id(CONV_A)
    assert looks_like_conv_id(ROOM)
    assert looks_like_conv_id(FILEASSIST_CONV_ID)
    assert not looks_like_conv_id("张三")
    assert split_single_conv_id(CONV_A) == (SELF, PEER_A)


def test_pick_display_name_prefers_chinese():
    c = Counter({"SELECT": 9, "C:\\WXWork": 4, "张三": 2, "foo": 8})
    picked = pick_display_name(c)
    assert picked is not None
    assert picked[0] == "张三"
    assert is_noise_name("SELECT")
    assert is_noise_name(CONV_A)


def test_seed_and_resolve_without_frida(tmp_path):
    cache = tmp_path / "conv_map.json"
    r = ContactConvResolver(pid=0, frida_module=object(), cache_path=cache)
    r._frida = None  # noqa: SLF001
    r.seed("张三", CONV_A)
    r.seed("测试群", ROOM)
    assert r.resolve("张三") == CONV_A
    assert r.resolve("测试群") == ROOM
    assert r.resolve(CONV_B) == CONV_B  # 已是 conv_id 则透传
    assert r.resolve("文件传输助手") == FILEASSIST_CONV_ID
    assert r.resolve(PEER_A) == CONV_A
    assert r.resolve("张") == CONV_A  # 唯一模糊命中
    assert r.mapping()["张三"] == CONV_A

    r2 = ContactConvResolver(pid=0, frida_module=object(), cache_path=cache)
    assert r2.resolve("张三") == CONV_A


def test_seed_rejects_empty_and_illegal():
    r = ContactConvResolver(pid=0, frida_module=object())
    with pytest.raises(ValueError):
        r.seed("", CONV_A)
    with pytest.raises(ValueError):
        r.seed("张三", "not-a-conv")


def test_refresh_builds_mapping_from_heap_scan():
    frida, exports = _fake(
        singles=[CONV_A, CONV_A, CONV_B],
        rooms=[ROOM],
        fileassist=3,
        neighbors={
            PEER_A: "张三",
            PEER_B: "李四",
            "10839797135036051": "测试群",
        },
    )
    resolver = ContactConvResolver(pid=22184, frida_module=frida, sleep=lambda _s: None)
    resolver.attach()
    try:
        mapping = resolver.refresh()
    finally:
        resolver.detach()

    assert mapping["张三"] == CONV_A
    assert mapping["李四"] == CONV_B
    assert mapping["测试群"] == ROOM
    assert mapping["文件传输助手"] == FILEASSIST_CONV_ID
    assert resolver.self_uin == SELF
    assert exports.find_conv_calls == 1
    assert PEER_A in exports.find_uin_calls
    assert resolver.resolve("李") == CONV_B


def test_refresh_syncs_contact_indexer(tmp_path):
    frida, _ = _fake(singles=[CONV_A], neighbors={PEER_A: "张三"})
    idx = ContactIndexer(
        PCWeComNavigator(backend=NullBackend()),
        cache_path=tmp_path / "contacts.json",
    )
    resolver = ContactConvResolver(
        pid=1, frida_module=frida, sleep=lambda _s: None, indexer=idx,
    )
    resolver.attach()
    try:
        resolver.refresh()
    finally:
        resolver.detach()
    hits = idx.search("张三")
    assert hits and hits[0].wecom_id == CONV_A
    assert isinstance(hits[0], ContactHit)


def test_attach_detach_and_errors():
    frida, _ = _fake()
    r = ContactConvResolver(pid=99, frida_module=frida, sleep=lambda _s: None)
    with r:
        assert r.is_attached is True
        assert r.agent_base == "0x970000"
    assert r.is_attached is False

    r2 = ContactConvResolver(pid=1, frida_module=None)
    r2._frida = None  # noqa: SLF001
    with pytest.raises(ResolverFridaUnavailableError):
        r2.attach()
    with pytest.raises(ResolverNotAttachedError):
        r2.scan_conv_ids()


def test_scan_before_attach_raises():
    r = ContactConvResolver(pid=1, frida_module=None)
    r._frida = None  # noqa: SLF001
    with pytest.raises(ResolverNotAttachedError):
        r.refresh()


def test_mapping_roundtrip_dict():
    m = ConvMapping(display_name="张三", conv_id=CONV_A, peer_uin=PEER_A, kind="single", score=4)
    assert ConvMapping.from_dict(m.to_dict()) == m

from app.messaging.asset_library import AssetLibrary
from app.messaging.types import MessageType
from app.pc_wecom.bubble_anchor import BubbleAnchorService


def test_anchor_bind_and_locate(tmp_path):
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.LOCATION, "上海南京路")
    code = entry.material_code or ""
    svc = BubbleAnchorService(lib)
    saved = svc.bind(code, entry.fingerprint or "", echo_message_id="echo-1")
    assert saved["current"]["echo_message_id"] == "echo-1"
    found = svc.locate(code)
    assert found["fingerprint_snippet"] == (entry.fingerprint or "")[:12]


def test_anchor_missing_raises(tmp_path):
    lib = AssetLibrary(tmp_path / "lib.json")
    svc = BubbleAnchorService(lib)
    try:
        svc.locate("missing-code")
        assert False, "should raise"
    except KeyError:
        assert True


class _FakeNativeReader:
    """test double：用于验证 native_reader 注入路径。"""

    def __init__(self, records):
        # records: dict[send_time_ms, msgid]
        self._by_time = dict(records)
        self.calls: list[tuple[int, int, float]] = []

    def wait_for_msgid(self, send_time_ms, *, tolerance_ms, timeout):
        self.calls.append((send_time_ms, tolerance_ms, timeout))
        from app.pc_wecom.native_msgid_reader import NativeMsgIdRecord
        if send_time_ms in self._by_time:
            return NativeMsgIdRecord(
                msgid=self._by_time[send_time_ms],
                send_time_ms=send_time_ms,
            )
        return None


def test_bind_overrides_wecom_message_id_via_native_reader(tmp_path):
    """当注入 NativeMsgIdReader 且 send_time_ms 命中时，
    应覆盖 wecom_message_id 为真实 per-message msgid（对应 §32.1）。"""
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.LOCATION, "上海南京路")
    code = entry.material_code or ""
    reader = _FakeNativeReader({1789137936: 461})
    svc = BubbleAnchorService(
        lib, native_reader=reader,
        native_wait_timeout_s=0.1, native_tolerance_ms=2000,
    )
    r = svc.bind(code, entry.fingerprint or "",
                 echo_message_id="e", send_time_ms=1789137936)
    assert r["current"]["wecom_message_id"] == 461
    assert r["current"]["send_time_ms"] == 1789137936
    assert reader.calls == [(1789137936, 2000, 0.1)]


def test_bind_keeps_zero_when_native_reader_misses(tmp_path):
    """send_time_ms 未命中时，msgid 保持 0，不写死错误值。"""
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.LOCATION, "上海南京路")
    code = entry.material_code or ""
    reader = _FakeNativeReader({})  # 空
    svc = BubbleAnchorService(lib, native_reader=reader,
                              native_wait_timeout_s=0.05)
    r = svc.bind(code, entry.fingerprint or "",
                 echo_message_id="e", send_time_ms=1234567890)
    # 未命中 → wecom_message_id 默认 0；由于 send_time_ms 已知但无 memory anchor 也无 native msgid，
    # to_dict 不写这些字段
    assert "wecom_message_id" not in r["current"] or \
        r["current"]["wecom_message_id"] == 0
    assert reader.calls  # 至少调用过一次


def test_bind_skips_native_reader_when_no_send_time(tmp_path):
    """send_time_ms=0 时不应调 native_reader，避免无谓阻塞。"""
    lib = AssetLibrary(tmp_path / "lib.json")
    entry = lib.register_forward(MessageType.LOCATION, "上海南京路")
    code = entry.material_code or ""
    reader = _FakeNativeReader({1789137936: 461})
    svc = BubbleAnchorService(lib, native_reader=reader,
                              native_wait_timeout_s=0.05)
    svc.bind(code, entry.fingerprint or "", echo_message_id="e")
    assert reader.calls == []

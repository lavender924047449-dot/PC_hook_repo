from datetime import datetime
from pathlib import Path

import pytest

from app.messaging.asset_library import AssetLibrary
from app.messaging.cache_scanner import MaterialCaptured
from app.messaging.types import MessageType
from app.pc_wecom.bubble_anchor import BubbleAnchorService
from app.pc_wecom.fta_code_echo import FtaCodeEcho
from app.pc_wecom.pipeline import wire_capture_echo


class _FakeScanner:
    def __init__(self) -> None:
        self.cb = None

    def subscribe(self, callback) -> None:
        self.cb = callback


def _evt(lib: AssetLibrary, tmp_path: Path) -> MaterialCaptured:
    entry = lib.register_forward(MessageType.LOCATION, "上海南京路")
    return MaterialCaptured(
        entry=entry,
        source_file=tmp_path / "x.bin",
        captured_at=datetime.now().isoformat(timespec="seconds"),
    )


def test_echo_clipboard_only_does_not_paste(tmp_path: Path):
    lib = AssetLibrary(tmp_path / "lib.json")
    copied: list[str] = []
    pasted = {"n": 0}
    echo = FtaCodeEcho(
        BubbleAnchorService(lib),
        mode="clipboard",
        copy_text=lambda t: copied.append(t) or True,
        is_wecom_foreground=lambda: True,
        paste=lambda: pasted.__setitem__("n", pasted["n"] + 1) or True,
    )
    echo.on_material_captured(_evt(lib, tmp_path))
    assert copied and copied[0].startswith("loc-")
    assert pasted["n"] == 0


def test_echo_paste_if_focused_when_wecom_foreground(tmp_path: Path):
    lib = AssetLibrary(tmp_path / "lib.json")
    pasted = {"n": 0}
    echo = FtaCodeEcho(
        BubbleAnchorService(lib),
        mode="paste_if_focused",
        copy_text=lambda t: True,
        is_wecom_foreground=lambda: True,
        paste=lambda: pasted.__setitem__("n", pasted["n"] + 1) or True,
    )
    echo.on_material_captured(_evt(lib, tmp_path))
    assert pasted["n"] == 1


def test_echo_skips_paste_when_wecom_not_foreground(tmp_path: Path):
    lib = AssetLibrary(tmp_path / "lib.json")
    pasted = {"n": 0}
    echo = FtaCodeEcho(
        BubbleAnchorService(lib),
        mode="paste_if_focused",
        copy_text=lambda t: True,
        is_wecom_foreground=lambda: False,
        paste=lambda: pasted.__setitem__("n", pasted["n"] + 1) or True,
    )
    echo.on_material_captured(_evt(lib, tmp_path))
    assert pasted["n"] == 0


def test_echo_ui_requires_navigator(tmp_path: Path):
    lib = AssetLibrary(tmp_path / "lib.json")
    with pytest.raises(ValueError, match="ui"):
        FtaCodeEcho(BubbleAnchorService(lib), mode="ui")


def test_wire_capture_echo_subscribes(tmp_path: Path):
    scanner = _FakeScanner()
    lib = AssetLibrary(tmp_path / "lib.json")
    echo = FtaCodeEcho(
        BubbleAnchorService(lib),
        mode="clipboard",
        copy_text=lambda t: True,
    )
    wire_capture_echo(scanner, echo)  # type: ignore[arg-type]
    assert scanner.cb.__self__ is echo


def test_clipboard_write_timeout_does_not_block(monkeypatch):
    import time

    from app.pc_wecom import fta_code_echo as echo_mod

    def _slow(_payload: str, _retries: int) -> bool:
        time.sleep(2.0)
        return True

    monkeypatch.setattr(echo_mod, "_copy_text_blocking", _slow)
    t0 = time.monotonic()
    assert echo_mod.copy_text_to_clipboard("abc") is False
    assert time.monotonic() - t0 < 1.0


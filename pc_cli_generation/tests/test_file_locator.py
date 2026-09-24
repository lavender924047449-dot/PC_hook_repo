from pathlib import Path

from app.messaging.asset_library import AssetLibrary
from app.messaging.file_locator import FileHint, parse_file_hints, parse_size_label, resolve_local_file
from app.messaging.types import MessageType


def test_parse_size_label():
    assert parse_size_label("270.6 KB") == int(270.6 * 1024)
    assert parse_size_label("1.5 MB") == int(1.5 * 1024 * 1024)
    assert parse_size_label("12 B") == 12
    assert parse_size_label("not a size") is None


def test_parse_file_hints_keeps_latest_and_binds_size():
    hints = parse_file_hints([
        "你好",
        "old.pdf",
        "12 KB",
        "复旦大学-简历.pdf",
        "270.6 KB",
        "file-abc123",
    ])
    assert [h.filename for h in hints] == ["old.pdf", "复旦大学-简历.pdf"]
    assert hints[-1].size == int(270.6 * 1024)


def test_resolve_prefers_cache_file(tmp_path: Path):
    cache = tmp_path / "Cache"
    month = cache / "File" / "2026-09"
    month.mkdir(parents=True)
    pdf = month / "report.pdf"
    pdf.write_bytes(b"P" * 300)
    hit = resolve_local_file(cache, FileHint("report.pdf", 300))
    assert hit == pdf.resolve()


def test_resolve_library_outside_cache(tmp_path: Path):
    cache = tmp_path / "Cache"
    (cache / "File").mkdir(parents=True)
    local = tmp_path / "docs" / "合同.docx"
    local.parent.mkdir()
    local.write_bytes(b"D" * 400)
    lib = AssetLibrary(tmp_path / "lib.json")
    lib.register_local(local, MessageType.FILE, display_name="合同")
    hit = resolve_local_file(cache, FileHint("合同.docx", 400), library=lib)
    assert hit == local.resolve()


def test_resolve_missing_returns_none(tmp_path: Path):
    cache = tmp_path / "Cache"
    (cache / "File").mkdir(parents=True)
    assert resolve_local_file(cache, FileHint("no-such.pdf")) is None

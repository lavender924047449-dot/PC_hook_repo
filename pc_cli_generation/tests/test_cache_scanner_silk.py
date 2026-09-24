"""
Stage 4.5.5.1.7  cache_scanner + silk_decoder 集成测试.

用 Mock 版 SilkDecoder 模拟 silk→wav, 不依赖真 exe.
"""

from __future__ import annotations

from pathlib import Path

from app.messaging.asset_library import AssetLibrary
from app.messaging.cache_scanner import WeComCacheScanner
from app.messaging.types import MessageType


# ---------------- 假 SilkDecoder ---------------- #

class _FakeSilkDecoder:
    """伪装的 SilkDecoder: 把输入 silk 内容包成一个"假 wav"."""

    def __init__(self, cache_dir: Path):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.calls: list[Path] = []

    def decode_to_cache(self, silk_path, *, cache_dir=None, force=False) -> Path:
        p = Path(silk_path)
        self.calls.append(p)
        # 用 silk 内容前 8 字节作 wav 文件名 (幂等)
        content = p.read_bytes()
        stem = content[:8].hex()
        out = self.cache_dir / f"{stem}.wav"
        # 写一个"假 WAV" (前缀 RIFF, 让 register_local 能算 sha1)
        out.write_bytes(b"RIFF" + b"FAKE" + content)
        return out


# ---------------- 构造 fixture ---------------- #

def _make_fake_wxwork(root: Path, subdirs: dict[str, list[tuple[str, bytes]]]) -> Path:
    """
    subdirs: { "Voice": [("f.silk", b"data"), ...], "Image": [("a.jpg", b"..."), ...] }
    返回 account_dir.
    """
    acct = root / "1688000000000001"
    cache = acct / "Cache"
    for sub, files in subdirs.items():
        d = cache / sub / "2026-09"
        d.mkdir(parents=True, exist_ok=True)
        for name, data in files:
            # 填充到 >=200B, 避免 _MIN_FILE_SIZE 过滤
            (d / name).write_bytes(data.ljust(200, b'\x00'))
    return acct


# ---------------- Tests ---------------- #

def test_no_silk_decoder_voice_still_scanned(tmp_path: Path):
    acct = _make_fake_wxwork(tmp_path, {
        "Voice": [("v1.silk", b"silk-content-1")],
        "Image": [("a.jpg", b"jpeg-content")],
    })
    scanner = WeComCacheScanner(acct)
    lib = AssetLibrary(tmp_path / "lib.json")
    r = scanner.register_new(lib)
    assert r.skipped_by_type == {}
    types = {e.semantic_type for e in r.registered}
    assert types == {MessageType.IMAGE, MessageType.VOICE}


def test_silk_decoder_auto_unskips_voice(tmp_path: Path):
    """给 silk_decoder 但不传 skip_subdirs → Voice 应被自动扫上"""
    acct = _make_fake_wxwork(tmp_path, {
        "Voice": [("v1.silk", b"silk-content-1"),
                  ("v2.silk", b"silk-content-2")],
    })
    fake = _FakeSilkDecoder(tmp_path / "silk_cache")
    scanner = WeComCacheScanner(acct, silk_decoder=fake)   # 默认 skip=None → 自动不跳
    lib = AssetLibrary(tmp_path / "lib.json")
    r = scanner.register_new(lib)
    assert r.skipped_by_type == {}
    assert len(r.registered) == 2
    assert all(e.semantic_type is MessageType.VOICE for e in r.registered)
    # 应产生 2 个 wav 缓存
    assert len(fake.calls) == 2


def test_silk_decoder_registers_wav_path_not_silk(tmp_path: Path):
    """入库的 source_path 必须是 wav, 而不是原 silk"""
    acct = _make_fake_wxwork(tmp_path, {
        "Voice": [("v1.silk", b"silk-content-XYZ")],
    })
    fake = _FakeSilkDecoder(tmp_path / "silk_cache")
    scanner = WeComCacheScanner(acct, silk_decoder=fake)
    lib = AssetLibrary(tmp_path / "lib.json")
    r = scanner.register_new(lib)
    assert len(r.registered) == 1
    entry = r.registered[0]
    assert entry.source_path.endswith(".wav")
    assert "silk" not in entry.source_path.lower().split("\\")[-1]
    # 该 wav 文件确实存在
    assert Path(entry.source_path).is_file()


def test_silk_decoder_explicit_skip_voice_overrides(tmp_path: Path):
    """显式 skip_subdirs=['Voice'] 应即使有 silk_decoder 也跳过"""
    acct = _make_fake_wxwork(tmp_path, {
        "Voice": [("v.silk", b"data")],
    })
    fake = _FakeSilkDecoder(tmp_path / "silk_cache")
    scanner = WeComCacheScanner(acct, silk_decoder=fake, skip_subdirs=["Voice"])
    lib = AssetLibrary(tmp_path / "lib.json")
    r = scanner.register_new(lib)
    assert r.skipped_by_type == {"Voice": 1}
    assert len(r.registered) == 0
    assert fake.calls == []


def test_silk_decoder_only_on_silk_extension(tmp_path: Path):
    """
    Voice/ 里可能出现非 .silk 文件 (少见), 应该不被 silk_decoder 处理,
    但依然按 VOICE 入库.
    """
    acct = _make_fake_wxwork(tmp_path, {
        "Voice": [("v.silk", b"AAAA"), ("stranger.wav", b"BBBB")],
    })
    fake = _FakeSilkDecoder(tmp_path / "silk_cache")
    scanner = WeComCacheScanner(acct, silk_decoder=fake)
    lib = AssetLibrary(tmp_path / "lib.json")
    r = scanner.register_new(lib)
    assert len(r.registered) == 2
    # 只有 .silk 走了解码
    assert len(fake.calls) == 1
    assert fake.calls[0].name == "v.silk"


def test_mixed_types_and_voice(tmp_path: Path):
    """图片+视频+文件+语音 一起扫, silk_decoder 只作用于 voice"""
    acct = _make_fake_wxwork(tmp_path, {
        "Image": [("a.jpg", b"AAAA")],
        "Video": [("v.mp4", b"BBBB")],
        "File":  [("x.pdf", b"CCCC")],
        "Voice": [("s.silk", b"DDDD")],
    })
    fake = _FakeSilkDecoder(tmp_path / "silk_cache")
    scanner = WeComCacheScanner(acct, silk_decoder=fake)
    lib = AssetLibrary(tmp_path / "lib.json")
    r = scanner.register_new(lib)
    assert len(r.registered) == 4
    types = {e.semantic_type for e in r.registered}
    assert types == {
        MessageType.IMAGE, MessageType.VIDEO,
        MessageType.FILE, MessageType.VOICE,
    }
    assert len(fake.calls) == 1

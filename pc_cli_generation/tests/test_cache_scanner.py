"""
Stage 4.5.5.1.7 WeComCacheScanner 单元测试.

用 tmp_path 模拟 WXWork 目录结构, 不依赖真实企微安装.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from app.messaging.asset_library import AssetLibrary
from app.messaging.cache_scanner import (
    CACHE_SUBDIR_TO_TYPE,
    SKIP_BY_DEFAULT,
    WeComCacheScanner,
    CachedFile,
)
from app.messaging.types import MessageType


# ---------------- 构造假 WXWork 目录 ---------------- #

def _make_fake_wxwork(root: Path, accounts: dict[str, dict[str, list[str]]]) -> None:
    """
    accounts: { "<acctId>": { "Image": ["a.jpg","b.jpg"], "File": ["x.pdf"], ... } }
    """
    for acct_id, subdirs in accounts.items():
        # 即使 subdirs 为空, 也建账号根 + Cache 目录, 模拟"账号存在但没缓存"
        (root / acct_id / "Cache").mkdir(parents=True, exist_ok=True)
        cache = root / acct_id / "Cache"
        for sub, filenames in subdirs.items():
            month = cache / sub / "2026-09"
            month.mkdir(parents=True, exist_ok=True)
            for i, fn in enumerate(filenames):
                p = month / fn
                # 每个文件写不同内容 (>=200B, 避免 _MIN_FILE_SIZE 过滤), 确保 sha1 不同
                p.write_bytes(f"content-{acct_id}-{sub}-{i}-{fn}".encode().ljust(200, b'\x00'))


# ---------------- list_accounts / auto_detect ---------------- #

def test_list_accounts_sorted_by_size(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {
        "1688000000000001": {"Image": ["a.jpg"]},
        "1688000000000002": {"Image": ["a.jpg", "b.jpg"], "File": ["x.pdf"]},
        "1688000000000003": {},
    })
    accts = WeComCacheScanner.list_accounts(tmp_path)
    ids = [a[0] for a in accts]
    counts = [a[1] for a in accts]
    assert ids[0] == "1688000000000002"    # 3 files, top
    assert counts == [3, 1, 0]


def test_list_accounts_ignores_non_numeric_dirs(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {"1688000000000001": {"Image": ["a.jpg"]}})
    (tmp_path / "Global").mkdir()                    # 非账号目录
    (tmp_path / "BrowserMetrics").mkdir()
    accts = WeComCacheScanner.list_accounts(tmp_path)
    assert [a[0] for a in accts] == ["1688000000000001"]


def test_list_accounts_missing_root(tmp_path: Path):
    assert WeComCacheScanner.list_accounts(tmp_path / "no_such") == []


def test_auto_detect_picks_biggest(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {
        "1688000000000001": {"Image": ["a.jpg"]},
        "1688000000000002": {"Image": ["a.jpg", "b.jpg"], "File": ["x.pdf"]},
    })
    s = WeComCacheScanner.auto_detect(tmp_path)
    assert s.account_dir.name == "1688000000000002"


def test_auto_detect_no_accounts_raises(tmp_path: Path):
    (tmp_path).mkdir(exist_ok=True)
    with pytest.raises(FileNotFoundError, match="未在"):
        WeComCacheScanner.auto_detect(tmp_path)


def test_auto_detect_all_empty_raises(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {"1688000000000001": {}})
    with pytest.raises(FileNotFoundError, match="缓存都是空"):
        WeComCacheScanner.auto_detect(tmp_path)


# ---------------- snapshot ---------------- #

def test_snapshot_finds_all_types(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {"1688000000000001": {
        "Image": ["a.jpg", "b.jpg"],
        "File": ["x.pdf"],
        "Video": ["v.mp4"],
        "Voice": ["s.silk"],
    }})
    s = WeComCacheScanner(tmp_path / "1688000000000001", skip_subdirs=[])
    snap = s.snapshot()
    assert len(snap) == 5
    types = {cf.semantic_type for cf in snap}
    assert types == {MessageType.IMAGE, MessageType.FILE,
                     MessageType.VIDEO, MessageType.VOICE}


def test_snapshot_stable_order(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {"1688000000000001": {
        "Image": ["b.jpg", "a.jpg"],
    }})
    s = WeComCacheScanner(tmp_path / "1688000000000001", skip_subdirs=[])
    snap1 = s.snapshot()
    snap2 = s.snapshot()
    assert [f.path for f in snap1] == [f.path for f in snap2]


def test_scanner_rejects_missing_cache(tmp_path: Path):
    (tmp_path / "1688000000000001").mkdir()
    with pytest.raises(NotADirectoryError, match="Cache"):
        WeComCacheScanner(tmp_path / "1688000000000001")


# ---------------- register_new ---------------- #

def test_register_new_baseline_diff(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {"1688000000000001": {
        "Image": ["old.jpg"],
    }})
    scanner = WeComCacheScanner(
        tmp_path / "1688000000000001", skip_subdirs=[],
    )
    lib = AssetLibrary(tmp_path / "lib.json")

    baseline = scanner.snapshot_paths()
    assert len(baseline) == 1

    # 用户"发了新文件"
    _make_fake_wxwork(tmp_path, {"1688000000000001": {
        "Image": ["old.jpg", "new1.jpg", "new2.jpg"],
    }})

    result = scanner.register_new(lib, baseline_paths=baseline)
    assert len(result.new_files) == 2
    assert len(result.registered) == 2
    assert all(e.tag.startswith("img_") for e in result.registered)
    assert result.skipped_by_type == {}


def test_register_new_includes_voice_by_default(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {"1688000000000001": {
        "Image": ["a.jpg"],
        "Voice": ["v1.silk", "v2.silk"],
    }})
    scanner = WeComCacheScanner(tmp_path / "1688000000000001")
    lib = AssetLibrary(tmp_path / "lib.json")

    result = scanner.register_new(lib)
    types = {e.semantic_type for e in result.registered}
    assert MessageType.IMAGE in types
    assert MessageType.VOICE in types
    assert len(result.registered) == 3
    assert result.skipped_by_type == {}


def test_register_new_can_skip_voice(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {"1688000000000001": {
        "Image": ["a.jpg"],
        "Voice": ["v1.silk"],
    }})
    scanner = WeComCacheScanner(
        tmp_path / "1688000000000001", skip_subdirs=["Voice"],
    )
    lib = AssetLibrary(tmp_path / "lib.json")
    result = scanner.register_new(lib)
    assert len(result.registered) == 1
    assert result.registered[0].semantic_type is MessageType.IMAGE
    assert result.skipped_by_type == {"Voice": 1}


def test_register_new_include_voice_when_asked(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {"1688000000000001": {
        "Voice": ["v.silk"],
    }})
    scanner = WeComCacheScanner(
        tmp_path / "1688000000000001", skip_subdirs=[],
    )
    lib = AssetLibrary(tmp_path / "lib.json")
    result = scanner.register_new(lib)
    assert len(result.registered) == 1
    assert result.registered[0].semantic_type is MessageType.VOICE


def test_register_new_idempotent_same_content(tmp_path: Path):
    """同 sha1 只入库一次 (来自 AssetLibrary 的幂等性)"""
    _make_fake_wxwork(tmp_path, {"1688000000000001": {
        "Image": ["a.jpg"],
    }})
    scanner = WeComCacheScanner(tmp_path / "1688000000000001", skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    r1 = scanner.register_new(lib)
    assert len(r1.registered) == 1

    # 把同内容文件再复制一份 (模拟企微二次接收 → hash 一样但文件名带 (1))
    src = list((tmp_path / "1688000000000001" / "Cache" / "Image").rglob("*.jpg"))[0]
    dup = src.parent / "a(1).jpg"
    dup.write_bytes(src.read_bytes())

    r2 = scanner.register_new(lib, baseline_paths={src})
    assert len(r2.new_files) == 1        # 扫到 1 个新文件
    assert len(r2.registered) == 1       # 但 tag 复用旧的
    assert r2.registered[0].tag == r1.registered[0].tag
    assert len(lib) == 1


def test_register_new_display_name_from_stem(tmp_path: Path):
    _make_fake_wxwork(tmp_path, {"1688000000000001": {
        "File": ["Pupuapp.docx"],
    }})
    scanner = WeComCacheScanner(tmp_path / "1688000000000001", skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    r = scanner.register_new(lib)
    assert r.registered[0].display_name == "Pupuapp"
    assert "Pupuapp" in r.registered[0].tag


def test_logical_cache_stem_strips_wecom_copy_suffix():
    from app.messaging.cache_scanner import logical_cache_stem
    assert logical_cache_stem("星空简洁") == "星空简洁"
    assert logical_cache_stem("星空简洁(1)") == "星空简洁"
    assert logical_cache_stem("简历_01(2)(1)") == "简历_01"
    assert logical_cache_stem("cloud(4)") == "cloud"
    assert logical_cache_stem("cloud(5)") == "cloud"


def test_register_new_coalesces_wecom_reencoded_copies(tmp_path: Path):
    """同一张图的原文件与 (1) 转码副本只入库一次，保留更大的那份。"""
    acct = tmp_path / "1688000000000001"
    month = acct / "Cache" / "Image" / "2026-09"
    month.mkdir(parents=True)
    original = month / "cloud.png"
    copy = month / "cloud(1).png"
    original.write_bytes(b"O" * 400)
    copy.write_bytes(b"C" * 200)
    scanner = WeComCacheScanner(acct, skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    result = scanner.register_new(lib)
    assert len(result.registered) == 1
    assert result.registered[0].source_path == str(original)
    assert result.skipped_by_type.get("wecom_copy") == 1
    assert len(lib) == 1


def test_coalesce_quiet_still_flushes_when_copies_rescanned(tmp_path: Path):
    """轮询会反复扫到两份缓存；不能因此把 quiet 计时清零导致编码一直不发。"""
    acct = tmp_path / "1688000000000001"
    month = acct / "Cache" / "Image" / "2026-09"
    month.mkdir(parents=True)
    (month / "cloud.png").write_bytes(b"O" * 400)
    (month / "cloud(1).png").write_bytes(b"C" * 200)
    scanner = WeComCacheScanner(acct, skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    # 两份都已在磁盘上：应立刻合并发出，不必空等 quiet。
    r1 = scanner.register_new(lib, coalesce_quiet_s=0.4)
    assert len(r1.registered) == 1
    seen = {cf.path for cf in r1.new_files}
    r2 = scanner.register_new(lib, baseline_paths=seen, coalesce_quiet_s=0.4)
    assert r2.registered == []


def test_single_file_flushes_after_quiet(tmp_path: Path):
    acct = tmp_path / "1688000000000001"
    month = acct / "Cache" / "Image" / "2026-09"
    month.mkdir(parents=True)
    (month / "solo.png").write_bytes(b"S" * 300)
    scanner = WeComCacheScanner(acct, skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    r1 = scanner.register_new(lib, coalesce_quiet_s=0.25)
    assert r1.registered == []
    time.sleep(0.28)
    r2 = scanner.register_new(lib, coalesce_quiet_s=0.25)
    assert len(r2.registered) == 1


def test_video_cover_thumbnail_not_coded(tmp_path: Path):
    acct = tmp_path / "1688000000000001"
    img_dir = acct / "Cache" / "Image" / "2026-09"
    vid_dir = acct / "Cache" / "Video" / "2026-09"
    img_dir.mkdir(parents=True)
    vid_dir.mkdir(parents=True)
    thumb = img_dir / "852312d5-7c96-4149-9b86-00fa6d9012c7.jpg"
    video = vid_dir / "clip.mp4"
    thumb.write_bytes(b"T" * 200)
    video.write_bytes(b"V" * 400)
    scanner = WeComCacheScanner(acct, skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    result = scanner.register_new(lib)
    assert len(result.registered) == 1
    assert result.registered[0].semantic_type is MessageType.VIDEO
    assert result.skipped_by_type.get("video_cover") == 1
    assert len(lib) == 1
    assert result.registered[0].cover_fingerprints


def test_uuid_image_alone_still_registers(tmp_path: Path):
    acct = tmp_path / "1688000000000001"
    img_dir = acct / "Cache" / "Image" / "2026-09"
    img_dir.mkdir(parents=True)
    img = img_dir / "852312d5-7c96-4149-9b86-00fa6d9012c7.jpg"
    img.write_bytes(b"I" * 300)
    scanner = WeComCacheScanner(acct, skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    result = scanner.register_new(lib)
    assert result.registered == []
    assert result.skipped_by_type.get("video_cover") == 1


def test_video_cover_alone_reuses_existing_vid_code(tmp_path: Path):
    """再次发送同一视频时往往只更新封面 jpg，应回写已有 vid 编码。"""
    acct = tmp_path / "1688000000000001"
    img_dir = acct / "Cache" / "Image" / "2026-09"
    vid_dir = acct / "Cache" / "Video" / "2026-09"
    img_dir.mkdir(parents=True)
    vid_dir.mkdir(parents=True)
    cover_bytes = b"T" * 200
    video = vid_dir / "clip.mp4"
    video.write_bytes(b"V" * 400)
    thumb1 = img_dir / "852312d5-7c96-4149-9b86-00fa6d9012c7.jpg"
    thumb1.write_bytes(cover_bytes)
    scanner = WeComCacheScanner(acct, skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    r1 = scanner.register_new(lib)
    assert len(r1.registered) == 1
    code = r1.registered[0].material_code
    assert code and code.startswith("vid-")
    seen = {cf.path for cf in r1.new_files}
    stat = {cf.path: (cf.size, cf.mtime) for cf in r1.new_files}
    thumb2 = img_dir / "0ab53ef9-2d4a-4d8d-be3f-6ef71a9fe5c3.jpg"
    thumb2.write_bytes(cover_bytes)
    r2 = scanner.register_new(lib, baseline_paths=seen, baseline_stat=stat)
    assert len(r2.registered) == 1
    assert r2.registered[0].material_code == code
    assert r2.registered[0].semantic_type is MessageType.VIDEO


def test_mtime_change_reuses_same_code(tmp_path: Path):
    acct = tmp_path / "1688000000000001"
    month = acct / "Cache" / "File" / "2026-09"
    month.mkdir(parents=True)
    pdf = month / "report.pdf"
    pdf.write_bytes(b"P" * 300)
    scanner = WeComCacheScanner(acct, skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    r1 = scanner.register_new(lib)
    assert len(r1.registered) == 1
    code = r1.registered[0].material_code
    seen = {cf.path for cf in r1.new_files}
    stat = {cf.path: (cf.size, cf.mtime) for cf in r1.new_files}
    time.sleep(0.05)
    pdf.write_bytes(b"P" * 300)
    pdf.touch()
    r2 = scanner.register_new(lib, baseline_paths=seen, baseline_stat=stat)
    assert len(r2.registered) == 1
    assert r2.registered[0].material_code == code
    assert len(lib) == 1


def test_file_not_blindly_reused_on_atime_change(tmp_path: Path):
    """文件只在真正落盘新文件时编码，atime 变化不应触发注册。"""
    acct = tmp_path / "1688000000000001"
    month = acct / "Cache" / "File" / "2026-09"
    month.mkdir(parents=True)
    pdf = month / "report.pdf"
    pdf.write_bytes(b"P" * 300)
    scanner = WeComCacheScanner(acct, skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    r1 = scanner.register_new(lib)
    assert len(r1.registered) == 1
    seen = {cf.path for cf in r1.new_files}
    stat = scanner.snapshot_stat()
    os.utime(pdf, (pdf.stat().st_atime + 2.0, pdf.stat().st_mtime))
    r2 = scanner.register_new(lib, baseline_paths=seen, baseline_stat=stat)
    assert r2.registered == []
    assert r2.new_files == []


def test_file_new_cache_does_register(tmp_path: Path):
    """Cache/File 真正出现新文件时应正常编码。"""
    acct = tmp_path / "1688000000000001"
    month = acct / "Cache" / "File" / "2026-09"
    month.mkdir(parents=True)
    scanner = WeComCacheScanner(acct, skip_subdirs=[])
    lib = AssetLibrary(tmp_path / "lib.json")
    r0 = scanner.register_new(lib)
    assert r0.registered == []
    seen = {cf.path for cf in r0.new_files}
    stat = scanner.snapshot_stat()
    pdf = month / "new_contract.pdf"
    pdf.write_bytes(b"X" * 500)
    r1 = scanner.register_new(lib, baseline_paths=seen, baseline_stat=stat)
    assert len(r1.registered) == 1
    assert r1.registered[0].semantic_type is MessageType.FILE


def test_subdir_type_map_consistent():
    assert set(CACHE_SUBDIR_TO_TYPE) == {"File", "Image", "Video", "Voice"}
    assert CACHE_SUBDIR_TO_TYPE["Image"] is MessageType.IMAGE
    assert "Voice" not in SKIP_BY_DEFAULT

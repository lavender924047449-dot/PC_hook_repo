"""
Stage 4.5.5.1 AssetLibrary 单元测试.

跑法:
    pytest tests/test_asset_library.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.messaging.asset_library import (
    AssetEntry,
    AssetLibrary,
    FORWARD_ONLY_TYPES,
    LOCAL_SOURCE_TYPES,
    TAG_PREFIX,
)
from app.messaging.types import MessageType


# ---------- 分类完整性 ---------- #

def test_tag_prefix_covers_all_non_text():
    assert set(TAG_PREFIX) | {MessageType.TEXT} == set(MessageType)


def test_local_forward_disjoint_and_cover():
    assert LOCAL_SOURCE_TYPES.isdisjoint(FORWARD_ONLY_TYPES)
    assert LOCAL_SOURCE_TYPES | FORWARD_ONLY_TYPES == (
        set(MessageType) - {MessageType.TEXT}
    )


# ---------- AssetEntry 校验 ---------- #

def test_entry_rejects_illegal_tag():
    with pytest.raises(ValidationError):
        AssetEntry(tag="bad tag!", semantic_type=MessageType.VOICE)
    with pytest.raises(ValidationError):
        AssetEntry(tag="", semantic_type=MessageType.VOICE)


def test_entry_allows_chinese_underscore():
    e = AssetEntry(tag="voice_问候语_a3f7c1", semantic_type=MessageType.VOICE)
    assert e.tag == "voice_问候语_a3f7c1"


def test_entry_brief_no_crash():
    e1 = AssetEntry(
        tag="voice_abc123",
        semantic_type=MessageType.VOICE,
        source_path="C:/a.wav",
        sha1="a" * 40,
    )
    e2 = AssetEntry(
        tag="mp_xyz789",
        semantic_type=MessageType.MINIPROGRAM,
        fta_locator="商品A",
    )
    e3 = AssetEntry(tag="tag_only", semantic_type=MessageType.STICKER)
    for e in (e1, e2, e3):
        assert isinstance(e.brief(), str)


def test_touch_refreshed():
    e = AssetEntry(tag="v_1", semantic_type=MessageType.VOICE)
    assert e.last_refreshed_at is None
    e.touch_refreshed()
    assert e.last_refreshed_at is not None


# ---------- register_local ---------- #

@pytest.fixture
def wav_file(tmp_path: Path) -> Path:
    p = tmp_path / "greeting.wav"
    p.write_bytes(b"RIFF" + b"\x00" * 1000)
    return p


@pytest.fixture
def wav_file2(tmp_path: Path) -> Path:
    p = tmp_path / "farewell.wav"
    p.write_bytes(b"RIFF" + b"\x11" * 1000)
    return p


def _lib(tmp_path: Path) -> AssetLibrary:
    return AssetLibrary(tmp_path / "lib.json")


def test_register_local_basic(tmp_path: Path, wav_file: Path):
    lib = _lib(tmp_path)
    e = lib.register_local(wav_file, MessageType.VOICE)
    assert e.tag.startswith("voice_")
    assert e.sha1 and len(e.sha1) == 40
    assert e.fingerprint == e.sha1
    assert e.material_code and e.material_code.startswith("voice-")
    assert e.source_path == str(wav_file)
    assert e.semantic_type is MessageType.VOICE


def test_register_local_with_display_name_slug(tmp_path: Path, wav_file: Path):
    lib = _lib(tmp_path)
    e = lib.register_local(
        wav_file, MessageType.VOICE, display_name="问候 语!"
    )
    # display_name 被 slug 化后并进 tag
    assert "问候_语" in e.tag or "问候" in e.tag
    assert e.tag.startswith("voice_")
    assert e.display_name == "问候 语!"


def test_register_local_idempotent(tmp_path: Path, wav_file: Path):
    lib = _lib(tmp_path)
    e1 = lib.register_local(wav_file, MessageType.VOICE)
    e2 = lib.register_local(wav_file, MessageType.VOICE)
    assert e1.tag == e2.tag           # 同 sha1 → 同 tag
    assert len(lib) == 1


def test_register_local_overwrite_updates_display(
    tmp_path: Path, wav_file: Path
):
    lib = _lib(tmp_path)
    e1 = lib.register_local(wav_file, MessageType.VOICE)
    e2 = lib.register_local(
        wav_file, MessageType.VOICE,
        display_name="新名字", overwrite=True,
    )
    assert e1.tag == e2.tag
    assert e2.display_name == "新名字"


def test_register_local_different_files_different_tags(
    tmp_path: Path, wav_file: Path, wav_file2: Path
):
    lib = _lib(tmp_path)
    e1 = lib.register_local(wav_file, MessageType.VOICE)
    e2 = lib.register_local(wav_file2, MessageType.VOICE)
    assert e1.tag != e2.tag
    assert e1.sha1 != e2.sha1


def test_register_local_rejects_forward_type(tmp_path: Path, wav_file: Path):
    lib = _lib(tmp_path)
    with pytest.raises(ValueError, match="register_local 不接受"):
        lib.register_local(wav_file, MessageType.MINIPROGRAM)


def test_register_local_rejects_missing_file(tmp_path: Path):
    lib = _lib(tmp_path)
    with pytest.raises(FileNotFoundError):
        lib.register_local(tmp_path / "nope.wav", MessageType.VOICE)


# ---------- register_forward ---------- #

def test_register_forward_basic(tmp_path: Path):
    lib = _lib(tmp_path)
    e = lib.register_forward(
        MessageType.MINIPROGRAM,
        fta_locator="商品A 小程序",
        display_name="商品A",
    )
    assert e.tag.startswith("mp_")
    assert e.material_code and e.material_code.startswith("mp-")
    assert "商品A" in e.tag
    assert e.fta_locator == "商品A 小程序"
    assert e.source_path is None
    assert e.sha1 is None


def test_register_forward_idempotent(tmp_path: Path):
    lib = _lib(tmp_path)
    e1 = lib.register_forward(MessageType.LOCATION, fta_locator="上海南京路")
    e2 = lib.register_forward(MessageType.LOCATION, fta_locator="上海南京路")
    assert e1.tag == e2.tag
    assert len(lib) == 1


def test_register_forward_rejects_local_type(tmp_path: Path):
    lib = _lib(tmp_path)
    with pytest.raises(ValueError, match="register_forward 不接受"):
        lib.register_forward(MessageType.VOICE, fta_locator="x")


def test_register_forward_rejects_empty_locator(tmp_path: Path):
    lib = _lib(tmp_path)
    with pytest.raises(ValueError, match="fta_locator"):
        lib.register_forward(MessageType.MINIPROGRAM, fta_locator="   ")


# ---------- Tag 冲突处理 ---------- #

def test_tag_conflict_appends_suffix(tmp_path: Path):
    """
    人为构造 tag 冲突: 用 _upsert_raw 塞入一个占位 entry, 再注册真素材验证追加 _1.
    """
    lib = _lib(tmp_path)
    # 手工确定 register_forward 会算出什么 tag
    from app.messaging.asset_library import _md5_of_str, _slug
    body = _md5_of_str("商品A 小程序")[:6]
    slug = _slug("商品A")
    predicted = f"mp_{slug}_{body}"

    # 先占坑
    placeholder = AssetEntry(
        tag=predicted, semantic_type=MessageType.MINIPROGRAM,
        fta_locator="占位", display_name="占位",
    )
    lib._upsert_raw(placeholder)

    # 再注册真实的 → 应追加 _1
    e = lib.register_forward(
        MessageType.MINIPROGRAM,
        fta_locator="商品A 小程序", display_name="商品A",
    )
    assert e.tag == f"{predicted}_1"


def test_tag_conflict_chain(tmp_path: Path):
    """连着起 3 个 tag base 相同的, 应得到 base / base_1 / base_2"""
    lib = _lib(tmp_path)
    tags = []
    for loc in ("A", "B", "C"):
        # 强制 body 相同: 直接 upsert_raw
        e = AssetEntry(
            tag=lib._make_tag(MessageType.LOCATION, "abc123", "同名"),
            semantic_type=MessageType.LOCATION,
            fta_locator=loc, display_name="同名",
        )
        lib._upsert_raw(e)
        tags.append(e.tag)
    assert tags[0].endswith("abc123")
    assert tags[1].endswith("abc123_1")
    assert tags[2].endswith("abc123_2")


# ---------- 查询 / 删除 ---------- #

def test_get_missing_raises(tmp_path: Path):
    lib = _lib(tmp_path)
    with pytest.raises(KeyError):
        lib.get("nope")


def test_has_and_contains(tmp_path: Path, wav_file: Path):
    lib = _lib(tmp_path)
    e = lib.register_local(wav_file, MessageType.VOICE)
    assert lib.has(e.tag)
    assert e.tag in lib
    assert not lib.has("nope")


def test_by_type(tmp_path: Path, wav_file: Path, wav_file2: Path):
    lib = _lib(tmp_path)
    lib.register_local(wav_file, MessageType.VOICE)
    lib.register_local(wav_file2, MessageType.VOICE)
    lib.register_forward(MessageType.MINIPROGRAM, "商品A")
    assert len(lib.by_type(MessageType.VOICE)) == 2
    assert len(lib.by_type(MessageType.MINIPROGRAM)) == 1
    assert len(lib.by_type(MessageType.LOCATION)) == 0


def test_remove(tmp_path: Path, wav_file: Path):
    lib = _lib(tmp_path)
    e = lib.register_local(wav_file, MessageType.VOICE)
    lib.remove(e.tag)
    assert not lib.has(e.tag)
    with pytest.raises(KeyError):
        lib.remove(e.tag)


# ---------- 持久化 ---------- #

def test_save_load_roundtrip(tmp_path: Path, wav_file: Path):
    fp = tmp_path / "lib.json"
    lib = AssetLibrary(fp)
    v = lib.register_local(wav_file, MessageType.VOICE, display_name="问候")
    m = lib.register_forward(
        MessageType.MINIPROGRAM,
        fta_locator="商品A 小程序", display_name="商品A",
    )
    lib.save()

    lib2 = AssetLibrary.load(fp)
    assert len(lib2) == 2
    assert lib2.get(v.tag).source_path == str(wav_file)
    assert lib2.get(v.tag).display_name == "问候"
    assert lib2.get(m.tag).fta_locator == "商品A 小程序"


def test_load_missing_file_is_empty(tmp_path: Path):
    lib = AssetLibrary.load(tmp_path / "not_here.json")
    assert len(lib) == 0


def test_load_legacy_entry_auto_fills_material_code(tmp_path: Path):
    fp = tmp_path / "legacy.json"
    fp.write_text(
        """
{
  "version": 1,
  "entries": [
    {
      "tag": "voice_old_abc123",
      "semantic_type": "voice",
      "source_path": "C:/tmp/a.wav",
      "sha1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
""".strip(),
        encoding="utf-8",
    )
    lib = AssetLibrary.load(fp)
    entry = lib.get("voice_old_abc123")
    assert entry.fingerprint == entry.sha1
    assert entry.material_code == "voice-aaaaaaaaaaaa"


def test_json_utf8(tmp_path: Path, wav_file: Path):
    fp = tmp_path / "lib.json"
    lib = AssetLibrary(fp)
    lib.register_local(wav_file, MessageType.VOICE, display_name="问候语")
    lib.register_forward(
        MessageType.MINIPROGRAM,
        fta_locator="商品A 小程序", display_name="商品A",
    )
    lib.save()
    raw = fp.read_text(encoding="utf-8")
    assert "问候语" in raw
    assert "商品A" in raw
    assert "\\u" not in raw

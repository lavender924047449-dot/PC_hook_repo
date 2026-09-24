"""
AssetLibrary — 素材索引与持久化。

兼容目标：
- 保留旧版 `tag` 作为主键，避免影响既有 Plan/测试。
- 新增 PC-FTA 主链路字段：`material_code` / `fingerprint` / `anchor` / `source_account`。
- 读取旧库时自动补齐编码字段，做到无感迁移。
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from loguru import logger
from pydantic import BaseModel, Field, field_validator

from app.config import resolve_path
from app.messaging.material_code_service import MaterialCodeService
from app.messaging.types import MessageType

TAG_PREFIX: dict[MessageType, str] = {
    MessageType.IMAGE: "img",
    MessageType.VIDEO: "vid",
    MessageType.FILE: "file",
    MessageType.VOICE: "voice",
    MessageType.CONTACT_CARD: "card",
    MessageType.LOCATION: "loc",
    MessageType.STICKER: "stk",
    MessageType.MINIPROGRAM: "mp",
    MessageType.CHANNEL_VIDEO: "cv",
}

LOCAL_SOURCE_TYPES: frozenset[MessageType] = frozenset({
    MessageType.IMAGE,
    MessageType.VIDEO,
    MessageType.FILE,
    MessageType.VOICE,
})

FORWARD_ONLY_TYPES: frozenset[MessageType] = frozenset({
    MessageType.MINIPROGRAM,
    MessageType.CHANNEL_VIDEO,
    MessageType.LOCATION,
    MessageType.CONTACT_CARD,
    MessageType.STICKER,
})

_SLUG_RE = re.compile(r"[^\w\u4e00-\u9fff]+", re.UNICODE)


def _sha1_of_file(path: Path, chunk: int = 65536) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _md5_of_str(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def _slug(name: str, max_len: int = 20) -> str:
    s = _SLUG_RE.sub("_", name.strip()).strip("_")
    if len(s) > max_len:
        s = s[:max_len].rstrip("_")
    return s


class AssetEntry(BaseModel):
    tag: str
    semantic_type: MessageType
    source_path: str | None = None
    sha1: str | None = None
    fta_locator: str | None = None
    display_name: str | None = None

    # Stage PC-FTA 新字段
    material_code: str | None = None
    fingerprint: str | None = None
    anchor: dict[str, Any] | None = None
    source_account: str | None = None

    # 视频封面缩略图的内容指纹，用于再次发送同一视频时（只落下封面、不重写 mp4）复用 vid 编码。
    cover_fingerprints: list[str] = Field(default_factory=list)

    created_at: str = Field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )
    last_refreshed_at: str | None = None

    @field_validator("tag")
    @classmethod
    def _tag_shape(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("tag 不能为空")
        if not re.fullmatch(r"[\w\u4e00-\u9fff]+", v):
            raise ValueError(f"tag 含非法字符: {v!r}")
        return v

    def brief(self) -> str:
        code = f", code={self.material_code}" if self.material_code else ""
        t = self.semantic_type.value
        if self.source_path:
            return f"{self.tag}({t}, {Path(self.source_path).name}{code})"
        if self.fta_locator:
            return f"{self.tag}({t}, FTA:{self.fta_locator!r}{code})"
        return f"{self.tag}({t}{code})"

    def touch_refreshed(self) -> None:
        self.last_refreshed_at = datetime.now().isoformat(timespec="seconds")


class AssetLibrary:
    DEFAULT_PATH: ClassVar[str] = "runtime/asset_library.json"

    def __init__(self, path: str | Path | None = None) -> None:
        self.path: Path = resolve_path(path or self.DEFAULT_PATH)
        self._entries: dict[str, AssetEntry] = {}
        self._code_service = MaterialCodeService(self.lookup_material_code)

    @classmethod
    def load(cls, path: str | Path | None = None) -> AssetLibrary:
        lib = cls(path)
        if lib.path.exists():
            raw = json.loads(lib.path.read_text(encoding="utf-8"))
            for item in raw.get("entries", []):
                entry = AssetEntry.model_validate(item)
                lib._fill_legacy_fields(entry)
                lib._entries[entry.tag] = entry
            logger.debug(f"AssetLibrary 加载 {len(lib._entries)} 条 ← {lib.path}")
        else:
            logger.debug(f"AssetLibrary 新库 (文件不存在): {lib.path}")
        return lib

    def save(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 2,
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "entries": [e.model_dump(mode="json") for e in self._entries.values()],
        }
        self.path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.debug(f"AssetLibrary 保存 {len(self._entries)} 条 → {self.path}")
        return self.path

    def lookup_material_code(self, code: str) -> AssetEntry | None:
        normalized = code.strip()
        for entry in self._entries.values():
            if (entry.material_code or "").strip() == normalized:
                return entry
        return None

    def register_local(
        self,
        source_path: str | Path,
        semantic_type: MessageType,
        *,
        display_name: str | None = None,
        fta_locator: str | None = None,
        overwrite: bool = False,
        source_account: str | None = None,
    ) -> AssetEntry:
        if semantic_type not in LOCAL_SOURCE_TYPES:
            allow = sorted(t.value for t in LOCAL_SOURCE_TYPES)
            raise ValueError(f"register_local 不接受 {semantic_type.value}; 可选: {allow}")

        p = Path(source_path)
        if not p.is_absolute():
            p = resolve_path(p)
        if not p.exists():
            raise FileNotFoundError(f"素材文件不存在: {p}")
        if not p.is_file():
            raise ValueError(f"素材必须是文件: {p}")

        sha1 = _sha1_of_file(p)
        fingerprint = self._code_service.fingerprint_from_file(p)

        for entry in self._entries.values():
            old_fp = entry.fingerprint or entry.sha1
            if old_fp == fingerprint and entry.semantic_type is semantic_type:
                if overwrite:
                    if display_name is not None:
                        entry.display_name = display_name
                    if fta_locator is not None:
                        entry.fta_locator = fta_locator
                    if source_account is not None:
                        entry.source_account = source_account
                entry.source_path = str(p)
                self._fill_legacy_fields(entry)
                logger.info(f"AssetLibrary 复用编码: {entry.brief()}")
                return entry

        material_code = self._code_service.generate(
            fingerprint,
            semantic_type,
            has_conflict=lambda c: (
                (exist := self.lookup_material_code(c)) is not None
                and (exist.fingerprint or exist.sha1) != fingerprint
            ),
        )
        tag = self._make_tag(semantic_type, sha1[:6], display_name)
        entry = AssetEntry(
            tag=tag,
            semantic_type=semantic_type,
            source_path=str(p),
            sha1=sha1,
            fta_locator=fta_locator,
            display_name=display_name,
            material_code=material_code,
            fingerprint=fingerprint,
            source_account=source_account,
        )
        self._entries[tag] = entry
        logger.info(f"AssetLibrary 注册本地素材: {entry.brief()}")
        return entry

    def register_forward(
        self,
        semantic_type: MessageType,
        fta_locator: str,
        *,
        display_name: str | None = None,
        overwrite: bool = False,
        source_account: str | None = None,
    ) -> AssetEntry:
        if semantic_type not in FORWARD_ONLY_TYPES:
            allow = sorted(t.value for t in FORWARD_ONLY_TYPES)
            raise ValueError(f"register_forward 不接受 {semantic_type.value}; 可选: {allow}")

        loc = fta_locator.strip()
        if not loc:
            raise ValueError("fta_locator 不能为空")

        fingerprint = self._code_service.fingerprint_from_structured_payload(
            {"semantic_type": semantic_type.value, "fta_locator": loc}
        )

        for entry in self._entries.values():
            if entry.semantic_type is semantic_type and (entry.fta_locator or "").strip() == loc:
                if overwrite:
                    if display_name is not None:
                        entry.display_name = display_name
                    if source_account is not None:
                        entry.source_account = source_account
                self._fill_legacy_fields(entry)
                return entry

        material_code = self._code_service.generate(
            fingerprint,
            semantic_type,
            has_conflict=lambda c: (
                (exist := self.lookup_material_code(c)) is not None
                and (exist.fingerprint or exist.sha1) != fingerprint
            ),
        )
        body = _md5_of_str(loc)[:6]
        tag = self._make_tag(semantic_type, body, display_name)
        entry = AssetEntry(
            tag=tag,
            semantic_type=semantic_type,
            fta_locator=loc,
            display_name=display_name,
            material_code=material_code,
            fingerprint=fingerprint,
            source_account=source_account,
        )
        self._entries[tag] = entry
        logger.info(f"AssetLibrary 注册转发素材: {entry.brief()}")
        return entry

    def get(self, tag: str) -> AssetEntry:
        try:
            return self._entries[tag]
        except KeyError:
            raise KeyError(f"AssetLibrary 没有 tag={tag!r}; 现有: {sorted(self._entries)[:20]}")

    def has(self, tag: str) -> bool:
        return tag in self._entries

    def all(self) -> list[AssetEntry]:
        return list(self._entries.values())

    def by_type(self, t: MessageType) -> list[AssetEntry]:
        return [e for e in self._entries.values() if e.semantic_type is t]

    def remove(self, tag: str) -> AssetEntry:
        try:
            removed = self._entries.pop(tag)
        except KeyError:
            raise KeyError(f"tag 不存在: {tag!r}")
        logger.info(f"AssetLibrary 删除: {removed.brief()}")
        return removed

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, tag: str) -> bool:
        return tag in self._entries

    def _make_tag(self, semantic_type: MessageType, body: str, display_name: str | None) -> str:
        prefix = TAG_PREFIX[semantic_type]
        slug_part = _slug(display_name) if display_name else ""
        parts = [prefix]
        if slug_part:
            parts.append(slug_part)
        parts.append(body)
        base = "_".join(parts)
        if base not in self._entries:
            return base
        i = 1
        while True:
            candidate = f"{base}_{i}"
            if candidate not in self._entries:
                return candidate
            i += 1

    def _upsert_raw(self, entry: AssetEntry) -> None:
        self._fill_legacy_fields(entry)
        self._entries[entry.tag] = entry

    def _fill_legacy_fields(self, entry: AssetEntry) -> None:
        if not entry.fingerprint:
            if entry.sha1:
                entry.fingerprint = entry.sha1
            elif entry.fta_locator:
                entry.fingerprint = self._code_service.fingerprint_from_structured_payload(
                    {"semantic_type": entry.semantic_type.value, "fta_locator": entry.fta_locator}
                )
        if not entry.material_code and entry.fingerprint:
            entry.material_code = self._code_service.generate(
                entry.fingerprint,
                entry.semantic_type,
                has_conflict=lambda c: (
                    (exist := self.lookup_material_code(c)) is not None and exist.tag != entry.tag
                ),
            )


__all__ = ["AssetEntry", "AssetLibrary", "TAG_PREFIX", "LOCAL_SOURCE_TYPES", "FORWARD_ONLY_TYPES"]

_covered = set(TAG_PREFIX) | {MessageType.TEXT}
assert _covered == set(MessageType), f"TAG_PREFIX 缺少类型: {set(MessageType) - _covered}"
_all_non_text = set(MessageType) - {MessageType.TEXT}
assert LOCAL_SOURCE_TYPES | FORWARD_ONLY_TYPES == _all_non_text
assert LOCAL_SOURCE_TYPES.isdisjoint(FORWARD_ONLY_TYPES)

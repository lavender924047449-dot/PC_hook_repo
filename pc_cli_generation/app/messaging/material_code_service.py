"""
素材编码服务（PC FTA 升级链路核心）。

职责：
1) 基于稳定指纹生成跨账号一致的素材编码：`<prefix>-<12hex>`
2) 提供各类型素材的指纹规范化函数
3) 提供编码查询入口（由 AssetLibrary 注入查询函数）
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable

from app.messaging.types import MessageType

CODE_PREFIX: dict[MessageType, str] = {
    MessageType.IMAGE: "img",
    MessageType.VIDEO: "vid",
    MessageType.FILE: "file",
    MessageType.VOICE: "voice",
    MessageType.MINIPROGRAM: "mp",
    MessageType.CHANNEL_VIDEO: "cv",
    MessageType.LOCATION: "loc",
    MessageType.CONTACT_CARD: "card",
    MessageType.STICKER: "stk",
    MessageType.TEXT: "txt",
}


def _sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _sha1_text(text: str) -> str:
    return _sha1_bytes(text.encode("utf-8"))


def _norm_text(value: str) -> str:
    return " ".join(value.strip().split()).lower()


def _hash_file(path: Path, chunk: int = 65536) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


class MaterialCodeService:
    """
    编码与指纹服务。

    `lookup_fn` 由上层注入，避免与 AssetLibrary 形成强耦合循环依赖。
    """

    def __init__(self, lookup_fn: Callable[[str], object | None] | None = None) -> None:
        self._lookup_fn = lookup_fn

    # ---------- 编码 ---------- #

    def generate(
        self,
        fingerprint: str,
        message_type: MessageType,
        *,
        has_conflict: Callable[[str], bool] | None = None,
    ) -> str:
        """
        按 `<prefix>-<12hex>` 生成编码；若冲突，追加 `-1/-2...`。
        """
        prefix = CODE_PREFIX[message_type]
        base = f"{prefix}-{fingerprint[:12].lower()}"
        if has_conflict is None or not has_conflict(base):
            return base
        i = 1
        while True:
            candidate = f"{base}-{i}"
            if not has_conflict(candidate):
                return candidate
            i += 1

    def lookup(self, code: str) -> object | None:
        if self._lookup_fn is None:
            return None
        return self._lookup_fn(code.strip())

    # ---------- 指纹 ---------- #

    def fingerprint_from_file(self, source_path: str | Path) -> str:
        p = Path(source_path)
        return _hash_file(p)

    def fingerprint_image(self, source_path: str | Path) -> str:
        return self.fingerprint_from_file(source_path)

    def fingerprint_video(self, source_path: str | Path) -> str:
        return self.fingerprint_from_file(source_path)

    def fingerprint_file(self, source_path: str | Path) -> str:
        return self.fingerprint_from_file(source_path)

    def fingerprint_voice(self, source_path: str | Path) -> str:
        return self.fingerprint_from_file(source_path)

    def fingerprint_miniprogram(
        self,
        *,
        title: str,
        description: str = "",
        app_name: str = "",
        appid_tail: str = "",
    ) -> str:
        raw = "|".join([
            _norm_text(title),
            _norm_text(description),
            _norm_text(app_name),
            _norm_text(appid_tail),
        ])
        return _sha1_text(raw)

    def fingerprint_channel_video(
        self,
        *,
        channel_name: str,
        video_title: str,
        publisher_id_tail: str = "",
    ) -> str:
        raw = "|".join([
            _norm_text(channel_name),
            _norm_text(video_title),
            _norm_text(publisher_id_tail),
        ])
        return _sha1_text(raw)

    def fingerprint_location(
        self,
        *,
        poi_name: str,
        address: str = "",
        lat: float | None = None,
        lng: float | None = None,
    ) -> str:
        coord = ""
        if lat is not None and lng is not None:
            coord = f"{lat:.4f},{lng:.4f}"
        raw = "|".join([_norm_text(poi_name), _norm_text(address), coord])
        return _sha1_text(raw)

    def fingerprint_contact_card(
        self,
        *,
        display_name: str,
        wecom_id_tail: str = "",
    ) -> str:
        raw = "|".join([_norm_text(display_name), _norm_text(wecom_id_tail)])
        return _sha1_text(raw)

    def fingerprint_sticker(self, source_path: str | Path) -> str:
        return self.fingerprint_from_file(source_path)

    def fingerprint_text_template(self, text: str) -> str:
        return _sha1_text(_norm_text(text))

    def fingerprint_from_structured_payload(self, payload: dict) -> str:
        """
        兜底：把结构化内容按稳定 JSON 序列化后哈希。
        """
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        return _sha1_text(raw)


__all__ = ["MaterialCodeService", "CODE_PREFIX"]

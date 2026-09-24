"""联系人检索：搜索 + 本地缓存。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.config import resolve_path
from app.pc_wecom.pc_navigator import PCWeComNavigator


@dataclass(frozen=True)
class ContactHit:
    name: str
    alias: str = ""
    wecom_id: str = ""


class ContactIndexer:
    def __init__(
        self,
        navigator: PCWeComNavigator,
        cache_path: str | Path = "runtime/contact_index.json",
    ) -> None:
        self._nav = navigator
        self._cache_path = resolve_path(cache_path)
        self._cache: list[ContactHit] = []
        self._load()

    def _load(self) -> None:
        if not self._cache_path.exists():
            self._cache = []
            return
        raw = json.loads(self._cache_path.read_text(encoding="utf-8"))
        self._cache = [ContactHit(**x) for x in raw.get("contacts", [])]

    def _save(self) -> None:
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"contacts": [c.__dict__ for c in self._cache]}
        self._cache_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def add_or_update(self, hit: ContactHit) -> None:
        key = (hit.name.strip(), hit.wecom_id.strip())
        for i, cur in enumerate(self._cache):
            if (cur.name.strip(), cur.wecom_id.strip()) == key:
                self._cache[i] = hit
                self._save()
                return
        self._cache.append(hit)
        self._save()

    def search(self, keyword: str) -> list[ContactHit]:
        kw = keyword.strip().lower()
        if not kw:
            return []
        out = [
            c
            for c in self._cache
            if kw in c.name.lower() or kw in c.alias.lower() or kw in c.wecom_id.lower()
        ]
        if out:
            return out
        # 本地无命中时，触发一次 UI 搜索动作（当前最小实现仅返回空，留待联调补齐解析）。
        self._nav.search_and_pick_contact(keyword)
        return []

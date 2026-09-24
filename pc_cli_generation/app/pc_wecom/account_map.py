"""多账号映射与当前账号识别。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.config import resolve_path


@dataclass
class AccountBinding:
    account_id: str
    wx_alias: str = ""
    wecom_alias: str = ""


class AccountMapService:
    def __init__(
        self,
        wxwork_root: str | Path | None = None,
        path: str | Path = "runtime/account_map.json",
    ) -> None:
        self._wxwork_root = Path(wxwork_root) if wxwork_root else Path.home() / "Documents" / "WXWork"
        self._path = resolve_path(path)
        self._map: dict[str, AccountBinding] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            self._map = {}
            return
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        self._map = {
            x["account_id"]: AccountBinding(**x)
            for x in raw.get("accounts", [])
            if x.get("account_id")
        }

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"accounts": [v.__dict__ for v in self._map.values()]}
        self._path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def detect_active_account(self) -> str:
        if not self._wxwork_root.exists():
            raise FileNotFoundError(f"WXWork 根目录不存在: {self._wxwork_root}")
        candidates: list[tuple[str, int]] = []
        for sub in self._wxwork_root.iterdir():
            if not sub.is_dir() or not sub.name.isdigit():
                continue
            cache = sub / "Cache"
            count = sum(1 for p in cache.rglob("*") if p.is_file()) if cache.exists() else 0
            candidates.append((sub.name, count))
        if not candidates:
            raise FileNotFoundError("未发现可用企微账号目录")
        candidates.sort(key=lambda x: -x[1])
        return candidates[0][0]

    def list_accounts(self) -> list[str]:
        if not self._wxwork_root.exists():
            return []
        out: list[str] = []
        for sub in self._wxwork_root.iterdir():
            if sub.is_dir() and sub.name.isdigit():
                out.append(sub.name)
        out.sort()
        return out

    def bind(self, account_id: str, *, wx_alias: str = "", wecom_alias: str = "") -> None:
        self._map[account_id] = AccountBinding(account_id, wx_alias=wx_alias, wecom_alias=wecom_alias)
        self._save()

    def get(self, account_id: str) -> AccountBinding | None:
        return self._map.get(account_id)

"""display_name → conv_id 映射服务（产品化 ⑤）。

把逆向脚本 ``runtime/wecom_re/list_conv_ids.py`` 的只读扫堆技术抽成产品模块，
再结合 ``identify_uin.py`` 的「uin 邻近字符串」抽取显示名，建立
``{display_name → conv_id}`` 供 ``SendQueue.target`` 解析。

企微 heap 里 ``colleague_remark_table`` 查询结果 cache 会把同事备注 / 昵称
和 uin 放在邻近内存；本模块只做 Frida **只读** attach + ``Memory.scanSync``，
**禁止** ``Interceptor.attach`` / 写 ``.text``（见 NativeRouter 同一安全约束）。

依赖注入
--------
``frida_module`` / ``clock`` / ``sleep`` 与 :class:`NativeRouter` 同款，
测试传入 fake frida 即可完全隔离进程。
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

DEFAULT_MODULE_NAME = "wxwork.exe"
DEFAULT_CONTEXT_BEFORE = 128
DEFAULT_CONTEXT_AFTER = 128

CONV_ID_SINGLE_RE = re.compile(r"^S:\d{16}_\d{16}$")
CONV_ID_ROOM_RE = re.compile(r"^R:\d{13,20}$")
FILEASSIST_CONV_ID = "FILEASSIST"
FILEASSIST_NAMES = frozenset({"文件传输助手", "File Transfer", "FILEASSIST", "fileassist"})

_SQL_NOISE = frozenset({
    "SELECT", "FROM", "WHERE", "AND", "OR", "NULL", "INT", "TEXT",
    "INSERT", "UPDATE", "DELETE", "INTO", "VALUES", "SET", "JOIN",
    "TABLE", "INDEX", "CREATE", "DROP", "PRIMARY", "KEY",
    "colleague_remark_table", "COLLEAGUE_REMARK_TABLE",
})
_SYSTEM_NOISE_PREFIXES = ("C:\\", "c:\\", "/", "http://", "https://")
_SYSTEM_NOISE_EXACT = frozenset({
    "WXWork", "wxwork", "Tencent", "tencent", "WeCom", "wecom",
    FILEASSIST_CONV_ID,
})


# ---------------------------------------------------------------------------
# Frida agent JS（只读扫堆，零 hook）
# ---------------------------------------------------------------------------

# 模板变量：{MODULE_NAME}
_FRIDA_JS_TEMPLATE = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === '{MODULE_NAME}';
})[0];
if (!wx) throw new Error('module not loaded: {MODULE_NAME}');
send({t:'info', msg: 'attached, base=' + wx.base});

function bytesToHex(bytes){
    let s = '';
    for (let i = 0; i < bytes.length; i++){
        s += bytes[i].toString(16).padStart(2, '0');
    }
    return s;
}

rpc.exports = {
    findConvIds: function(){
        const results = {S: [], R: [], FILEASSIST: 0};
        const ranges = Process.enumerateRanges({protection: 'rw-', coalesce: false});
        for (let i = 0; i < ranges.length; i++){
            const r = ranges[i];
            try {
                const hits = Memory.scanSync(r.base, r.size, '53 3a 3?');
                for (let j = 0; j < hits.length; j++){
                    const p = hits[j].address;
                    let bytes;
                    try { bytes = new Uint8Array(p.readByteArray(36)); }
                    catch(e){ continue; }
                    let s = '';
                    for (let k = 0; k < 35 && k < bytes.length; k++){
                        const b = bytes[k];
                        if (b < 0x20 || b > 0x7e) { s = ''; break; }
                        s += String.fromCharCode(b);
                    }
                    if (s && /^S:\d{16}_\d{16}$/.test(s)){
                        results.S.push(s);
                    }
                }
            } catch(e){}

            try {
                const hits = Memory.scanSync(r.base, r.size, '52 3a 3?');
                for (let j = 0; j < hits.length; j++){
                    const p = hits[j].address;
                    let bytes;
                    try { bytes = new Uint8Array(p.readByteArray(24)); }
                    catch(e){ continue; }
                    if (bytes[0] === 0x52 && bytes[1] === 0x3a && bytes[2] >= 0x30 && bytes[2] <= 0x39){
                        let full = 'R:';
                        for (let k = 2; k < 24; k++){
                            const b = bytes[k];
                            if (b >= 0x30 && b <= 0x39) full += String.fromCharCode(b);
                            else break;
                        }
                        if (full.length >= 15 && full.length <= 22){
                            results.R.push(full);
                        }
                    }
                }
            } catch(e){}

            try {
                const hits = Memory.scanSync(r.base, r.size, '46 49 4c 45 41 53 53 49 53 54');
                results.FILEASSIST += hits.length;
            } catch(e){}
        }
        return results;
    },

    findUin: function(uinStr, contextBefore, contextAfter){
        const results = [];
        const uinBytes = [];
        for (let i = 0; i < uinStr.length; i++) uinBytes.push(uinStr.charCodeAt(i));
        const pattern = uinBytes.map(function(b){ return b.toString(16).padStart(2,'0'); }).join(' ');

        const ranges = Process.enumerateRanges({protection: 'rw-', coalesce: false});
        let hitCount = 0;
        const MAX_HITS = 200;
        for (let i = 0; i < ranges.length && hitCount < MAX_HITS; i++){
            const r = ranges[i];
            try {
                const ms = Memory.scanSync(r.base, r.size, pattern);
                for (let j = 0; j < ms.length && hitCount < MAX_HITS; j++){
                    const p = ms[j].address;
                    let prevOk = true;
                    try {
                        const prev = p.sub(1).readU8();
                        if (prev >= 0x30 && prev <= 0x39) prevOk = false;
                    } catch(e){}
                    if (!prevOk) continue;
                    try {
                        const next = p.add(uinStr.length).readU8();
                        if (next >= 0x30 && next <= 0x39) continue;
                    } catch(e){}

                    let beforeHex = '';
                    let afterHex = '';
                    try {
                        beforeHex = bytesToHex(new Uint8Array(p.sub(contextBefore).readByteArray(contextBefore)));
                    } catch(e){}
                    try {
                        afterHex = bytesToHex(new Uint8Array(p.add(uinStr.length).readByteArray(contextAfter)));
                    } catch(e){}
                    results.push({
                        addr: p.toString(),
                        before_hex: beforeHex,
                        after_hex: afterHex
                    });
                    hitCount++;
                }
            } catch(e){}
        }
        return results;
    }
};
send({t:'ready'});
"""


def _build_frida_js(module_name: str = DEFAULT_MODULE_NAME) -> str:
    return _FRIDA_JS_TEMPLATE.replace("{MODULE_NAME}", module_name.lower())


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConvMapping:
    """一条 display_name → conv_id 映射。"""

    display_name: str
    conv_id: str
    peer_uin: str = ""
    kind: str = "single"  # single | room | fta
    score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "display_name": self.display_name,
            "conv_id": self.conv_id,
            "peer_uin": self.peer_uin,
            "kind": self.kind,
            "score": self.score,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ConvMapping":
        return cls(
            display_name=str(d.get("display_name", "")),
            conv_id=str(d.get("conv_id", "")),
            peer_uin=str(d.get("peer_uin", "")),
            kind=str(d.get("kind", "single") or "single"),
            score=int(d.get("score", 0) or 0),
        )


@dataclass(frozen=True)
class ConvIdScanResult:
    """一次 conv_id 扫堆结果（未绑定显示名）。"""

    singles: tuple[str, ...]
    rooms: tuple[str, ...]
    fileassist_hits: int
    self_uin: str = ""


class ContactConvResolverError(Exception):
    """ContactConvResolver 相关异常基类。"""


class ResolverNotAttachedError(ContactConvResolverError):
    """未 attach 就调用需要 attach 的方法。"""


class ResolverFridaUnavailableError(ContactConvResolverError):
    """frida 模块不可用。"""


# ---------------------------------------------------------------------------
# 字符串抽取（identify_uin.py 产品化）
# ---------------------------------------------------------------------------


def extract_strings_from_hex(hex_str: str, min_len: int = 3) -> list[str]:
    """从邻近 dump 的 hex 中提取 UTF-8 / UTF-16-LE 可读字符串。"""
    if not hex_str:
        return []
    try:
        data = bytes.fromhex(hex_str)
    except ValueError:
        return []
    out: list[str] = []
    out.extend(_extract_utf8(data, min_len))
    out.extend(_extract_utf16le(data, min_len))
    return out


def _extract_utf8(data: bytes, min_len: int) -> list[str]:
    strs: list[str] = []
    i = 0
    n = len(data)
    while i < n:
        start = i
        cur = bytearray()
        while i < n:
            b = data[i]
            if b == 0:
                break
            if b in (0x09, 0x0A, 0x0D) or (0x20 <= b <= 0x7E) or b >= 0x80:
                cur.append(b)
                i += 1
            else:
                break
        if len(cur) >= min_len:
            s = cur.decode("utf-8", errors="ignore").strip()
            if s and len(s) >= min_len:
                strs.append(s)
        while i < n and data[i] == 0:
            i += 1
        if i == start:
            i += 1
    return strs


def _extract_utf16le(data: bytes, min_len: int) -> list[str]:
    """抽取 UTF-16-LE 字符串。必须 00 00 终止，避免把 UTF-8 中文误读成其它汉字。"""
    strs: list[str] = []
    n = len(data)
    i = 0
    while i + 3 < n:  # 至少 1 个 wchar + NUL
        chars: list[str] = []
        j = i
        while j + 1 < n:
            code = data[j] | (data[j + 1] << 8)
            if code == 0:
                break
            if 0x20 <= code <= 0x7E or 0x4E00 <= code <= 0x9FFF or 0x3400 <= code <= 0x4DBF:
                chars.append(chr(code))
                j += 2
            else:
                break
        terminated = j + 1 < n and (data[j] | (data[j + 1] << 8)) == 0
        if terminated and len(chars) >= min_len:
            s = "".join(chars).strip()
            if s:
                strs.append(s)
            i = j + 2
            continue
        i += 1
    return strs


def looks_like_conv_id(value: str) -> bool:
    v = value.strip()
    if v == FILEASSIST_CONV_ID:
        return True
    return bool(CONV_ID_SINGLE_RE.match(v) or CONV_ID_ROOM_RE.match(v))


def split_single_conv_id(conv_id: str) -> Optional[tuple[str, str]]:
    """S:{self}_{peer} → (self_uin, peer_uin)。"""
    if not CONV_ID_SINGLE_RE.match(conv_id):
        return None
    body = conv_id[2:]
    self_uin, peer_uin = body.split("_", 1)
    return self_uin, peer_uin


def conv_kind(conv_id: str) -> str:
    if conv_id == FILEASSIST_CONV_ID:
        return "fta"
    if CONV_ID_ROOM_RE.match(conv_id):
        return "room"
    return "single"


def is_noise_name(s: str) -> bool:
    raw = s.strip()
    if not raw or len(raw) < 2 or len(raw) > 32:
        return True
    if raw.isdigit() and len(raw) <= 20:
        return True
    if looks_like_conv_id(raw):
        return True
    if raw.upper() in _SQL_NOISE or raw in _SYSTEM_NOISE_EXACT:
        return True
    if raw.startswith(_SYSTEM_NOISE_PREFIXES):
        return True
    if raw.lower().endswith((".exe", ".dll", ".dat", ".db")):
        return True
    return False


def pick_display_name(neighbors: Counter[str]) -> Optional[tuple[str, int]]:
    """从 uin 邻近字符串里挑最像显示名的一条。优先中文，其次频次。"""
    scored: list[tuple[int, int, int, str]] = []
    for s, cnt in neighbors.items():
        if is_noise_name(s):
            continue
        has_cn = any(ord(ch) > 0x7F for ch in s)
        scored.append((1 if has_cn else 0, cnt, -len(s), s))
    if not scored:
        return None
    scored.sort(reverse=True)
    best = scored[0]
    return best[3], best[1]


# ---------------------------------------------------------------------------
# ContactConvResolver
# ---------------------------------------------------------------------------


class ContactConvResolver:
    """扫堆建立并查询 ``{display_name → conv_id}``。

    典型用法::

        resolver = ContactConvResolver(pid=22184, cache_path=Path("runtime/conv_map.json"))
        resolver.attach()
        try:
            resolver.refresh()
            conv_id = resolver.resolve("张三")
        finally:
            resolver.detach()

        # 测试 / 运营也可手动 seed，不依赖 Frida：
        resolver.seed("张三", "S:1688855042791155_7881300363276969")
    """

    def __init__(
        self,
        pid: int = 0,
        *,
        module_name: str = DEFAULT_MODULE_NAME,
        frida_module: Any = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        script_load_timeout_s: float = 3.0,
        context_before: int = DEFAULT_CONTEXT_BEFORE,
        context_after: int = DEFAULT_CONTEXT_AFTER,
        cache_path: str | Path | None = None,
        indexer: Any = None,
    ) -> None:
        self.pid = int(pid)
        self.module_name = module_name
        self._clock = clock
        self._sleep = sleep
        self._script_load_timeout_s = float(script_load_timeout_s)
        self._context_before = int(context_before)
        self._context_after = int(context_after)
        self._cache_path = Path(cache_path) if cache_path else None
        self._indexer = indexer

        if frida_module is None:
            try:
                import frida  # type: ignore
                frida_module = frida
            except ImportError:
                frida_module = None
        self._frida = frida_module

        self._session: Any = None
        self._script: Any = None
        self._script_ready: bool = False
        self._agent_base: Optional[str] = None

        self._by_name: dict[str, ConvMapping] = {}
        self._by_name_lower: dict[str, ConvMapping] = {}
        self._self_uin: str = ""
        if self._cache_path:
            self.load_cache()

    # ------------------------------------------------------------------
    # Attach / detach（只读，禁止 Interceptor）
    # ------------------------------------------------------------------

    def attach(self) -> None:
        if self._frida is None:
            raise ResolverFridaUnavailableError(
                "frida module not available; install `frida` or inject via frida_module"
            )
        if self._session is not None:
            logger.debug("ContactConvResolver already attached to pid=%d", self.pid)
            return
        device = self._frida.get_local_device()
        self._session = device.attach(self.pid)
        self._script = self._session.create_script(_build_frida_js(self.module_name))
        self._script_ready = False
        self._agent_base = None
        self._script.on("message", self._on_message)
        self._script.load()
        deadline = self._clock() + self._script_load_timeout_s
        while self._clock() < deadline:
            if self._script_ready:
                return
            self._sleep(0.05)
        logger.warning(
            "ContactConvResolver script ready signal not received within %.1fs; continuing",
            self._script_load_timeout_s,
        )

    def detach(self) -> None:
        try:
            if self._script is not None:
                try:
                    self._script.unload()
                except Exception:
                    logger.debug("script.unload() raised", exc_info=True)
            if self._session is not None:
                try:
                    self._session.detach()
                except Exception:
                    logger.debug("session.detach() raised", exc_info=True)
        finally:
            self._script = None
            self._session = None
            self._script_ready = False
            self._agent_base = None

    @property
    def is_attached(self) -> bool:
        return self._script is not None

    @property
    def agent_base(self) -> Optional[str]:
        return self._agent_base

    @property
    def self_uin(self) -> str:
        return self._self_uin

    def _on_message(self, message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload") or {}
            t = payload.get("t")
            if t == "ready":
                self._script_ready = True
            elif t == "info":
                msg = payload.get("msg", "")
                if "base=" in msg:
                    self._agent_base = msg.split("base=")[-1].strip()
                logger.info("frida: %s", msg)
        elif message.get("type") == "error":
            logger.warning("frida error: %s", message.get("description"))

    def _require_script(self) -> Any:
        if self._script is None:
            raise ResolverNotAttachedError("ContactConvResolver is not attached; call .attach() first")
        return self._script

    def __enter__(self) -> "ContactConvResolver":
        self.attach()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.detach()

    # ------------------------------------------------------------------
    # 扫堆
    # ------------------------------------------------------------------

    def scan_conv_ids(self) -> ConvIdScanResult:
        """扫一次堆，返回去重后的 conv_id 列表。"""
        script = self._require_script()
        raw = script.exports_sync.find_conv_ids() or {}
        singles = tuple(Counter(raw.get("S") or []).keys())
        rooms = tuple(Counter(raw.get("R") or []).keys())
        fa = int(raw.get("FILEASSIST") or 0)
        self_uin = _majority_self_uin(singles)
        return ConvIdScanResult(
            singles=singles,
            rooms=rooms,
            fileassist_hits=fa,
            self_uin=self_uin,
        )

    def refresh(self, *, max_uins: Optional[int] = None) -> dict[str, str]:
        """全量扫堆并重建映射。命中后写 cache、可选同步 ContactIndexer。"""
        scan = self.scan_conv_ids()
        self._self_uin = scan.self_uin
        mappings: list[ConvMapping] = []

        peer_to_conv: dict[str, str] = {}
        for cid in scan.singles:
            parts = split_single_conv_id(cid)
            if not parts:
                continue
            _self_uin, peer = parts
            peer_to_conv[peer] = cid

        uins = list(peer_to_conv.keys())
        if max_uins is not None:
            uins = uins[: max(0, int(max_uins))]

        for uin in uins:
            neighbors = self._neighbor_counter(uin)
            picked = pick_display_name(neighbors)
            if not picked:
                continue
            name, score = picked
            mappings.append(
                ConvMapping(
                    display_name=name,
                    conv_id=peer_to_conv[uin],
                    peer_uin=uin,
                    kind="single",
                    score=score,
                )
            )

        for cid in scan.rooms:
            room_id = cid[2:]
            neighbors = self._neighbor_counter(room_id)
            picked = pick_display_name(neighbors)
            if not picked:
                continue
            name, score = picked
            mappings.append(
                ConvMapping(
                    display_name=name,
                    conv_id=cid,
                    peer_uin=room_id,
                    kind="room",
                    score=score,
                )
            )

        if scan.fileassist_hits > 0:
            mappings.append(
                ConvMapping(
                    display_name="文件传输助手",
                    conv_id=FILEASSIST_CONV_ID,
                    kind="fta",
                    score=scan.fileassist_hits,
                )
            )

        self._replace_mappings(mappings)
        self.save_cache()
        self.sync_indexer()
        return self.mapping()

    def _neighbor_counter(self, token: str) -> Counter[str]:
        script = self._require_script()
        hits = script.exports_sync.find_uin(token, self._context_before, self._context_after) or []
        counter: Counter[str] = Counter()
        for h in hits:
            for field in ("before_hex", "after_hex"):
                for s in extract_strings_from_hex(h.get(field, ""), min_len=2):
                    s = s.strip()
                    if s:
                        counter[s] += 1
        return counter

    # ------------------------------------------------------------------
    # 查询 / 手动 seed
    # ------------------------------------------------------------------

    def seed(self, display_name: str, conv_id: str, *, peer_uin: str = "", score: int = 0) -> ConvMapping:
        """手动写入一条映射（测试 / 运营覆盖）。"""
        name = display_name.strip()
        cid = conv_id.strip()
        if not name or not cid:
            raise ValueError("display_name 与 conv_id 都不能为空")
        if not looks_like_conv_id(cid):
            raise ValueError(f"非法 conv_id: {cid!r}")
        if not peer_uin:
            parts = split_single_conv_id(cid)
            peer_uin = parts[1] if parts else ""
        mapping = ConvMapping(
            display_name=name,
            conv_id=cid,
            peer_uin=peer_uin,
            kind=conv_kind(cid),
            score=score,
        )
        self._put(mapping)
        self.save_cache()
        return mapping

    def resolve(self, display_name: str) -> Optional[str]:
        """把 SendQueue.target（显示名 / uin / 已是 conv_id）解析成 conv_id。"""
        key = (display_name or "").strip()
        if not key:
            return None
        if looks_like_conv_id(key):
            return key
        if key in FILEASSIST_NAMES or key.lower() in FILEASSIST_NAMES:
            return FILEASSIST_CONV_ID
        hit = self._by_name.get(key) or self._by_name_lower.get(key.lower())
        if hit:
            return hit.conv_id
        # 16 位 uin
        if key.isdigit() and len(key) == 16:
            for m in self._by_name.values():
                if m.peer_uin == key:
                    return m.conv_id
            if self._self_uin:
                return f"S:{self._self_uin}_{key}"
        # 模糊：子串
        kw = key.lower()
        fuzzy = [
            m for m in self._by_name.values()
            if kw in m.display_name.lower() or (m.peer_uin and kw in m.peer_uin)
        ]
        if len(fuzzy) == 1:
            return fuzzy[0].conv_id
        if len(fuzzy) > 1:
            fuzzy.sort(key=lambda m: (-m.score, len(m.display_name)))
            return fuzzy[0].conv_id
        return None

    def mapping(self) -> dict[str, str]:
        """当前 ``{display_name → conv_id}`` 快照。"""
        return {name: m.conv_id for name, m in self._by_name.items()}

    def mappings(self) -> list[ConvMapping]:
        return list(self._by_name.values())

    def sync_indexer(self) -> int:
        """把映射写入可选的 ContactIndexer（name + wecom_id=conv_id）。"""
        indexer = self._indexer
        if indexer is None:
            return 0
        add = getattr(indexer, "add_or_update", None)
        if not callable(add):
            return 0
        from app.pc_wecom.contact_indexer import ContactHit

        n = 0
        for m in self._by_name.values():
            add(ContactHit(name=m.display_name, wecom_id=m.conv_id))
            n += 1
        return n

    # ------------------------------------------------------------------
    # cache
    # ------------------------------------------------------------------

    def load_cache(self) -> None:
        path = self._cache_path
        if path is None or not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("failed to load conv map cache: %s", path)
            return
        self._self_uin = str(raw.get("self_uin") or "")
        items = raw.get("mappings") or []
        mappings: list[ConvMapping] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                mappings.append(ConvMapping.from_dict(item))
            except (TypeError, ValueError):
                continue
        self._replace_mappings(mappings)

    def save_cache(self) -> None:
        path = self._cache_path
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "self_uin": self._self_uin,
            "mappings": [m.to_dict() for m in self._by_name.values()],
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _replace_mappings(self, mappings: list[ConvMapping]) -> None:
        self._by_name = {}
        self._by_name_lower = {}
        for m in mappings:
            if m.display_name and m.conv_id:
                self._put(m)

    def _put(self, mapping: ConvMapping) -> None:
        existing = self._by_name.get(mapping.display_name)
        if existing is not None and existing.score > mapping.score:
            return
        self._by_name[mapping.display_name] = mapping
        self._by_name_lower[mapping.display_name.lower()] = mapping


def _majority_self_uin(singles: tuple[str, ...] | list[str]) -> str:
    votes: Counter[str] = Counter()
    for cid in singles:
        parts = split_single_conv_id(cid)
        if parts:
            votes[parts[0]] += 1
    if not votes:
        return ""
    return votes.most_common(1)[0][0]


__all__ = [
    "CONV_ID_ROOM_RE",
    "CONV_ID_SINGLE_RE",
    "ContactConvResolver",
    "ContactConvResolverError",
    "ConvIdScanResult",
    "ConvMapping",
    "DEFAULT_MODULE_NAME",
    "FILEASSIST_CONV_ID",
    "FILEASSIST_NAMES",
    "ResolverFridaUnavailableError",
    "ResolverNotAttachedError",
    "conv_kind",
    "extract_strings_from_hex",
    "is_noise_name",
    "looks_like_conv_id",
    "pick_display_name",
    "split_single_conv_id",
]

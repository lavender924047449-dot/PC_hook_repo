"""气泡锚点服务：记录与查询素材对应的 FTA 气泡定位信息。

v2 新增：通过 WeComMemoryReader 从进程内存读取精确的
(sequence, send_time_ms, wecom_message_id) 三元组，
替代原有的 timestamp 伪锚点。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from app.messaging.asset_library import AssetLibrary
from app.pc_wecom.native_msgid_reader import NativeMsgIdReader


@dataclass(frozen=True)
class AnchorRecord:
    """消息气泡锚点记录。

    Attributes:
        bubble_timestamp:    发送时刻的 ISO 时间串（本机时间，非精确）。
        echo_message_id:     FTA echo 消息 ID（字符串）。
        fingerprint_snippet: 素材指纹片段（前 12 字符）。
        relative_position:   消息在聊天窗口的相对位置（-1=未知）。
        sequence:            从企微进程内存读取的会话内序列号（0=未获取）。
        send_time_ms:        从进程内存读取的发送时间（Unix 毫秒，0=未获取）。
        wecom_message_id:    企微内部 message_id（0=未获取）。
    """

    bubble_timestamp: str
    echo_message_id: str
    fingerprint_snippet: str
    relative_position: int = -1
    # 逆向提取的精确字段（2026-09-09 v2）
    sequence: int = 0
    send_time_ms: int = 0
    wecom_message_id: int = 0

    @property
    def has_memory_anchor(self) -> bool:
        """是否已从进程内存获取精确锚点（内存扫描路径）。"""
        return self.sequence > 0 and self.send_time_ms > 0

    @property
    def has_native_msgid(self) -> bool:
        """是否已从 SQLite bind hook 拿到真实 per-message msgid。"""
        return self.wecom_message_id > 0

    @property
    def has_precise_anchor(self) -> bool:
        """任一精确锚点来源命中。"""
        return self.has_memory_anchor or self.has_native_msgid

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "bubble_timestamp": self.bubble_timestamp,
            "echo_message_id": self.echo_message_id,
            "fingerprint_snippet": self.fingerprint_snippet,
            "relative_position": self.relative_position,
        }
        if self.has_precise_anchor:
            d["sequence"] = self.sequence
            d["send_time_ms"] = self.send_time_ms
            d["wecom_message_id"] = self.wecom_message_id
        return d


class BubbleAnchorService:
    """气泡锚点服务。

    可选注入 WeComMemoryReader，若注入则在 bind 时自动查询内存三元组。
    """

    def __init__(
        self,
        library: AssetLibrary,
        *,
        memory_reader: Optional[Any] = None,
        native_reader: Optional[NativeMsgIdReader] = None,
        native_wait_timeout_s: float = 8.0,
        native_tolerance_ms: int = 2000,
    ) -> None:
        self._library = library
        self._memory_reader = memory_reader  # WeComMemoryReader | None
        # v3 (2026-09-11)：SQLite bind hook 给出的每消息真实 msgid 读取器。
        # 若注入，bind() 拿到 send_time_ms 后会用它覆写 wecom_message_id
        # （原本恒等于 FTA 会话 ID `193405740`，非 per-message）。
        self._native_reader = native_reader
        self._native_wait_timeout_s = float(native_wait_timeout_s)
        self._native_tolerance_ms = int(native_tolerance_ms)

    # ── 内部辅助 ────────────────────────────────────────────────────────────

    def _probe_memory_triplet(
        self,
        send_time_ms: int = 0,
    ) -> tuple[int, int, int]:
        """尝试从进程内存取精确三元组，失败则返回 (0, 0, 0)。

        Returns:
            (sequence, send_time_ms, wecom_message_id)
        """
        if self._memory_reader is None:
            return 0, 0, 0
        try:
            if send_time_ms > 0:
                t = self._memory_reader.find_by_send_time(
                    send_time_ms, tolerance_ms=30_000
                )
            else:
                # 扫最近 5 分钟，取最新一条
                recent = self._memory_reader.scan_recent(minutes=5)
                t = recent[-1] if recent else None
            if t is None:
                return 0, 0, 0
            return t.sequence, t.send_time_ms, t.message_id
        except Exception:
            return 0, 0, 0

    # ── 公开接口 ─────────────────────────────────────────────────────────────

    def bind(
        self,
        material_code: str,
        fingerprint: str,
        *,
        echo_message_id: str,
        send_time_ms: int = 0,
        sequence: int = 0,
        wecom_message_id: int = 0,
    ) -> dict[str, Any]:
        """绑定气泡锚点，可选自动探测内存三元组。

        Args:
            material_code:    素材编码。
            fingerprint:      素材指纹字符串。
            echo_message_id:  FTA echo 消息 ID。
            send_time_ms:     已知的发送时间（毫秒，可来自内存扫描或估算）。
            sequence:         已知的序列号（若调用方已扫过内存则传入，避免重复扫描）。
            wecom_message_id: 已知的企微内部 message_id（同上）。

        决策逻辑：
          - 若 `sequence > 0`，视为调用方已完成内存扫描，直接使用传入值；
          - 否则尝试通过 `memory_reader.find_by_send_time(send_time_ms)` 扫描；
          - 若 `send_time_ms=0` 则扫最近 5 分钟内最新一条。
        """
        entry = self._library.lookup_material_code(material_code)
        if entry is None:
            raise KeyError(f"未找到素材编码: {material_code}")

        # 优先使用调用方传入的完整三元组（避免重复扫描）
        if sequence > 0 and send_time_ms > 0:
            seq, ts_ms, mid = sequence, send_time_ms, wecom_message_id
        else:
            # 否则内部扫描（若无 memory_reader 则返回 (0,0,0)）
            seq, ts_ms, mid = self._probe_memory_triplet(send_time_ms)
            # 如果扫描失败但调用方给了 send_time_ms，仍保留它
            if ts_ms == 0 and send_time_ms > 0:
                ts_ms = send_time_ms

        # v3：用 SQLite bind hook 拿到的真实 per-message msgid 覆盖
        # `wecom_message_id`（原本是 FTA 会话 ID `193405740`，无法定位单条）
        if self._native_reader is not None and ts_ms > 0:
            try:
                native = self._native_reader.wait_for_msgid(
                    send_time_ms=ts_ms,
                    tolerance_ms=self._native_tolerance_ms,
                    timeout=self._native_wait_timeout_s,
                )
                if native is not None and native.msgid > 0:
                    mid = native.msgid
            except Exception:
                # 读取失败不阻断主流程；保留 memory_reader 的原值
                pass

        rec = AnchorRecord(
            bubble_timestamp=datetime.now().isoformat(timespec="seconds"),
            echo_message_id=echo_message_id,
            fingerprint_snippet=fingerprint[:12],
            relative_position=-1,
            sequence=seq,
            send_time_ms=ts_ms,
            wecom_message_id=mid,
        )
        current = rec.to_dict()
        history: list[dict] = []
        if isinstance(entry.anchor, dict):
            old_his = entry.anchor.get("history")
            if isinstance(old_his, list):
                history = [x for x in old_his if isinstance(x, dict)]
            old_current = entry.anchor.get("current")
            if isinstance(old_current, dict):
                history.append(old_current)
        history.append(current)
        history = history[-20:]
        entry.anchor = {"current": current, "history": history}
        return entry.anchor

    def locate(self, material_code: str) -> dict[str, Any]:
        """查询素材锚点记录。"""
        entry = self._library.lookup_material_code(material_code)
        if entry is None:
            raise KeyError(f"未找到素材编码: {material_code}")
        if not entry.anchor:
            raise KeyError(f"素材缺少锚点: {material_code}")
        if isinstance(entry.anchor, dict) and isinstance(
            entry.anchor.get("current"), dict
        ):
            return entry.anchor["current"]
        return entry.anchor

"""
MessageSender 协议 + SenderRegistry (Stage 4.5.1 骨架)

设计要点:
    - 每个 Sender 实现类持有 supported_types (它能发的类型)
    - Direct 类 (DIRECT_SEND_TYPES): 假定 chat 已打开, targets=[当前联系人]
    - Forward 类 (FORWARD_TYPES):    自己打开文件传输助手, targets 可多人 (B 模式)
    - Dispatcher 依据 msg.type 选 sender, 依据类别决定"逐人 vs 多选"

具体 Sender 实现将在 Stage 4.5.2 ~ 4.5.8 逐个补齐。
本文件先给出接口 + 注册表 + 一个仅打印的 StubSender (便于 4.5.1 干跑)。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Protocol, runtime_checkable

from loguru import logger

from app.messaging.types import (
    DIRECT_SEND_TYPES,
    FORWARD_TYPES,
    Message,
    MessageType,
)


# ---------- 发送上下文 (跨 sender 共享的运行时依赖) ---------- #

@dataclass
class SendContext:
    """
    传给 Sender.send() 的运行时上下文。

    刻意用 dataclass 而非全局，方便测试 mock。

    字段:
      dev            — uiautomator2 Device
      nav            — WeComNavigator
      cfg            — AppConfig
      file_store     — AndroidFileStore    (media/file sender 用: adb push)
      asset_library  — AssetLibrary        (forward sender 用: tag → fta_locator)

    Stage 沿革:
      * 4.5.1 初始只有 dev/nav/cfg
      * 4.5.3 引入 asset_library 字段临时挂 AndroidFileStore (hack)
      * 4.5.5.4 拆分为 file_store + asset_library, 语义各归其位
    """
    dev: object | None = None                    # uiautomator2 Device
    nav: object | None = None                    # WeComNavigator
    cfg: object | None = None                    # AppConfig
    file_store: object | None = None             # AndroidFileStore
    asset_library: object | None = None          # AssetLibrary


# ---------- Sender 协议 ---------- #

@runtime_checkable
class MessageSender(Protocol):
    """
    单一类型 (或一小组同类) 的消息发送器。

    契约:
      - supported_types: 声明该 sender 能处理的 MessageType 集合
      - send(ctx, targets, message):
          * 对 DIRECT_SEND_TYPES: 调用方保证 targets=[current_contact] 且
            该联系人的聊天窗口已打开; Sender 只负责在当前 chat 里发出消息
          * 对 FORWARD_TYPES: targets 可为多人; Sender 自行处理
            "文件传输助手 → 长按 → 多选转发 → 确认发送" 全流程
      - 失败时抛异常 (BatchRunner 会捕获, 严格模式下终止)
    """

    supported_types: ClassVar[frozenset[MessageType]]

    def send(
        self,
        ctx: SendContext,
        targets: list[str],
        message: Message,
    ) -> None: ...


def is_forward_sender(sender: MessageSender) -> bool:
    """该 sender 是否走"转发类"路径 (支持一次多选发多人)"""
    return sender.supported_types.issubset(FORWARD_TYPES)


# ---------- 注册表 & 分发 ---------- #

class SenderRegistry:
    """
    维护 MessageType → Sender 的映射，并在缺失时给出清晰错误。
    """

    def __init__(self) -> None:
        self._by_type: dict[MessageType, MessageSender] = {}

    def register(self, sender: MessageSender) -> None:
        if not sender.supported_types:
            raise ValueError(f"{sender!r} 的 supported_types 为空")
        # 一个 sender 只能属于纯 direct 或纯 forward
        st = sender.supported_types
        if not (st.issubset(DIRECT_SEND_TYPES) or st.issubset(FORWARD_TYPES)):
            raise ValueError(
                f"{sender!r} 的 supported_types 跨类别 "
                f"(direct 与 forward 混用): {st}"
            )
        for t in sender.supported_types:
            if t in self._by_type:
                raise ValueError(
                    f"类型 {t.value} 已被 {self._by_type[t]!r} 占用"
                )
            self._by_type[t] = sender

    def get(self, t: MessageType) -> MessageSender:
        try:
            return self._by_type[t]
        except KeyError:
            raise KeyError(
                f"未注册 sender 处理 type={t.value}; "
                f"已注册: {sorted(k.value for k in self._by_type)}"
            )

    def missing_types(self) -> set[MessageType]:
        return set(MessageType) - set(self._by_type)

    def __contains__(self, t: MessageType) -> bool:
        return t in self._by_type


# ---------- Stub (占位, 只打印) ---------- #

class StubSender:
    """
    仅打印的 sender，用于 Stage 4.5.1 干跑打印一份 plan 时使用。
    真正的实现会在 4.5.2+ 逐个替换掉。
    """

    def __init__(
        self,
        supported: frozenset[MessageType],
        label: str = "stub",
    ) -> None:
        self.supported_types: frozenset[MessageType] = supported
        self.label = label

    def send(
        self,
        ctx: SendContext,
        targets: list[str],
        message: Message,
    ) -> None:
        mode = "forward-multi" if is_forward_sender(self) else "direct"
        logger.info(
            f"  [stub:{self.label}] {mode}  targets={targets}  "
            f"msg={message.brief()}"
        )


def build_stub_registry() -> SenderRegistry:
    """
    构造一份"所有类型都用 stub"的注册表。仅用于 4.5.1 干跑打印。
    每种类型给一个独立 stub, 保持 direct/forward 边界干净。
    """
    reg = SenderRegistry()
    for t in DIRECT_SEND_TYPES:
        reg.register(StubSender(frozenset({t}), label=t.value))
    for t in FORWARD_TYPES:
        reg.register(StubSender(frozenset({t}), label=t.value))
    return reg

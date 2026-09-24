"""
消息类型 & 单条消息模型。

Message 采用"扁平化 + 按 type 校验对应字段"的设计，好处：
    - JSON 序列化直观：{"type": "text", "text": "hi"}
    - GUI 编排时字段稳定，不用切换 payload 类
    - pydantic 校验 + IDE 自动补全都好用

字段-类型 对应关系:
    TEXT                  → text
    IMAGE / VIDEO / FILE  → path   (可选 caption)
    VOICE                 → path
    LOCATION / STICKER
    MINIPROGRAM
    CHANNEL_VIDEO         → tag    (来自 AssetLibrary)
    CONTACT_CARD          → friend_name
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator


class MessageType(str, Enum):
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    FILE = "file"
    VOICE = "voice"
    CONTACT_CARD = "contact_card"
    LOCATION = "location"
    STICKER = "sticker"
    MINIPROGRAM = "miniprogram"
    CHANNEL_VIDEO = "channel_video"


# ---------- 按"执行路径"分类 ---------- #

#: 直发类：程序进入每个客户聊天窗口，逐人发送
DIRECT_SEND_TYPES: frozenset[MessageType] = frozenset({
    MessageType.TEXT,
    MessageType.IMAGE,
    MessageType.VIDEO,
    MessageType.FILE,
    MessageType.VOICE,
    MessageType.CONTACT_CARD,
    MessageType.STICKER,       # 收藏表情面板，不能转发
})

#: 转发类：从"文件传输助手"源卡片转发，支持一次多选群发 (B 模式核心优化)
FORWARD_TYPES: frozenset[MessageType] = frozenset({
    MessageType.LOCATION,
    MessageType.MINIPROGRAM,
    MessageType.CHANNEL_VIDEO,
})

assert DIRECT_SEND_TYPES.isdisjoint(FORWARD_TYPES)
assert DIRECT_SEND_TYPES | FORWARD_TYPES == set(MessageType)


# ---------- Message 单条消息 ---------- #

class Message(BaseModel):
    """
    一条待发送的消息。type 决定使用哪个字段。

    JSON 示例：
        {"type": "text", "text": "周末愉快"}
        {"type": "image", "path": "C:/pics/promo.jpg", "caption": "新品"}
        {"type": "miniprogram", "tag": "mp_产品介绍"}
        {"type": "contact_card", "friend_name": "张三"}
    """

    type: MessageType

    # 按 type 使用的字段 (只有一个会被填充)
    text: str | None = None
    path: str | None = None            # 用 str 保持 JSON 干净; 转 Path 由发送端做
    tag: str | None = None
    friend_name: str | None = None

    #: 图片/视频/转发卡片的附言 (可选，独立文本消息更清晰，一般不用)
    caption: str | None = None

    # ---------- 校验：type 与字段必须匹配 ---------- #

    @field_validator("text", "path", "tag", "friend_name", "caption")
    @classmethod
    def _strip(cls, v):
        if isinstance(v, str):
            v = v.strip()
            return v or None
        return v

    @model_validator(mode="after")
    def _check_field_by_type(self) -> "Message":
        t = self.type
        # 需要的字段
        need_text = t == MessageType.TEXT
        need_path = t in {
            MessageType.IMAGE, MessageType.VIDEO,
            MessageType.FILE, MessageType.VOICE,
        }
        need_tag = t in {
            MessageType.LOCATION, MessageType.STICKER,
            MessageType.MINIPROGRAM, MessageType.CHANNEL_VIDEO,
        }
        need_friend = t == MessageType.CONTACT_CARD

        if need_text and not self.text:
            raise ValueError(f"type={t.value} 必须提供 text")
        if need_path and not self.path:
            raise ValueError(f"type={t.value} 必须提供 path")
        if need_tag and not self.tag:
            raise ValueError(f"type={t.value} 必须提供 tag")
        if need_friend and not self.friend_name:
            raise ValueError(f"type={t.value} 必须提供 friend_name")

        # caption 只有 image/video/转发类才有意义, 不做强制清空 (保留 GUI 灵活性)
        return self

    # ---------- 便捷构造 ---------- #

    @classmethod
    def text_msg(cls, text: str) -> "Message":
        return cls(type=MessageType.TEXT, text=text)

    @classmethod
    def image(cls, path: str | Path, caption: str | None = None) -> "Message":
        return cls(type=MessageType.IMAGE, path=str(path), caption=caption)

    @classmethod
    def video(cls, path: str | Path, caption: str | None = None) -> "Message":
        return cls(type=MessageType.VIDEO, path=str(path), caption=caption)

    @classmethod
    def file(cls, path: str | Path) -> "Message":
        return cls(type=MessageType.FILE, path=str(path))

    @classmethod
    def voice(cls, path: str | Path) -> "Message":
        return cls(type=MessageType.VOICE, path=str(path))

    @classmethod
    def contact_card(cls, friend_name: str) -> "Message":
        return cls(type=MessageType.CONTACT_CARD, friend_name=friend_name)

    @classmethod
    def location(cls, tag: str) -> "Message":
        return cls(type=MessageType.LOCATION, tag=tag)

    @classmethod
    def sticker(cls, tag: str) -> "Message":
        return cls(type=MessageType.STICKER, tag=tag)

    @classmethod
    def miniprogram(cls, tag: str) -> "Message":
        return cls(type=MessageType.MINIPROGRAM, tag=tag)

    @classmethod
    def channel_video(cls, tag: str) -> "Message":
        return cls(type=MessageType.CHANNEL_VIDEO, tag=tag)

    # ---------- 便于日志 ---------- #

    def brief(self) -> str:
        t = self.type.value
        if self.text:
            return f"{t}('{self.text[:20]}')"
        if self.path:
            return f"{t}({Path(self.path).name})"
        if self.tag:
            return f"{t}(#{self.tag})"
        if self.friend_name:
            return f"{t}(@{self.friend_name})"
        return t

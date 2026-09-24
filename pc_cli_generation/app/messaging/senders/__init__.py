"""
消息类型的具体 Sender 实现。

DEPRECATED: Android 端发送链路，已由 PC 企微 FTA 链路取代，仅保留兼容。

Stage 4.5.2 起逐个补齐。已实现:
    TextSender          — TEXT                                   (4.5.2)
    ImageSender / VideoSender — IMAGE / VIDEO                    (4.5.3)
    FileSender / VoiceSender  — FILE / VOICE                     (4.5.4)
    ForwardSender             — MINIPROGRAM/CHANNEL_VIDEO/LOCATION (4.5.5.3)
    ContactCardSender         — CONTACT_CARD                     (4.5.6)
    StickerSender             — STICKER                          (4.5.8)

全部 MessageType 现已覆盖.
"""

from app.messaging.senders.contact_card import ContactCardSender
from app.messaging.senders.file import FileSender
from app.messaging.senders.forward import ForwardSender
from app.messaging.senders.media import ImageSender, MediaSender, VideoSender
from app.messaging.senders.sticker import StickerSender
from app.messaging.senders.text import TextSender
from app.messaging.senders.voice import VoiceSender

__all__ = [
    "TextSender",
    "ImageSender",
    "VideoSender",
    "MediaSender",
    "FileSender",
    "VoiceSender",
    "ForwardSender",
    "ContactCardSender",
    "StickerSender",
]

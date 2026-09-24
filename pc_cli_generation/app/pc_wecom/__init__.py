"""PC 企业微信自动化层。"""

from app.pc_wecom.account_map import AccountMapService
from app.pc_wecom.bubble_anchor import BubbleAnchorService
from app.pc_wecom.contact_conv_resolver import ContactConvResolver, ConvMapping
from app.pc_wecom.contact_indexer import ContactHit, ContactIndexer
from app.pc_wecom.forward_executor import ForwardExecutor, ForwardResult, PreparedForward
from app.pc_wecom.fta_code_echo import FtaCodeEcho
from app.pc_wecom.locators import LocatorSet, default_locators
from app.pc_wecom.native_router import NativeRouter
from app.pc_wecom.pc_navigator import PCWeComNavigator
from app.pc_wecom.pipeline import wire_capture_echo
from app.pc_wecom.send_pipeline import SendPipeline, build_send_pipeline

__all__ = [
    "AccountMapService",
    "BubbleAnchorService",
    "ContactConvResolver",
    "ContactIndexer",
    "ContactHit",
    "ConvMapping",
    "ForwardExecutor",
    "ForwardResult",
    "FtaCodeEcho",
    "LocatorSet",
    "NativeRouter",
    "PreparedForward",
    "default_locators",
    "PCWeComNavigator",
    "SendPipeline",
    "build_send_pipeline",
    "wire_capture_echo",
]

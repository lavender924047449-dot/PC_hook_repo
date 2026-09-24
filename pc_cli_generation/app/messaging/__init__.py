"""
消息发送模型层 (Stage 4.5.1+)

对外暴露的核心类型：
    MessageType     — 消息种类枚举
    Message         — 单条消息 (含 type + 对应字段)
    BroadcastTask   — 一批客户 + 一份消息序列
    BatchPlan       — 一次 GUI 计划 (多个 BroadcastTask + 类型化间隔)
    load_plan/save_plan  — JSON 序列化
"""

from app.messaging.types import (
    MessageType,
    Message,
    DIRECT_SEND_TYPES,
    FORWARD_TYPES,
)
from app.messaging.plan import (
    BroadcastTask,
    BatchPlan,
    TypedIntervals,
    load_plan,
    save_plan,
)
from app.messaging.asset_library import (
    AssetEntry,
    AssetLibrary,
    FORWARD_ONLY_TYPES,
    LOCAL_SOURCE_TYPES,
    TAG_PREFIX,
)
from app.messaging.material_code_service import (
    MaterialCodeService,
    CODE_PREFIX,
)
from app.messaging.sender import (
    MessageSender,
    SendContext,
    SenderRegistry,
    StubSender,
    build_stub_registry,
    is_forward_sender,
)
from app.messaging.runner import (
    PlanRunner,
    PlanStep,
    StepKind,
    StepStatus,
    build_steps,
    plan_hash,
)

__all__ = [
    "MessageType",
    "Message",
    "DIRECT_SEND_TYPES",
    "FORWARD_TYPES",
    "BroadcastTask",
    "BatchPlan",
    "TypedIntervals",
    "load_plan",
    "save_plan",
    "MessageSender",
    "SendContext",
    "SenderRegistry",
    "StubSender",
    "build_stub_registry",
    "is_forward_sender",
    "AssetEntry",
    "AssetLibrary",
    "FORWARD_ONLY_TYPES",
    "LOCAL_SOURCE_TYPES",
    "TAG_PREFIX",
    "MaterialCodeService",
    "CODE_PREFIX",
    "PlanRunner",
    "PlanStep",
    "StepKind",
    "StepStatus",
    "build_steps",
    "plan_hash",
]

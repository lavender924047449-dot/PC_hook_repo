"""PC 企微发送管线装配器（产品化 ⑥）。

把已交付的部件接到真正可调用的发送入口：

* ``ForwardExecutor``（prepare + send_to_target）
* ``NativeRouter``（heap conv_id hijack）
* ``ContactConvResolver``（display_name → conv_id）
* ``QueueExecutor``（SendQueue 清单）

转发对消息类型无感：只要素材已有 ``material_code`` + 气泡锚点，
语音 / 图片 / 视频 / 文件 / 小程序卡片走同一条「长按 → 转发」路径，
客户收到的是企微原生形态。

Native 路径需要 ``decoy_target`` + 等长 ``decoy_conv_id``；缺任一或
Frida/进程不可用时自动回退 UIA 搜人，不阻断发送。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

from app.config import AppConfig, PCWeComConfig, resolve_path
from app.messaging.asset_library import AssetLibrary
from app.messaging.executor import QueueExecutor
from app.messaging.send_queue import SendQueue
from app.pc_wecom.bubble_anchor import BubbleAnchorService
from app.pc_wecom.contact_conv_resolver import ContactConvResolver
from app.pc_wecom.forward_executor import ForwardExecutor, ForwardResult
from app.pc_wecom.native_router import DEFAULT_VTABLE_OFFSET, NativeRouter
from app.pc_wecom.pc_navigator import PCWeComNavigator

logger = logging.getLogger(__name__)


def parse_vtable_offset(value: str | int | None) -> int:
    if value is None or value == "":
        return DEFAULT_VTABLE_OFFSET
    if isinstance(value, int):
        return value
    return int(str(value).strip(), 0)


def resolve_wxwork_pid(explicit: int | None = None) -> Optional[int]:
    if explicit and int(explicit) > 0:
        return int(explicit)
    try:
        from app.pc_wecom.wecom_memory_reader import find_wxwork_pid

        return find_wxwork_pid()
    except Exception:
        logger.debug("find_wxwork_pid failed", exc_info=True)
        return None


@dataclass
class SendPipeline:
    """一次发送会话用到的全部组件。"""

    navigator: PCWeComNavigator
    anchor: BubbleAnchorService
    forward: ForwardExecutor
    router: Any | None
    resolver: Any | None
    pid: int | None
    native_enabled: bool

    def close(self) -> None:
        for obj in (self.router, self.resolver):
            detach = getattr(obj, "detach", None)
            if callable(detach):
                try:
                    detach()
                except Exception:
                    logger.debug("detach raised", exc_info=True)

    def __enter__(self) -> "SendPipeline":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def send(
        self,
        material_code: str,
        target: str,
        *,
        conv_id: str | None = None,
        retries: int = 2,
    ) -> ForwardResult:
        dest = conv_id
        if dest is None and self.resolver is not None:
            resolve = getattr(self.resolver, "resolve", None)
            if callable(resolve):
                hit = resolve(target)
                dest = str(hit).strip() if hit else None
        return self.forward.forward(
            material_code, target, conv_id=dest, retries=retries,
        )

    def make_queue_executor(
        self,
        queue: SendQueue,
        *,
        history_path: str | None = None,
        scheduler: Any = None,
        ignore_schedule: bool = False,
    ) -> QueueExecutor:
        return QueueExecutor(
            queue,
            self.forward,
            history_path=history_path or "runtime/send_history.json",
            scheduler=scheduler,
            ignore_schedule=ignore_schedule,
            conv_resolver=self.resolver,
        )


def build_send_pipeline(
    library: AssetLibrary,
    *,
    cfg: PCWeComConfig | None = None,
    app_config: AppConfig | None = None,
    navigator: PCWeComNavigator | None = None,
    anchor: BubbleAnchorService | None = None,
    pid: int | None = None,
    enable_native: bool | None = None,
    frida_module: Any = None,
    native_router: Any = None,
    conv_resolver: Any = None,
    find_pid: Callable[[], Optional[int]] | None = None,
) -> SendPipeline:
    """装配发送栈。测试可注入 navigator / fake router / fake resolver。"""
    pc_cfg = cfg
    if pc_cfg is None:
        if app_config is not None:
            pc_cfg = app_config.pc_wecom
        else:
            pc_cfg = PCWeComConfig()

    nav = navigator or PCWeComNavigator()
    anchor_svc = anchor or BubbleAnchorService(library)

    want_native = pc_cfg.native_hijack if enable_native is None else bool(enable_native)
    resolved_pid = pid
    if want_native and resolved_pid is None:
        finder = find_pid or (lambda: resolve_wxwork_pid())
        resolved_pid = finder()

    router = native_router
    resolver = conv_resolver

    if want_native and router is None and resolved_pid:
        try:
            router = NativeRouter(
                int(resolved_pid),
                vtable_offset=parse_vtable_offset(pc_cfg.vtable_offset),
                frida_module=frida_module,
            )
            router.attach()
            logger.info("NativeRouter attached pid=%s base=%s", resolved_pid, router.agent_base)
        except Exception as e:  # noqa: BLE001
            logger.warning("NativeRouter 不可用，回退 UIA：%s", e)
            router = None

    if want_native and resolver is None and native_router is None:
        cache = resolve_path(pc_cfg.conv_map_file)
        try:
            resolver = ContactConvResolver(
                pid=int(resolved_pid or 0),
                frida_module=frida_module,
                cache_path=cache,
            )
            if resolved_pid and router is not None:
                try:
                    resolver.attach()
                except Exception as e:  # noqa: BLE001
                    logger.warning("ContactConvResolver attach 失败，仅使用本地 cache：%s", e)
        except Exception as e:  # noqa: BLE001
            logger.warning("ContactConvResolver 不可用：%s", e)
            resolver = None

    native_ok = router is not None
    decoy_target = pc_cfg.decoy_target.strip() or None
    decoy_conv_id = pc_cfg.decoy_conv_id.strip() or None
    if native_ok and not (decoy_target and decoy_conv_id):
        logger.info(
            "native hijack 已 attach，但未配置 decoy_target/decoy_conv_id；"
            "若 target 的 conv_id 能解析且与目的相同，将走 UIA 选人"
        )

    forward = ForwardExecutor(
        nav,
        anchor_svc,
        native_router=router,
        conv_resolver=resolver,
        decoy_target=decoy_target,
        decoy_conv_id=decoy_conv_id,
    )
    return SendPipeline(
        navigator=nav,
        anchor=anchor_svc,
        forward=forward,
        router=router,
        resolver=resolver,
        pid=resolved_pid,
        native_enabled=native_ok,
    )


__all__ = [
    "SendPipeline",
    "build_send_pipeline",
    "parse_vtable_offset",
    "resolve_wxwork_pid",
]

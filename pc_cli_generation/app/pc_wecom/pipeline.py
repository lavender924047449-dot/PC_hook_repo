"""PC FTA 主链路装配器：监听捕捉事件并触发编码回写。"""

from __future__ import annotations

from app.messaging.cache_scanner import WeComCacheScanner
from app.pc_wecom.fta_code_echo import FtaCodeEcho


def wire_capture_echo(scanner: WeComCacheScanner, echo: FtaCodeEcho) -> None:
    scanner.subscribe(echo.on_material_captured)

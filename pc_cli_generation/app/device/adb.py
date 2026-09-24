"""
ADB / uiautomator2 会话管理。

DEPRECATED: Android 链路已由 PC 企微 FTA 主链路取代，仅保留兼容。

用法：
    from app.device.adb import AdbSession
    with AdbSession(port=16384) as sess:
        sess.dev.dump_hierarchy()       # 直接用 u2.Device
        sess.adb.shell("input keyevent 4")
"""

from __future__ import annotations

from types import TracebackType
from typing import Self

import adbutils
import uiautomator2 as u2
from loguru import logger


class AdbConnectError(RuntimeError):
    pass


class AdbSession:
    """
    连接 MuMu / 真机 的 adb + uiautomator2 会话。

    - port: MuMu Pro 12 默认 16384
    - 复用已有 device_list，若空则 try connect 127.0.0.1:{port}
    """

    def __init__(
        self,
        port: int = 16384,
        connect_timeout: float = 5.0,
        host: str = "127.0.0.1",
    ) -> None:
        self.port = port
        self.host = host
        self.timeout = connect_timeout
        self._serial: str | None = None
        self._adb_dev: adbutils.AdbDevice | None = None
        self._u2_dev: u2.Device | None = None

    # ---- 上下文管理 ---- #
    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        # 不 disconnect：留给下次复用，MuMu 一般常驻
        pass

    # ---- 属性 ---- #
    @property
    def serial(self) -> str:
        if not self._serial:
            raise AdbConnectError("尚未连接，先调用 connect()")
        return self._serial

    @property
    def adb(self) -> adbutils.AdbDevice:
        if not self._adb_dev:
            raise AdbConnectError("adb 设备未初始化")
        return self._adb_dev

    @property
    def dev(self) -> u2.Device:
        if not self._u2_dev:
            raise AdbConnectError("uiautomator2 未初始化")
        return self._u2_dev

    # ---- 连接 ---- #
    def connect(self) -> None:
        adb = adbutils.adb
        devs = adb.device_list()
        if not devs:
            addr = f"{self.host}:{self.port}"
            logger.info(f"adb connect {addr} ...")
            try:
                r = adb.connect(addr, timeout=self.timeout)
                logger.debug(f"connect result: {r}")
            except Exception as e:
                raise AdbConnectError(f"adb connect 失败: {e}") from e
            devs = adb.device_list()
        if not devs:
            raise AdbConnectError(
                f"未发现任何设备。请检查：\n"
                f"  1) MuMu 是否已启动并进入 Android 桌面\n"
                f"  2) MuMu adb 端口是否为 {self.port}\n"
                f"  3) MuMu 设置里是否已开启 adb 调试"
            )
        ad = devs[0]
        self._serial = ad.serial
        self._adb_dev = ad
        self._u2_dev = u2.connect(ad.serial)
        info = self._u2_dev.info
        logger.info(
            f"已连接: {ad.serial}   "
            f"分辨率 {info.get('displayWidth')}x{info.get('displayHeight')}"
        )

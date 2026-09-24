"""
精确手势控制 — "按下 → 中间行为 (blocking) → 松开"

核心 API: press_hold_and_run

设计要点：
    - 用 try/finally 保证异常时也一定松开手指，避免企微一直录音
    - action 是一个 blocking 可调用，通常是 sd.play(..., blocking=True)
    - pre_roll: 按下后先等一段再执行 action (给企微开始录音的时间)
    - post_roll: action 完成后再等一段才松开 (防末尾截断)
"""

from __future__ import annotations

import time
from collections.abc import Callable

import uiautomator2 as u2
from loguru import logger


def press_hold_and_run(
    dev: u2.Device,
    x: int,
    y: int,
    action: Callable[[], None],
    *,
    pre_roll_ms: int = 150,
    post_roll_ms: int = 300,
) -> float:
    """
    按下坐标 (x, y) → 等 pre_roll → 执行 action → 等 post_roll → 松开。

    返回：实际持续时长 (秒)

    action 应该是 blocking 的 (例如 sounddevice.play(..., blocking=True))。
    如果 action 抛异常，也会先松开再传播。
    """
    logger.debug(
        f"press_hold_and_run @({x}, {y})  pre={pre_roll_ms}ms  post={post_roll_ms}ms"
    )
    t0 = time.perf_counter()
    dev.touch.down(x, y)
    try:
        if pre_roll_ms > 0:
            time.sleep(pre_roll_ms / 1000)
        action()
        if post_roll_ms > 0:
            time.sleep(post_roll_ms / 1000)
    finally:
        try:
            dev.touch.up(x, y)
        except Exception as e:
            logger.error(f"touch.up 失败: {e}")
    elapsed = time.perf_counter() - t0
    logger.debug(f"press_hold_and_run 完成，耗时 {elapsed:.3f}s")
    return elapsed


def tap(dev: u2.Device, x: int, y: int) -> None:
    """简单点击 (down + up 无间隔) — 用于点图标"""
    dev.click(x, y)


def press_back(dev: u2.Device, times: int = 1, interval_s: float = 0.3) -> None:
    for _ in range(times):
        dev.press("back")
        time.sleep(interval_s)

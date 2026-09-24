"""
环境检测脚本 (独立小工具，非项目正式代码)

用途：检测当前 Windows 环境是否满足 "企业微信语音批量发送工具" 的运行/开发前置条件。
用法：
    python check_env.py

只做检测，不做任何修改，可以安全反复运行。
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import sys
import winreg
from pathlib import Path


# --------------------------- 输出辅助 --------------------------- #

class C:
    OK = "\033[92m"
    WARN = "\033[93m"
    ERR = "\033[91m"
    DIM = "\033[90m"
    B = "\033[1m"
    END = "\033[0m"


def _enable_win_ansi() -> None:
    """启用 Windows 终端 ANSI 颜色支持"""
    try:
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        pass


def line(status: str, name: str, detail: str = "") -> None:
    icon = {"ok": f"{C.OK}[✓]{C.END}", "warn": f"{C.WARN}[!]{C.END}",
            "err": f"{C.ERR}[✗]{C.END}", "info": f"{C.DIM}[·]{C.END}"}[status]
    print(f"  {icon} {name:<32} {C.DIM}{detail}{C.END}")


def section(title: str) -> None:
    print(f"\n{C.B}== {title} =={C.END}")


# --------------------------- 检测项 --------------------------- #

results: list[tuple[str, str, str]] = []  # (status, name, detail)


def record(status: str, name: str, detail: str = "") -> None:
    results.append((status, name, detail))
    line(status, name, detail)


def check_os() -> None:
    section("操作系统")
    if platform.system() != "Windows":
        record("err", "操作系统", f"当前 {platform.system()}, 仅支持 Windows")
        return
    ver = platform.version()
    rel = platform.release()
    record("ok", "Windows", f"{rel} (build {ver})")

    # 64 位检测
    is_64 = platform.machine().endswith("64")
    record("ok" if is_64 else "warn", "系统架构",
           platform.machine() + ("" if is_64 else " (建议 64 位)"))


def check_python() -> None:
    section("Python")
    v = sys.version_info
    if v.major == 3 and v.minor >= 10:
        record("ok", "Python 版本", f"{sys.version.split()[0]}  ({sys.executable})")
    else:
        record("err", "Python 版本",
               f"{sys.version.split()[0]} (需要 ≥ 3.10)")

    # pip
    try:
        r = subprocess.run([sys.executable, "-m", "pip", "--version"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            record("ok", "pip", r.stdout.strip())
        else:
            record("err", "pip", "不可用")
    except Exception as e:
        record("err", "pip", f"检测失败: {e}")


def check_ffmpeg() -> None:
    section("FFmpeg")
    path = shutil.which("ffmpeg")
    if not path:
        record("warn", "ffmpeg (PATH)",
               "未在 PATH 中找到 (可选：正式项目会内置 ffmpeg.exe)")
        return
    try:
        r = subprocess.run([path, "-version"],
                           capture_output=True, text=True, timeout=10)
        first = r.stdout.splitlines()[0] if r.stdout else ""
        record("ok", "ffmpeg (PATH)", f"{path}\n      {first}")
    except Exception as e:
        record("warn", "ffmpeg (PATH)", f"存在但调用失败: {e}")


def _list_audio_devices() -> tuple[list[str], list[str]]:
    """
    返回 (输入设备名列表, 输出设备名列表)。
    优先用 sounddevice，其次尝试 PowerShell。
    """
    try:
        import sounddevice as sd  # type: ignore
        devs = sd.query_devices()
        inputs = [d["name"] for d in devs if d["max_input_channels"] > 0]
        outputs = [d["name"] for d in devs if d["max_output_channels"] > 0]
        return inputs, outputs
    except Exception:
        pass

    # 回退: PowerShell 枚举 (只能拿到启用的设备)
    try:
        ps = (
            "Get-CimInstance Win32_PnPEntity | "
            "Where-Object {$_.PNPClass -eq 'AudioEndpoint' -or "
            "$_.PNPClass -eq 'MEDIA'} | "
            "Select-Object -ExpandProperty Name"
        )
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=15)
        names = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        return names, names  # 无法区分输入输出
    except Exception:
        return [], []


def check_vbcable() -> None:
    section("VB-CABLE 虚拟声卡")
    inputs, outputs = _list_audio_devices()

    if not inputs and not outputs:
        record("warn", "音频设备枚举", "无法枚举 (sounddevice 未安装且 PowerShell 回退失败)")
        record("info", "提示", "安装 sounddevice 后重跑: pip install sounddevice")
        return

    # 找 CABLE Input (播放端) 和 CABLE Output (录音端)
    cable_in = [n for n in outputs if "CABLE Input" in n]
    cable_out = [n for n in inputs if "CABLE Output" in n]

    if cable_in:
        record("ok", "CABLE Input (播放到虚拟麦克风)", cable_in[0])
    else:
        record("err", "CABLE Input", "未检测到 → 需要安装 VB-CABLE")

    if cable_out:
        record("ok", "CABLE Output (虚拟麦克风)", cable_out[0])
    else:
        record("err", "CABLE Output", "未检测到 → 需要安装 VB-CABLE")

    if not cable_in and not cable_out:
        record("info", "下载地址", "https://vb-audio.com/Cable/  (装完需重启)")


def check_default_mic() -> None:
    section("默认音频输入设备")
    try:
        import sounddevice as sd  # type: ignore
        default_in = sd.default.device[0]
        devs = sd.query_devices()
        name = devs[default_in]["name"] if 0 <= default_in < len(devs) else "?"
        record("ok", "当前默认麦克风", name)
        if "CABLE Output" in name:
            record("info", "状态", "已指向 VB-CABLE，可以直接发送")
        else:
            record("info", "状态",
                   "非 VB-CABLE (正常，程序会在发送时自动切换并还原)")
    except Exception as e:
        record("warn", "默认麦克风", f"检测失败: {e}")


def _read_reg_wecom() -> tuple[str, str] | None:
    """
    在注册表卸载信息中查找企业微信，返回 (安装路径, 版本号) 或 None。
    """
    hives = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for root, sub in hives:
        try:
            with winreg.OpenKey(root, sub) as k:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(k, i)
                        i += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(k, name) as sk:
                            disp, _ = winreg.QueryValueEx(sk, "DisplayName")
                            if "企业微信" in disp or "WXWork" in disp or "WeCom" in disp:
                                try:
                                    ver, _ = winreg.QueryValueEx(sk, "DisplayVersion")
                                except FileNotFoundError:
                                    ver = "?"
                                try:
                                    loc, _ = winreg.QueryValueEx(sk, "InstallLocation")
                                except FileNotFoundError:
                                    loc = "?"
                                return loc, ver
                    except (FileNotFoundError, OSError):
                        continue
        except FileNotFoundError:
            continue
    return None


def _find_wecom_exe() -> Path | None:
    """兜底：扫描常见安装位置"""
    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WXWork" / "WXWork.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "WXWork" / "WXWork.exe",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def check_wecom() -> None:
    section("企业微信 PC 版")
    reg = _read_reg_wecom()
    if reg:
        loc, ver = reg
        record("ok", "企业微信", f"版本 {ver}  路径: {loc}")
        # 版本建议
        if ver.startswith("4.1."):
            record("info", "版本建议", "4.1.x 主线，UI 相对稳定 ✅")
        elif ver.startswith("4.0."):
            record("info", "版本建议", "4.0.x 偏旧，建议升级到 4.1.x")
        elif ver.startswith("4.2.") or ver.startswith("5."):
            record("warn", "版本建议",
                   "较新版本，UI 可能与标定基准不一致，需要测试")
        return

    exe = _find_wecom_exe()
    if exe:
        record("warn", "企业微信", f"找到 exe 但未在注册表: {exe}")
        return

    record("err", "企业微信", "未检测到 → 需要安装")
    record("info", "下载地址", "https://work.weixin.qq.com/#indexDownload")


def check_optional_packages() -> None:
    section("Python 依赖包 (当前已安装的相关包)")
    pkgs = [
        "sounddevice", "soundfile", "numpy", "pywinauto",
        "pycaw", "pynput", "pywin32", "PySide6",
        "loguru", "pydantic", "PyYAML", "mss", "pandas", "psutil",
    ]
    for name in pkgs:
        try:
            mod_name = {"pywin32": "win32api", "PyYAML": "yaml",
                        "PySide6": "PySide6"}.get(name, name.lower())
            __import__(mod_name)
            try:
                import importlib.metadata as im
                v = im.version(name)
            except Exception:
                v = "installed"
            record("ok", name, v)
        except ImportError:
            record("info", name, "未安装 (Spike / 正式开发时再装)")


# --------------------------- 汇总 --------------------------- #

def summarize() -> int:
    section("汇总")
    total = len(results)
    ok = sum(1 for s, *_ in results if s == "ok")
    warn = sum(1 for s, *_ in results if s == "warn")
    err = sum(1 for s, *_ in results if s == "err")
    print(f"  通过: {C.OK}{ok}{C.END}  "
          f"警告: {C.WARN}{warn}{C.END}  "
          f"缺失: {C.ERR}{err}{C.END}  "
          f"总计: {total}")

    if err == 0 and warn == 0:
        print(f"\n{C.OK}{C.B}✔ 环境完备，可直接进入 Spike 1{C.END}")
    elif err == 0:
        print(f"\n{C.WARN}{C.B}◐ 主体可用，警告项建议处理后再进入 Spike{C.END}")
    else:
        print(f"\n{C.ERR}{C.B}✘ 有缺失项，请先安装缺失组件{C.END}")

    # 打印待办
    todos = [name for s, name, _ in results if s in ("err",)]
    if todos:
        print(f"\n{C.B}待办：{C.END}")
        for t in todos:
            print(f"  - 修复: {t}")

    return err


def main() -> int:
    _enable_win_ansi()
    print(f"{C.B}企业微信语音发送工具 - 环境自检{C.END}")
    print(f"{C.DIM}检测时间: {platform.node()}  Python {sys.version.split()[0]}{C.END}")

    check_os()
    check_python()
    check_ffmpeg()
    check_optional_packages()   # 放前面：sounddevice 若已装，下面才能列音频设备
    check_vbcable()
    check_default_mic()
    check_wecom()
    return summarize()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)

"""
坐标诊断脚本（无需交互）：
  1. 显示企微窗口位置和估算气泡坐标
  2. 把鼠标移到各候选点并短暂停留，方便肉眼确认位置是否正确
  3. 不产生任何点击，纯诊断

用法（企微主窗口已打开 FTA 聊天）：
  python spikes/spike_coord_diagnose.py

看到鼠标在屏幕上停留时，确认它是否落在消息气泡上。
"""
from __future__ import annotations
import ctypes, ctypes.wintypes, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

class RECT(ctypes.Structure):
    _fields_ = [
        ('left', ctypes.c_long), ('top', ctypes.c_long),
        ('right', ctypes.c_long), ('bottom', ctypes.c_long),
    ]

user32  = ctypes.windll.user32
win32api_available = False
try:
    import win32api, win32con
    win32api_available = True
except ImportError:
    pass

def move_to(x: int, y: int) -> None:
    if win32api_available:
        win32api.SetCursorPos((x, y))
    else:
        ctypes.windll.user32.SetCursorPos(x, y)

# ── 找窗口 ────────────────────────────────────────────────────────────────────
hwnd = user32.FindWindowW('WeWorkWindow', None)
if not hwnd:
    print("[FAIL] WeWorkWindow NOT FOUND -- 请先打开企业微信主窗口")
    sys.exit(1)

# 恢复最小化
SW_RESTORE = 9
user32.ShowWindow(hwnd, SW_RESTORE)
time.sleep(0.4)

r = RECT()
user32.GetWindowRect(hwnd, ctypes.byref(r))
W = r.right  - r.left
H = r.bottom - r.top

print(f"[OK] WeWorkWindow  HWND={hwnd}")
print(f"    位置: ({r.left},{r.top}) → ({r.right},{r.bottom})")
print(f"    尺寸: {W} × {H} px")
print()

from app.pc_wecom.locators import LocatorSet
loc = LocatorSet()  # 使用默认值（与 spike_forward_flow_validate.py 相同）
loc_custom = LocatorSet(material_bubble_offset=120)

chat_left  = r.left + int(W * loc_custom.chat_left_ratio)
chat_right = r.right - 4
bx = chat_left + int((chat_right - chat_left) * loc_custom.bubble_click_x_ratio)

print(f"    chat_left={chat_left}  chat_right={chat_right}  bubble_x={bx}")
print(f"    input_top={r.bottom - loc_custom.input_area_height}")
print()

candidates = [
    ("offset=80 (最低)",  r.bottom - loc_custom.input_area_height - loc_custom.echo_bubble_height - 80),
    ("offset=100",         r.bottom - loc_custom.input_area_height - loc_custom.echo_bubble_height - 100),
    ("offset=120 (默认)", r.bottom - loc_custom.input_area_height - loc_custom.echo_bubble_height - 120),
    ("offset=150",         r.bottom - loc_custom.input_area_height - loc_custom.echo_bubble_height - 150),
    ("offset=180",         r.bottom - loc_custom.input_area_height - loc_custom.echo_bubble_height - 180),
    ("offset=220 (最高)", r.bottom - loc_custom.input_area_height - loc_custom.echo_bubble_height - 220),
]

print("── 鼠标将依次移到候选点（每点停留 1.5s，请观察位置）──")
print("   目标：鼠标落在素材气泡（图片/文件）内，而非空白或时间标签")
print()

for label, cy in candidates:
    # 安全夹紧
    cy_safe = max(r.top + 60, min(cy, r.bottom - loc_custom.input_area_height - 10))
    print(f"  {label}  → ({bx}, {cy_safe})")
    move_to(bx, cy_safe)
    time.sleep(1.5)

print()
print("── 诊断完成 ──")
print("请记住哪个 offset 让鼠标落在素材气泡上，")
print("然后在 spikes/spike_forward_flow_validate.py 的 LOCATORS 里设置 material_bubble_offset=<该值>")

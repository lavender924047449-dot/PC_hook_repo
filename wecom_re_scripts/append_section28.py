# append_section28.py - 以 UTF-8 写入第28节
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

doc_path = r'd:\Only internship outputs\Test-Voice\docs\REVERSE_ENGINEERING_HANDOFF.md'

# 读原文，找截断点（## 28. 之前）
with open(doc_path, encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

cut = len(lines)
for i, l in enumerate(lines):
    if l.startswith('## 28.'):
        cut = i
        break

print(f'保留前 {cut} 行，截断并追加第 28 节')

section28 = '''
---

## 28. 第十轮详细发现（2026-09-11 傍晚）

> **核心发现：WXWork 在 2026-08-15 静默升级，新版 ForwardMessage 的 CGI 路径已完全重构，旧版所有 compact/RVA 失效。**

### 28.1 新旧版本对比

| 项目 | 旧版（第九轮，PID≈17020）| 新版（第十轮，PID=32736）|
|------|--------------------------|--------------------------|
| 二进制大小 | ~271 MB | **256 MB（2026-08-15 更新）** |
| 主进程基址 | 0x2D0000（稳定）| 0x2D0000（稳定）|
| ForwardMessage compact | **01004179** | **不存在**（内存/文件均无）|
| CGI 背景 baseline | 01000000、01004179 附近 | **01000000、0184f125、01650000** |
| CGI_A(0x390B39) 转发触发 | ✅ 会触发 | ❌ 用户多次转发均无触发 |
| CGI_B(0x430B39) 转发触发 | 未测 | ❌ 同上 |
| 转发代码路径 | CGI_ITER 可见 | **完全未知（已重构）** |

### 28.2 多次捕获实验结果汇总

本轮共运行 6 次捕获脚本，用户配合执行了多次真实转发（FTA→FTA，图片）：

| 脚本 | 结果 |
|------|------|
| `verify_fwd_compact.py` | 监听 01414f32+01004179，用户 5:42PM 转发，**0 命中** |
| `all_compact_diff.py` | Phase2 窗口 15s，**0 次 CGI 调用**（recv 一次性消费 bug） |
| `ts_diff.py` × 2 | Phase2 窗口 20s，仅见背景 0184f125，**0 新 compact** |
| `find_fwd_compact.py` | 长时间监听，仅见 01000000/01650000/0184f125 |
| `snap_on_go.py` | GO 后出现 01ed4135(TLS 证书)和 01414f32；但未确认与转发关联 |

**结论：新版 WXWork 转发操作完全绕开了 RVA 0x390B39 和 0x430B39。**

### 28.3 字符串与 proto 分析

#### forward_msg 三处字符串均为 log 格式串（非 proto 描述符）

| VA | 内容 | 性质 |
|----|------|------|
| 0xae89cd4 | `forward_msg` | 原始字符串（rdata） |
| 0xb2a3d0c | `forward_msgids_num: unable_emotion_` | **LOG 格式串**（调试打印） |
| 0xb2f5cc2 | `forward_msg_preview\\forward_message_prev` | **LOG 格式串** |

这 3 处均不是 proto 描述符字段名，不能用于 xref 追踪 proto handler。

#### ForwardMessageReq 字符串情况

| 项 | 值 |
|----|----|
| VA（运行时） | 0x0AD725E1 |
| RVA | 0xaaa25e1 |
| text 段 xref | **0 处** |
| rdata 段 xref | **0 处** |
| 原因 | WXWork 使用 **protobuf-lite**（无运行时反射），字符串仅为编译器保留的 debug 信息，代码不直接引用 |

#### WSASend 明文数据（plaintext_20260911_134541.json）

`a2` 字段包含 TLS 会话 UUID（如 `701a9d67-f70c-47ae-8f1c-8b75d188d736`），而非应用层 proto 字节。WSASend 层已是 mmtls 密文，无法直接获取 proto。

### 28.4 技术结论

| # | 结论 | 置信度 |
|---|------|--------|
| 1 | WXWork 2026-08-15 更新，compact 01004179 消失 | ✅ 确认 |
| 2 | 新版转发不经过 RVA 0x390B39 或 0x430B39 | ✅ 确认（4次实验）|
| 3 | WXWork 使用 proto-lite，无运行时字符串反射，xref 追踪无效 | ✅ 确认 |
| 4 | forward_msg 字符串是 log format string，非 proto 描述符 | ✅ 确认 |
| 5 | WSASend 层为 mmtls 密文，不含明文 proto | ✅ 确认 |
| 6 | 新版 ForwardMessage 可能走异步队列/新线程池/不同 CGI 注册点 | ⚠️ 假设 |

### 28.5 当前有效环境（2026-09-11）

```
PID        = 32736（:9882 LISTENING 进程）
wxBase     = 0x2D0000
CGI_A      = 0x390B39（background 0184f125 每 ~8s 触发）
CGI_B      = 0x430B39（未观测到任何事件）
baseline   = {01000000, 0184f125, 01650000}
WXWork     = D:\\Cursor_env\\企业微信\\WXWork\\WXWork.exe（256MB，2026-08-15）
Frida      = 17.17.0 / Python 3.11
```

### 28.6 下一步推荐路线（优先级排序）

#### 🥇 路线 X（最高优先）— Frida Stalker 追踪转发时刻新代码路径

```python
# 目标：用 Stalker 追踪用户触发转发时调用的函数集合，与基线 diff
# 输出：转发专属函数列表 → 找新的 CGI 注册/dispatch 点
# 注意：Stalker 轻量模式（仅 CALL 指令）避免崩溃
# 脚本模板：runtime/wecom_re/stalker_fwd_diff.py（待实现）
```

关键参数：
- `include_range = ('WXWork.exe', 'WXWork.exe')` 仅追踪模块内
- `event_type = 'call'` 仅追踪 CALL 指令（轻量）
- 用户转发 vs 基线 CALL 差集 = 转发专属函数

#### 🥈 路线 Y — WXWork 启动期 CGI 注册表枚举

WXWork 启动时通过类似 `RegisterCGIHandler(compact, handler)` 建立路由表：
1. 在进程启动后立即 hook 所有对「注册函数」的调用
2. 记录所有 `(compact, handler_addr)` 对
3. 在 `forward_msg` 相关的字符串附近找对应 compact
4. 这个 compact 就是新版 ForwardMessage 的 compact

找注册函数的方法：在旧版二进制中 01004179 的引用处回溯，找到 RegisterCGIHandler 的地址；用 xref 工具扫描 .text 中对该地址的调用。

#### 🥉 路线 Z — Wireshark 网络抓包 + mmtls 密钥提取

1. 安装 Npcap，Wireshark 抓取 `183.57.48.*` 等企微服务器 IP 的 TCP 流
2. 转发时刻观察新 TCP 连接或 TLS record 长度突增
3. 从 WXWork 内存中搜索 mmtls 会话密钥（mmtls 握手协议可能在内存留有密钥材料）
4. 用密钥解密 mmtls 记录，还原 protobuf 明文

### 28.7 本轮产出脚本

| 文件 | 用途 | 状态 |
|------|------|------|
| `verify_fwd_compact.py` | 监听特定 compact 等待触发 | 可复用 |
| `all_compact_diff.py` | 双 CGI hook + Phase 差分 | 已修复 recv bug |
| `ts_diff.py` | 时间戳差分捕获（推荐复用）| 可直接用 |
| `read_proto_desc.py` | proto 描述符分析 | 结论已明确 |
| `inspect_plaintext.py` | WSASend plaintext 分析 | 结论已明确 |
| `ts_diff_20260911_17*.json` | 两次 diff 原始数据 | 存档 |

### 28.8 一句话给下一 Agent

> **WXWork 2026-08-15 升级后，ForwardMessage compact(01004179) 消失，新版转发完全绕开 CGI_ITER RVA 0x390B39/0x430B39；下一步优先用 Frida Stalker（CALL 事件轻量模式）追踪用户转发时刻的新代码路径，得到转发专属函数列表后再定位新 compact 和 proto 结构。**
'''

# 写回文件（保留前 cut 行 + 新第 28 节）
with open(doc_path, 'w', encoding='utf-8') as f:
    f.writelines(lines[:cut])
    f.write(section28)

print(f'完成，文件行数: {len(lines[:cut]) + len(section28.splitlines())}')

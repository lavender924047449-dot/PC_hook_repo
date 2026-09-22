path = r'd:\Only internship outputs\Test-Voice\docs\REVERSE_ENGINEERING_HANDOFF.md'
section = """
### 28.9 第十轮续 — metadata 深度解析（2026-09-11 18:46）

#### 新发现：CGI 路由从 binary compact 改为 ASCII tag4

metadata 块（task[+52]）在 magic `d0070002` 之后 offset +24 处有 **4 字符 ASCII 路由标签**：

| tag4 | subcount | 场景 |
|------|----------|------|
| `417+` | 1 | 转发 UI 触发（含 icon/glyph/plus）|
| `W1pd` | 3 | 转发后 task |
| `WbWC` | 4 | 转发后 task（最可疑）|
| `ZSBQ` | 3 | 背景/其他 |

**结论：新版不再使用 `01004179` 这类 4 字节 binary compact，改用 ASCII tag4 标识 CGI 路由。**

#### payload 描述符（0x24bb1bf4，WbWC task 内多次引用）

- header magic: `0x0b79434c`（bytes: 4c43790b）
- offset +92: uint32 `346833984`（0x14ac4440，疑似 conv/session id）
- 尚未确认 msg_ids 字段位置

#### 下一 Agent 建议（精准 1 步）

静态搜索 `WbWC` / `417+` 字符串 xref，或从 0x390CE0 回溯 caller，定位 tag4→handler 映射后尝试 Frida 直调。
"""
with open(path, 'a', encoding='utf-8') as f:
    f.write(section)
print('done')

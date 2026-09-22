# Android 端企微逆向 — 语音自动化 Handoff

> **本文档定位**：给下一个 Agent 的**全局入口**。读完 §0–§2 即可建立完整项目意识；**§5 为动态观测结论**；**§15 为架构决策（最优先读）**；**§14 为实施进展与阻塞项**；§9 为旧的下一 agent 行动清单（部分已过期，看 §14–§15 覆盖表）。
>
> **PC 端完整逆向史**见 [`REVERSE_ENGINEERING_HANDOFF.md`](REVERSE_ENGINEERING_HANDOFF.md)（6200+ 行，尤其 §47.14–§47.16.25）。**PC 不参与 Phase A 发送**（见 §15.2）。
> **实施计划 v2.0**：Overall Progress **35%**；Step 1–3 已完成（voice/text ✅，image 阻塞）；**下一步 = Step 3.5 图片 P0**；详见 [`PLAN_VOICE_LIBRARY_AND_BROADCAST.md`](PLAN_VOICE_LIBRARY_AND_BROADCAST.md)。
> **本文档**只记录 Android 战术切换后的进展，并整合本会话中讨论过的目的、选型与决策。

---

## 0. 项目目的（Why）

### 0.1 业务目标（一句话）

**对「外部客户」批量、自动、可重复地发送真正的企微语音气泡**——对端看到的是可播放的语音消息，**不是** `[语音]` 文本占位，也不是 file/附件降级。

### 0.2 典型使用场景

1. 运营/销售有一份联系人清单（CSV / Plan JSON）
2. 每条联系人对应一段预录语音（或 TTS 生成的 silk/wav）
3. 程序按清单逐人发送，**无需人工逐条按住说话**
4. 同一段语音可发给不同联系人（去重、失败重试、日志可追溯）

### 0.3 硬约束（用户多次强调，不可妥协）

| 约束 | 说明 |
|-----|------|
| **目标对象 = 外部客户** | 不是企业内部成员；官方自建应用 API 发不了外部客户语音 |
| **必须是原生语音气泡** | 不接受 file 附件替代、不接受 `[语音]` 文本、不接受仅 PC 端能看的占位 |
| **PC 端无语音 UI** | PC 企微没有「按住说话」按钮，也不能右键转发语音（会变成 `[语音]`） |
| **尽量绕过 UI 自动化** | 用户倾向逆向/协议层；UI 自动化有被企微风控警告的风险（亲测小规模测试已触发） |
| **不重复造轮子** | 优先复用项目已有基建（PC NativeRouter 文字劫持、PlanRunner、ADB 层等） |

### 0.4 验收标准（POC → 产品）

| 阶段 | 验收 |
|-----|------|
| **POC** | 在 MuMu 企微里，**不触碰「按住说话」UI**，向「文件传输助手」或指定外部客户会话成功发出 1 条可播放语音气泡 |
| **MVP** | Python CLI：`send_voice.py --contact "张三" --silk hi.silk --duration 3` 稳定成功 |
| **产品化** | 接入现有 `PlanRunner` / `SendQueue`，支持批量清单、失败重试、日志 report |

---

## 1. 全局方案演进（What we tried → What we chose）

### 1.1 方案全景图

```
                    ┌─────────────────────────────────────────┐
                    │  目标：外部客户 + 原生语音气泡 + 批量自动化  │
                    └────────────────────┬────────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         │                               │                               │
    PC 端路线                        Android UI 路线                  Android 逆向路线
         │                               │                               │
  A. 文字→语音劫持                   B. MuMu + UIA + VB-CABLE          C. Frida 直调 sendVoice
  (SendMessage 堆覆写)               (按住说话 + 虚拟麦)                 (MessageManager.U8)
         │                               │                               │
      ❌ 结构性死路                    ⚠️ ~85% 跑通但弃选                 ✅ 当前主路线
```

### 1.2 各路线结论摘要

#### ❌ PC 方案 A：文字发送瞬间替换成语音（类似已成功的文字劫持）

- **已有成功**：PC 端 `conv_id` 堆覆写 + 文字内容替换，端到端 patch-and-send 已验证（§47.14）
- **对语音不可行**：PC 企微存在**四层语音出站封锁**（§47.16.15）：
  1. UI 警告
  2. 多选转发拦截
  3. wire builder 过滤 voice 子消息
  4. voice body 被替换成 `[语音]` 文本字面量
- **更深层**：PC 端**没有** `VoiceMessage` 类、**没有** `send_voice` 代码路径、**没有** silk CDN 上传链路（§47.16.24 静态穷举）
- **用户最初想法**：「文字劫持已成功，语音是否也能在发送瞬间替换？」→ **答案：不行**，不是 hook 点问题，是 PC 二进制里根本没有完整 voice outbound pipeline

#### ❌ PC 方案 A 变体：G1 克隆 recv 侧 VoiceMessage / G2 官方 API / G7 找独立 send_voice

| 子方案 | 结论 |
|-------|------|
| G1 克隆收侧 VoiceMessage | ❌ PreSend args 无 voice slot；降级发生在 PreSend 之前 |
| G2 官方自建应用 API | ❌ **只支持内部成员**，不支持外部客户 |
| G7 独立 send_voice 入口 | ❌ PC 静态搜索无 `send_voice` / `VoiceMessage`  concrete class |
| Y 语音房 SendAudio | ⚠️ 非 1:1 聊天气泡，不符合需求 |
| Z 降级目标（file/文本） | ❌ 用户明确拒绝 |

#### ⚠️ Android 方案 B：MuMu 模拟器 + UI 自动化 + VB-CABLE（项目早期主路线）

- **实现位置**：`app/messaging/senders/voice.py`、`app/automation/navigator.py`、`spikes/spike4_forward_flow.py`
- **原理**：MuMu 装企微 → VB-CABLE 虚拟麦克风 → `press_hold_and_run()` 模拟按住说话 → 播放预录 WAV → 松开 → 企微走正常录音链路
- **进度**：前五轮 Agent 一直在推这条路，**约 85% 跑通**
- **弃选原因**（用户 + 实测）：
  1. **远程操控 / 自动化特征**被企微检测，小规模测试已收到警告
  2. 依赖 UI 按压，稳定性受模拟器分辨率/焦点/弹窗影响
  3. 既然 Android APK 里存在 `sendVoiceMessage` 原生 API，**直接调 API 比模拟按压简单一个数量级**
- **保留价值**：POC 阶段若 Frida 路线卡住，可临时 fallback；VB-CABLE / ADB / navigator 基建仍可用

#### ✅ Android 方案 C：Frida 直调 `MessageManager.U8()`（**当前选定主路线**）

- **发现过程**：对 `vendor/wework_apk/base.apk`（企微 Android 5.0.10）做 jadx 反编译 + DEX 字符串扫描
- **核心入口**：
  ```
  iqy.f5().U8(Activity, conversationId, voiceFilePath, voiceTime) → boolean
  ```
  - `iqy` = R8 混淆后的 `MessageManager`（`static String T = "MessageManager"`）
  - 内部：`U1()` 构建 `WwRichmessage.FileMessage` → `G8(..., msgtype=9)` → CDN 上传 + 长连接发送
- **优势**：
  - **完全不走 UI**，不需要「按住说话」
  - 参数是**文件路径**（silk 文件 push 到 `/sdcard` 即可）
  - Android 端有 PC 端缺失的全套组件（VoiceMessage、AudioDumper、SilkEncoder、CdnUpload）
- **当前进度**：静态分析 100% 确认 `iqy` 签名；**运行时观测已突破**——真人发送语音可稳定 hook 到 `h8y.U1()` 并 dump silk 路径/时长/文件头（§5–§6）；**主动调用 POC 尚未完成**（缺 `convId` + 下游 send 入口）

#### ❌ 其他被排除的 Android 线索

| 线索 | 排除原因 |
|-----|---------|
| `sendCustomAudioData` / `sendPCMAudioData` | 来自 TRTC/V2TXLive/iLinkLive，是**音视频通话推流**，不发聊天气泡 |
| `wework-1` 开源项目 | 用户明确不用：收藏率低、未经验证 |
| LSPosed/Xposed 模块 | MuMu root 是 adbd-as-root，**无 Magisk**，装不了 LSPosed |
| AudioRecord hook + 按住说话 | 可行但重；已被 `U8` 直调替代 |

### 1.3 为什么从 PC 切到 Android

| 维度 | PC | Android |
|-----|-----|---------|
| 语音 outbound 代码 | **不存在** | **完整存在**（461 方法的 MessageManager） |
| 用户操作入口 | 无按住说话 | 有（但我们要 bypass） |
| 已有项目基建 | NativeRouter 文字 hijack 成熟 | ADB/VoiceSender/UIA 有，但待升级 |
| root/hook 环境 | Frida + 堆覆写（文字已通） | Frida 16 + adbd root |
| 目标对象 | 同一账号的 PC + 手机企微 | 手机企微可直接触达外部客户 |

**结论（2026-09-15 更新）**：PC 端 NativeRouter 仅文字 hijack 已产品化；**语音结构性只能 Android**；图片/视频 PC 无主动发送 API（§47.16.24）。**Phase A MVP 全部走 Android Frida 直调**，拒绝 PC UIA 混合方案（见 §15）。

---

## 2. 与现有 Repo 基建的关系

### 2.1 项目仓库概览

```
Test-Voice/   (a.k.a. wecom-voice-blaster)
├── app/
│   ├── pc_wecom/          ← PC 端：NativeRouter, ForwardExecutor, bubble_anchor（text/file 已通）
│   ├── messaging/         ← PlanRunner, SendQueue, 各类型 Sender
│   ├── automation/        ← WeComNavigator（MuMu UIA，Android UI 路线）
│   ├── device/            ← AdbSession, AndroidFileStore
│   └── audio/             ← AudioPreprocessor, CablePlayer, silk_decoder
├── vendor/wework_apk/     ← 用户提供的企微 Android APK (base.apk, 493MB)
├── runtime/wework_re_android/  ← 本次会话产出的探针脚本
├── d:\wework_src\         ← jadx 反编译输出（58k java 文件，不在 repo 内）
├── spikes/spike4_forward_flow.py  ← Android 转发 UI 探索（历史）
└── docs/
    ├── REVERSE_ENGINEERING_HANDOFF.md   ← PC 逆向全书
    └── ANDROID_RE_HANDOFF.md            ← 本文档
```

### 2.2 可复用的已有能力

| 模块 | 路径 | 语音路线怎么用 |
|-----|------|--------------|
| ADB 会话 | `app/device/adb.py` | push silk 文件到 `/sdcard`、启停企微 |
| Android 文件推送 | `app/device/file_store.py` | 上传 voice 文件到设备 |
| 音频预处理 | `app/audio/preprocessor.py` | wav → 标准化；后续可能需要 wav→silk 转换 |
| silk 解码 | `app/audio/silk_decoder.py` | 参考 silk 格式；发送侧可能需要 encoder |
| Plan 批处理 | `app/messaging/runner.py`, `plan.py` | POC 成功后接入批量调度 |
| PC NativeRouter | `app/pc_wecom/native_router.py` | **Phase A 不参与**；历史文字 hijack，见 §15.2 |
| VoiceSender (旧) | `app/messaging/senders/voice.py` | UI+VB-CABLE 路线；已被 Frida 直调替代 |

### 2.3 预期最终架构（目标态 · Phase A）

```
gui/main.py 或 CLI
      │
      ▼
app/broadcast/runner.py（Plan 串行执行）
      │
      ├── conv_resolver.resolve(name) → conv_local
      ├── perturb.py → silk 扰动副本
      └── runtime/wework_re_android/send_engine.py
                │
                ├── send_voice  → h8y.U1 + h8y.X4().E8()     ✅
                ├── send_text   → h8y.B8()                   ✅
                └── send_image  → 完整 CDN 链（Step 3.5）    ⏳
                          │
                          ▼
                 企微内部：FileMessage → CDN upload → SendMessage → 对端可见
```

> **2026-09-15 v2**：发送入口已确认为 `h8y` 簇（非 handoff v1 预期的 `iqy.U8`）。**全部消息类型在 Android 单端完成**；不复用 PC `PlanRunner` / `forward_executor`（见 §15）。

---

## 3. 用户环境与决策记录

### 3.1 用户提供的设备信息

| 项 | 值 | 备注 |
|---|-----|------|
| 模拟器 | **MuMu 12 Pro** | 非华为真机 |
| Android 版本 | **12 (SDK 32)** | 用户曾误报 HarmonyOS 4.3.0，实测为 Android 12 |
| CPU | **x86_64** host + **ARM 转译** | APK 只有 arm64-v8a .so，MuMu 转译可跑 |
| root | **adbd-as-root**（`adb root`） | 非 Magisk；`su -c id` 单独调用无响应，但 `adb root` 后 `id=0` |
| 企微 Android 版 | **5.0.10** (versionCode 79677) | 与 PC 版同代；用户说的 5.0.11 是 PC 版号 |
| APK 来源 | `vendor/wework_apk/base.apk` | 华为渠道包（带 HMSCore），只有 arm64-v8a native libs |
| adb 端口 | 16384（主）、7555（兼容） | `adb connect 127.0.0.1:16384` |

### 3.2 本会话关键决策时间线

1. 用户问：PC 文字劫持已成功，语音能否同样「发送瞬间替换」？ → 分析后 **否**
2. 用户问：官方 API / UI 转发 / PC 造语音入口是否可行？ → **逐一否**（见 §1.2）
3. 用户透露：前五轮一直在做 MuMu UIA 路线（方案 B），不是 Xposed hook
4. 用户提供 APK → 静态分析发现 `sendVoiceMessage` / `MessageManager.U8`
5. 用户选：不等 jadx，并行装 frida-server → 验证 Java bridge
6. 确认 MuMu root（`adb root`）+ Frida 16（17 不兼容）
7. 发现 R8 类名冲突 → 记录三种绕开方案
8. 用户选：**先写 handoff 存盘，新会话继续**
9. **本会话（2026-09-15 下午）**：执行方案 B + 多进程扫描 + 低侵入 hook → **首次成功观测真人语音发送**（4/4 命中 `h8y.U1`）
10. 确认语音文件格式为 **SILK_V3**；`voiceTime` 观测值为 **秒**（1/2/3）；`convId` 仍未从 hook 直接拿到

---

## 4. 技术核心：MessageManager 发送链（已静态确认）

### 4.1 完整调用链

```
iqy.f5()                                                ← 单例 getter (double-checked lock)
  ↓ return volatile static field iqy.U
iqy.U8(Activity, long convId, String voiceFilePath, int voiceTime) : boolean
  ↓ log tag "sendVoiceMessage"
  ↓ 调 U1() 构建 FileMessage
iqy.U1(String path, 0, 0, int voiceTime) : WwRichmessage$FileMessage   ← 静态方法
  ↓ 走进 V1 → W1 — log tag "buildFileMessage"
iqy.G8(Context, long convId, FileMessage, 9 /*msgtype=voice*/, null, callback) : boolean
  ↓ 分发到底层 SendMessage
[企微内部：CDN 上传 silk → 长连接发送 → 对端出现语音气泡]
```

### 4.2 DEX 层硬证据（`classes8.dex` 的 `Liqy;`）

- **39 个字段**，含 `String T = "MessageManager"`、`iqy U`（单例）
- **461 个方法**，核心签名：

```
Z  U8(Landroid/app/Activity;, J, Ljava/lang/String;, I)
Lcom/tencent/wework/foundation/model/pb/WwRichmessage$FileMessage;  U1(Ljava/lang/String;, I, I, I)
Z  G8(Landroid/content/Context;, J, Lcom/tencent/wework/foundation/model/pb/WwRichmessage$FileMessage;, I, Ln3a0;, Lcom/tencent/wework/foundation/callback/ISendMessageCallback;)
Liqy;  f5()
```

### 4.3 jadx 反编译关键节选

源文件：`d:\wework_src\sources\defpackage\iqy.java`（12000+ 行）

```java
/* JADX INFO: loaded from: classes8.dex */
public class iqy extends z3t implements nvp, Handler.Callback {
    public static String T = "MessageManager";
    public static volatile iqy U;

    public static iqy f5() {
        if (U == null) synchronized (iqy.class) {
            if (U == null) U = new iqy();
        }
        return U;
    }

    public boolean U8(Activity activity, long convId, String voiceFilePath, int voiceTime) {
        pb.n(T, {"sendVoiceMessage", convId, voiceFilePath, " voiceTime: ", voiceTime}, ...);
        WwRichmessage.FileMessage fm = U1(voiceFilePath, 0, 0, voiceTime);
        if (fm != null) {
            return G8(activity, convId, fm, 9, null, new iqy.i(convId, voiceTime, voiceFilePath));
        }
        return false;
    }
}
```

### 4.4 其他有价值的 Android 组件（静态扫描命中）

| 关键字 | 命中 | 用途 |
|-------|------|------|
| `sendVoiceMessage` | 9 | 发送入口（已在 iqy.U8 确认） |
| `VoiceMessage` | 30 | protobuf/UI 层语音消息类（PC 端不存在） |
| `AudioDumper` | 9 | 音频采集封装（`libAudioDumper.so`） |
| `SilkEncoder` | 1 | silk 编码 |
| `CdnUpload` | 24 | CDN 上传请求/响应 |
| `uploadSilkVoice` | 1 | silk 上传方法名 |
| `initAudioDumperWithSelfChatRecordInfo` | 1 | 暗示可注入已有录音信息 |

---

## 5. 本会话进展：Frida 动态观测（2026-09-15）

### 5.1 执行摘要

| 项 | 状态 |
|----|------|
| 方案 B（G8 签名反查） | ✅ 已执行；❌ **当前已加载类中无 handoff 预期的 6 参 G8 / 4 参 U8(Activity,...)** |
| 多进程扫描 | ✅ 已扫 `com.tencent.wework` / `:wemeet` / `:wxa_container0`；均无 Scheme B 命中 |
| 低侵入 hook | ✅ **成功**——fallback 定位到 `h8y`，hook `U1(String,int,int,int,boolean)` |
| 真人语音观测 | ✅ **4/4 命中**（FTA 2 次 + 外部联系人 2 次） |
| 主动调用 POC | ❌ 未完成（缺 convId + 下游 send 方法） |

### 5.2 静态 vs 运行时签名差异（重要）

jadx/DEX 静态分析（`classes8.dex` 的 `Liqy;`）与**当前运行时主进程已加载类**不一致：

| 方法 | 静态（iqy / MessageManager） | 运行时观测（h8y） |
|------|------------------------------|-------------------|
| 构建 FileMessage | `U1(String, int, int, int)` | **`U1(String, int, int, int, boolean)`** → `WwRichmessage$FileMessage` |
| 发送入口 | `U8(Activity, long, String, int)` → boolean | **`U8(java.util.List)`** → void（签名完全不同） |
| 分发 | `G8(Context, long, FileMessage, int, *, ISendMessageCallback)` | **`G8(int)`** → void |

**推论**：
1. R8 混淆 + 版本/加载时机导致 `Java.enumerateMethods` 扫不到未加载的 `iqy.U8` 6 参版本；
2. 真人录音发送链路**至少经过 `h8y.U1` 构建 silk FileMessage**；
3. 下一 agent 应沿 `h8y` 的调用栈向下游 hook（`U8(List)`、`G8(int)` 或 `wjc`/`inc`/`qdx` 等同进程候选），而非死磕 `Java.use('iqy')`。

### 5.3 已验证的真人发送参数（4 次 hook 实测）

探针脚本：`runtime/wework_re_android/probe_msgmgr_scheme_b.py`（safe mode + fallback）

**命中类**：`h8y`  
**命中方法**：`U1(String path, int a, int b, int voiceTime, boolean flag)`

| 时间戳（文件名） | voiceTime | flag | 文件路径（节选） |
|-----------------|-----------|------|------------------|
| `2026_09_15_12_31_35_261.silk` | **3** | false | `.../voicemsg/1688855042791155/...` |
| `2026_09_15_12_31_46_638.silk` | **3** | false | 同上目录 |
| `2026_09_15_12_32_10_655.silk` | **2** | false | 同上目录 |
| `2026_09_15_12_32_15_819.silk` | **1** | false | 同上目录 |

**文件头（前 16 字节 hex）**：
```
02 23 21 53 49 4c 4b 5f 56 33 ...
```
ASCII：`#!SILK_V3` → **确认企微 Android 真人语音为 Tencent SILK v3 格式**。

**路径规律**：
```
/storage/emulated/0/Android/data/com.tencent.wework/files/voicemsg/<FOLDER>/<timestamp>.silk
```
- `<FOLDER>` 四次均为 **`1688855042791155`**（疑似会话/账号相关 ID，**待与 convId 对照验证**）
- 当前 hook **未打印 convId**；需 hook 下游 send 或解析路径 folder ↔ 会话映射

**voiceTime 单位**：观测值 1/2/3 与录音时长一致 → **单位为秒**（非毫秒）。

### 5.4 多进程扫描结果

脚本：`runtime/wework_re_android/scan_scheme_b_multi_proc.py`

| PID | 进程名 | U8 类数 | G8 类数 | Scheme B 命中 |
|-----|--------|---------|---------|---------------|
| 4828 | `com.tencent.wework` | 9 | 8 | **0** |
| 4768 | `com.tencent.wework:wemeet` | 1 | 0 | 0 |
| 5050 | `com.tencent.wework:wxa_container0` | 1 | 0 | 0 |

主进程内与语音相关的已加载候选（非 Scheme B 签名）：
- `h8y` — 含 `U1` FileMessage builder（**已证实参与真人发送**）
- `wjc` — `G8(long)`, `f5(boolean)`, `U8(boolean)`
- `inc`, `qdx` — 各有一套不同签名的 U8/G8

### 5.5 R8 类名冲突（仍有效，但已不是唯一卡点）

Frida 里 `Java.use('iqy')` 仍返回 **classes7.dex 的假 iqy**（1 字段 onClick lambda）：

```
Cls.name = iqy
Cls.getDeclaredFields count = 1
  field: MomentsComposeActivity d
Cls.getDeclaredMethods count = 1
  method: onClick
```

ART 报错：
> `NoSuchFieldException: No field T in class Liqy; (declaration of 'iqy' appears in .../base.apk!classes7.dex)`

**绕开方案执行结果**：

| 方案 | 结果 |
|-----|------|
| **B. G8 签名反查** | 已执行；已加载类中**无** 6 参 G8 命中 → 改用 U1 fallback 成功 |
| **A. 指定 DEX 元素** | 未执行 |
| **C. 单例堆扫** | 未执行 |

### 5.6 Frida 反调试 / 稳定性教训（必读）

| 做法 | 结果 |
|------|------|
| `spawn` + `resume` 启动企微 | ❌ 用户反馈**一开就自动下线** |
| 全局 hook `ClassLoader.loadClass` | ❌ 高侵入，易触发 anti-debug |
| `attach` 已运行进程 + 无全局 hook + 5s 周期扫描 | ✅ 稳定，用户可正常登录发消息 |
| 多次 attach 同一 session | ⚠️ 可能 `create_script timeout` → 需 `am force-stop` + 重启 frida-server |
| `py -3` 启动器 | ⚠️ 偶发 `Internal CLR error (0x80131506)` → 用直连 Python 路径 |

**推荐启动方式**（低侵入）：
```powershell
# 1. 用户手动打开企微并登录到聊天页
# 2. 再 attach（不要用 spawn）
& 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' -u runtime\wework_re_android\probe_msgmgr_scheme_b.py
```

---

## 6. 待验证 / 已部分验证的下游细节

| # | 问题 | 状态 | 结论 / 下一步 |
|---|-----|------|--------------|
| 1 | `voiceFilePath` 格式？ | ✅ **已验证** | Tencent **SILK_V3**（`02 23 21 53 49 4c 4b 5f 56 33`） |
| 2 | `conversationId` 怎么拿？ | ⚠️ **部分** | 路径中 folder `1688855042791155` 疑似相关；需 hook 下游 send 或对照 ConversationService |
| 3 | `Activity` 能否 mock？ | ❓ 未验证 | 原 `iqy.U8` 未命中；若走 `h8y` 簇需重新定位 send 入口 |
| 4 | `voiceTime` 单位？ | ✅ **已验证** | **秒**（观测 1/2/3 与录音时长一致） |
| 5 | FTA vs 外部联系人能否区分？ | ❌ 未验证 | 四次 U1 路径 folder 相同；需 hook 带 convId 的下游方法 |
| 6 | `h8y` 与 `iqy` 关系？ | ❓ 未验证 | jadx 静态为 iqy；运行时为 h8y.U1 — 需栈回溯或 jadx 交叉引用 |
| 7 | 主动调用最小参数集？ | ❌ 未验证 | 需定位等价于 `G8(..., msgtype=9)` 的运行时方法 |

---

## 7. 环境与工具（已就绪）

| 组件 | 版本/位置 | 验证命令 |
|-----|----------|---------|
| 模拟器 | MuMu 12 Pro, x86_64, Android 12 | `adb shell getprop ro.build.version.release` → `12` |
| adb | 127.0.0.1:16384 | `adb connect 127.0.0.1:16384` |
| root | adbd-as-root | `adb root && adb shell id` → `uid=0(root)` |
| 企微 | v5.0.10, 已装 | `adb shell dumpsys package com.tencent.wework \| grep versionName` |
| APK | `vendor/wework_apk/base.apk` | 493 MB, 20 dex, arm64-v8a only |
| JDK | Temurin 21 | `C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot` |
| jadx | 1.5.6 | `jadx --version` |
| 反编译 | `d:\wework_src\` | 58,671 java files |
| frida-tools | **16.7.19**（必须 16.x） | `pip show frida` |
| frida-server | 16.7.19 android-x86_64 | `/data/local/tmp/frida-server` |

**frida-server 启动**（可与企微并行，勿 force-stop 已登录的 App）：
```powershell
adb -s 127.0.0.1:16384 root
adb -s 127.0.0.1:16384 shell "killall -9 frida-server 2>/dev/null; nohup /data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 &"
adb -s 127.0.0.1:16384 forward tcp:27042 tcp:27042
```

**探针 attach**（用户先手动打开企微并登录）：
```powershell
& 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' -u runtime\wework_re_android\probe_msgmgr_scheme_b.py
```

**仅在 attach 失败 / timeout 时**才 force-stop 重启企微：
```powershell
adb -s 127.0.0.1:16384 shell "am force-stop com.tencent.wework"
adb -s 127.0.0.1:16384 shell "am start -n com.tencent.wework/com.tencent.wework.launch.LaunchSplashActivity"
Start-Sleep -Seconds 8
```

**⚠️ 陷阱**：
- Frida 17.x 移除 `Java` global → 脚本全挂
- 企微主进程 PID：`adb shell ps -A -o PID,NAME | grep 'com.tencent.wework$'`（不含 `:` 的）
- Frida 枚举进程时主进程名可能是乱码中文，不要按 `WeCom` 字符串匹配
- 多次 attach → anti-debug 累积 → `create_script` timeout → 必须 force-stop + 重启 frida-server
- **禁止 spawn 启动企微**（会触发自动下线）；必须先手动打开 App 再 attach
- **禁止全局 hook ClassLoader.loadClass**（高侵入，易触发 anti-debug）
- `py -3` 偶发 CLR 崩溃 → 用 `C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe`
- adb 多设备时加 `-s 127.0.0.1:16384`，否则 `more than one device/emulator`

---

## 8. 产出资产索引

| 路径 | 用途 |
|-----|------|
| `d:\wework_src\` | jadx 完整反编译（58k java） |
| `d:\wework_src\sources\defpackage\iqy.java` | MessageManager 静态源码（classes8.dex） |
| `vendor/wework_apk/base.apk` | 目标 APK |
| `vendor/frida-server-16.7.19-android-x86_64` | frida-server 二进制 |
| **`runtime/wework_re_android/probe_msgmgr_scheme_b.py`** | **当前主探针**：safe mode + Scheme B + `h8y` fallback hook U1/U8 |
| **`runtime/wework_re_android/scan_scheme_b_multi_proc.py`** | **多进程一次性扫描** U8/G8 签名 |
| `runtime/wework_re_android/scan_sendvoice.py` | DEX 字符串扫描 |
| `runtime/wework_re_android/sendvoice_hits.txt` | 扫描结果 |
| `runtime/wework_re_android/find_realname_messagemanager.py` | 确认 T="MessageManager" 的 dex/类 |
| `runtime/wework_re_android/dump_liqy_from_dex.py` | dump Liqy 全部字段/方法签名 |
| `runtime/wework_re_android/dex_class_collision.py` | 类名冲突检查 |
| `runtime/wework_re_android/probe_msgmgr_v4.py` | 旧探针（loadClass 遇 R8 冲突，已 supersede） |
| `runtime/wework_re_android/probe_msgmgr_v3.py` | 旧探针（ClassFactory loader 绑定） |
| `runtime/wework_re_android/probe_list_u8.py` | 列出当前进程所有 U8/G8/f5 签名 |
| `runtime/wework_re_android/probe_find_sendvoice.py` | U8(Activity,...) 签名反查（运行时 0 命中） |
| `runtime/wework_re_android/probe_u8_tiny.py` | 最小 U8 枚举 |
| `runtime/wework_re_android/probe_iqy_inspect.py` | 检查各 loader 中 iqy 字段/方法 |
| `runtime/wework_re_android/probe_send_voice.py` | 早期 iqy.U8 hook 探针 |
| `runtime/wework_re_android/probe_java_v2.py` | 验证 Java bridge + 定位主进程 PID |
| `runtime/jadx_decompile.log` | jadx 日志 |

---

## 9. 下一 Agent 行动清单（按优先级）

### ✅ 已完成（勿重复）

- [x] 方案 B G8 签名反查（已加载类无命中 → 转 fallback）
- [x] 多进程扫描（主进程 / wemeet / wxa_container0）
- [x] 低侵入 attach hook，观测真人发送 4 次
- [x] 确认 silk 格式（SILK_V3）、voiceTime 单位（秒）、文件路径规律

### P0 — 定位 send 入口 + 拿 convId

1. **用户手动打开企微并登录** → attach（§5.6，禁止 spawn）
2. 在 `probe_msgmgr_scheme_b.py` 基础上，对 `h8y.U1` 做 **stack trace**（`Thread.currentThread().getStackTrace()`），找调用方
3. 并行 hook 同进程候选：`h8y.U8(List)`、`h8y.G8(int)`、`wjc.G8(long)`、`inc`/`qdx` 中带 `Conversation`/`long convId` 的方法
4. 请用户分别向 **FTA** 和 **外部联系人** 各发 1 条语音 → 记录 **convId** 及 FTA/外部差异
5. 验证路径 folder `1688855042791155` 是否等于 convId 或 remoteId

### P1 — 主动调用 POC

6. 用观测到的 silk 路径格式，push 测试 silk 到 `.../voicemsg/<folder>/test.silk`
7. Frida 主动调用下游 send 方法（可能是 `h8y` 簇或延迟加载的 `iqy.U8`）
8. 确认 FTA / 外部联系人收到可播放语音气泡

### P2 — 封装 + 接入产品

9. 封装 `FridaVoiceAgent` + Python CLI：`send_voice.py --contact "xxx" --silk hi.silk --duration 3`
10. 实现 `contact_name → conversationId` resolver（ConversationService 枚举 or hook 缓存）
11. 替换 `app/messaging/senders/voice.py` 的 UI+VB-CABLE 实现
12. 接入 `PlanRunner`，支持批量 + 重试 + report

### P3 — 若 h8y 路线卡住时的备选

- 方案 A：反射指定 `dexElements[N]` 强制加载 classes8.dex 的 `iqy`
- 方案 C：heap walk 找 `T="MessageManager"` 或 39 字段单例实例
- jadx 反查 `h8y.java` 与 `iqy.java` 的调用关系（`d:\wework_src\sources\defpackage\`）

---

## 10. 已排除路线速查表

| 路线 | 结论 | 证据 |
|-----|------|------|
| PC 文字→语音劫持 | ❌ | §47.16.15 四层封锁 + 无 VoiceMessage |
| PC 构造语音 UI 入口 | ❌ | PC 无 send_voice 代码 |
| 官方 API 发语音给外部客户 | ❌ | 只支持内部成员 |
| PC 语音转发 | ❌ | 变成 `[语音]` 文本 |
| TRTC sendCustomAudioData | ❌ | 通话推流，非聊天气泡 |
| LSPosed / Xposed | ❌ | 无 Magisk |
| wework-1 开源 | ❌ | 用户不要 |
| Android UI + VB-CABLE | ⚠️ 弃选 | 85% 通但有风控风险；被 C 替代 |

---

## 11. 风险与备注

- **MuMu ARM 转译 + Frida**：多次 attach 不稳定；`create_script timeout` 时才 force-stop + 重启 frida-server（**不要每轮都重启已登录企微**）
- **Frida 反调试**：spawn / 全局 ClassLoader hook 会导致企微自动下线；务必 attach-only + 低侵入（§5.6）
- **静态 vs 运行时签名**：jadx 的 `iqy.U8` 与运行时 `h8y.U1` 不一致，POC 必须以动态观测为准
- **企微版本绑定**：方法签名/类名随版本变；当前锁定 **5.0.10**
- **风控**：即使走 API 直调，频繁批量发送仍可能触发服务端/客户端风控；建议 POC 阶段低频测试
- **长期方案**：若 MuMu 不稳定，可换 **真机 + Magisk**（红米二手 ~300 元），但当前 adbd root + Frida 已够用
- **与 PC 路线关系**：Phase A **全部走 Android Frida**；PC 端仅作历史参考，不参与发送（§15）

---

## 12. 新会话启动口令（复制即用）

> 阅读 `docs/ANDROID_RE_HANDOFF.md` §5–§9，继续 Android 语音自动化。
>
> **当前状态**：真人发送已 hook 到 `h8y.U1(String,int,int,int,boolean)`，确认 SILK_V3 + voiceTime=秒；**缺 convId 和下游 send 入口**。
>
> **下一任务（P0）**：
> 1. 用 `probe_msgmgr_scheme_b.py`（attach only，禁止 spawn）对 `h8y.U1` 做 stack trace；
> 2. hook 下游 send（`h8y.U8(List)` / `wjc.G8(long)` 等）拿 convId；
> 3. 区分 FTA vs 外部联系人 convId；
> 4. 主动调用完成 POC。
>
> 环境：MuMu 12 @ 127.0.0.1:16384，企微 5.0.10，frida 16.7.19。
> Python：`C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe`

---

## 13. 本会话实测日志摘录（供对照）

```
[+] Fallback matched class: h8y by U1 voice builder signature
[+] Hooked U1(String,int,int,int,boolean)

============ U1 HIT (fallback) ============
class      : h8y
path       : /storage/emulated/0/Android/data/com.tencent.wework/files/voicemsg/1688855042791155/2026_09_15_12_31_35_261.silk
voiceTime  : 3
flag       : false
fileHead   : {"got":64,"head":"02 23 21 53 49 4c 4b 5f 56 33 11 00 a7 36 29 2e ..."}
returnType : com.tencent.wework.foundation.model.pb.WwRichmessage$FileMessage
============================================
```

（共 4 条类似记录：voiceTime = 3, 3, 2, 1；均无 U8(Activity,...) 命中）

---

**文档版本**：2026-09-15 v3（整合 Frida 动态观测、h8y 运行时签名、反调试教训、P0 更新）
**上一 agent 最后操作**：成功 hook `h8y.U1` 观测 4 次真人语音发送；确认 SILK_V3；多进程扫描无 Scheme B 命中；更新 handoff

---

## 14. 本轮进展（2026-09-15 v6，Step 1–3 + 架构决策）

> **停点**：架构已敲定（§15）；**Step 3.5 图片 P0 是唯一阻塞项**；实施前需 smoke check 企微登录状态。
>
> **详情请见 [`PLAN_VOICE_LIBRARY_AND_BROADCAST.md`](PLAN_VOICE_LIBRARY_AND_BROADCAST.md) v2.0**（Phase A/B、Step 3.5 P0、Critical Decisions #11–14、详细改动清单、手动测试清单）。

### 14.1 关键突破

- **主动发送 POC 完全跑通**：`h8y.U1(silkPath, 0, 0, voiceTime, false)` 构建 FileMessage，`h8y.X4().E8(activity, convLocal, silkPath, voiceTime)` 发送成功。全程 attach-only 低侵入、进程稳定、不掉线。
- **无需停留在对话页**：在 `WwMainActivity`（企微主页）即可主动发起发送，`E8` 返回 `true`，对方端收到可播放语音气泡（3s，用户已确认）。
- **联系人解析跑通（B 方案）**：`ConversationService.FetchSessionList(cb, false)` + `Conversation.getDefaultName(true)` + `getMembers()`，通过关键字过滤即可从昵称拿到 `conv-local`。示例：
  - `海鸟与鱼` → conv-local=**7685582584742596232**, remote=7881300363276969（type:0 外部微信联系人）
  - `范新怡、笑看人生、海鸟与鱼`（外部群）→ remote=10839797135036051（type:1）

### 14.2 已发生的关键脚本

| 脚本 | 用途 |
| --- | --- |
| `runtime/wework_re_android/send_voice_poc_h8y.py` | 主动发送 POC（已参数化，`--activity-guard` 可选） |
| `runtime/wework_re_android/list_conversations_with_names.py` | 全量会话枚举 + 关键字过滤 + 真实中文名解析 |
| `runtime/wework_re_android/fetch_session_list_by_keyword.py` | `FetchSessionList` 主动刷新缓存的最小样例 |
| `runtime/wework_re_android/resolve_external_names.py` | `h8y` long→String 系列辅助方法的探测记录 |

### 14.3 用户拍板的下一阶段方向

- **A 方案**：素材来源限定为"真人在企微 FTA 里录制的 silk"，程序自动入库到设备端独立目录，GUI 打话术标签。
- **架构（2026-09-15 敲定）**：**全 Android**；拒绝 PC 混合 / UIA 转发（详见 §15）。
- **Phase A MVP**：voice + text + **image** 三种消息类型 + Plan/Runner + GUI + 反风控。
- **Phase B（v1.1）**：video / 小程序 / 视频号 / 卡片，Phase A 上线后启动。
- **反风控**：silk 尾静音帧无感扰动 + 消息间/联系人间随机时序打散；速率上限灰度试探。
- **失败策略**：单条失败继续跑，整轮结束向用户汇报明细，用户决定是否只重试失败项。
- **GUI**：本地单窗口 3 Tab（素材库 / 编 Plan / 执行结果）。

### 14.4 §9 行动清单的状态更新

| 原 §9 条目 | 状态 |
| --- | --- |
| P0 全部（定位 send 入口 + convId） | ✅ 已完成 |
| P1 全部（silk 复用 + 主动调用 POC + 外部联系人可播放） | ✅ 已完成 |
| P2-9 `send_voice.py` CLI | ⏸ 由本轮计划 Step 3.4 承接 |
| P2-10 `contact_name → conv_local` resolver | ✅ `list_conversations_with_names.py` 已实现，Step 4.4 抽为函数 |
| P2-11 替换 UI+VB-CABLE 语音发送 | ⏸ 由本轮计划 Step 4 承接 |
| P2-12 PlanRunner 接入 | 🟨 由本轮计划自建 Runner（不复用 PC 侧 PlanRunner，因为需求已发散：多联系人 × 多消息类型 × 反风控） |

### 14.5 实施计划进度（[`PLAN_VOICE_LIBRARY_AND_BROADCAST.md`](PLAN_VOICE_LIBRARY_AND_BROADCAST.md) v2.0）

**Overall Progress：35%**（Step 1–3 部分完成；**Step 3.5 图片 P0 阻塞**；Step 4–6 未开始）

| Step | 状态 | 摘要 |
| --- | --- | --- |
| Step 1 路径可读性 | ✅ | `VOICE_LIB_ROOT="/sdcard/Test-Voice/voice_lib"` 已验证 |
| Step 2 语音素材库 | ✅ | `VoiceLibrary` + `fta_capture.py`；单测 2/2 通过 |
| Step 3 发送引擎 | 🟨 | voice/text ✅ 对端可见；image `f8` 假阳性 → 移交 Step 3.5 |
| **Step 3.5 图片 P0** | 🟥 **阻塞** | 逆向完整 CDN 链；Step 4 前必须完成 |
| Step 4 Plan/Runner | ⏸ | 依赖 Step 3.5（image 节点） |
| Step 5 GUI | ⏸ | 依赖 Step 4 |
| Step 6 反风控试探 | ⏸ | 最后 |
| Step 7+ Phase B | ⏸ | video 等，Phase A 后 |

**新增代码位置**：

| 路径 | 用途 |
| --- | --- |
| `app/broadcast/paths.py` | `VOICE_LIB_ROOT` / `VOICE_LIB_ROOT_FALLBACK` 常量 |
| `app/broadcast/library.py` | `VoiceLibrary` + `voice_lib_index.json` 读写 |
| `runtime/wework_re_android/fta_capture.py` | FTA 语音入库监听（hook U1 + SendMessage） |
| `runtime/wework_re_android/send_engine.py` | 统一发送引擎 CLI（voice/text/image） |
| `runtime/wework_re_android/capture_voice_u1_once.py` | 低侵入一次性语音捕捉（推荐） |
| `tests/test_library.py` | VoiceLibrary 单测 |

---

### 14.6 已验证的运行时会话 ID（本轮实测，**以运行时为准**）

| 对象 | conv-local | remote | type | 备注 |
| --- | --- | --- | --- | --- |
| **文件传输助手（FTA）** | `7685582580447628882` | `10006` | `4` | 计划文档曾写 remote=10004，**实测 FTA 为 10006**；`fta_capture.py` 默认常量需对齐 |
| **海鸟与鱼**（外部微信联系人） | `7685582584742596232` | `7881300363276969` | `0` | 语音/文字发送验证目标 |
| **范新怡、笑看人生、海鸟与鱼**（外部群） | — | `10839797135036051` | `1` | 仅枚举确认 |

**注意**：旧 FTA conv-local `7685582580447628875` 已失效，`E8 return=false`。

---

### 14.7 发送能力验证结论（2026-09-15 下午）

#### ✅ 语音（voice）— 已端到端跑通

- 入口：`h8y.U1(silkPath,0,0,voiceTime,false)` + `h8y.X4().E8(activity, convLocal, silkPath, voiceTime)`
- CLI：`python -m runtime.wework_re_android.send_engine voice --conv-local ... --silk-path ... --voice-time N`
- **用户已确认**：捕捉 FTA 真人录音后转发至「海鸟与鱼」，对端**可播放且有声音**（非静音样本）
- 样本路径示例：`/storage/emulated/0/Android/data/com.tencent.wework/files/voicemsg/1688855042791155/2026_09_15_14_42_46_321.silk`（3s，有声）

#### ✅ 文字（text）— 已跑通

- 运行时签名：`h8y.B8(Context, long, CharSequence, boolean)`
- CLI：`python -m runtime.wework_re_android.send_engine text --conv-local ... --body "..."` → `return=true`
- 用户侧可见 `[IMG-PROBE]` 标记文本（证明 text 链路可达对端）

#### ⚠️ 图片（image）— **调用成功但对端不可见（阻塞项）**

- 运行时签名：`h8y.f8(Context, long, String, zi90)`，需 `h8y.X4()` 实例调用（非 static）
- CLI 返回 `action=image return=true`，且 `SendMessage mType=7` 已命中
- **但用户多次确认对端（海鸟与鱼）未收到图片**
- 推测：直调 `f8` 只完成了客户端本地 SendMessage 构建，**未完成 CDN 上传 / 外部联系人可达的全链路**；企微对图片有额外规范化步骤

---

### 14.8 FTA 图片链路观测（关键发现）

用户手动向 FTA 发图后，设备侧出现企微内部规范化产物（时间戳 17:56 对齐）：

| 路径 | 大小 | 实际格式（ffmpeg 探测） |
| --- | --- | --- |
| `.../tempimagecache/1688855042791155/*_compress.png` | ~107KB | **JPEG**（mjpeg），1430×2560 |
| `.../uploadTempMidbimage/*.midimage` | ~38KB | **JPEG**，715×1280 |
| `.../uploadTempThumbimage/*.thumbimage` | ~3KB | **JPEG**，162×290 |

**推论**：

1. 企微发图不是"原样读本地 PNG/JPG 直发"，而是走 **压缩 → 中图 → 缩略图 → CDN** 管线。
2. 我们直喂 `/sdcard/Test-Voice/.../*.png` 虽 `f8 return=true`，但缺少上述中间态与 CDN 字段，外部联系人可能收不到。
3. `probe_fta_image_pipeline_v2.py` 仅抓到 `SendMessage(mType=7)`，**未命中 `h8y.f8/U1/W1`**（手动发图可能走不同 builder 路径，或 hook 时机问题）——需下一 agent 继续逆向。

**测试用图片路径**（已 push 到设备）：

- `/sdcard/Test-Voice/voice_lib/send_probe_screen.png`（67KB，设备截图）
- `/sdcard/Test-Voice/voice_lib/test_send_image_visible.png`（720×480 蓝底测试图）

---

### 14.9 图片发送路径 — 风险评估（用户 2026-09-15 决策前讨论）

| 路径 | 技术可行性 | 对端可达性 | 风控/UI 风险 | 综合风险 |
| --- | --- | --- | --- | --- |
| **A. Frida 直调 `f8` 发本地路径** | 高（return=true） | **低（实测不可见）** | 低 | ⚠️ 中偏高（假阳性） |
| **B. 先 FTA 入库 + Frida 转发** | 中（需逆向 forward API） | 中（待验证） | 低 | 中 |
| **C. 先 FTA 入库 + UIA 长按转发** | 低（见 §14.10） | 中（理论可行） | **高**（UI 自动化） | **高** |
| **D. 逆向完整 `sendImageMessage` 链（W1→G8→CDN）** | 低（工作量大） | 高（若成功） | 低 | 中（研发成本） |

**当前建议（下一 agent）**：

1. **优先 D**：沿 `iqy.w8` / `W1` / `G8(context, conv, FileMessage, msgtype, ...)` 逆向，找图片 CDN 上传 + 外部联系人可达的最小 Frida 调用面（与 voice 同级，不走 UI）。
2. **备选 B**：若 D 卡住，尝试 Frida 层模拟"转发"（hook 转发菜单对应的 native 方法），而非 UIA。
3. **暂弃 C**：UIA 转发在 MuMu 上报 `INJECT_EVENTS permission` 错误，且用户明确倾向 Frida 直调。

---

### 14.10 踩坑与稳定性教训（本轮新增）

| 现象 | 原因 | 正确做法 |
| --- | --- | --- |
| `probe_msgmgr_scheme_b.py` 导致企微崩溃/掉线 | 下游 hook（`inc.G8` 等）递归调用，堆栈深度爆炸 | **禁用**；改用 `capture_voice_u1_once.py` 或 `probe_msgmgr_lite.py` |
| 旧 plan 中 FTA remote=10004 入库不触发 | 实测 FTA remote=**10006** | 更新 `fta_capture.py` 默认 `--fta-remote-id 10006` |
| 用旧 FTA conv-local 发送失败 | conv-local 已变 | 以 `list_conversations_with_names.py` 运行时枚举为准 |
| `send_engine image return=true` 但对端无图 | 仅本地 SendMessage，缺 CDN 全链路 | 见 §14.8–14.9 |
| `send_image_via_fta_forward.py` UIA 转发失败 | `SecurityException: INJECT_EVENTS permission` | MuMu 上 uiautomator2 滑动/点击受限；**不要依赖 UIA 转发** |
| `py -3` 启动 Python | 偶发 CLR 崩溃 | 用 `C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe` |
| venv 的 frida 调 send_engine | `ProtocolError: major versions match` | Frida 脚本用 **系统 Python311 + frida 16**；业务层用 venv |
| 企微进程掉线 | 多次 attach + 高侵入 hook 累积 | attach-only；低侵入；失败时 `force-stop` + 重启 frida-server，**不要每轮都重启已登录企微** |

**推荐 attach 流程**（用户需先手动打开企微并登录）：

```powershell
adb -s 127.0.0.1:16384 root
adb -s 127.0.0.1:16384 shell "killall -9 frida-server 2>/dev/null; nohup /data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 &"
adb -s 127.0.0.1:16384 forward tcp:27042 tcp:27042

# Frida 脚本（语音/发送）
& 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' -m runtime.wework_re_android.send_engine text --conv-local 7685582584742596232 --body "ping"

# 业务层单测 / fta_capture（需 venv）
.\.venv\Scripts\python.exe -m pytest tests\test_library.py -q
```

---

### 14.11 本轮新增脚本索引

| 脚本 | 用途 | 状态 |
| --- | --- | --- |
| `send_engine.py` | 统一 voice/text/image 发送 CLI | ✅ 可用（image 对端不可见） |
| `capture_voice_u1_once.py` | 低侵入捕捉一条 FTA/任意语音 U1 事件 | ✅ 推荐 |
| `fta_capture.py` | 持续监听 FTA 语音入库 + 备注 | ✅ 骨架可用；需修正 FTA remote id |
| `probe_fta_image_pipeline.py` / `_v2.py` | 观测 FTA 手动发图链路 | ⚠️ 仅抓到 SendMessage；进程可能异常退出 |
| `probe_image_send_result.py` | 监听 SendMessage + callback onResult | ⚠️ 未拿到 onResult code |
| `send_image_via_fta_forward.py` | FTA 发图 + UIA 转发 | ❌ UIA 权限失败，勿用 |
| `send_voice_poc_h8y.py` | 原始语音 POC | ✅ 保留演示 |

---

### 14.12 下一 agent 从哪里接手（2026-09-15 停点 · 架构已敲定）

**当前停点**：架构决策已写入 §15；**Step 3.5 图片 P0 是唯一阻塞项**；企微可能已掉线，实施前需 smoke check。

**建议优先级（与 plan v2.0 对齐）**：

1. **P0 — Step 3.5 图片 CDN 全链路逆向**（详见 plan Step 3.5.1–3.5.5）
   - 静态：`iqy.w8` → `W1` → `G8`（`iqy.java` ~3482 行）
   - 动态：`probe_fta_image_pipeline_v3.py` 观测 FTA 手动发图
   - 验收：外部联系人「海鸟与鱼」**真实收到可打开图片**（非 `return=true` 假阳性）

2. **P1 — FTA 入库端到端验证**（可与 P0 并行）
   - `fta_capture.py`：`--fta-remote-id 10006`
   - 用户 FTA 发语音 → 自动入库 → 备注回填

3. **P2 — Step 4 Plan/Runner**（Step 3.5 完成后）
4. **P3 — Step 5 GUI / Step 6 反风控**

**不要做的事**：

- ❌ PC 混合方案 / `forward_executor` UIA 转发（§15.2）
- ❌ `probe_msgmgr_scheme_b.py`（会崩进程）
- ❌ UIA 转发图片（INJECT_EVENTS + 风控）
- ❌ venv Python 跑 Frida attach

**Plan 文档**：[`PLAN_VOICE_LIBRARY_AND_BROADCAST.md`](PLAN_VOICE_LIBRARY_AND_BROADCAST.md) v2.0（进度 35%）

---

## 15. 架构决策（2026-09-15 · 探索阶段收官）

> **本章 = 下一 Agent 必读。** 用户在探索阶段敲定了 Phase A 架构；后续实施不得偏离，除非用户显式变更。

### 15.1 决策摘要

| 项 | 结论 |
| --- | --- |
| **发送面** | **全 Android**（MuMu 12 + Frida 16 + `h8y` 簇直调） |
| **Phase A MVP** | voice + text + **image** |
| **Phase B（v1.1）** | video / 小程序 / 视频号 / 卡片 |
| **UIA** | **任何消息类型均不接受 UIA**（含 PC `forward_executor`） |
| **执行顺序** | Step 3.5 图片 P0 → Step 4 Runner → Step 5 GUI → Step 6 反风控 |

### 15.2 为何拒绝 PC 混合方案

探索阶段对 PC 端 35+ 轮逆向做了复核（[`REVERSE_ENGINEERING_HANDOFF.md`](REVERSE_ENGINEERING_HANDOFF.md) §37–§47.16），结论：

| PC 能力 | 实际状态 | Phase A 是否采用 |
| --- | --- | --- |
| NativeRouter 文字 body 覆写 | ✅ 已产品化（§47.14） | ❌ |
| BubbleAnchor + NativeReadMsgId | ✅ 读 msgid | ❌ |
| forward_executor UIA 长按转发 | ⚠️ 可用但是 UIA | ❌ 用户拒绝 UIA |
| 图片/视频主动发送 API | ❌ 静态穷举不存在（§47.16.24） | ❌ |
| M3 file→voice 内存 patch | ❌ 证伪（§45） | ❌ |

**关键纠正**：所谓"PC 已基本逆好图片"实为 **UIA 长按转发 FTA 里已有素材**，不是主动发送 API。与用户弃 Android UIA + VB-CABLE 的风控理由（小规模测试已触发警告）矛盾。

混合方案额外引入：Windows + MuMu 双端 Runner、PC `S:xxx_yyy` 与 Android `conv_local` 双向映射、双 Frida 进程稳定性预算 —— **复杂度 ×2，收益为负**。

### 15.3 Phase A 发送能力现状

| 类型 | Android 状态 | 对端可达 | 下一步 |
| --- | --- | --- | --- |
| voice | ✅ `h8y.U1 + E8` | ✅ 可播放 | 接入 Runner |
| text | ✅ `h8y.B8` | ✅ 可见 | 接入 Runner |
| image | ⚠️ `h8y.f8` 假阳性 | ❌ 不可见 | **Step 3.5 P0** |
| video | ❌ 未开始 | — | Phase B Step 7 |

### 15.4 下一 Agent 起手式

1. 读 [`PLAN_VOICE_LIBRARY_AND_BROADCAST.md`](PLAN_VOICE_LIBRARY_AND_BROADCAST.md) Step 3.5 全文
2. Smoke check：adb connect → frida-server → 企微已登录
3. 执行 Step 3.5.1 静态笔记 → 3.5.2 动态观测 → 3.5.3 最小调用面 → 3.5.4 集成 → 3.5.5 验收
4. Step 3.5 通过后进入 Step 4

---

## 15.5 部署与运营前置约定（2026-09-15 追加）

> **目的**：把探索阶段就"MuMu 能否真机迁移 / 素材接收器在哪 / 员工怎么用"讨论出的结论一次写清，避免下一 Agent 或运营接手者反复问同样的问题。

### 15.5.1 素材接收器 = **Android 端的 FTA**（不是 PC FTA）

FTA（文件传输助手）虽是跨端虚拟端点，但**入库触发点是 Android 进程内的 `h8y.U1`**，PC 企微对 FTA 发消息**不会**触发我们的 hook。

| 用户动作 | 是否入库 |
| --- | --- |
| ✅ 在 Android 企微（MuMu / 真机）里对 FTA 按住说话录语音 | 会（`h8y.U1` 触发） |
| ❌ 在 PC 企微里对 FTA 发消息 | 不会（PC 进程未 hook） |
| ❌ 在 Android 企微里对非 FTA 联系人录语音 | 不会（`fta_capture.py` 有 `remote=10006` 过滤） |

**FTA 常量**：`remote=10006`（§14.6 实测校准，非旧文档记载的 10004）。

### 15.5.2 双账号强制模型（企微服务端规则）

企微/微信服务端强制：**同一账号在两个 Android 端只能二选一**（真机 + 模拟器、真机 + 应用分身、模拟器 + 云手机 …… 所有组合都一样）。这不是我们工具的限制，也**绕不过去**（多开破解违反用户协议且封号率极高）。

**含义**：本项目必须运行在"**营销专号**"上，员工个人主号继续在自己手机上正常用。

| 账号 | 角色 | 装在哪 | 谁在用 |
| --- | --- | --- | --- |
| 员工个人主号 | 日常 1v1、加人、朋友圈 | 员工个人真机 | 员工本人 |
| **营销号** | 批量群发（本项目目标） | **PC MuMu 或员工手机应用分身**（详见 15.5.4） | Frida 脚本托管 |

**营销号来源**（成本递增）：

| 来源 | 成本 | 稳定性 |
| --- | --- | --- |
| ★ 公司企微管理后台自建成员（用工作号手机绑定） | ~30 元/号（手机号） | ✅ 官方账号最稳，责任边界清晰 |
| 员工实名副号（工作补贴报销） | 中 | ✅ 稳 |
| 号商买号 | 80–500 元/号 | ⚠️ 有历史包袱，风控高 |

**首选**：企微管理后台自建 —— 一个营业执照可挂 200 号，员工离职后号留在公司。

### 15.5.3 当前敲定的部署形态（用户 2026-09-15 拍板）

**开发期与初期上线（当前）**：

```
员工个人真机（Android，员工主号，日常使用）  ← 不受本项目影响
                          ⊘（服务端隔离，无冲突）
员工工位电脑（Windows + MuMu 12）
  └── MuMu 里的企微登营销号 ──► Frida hook ──► send_engine.py
```

- 员工主号在手机、营销号在 PC MuMu，两个**不同账号** → 不触发多端冲突
- **每员工需要**：一台 16 GB+ 内存的工位电脑 + MuMu + 一个营销号
- Phase A 直接沿用**开发者本机**的部署模板即可（本项目就是这么跑通的）

### 15.5.4 规模化升级路径（Phase B 之后再决定，此刻仅备忘）

| 规模 | 推荐方案 | 单员工成本 | 风控画像 |
| --- | --- | --- | --- |
| 1–5 员工（当前） | ★ **PC MuMu + 营销号**（当前形态） | 已有电脑，~30 元手机号 | ⚠️ 模拟器指纹，需保守速率 |
| 5–20 员工 | **员工手机应用分身 + Frida**（需 root，手机品牌需支持系统应用分身：小米/华为/OPPO/vivo/荣耀） | 备机 ~300 元/员工（如员工不愿 root 主机） | ✅ 真机指纹，最稳 |
| 20–100 员工 | 云手机集群（阿里云手机 / 华为云手机，选支持 root 的套餐） | 50–200 元/号/月 | ✅ 真机指纹，可批量管理 |
| 100+ 员工 | 应考虑正规商务合作，逆向路线不可持续 | — | — |

**不推荐的方案**：
- ❌ 把 MuMu 打包到真机（架构不匹配，Windows x86_64 vs Android ARM64）
- ❌ 让真机操控 MuMu 双端在线（服务端强制规则，绕不了）
- ❌ 自研企微客户端（工作量数十人年 + 反不正当竞争法律风险）
- ❌ 员工个人主号做群发（一旦封号损失个人客户资产）

### 15.5.5 真机迁移的技术门槛（若未来切真机）

| 项 | 变更 |
| --- | --- |
| frida-server | 换 **`android-arm64`**（当前是 `android-x86_64`） |
| root | 需 Magisk / KernelSU（真机必须解 BL；华为高端机基本无解） |
| Frida 脚本本身 | **不用改**（`h8y.U1/B8/E8` 是 Java 层 hook，跨架构可移植） |
| 企微版本 | 必须锁 5.0.10；企微升级后 R8 类名会变，需重逆 |
| conv_local | 换账号后重跑 `list_conversations_with_names.py` 枚举 |

### 15.5.6 反风控参数受部署形态影响（Step 6 已回填）

Step 6 灰度试探（5 个内部同事号）结论如下：

| 部署形态 | `msg_gap` 建议起点 | `contact_gap` 建议起点 |
| --- | --- | --- |
| PC MuMu（当前） | `[10, 30]`（模拟器画像更保守） | `[60, 150]` |
| 真机应用分身 | `[8, 25]`（真机可更激进） | `[45, 120]` |
| 云手机 | `[8, 25]` | `[45, 120]` |

其中 MuMu `L3(msg=[8,24], contact=[48,120])` 出现 1 次风险提示；按 `-20%` 速度余量回写 `plan.py` 默认常量：

- `DEFAULT_MSG_GAP = (10.0, 30.0)`
- `DEFAULT_CONTACT_GAP = (60.0, 150.0)`

证据：`runtime/reports/step6_risk_tuning_observations_20260916.json`、`runtime/reports/step6_risk_tuning_report_20260916.json`。

---

### 15.6 Step 3.5 完成回填（2026-09-15 晚）

- `probe_fta_image_pipeline_v3.py` 已完成动态观测并产出 ndjson：手动发图命中 `V1 -> V8 -> SendMessage(mType=7)`。
- `send_engine.py` 的 image 发送已从 `f8` 直调切换为 `V1 -> V8 -> q8(msgtype=7)` 主链，`f8` 仅保留 fallback。
- 已加入发送前 `adb` 预落盘：把源图复制到 `.../Android/data/com.tencent.wework/files/tempimagecache/testvoice/...` 后再发，规避外部路径权限导致的红色感叹号。
- 外部联系人「海鸟与鱼」已完成两次可见可打开验证（B3/B4 通过），`Step 4` 解除图片阻塞。

---

**文档版本**：2026-09-16 v14（Step 8 降级跳过）
**上一 agent 最后操作**：完成 Step 7。动态探针确认公众号链路为 `mType=13`，并命中 `h8y.f2(link,title,desc,imgUrl,...)`；模板落 `app/broadcast/oa_templates/11a3bca9-f3a1-441d-a5d2-0cabf8d8b018.json`；`send_engine oa` 已接入并对外部联系人「海鸟与鱼」验收通过。

### 15.7 Phase B 三类逆向执行顺序（v2.3 敲定）

| # | 类型 | 严格定义 | 新未知轴 | 复用来源 | 复杂度 |
| --- | --- | --- | --- | --- | --- |
| Step 7 | **公众号图文卡片**（`appmsg`） | 微信公众号文章右上角 → 分享给朋友 → 企微 FTA 出来的**可点击图文卡片**；含 title/desc/url/thumburl/sourcename/appid，`appMsgType=5` | msgtype≈5 + `AppMsgFileMessage` 字段 | 复用 Step 3.5 `q8` 泛化路径 | 低 |
| Step 8 | **小程序**（wxa card） | 微信小程序卡片，含 appid / pagepath / thumb / WxaAppInfo | 本地 thumb 上传子链 + `WxaAppInfo` 模板 | 复用公众号 msgtype 路径 + image `V1/V8` thumb 段 | 中 |
| Step 9 | **视频** | 短视频消息（≤10s POC），msgtype=6 | msgtype=6 + VideoFileMessage + 双 CDN 上传 | 组合 [图片媒体主链] + [小程序 thumb 子链] | 高 |
| Step 10 | 视频号 / 其他 | channels/finder 分享等 | — | — | **Phase C 搁置** |

**排序依据**：每一步只新增一个未知轴；公众号验证 `q8` 泛化 + `appmsg` 结构，小程序独立验证本地 thumb 上传，视频只做组合。三类均以外部联系人「海鸟与鱼」实测为准（拒绝 `return=true` 假阳性）。**公众号 vs 普通链接卡片区分**：用户明确指"卡片" = 公众号文章分享出来的图文卡片，**不是**外链/网页链接/纯 URL 文本；探针阶段必须走公众号文章的官方分享路径抓栈。

### 15.8 Step 7 回填（2026-09-16）

- 运行时路径修正：公众号卡片并非 `FileMessage/q8(msgtype=5)` 主链，实测落在 `LinkMessage` 链，最终 `SendMessage mType=13`。
- 最小发送面（已集成到 `send_engine.py`）：
  - `h8y.f2(link,title,desc,imgUrl,emptyBytes)` -> `LinkMessage`
  - `h8y.j2(13, linkMessage)` -> `Message`
  - `h8y.s8(context, conversation, message, null, null)` -> 发送
- 对端验收：外部联系人「海鸟与鱼」已确认收到可点击公众号图文卡片（Step 7.5 通过）。

### 15.9 Step 8 启动记录（2026-09-16）

- 已新增小程序模板仓库：`app/broadcast/wxa_templates.py`（与 `oa_templates` 同结构，支持 `save/load/list`）。
- 已新增 Step 8 动态探针：`runtime/wework_re_android/probe_fta_wxa_pipeline.py`，能力覆盖：
  - `ConversationService.SendMessage` 抓 `mType` 与 `messageInfoSnapshot`
  - `h8y.q8 / V1 / V8 / f2` 观测调用栈与参数
  - 文件时序轮询 `tempimagecache` / `uploadTempMidbimage` / `uploadTempThumbimage`
  - 自动落模板到 `app/broadcast/wxa_templates/<template_id>.json`
- 已新增笔记骨架：`runtime/wework_re_android/notes/wxa_send_chain.md`，用于回填 8.1/8.3/8.4 结论。
- 当前环境阻塞（本机）：`python -m runtime.wework_re_android.probe_fta_wxa_pipeline` 报 `ModuleNotFoundError: No module named 'frida'`；需在已安装 `frida` 的逆向环境运行 8.2-B 手动分享实测。
- 新发现的业务门槛：小程序在当前锁定企微版本上可能出现“需要升级更高版本才能打开”。建议将 Step 8 验收拆分为：
  - **链路验收**：对端收到小程序卡片气泡（非纯文本/非普通链接降级）
  - **能力验收**：点击可打开（受客户端版本门槛影响，暂作为环境项单独记录）

### 15.10 Step 8 口径调整（2026-09-16）

- 用户确认可接受“长按转发链接”作为业务交付能力。
- 该路径本质属于 text/link（非 wxa card），因此：
  - Step 8 从 Phase B 阻塞项降级为可选探索项；
  - Step 9 不再依赖“Step 8 先完成”，改为在视频动态探针中直接观测并回填 thumb 子链。
- 结论：当前版本锁定策略（企微 5.0.10）保持不变，不为了 Step 8 单独升级版本。

### 15.11 Step 9 启动记录（2026-09-16）

- 已完成首轮静态回填（`d:\wework_src\sources\defpackage\iqy.java`）：
  - `T8(activity, convId, videoPath, str2, thumbPath, flag)` 对应 `sendVideoMessage`
  - `T8 -> x2(videoPath, thumbPath, flag) -> E8(...)`
  - `x2` 构造 `WwRichmessage.VideoMessage` 字段：`url/rawUrl/size/videoWidth/videoHeight/videoDuration/previewImgUrl`
  - `E8` 发送时 `message.contentType=5`
- 已新增视频动态探针：`runtime/wework_re_android/probe_fta_video_pipeline.py`
  - 覆盖 `h8y.U1 / V1 / V8 / q8 / T8 / E8` + `ConversationService.SendMessage`
  - 文件时序覆盖 `tempvideocache` / `tempimagecache` / `uploadTemp*video*` / `uploadTemp*image*`
  - 产物路径：`runtime/wework_re_android/artifacts/video_pipeline.ndjson`
- 已完成 3 秒 attach 烟测：
  - hook 安装成功；关键签名命中 `U1(String,int,int,int,boolean)`、`V1(String,int,int,int,boolean,Function2)`、`q8(Context,long,FileMessage,int,...)`
  - `h8y.T8` 当前仅见 `T8(List)`，`h8y.E8` 为语音签名，说明静态 `iqy.T8/E8` 需通过运行时映射继续确认
- 已新增视频链笔记骨架：`runtime/wework_re_android/notes/video_send_chain.md`
- 已扩展发送引擎：`runtime/wework_re_android/send_engine.py`
  - 新增命令：`video --conv-local ... --video-path ... [--thumb-path ...] [--duration ...]`
  - 发送前 `adb` 预落盘：`/storage/emulated/0/Android/data/com.tencent.wework/files/tempvideocache/testvoice/`
- 已接入广播执行层：
  - `app/broadcast/plan.py`：`video` 标记为 ready
  - `app/broadcast/runner.py`：新增 `send_video` dispatch
- 当前待办（Step 9.2/9.5）：
  - 在已安装 `frida` 的逆向环境运行视频探针，执行一次真人 FTA 短视频分享并回填证据。

### 15.12 Step 9.2 真人视频探针回填（2026-09-16）

- 已完成 `python -m runtime.wework_re_android.probe_fta_video_pipeline --timeout-seconds 180` + 手动 FTA 发短视频。
- 关键命中：
  - `send_message.mType = 23`
  - `send_message.conv.remote = 10006`（FTA）
  - `send_message.conv.local = 7685582580447628882`
  - `messageInfoSnapshot.fields.contentType = 23`
- 文件侧观测（adb）：
  - 视频本体落盘：`.../files/filecache/1688855042791155/c7/274081b28433d39f43a2def850a6e168/274081b28433d39f43a2def850a6e168.mp4`
  - 首帧 thumb：`.../files/tempimagecache/1688855042791155/video_thumb/70baf07c446aa0f188f9f6bec89c6915_thumb.wwdata`
- 推论：
  - 视频发送链动态 `mType` 已确认是 `23`（非先验 `6`）。
  - thumb 子链复用 `tempimagecache`（`video_thumb` 子目录）。
- 代码同步：
  - `send_engine.py` 视频 q8 fallback 的 `msgType` 已由 `6` 修正为 `23`。

### 15.13 Step 9 视频主动发送失败修复（2026-09-16）

- 现象：主动发送到 FTA 出现红色感叹号（发送失败）。
- 根因：旧实现使用 `q8(FileMessage)` fallback，`V8 ret=7` 暗示进入图片语义，不是视频主发送链。
- 修复：
  - `send_engine video` 主调用改为 `h8y.D8(Activity,long,videoPath,?,thumbPath,boolean)`；
  - 未提供 `thumb_path` 时自动抽取首帧生成 JPEG（`tempimagecache/test_voice/`）；
  - `thumb_path` 输入预落盘目录改为 `tempimagecache`。
- 本地验证日志：
  - `video D8 return=true`
  - `action=video return=true`

### 15.14 Step 9 当前验收状态（2026-09-16）

- 用户确认：外部联系人「海鸟与鱼」已成功收到视频（可播放）。
- 当前判定：
  - Step 9.3 最小调用面：已切换为 `h8y.D8(...)` 主链并生效；
  - Step 9.4 工程集成：`send_engine video` 可执行并返回成功；
  - Step 9.5 首轮业务验收：通过。
- 剩余建议：
  - 再做 1 轮相同 mp4 连续发送，补齐“稳定性双次通过”证据（Step 9 I5）。

### 15.15 批量顺序发送实测（2026-09-16）

- 用户确认：本轮批量测试全部成功。
- 执行顺序（每个目标一致）：
  - `文字 -> 图片 -> 视频 -> 小程序(链接替代) -> 公众号`
- 目标顺序：
  - `海鸟与鱼`（`conv_local=7685582584742596232`）
  - `笑看人生`（`conv_local=7685582584742596231`）
  - 外部群会话（`conv_local=7685582584742596198`，`remote=10839797135036051`）
- 运行结果（send_engine）：
  - 各步骤均返回 `action=... return=true`
  - 视频步骤均命中修复后主链：`video D8 return=true`
- 结论：
  - Step 9 I5（稳定性）与 I6（运行稳定）可判定通过；
  - Step 9 进入“已完成”状态。

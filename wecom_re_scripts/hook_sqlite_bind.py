# hook_sqlite_bind.py — 第十四轮 P0：SQLite bind hook 路线
# ================================================================
# 目标（源自 docs/REVERSE_ENGINEERING_HANDOFF.md §31.5 / §31.9）：
#   * 用签名匹配定位静态链接在 WXWork.exe 内的
#       sqlite3_prepare_v2 / sqlite3_bind_int64 / sqlite3_bind_text /
#       sqlite3_bind_blob / sqlite3_step
#   * hook 三件套 → 转发一次 → 抓到
#       INSERT ... appinfo(msgid, send_time, appinfo) VALUES(?,?,?)
#       UPDATE conversation_XXX SET ...
#     里的 msgid / send_time / appinfo blob / conversationId
#   * 提供 `NativeReadMsgId` 类，直接替代 bubble_anchor 的 UI 长按方案
#
# 定位策略（无独立 sqlite3.dll，全部静态链接）：
#   A. sqlite3_prepare_v2:
#      在 .rdata 找已知 SQL 字面量（'message_appinfo' / 'select sqlite_version'
#      / 'BEGIN IMMEDIATE'），扫 .text 中 push imm32(=字符串地址) 的位置，
#      取紧随其后的 `call rel32` 目标 → 出现频率最高者即 prepare_v2 入口。
#   B. sqlite3_bind_* 家族:
#      在 .rdata 找 SQLite 内部错误串
#         "bind on a busy prepared statement: [%s]"
#      xref 定位 vdbeUnbind() 入口；扫 .text 中所有 `call rel32=vdbeUnbind`
#      的位置，向前找到最近的函数序言 → 全部候选就是
#      sqlite3_bind_null / int / int64 / text / text16 / blob / zeroblob。
#      我们对全部候选都 hook，然后按调用参数（读 stack ESP+4/+8/+0xC/+0x10）
#      + 已缓存的 stmt→sql 映射 + SQL 里 `?` 占位符位置，来推断实际类型。
#   C. sqlite3_step:
#      在 .rdata 找 "cannot start a transaction within a transaction"
#      作为 sqlite3Step 内部日志；xref 得到 sqlite3Step；再扫 .text
#      中 `call rel32=sqlite3Step` 的地方 → 最靠近的函数序言就是外壳
#      sqlite3_step。如果启发式失败，可通过 `--stalker` 参数在 prepare
#      与 finalize 之间做一次 Stalker follow 兜底。
#
# 输出：
#   * NDJSON: runtime/wecom_re/sqlite_bind_<TS>.ndjson （每条 stmt 完整状态）
#   * 汇总  : runtime/wecom_re/sqlite_bind_summary_<TS>.json
#   * 地址缓存 : runtime/wecom_re/sqlite_addrs.json （下次可 --reuse 跳过发现）
#   * 消息映射 : runtime/wecom_re/native_msgid_map.json
#                {send_time_ms: {msgid, conversation_id, appinfo_hex, ts}}
#
# CLI:
#   python hook_sqlite_bind.py                # 全流程：发现 + hook
#   python hook_sqlite_bind.py --discover-only
#   python hook_sqlite_bind.py --reuse        # 使用 sqlite_addrs.json 缓存
#   python hook_sqlite_bind.py --duration 600 # 最长运行 600s（默认 900s）
# ================================================================

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

# frida 只在 Python 3.11 venv 里安装；主项目跑在 Python 3.14 中。
# 延迟导入 → 使 `NativeReadMsgId`、`SqliteAddrs` 等纯 Python 类型
# 可在无 frida 的环境里被单测/工具脚本 import。
if TYPE_CHECKING:  # pragma: no cover
    import frida  # noqa: F401

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

# ─── 常量 ────────────────────────────────────────────────────────────
BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

ADDR_CACHE = OUT_DIR / "sqlite_addrs.json"
NATIVE_MAP = OUT_DIR / "native_msgid_map.json"

# 已在 §31.4 / §5.4 证实的 SQL 字面量与 SQLite 内部错误串
SQL_ANCHORS = [
    b"message_appinfo(msgid,send_time,appinfo)",  # §31.4 Hit 20/21 明证
    b"replace into message_appinfo",
    b"conversation_avatar_table",                 # §30.4
    b"cancle_upload_message_file_table",          # §31.4 Hit 11
    b"select sqlite_version()",
    b"BEGIN IMMEDIATE",
]

# SQLite amalgamation 内部错误串（32-bit MSVC 静态编译后仍保留在 .rdata）
UNBIND_ERR = b"bind on a busy prepared statement: [%s]"
# 用于定位 sqlite3Step / sqlite3_step
STEP_ERR_CANDIDATES = [
    b"cannot start a transaction within a transaction",
    b"database schema has changed",
    b"cannot rollback - no transaction is active",
    b"cannot commit - no transaction is active",
    b"cannot commit transaction - SQL statements in progress",
    b"cannot open savepoint - SQL statements in progress",
    b"another row available",
    b"no more rows available",
    b"statement aborts at %d: [%s] %s",
    b"abort at %d in [%s]: %s",
    b"stale statement handle",
]

SENTINEL = OUT_DIR / "_sqlite_hook_done.flag"


# ─── PID 发现 ────────────────────────────────────────────────────────
def get_wxwork_pid() -> int:
    """通过 :9882 LISTENING 端口定位主进程（与本目录其它脚本一致）。"""
    o = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ":9882" in l and "LISTENING" in l:
            return int(l.strip().split()[-1])
    raise RuntimeError("WXWork.exe :9882 not found — 请先启动企微")


# ─── Frida JS（发现 + hook 两阶段合一） ──────────────────────────────
FRIDA_JS = r"""
'use strict';

// -------- 全局状态 --------
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;
var wxEnd = base.add(wx.size);
send({t:'info', msg:'WXWork.exe base=' + base + ' size=0x' + wx.size.toString(16)});

// 目标地址（Python 决定后经 rpc 注入）
var ADDRS = {
    prepare_v2: null,          // NativePointer
    bind_family: [],           // NativePointer[]
    step: null,                // NativePointer
};

// stmt -> {sql, prep_thread, args:{idx: {type,value}}, prepared_at}
var STMT_TABLE = {};

// -------- 通用工具 --------
function isReadable(p, sz){
    try { p.readU8(); if (sz>1) p.add(sz-1).readU8(); return true; }
    catch(e){ return false; }
}

function readCString(p, max){
    max = max || 4096;
    try {
        var s = p.readCString(max);
        return s;
    } catch(e){ return null; }
}

function readUtf16(p, max){
    max = max || 2048;
    try {
        var s = p.readUtf16String(max);
        return s;
    } catch(e){ return null; }
}

function hexBlob(p, len){
    if (len <= 0 || len > 65536) return null;
    try {
        var buf = p.readByteArray(len);
        var a = new Uint8Array(buf);
        var h = '';
        for (var i = 0; i < a.length; i++){
            var b = a[i]; if (b < 16) h += '0'; h += b.toString(16);
        }
        return h;
    } catch(e){ return null; }
}

// -------- 阶段 1：签名匹配定位 --------
// 输入：字符串 marker 数组；输出：{marker: [addr,...]}
function scanRdataForMarkers(markers){
    // Module#enumerateRanges 只接受 protection 字符串
    var ranges = wx.enumerateRanges('r--').concat(wx.enumerateRanges('rw-'));
    var results = {};
    markers.forEach(function(m){ results[m] = []; });
    // 用 hex pattern 扫 .rdata 段（module 内所有可读段就行）
    markers.forEach(function(m){
        // 转 pattern
        var pat = '';
        for (var i = 0; i < m.length; i++){
            var c = m.charCodeAt(i);
            if (c < 16) pat += '0';
            pat += c.toString(16);
            if (i < m.length-1) pat += ' ';
        }
        ranges.forEach(function(r){
            try {
                var hits = Memory.scanSync(r.base, r.size, pat);
                hits.forEach(function(h){ results[m].push(h.address); });
            } catch(e){}
        });
    });
    return results;
}

// 把 addr 转成 4-byte little-endian hex pattern（用于扫 .text 中的 push imm32）
function addrLePattern(addr){
    var v = addr.toUInt32();
    var b0 = v & 0xff, b1 = (v>>>8)&0xff, b2=(v>>>16)&0xff, b3=(v>>>24)&0xff;
    function h(x){var s=x.toString(16); return s.length<2?'0'+s:s;}
    return h(b0) + ' ' + h(b1) + ' ' + h(b2) + ' ' + h(b3);
}

// 扫 .text 里所有把 addr 当立即数使用的地方（PUSH imm32=68 xx xx xx xx / MOV imm32）
function findImm32Refs(addr){
    var pat = addrLePattern(addr);
    var textRanges = wx.enumerateRanges('r-x');
    var refs = [];
    textRanges.forEach(function(r){
        try {
            var hits = Memory.scanSync(r.base, r.size, pat);
            hits.forEach(function(h){ refs.push(h.address); });
        } catch(e){}
    });
    return refs;
}

// 从 imm32 出现位置向后 32 字节内解析 `call rel32`（E8 xx xx xx xx），返回目标地址
function callTargetAfter(imm32Pos){
    // imm32 位于 push/mov 指令的操作数位置；push imm32 opcode = 68，紧跟 4 字节；
    // 所以 push 指令头 = imm32Pos - 1；下条指令 = imm32Pos + 4。
    // 我们不严格假设 push 结构，而是从 imm32Pos - 1 处线性反汇编，直到遇到 CALL。
    var start = imm32Pos.sub(1);
    var pc = start;
    var end = imm32Pos.add(64);
    for (var step = 0; step < 16 && pc.compare(end) < 0; step++){
        try {
            var ins = Instruction.parse(pc);
            if (ins.mnemonic === 'call'){
                // 只关心 direct near call (E8 rel32)
                try {
                    var tgt = ptr(ins.opStr);
                    if (tgt.compare(base) >= 0 && tgt.compare(wxEnd) < 0)
                        return tgt;
                } catch(e){}
            }
            pc = ins.next;
        } catch(e){ break; }
    }
    return null;
}

// 向前扫 max 字节找函数序言（55 8B EC / 8B FF 55 8B EC / 53 8B DC）
function findPrologueBefore(addr, maxBack){
    maxBack = maxBack || 8192;
    var start = addr.sub(maxBack);
    if (start.compare(base) < 0) start = base;
    var size = addr.toUInt32() - start.toUInt32();
    var bytes;
    try { bytes = new Uint8Array(start.readByteArray(size)); }
    catch(e){ return null; }
    // 从后往前找
    for (var i = bytes.length - 5; i >= 0; i--){
        // hotpatch: 8B FF 55 8B EC
        if (bytes[i]===0x8b && bytes[i+1]===0xff && bytes[i+2]===0x55 &&
            bytes[i+3]===0x8b && bytes[i+4]===0xec)
            return start.add(i);
        // 55 8B EC
        if (bytes[i]===0x55 && bytes[i+1]===0x8b && bytes[i+2]===0xec)
            return start.add(i);
    }
    return null;
}

// 综合发现：返回 {prepare_v2, bind_family[], step}
function discoverAll(sqlAnchors, unbindErr, stepErrs){
    var out = {prepare_v2: null, prepare_v2_votes: {},
               vdbe_unbind: null, bind_family: [],
               step: null, step_votes: {},
               notes: []};

    // ---- prepare_v2 ----
    var markers = sqlAnchors.slice();
    var mkResults = scanRdataForMarkers(markers);
    var voter = {};
    Object.keys(mkResults).forEach(function(m){
        var addrs = mkResults[m];
        if (!addrs.length) return;
        // 一般 SQL 字面量只出现一次；取所有
        addrs.forEach(function(strAddr){
            var xrefs = findImm32Refs(strAddr);
            xrefs.forEach(function(x){
                var tgt = callTargetAfter(x);
                if (tgt){
                    var k = tgt.toString();
                    voter[k] = (voter[k]||0) + 1;
                }
            });
        });
    });
    // 得票最多者
    var bestKey = null, bestVote = 0;
    Object.keys(voter).forEach(function(k){
        if (voter[k] > bestVote){ bestVote = voter[k]; bestKey = k; }
    });
    if (bestKey){
        out.prepare_v2 = bestKey;
        out.prepare_v2_votes = voter;
    } else {
        out.notes.push('prepare_v2 not found via SQL anchor xref');
    }

    // ---- vdbeUnbind → bind family ----
    var unbindHits = scanRdataForMarkers([unbindErr])[unbindErr];
    if (unbindHits && unbindHits.length){
        var strAddr = unbindHits[0];
        var xrefs = findImm32Refs(strAddr);
        // vdbeUnbind 引用该串一次；xref 应指向 vdbeUnbind 内部
        // → 向前扫到函数序言即 vdbeUnbind 入口
        var funcs = {};
        xrefs.forEach(function(x){
            var p = findPrologueBefore(x, 4096);
            if (p) funcs[p.toString()] = (funcs[p.toString()]||0) + 1;
        });
        var vu = null, vv = 0;
        Object.keys(funcs).forEach(function(k){
            if (funcs[k] > vv){ vv = funcs[k]; vu = k; }
        });
        if (vu){
            out.vdbe_unbind = vu;
            // 找所有 CALL rel32 = vdbeUnbind
            var vuPtr = ptr(vu);
            var callers = [];
            var textRanges = wx.enumerateRanges('r-x');
            // scan for E8 xx xx xx xx where target = vu
            // 用直接的 pattern 太贵；改成扫 E8 opcode 并解析
            textRanges.forEach(function(r){
                var buf;
                try { buf = new Uint8Array(r.base.readByteArray(r.size)); }
                catch(e){ return; }
                for (var i = 0; i < buf.length - 4; i++){
                    if (buf[i] !== 0xe8) continue;
                    var rel = buf[i+1] | (buf[i+2]<<8) | (buf[i+3]<<16) | (buf[i+4]<<24);
                    // 有符号扩展
                    if (rel & 0x80000000) rel = rel - 0x100000000;
                    var callSite = r.base.toUInt32() + i;
                    var callTgt = (callSite + 5 + rel) >>> 0;
                    if (callTgt === vuPtr.toUInt32()){
                        callers.push(ptr(callSite));
                    }
                }
            });
            // 每个 caller 回溯函数入口 → 去重 → bind_family
            var famSet = {};
            callers.forEach(function(c){
                var p = findPrologueBefore(c, 4096);
                if (p) famSet[p.toString()] = (famSet[p.toString()]||0) + 1;
            });
            out.bind_family = Object.keys(famSet);
            out.bind_family_counts = famSet;
            out.notes.push('vdbeUnbind callers → ' + callers.length + ' sites, ' +
                           out.bind_family.length + ' unique funcs');
        } else {
            out.notes.push('vdbeUnbind prologue not found');
        }
    } else {
        out.notes.push('vdbeUnbind marker string not found in .rdata');
    }

    // ---- sqlite3Step / sqlite3_step ----
    var stepFunc = null;
    for (var si = 0; si < stepErrs.length && !stepFunc; si++){
        var s = stepErrs[si];
        var hits = scanRdataForMarkers([s])[s];
        if (!hits || !hits.length) continue;
        var xrefs = findImm32Refs(hits[0]);
        var funcs = {};
        xrefs.forEach(function(x){
            var p = findPrologueBefore(x, 8192);
            if (p) funcs[p.toString()] = (funcs[p.toString()]||0) + 1;
        });
        // sqlite3Step 的入口即引用该串的函数入口
        var best = null, bv = 0;
        Object.keys(funcs).forEach(function(k){
            if (funcs[k] > bv){ bv = funcs[k]; best = k; }
        });
        if (best){
            stepFunc = best;
            out.step_votes[s] = funcs;
            out.notes.push('sqlite3Step candidate via "' + s + '" = ' + best);
        }
    }
    if (stepFunc){
        // 现在找 sqlite3_step 外壳：扫 CALL rel32 = sqlite3Step
        var stepPtr = ptr(stepFunc);
        var wrappers = {};
        var textRanges2 = wx.enumerateRanges('r-x');
        textRanges2.forEach(function(r){
            var buf;
            try { buf = new Uint8Array(r.base.readByteArray(r.size)); }
            catch(e){ return; }
            for (var i = 0; i < buf.length - 4; i++){
                if (buf[i] !== 0xe8) continue;
                var rel = buf[i+1] | (buf[i+2]<<8) | (buf[i+3]<<16) | (buf[i+4]<<24);
                if (rel & 0x80000000) rel = rel - 0x100000000;
                var callSite = r.base.toUInt32() + i;
                var callTgt = (callSite + 5 + rel) >>> 0;
                if (callTgt === stepPtr.toUInt32()){
                    var p = findPrologueBefore(ptr(callSite), 512);
                    if (p) wrappers[p.toString()] = (wrappers[p.toString()]||0) + 1;
                }
            }
        });
        // sqlite3_step 是仅调用一次 sqlite3Step 的短小 wrapper
        // 取调用最集中的（其它调用 sqlite3Step 的函数可能是 sqlite3_reset 等）
        // 保守做法：候选中调用点数 >=1 都算，Python 侧再筛
        out.step = stepFunc;
        out.step_wrappers = Object.keys(wrappers);
    } else {
        out.notes.push('sqlite3_step marker strings all missed');
    }

    return out;
}

// -------- 阶段 2：hook 三件套 --------
function installHooks(){
    if (!ADDRS.bind_family || ADDRS.bind_family.length === 0){
        send({t:'err', msg:'bind_family empty'});
        return false;
    }

    // sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail) —— 可选
    // 若识别到的是 wwdb wrapper（thiscall + 少参数），Vdbe fallback 兜底
    if (ADDRS.prepare_v2){
    var pv2 = ptr(ADDRS.prepare_v2);
    Interceptor.attach(pv2, {
        onEnter: function(args){
            this.zSql = args[1];
            this.nByte = args[2].toInt32();
            this.ppStmt = args[3];
            this.tid = this.threadId;
        },
        onLeave: function(rc){
            try {
                var stmtPtr = null;
                try { stmtPtr = this.ppStmt.readPointer(); } catch(e){}
                var sql = null;
                if (this.zSql){
                    sql = readCString(this.zSql, this.nByte > 0 ? this.nByte : 4096);
                }
                if (stmtPtr && !stmtPtr.isNull() && sql){
                    var key = stmtPtr.toString();
                    STMT_TABLE[key] = {
                        sql: sql,
                        args: {},
                        prep_tid: this.tid,
                        prep_ts: Date.now(),
                    };
                    // 只报告我们感兴趣的 SQL，避免刷屏
                    if (/message_appinfo|conversation|message_table|upload_message/i.test(sql)){
                        send({t:'prepare', stmt: key, sql: sql, tid: this.tid,
                              rc: rc.toInt32()});
                    }
                }
            } catch(e){ send({t:'err', where:'prepare_v2.onLeave', msg: e.message}); }
        }
    });
    }  // end if (ADDRS.prepare_v2)

    // 从 stmt (Vdbe*) 内存里扫出原始 SQL 字符串
    // Vdbe.zSql offset 版本不同（常见 0x38..0x80），做启发式扫描
    function extractSqlFromStmt(stmtPtr){
        try {
            for (var off = 0; off < 512; off += 4){
                var v = 0;
                try { v = stmtPtr.add(off).readU32() >>> 0; }
                catch(e){ break; }
                if (v < 0x10000 || v >= 0xF0000000) continue;
                try {
                    var s = ptr(v).readCString(4096);
                    if (!s || s.length < 8) continue;
                    // SQL 首词判定
                    var head = s.substring(0, 12).toLowerCase();
                    if (head.indexOf('insert') === 0 ||
                        head.indexOf('replace') === 0 ||
                        head.indexOf('update') === 0 ||
                        head.indexOf('select') === 0 ||
                        head.indexOf('delete') === 0 ||
                        head.indexOf('begin') === 0 ||
                        head.indexOf('commit') === 0 ||
                        head.indexOf('rollback') === 0 ||
                        head.indexOf('create') === 0 ||
                        head.indexOf('with ') === 0){
                        return {sql: s, off: off};
                    }
                } catch(e){}
            }
        } catch(e){}
        return null;
    }

    // sqlite3_bind_* 家族：统一 attach，读取 stack 4 dwords
    // 常见签名：
    //   bind_null (stmt, idx)
    //   bind_int  (stmt, idx, int32)
    //   bind_int64(stmt, idx, int64)      ← 3rd+4th = i64 low/high
    //   bind_text (stmt, idx, ptr, n, xDel)
    //   bind_blob (stmt, idx, ptr, n, xDel)
    //   bind_double(stmt, idx, double)    ← 3rd+4th = double
    // 我们保留原始 4 个 dword，Python 结合 SQL 里 ? 数量 + 相邻 bind idx 单调递增来分派。
    ADDRS.bind_family.forEach(function(a, idx){
        try {
            var fp = ptr(a);
            Interceptor.attach(fp, {
                onEnter: function(args){
                    try {
                        var stmt = args[0];
                        var stmtKey = stmt.toString();
                        var st = STMT_TABLE[stmtKey];
                        if (!st){
                            // 从 Vdbe 结构里挖 SQL；只关心 message_appinfo /
                            // conversation_* / message_table / upload_message
                            var meta = extractSqlFromStmt(stmt);
                            if (!meta) return;
                            var sqlLow = meta.sql.toLowerCase();
                            if (sqlLow.indexOf('message_appinfo') < 0 &&
                                sqlLow.indexOf('conversation') < 0 &&
                                sqlLow.indexOf('message_table') < 0 &&
                                sqlLow.indexOf('upload_message') < 0){
                                return;
                            }
                            st = STMT_TABLE[stmtKey] = {
                                sql: meta.sql,
                                sql_off: meta.off,
                                args: {},
                                prep_tid: this.threadId,
                                prep_ts: Date.now(),
                                discovered_at_bind: true,
                            };
                            send({t:'prepare', stmt: stmtKey, sql: meta.sql,
                                  tid: this.threadId, discovered:true,
                                  vdbe_off:meta.off});
                        }
                        var bindIdx = args[1].toInt32();
                        // 读原始 4 个 dword (arg2..arg5)
                        var raw = [];
                        for (var i = 2; i < 6; i++){
                            try { raw.push('0x' + args[i].toUInt32().toString(16)); }
                            catch(e){ raw.push(null); }
                        }
                        // 试着 deref 成串
                        var asCStr = readCString(args[2], 4096);
                        var asU16  = readUtf16(args[2], 2048);
                        // int64 组合
                        var lo = args[2].toUInt32(), hi = 0;
                        try { hi = args[3].toUInt32(); } catch(e){}
                        // signed int64 (little endian)
                        var i64Approx = null;
                        if (hi === 0) i64Approx = lo;
                        else if (hi === 0xffffffff) i64Approx = -((~lo + 1) >>> 0);
                        else i64Approx = (hi * 4294967296) + lo;  // JS 精度损失可接受

                        // blob 尝试：SQLite 的 bindText/bindBlob 6 参签名为
                        //   (stmt, idx, ptr, n, xDel, encoding)
                        // 现代 SQLite 里 sqlite3_bind_blob 也走 bindText(enc=0)。
                        // 【旧代码 bug】当 arg2 前几字节看起来像 printable 时
                        // readCString 会返回一段"假 cstr"（遇到内部 NUL 就停），
                        // 导致 blobHex 被条件 `asCStr===null` 跳过 → appinfo
                        // 二进制 blob 永远抓不到。
                        // 【修复】只要 arg3 (n) 是合理 blob/text 长度就 dump
                        // hex，不再受 asCStr 是否为空影响；Python 侧按 SQL
                        // schema (message_appinfo ?3 = blob) 选用 blob_hex。
                        var n = 0;
                        try { n = args[3].toInt32(); } catch(e){}
                        var blobHex = null;
                        if (n > 0 && n <= 65536){
                            blobHex = hexBlob(args[2], n);
                        }
                        // encoding u8：SQLite 6 参签名的最后一个参数
                        //   0 = blob   (via sqlite3_bind_blob → bindText)
                        //   1 = SQLITE_UTF8
                        //   2 = SQLITE_UTF16LE
                        //   3 = SQLITE_UTF16BE
                        //   4 = SQLITE_UTF16
                        // 若非上述值，说明该 bind 变体不是 bindText/bindBlob，
                        // 忽略即可（Python 侧只在 encoding===0 时取 blob）。
                        var encU8 = null;
                        try {
                            var v = args[5].toUInt32() & 0xff;
                            if (v <= 4) encU8 = v;
                        } catch(e){}

                        var entry = {
                            variant: idx,
                            raw: raw,
                            i64: i64Approx,
                            cstr: asCStr,
                            u16: asU16,
                            n: n,
                            blob_hex: blobHex,
                            enc: encU8,
                            ts: Date.now(),
                        };
                        st.args[bindIdx] = entry;
                        // 立即 send —— 不再依赖 step 边界
                        send({t:'bind', stmt: stmtKey, sql: st.sql,
                              idx: bindIdx, val: entry, tid: this.threadId});
                    } catch(e){
                        send({t:'err', where:'bind.onEnter', msg:e.message});
                    }
                }
            });
        } catch(e){
            send({t:'err', where:'bind.attach', addr:a, msg:e.message});
        }
    });

    // sqlite3_step(stmt) → 完成一次 bind 组，dump
    if (ADDRS.step){
        try {
            Interceptor.attach(ptr(ADDRS.step), {
                onEnter: function(args){
                    var stmtKey = args[0].toString();
                    var st = STMT_TABLE[stmtKey];
                    if (!st) return;
                    // 快照
                    var snap = {
                        stmt: stmtKey,
                        sql: st.sql,
                        args: st.args,
                        tid: this.threadId,
                        ts: Date.now(),
                    };
                    send({t:'step', snap: snap});
                    // 清空 args，等待下一次 bind→step 循环
                    st.args = {};
                }
            });
        } catch(e){ send({t:'err', where:'step.attach', msg:e.message}); }
    }

    return true;
}

// -------- RPC 接口 --------
rpc.exports = {
    discover: function(anchors, unbindErr, stepErrs){
        return discoverAll(anchors, unbindErr, stepErrs);
    },
    setAddrs: function(addrs){
        ADDRS.prepare_v2 = addrs.prepare_v2 ? ptr(addrs.prepare_v2) : null;
        ADDRS.bind_family = (addrs.bind_family || []).map(function(x){ return ptr(x); });
        ADDRS.step = addrs.step ? ptr(addrs.step) : null;
        return true;
    },
    installHooks: function(){ return installHooks(); },
    bye: function(){ send({t:'bye', stmts: Object.keys(STMT_TABLE).length}); }
};

send({t:'ready'});
"""


# ─── Python 侧 ──────────────────────────────────────────────────────
@dataclass
class SqliteAddrs:
    base: str
    prepare_v2: Optional[str] = None
    bind_family: list[str] = field(default_factory=list)
    step: Optional[str] = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_cached_addrs() -> Optional[SqliteAddrs]:
    if not ADDR_CACHE.exists():
        return None
    try:
        d = json.loads(ADDR_CACHE.read_text(encoding="utf-8"))
        return SqliteAddrs(**d)
    except Exception as e:
        print(f"[!] cache load failed: {e}")
        return None


def save_cached_addrs(a: SqliteAddrs) -> None:
    ADDR_CACHE.write_text(json.dumps(a.as_dict(), ensure_ascii=False, indent=2),
                          encoding="utf-8")
    print(f"[+] addrs cached → {ADDR_CACHE.name}")


class NativeReadMsgId:
    """
    替代 `bubble_anchor.BubbleAnchorService` 里 UI 长按定位 msgid 的方案。

    工作方式：
      * 后台跑本脚本 hook SQLite；每次 step() 命中包含 `message_appinfo`
        INSERT 的 stmt 时，抽取 msgid / send_time_ms / appinfo_hex，
        以 send_time_ms 为主键写入 `_by_send_time`。
      * 上层（fta_code_echo / bubble_anchor.bind）不再走 UI 长按，
        改调 `wait_for_msgid(send_time_ms, timeout=15)`。
      * 同时维护 conversationId 映射（来自 UPDATE conversation_XXX SET ...
        或 bind_text 侧观察到的 "S:xxx_xxx" 串）。

    使用示例：
        native = NativeReadMsgId(persist=NATIVE_MAP)
        native.on_record(record)   # 由本脚本回调
        msgid = native.wait_for_msgid(send_time_ms=1789008677110, timeout=15)
    """

    _CONV_RE = re.compile(r"S:\d{16}_\d{16}")

    # 记录被这些 SQL 提供了完整字段的 msgid→字段映射，用于跨 SQL 补齐
    _MSGID_ENRICH_SQL = (
        "insert into message_table",
        "replace into message_sender_lookup_table",
        "insert or ignore into message_lookup_table",
        "update message_table",
    )

    def __init__(self, persist: Optional[Path] = None):
        self._by_send_time: dict[int, dict[str, Any]] = {}
        self._by_msgid: dict[int, dict[str, Any]] = {}
        self._latest_conv_id: Optional[str] = None
        self._latest_con_numeric_id: Optional[int] = None
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._persist = persist
        # 第十六轮：blob 抓取诊断计数（写入 summary 便于排查）
        self.stats: dict[str, int] = {
            "appinfo_records": 0,
            "appinfo_blob_from_hex": 0,
            "appinfo_blob_from_cstr": 0,
            "appinfo_blob_missed": 0,
            "enrich_records": 0,
            "conv_id_from_bind": 0,
        }
        if persist and persist.exists():
            try:
                d = json.loads(persist.read_text(encoding="utf-8"))
                self._by_send_time = {int(k): v for k, v in d.items()}
                for st, e in self._by_send_time.items():
                    m = e.get("msgid")
                    if isinstance(m, int):
                        self._by_msgid[m] = e
            except Exception:
                pass

    # 第十六轮：从 bind 记录里推 appinfo blob 的 hex 字符串。
    #
    # 优先级：
    #   1) v.blob_hex （JS 已就地 hex 编码；n∈[1,65536] 时必被填充）
    #   2) v.cstr     （极少数 blob 恰好可 c-string 解 → utf-8 编码后 hex）
    #   3) v.u16      （UTF-16 版本；同上）
    #   4) 都空 → None
    @staticmethod
    def _extract_appinfo_hex(v: dict[str, Any]) -> Optional[str]:
        hx = v.get("blob_hex")
        if isinstance(hx, str) and hx:
            return hx
        s = v.get("cstr")
        if isinstance(s, str) and s:
            try:
                return s.encode("utf-8", "surrogatepass").hex()
            except Exception:
                pass
        s16 = v.get("u16")
        if isinstance(s16, str) and s16:
            try:
                return s16.encode("utf-16-le", "surrogatepass").hex()
            except Exception:
                pass
        return None

    # 由 hook 侧调用
    def on_record(self, rec: dict[str, Any]) -> None:
        sql = (rec.get("sql") or "").lower()
        # JS 侧 Object 键在 JSON 中是字符串，这里统一按字符串 key 取
        args_raw = rec.get("args") or {}
        args: dict[str, dict[str, Any]] = {str(k): v for k, v in args_raw.items()}

        # 找 msgid + send_time
        msgid = None
        send_time = None
        appinfo_hex = None
        conv_id = None

        is_appinfo_ins = (
            ("message_appinfo" in sql and "insert" in sql)
            or ("replace into message_appinfo" in sql)
        )
        if is_appinfo_ins:
            # 通常按 SQL 里 ? 顺序：(msgid, send_time, appinfo)
            v1 = args.get("1") or {}
            v2 = args.get("2") or {}
            v3 = args.get("3") or {}
            msgid = v1.get("i64") if isinstance(v1.get("i64"), int) else None
            send_time = v2.get("i64") if isinstance(v2.get("i64"), int) else None
            # 第十六轮：三级兜底抓 blob
            #   1) JS 侧 hexBlob (n∈[1,65536]) —— 修 bug 后覆盖率 ~100%
            #   2) JS 侧 cstr 兜底 —— appinfo 若前缀恰好可打印则 fallback 到
            #      utf-8 hex（真实 blob 首字节多为 protobuf tag，罕见但兼容）
            #   3) 都空 → missed（计数用于诊断）
            appinfo_hex = self._extract_appinfo_hex(v3)
            self.stats["appinfo_records"] += 1
            if v3.get("blob_hex"):
                self.stats["appinfo_blob_from_hex"] += 1
            elif appinfo_hex:
                self.stats["appinfo_blob_from_cstr"] += 1
            else:
                self.stats["appinfo_blob_missed"] += 1

        # 无论哪种 SQL，都扫一遍 bind 里的字符串找 conversationId
        for _idx, v in args.items():
            for key in ("cstr", "u16"):
                s = v.get(key)
                if isinstance(s, str):
                    m = self._CONV_RE.search(s)
                    if m:
                        conv_id = m.group(0)
                        break
            if conv_id:
                break
        if conv_id:
            self.stats["conv_id_from_bind"] += 1

        # 从辅助 SQL 抽 (msgid, con_numeric_id, send_time) 用于补齐
        enrich_msgid: Optional[int] = None
        enrich_con_numeric: Optional[int] = None
        enrich_send_time: Optional[int] = None
        is_enrich = any(sql.startswith(k) for k in self._MSGID_ENRICH_SQL)
        if is_enrich:
            self.stats["enrich_records"] += 1
            # message_table INSERT 的字段顺序里 message_id 常在 ?1，
            # send_time / con_numeric_id 位置视语句而定；只做启发式提取：
            # · 找一个「合理 msgid」的 int：> 0 且 < 2^40（企微 msgid 范围）
            # · 找一个「合理 send_time_ms」：> 1e12 且 < 2e13
            # · 找一个「合理 con_numeric_id」：> 0 且 < 1e16
            for _idx, v in args.items():
                iv = v.get("i64")
                if not isinstance(iv, int):
                    continue
                if enrich_msgid is None and 0 < iv < (1 << 40):
                    enrich_msgid = iv
                    continue
                if enrich_send_time is None and 1_000_000_000_000 < iv < 20_000_000_000_000:
                    enrich_send_time = iv
                    continue
                if enrich_con_numeric is None and 0 < iv < 1_000_000_000_000_000_000:
                    enrich_con_numeric = iv

        with self._cond:
            if conv_id:
                self._latest_conv_id = conv_id
            if enrich_con_numeric is not None:
                self._latest_con_numeric_id = enrich_con_numeric

            # 1) 从 message_appinfo 主 SQL 落地
            if msgid is not None and send_time is not None:
                entry = self._by_send_time.setdefault(int(send_time), {})
                entry.update({
                    "msgid": int(msgid),
                    "send_time_ms": int(send_time),
                    "appinfo_hex": appinfo_hex or entry.get("appinfo_hex"),
                    "conversation_id": conv_id or entry.get("conversation_id")
                                        or self._latest_conv_id,
                    "con_numeric_id": entry.get("con_numeric_id")
                                        or self._latest_con_numeric_id,
                    "sql": rec.get("sql"),
                    "ts": rec.get("ts"),
                })
                self._by_msgid[int(msgid)] = entry
                self._cond.notify_all()
                self._flush()

            # 2) 从辅助 SQL 反向补齐已存在的 entry
            if enrich_msgid is not None and enrich_msgid in self._by_msgid:
                e = self._by_msgid[enrich_msgid]
                if enrich_con_numeric and not e.get("con_numeric_id"):
                    e["con_numeric_id"] = enrich_con_numeric
                if enrich_send_time and not e.get("send_time_ms"):
                    e["send_time_ms"] = enrich_send_time
                    self._by_send_time[enrich_send_time] = e
                if conv_id and not e.get("conversation_id"):
                    e["conversation_id"] = conv_id
                self._cond.notify_all()
                self._flush()

    def wait_for_msgid(self, send_time_ms: int, *, tolerance_ms: int = 2000,
                       timeout: float = 15.0) -> Optional[dict[str, Any]]:
        """返回 {msgid, send_time_ms, appinfo_hex, conversation_id, ...} or None。"""
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                hit = self._find_locked(send_time_ms, tolerance_ms)
                if hit:
                    return hit
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def latest_conversation_id(self) -> Optional[str]:
        with self._lock:
            return self._latest_conv_id

    def snapshot(self) -> dict[int, dict[str, Any]]:
        with self._lock:
            return dict(self._by_send_time)

    # ---- 内部 ----
    def _find_locked(self, target: int, tol: int) -> Optional[dict[str, Any]]:
        # 精确
        if target in self._by_send_time:
            return self._by_send_time[target]
        # 近似
        best = None
        best_delta = None
        for st, entry in self._by_send_time.items():
            d = abs(st - target)
            if d <= tol and (best_delta is None or d < best_delta):
                best = entry; best_delta = d
        return best

    def _flush(self) -> None:
        if not self._persist:
            return
        try:
            d = {str(k): v for k, v in self._by_send_time.items()}
            self._persist.write_text(json.dumps(d, ensure_ascii=False, indent=2),
                                     encoding="utf-8")
        except Exception:
            pass


# ─── 主流程 ─────────────────────────────────────────────────────────
def _fmt(addr: Optional[str]) -> str:
    return addr if addr else "<none>"


def do_discover(script: "frida.core.Script") -> SqliteAddrs:
    print("[*] discovery: scanning .rdata anchors + xrefs ...")
    anchors = [m.decode("latin-1") for m in SQL_ANCHORS]
    step_errs = [m.decode("latin-1") for m in STEP_ERR_CANDIDATES]
    result = script.exports_sync.discover(anchors, UNBIND_ERR.decode("latin-1"), step_errs)

    base = None
    # info 消息里已发过 base；也可以从 script 拿。这里再问一次也行，简化不管。
    a = SqliteAddrs(
        base=str(base),
        prepare_v2=result.get("prepare_v2"),
        bind_family=result.get("bind_family") or [],
        step=result.get("step"),
        notes=result.get("notes") or [],
    )
    print(f"[+] prepare_v2  = {_fmt(a.prepare_v2)}   (votes={result.get('prepare_v2_votes')})")
    print(f"[+] vdbeUnbind  = {_fmt(result.get('vdbe_unbind'))}")
    print(f"[+] bind_family = {len(a.bind_family)} candidates")
    for x in a.bind_family:
        print(f"       {x}")
    print(f"[+] step        = {_fmt(a.step)}")
    for n in a.notes:
        print(f"    · note: {n}")
    return a


def run(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reuse", action="store_true", help="使用 sqlite_addrs.json 缓存")
    ap.add_argument("--discover-only", action="store_true")
    ap.add_argument("--duration", type=int, default=900,
                    help="最长运行秒数（默认 900s / 15min）")
    ap.add_argument("--pid", type=int, default=None, help="覆盖自动 PID 检测")
    args = ap.parse_args(argv)

    pid = args.pid or get_wxwork_pid()
    print(f"[*] attaching PID = {pid}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_path = OUT_DIR / f"sqlite_bind_{ts}.ndjson"
    summary_path = OUT_DIR / f"sqlite_bind_summary_{ts}.json"
    if SENTINEL.exists():
        SENTINEL.unlink()

    native = NativeReadMsgId(persist=NATIVE_MAP)
    stmt_sql_by_key: dict[str, str] = {}
    step_records: list[dict[str, Any]] = []
    prepare_count = 0
    step_count = 0

    # bind 事件聚合：{stmt: {"sql":..., "args":{idx:val}, "tid":..., "ts":...}}
    bind_agg: dict[str, dict[str, Any]] = {}

    ndjson_fp = ndjson_path.open("a", encoding="utf-8")

    def flush_stmt(stmt_key: str, reason: str) -> None:
        nonlocal step_count
        rec = bind_agg.pop(stmt_key, None)
        if not rec or not rec.get("args"):
            return
        step_count += 1
        snap = {
            "stmt": stmt_key,
            "sql": rec.get("sql_clean") or rec["sql"],
            "sql_raw": rec["sql"],
            "args": rec["args"],
            "tid": rec.get("tid"),
            "ts": rec.get("ts"),
            "flush": reason,
        }
        step_records.append(snap)
        ndjson_fp.write(json.dumps(snap, ensure_ascii=False) + "\n")
        ndjson_fp.flush()
        native.on_record(snap)
        sql_short = (snap["sql"] or "")[:120]
        print(f"  flush #{step_count} [{reason}] tid={snap['tid']} sql={sql_short!r}")
        for idx, v in sorted(snap["args"].items(), key=lambda x: int(x[0])):
            short = {kk: (vv if not isinstance(vv, str) or len(vv) < 120
                          else vv[:120] + "...")
                     for kk, vv in v.items() if vv not in (None, "")
                     and kk in ("i64", "cstr", "u16", "n", "blob_hex")}
            print(f"      ?{idx} = {short}")


    def on_message(msg, _data):
        nonlocal prepare_count, step_count
        if msg.get("type") == "error":
            print(f"[JS ERROR] {msg.get('description')}")
            return
        if msg.get("type") != "send":
            return
        p = msg["payload"]
        t = p.get("t")
        if t == "info":
            print(f"[JS] {p.get('msg')}")
        elif t == "err":
            print(f"[JS ERR@{p.get('where')}] {p.get('msg')}")
        elif t == "prepare":
            prepare_count += 1
            stmt_sql_by_key[p["stmt"]] = p["sql"]
            print(f"  prep #{prepare_count} stmt={p['stmt']} tid={p['tid']}")
            print(f"    SQL: {p['sql'][:180]}")
        elif t == "bind":
            stmt_key = p["stmt"]
            idx = int(p["idx"])
            agg = bind_agg.get(stmt_key)
            # idx 复位（新一轮 bind）→ 先 flush 上一轮
            if agg and idx == 1 and agg.get("args"):
                flush_stmt(stmt_key, reason="idx-reset")
                agg = None
            if agg is None:
                agg = bind_agg[stmt_key] = {
                    "sql": p["sql"],
                    "args": {},
                    "tid": p["tid"],
                    "ts": p["val"].get("ts"),
                }
            agg["args"][str(idx)] = p["val"]
            # 计算 ? 数量：截到第一个 ';' 或第一个非 ASCII 字节，避免 Vdbe 尾部垃圾干扰
            raw_sql = agg["sql"]
            trim_end = len(raw_sql)
            sc = raw_sql.find(";")
            if sc >= 0:
                trim_end = min(trim_end, sc + 1)
            for i, ch in enumerate(raw_sql[:trim_end]):
                if not (0x20 <= ord(ch) <= 0x7e):
                    trim_end = i; break
            sql_clean = raw_sql[:trim_end]
            agg["sql_clean"] = sql_clean
            q_count = sql_clean.count("?")
            if q_count > 0 and len(agg["args"]) >= q_count:
                flush_stmt(stmt_key, reason="all-bound")
        elif t == "step":
            step_count += 1
            snap = p["snap"]
            step_records.append(snap)
            ndjson_fp.write(json.dumps(snap, ensure_ascii=False) + "\n")
            ndjson_fp.flush()
            native.on_record(snap)
            sql_short = (snap.get("sql") or "")[:120]
            args_short = {k: {kk: vv for kk, vv in v.items()
                              if kk in ("i64", "cstr", "u16", "n")}
                          for k, v in (snap.get("args") or {}).items()}
            print(f"  step #{step_count} tid={snap.get('tid')} sql={sql_short!r}")
            for idx, v in sorted(args_short.items(), key=lambda x: int(x[0])):
                short = {kk: (vv if not isinstance(vv, str) or len(vv) < 120
                              else vv[:120] + "...")
                         for kk, vv in v.items() if vv not in (None, "")}
                print(f"      ?{idx} = {short}")
        elif t == "bye":
            print(f"[BYE] JS reports stmts={p.get('stmts')}")

    import frida  # 延迟导入：只在实际 run() 时才需要 frida 环境
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    script.on("message", on_message)
    script.load()
    time.sleep(0.5)  # 等待 'ready'

    # 发现或复用
    addrs: Optional[SqliteAddrs] = None
    if args.reuse:
        addrs = load_cached_addrs()
        if addrs is None:
            print("[!] --reuse 但 sqlite_addrs.json 不存在；转入自动发现")
    if addrs is None:
        addrs = do_discover(script)
        save_cached_addrs(addrs)

    if not addrs.prepare_v2:
        print("[!] prepare_v2 未找到；将仅依赖 bind 阶段从 Vdbe 结构挖 SQL")
    if not addrs.bind_family:
        print("[X] 未定位 sqlite3_bind_* 家族，退出")
        script.unload(); session.detach()
        return 3

    if args.discover_only:
        print("[*] --discover-only 完成，退出")
        script.unload(); session.detach()
        return 0

    # 注入地址 + 安装 hook
    ok = script.exports_sync.set_addrs({
        "prepare_v2": addrs.prepare_v2,
        "bind_family": addrs.bind_family,
        "step": addrs.step,
    })
    if not ok:
        print("[X] set_addrs 失败"); script.unload(); session.detach(); return 4
    ok = script.exports_sync.install_hooks()
    if not ok:
        print("[X] install_hooks 失败"); script.unload(); session.detach(); return 5

    print()
    print("=" * 72)
    print(">>> hook 已就位。请在企微中操作：")
    print(">>>   Round A: 转发到 FTA（自己）")
    print(">>>   Round B: 转发到任意外部联系人（用于 A/B 差分 conversationId）")
    print(f">>> 完成后 `New-Item {SENTINEL.name}` 触发结束，或最长 {args.duration}s")
    print("=" * 72)
    print()

    t0 = time.time()
    last_hb = t0
    try:
        while not SENTINEL.exists() and time.time() - t0 < args.duration:
            time.sleep(0.5)
            if time.time() - last_hb > 30:
                last_hb = time.time()
                print(f"  [hb] elapsed={int(time.time()-t0)}s "
                      f"prep={prepare_count} step={step_count} "
                      f"map={len(native.snapshot())}")
    except KeyboardInterrupt:
        print("[!] KeyboardInterrupt")

    if SENTINEL.exists():
        try: SENTINEL.unlink()
        except OSError: pass

    try:
        script.exports_sync.bye()
        time.sleep(0.5)
    except Exception:
        pass

    ndjson_fp.close()

    summary = {
        "pid": pid,
        "ts": ts,
        "addrs": addrs.as_dict(),
        "counts": {"prepare": prepare_count, "step": step_count},
        "captured_map_size": len(native.snapshot()),
        "latest_conversation_id": native.latest_conversation_id(),
        # 第十六轮：blob 抓取诊断（用于评估 JS 侧 hexBlob 修复覆盖率）
        "native_stats": dict(native.stats),
        "sample_records": step_records[:20],
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                            encoding="utf-8")
    print(f"[+] ndjson  : {ndjson_path.name}  ({step_count} records)")
    print(f"[+] summary : {summary_path.name}")
    print(f"[+] map     : {NATIVE_MAP.name}  ({len(native.snapshot())} send_time keys)")

    try:
        script.unload(); session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(run())

# m2c_cdn_upload.py — B 路线 M2c · NativeFunction 触发 FileService::CdnUploadFile
# =============================================================================
#
# 目标：不 hook、不依赖手机发语音，程序侧直接：
#   stage silk → 构造 CdnUploadParam → NativeFunction 调 CdnUploadFile
#   → 扫堆确认 CdnUploadFileTask → 可选 conv hijack
#
# 严格约束：禁止 Interceptor.attach / .replace；只允许只读扫 + NativeFunction + 定长 heap 写。
#
# 子命令：
#   recon   找 FileService 单例、CdnUploadFile 入口、CdnUploadParam 布局
#   call    用 recon 产物构造 param 并 NativeFunction 调用
#   run     stage + recon(如缺) + call + 短窗 watch/hijack
#
# 签名（RTTI 已确认，MSVC 32-bit thiscall）：
#   void FileService::CdnUploadFile(
#       CdnUploadParam const&,
#       Callback<void(bool, string const&, string const&, string const&)> const&,
#       Callback<void(string const&, unsigned, unsigned)> const&);
# =============================================================================

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"
RECON_CACHE = OUT_DIR / "m2c_cdn_recon.json"

from cdn_task_constants import (  # noqa: E402
    CDN_UPLOAD_VTABLES,
    POST_SEND_MESSAGE_TASK2,
    WATCH_VTABLES,
)
from poc_voice_cdn_inject import (  # noqa: E402
    _find_account_dir,
    _find_wxwork_pid,
    _resolve_staged_silk,
    stage_silk,
)

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('wxwork.exe not loaded');
const WXBASE = wx.base;
const WXSIZE = wx.size;
const WXBASE_U32 = WXBASE.toUInt32();
const WXEND = WXBASE_U32 + WXSIZE;
send({t:'info', msg:'wx base=' + WXBASE + ' size=0x' + WXSIZE.toString(16)});

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function safeCstr(p, cap){ try { return p.readCString(cap || 256); } catch(e){ return null; } }
function isWxPtr(v){ return v >= WXBASE_U32 && v < WXEND; }

function strToPat(s){
    let p = '';
    for (let i = 0; i < s.length; i++){
        p += (i ? ' ' : '') + s.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return p;
}
function u32ToPat(v){
    return [
        (v & 0xff).toString(16).padStart(2, '0'),
        ((v >>> 8) & 0xff).toString(16).padStart(2, '0'),
        ((v >>> 16) & 0xff).toString(16).padStart(2, '0'),
        ((v >>> 24) & 0xff).toString(16).padStart(2, '0')
    ].join(' ');
}
function vtPattern(rva){
    return u32ToPat(WXBASE.add(rva).toUInt32());
}

function findExactRtti(exactName){
    // exactName: ".?AVFileService@@"  （必须整串匹配，避免 FileServiceImpl 误伤）
    let hits;
    try { hits = Memory.scanSync(WXBASE, WXSIZE, strToPat(exactName)); }
    catch(e){ return {err:'scan failed '+e.message, vtables:[]}; }
    const rec = {name: exactName, td_name_hits: hits.length, vtables:[]};
    for (let i = 0; i < hits.length; i++){
        const nameVA = hits[i].address;
        const got = safeCstr(nameVA, 128);
        if (got !== exactName) continue;
        const tdVA = nameVA.sub(8);
        let tdRefs;
        try { tdRefs = Memory.scanSync(WXBASE, WXSIZE, u32ToPat(tdVA.toUInt32())); }
        catch(e){ continue; }
        for (let j = 0; j < tdRefs.length; j++){
            const colVA = tdRefs[j].address.sub(0xc);
            const sig = u32(colVA);
            if (sig !== 0 && sig !== 1) continue;
            let colRefs;
            try { colRefs = Memory.scanSync(WXBASE, WXSIZE, u32ToPat(colVA.toUInt32())); }
            catch(e){ continue; }
            for (let k = 0; k < colRefs.length; k++){
                const vtableVA = colRefs[k].address.add(4);
                const rva = vtableVA.toUInt32() - WXBASE_U32;
                rec.vtables.push({
                    va: vtableVA.toString(),
                    rva: '0x' + rva.toString(16),
                    slot0: '0x' + u32(vtableVA).toString(16),
                });
            }
        }
    }
    return rec;
}

function dumpSlots(vtableRva, n){
    const vt = WXBASE.add(vtableRva);
    const slots = [];
    for (let i = 0; i < n; i++){
        const fn = u32(vt.add(i * 4));
        slots.push({
            i: i,
            fn: '0x' + fn.toString(16),
            rva: isWxPtr(fn) ? ('0x' + (fn - WXBASE_U32).toString(16)) : null,
        });
    }
    return slots;
}

function tryStdString(base){
    let ptrOrSso, size, cap;
    try {
        ptrOrSso = u32(base);
        size = u32(base.add(0x10));
        cap  = u32(base.add(0x14));
    } catch(e){ return null; }
    if (size > 0x10000 || cap > 0x400000 || cap < size) return null;
    if (size === 0) return {kind:'empty', size:0, cap:cap, str:''};
    let dataPtr = base;
    if (size > 15){
        if (ptrOrSso < 0x10000) return null;
        dataPtr = ptr(ptrOrSso);
    }
    let bytes;
    try { bytes = new Uint8Array(dataPtr.readByteArray(size)); }
    catch(e){ return null; }
    let s = '';
    for (let i = 0; i < size; i++){
        const b = bytes[i];
        s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '?';
    }
    return {kind: size<=15?'sso':'heap', size:size, cap:cap, str:s, data_ptr:dataPtr.toString()};
}

function scanFnHints(fnVA, maxBytes, interestingImm){
    const hints = {strings:[], imm_hits:[], first_insns:[]};
    if (!isWxPtr(fnVA)) return hints;
    let cur = ptr(fnVA);
    let walked = 0;
    for (let n = 0; n < 96 && walked < maxBytes; n++){
        let ins;
        try { ins = Instruction.parse(cur); }
        catch(e){ break; }
        if (n < 8) hints.first_insns.push(ins.mnemonic + ' ' + ins.opStr);
        for (let oi = 0; oi < ins.operands.length; oi++){
            const op = ins.operands[oi];
            if (op.type !== 'imm') continue;
            const v = op.value >>> 0;
            if (!isWxPtr(v)) continue;
            const s = safeCstr(ptr(v), 120);
            if (s && s.length >= 4 && s.length < 100){
                hints.strings.push(s);
            }
            for (let k = 0; k < interestingImm.length; k++){
                if (v === interestingImm[k]){
                    hints.imm_hits.push('0x'+v.toString(16));
                }
            }
        }
        if (ins.mnemonic === 'ret') break;
        walked += ins.size;
        cur = cur.add(ins.size);
    }
    return hints;
}

function heapScanVtable(rva, maxHits){
    const pat = vtPattern(rva);
    const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
    const addrs = [];
    for (let i = 0; i < ranges.length && addrs.length < maxHits; i++){
        const r = ranges[i];
        if (r.file) continue;
        if (r.size < 0x1000 || r.size > 0x8000000) continue;
        let ms;
        try { ms = Memory.scanSync(r.base, r.size, pat); }
        catch(e){ continue; }
        for (let j = 0; j < ms.length && addrs.length < maxHits; j++){
            addrs.push(ms[j].address.toString());
        }
    }
    return addrs;
}

function scanAsciiHits(needle, maxHits, around){
    const pat = strToPat(needle);
    let hits;
    try { hits = Memory.scanSync(WXBASE, WXSIZE, pat); }
    catch(e){ return []; }
    const out = [];
    for (let i = 0; i < hits.length && i < maxHits; i++){
        const p = hits[i].address;
        const rec = {va: p.toString(), rva:'0x'+(p.toUInt32()-WXBASE_U32).toString(16)};
        rec.cstr = safeCstr(p, 160);
        // 周边可打印串
        const tokens = [];
        try {
            const raw = new Uint8Array(p.sub(around).readByteArray(around * 2 + needle.length));
            let cur = '';
            for (let b = 0; b < raw.length; b++){
                if (raw[b] >= 0x20 && raw[b] <= 0x7e) cur += String.fromCharCode(raw[b]);
                else {
                    if (cur.length >= 3) tokens.push(cur);
                    cur = '';
                }
            }
            if (cur.length >= 3) tokens.push(cur);
        } catch(e){}
        rec.nearby = tokens.slice(0, 40);
        out.push(rec);
    }
    return out;
}

function findCtorByVtableWrite(vtableRva, maxHits){
    // 扫 .text 里出现该 vtable VA 的立即数 → 多半是 ctor/dtor 写 vptr
    const vtVA = WXBASE.add(vtableRva).toUInt32();
    let refs;
    try { refs = Memory.scanSync(WXBASE, WXSIZE, u32ToPat(vtVA)); }
    catch(e){ return []; }
    const out = [];
    for (let i = 0; i < refs.length && out.length < maxHits; i++){
        const site = refs[i].address;
        const rva = site.toUInt32() - WXBASE_U32;
        // 回溯最多 0x40 找常见 prologue
        let fn = null;
        for (let back = 0; back <= 0x40; back += 1){
            const p = site.sub(back);
            try {
                const b0 = p.readU8();
                const b1 = p.add(1).readU8();
                // 55 8B EC  push ebp; mov ebp,esp
                // 55 89 E5
                // 56 8B F1  push esi; mov esi,ecx
                if ((b0 === 0x55 && b1 === 0x8b) || (b0 === 0x55 && b1 === 0x89) ||
                    (b0 === 0x56 && b1 === 0x8b) || (b0 === 0x53 && b1 === 0x56)){
                    fn = p;
                    break;
                }
            } catch(e){ break; }
        }
        out.push({
            site: site.toString(),
            site_rva: '0x'+rva.toString(16),
            fn: fn ? fn.toString() : null,
            fn_rva: fn ? ('0x'+(fn.toUInt32()-WXBASE_U32).toString(16)) : null,
        });
    }
    return out;
}

function writeStdString(base, s){
    const n = s.length;
    const bytes = [];
    for (let i = 0; i < n; i++) bytes.push(s.charCodeAt(i) & 0xff);
    if (n <= 15){
        const buf = new Uint8Array(16);
        for (let i = 0; i < n; i++) buf[i] = bytes[i];
        base.writeByteArray(buf.buffer);
        base.add(0x10).writeU32(n);
        base.add(0x14).writeU32(15);
        return {ok:true, kind:'sso', n:n};
    }
    const heap = Memory.alloc(n + 1);
    heap.writeByteArray(bytes);
    heap.add(n).writeU8(0);
    base.writeU32(heap.toUInt32());
    base.add(0x10).writeU32(n);
    base.add(0x14).writeU32(n);
    return {ok:true, kind:'heap', n:n, ptr:heap.toString()};
}

rpc.exports = {
    recon: function(cfgJson){
        const cfg = JSON.parse(cfgJson || '{}');
        const slotN = cfg.slot_n || 48;
        const uploadTaskRva = cfg.upload_task_rva || 0xb48ca88;

        const classes = [
            '.?AVFileService@@',
            '.?AVFileServiceWinMember@@',
            '.?AVFileServiceImpl@logic@wework@@',
            '.?AVFileService@logic@wework@@',
            '.?AVCdnUploadParam@pb@@',
            '.?AVCdnDownloadParam@pb@@',
        ];
        const rtti = {};
        for (let i = 0; i < classes.length; i++){
            send({t:'info', msg:'rtti '+classes[i]});
            rtti[classes[i]] = findExactRtti(classes[i]);
        }

        function firstRva(name){
            const v = (rtti[name] && rtti[name].vtables) || [];
            return v.length ? parseInt(v[0].rva, 16) : 0;
        }

        const fsRva = firstRva('.?AVFileService@@');
        const winRva = firstRva('.?AVFileServiceWinMember@@');
        const implRva = firstRva('.?AVFileServiceImpl@logic@wework@@');
        const logicFsRva = firstRva('.?AVFileService@logic@wework@@');
        const paramRva = firstRva('.?AVCdnUploadParam@pb@@');

        const uploadTaskVA = WXBASE.add(uploadTaskRva).toUInt32();
        const interesting = [uploadTaskVA];
        if (paramRva) interesting.push(WXBASE.add(paramRva).toUInt32());

        function analyzeVtable(name, rva){
            if (!rva) return null;
            const slots = dumpSlots(rva, slotN);
            const interestingSlots = [];
            for (let i = 0; i < slots.length; i++){
                const fn = parseInt(slots[i].fn, 16);
                const h = scanFnHints(fn, 0x280, interesting);
                const joined = (h.strings || []).join('\n');
                const hit =
                    h.imm_hits.length > 0 ||
                    /CdnUpload|upload_cdn|CdnUploadParam|\.silk|Cache\\Voice|file_path|file_type/i.test(joined);
                if (hit){
                    interestingSlots.push({
                        i: i,
                        fn: slots[i].fn,
                        rva: slots[i].rva,
                        strings: h.strings.slice(0, 12),
                        imm_hits: h.imm_hits,
                        first_insns: h.first_insns,
                    });
                }
            }
            return {rva:'0x'+rva.toString(16), n_slots:slots.length, slots:slots, interesting:interestingSlots};
        }

        send({t:'info', msg:'analyze FileService vtable'});
        const fsVt = analyzeVtable('FileService', fsRva);
        send({t:'info', msg:'analyze FileServiceWinMember vtable'});
        const winVt = analyzeVtable('FileServiceWinMember', winRva);
        send({t:'info', msg:'analyze FileServiceImpl vtable'});
        const implVt = analyzeVtable('FileServiceImpl', implRva);

        send({t:'info', msg:'heap scan singletons'});
        const heap = {
            FileService: fsRva ? heapScanVtable(fsRva, 8) : [],
            FileServiceWinMember: winRva ? heapScanVtable(winRva, 8) : [],
            FileServiceImpl: implRva ? heapScanVtable(implRva, 8) : [],
            FileService_logic: logicFsRva ? heapScanVtable(logicFsRva, 8) : [],
        };

        send({t:'info', msg:'scan CdnUploadParam strings'});
        const paramHits = scanAsciiHits('CdnUploadParam', 8, 0x180);
        const cppHits = scanAsciiHits('upload_cdn_file_task2.cpp', 6, 0x80);
        const fieldNeedles = [
            'file_path','local_path','file_type','file_size','aes_key','file_id','fileid',
            'voice_time','play_time','conversation_id','md5','file_key','thumb_path',
            'CdnFileType','kVoice','VOICE'
        ];
        const fieldHits = {};
        for (let i = 0; i < fieldNeedles.length; i++){
            fieldHits[fieldNeedles[i]] = scanAsciiHits(fieldNeedles[i], 4, 0x40);
        }

        send({t:'info', msg:'find CdnUploadParam ctor'});
        const paramCtors = paramRva ? findCtorByVtableWrite(paramRva, 12) : [];

        // proto descriptor: 搜索 0a 0e "CdnUploadParam"  (len=14)
        let protoDesc = [];
        try {
            const descHits = Memory.scanSync(WXBASE, WXSIZE, '0a 0e 43 64 6e 55 70 6c 6f 61 64 50 61 72 61 6d');
            for (let i = 0; i < descHits.length && i < 4; i++){
                const p = descHits[i].address;
                protoDesc.push({
                    va: p.toString(),
                    rva: '0x'+(p.toUInt32()-WXBASE_U32).toString(16),
                    nearby: scanAsciiHits('CdnUploadParam', 1, 0)[0] ? null : null,
                    hex: Array.from(new Uint8Array(p.sub(8).readByteArray(256))).map(function(b){
                        return b.toString(16).padStart(2,'0');
                    }).join(' '),
                    ascii: (function(){
                        const u = new Uint8Array(p.sub(8).readByteArray(256));
                        let s='';
                        for (let k=0;k<u.length;k++) s += (u[k]>=0x20&&u[k]<0x7f)?String.fromCharCode(u[k]):'.';
                        return s;
                    })()
                });
            }
        } catch(e){}

        return {
            wx_base: WXBASE.toString(),
            wx_size: '0x'+WXSIZE.toString(16),
            rtti: rtti,
            vtables: {
                FileService: fsVt,
                FileServiceWinMember: winVt,
                FileServiceImpl: implVt,
                FileService_logic_rva: logicFsRva ? ('0x'+logicFsRva.toString(16)) : null,
                CdnUploadParam_rva: paramRva ? ('0x'+paramRva.toString(16)) : null,
            },
            heap: heap,
            param_string_hits: paramHits,
            cpp_hits: cppHits,
            field_hits: fieldHits,
            param_ctors: paramCtors,
            proto_desc: protoDesc,
        };
    },

    probeUpload: function(vtablesJson){
        const vtables = JSON.parse(vtablesJson);
        const byClass = {};
        let total = 0;
        const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
        for (let i = 0; i < vtables.length; i++){
            const pat = vtPattern(vtables[i].rva);
            let n = 0;
            for (let ri = 0; ri < ranges.length; ri++){
                const r = ranges[ri];
                try { n += Memory.scanSync(r.base, r.size, pat).length; }
                catch(e){}
            }
            byClass[vtables[i].name] = n;
            total += n;
        }
        return {total: total, byClass: byClass};
    },

    callUpload: function(cfgJson){
        const cfg = JSON.parse(cfgJson);
        const result = {ok:false, steps:[]};

        const thisPtr = ptr(cfg.this_va);
        const fnPtr = ptr(cfg.fn_va);
        const paramSize = cfg.param_size || 0x200;
        const ctorVa = cfg.ctor_va || null;
        const silkPath = cfg.silk_path || '';
        const filename = cfg.filename || '';
        const md5 = cfg.md5 || '';
        const fileType = cfg.file_type || 5;  // 先按常见 voice/file 枚举试，recon 后可改
        const conv = cfg.conv || 'FILEASSIST';
        const dry = !!cfg.dry_run;
        const fieldMap = cfg.field_map || {};  // {name: offset}

        result.steps.push('alloc param '+paramSize);
        const param = Memory.alloc(paramSize);
        Memory.protect(param, paramSize, 'rw-');
        for (let i = 0; i < paramSize; i += 4) param.add(i).writeU32(0);

        if (ctorVa){
            result.steps.push('call ctor '+ctorVa);
            try {
                const ctor = new NativeFunction(ptr(ctorVa), 'pointer', ['pointer'], 'thiscall');
                ctor(param);
                result.ctor_ok = true;
                result.param_vt = '0x'+u32(param).toString(16);
            } catch(e){
                result.ctor_ok = false;
                result.ctor_err = e.message;
                return result;
            }
        } else if (cfg.param_vtable_va){
            param.writeU32(ptr(cfg.param_vtable_va).toUInt32());
            result.steps.push('wrote param vtable without ctor');
        } else {
            result.err = 'no ctor and no param vtable';
            return result;
        }

        function setField(name, kind, value){
            if (fieldMap[name] === undefined || fieldMap[name] === null) return false;
            const off = fieldMap[name];
            const p = param.add(off);
            if (kind === 'string'){
                writeStdString(p, String(value));
                return true;
            }
            if (kind === 'u32'){
                p.writeU32(value >>> 0);
                return true;
            }
            return false;
        }

        const applied = [];
        if (setField('file_path', 'string', silkPath)) applied.push('file_path');
        if (setField('local_path', 'string', silkPath)) applied.push('local_path');
        if (setField('filename', 'string', filename)) applied.push('filename');
        if (setField('md5', 'string', md5)) applied.push('md5');
        if (setField('file_id', 'string', md5)) applied.push('file_id');
        if (setField('conversation_id', 'string', conv)) applied.push('conversation_id');
        if (setField('file_type', 'u32', fileType)) applied.push('file_type');
        if (setField('file_size', 'u32', cfg.file_size || 0)) applied.push('file_size');
        result.applied_fields = applied;

        // 若 recon 还没给出 field_map：启发式扫 ctor 后对象，把空 std::string 槽记下来
        const strings = [];
        for (let off = 4; off + 0x18 <= paramSize; off += 4){
            const s = tryStdString(param.add(off));
            if (s) strings.push({off:'0x'+off.toString(16), ...s});
        }
        result.param_strings_before = strings;

        // 没有 field_map 时：把第一条 empty std::string 写成 silk 路径（常见 file_path 在前部）
        if (!applied.length && silkPath){
            for (let i = 0; i < strings.length; i++){
                if (strings[i].size === 0 && (strings[i].cap === 0 || strings[i].cap === 15)){
                    writeStdString(param.add(parseInt(strings[i].off, 16)), silkPath);
                    applied.push('heuristic_first_empty_str=' + strings[i].off);
                    break;
                }
            }
            result.applied_fields = applied;
        }

        const cbDone = Memory.alloc(0x20);
        const cbProg = Memory.alloc(0x20);
        for (let i = 0; i < 0x20; i += 4){ cbDone.add(i).writeU32(0); cbProg.add(i).writeU32(0); }

        result.this_va = thisPtr.toString();
        result.fn_va = fnPtr.toString();
        result.param_va = param.toString();
        result.cb_done = cbDone.toString();
        result.cb_prog = cbProg.toString();

        if (dry){
            result.ok = true;
            result.dry_run = true;
            result.steps.push('dry-run: skip NativeFunction');
            return result;
        }

        result.steps.push('NativeFunction thiscall CdnUploadFile');
        try {
            const fn = new NativeFunction(fnPtr, 'void',
                ['pointer', 'pointer', 'pointer', 'pointer'], 'thiscall');
            fn(thisPtr, param, cbDone, cbProg);
            result.ok = true;
            result.called = true;
        } catch(e){
            result.ok = false;
            result.call_err = e.message;
        }
        return result;
    },

    watchShort: function(cfgJson){
        const cfg = JSON.parse(cfgJson);
        const vtables = cfg.vtables || [];
        const durationMs = cfg.duration_ms || 8000;
        const patchConv = cfg.patch_conv || '';
        const postSendRva = cfg.post_send_rva || 0;
        const patterns = [];
        for (let i = 0; i < vtables.length; i++){
            patterns.push({name:vtables[i].name, rva:vtables[i].rva, bytes: vtPattern(vtables[i].rva)});
        }
        const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
        const priv = [];
        for (let i = 0; i < ranges.length; i++){
            if (ranges[i].file) continue;
            if (ranges[i].size < 0x1000 || ranges[i].size > 0x8000000) continue;
            priv.push(ranges[i]);
        }
        const seen = {};
        const dumps = [];
        const patches = [];
        const t0 = Date.now();
        let scans = 0;
        while (Date.now() - t0 < durationMs){
            scans++;
            for (let p = 0; p < patterns.length; p++){
                const pat = patterns[p];
                for (let ri = 0; ri < priv.length; ri++){
                    let ms;
                    try { ms = Memory.scanSync(priv[ri].base, priv[ri].size, pat.bytes); }
                    catch(e){ continue; }
                    for (let j = 0; j < ms.length; j++){
                        const key = pat.name+'@'+ms[j].address.toString();
                        if (seen[key]) continue;
                        seen[key] = true;
                        const addr = ms[j].address;
                        const strings = [];
                        for (let off = 0; off + 0x18 <= 0x400; off += 4){
                            const s = tryStdString(addr.add(off));
                            if (s && s.size >= 1) strings.push({off:'0x'+off.toString(16), str:s.str});
                        }
                        dumps.push({class_name:pat.name, addr:addr.toString(), strings:strings.slice(0,20)});
                        send({t:'cdn_task', class_name:pat.name, addr:addr.toString(), n_str:strings.length});
                    }
                }
            }
            if (patchConv && postSendRva){
                const postPat = vtPattern(postSendRva);
                for (let ri = 0; ri < priv.length; ri++){
                    let ms;
                    try { ms = Memory.scanSync(priv[ri].base, priv[ri].size, postPat); }
                    catch(e){ continue; }
                    for (let j = 0; j < ms.length; j++){
                        const task = ms[j].address;
                        const pkgPtr = u32(task.add(0x30));
                        if (!pkgPtr || pkgPtr < 0x10000) continue;
                        const convBase = ptr(pkgPtr).add(0x28);
                        const conv = tryStdString(convBase);
                        if (!conv || conv.size !== patchConv.length) continue;
                        const key = 'PostSend@'+task.toString();
                        if (seen[key]) continue;
                        seen[key] = true;
                        try {
                            const arr = new Uint8Array(patchConv.length);
                            for (let i = 0; i < patchConv.length; i++) arr[i] = patchConv.charCodeAt(i);
                            ptr(conv.data_ptr).writeByteArray(arr.buffer);
                            patches.push({task:task.toString(), from:conv.str, to:patchConv, ok:true});
                        } catch(e){
                            patches.push({task:task.toString(), err:e.message});
                        }
                    }
                }
            }
        }
        return {scans:scans, duration_ms: Date.now()-t0, dumps:dumps, patches:patches, n_tasks:dumps.length};
    }
};
send({t:'ready'});
"""


def _attach(pid: int):
    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}

    def on_message(msg, _data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "ready":
                ready["v"] = True
            elif p.get("t") == "info":
                print(f"    [js] {p['msg']}")
            elif p.get("t") == "cdn_task":
                print(f"  [cdn] {p['class_name']} @{p['addr']} strings={p.get('n_str')}")
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(50):
        if ready["v"]:
            break
        time.sleep(0.1)
    if not ready["v"]:
        raise RuntimeError("frida script not ready")
    return session, script


def _detach(session, script) -> None:
    try:
        script.unload()
        session.detach()
    except Exception:
        pass


def cmd_recon(args: argparse.Namespace) -> int:
    pid = args.pid or _find_wxwork_pid()
    if pid is None:
        print("[!] no WXWork.exe")
        return 1
    print(f"[*] M2c recon PID={pid}")
    session, script = _attach(pid)
    t0 = time.monotonic()
    rec = script.exports_sync.recon(json.dumps({
        "slot_n": args.slots,
        "upload_task_rva": CDN_UPLOAD_VTABLES["CdnUploadFileTask"],
    }))
    print(f"[+] recon done in {time.monotonic()-t0:.1f}s")
    _detach(session, script)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"m2c_cdn_recon_{ts}.json"
    out.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
    RECON_CACHE.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print("=" * 72)
    print("[RTTI / vtable]")
    for name, info in (rec.get("rtti") or {}).items():
        vts = info.get("vtables") or []
        print(f"  {name}")
        if info.get("err"):
            print(f"    err={info['err']}")
        for v in vts[:3]:
            print(f"    vtable {v.get('rva')}  VA {v.get('va')}")

    print()
    print("[heap singletons]")
    for k, addrs in (rec.get("heap") or {}).items():
        print(f"  {k}: {len(addrs)}  {addrs[:4]}")

    def _show_interesting(title, block):
        if not block:
            print(f"  {title}: (none)")
            return
        hits = block.get("interesting") or []
        print(f"  {title}: rva={block.get('rva')} interesting_slots={len(hits)}")
        for h in hits:
            print(f"    slot[{h['i']}] {h.get('rva')}  imm={h.get('imm_hits')}  str={h.get('strings')[:6]}")

    print()
    print("[vtable interesting slots]")
    vts = rec.get("vtables") or {}
    _show_interesting("FileService", vts.get("FileService"))
    _show_interesting("FileServiceWinMember", vts.get("FileServiceWinMember"))
    _show_interesting("FileServiceImpl", vts.get("FileServiceImpl"))

    print()
    print("[CdnUploadParam]")
    print(f"  vtable rva = {vts.get('CdnUploadParam_rva')}")
    print(f"  ctor candidates = {len(rec.get('param_ctors') or [])}")
    for c in (rec.get("param_ctors") or [])[:6]:
        print(f"    site {c.get('site_rva')}  fn {c.get('fn_rva')}")
    print(f"  proto_desc hits = {len(rec.get('proto_desc') or [])}")
    for d in (rec.get("proto_desc") or [])[:2]:
        print(f"    {d.get('rva')}  {d.get('ascii','')[:80]}")
    print()
    print("[field string hits in module]")
    for k, arr in (rec.get("field_hits") or {}).items():
        if arr:
            print(f"  {k}: {len(arr)}  first={arr[0].get('rva')} {arr[0].get('cstr')}")
    print(f"[+] cache → {RECON_CACHE.name}")
    print(f"[+] dump  → {out.name}")
    return 0


def _pick_call_targets(rec: dict) -> dict:
    """从 recon 结果挑 this / fn / ctor。宁可少调，不瞎调。"""
    heap = rec.get("heap") or {}
    vts = rec.get("vtables") or {}
    this_va = None
    this_class = None
    for key in ("FileServiceWinMember", "FileService", "FileServiceImpl"):
        addrs = heap.get(key) or []
        if addrs:
            this_va = addrs[0]
            this_class = key
            break

    fn_va = None
    fn_slot = None
    fn_from = None
    # 优先：slot 里直接引用 CdnUploadFileTask vtable / CdnUploadParam
    for name in ("FileService", "FileServiceWinMember", "FileServiceImpl"):
        block = vts.get(name) or {}
        for h in block.get("interesting") or []:
            strs = " ".join(h.get("strings") or [])
            if h.get("imm_hits") or "CdnUploadParam" in strs or "upload_cdn" in strs or "CdnUpload" in strs:
                fn_va = h.get("fn")
                fn_slot = h.get("i")
                fn_from = f"{name}[{fn_slot}]"
                break
        if fn_va:
            break

    ctor_va = None
    for c in rec.get("param_ctors") or []:
        if c.get("fn"):
            ctor_va = c["fn"]
            break

    param_vt = None
    rtti = rec.get("rtti") or {}
    pvt = ((rtti.get(".?AVCdnUploadParam@pb@@") or {}).get("vtables") or [])
    if pvt:
        param_vt = pvt[0].get("va")

    return {
        "this_va": this_va,
        "this_class": this_class,
        "fn_va": fn_va,
        "fn_from": fn_from,
        "ctor_va": ctor_va,
        "param_vtable_va": param_vt,
        "wx_base": rec.get("wx_base"),
    }


def _load_recon(path: Path | None = None) -> dict:
    p = path or RECON_CACHE
    if not p.is_file():
        raise FileNotFoundError(f"缺少 recon 缓存: {p}  （先跑 recon）")
    return json.loads(p.read_text(encoding="utf-8"))


def cmd_call(args: argparse.Namespace) -> int:
    pid = args.pid or _find_wxwork_pid()
    if pid is None:
        print("[!] no WXWork.exe")
        return 1
    rec = _load_recon(Path(args.recon) if args.recon else None)
    tgt = _pick_call_targets(rec)
    print("[*] call targets:")
    for k, v in tgt.items():
        print(f"    {k} = {v}")

    if not tgt["this_va"] or not tgt["fn_va"]:
        print("[!] 入口不足：需要 FileService* this 和 CdnUploadFile fn。请先看 recon 的 interesting slots。")
        return 2

    silk = None
    if args.silk or (OUT_DIR / "poc_staged_voice.json").is_file():
        class _A:
            pass
        a = _A()
        a.silk = args.silk or ""
        a.no_temp = True
        silk = _resolve_staged_silk(a)
        print(f"[*] silk = {silk.silk_path}  md5={silk.md5}  size={silk.size}")

    field_map: dict[str, int] = {}
    if args.field_map:
        field_map = json.loads(Path(args.field_map).read_text(encoding="utf-8"))

    print(f"[*] attach PID={pid} dry_run={args.dry_run}")
    session, script = _attach(pid)

    before = script.exports_sync.probe_upload(json.dumps(
        [{"name": n, "rva": rva} for n, rva in CDN_UPLOAD_VTABLES.items()]
    ))
    print(f"[*] upload tasks before: {before}")

    call_cfg = {
        "this_va": tgt["this_va"],
        "fn_va": tgt["fn_va"],
        "ctor_va": tgt["ctor_va"],
        "param_vtable_va": tgt["param_vtable_va"],
        "param_size": args.param_size,
        "silk_path": str(silk.silk_path) if silk else "",
        "filename": silk.filename if silk else "",
        "md5": silk.md5 if silk else "",
        "file_size": silk.size if silk else 0,
        "file_type": args.file_type,
        "conv": args.to_conv or "FILEASSIST",
        "dry_run": args.dry_run,
        "field_map": field_map,
    }
    cres = script.exports_sync.call_upload(json.dumps(call_cfg))
    print("[*] NativeFunction result:")
    print(json.dumps(cres, ensure_ascii=False, indent=2))

    watch = None
    if cres.get("ok") and not args.dry_run:
        print(f"[*] watch {args.watch}s for CdnUploadFileTask / PostSendMessageTask2")
        watch = script.exports_sync.watch_short(json.dumps({
            "vtables": [{"name": n, "rva": rva} for n, rva in WATCH_VTABLES.items()],
            "duration_ms": args.watch * 1000,
            "patch_conv": args.to_conv or "",
            "post_send_rva": POST_SEND_MESSAGE_TASK2 if args.to_conv else 0,
        }))
        print(f"[+] watch tasks={watch.get('n_tasks')} patches={len(watch.get('patches') or [])}")
        after = script.exports_sync.probe_upload(json.dumps(
            [{"name": n, "rva": rva} for n, rva in CDN_UPLOAD_VTABLES.items()]
        ))
        print(f"[*] upload tasks after: {after}")
        watch["probe_after"] = after

    _detach(session, script)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"m2c_cdn_call_{ts}.json"
    out.write_text(json.dumps({
        "targets": tgt,
        "call": cres,
        "probe_before": before,
        "watch": watch,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] → {out.name}")
    if not cres.get("ok"):
        return 1
    if args.dry_run:
        return 0
    if watch and watch.get("n_tasks", 0) > 0:
        print("[+] M2c 信号：堆上出现 CDN Task（Upload 或 Download）")
        return 0
    print("[i] 调用未崩，但短窗内没扫到 CDN Task。可能是线程不对、param 字段不全、或 Task 生命周期极短。")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if args.silk:
        staged = stage_silk(Path(args.silk), also_temp=not args.no_temp)
        print(f"[+] staged → {staged.silk_path}")
        meta = OUT_DIR / "poc_staged_voice.json"
        meta.write_text(json.dumps({
            "silk_path": str(staged.silk_path),
            "filename": staged.filename,
            "md5": staged.md5,
            "size": staged.size,
            "temp_path": str(staged.temp_path) if staged.temp_path else None,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    if not RECON_CACHE.is_file() or args.force_recon:
        print("[*] recon cache missing or --force-recon")
        rc = cmd_recon(args)
        if rc != 0:
            return rc
    return cmd_call(args)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="M2c: NativeFunction FileService::CdnUploadFile")
    ap.add_argument("--pid", type=int, default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_re = sub.add_parser("recon", help="find FileService / CdnUploadParam / CdnUploadFile")
    p_re.add_argument("--pid", type=int, default=None)
    p_re.add_argument("--slots", type=int, default=48)
    p_re.set_defaults(func=cmd_recon)

    p_call = sub.add_parser("call", help="NativeFunction trigger upload")
    p_call.add_argument("--pid", type=int, default=None)
    p_call.add_argument("--recon", default="")
    p_call.add_argument("--silk", default="")
    p_call.add_argument("--to-conv", default="")
    p_call.add_argument("--file-type", type=int, default=5)
    p_call.add_argument("--param-size", type=int, default=0x200)
    p_call.add_argument("--field-map", default="")
    p_call.add_argument("--watch", type=int, default=12)
    p_call.add_argument("--dry-run", action="store_true")
    p_call.set_defaults(func=cmd_call)

    p_run = sub.add_parser("run", help="stage + recon + call + watch")
    p_run.add_argument("--pid", type=int, default=None)
    p_run.add_argument("--silk", default="")
    p_run.add_argument("--to-conv", default="")
    p_run.add_argument("--file-type", type=int, default=5)
    p_run.add_argument("--param-size", type=int, default=0x200)
    p_run.add_argument("--field-map", default="")
    p_run.add_argument("--watch", type=int, default=12)
    p_run.add_argument("--slots", type=int, default=48)
    p_run.add_argument("--no-temp", action="store_true")
    p_run.add_argument("--force-recon", action="store_true")
    p_run.add_argument("--dry-run", action="store_true")
    p_run.add_argument("--recon", default="")
    p_run.set_defaults(func=cmd_run)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

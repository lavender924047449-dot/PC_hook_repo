# m3_hijack_file_to_voice.py — 拖入 silk 为文件 → hijack 成 voice 气泡
#
# 前提（M1 已确认）：
#   task+0x30  → package_ptr
#   package+0x50 → subtype  (text=2, image=7, file=8)
#   package+0x28 → conv_id  (35B "S:{16}_{16}")
#
# M3 结论：仅改 subtype 8→2 仍显示文件图标；必须同步改 header + protobuf body。
#
# 用法：
#   python m3_hijack_file_to_voice.py --patch-body --wait 90 --to-conv FILEASSIST
#   拖 staged .silk 到文件传输助手发送
#
# M1 实证 subtype（package+0x50）：
#   text=2, voice=2, image=7, file=8
# voice 与 text 同 subtype，差异在 protobuf body（+0x1b8 起）

from __future__ import annotations
import argparse, json, re, subprocess, sys, time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
STAGED = OUT_DIR / "poc_staged_voice.json"

POST_SEND_VT = 0xABBB210  # PostSendMessageTask2

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const POST_SEND_VA = W0 + __POST_SEND_VT__;
const NEW_SUBTYPE = __NEW_SUBTYPE__;
const TO_CONV = __TO_CONV__;
const PATCH_BODY = __PATCH_BODY__;
const MINIMAL_BODY = __MINIMAL_BODY__;
const STAGED = __STAGED__;
const VOICE_TPL = __VOICE_TPL__;
const FILE_SUBTYPES = __FILE_SUBTYPES__;

function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function u8(p){ try{return p.readU8();}catch(e){return 0;} }

function vtPat(vt){
    return [(vt)&255,((vt>>>8)&255),((vt>>>16)&255),((vt>>>24)&255)]
        .map(b=>b.toString(16).padStart(2,'0')).join(' ');
}

function readStdString(p){
    try {
        const size = u32(p.add(0x10)); const cap = u32(p.add(0x14));
        if (size>0x1000 || cap<size) return null;
        if (size===0) return '';
        let dp = size<=15 ? p : ptr(u32(p));
        const bytes = new Uint8Array(dp.readByteArray(size));
        let s=''; for(let i=0;i<size;i++) s += String.fromCharCode(bytes[i]);
        return s;
    } catch(e){ return null; }
}

function isValidMsgId(s){
    return s && s.length >= 20 && s.length <= 40 && s.indexOf('CIGAE') === 0;
}
function isValidConv(s){
    return s && (s === 'FILEASSIST' || (s.indexOf('S:') === 0 && s.length >= 10));
}
function isValidPostSendTask(task, pkg){
    if (u32(task) !== POST_SEND_VA) return false;
    if (!isValidMsgId(readStdString(pkg.add(0x10)))) return false;
    if (!isValidConv(readStdString(pkg.add(0x28)))) return false;
    try { pkg.readByteArray(0x60); } catch(e){ return false; }
    return true;
}
function readFilePath1b8(pkg){
    try {
        const sz = u32(pkg.add(0x1c8)); const cap = u32(pkg.add(0x1cc));
        if (!sz || sz > 0x400 || cap < sz) return '';
        const ptrVal = u32(pkg.add(0x1b8));
        const dp = sz <= 15 ? pkg.add(0x1b8) : ptr(ptrVal);
        const bytes = new Uint8Array(dp.readByteArray(sz));
        let s = '';
        for (let i=0;i<sz;i++) s += String.fromCharCode(bytes[i]);
        return s;
    } catch(e){ return readStdString(pkg.add(0x1b8)) || ''; }
}

function writeBytes(p, arr){
    for (let i=0;i<arr.length;i++) p.add(i).writeU8(arr[i]);
}

// 用进程自己的 HeapAlloc 分配，确保析构时 CRT free() 可以正确释放
let _heapAllocFn = null;
let _hHeap = null;
function processHeapAlloc(n){
    if (!_heapAllocFn){
        const k32 = Process.getModuleByName('kernel32.dll');
        const gph = k32.findExportByName('GetProcessHeap');
        const ha  = k32.findExportByName('HeapAlloc');
        if (!gph || !ha) throw new Error('kernel32 exports not found');
        const _gph = new NativeFunction(gph, 'pointer', []);
        _heapAllocFn = new NativeFunction(ha, 'pointer', ['pointer','uint32','size_t']);
        _hHeap = _gph();
    }
    const p = _heapAllocFn(_hHeap, 0, n);
    if (p.isNull()) throw new Error('HeapAlloc(' + n + ') failed');
    return p;
}

// MSVC 32-bit std::string @ base — 写入任意二进制 payload
function writeStdStringBytes(base, arr){
    const n = arr.length;
    if (n <= 15){
        const buf = new Uint8Array(16);
        for (let i=0;i<n;i++) buf[i]=arr[i];
        base.writeByteArray(buf.buffer);
        base.add(0x10).writeU32(n);
        base.add(0x14).writeU32(15);
        return {kind:'sso', n:n};
    }
    // 尝试复用现有 heap buffer（若 cap 足够）
    const existingPtr = u32(base);
    const existingCap = u32(base.add(0x14));
    if (existingPtr > 0x10000 && existingCap >= n){
        const heap = ptr(existingPtr);
        writeBytes(heap, arr);
        heap.add(n).writeU8(0);
        base.add(0x10).writeU32(n);
        return {kind:'reuse_heap', n:n, ptr:'0x'+existingPtr.toString(16), cap:existingCap};
    }
    // 用进程堆分配（析构安全），写入 std::string heap layout
    const heap = processHeapAlloc(n + 1);
    writeBytes(heap, arr);
    heap.add(n).writeU8(0);
    base.writeU32(heap.toUInt32());
    base.add(0x10).writeU32(n);
    base.add(0x14).writeU32(n);
    return {kind:'process_heap', n:n, ptr:'0x'+heap.toUInt32().toString(16)};
}

function hexToBytes(h){
    const out=[]; h=(h||'').replace(/\s/g,'');
    for(let i=0;i<h.length;i+=2) out.push(parseInt(h.substr(i,2),16));
    return out;
}

function findHex32(s){
    if (!s) return null;
    const m = s.match(/[0-9a-f]{32}/i);
    return m ? m[0].toLowerCase() : null;
}

function scanPkgForFileId(pkg, excludeMd5){
    const md5 = (excludeMd5 || '').toLowerCase();
    for (let off=0x80; off<0x400; off+=4){
        const s = readStdString(pkg.add(off));
        const id = findHex32(s);
        if (id && id.length===32 && id !== md5) {
            return {off:'0x'+off.toString(16), file_id:id, src:s.slice(0,80), via:'stdstring'};
        }
    }
    try {
        const raw = new Uint8Array(pkg.readByteArray(0x500));
        const hex = Array.from(raw).map(b=>b.toString(16).padStart(2,'0')).join('');
        const re = /[0-9a-f]{32}/gi;
        let m;
        while ((m = re.exec(hex)) !== null){
            const id = m[0].toLowerCase();
            if (md5 && id === md5) continue;
            return {off:'0x'+(m.index/2).toString(16), file_id:id, via:'raw'};
        }
    } catch(e){}
    return null;
}

function pbVarint(n){
    n = n>>>0; const out=[];
    while(n>0x7f){out.push((n&0x7f)|0x80); n>>>=7;}
    out.push(n); return out;
}
function pbBytesField(fn, data){
    return pbVarint((fn<<3)|2).concat(pbVarint(data.length), data);
}
function pbVarintField(fn, v){
    return pbVarint((fn<<3)|0).concat(pbVarint(v));
}
function asciiBytes(s){
    const out=[]; for(let i=0;i<s.length;i++) out.push(s.charCodeAt(i)&0xff); return out;
}
function buildVoiceWrappedPb(filename, fileId, md5){
    let nested = pbVarintField(1, 5);
    nested = nested.concat(pbBytesField(2, [0x0a,0x03,0x31,0x32,0x33]));
    let inner = pbBytesField(2, asciiBytes(filename));
    inner = inner.concat(pbBytesField(3, nested));
    inner = inner.concat(pbBytesField(8, asciiBytes(fileId)));
    inner = inner.concat(pbBytesField(10, asciiBytes(md5)));
    return pbBytesField(1, inner);
}

function patchVoiceBody(pkg, rec){
    if (!PATCH_BODY) return;
    const tpl = VOICE_TPL;
    const md5 = STAGED.md5 || '';
    const pathStr = readFilePath1b8(pkg) || readStdString(pkg.add(0x1b8)) || '';
    rec.file_path = pathStr.slice(0,120);

    let pb;
    if (MINIMAL_BODY){
        pb = hexToBytes(tpl.minimal_voice_pb_hex || '0a09080012050a03313233');
        rec.body_mode = 'minimal';
    } else {
        // file_id 必须来自 staged（手机已上传 CDN 的合法 ID），不从 package raw 扫（易误判）
        const fileId = STAGED.file_id || '';
        if (!fileId){
            rec.skip_body_reason = 'poc_staged_voice.json missing file_id field';
            return;
        }
        pb = buildVoiceWrappedPb(STAGED.filename || 'voice.silk', fileId, md5);
        rec.used_file_id = fileId;
        rec.body_mode = 'staged_file_id';
    }
    rec.used_md5 = md5;
    rec.pb_len = pb.length;

    // voice dump 在 +0x1af 有 0x1d 标记；不写 header 模板（避免过期堆指针）
    try { pkg.add(0x1af).writeU8(0x1d); } catch(e){}

    const ss = writeStdStringBytes(pkg.add(0x1b8), pb);
    rec.body_string = ss;
    rec.body_patched = true;
}

rpc.exports = {
    watch: function(durationMs){
        const pat = vtPat(POST_SEND_VA);
        const seen = {};
        const patches = [];
        // ── M3e: 二次 patch 队列 ──
        // Phase-1: 检测到 file task → 放入 pendingCdn，等 CDN 完成
        // Phase-2: CDN 完成 (subtype→15) → 立即二次 patch (subtype→2 + voice body)
        const pendingCdn = []; // {pkgPtr, task_addr, conv, clientMsgId, detect_time}
        const t0 = Date.now();
        while (Date.now() - t0 < durationMs){
            // ── Phase-1: vtable scan → 发现 file task ──
            for (const r of Process.enumerateRanges({protection:'rw-', coalesce:false})){
                if (r.file) continue;
                if (r.size < 0x1000 || r.size > 0x8000000) continue;
                let ms; try{ ms=Memory.scanSync(r.base, r.size, pat);}catch(e){continue;}
                for (const m of ms){
                    const task = m.address;
                    if (seen[task.toString()]) continue;
                    seen[task.toString()] = true;

                    const pkgPtr = u32(task.add(0x30));
                    if (!pkgPtr || pkgPtr < 0x10000) continue;
                    const pkg = ptr(pkgPtr);
                    if (!isValidPostSendTask(task, pkg)) continue;

                    const conv = readStdString(pkg.add(0x28));
                    const clientMsgId = readStdString(pkg.add(0x10));
                    const subtypeByte = u8(pkg.add(0x50));

                    // conv 过滤
                    if (TO_CONV && conv !== TO_CONV){
                        send({t:'hit', task:task.toString(), conv, subtype_before_byte:subtypeByte,
                              skip_reason:'conv mismatch: '+conv, patched:false});
                        patches.push({task:task.toString(), conv, subtype_before_byte:subtypeByte,
                                      skip_reason:'conv mismatch: '+conv});
                        continue;
                    }

                    const isFileSubtype = FILE_SUBTYPES.indexOf(subtypeByte) >= 0;
                    if (!isFileSubtype){
                        send({t:'hit', task:task.toString(), conv, subtype_before_byte:subtypeByte,
                              skip_reason:'not file subtype='+subtypeByte, patched:false});
                        patches.push({task:task.toString(), conv, subtype_before_byte:subtypeByte,
                                      skip_reason:'not file subtype'});
                        continue;
                    }

                    const pathHint = readFilePath1b8(pkg) || '';
                    // Phase-1 完成：记录任务，等待 CDN 完成
                    const entry = {
                        pkgPtr, taskAddr: task.toUInt32(),
                        conv, clientMsgId,
                        subtype_at_detect: subtypeByte,
                        path_hint: pathHint.slice(0,120),
                        detect_time: Date.now(),
                        phase2_done: false
                    };
                    pendingCdn.push(entry);
                    send({t:'hit', task:task.toString(), pkg:pkgPtr.toString(16),
                          conv, clientMsgId, subtype_before_byte:subtypeByte,
                          patched:false, phase:'waiting_cdn', path_hint:entry.path_hint});
                    patches.push({task:task.toString(), pkg:pkgPtr.toString(16),
                                  conv, clientMsgId, subtype_before_byte:subtypeByte, phase:'waiting_cdn'});
                }
            }

            // ── Phase-2: 轮询 pendingCdn，CDN 完成 → 二次 patch ──
            for (const entry of pendingCdn){
                if (entry.phase2_done) continue;
                const age = Date.now() - entry.detect_time;
                if (age > 30000){ entry.phase2_done=true; continue; } // 30s 超时放弃

                try {
                    const p = ptr(entry.pkgPtr);
                    const cur_sub = u8(p.add(0x50));

                    // CDN 完成信号: subtype 变为 15（上传完毕）
                    if (cur_sub === 15){
                        entry.phase2_done = true;
                        const rec2 = {
                            task:'0x'+entry.taskAddr.toString(16),
                            pkg: entry.pkgPtr.toString(16),
                            conv: entry.conv, clientMsgId: entry.clientMsgId,
                            subtype_before_byte: cur_sub,
                            cdn_age_ms: age,
                            phase: 'post_cdn_patch'
                        };
                        // 二次 patch
                        try {
                            p.add(0x50).writeU8(NEW_SUBTYPE);
                            rec2.new_subtype = NEW_SUBTYPE;
                            rec2.subtype_after = u8(p.add(0x50));
                            if (PATCH_BODY) patchVoiceBody(p, rec2);
                            rec2.patched = true;
                        } catch(e){ rec2.patch_err = e.message; }

                        // dump 512B after second patch
                        try {
                            const raw = new Uint8Array(p.readByteArray(512));
                            rec2.pkg_hex = Array.from(raw).map(b=>b.toString(16).padStart(2,'0')).join('');
                        } catch(e){}

                        patches.push(rec2);
                        send({t:'hit', ...rec2});
                    }
                } catch(e){ entry.phase2_done = true; }
            }

            Thread.sleep(0.02); // 20ms 轮询（更快发现 subtype=15）
        }
        return {n: patches.filter(p=>p.patched).length, patches};
    }
};
send({t:'ready'});
"""

def _pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def _load_staged() -> dict:
    if STAGED.is_file():
        return json.loads(STAGED.read_text(encoding="utf-8"))
    return {}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--wait", type=int, default=60)
    ap.add_argument("--subtype", type=int, default=2, help="patch subtype (M1: voice=2, file=8)")
    ap.add_argument("--to-conv", default="", help="only patch when conv matches")
    ap.add_argument("--patch-body", action="store_true", help="also patch voice protobuf body (+0x1b8 std::string)")
    ap.add_argument("--minimal-body", action="store_true", help="use 11B voice template pb (crash isolation)")
    ap.add_argument("--file-subtypes", default="8,15", help="accepted file subtypes before patch (default 8,15)")
    ap.add_argument("--dry-run", action="store_true", help="just observe, no patch")
    args = ap.parse_args()

    pid = args.pid or _pid()
    if not pid:
        print("[!] no WXWork.exe"); return 1

    subtype = -1 if args.dry_run else args.subtype
    staged = _load_staged()
    pb_cfg = {}
    if args.patch_body and staged:
        sys.path.insert(0, str(OUT_DIR))
        from m3_voice_pb import build_voice_content_pb, wrap_package_body_pb, load_voice_template_slices
        inner = build_voice_content_pb(
            staged.get("filename", "voice.silk"),
            staged.get("file_id") or staged.get("md5", ""),
            staged.get("md5", ""),
        )
        wrapped = wrap_package_body_pb(inner)
        tpl = load_voice_template_slices()
        voice_pkg = bytes.fromhex(json.loads(
            (OUT_DIR / "pkg_layout_voice_20260913_181713.json").read_text(encoding="utf-8")
        )["tasks"][0]["pkg_hex"])
        pb_cfg = {
            "content_pb_hex": inner.hex(),
            "wrapped_pb_hex": wrapped.hex(),
            "minimal_voice_pb_hex": voice_pkg[0x1B8 : 0x1B8 + 11].hex(),
            **{k: v.hex() for k, v in tpl.items()},
        }

    js = FRIDA_JS.replace("__POST_SEND_VT__", hex(POST_SEND_VT)) \
                 .replace("__NEW_SUBTYPE__", str(subtype)) \
                 .replace("__TO_CONV__", json.dumps(args.to_conv)) \
                 .replace("__PATCH_BODY__", "true" if args.patch_body else "false") \
                 .replace("__MINIMAL_BODY__", "true" if args.minimal_body else "false") \
                 .replace("__STAGED__", json.dumps(staged)) \
                 .replace("__VOICE_TPL__", json.dumps(pb_cfg)) \
                 .replace("__FILE_SUBTYPES__", json.dumps(
                     [int(x) for x in args.file_subtypes.split(",") if x.strip()]))

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(js)
    ready = {"v": False}
    events = []
    def on_msg(m, _d):
        if m.get("type") == "send":
            p = m["payload"]
            if p.get("t") == "ready":
                ready["v"] = True
            elif p.get("t") == "hit":
                events.append(p)
                phase = p.get("phase","")
                if p.get("patched") and phase == "post_cdn_patch":
                    mark = "[POST-CDN PATCHED]"
                elif p.get("patched"):
                    mark = "[PATCHED]"
                elif phase == "waiting_cdn":
                    mark = "[DETECTED→wait CDN]"
                else:
                    mark = "[SKIP]"
                cdn_info = f" cdn_age={p.get('cdn_age_ms','?')}ms" if phase == "post_cdn_patch" else ""
                print(f"  {mark} task={p.get('task')} conv={p.get('conv')} subtype={p.get('subtype_before_byte')}"
                      f"{cdn_info} reason={p.get('skip_reason','')}")
            elif p.get("t") == "cdn_monitor":
                age = p.get("age_ms", 0)
                changed = p.get("changed")
                if changed:
                    print(f"  [CDN-OVERWRITE!] age={age}ms pkg={p.get('pkg')}"
                          f" ptr: {p.get('orig_ptr')} → {p.get('cur_ptr')}"
                          f" sz: {p.get('orig_sz')} → {p.get('cur_sz')}"
                          f" subtype={p.get('cur_subtype')}")
                elif p.get("err"):
                    print(f"  [CDN-monitor] age={age}ms pkg={p.get('pkg')} err={p.get('err')}")
                else:
                    print(f"  [CDN-stable]  age={age}ms pkg={p.get('pkg')}"
                          f" ptr={p.get('cur_ptr')} sz={p.get('cur_sz')} subtype={p.get('cur_subtype')}")
                events.append(p)
        elif m.get("type") == "error":
            print("  [ERR]", m.get("description"))

    script.on("message", on_msg)
    script.load()
    for _ in range(50):
        if ready["v"]: break
        time.sleep(0.1)

    mode = "DRY-RUN observe" if args.dry_run else f"HIJACK subtype=8 → {args.subtype}"
    if args.patch_body:
        mode += " + VOICE BODY" + (" (minimal 11B)" if args.minimal_body else " (dynamic file_id)")
    print(f"[*] attached PID={pid}  {mode}")
    if staged:
        print(f"    staged silk: {staged.get('filename')} md5={staged.get('md5')}")
    if args.to_conv:
        print(f"    conv filter: {args.to_conv}")
    print("=" * 70)
    print("  操作步骤:")
    print("    1. 打开企微目标会话（推荐先用【文件传输助手】测试）")
    print(f"    2. 把 silk 文件拖入会话作为【文件】发送")
    print(f"       silk: C:\\Users\\LENOVO\\Documents\\WXWork\\1688855042791155\\Cache\\Voice\\2026-09\\...silk")
    print(f"    3. 观察接收端气泡形态")
    print(f"    {args.wait}s 窗口开始 ...")
    print("=" * 70)

    t0 = time.monotonic()
    result = {"n": 0, "patches": [], "error": None}
    try:
        result = script.exports_sync.watch(args.wait * 1000)
        print(f"[+] {time.monotonic()-t0:.1f}s")
    except Exception as exc:
        result["error"] = str(exc)
        print(f"[!] watch ended early ({time.monotonic()-t0:.1f}s): {exc}")
    finally:
        try: script.unload(); session.detach()
        except Exception: pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"m3_hijack_{ts}.json"
    out.write_text(json.dumps({"args": vars(args), "events": events, "result": result},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    patched = sum(1 for e in events if e.get("patched"))
    print(f"[+] {result.get('n', len(events))} tasks captured, {patched} patched → {out.name}")
    return 0 if patched > 0 else 1

if __name__ == "__main__":
    sys.exit(main())

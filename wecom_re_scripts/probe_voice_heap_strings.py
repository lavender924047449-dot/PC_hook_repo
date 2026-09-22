# probe_voice_heap_strings.py — 即时探测堆内 Voice 路径字符串数量
from __future__ import annotations
import json, subprocess, sys, time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

FRIDA_JS = r"""
'use strict';
function countNeedle(needle, privateOnly){
    let pat = '';
    for (let i = 0; i < needle.length; i++)
        pat += (i?' ':'') + needle.charCodeAt(i).toString(16).padStart(2,'0');
    const all = Process.enumerateRanges({protection:'rw-', coalesce:false});
    let hits = 0, ranges = 0;
    for (let ri = 0; ri < all.length; ri++){
        const r = all[ri];
        if (privateOnly && r.file) continue;
        ranges++;
        try { hits += Memory.scanSync(r.base, r.size, pat).length; } catch(e){}
    }
    return {hits, ranges};
}
rpc.exports = {
    probe: function(){
        return {
            cache_voice_all: countNeedle('Cache\\Voice', false),
            cache_voice_priv: countNeedle('Cache\\Voice', true),
            dot_silk_all: countNeedle('.silk', false),
        };
    }
};
send({t:'ready'});
"""

def _pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue | Sort-Object WorkingSet64 -Desc | Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def main():
    import frida
    pid = _pid()
    print(f"[*] PID={pid}")
    s = frida.get_local_device().attach(pid)
    sc = s.create_script(FRIDA_JS)
    ready = {"v": False}
    sc.on("message", lambda m,_: ready.update({"v": True}) if m.get("type")=="send" and m["payload"].get("t")=="ready" else None)
    sc.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)
    r = sc.exports_sync.probe()
    print(json.dumps(r, indent=2))
    sc.unload(); s.detach()

if __name__ == "__main__":
    main()

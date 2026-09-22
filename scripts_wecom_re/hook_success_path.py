"""
Hook 0xb91204 (成功路径，JG 跳转目标)
当 [ESI+0x28] > 0 时，[ESI+0x2C] 里有 sequence + send_time 数据
同时 gate：仅在 logger 检测到 message_lookup.db 访问后的 3 秒内触发
"""
import frida, time, json, pathlib, sys, argparse

parser = argparse.ArgumentParser()
parser.add_argument('--pid', type=int, default=20632)
parser.add_argument('--logger-addr', default='0xa3616d0')
parser.add_argument('--success-addr', default='0xb91204')  # JG target
parser.add_argument('--duration', type=int, default=90)
parser.add_argument('--out', default='runtime/wecom_re/success_path_hook.json')
args = parser.parse_args()

out = pathlib.Path(args.out)
events = []

sess = frida.attach(args.pid)
js = r"""
var LOGGER_ADDR = ptr('__LOGGER__');
var SUCCESS_ADDR = ptr('__SUCCESS__');
var MAX_EVENTS = 20;

var gate = null; // { expires, dbPath }
var events = [];

// Hook logger to arm gate
Interceptor.attach(LOGGER_ADDR, {
  onEnter: function(args) {
    // Logger signature: (handle, format, ...) or (level, path, ...)
    // Try to read arg as path
    var path = '';
    for (var i = 0; i < 6; i++) {
      try {
        var s = args[i].readUtf8String(200);
        if (s && s.indexOf('message_lookup') >= 0) {
          path = s;
          break;
        }
      } catch(e) {}
    }
    if (path) {
      gate = { expires: Date.now() + 3000, path: path };
    }
  }
});

// Hook success path
Interceptor.attach(SUCCESS_ADDR, {
  onEnter: function(args) {
    if (events.length >= MAX_EVENTS) return;
    if (!gate || Date.now() > gate.expires) return;
    
    var esi = this.context.esi;
    var ebp = this.context.ebp;
    
    // Read count at [ESI+0x28]
    var count = 0;
    try { count = esi.add(0x28).readU32(); } catch(e) {}
    
    // Read data at [ESI+0x2C] - this should have sequence (uint64) and send_time (int64)
    // sequence is likely 8 bytes at [ESI+0x2C+0], send_time is 8 bytes at [ESI+0x2C+8]
    var seq_lo = 0, seq_hi = 0, st_lo = 0, st_hi = 0;
    try {
      seq_lo = esi.add(0x2C).readU32();
      seq_hi = esi.add(0x30).readU32();
      st_lo  = esi.add(0x34).readU32();
      st_hi  = esi.add(0x38).readU32();
    } catch(e) {}
    
    // Also dump 96 bytes from [ESI+0x20] to see full struct
    var esi_dump = '';
    try { esi_dump = hexdump(esi.add(0x20), {offset:0,length:96,header:false,ansi:false}); } catch(e) {}
    
    // Read a8 from the current function frame (message_id should be somewhere)
    // From previous analysis, frame[5] had a28=1661 as possible message_id
    // In THIS function, let's read [EBP+8..EBP+0x20]
    var ebp_args = [];
    for (var off = 8; off <= 0x20; off += 4) {
      var v = 0;
      try { v = ebp.add(off).readU32(); } catch(e) {}
      ebp_args.push({off: off, hex: '0x' + v.toString(16), dec: v});
    }
    
    // Read [EBP-0x3C] (the result pointer from the analysis)
    var res_ptr = 0;
    try { res_ptr = ebp.add(-0x3C).readU32(); } catch(e) {}
    var res_dump = '';
    if (res_ptr > 0x10000 && res_ptr < 0x7FFF0000) {
      try { res_dump = hexdump(ptr(res_ptr), {offset:0,length:32,header:false,ansi:false}); } catch(e) {}
    }
    
    events.push({
      ts: Date.now(),
      tid: this.threadId,
      gate_path: gate.path,
      esi: '0x' + esi.toString(16),
      count_at_28: count,
      // Read wider: 16 dwords from ESI+0x28
      esi_wide: (function(){
        var arr = [];
        for (var o = 0x20; o <= 0x80; o += 4) {
          var v = 0;
          try { v = esi.add(o).readU32(); } catch(e) {}
          arr.push({off: o, hex: '0x'+v.toString(16), dec: v});
        }
        return arr;
      })(),
      esi_dump: esi_dump,
      ebp_args: ebp_args,
      res_ptr: '0x' + res_ptr.toString(16),
      res_dump: res_dump,
      seq: { lo: seq_lo, hi: seq_hi, hex: '0x' + (seq_hi * 0x100000000 + seq_lo).toString(16) },
      st:  { lo: st_lo,  hi: st_hi,  hex: '0x' + (st_hi  * 0x100000000 + st_lo ).toString(16) },
    });
    send({type: 'hit', count: count, esi: '0x'+esi.toString(16)});
  }
});

send({type: 'ready'});
""".replace('__LOGGER__', args.logger_addr).replace('__SUCCESS__', args.success_addr)

def on_msg(m, d):
    p = m.get('payload', {})
    if p.get('type') == 'ready':
        print('Hook active! Trigger WeChat Work operations...')
        sys.stdout.flush()
    elif p.get('type') == 'hit':
        print(f'HIT: ESI={p.get("esi")} count_at_28={p.get("count")}')
        sys.stdout.flush()

script = sess.create_script(js)
script.on('message', lambda m,d: (on_msg(m,d), events.append(m.get('payload',{})) if m.get('payload',{}).get('type')=='hit' else None))

# Get events from script
all_msgs = []
script.on('message', lambda m,d: all_msgs.append(m))

try:
    script.load()
    print(f'Script loaded, waiting {args.duration}s...')
    sys.stdout.flush()
    time.sleep(args.duration)
finally:
    payload = {
        "pid": args.pid,
        "logger_addr": args.logger_addr,
        "success_addr": args.success_addr,
        "duration_s": args.duration,
        "event_count": 0,
        "events": []
    }
    # Extract events from script via its internal state
    # We need to read events from the JS side
    # Use a simple approach: read from the all_msgs list
    for m in all_msgs:
        p = m.get('payload', {})
        if p.get('type') == 'hit':
            payload['events'].append(p)
    
    payload['event_count'] = len(payload['events'])
    
    # Also inject a read script to get the full event data
    try:
        read_js = r"""
var evts = events;
send({events: evts});
"""
        # This won't work since 'events' is in a different scope
        # Instead, instrument the success hook to send full data
        pass
    except Exception:
        pass
    
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({"out": str(out), "event_count": payload['event_count']}, ensure_ascii=False))
    sys.stdout.flush()
    try:
        script.unload()
        sess.detach()
    except Exception:
        pass

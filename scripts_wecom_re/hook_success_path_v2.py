"""
Hook 0xb91204 (成功路径) 捕获 [ESI+0x2C] 里的 sequence + send_time
"""
import frida, time, json, pathlib, sys

PID = 20632
LOGGER_ADDR = '0xa3616d0'
SUCCESS_ADDR = '0xb91204'
DURATION = 90
OUT = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\success_path_hook_v2.json')

sess = frida.attach(PID)
js = r"""
var LOGGER_ADDR = ptr('""" + LOGGER_ADDR + r"""');
var SUCCESS_ADDR = ptr('""" + SUCCESS_ADDR + r"""');
var MAX_EVENTS = 20;

var gate = null;
var events = [];

function u32(p) { try { return p.readU32()>>>0; } catch(e) { return 0; } }
function hd(p, n) { try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e) { return ''; } }

// Hook logger to arm gate
Interceptor.attach(LOGGER_ADDR, {
  onEnter: function(args) {
    var path = '';
    for (var i = 0; i < 6; i++) {
      try {
        var s = args[i].readUtf8String(300);
        if (s && s.indexOf('message_lookup') >= 0) { path = s; break; }
      } catch(e) {}
    }
    if (path) {
      gate = { expires: Date.now() + 3000, path: path };
    }
  }
});

// Hook 0xb91204 (JG success target: [ESI+0x28] > 0, data at [ESI+0x2C])
Interceptor.attach(SUCCESS_ADDR, {
  onEnter: function(args) {
    if (events.length >= MAX_EVENTS) return;
    if (!gate || Date.now() > gate.expires) return;
    
    var esi = this.context.esi;
    var ebp = this.context.ebp;
    
    var count28 = u32(esi.add(0x28));
    
    // Read 96 bytes from ESI+0x20 (covers 0x28=count and 0x2C=data)
    var esi_dump = hd(esi.add(0x20), 96);
    
    // Decode potential data at ESI+0x2C (first 32 bytes = 4 uint64)
    var data = [];
    for (var i = 0; i < 8; i++) {
      var lo = u32(esi.add(0x2C + i*4));
      data.push({off_from_2c: i*4, hex: '0x' + lo.toString(16), dec: lo});
    }
    
    // Also look for message_id: check frame args
    var frame_args = [];
    for (var off = 8; off <= 0x30; off += 4) {
      var v = u32(ebp.add(off));
      frame_args.push({off: off, hex: '0x' + v.toString(16), dec: v});
    }
    
    var ev = {
      ts: Date.now(),
      tid: this.threadId,
      gate_path: gate.path,
      esi: '0x' + esi.toString(16),
      count28: count28,
      data_at_2c: data,
      esi_dump: esi_dump,
      frame_args: frame_args
    };
    events.push(ev);
    send({type: 'hit', ev: ev});
  }
});

send({type: 'ready'});
"""

all_events = []

def on_msg(m, d):
    p = m.get('payload', {})
    t = p.get('type', '')
    if t == 'ready':
        print('Hook active. Please trigger WeChat Work ops...')
        sys.stdout.flush()
    elif t == 'hit':
        ev = p.get('ev', {})
        print(f'HIT tid={ev.get("tid")} ESI={ev.get("esi")} count28={ev.get("count28")}')
        data = ev.get('data_at_2c', [])
        print(f'  data@2C: {[(d["off_from_2c"], d["hex"], d["dec"]) for d in data[:4]]}')
        sys.stdout.flush()
        all_events.append(ev)

script = sess.create_script(js)
script.on('message', on_msg)

try:
    script.load()
    print(f'Waiting {DURATION}s...')
    sys.stdout.flush()
    time.sleep(DURATION)
finally:
    payload = {
        "pid": PID,
        "success_addr": SUCCESS_ADDR,
        "duration_s": DURATION,
        "event_count": len(all_events),
        "events": all_events,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({"out": str(OUT), "event_count": len(all_events)}, ensure_ascii=False))
    sys.stdout.flush()
    try:
        script.unload()
        sess.detach()
    except Exception:
        pass

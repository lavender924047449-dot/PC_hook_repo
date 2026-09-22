"""
简单验证：dispatcher 是否被调用（不过滤 case），触发企微操作后观察
"""
import frida, time, json, pathlib, sys

sess = frida.attach(20632)
js = r"""
var DISP = ptr('0x08b6b4c2');
var counts = {};
var samples = [];
var MAX = 50;

Interceptor.attach(DISP, {
  onEnter: function(args) {
    var ebp = this.context.ebp;
    var caseVal = 0;
    try { caseVal = ebp.add(0x14).readU32(); } catch(e) {}
    var key = caseVal.toString();
    counts[key] = (counts[key] || 0) + 1;
    if (samples.length < MAX) {
      var mid_lo = 0, mid_hi = 0;
      try { mid_lo = ebp.add(0x0C).readU32(); } catch(e) {}
      try { mid_hi = ebp.add(0x10).readU32(); } catch(e) {}
      samples.push({case: caseVal, mid_lo: mid_lo, mid_hi: mid_hi, tid: this.threadId});
    }
  }
});

// Report every 5 seconds
var timer_count = 0;
var interval = setInterval(function() {
  timer_count++;
  send({type:'tick', t: timer_count, counts: counts, samples: samples.slice(0,10)});
  if (timer_count >= 6) clearInterval(interval);
}, 5000);
"""

print("Dispatcher hook active for 30s. Please trigger WeChat Work operations!")
print("(send message, scroll, switch chats in FTA)")
sys.stdout.flush()

msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m))
script.load()
time.sleep(32)
script.unload()
sess.detach()

print("\n=== Results ===")
for m in msgs:
    p = m.get('payload', {})
    if p.get('type') == 'tick':
        print(f"\n[t={p['t']*5}s] Case counts: {p['counts']}")
        for s in p.get('samples', [])[:5]:
            print(f"  case={s['case']} mid_lo=0x{s['mid_lo']:08x} mid_hi=0x{s['mid_hi']:08x} tid={s['tid']}")

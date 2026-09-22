"""
先找 WXWork.exe 模块范围，再精确扫描
"""
import frida, time, json

sess = frida.attach(20632)
js = r"""
// First: find the module range containing 0x08b6b4c2
var target_addr = ptr('0x08b6b4c2');
var mods = Process.enumerateModules();
var main_mod = null;
for (var i = 0; i < mods.length; i++) {
  var m = mods[i];
  var base = m.base.toUInt32();
  if (base <= 0x08b6b4c2 && base + m.size > 0x08b6b4c2) {
    main_mod = {name: m.name, base: '0x'+base.toString(16), size: m.size, path: m.path};
    break;
  }
}
// Also list first 10 modules
var mod_list = mods.slice(0,15).map(function(m){
  return {name: m.name, base: '0x'+m.base.toUInt32().toString(16), size: m.size};
});
send({main_mod: main_mod, mod_list: mod_list});
"""
msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m))
script.load()
time.sleep(3)
script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    print("Module containing dispatcher:", p.get('main_mod'))
    print("\nAll modules (first 15):")
    for mod in p.get('mod_list', []):
        print(f"  {mod['name']:40s} base={mod['base']} size={hex(mod['size'])}")

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict

import frida


@dataclass
class MarkerResult:
    process_name: str
    pid: int
    frida_version: str
    module_base: str
    module_size: int
    marker_hits: dict[str, int]


def build_script(module_name: str) -> str:
    return f"""
rpc.exports = {{
  probe: function() {{
    const m = Process.getModuleByName("{module_name}");
    const patterns = {{
      sqlite3_open: "73 71 6c 69 74 65 33 5f 6f 70 65 6e",
      sqlite3_prepare_v2: "73 71 6c 69 74 65 33 5f 70 72 65 70 61 72 65 5f 76 32",
      sqlite3_exec: "73 71 6c 69 74 65 33 5f 65 78 65 63",
      sqlite_master: "73 71 6c 69 74 65 5f 6d 61 73 74 65 72",
      sqlite_header: "53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33",
      message_db: "6d 65 73 73 61 67 65 2e 64 62"
    }};
    const out = {{}};
    for (const k in patterns) {{
      out[k] = Memory.scanSync(m.base, m.size, patterns[k]).length;
    }}
    return {{
      module_base: m.base.toString(),
      module_size: m.size,
      marker_hits: out
    }};
  }}
}};
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe SQLite markers in WXWork process memory via Frida.")
    parser.add_argument("--pid", type=int, required=True, help="Target WXWork process PID.")
    parser.add_argument("--process-name", default="WXWork.exe", help="Display name for report.")
    parser.add_argument("--module-name", default="WXWork.exe", help="Module name to scan.")
    args = parser.parse_args()

    session = frida.attach(args.pid)
    try:
        script = session.create_script(build_script(args.module_name))
        script.load()
        payload = script.exports_sync.probe()
    finally:
        session.detach()

    result = MarkerResult(
        process_name=args.process_name,
        pid=args.pid,
        frida_version=frida.__version__,
        module_base=payload["module_base"],
        module_size=payload["module_size"],
        marker_hits=payload["marker_hits"],
    )
    print(json.dumps(asdict(result), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Compact view for DB summary output.")
    parser.add_argument("--infile", required=True)
    parser.add_argument("--top", type=int, default=12)
    args = parser.parse_args()

    p = Path(args.infile)
    data = json.loads(p.read_text(encoding="utf-8"))
    dbs = data.get("dbs", [])

    compact = {
        "infile": str(p),
        "db_count": data.get("db_count", 0),
        "top_dbs": [],
    }

    for item in dbs[: args.top]:
        sample_bt = []
        if item.get("samples"):
            sample_bt = item["samples"][0].get("bt", [])[:8]
        compact["top_dbs"].append(
            {
                "db": item.get("db", ""),
                "ret_counts": item.get("ret_counts", [])[:3],
                "sample_bt_head": sample_bt,
            }
        )

    print(json.dumps(compact, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

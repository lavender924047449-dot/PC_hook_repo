from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


DB_PAT = re.compile(r"(?i)([A-Z]:\\[^\n\r]*?\.(?:db))")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract DB-path related hits from logger trace JSON.")
    parser.add_argument("--infile", required=True)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    p = Path(args.infile)
    data = json.loads(p.read_text(encoding="utf-8"))
    events = data.get("events", [])

    by_db_ret: dict[str, Counter[str]] = defaultdict(Counter)
    db_samples: dict[str, list[dict]] = defaultdict(list)

    for e in events:
        blob = " | ".join(str(e.get(k, "")) for k in ("s0", "s1", "s2", "u0", "u1", "u2"))
        dbs = DB_PAT.findall(blob)
        if not dbs:
            continue
        ret = str(e.get("ret", ""))
        for db in dbs:
            db_norm = db.lower()
            by_db_ret[db_norm][ret] += 1
            if len(db_samples[db_norm]) < 5:
                db_samples[db_norm].append(
                    {
                        "ts": e.get("ts"),
                        "ret": ret,
                        "s0": e.get("s0", ""),
                        "s1": e.get("s1", ""),
                        "s2": e.get("s2", ""),
                        "bt": e.get("bt", []),
                    }
                )

    summary = {
        "infile": str(p),
        "db_count": len(by_db_ret),
        "dbs": [
            {
                "db": db,
                "ret_counts": [{"ret": r, "count": c} for r, c in cnt.most_common(10)],
                "samples": db_samples[db],
            }
            for db, cnt in sorted(by_db_ret.items(), key=lambda kv: sum(kv[1].values()), reverse=True)
        ],
    }

    text = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()

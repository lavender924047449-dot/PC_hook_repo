from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


DB_PAT = re.compile(
    r"(?i)(\.db|sqlite|sqlcipher|wcdb|message\.db|session\.db|user\.db|kv\.db|crm\.db|file\.db)"
)
SQL_PAT = re.compile(r"(?i)(select |insert |update |delete |create table|pragma )")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize logger trace JSON for DB/SQL hints.")
    parser.add_argument("--infile", required=True)
    parser.add_argument("--top", type=int, default=20)
    args = parser.parse_args()

    p = Path(args.infile)
    data = json.loads(p.read_text(encoding="utf-8"))
    events = data.get("events", [])

    s0_counter: Counter[str] = Counter()
    ret_counter: Counter[str] = Counter()
    db_hits = []
    sql_hits = []

    for e in events:
        s0 = str(e.get("s0", ""))
        s0_counter[s0] += 1
        ret_counter[str(e.get("ret", ""))] += 1

        blob = " | ".join(str(e.get(k, "")) for k in ("s0", "s1", "s2", "u0", "u1", "u2"))
        if DB_PAT.search(blob):
            db_hits.append(e)
        if SQL_PAT.search(blob):
            sql_hits.append(e)

    summary = {
        "infile": str(p),
        "event_count": len(events),
        "top_s0_paths": [{"count": c, "path": s} for s, c in s0_counter.most_common(args.top)],
        "top_return_addresses": [
            {"count": c, "ret": r} for r, c in ret_counter.most_common(min(args.top, 10))
        ],
        "db_like_count": len(db_hits),
        "sql_like_count": len(sql_hits),
        "db_like_samples": db_hits[:5],
        "sql_like_samples": sql_hits[:5],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

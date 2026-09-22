"""读取 message.db 结构和最近消息"""
import sqlite3

db = r'C:\Users\LENOVO\Documents\WXWork\1688855042791155\Data\message.db'

try:
    con = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
    cur = con.cursor()
    print('SQLite OK, version:', cur.execute('SELECT sqlite_version()').fetchone())

    # 表结构
    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]
    print(f'\nTables ({len(tables)}):')
    for t in tables:
        count = cur.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0]
        print(f'  {t}  ({count} rows)')

    # 找消息相关表
    for t in tables:
        if 'message' in t.lower() or 'msg' in t.lower():
            print(f'\n-- Table: {t} --')
            cols = [r[1] for r in cur.execute(f'PRAGMA table_info("{t}")').fetchall()]
            print(f'  Columns: {cols}')
            rows = cur.execute(f'SELECT * FROM "{t}" ORDER BY rowid DESC LIMIT 3').fetchall()
            for row in rows:
                print(f'  row: {str(row)[:200]}')

    con.close()

except sqlite3.DatabaseError as e:
    print(f'DB Error (may be encrypted): {e}')
    # 读文件头
    with open(db, 'rb') as f:
        head = f.read(32)
    print(f'File header: {head[:16].hex()}')
    print(f'Header ASCII: {"".join(chr(b) if 32<=b<127 else "." for b in head[:16])}')
except Exception as e:
    print(f'Error: {e}')
    import traceback; traceback.print_exc()

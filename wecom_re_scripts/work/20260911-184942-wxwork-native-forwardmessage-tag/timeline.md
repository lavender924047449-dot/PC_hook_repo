# Timeline — WXWork tag4 native forward

| time | action | result |
|------|--------|--------|
| 18:49 | reverse-skill master-route | PRIMARY=reverse-engineering R0 |
| 18:49 | case-init + scope auth granted | ready_for_act=true |
| 18:50 | scan_disk_tag4.py 静态扫描 | WbWC/417+/W1pd/ZSBQ 在 rdata 加密 blob 中为子串，非明文注册表 |
| 18:51 | xref_rdata_table.py | 全部 0 处 LE ptr xref（VMP 间接访问）|
| 18:51 | hook_tag4_caller.py | Phase2 0 事件（用户未在窗口内转发）|
| 18:52 | payload magic 0x4c43790b | .text file_off=0x07b86b35，VMP 区无标准 prologue |

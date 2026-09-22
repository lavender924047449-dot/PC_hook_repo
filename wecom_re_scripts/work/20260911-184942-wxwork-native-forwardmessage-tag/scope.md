# Case Scope

## meta
- case_id: 20260911-184942-wxwork-native-forwardmessage-tag
- created: 2026-09-11T18:49:44.5467684+08:00
- operator: local
- project_root: D:\Only internship outputs\Test-Voice\runtime\wecom_re
- primary_skill: reverse-engineering/SKILL.md
- primary_id: R0
- lead_role: lead
- specialist_roles: []
- hint: WXWork native ForwardMessage tag4 WbWC xref handler mapping
- preset: none

## auth
- status: granted
- basis: own_system
- evidence_of_auth: 用户自有企微账号 FTA 转发自动化，会话内多次确认授权
- MUST NOT proceed if status != granted

## in_scope
- assets:
  - WXWork.exe PID via :9882 (local)
  - runtime/wecom_re/*.json captures
- surfaces: [Frida attach, memory read, static string scan]
- activities: [dynamic hook, xref scan, handler mapping]

## out_of_scope
- assets: []
- activities: [dos, phishing_real_users, unrestricted_exfil]

## network_profile
- mode: offline
- notes: |
    offline | lab_only | authorized_target_only | unrestricted_lab
    Change mode only after auth.status = granted.

## deliverables
- report: true
- field_journal: true
- diagrams: true
- timeline: true

## constraints
- timebox: {}
- stealth: low
- data_handling: anonymize

## signoff
- ready_for_act: true
- checklist:
  - [x] auth.status = granted
  - [x] in_scope.assets non-empty OR offline sample path set
  - [x] network_profile.mode chosen
  - [ ] out_of_scope reviewed
  - [ ] roles assigned (see skills/ops/role-map.md)

## ops_refs
- skills/ops/scope-contract.md
- skills/ops/evidence-finding-path.md
- skills/ops/role-map.md
- skills/ops/timeline-workitem.md
- skills/ops/IDENTITY.md
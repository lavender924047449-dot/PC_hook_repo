# cdn_task_constants.py — 企微 5.0.10.6015 CDN 上传 Task vtable RVA
# =============================================================================
# 由 find_vtable_by_class.py 于 2026-09-13 实证：
#   CdnUploadFileTask     → 0xb48ca88
#   BigCdnUploadFileTask  → 0xab9d094
# 升版后需重跑 find_vtable_by_class.py 更新。
# =============================================================================

from __future__ import annotations

CDN_UPLOAD_VTABLES: dict[str, int] = {
    "CdnUploadFileTask": 0xB48CA88,
    "BigCdnUploadFileTask": 0xAB9D094,
}

# 手机→FTA→PC 同步落盘时，PC 端常见 Download 而非 Upload
CDN_DOWNLOAD_VTABLES: dict[str, int] = {
    "DownloadFileTask2": 0xAB9F098,
    "DownloadFtnFileTask": 0xAB9F88C,
    "CdnCopyFileTask": 0xB48C768,
}

WATCH_VTABLES: dict[str, int] = {**CDN_UPLOAD_VTABLES, **CDN_DOWNLOAD_VTABLES}

# 语音发送链路上 PostSendMessageTask2 仍可能出现（极短窗口），conv hijack 备用
POST_SEND_MESSAGE_TASK2 = 0xABBB210

# M2c · FileService / CdnUploadParam（2026-09-13 find_vtable_by_class，5.0.10.6015）
FILESERVICE_VTABLES: dict[str, int] = {
    "FileServiceWinMember": 0xAB69988,
    "FileServiceImpl_0": 0xB48FAB4,
    "FileServiceImpl_1": 0xB48FAC0,
    "FileService_logic": 0xB48F918,
    "CdnUploadParam": 0xB795B58,
}

# M2c · NativeFunction 触发 CdnUploadFile（2026-09-13 实证，5.0.10.6015）
M2C: dict[str, int] = {
    "FileService_vtable": 0xAB69924,
    "CdnUploadFile_slot2": 0x2499BB0,       # FileService vtable[2], ret 0xC
    "CdnUploadParam_size": 0x2C,
    "CdnUploadParam_vtable": 0xB795B58,
    "CdnUploadParam_init": 0xA08B00,        # 实为 FtnUploadParam::InitFromDefault；Cdn 用手工 init
    "CdnUploadParam_ctor": 0xA08C56,        # thiscall dtor/清理（会覆写 vtable，勿直接当 ctor）
    "CdnUploadParam_copy": 0x3A94A7,
    "CdnUploadParam_field_type": 0x1C,      # dispatch cmp [param+0x1c]
    "CdnUpload_type5_handler": 0x249CF20,   # file_type == 5
    "FileType_voice": 5,                    # slot2: cmp eax,5 → voice CDN path
}

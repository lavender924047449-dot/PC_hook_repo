from app.messaging.material_code_service import MaterialCodeService
from app.messaging.types import MessageType


def test_generate_code_with_prefix():
    svc = MaterialCodeService()
    fp = "3f8a2c9d1b47" + "0" * 28
    code = svc.generate(fp, MessageType.VOICE)
    assert code == "voice-3f8a2c9d1b47"


def test_generate_code_conflict_suffix():
    svc = MaterialCodeService()
    fp = "abcdefffffff" + "1" * 28
    code = svc.generate(fp, MessageType.IMAGE, has_conflict=lambda c: c == "img-abcdefffffff")
    assert code == "img-abcdefffffff-1"


def test_structured_fingerprint_stable():
    svc = MaterialCodeService()
    p1 = {"a": 1, "b": "x"}
    p2 = {"b": "x", "a": 1}
    assert svc.fingerprint_from_structured_payload(p1) == svc.fingerprint_from_structured_payload(p2)

from app.pc_wecom.contact_indexer import ContactHit, ContactIndexer
from app.pc_wecom.pc_navigator import NullBackend, PCWeComNavigator


def _build_indexer(tmp_path):
    nav = PCWeComNavigator(backend=NullBackend())
    return ContactIndexer(nav, cache_path=tmp_path / "contacts.json")


def test_fuzzy_search_hits_name_alias_id(tmp_path):
    idx = _build_indexer(tmp_path)
    idx.add_or_update(ContactHit(name="张三", alias="销售张老师", wecom_id="zhangsan_001"))
    idx.add_or_update(ContactHit(name="李四", alias="客服小李", wecom_id="lisi_888"))

    assert idx.search("张三")[0].name == "张三"
    assert idx.search("张老师")[0].name == "张三"
    assert idx.search("888")[0].name == "李四"


def test_search_miss_calls_navigator(tmp_path):
    backend = NullBackend()
    nav = PCWeComNavigator(backend=backend)
    idx = ContactIndexer(nav, cache_path=tmp_path / "contacts.json")
    assert idx.search("不存在") == []
    assert any(x.startswith("pick_contact:不存在") for x in backend.logs)

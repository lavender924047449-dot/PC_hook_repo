from pathlib import Path

from app.pc_wecom.locators import LocatorSet
from app.pc_wecom.pc_navigator import BubbleAnchor, NavigatorBackend, PCWeComNavigator


class _FakeBackend(NavigatorBackend):
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.ok = True

    def ensure_window(self, locators: LocatorSet) -> bool:
        self.calls.append("ensure_window")
        return self.ok

    def focus_chat(self, chat_name: str, locators: LocatorSet) -> bool:
        self.calls.append(f"focus_chat:{chat_name}")
        return self.ok

    def send_text(self, text: str, locators: LocatorSet) -> bool:
        self.calls.append(f"send_text:{text}")
        return self.ok

    def right_click_bubble(self, anchor: BubbleAnchor, locators: LocatorSet) -> bool:
        self.calls.append(f"bubble:{anchor.material_code}")
        return self.ok

    def click_menu(self, names: tuple[str, ...], locators: LocatorSet | None = None) -> bool:
        self.calls.append(f"menu:{names[0]}")
        return self.ok

    def pick_contact(self, keyword: str, locators: LocatorSet) -> bool:
        self.calls.append(f"pick:{keyword}")
        return self.ok

    def dump_tree(self) -> str:
        return "fake_tree"


def test_navigator_happy_path(tmp_path: Path):
    backend = _FakeBackend()
    loc = LocatorSet(ui_dump_dir=str(tmp_path / "dump"))
    nav = PCWeComNavigator(locators=loc, backend=backend)

    nav.open_fta()
    nav.send_text("voice-abc123")
    nav.long_press_bubble(BubbleAnchor(material_code="voice-abc123"))
    nav.pick_forward_menu()
    assert nav.search_and_pick_contact("张三") is True
    nav.confirm_send()
    dump = nav.dump_ui_tree("test")
    assert dump.exists()
    assert "ensure_window" in backend.calls
    assert "focus_chat:文件传输助手" in backend.calls


def test_search_contact_empty_returns_false():
    backend = _FakeBackend()
    nav = PCWeComNavigator(backend=backend)
    assert nav.search_and_pick_contact("   ") is False

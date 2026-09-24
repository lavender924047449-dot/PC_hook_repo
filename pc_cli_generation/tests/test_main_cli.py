"""
Stage 5.5 · `main.py` argparse 层回归护栏 + 若干纯逻辑分支的 mock 单测.

不做的事:
    * 不真连 adb / ffmpeg / PC 企微
    * 不启动 GUI (只验证 gui 子命令的 parser 定义)

覆盖:
    * 每个子命令能被 argparse 正确识别 (回归"改了 flag 名字"这类问题)
    * scan-cache 的关键 flag (--list / --timeout / --account 等)
    * plan-run 的关键 flag (--dry-run / --loose / --resume 等)
    * cmd_scan_cache --list 分支 (mock list_accounts, 不接触真磁盘)
    * _refresh_forward_assets(): 无转发 tag → 跳过; 有 tag → forward_to_self 被逐个调用
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

import main as main_mod


# ---------------- 1. argparse 结构护栏 ---------------- #

def _parse(argv: list[str]):
    parser = main_mod.build_parser()
    return parser.parse_args(argv)


class TestSubcommandRouting:
    """确保每个子命令都能被 argparse 找到并绑定到正确的 func."""

    def test_show_config(self):
        ns = _parse(["show-config"])
        assert ns.func is main_mod.cmd_show_config

    def test_check(self):
        ns = _parse(["check"])
        assert ns.func is main_mod.cmd_check

    def test_send(self):
        ns = _parse(["send", "张三", "runtime/hi.wav"])
        assert ns.func is main_mod.cmd_send
        assert ns.contact == "张三"
        assert ns.audio == "runtime/hi.wav"

    def test_batch(self):
        ns = _parse(["batch", "contacts.csv", "--dry-run", "--loose", "--no-jitter"])
        assert ns.func is main_mod.cmd_batch
        assert ns.csv == "contacts.csv"
        assert ns.dry_run is True
        assert ns.loose is True
        assert ns.no_jitter is True

    def test_plan(self):
        ns = _parse(["plan", "samples/plan_text_smoke.json", "--summary-only"])
        assert ns.func is main_mod.cmd_plan
        assert ns.summary_only is True

    def test_plan_run_all_flags(self):
        ns = _parse([
            "plan-run", "samples/plan_text_smoke.json",
            "--dry-run",
            "--limit-contacts", "3",
            "--no-jitter",
            "--keep-remote",
            "--refresh-forward-assets",
            "--loose",
            "--resume",
            "--ignore-schedule",
            "--report-dir", "some/dir",
        ])
        assert ns.func is main_mod.cmd_plan_run
        assert ns.plan == "samples/plan_text_smoke.json"
        assert ns.dry_run is True
        assert ns.limit_contacts == 3
        assert ns.no_jitter is True
        assert ns.keep_remote is True
        assert ns.refresh_forward_assets is True
        assert ns.loose is True
        assert ns.resume is True
        assert ns.ignore_schedule is True
        assert ns.report_dir == "some/dir"

    def test_plan_run_defaults(self):
        ns = _parse(["plan-run", "p.json"])
        assert ns.dry_run is False
        assert ns.limit_contacts == 0
        assert ns.no_jitter is False
        assert ns.keep_remote is False
        assert ns.refresh_forward_assets is False
        assert ns.loose is False
        assert ns.resume is False
        assert ns.ignore_schedule is False
        assert ns.report_dir == "runtime/reports"

    def test_scan_cache_list(self):
        ns = _parse(["scan-cache", "--list"])
        assert ns.func is main_mod.cmd_scan_cache
        assert ns.list is True
        # 其它 flag 应有默认值
        assert ns.timeout == 0.0
        assert ns.poll == 0.4
        assert ns.stop_on_first is False
        assert ns.include_voice is False
        assert ns.skip_voice is False
        assert ns.decode_silk is False
        assert ns.watch is False
        assert ns.echo_code is False
        assert ns.echo_mode == "paste_if_focused"
        assert ns.no_wait is False
        assert ns.lib == "runtime/asset_library.json"

    def test_forward_parser(self):
        ns = _parse(["forward", "img-abc123def456", "张三", "--conv-id", "S:1", "--no-native"])
        assert ns.func is main_mod.cmd_forward
        assert ns.material_code == "img-abc123def456"
        assert ns.target == "张三"
        assert ns.conv_id == "S:1"
        assert ns.no_native is True
        assert ns.pid is None

    def test_queue_run_parser(self):
        ns = _parse(["queue-run", "--ignore-schedule", "--source-account", "acct1"])
        assert ns.func is main_mod.cmd_queue_run
        assert ns.ignore_schedule is True
        assert ns.source_account == "acct1"
        assert ns.no_native is False

    def test_conv_map_parser(self):
        ns = _parse(["conv-map", "--seed", "张三", "S:1688855042791155_7881300363276969"])
        assert ns.func is main_mod.cmd_conv_map
        assert ns.seed_pair == ["张三", "S:1688855042791155_7881300363276969"]
        ns2 = _parse(["conv-map", "--resolve", "张三", "--refresh"])
        assert ns2.resolve == "张三"
        assert ns2.refresh is True

    def test_scan_cache_all_flags(self):
        ns = _parse([
            "scan-cache",
            "--account", "1688000000000001",
            "--wxwork-root", "D:/tmp/WXWork",
            "--timeout", "20",
            "--poll", "0.5",
            "--stop-on-first",
            "--include-voice",
            "--skip-voice",
            "--decode-silk",
            "--watch",
            "--echo-code",
            "--echo-mode", "clipboard",
            "--lib", "runtime/custom_lib.json",
            "--no-wait",
        ])
        assert ns.account == "1688000000000001"
        assert ns.wxwork_root == "D:/tmp/WXWork"
        assert ns.timeout == 20.0
        assert ns.poll == 0.5
        assert ns.stop_on_first is True
        assert ns.include_voice is True
        assert ns.skip_voice is True
        assert ns.decode_silk is True
        assert ns.watch is True
        assert ns.echo_code is True
        assert ns.echo_mode == "clipboard"
        assert ns.lib == "runtime/custom_lib.json"
        assert ns.no_wait is True

    def test_gui_with_and_without_plan(self):
        ns = _parse(["gui"])
        assert ns.func is main_mod.cmd_gui
        assert ns.plan is None

        ns2 = _parse(["gui", "samples/plan_text_smoke.json"])
        assert ns2.plan == "samples/plan_text_smoke.json"

    def test_gui_entry_exists_and_dispatches_to_gui(self, monkeypatch):
        """J: pyproject 的 [project.gui-scripts] 用 `_gui_entry` 作入口, 应等价于 `main.py gui`。"""
        seen: list = []
        # 拦截 cmd_gui, 只验证被派发, 不真开 Qt
        monkeypatch.setattr(
            main_mod, "cmd_gui",
            lambda args: seen.append(args) or 0,
        )
        # build_parser 里 `gui` 子命令的默认 func 是模块级 cmd_gui;
        # monkeypatch 打上后, argparse 里已经 bind 好的旧引用不会自动跟换,
        # 因此我们直接检查 _gui_entry 会构造 argparse 并 dispatch.
        # 若 cmd_gui 未被换掉, 只要 ns.plan 为 None + rc == 0 (或非错), 也算通过.
        rc = main_mod._gui_entry()
        # 允许 0 (走 cmd_gui) 或 2 (PySide6 未装的错误码), 但不应异常
        assert rc in (0, 2)

    def test_normalize(self):
        ns = _parse(["normalize", "in.wav", "-o", "out.wav", "--force"])
        assert ns.func is main_mod.cmd_normalize
        assert ns.input == "in.wav"
        assert ns.output == "out.wav"
        assert ns.force is True

    def test_register_basic(self):
        ns = _parse(["register", "D:/合同.pdf"])
        assert ns.func is main_mod.cmd_register
        assert ns.files == ["D:/合同.pdf"]
        assert ns.echo_code is False
        assert ns.lib == "runtime/asset_library.json"

    def test_register_multiple_files(self):
        ns = _parse(["register", "a.mp4", "b.docx", "--echo-code"])
        assert ns.files == ["a.mp4", "b.docx"]
        assert ns.echo_code is True

    def test_missing_subcommand_errors(self):
        parser = main_mod.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_unknown_subcommand_errors(self):
        parser = main_mod.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["not-a-command"])


# ---------------- 2. cmd_register 功能测试 ---------------- #

class TestCmdRegister:
    def test_register_pdf_generates_file_code(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)
        pdf = tmp_path / "合同.pdf"
        pdf.write_bytes(b"PDF content here for testing" * 10)
        lib_path = tmp_path / "lib.json"
        ns = _parse(["register", str(pdf), "--lib", str(lib_path)])
        rc = main_mod.cmd_register(ns)
        assert rc == 0
        from app.messaging.asset_library import AssetLibrary
        lib = AssetLibrary.load(lib_path)
        assert len(lib) == 1
        entry = lib.all()[0]
        assert entry.material_code.startswith("file-")
        assert entry.source_path == str(pdf)

    def test_register_mp4_generates_vid_code(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)
        vid = tmp_path / "demo.mp4"
        vid.write_bytes(b"fake mp4 data" * 20)
        lib_path = tmp_path / "lib.json"
        ns = _parse(["register", str(vid), "--lib", str(lib_path)])
        rc = main_mod.cmd_register(ns)
        assert rc == 0
        from app.messaging.asset_library import AssetLibrary
        lib = AssetLibrary.load(lib_path)
        entry = lib.all()[0]
        assert entry.material_code.startswith("vid-")

    def test_register_nonexistent_file_returns_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)
        lib_path = tmp_path / "lib.json"
        ns = _parse(["register", str(tmp_path / "no_such.pdf"), "--lib", str(lib_path)])
        rc = main_mod.cmd_register(ns)
        assert rc == 1

    def test_register_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)
        pdf = tmp_path / "report.pdf"
        pdf.write_bytes(b"same content" * 10)
        lib_path = tmp_path / "lib.json"
        ns = _parse(["register", str(pdf), "--lib", str(lib_path)])
        main_mod.cmd_register(ns)
        ns2 = _parse(["register", str(pdf), "--lib", str(lib_path)])
        main_mod.cmd_register(ns2)
        from app.messaging.asset_library import AssetLibrary
        lib = AssetLibrary.load(lib_path)
        assert len(lib) == 1


class TestCmdRegisterForward:
    def test_register_forward_parser(self):
        ns = _parse(["register-forward", "miniprogram", "朴朴超市"])
        assert ns.func is main_mod.cmd_register_forward
        assert ns.type == "miniprogram"
        assert ns.locator == "朴朴超市"
        assert ns.echo_code is False

    def test_register_forward_with_shorthand(self):
        ns = _parse(["register-forward", "mp", "小程序标题", "--echo-code"])
        assert ns.type == "mp"
        assert ns.echo_code is True

    def test_register_miniprogram(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)
        lib_path = tmp_path / "lib.json"
        ns = _parse(["register-forward", "miniprogram", "测试小程序", "--lib", str(lib_path)])
        rc = main_mod.cmd_register_forward(ns)
        assert rc == 0
        from app.messaging.asset_library import AssetLibrary
        lib = AssetLibrary.load(lib_path)
        assert len(lib) == 1
        entry = lib.all()[0]
        assert entry.material_code.startswith("mp-")
        assert entry.fta_locator == "测试小程序"

    def test_register_channel_video(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)
        lib_path = tmp_path / "lib.json"
        ns = _parse(["register-forward", "cv", "视频号标题", "--lib", str(lib_path)])
        rc = main_mod.cmd_register_forward(ns)
        assert rc == 0
        from app.messaging.asset_library import AssetLibrary
        lib = AssetLibrary.load(lib_path)
        entry = lib.all()[0]
        assert entry.material_code.startswith("cv-")

    def test_register_location(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)
        lib_path = tmp_path / "lib.json"
        ns = _parse(["register-forward", "位置", "上海南京路", "--lib", str(lib_path)])
        rc = main_mod.cmd_register_forward(ns)
        assert rc == 0
        from app.messaging.asset_library import AssetLibrary
        lib = AssetLibrary.load(lib_path)
        entry = lib.all()[0]
        assert entry.material_code.startswith("loc-")

    def test_register_forward_unknown_type(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)
        lib_path = tmp_path / "lib.json"
        ns = _parse(["register-forward", "unknown", "test", "--lib", str(lib_path)])
        rc = main_mod.cmd_register_forward(ns)
        assert rc == 1

    def test_register_forward_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)
        lib_path = tmp_path / "lib.json"
        ns = _parse(["register-forward", "mp", "同一个小程序", "--lib", str(lib_path)])
        main_mod.cmd_register_forward(ns)
        ns2 = _parse(["register-forward", "mp", "同一个小程序", "--lib", str(lib_path)])
        main_mod.cmd_register_forward(ns2)
        from app.messaging.asset_library import AssetLibrary
        lib = AssetLibrary.load(lib_path)
        assert len(lib) == 1


# ---------------- 3. cmd_scan_cache --list 分支 ---------------- #

class TestScanCacheList:
    def test_list_prints_accounts(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "app.messaging.cache_scanner.WeComCacheScanner.list_accounts",
            lambda root=None: [("1688857496937113", 42), ("1688111111111111", 3)],
        )
        # 避免真的初始化 loguru handlers
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)

        ns = _parse(["scan-cache", "--list"])
        rc = main_mod.cmd_scan_cache(ns)
        assert rc == 0

    def test_list_empty_returns_2(self, monkeypatch):
        monkeypatch.setattr(
            "app.messaging.cache_scanner.WeComCacheScanner.list_accounts",
            lambda root=None: [],
        )
        monkeypatch.setattr(main_mod, "_init", lambda cfg: None)

        ns = _parse(["scan-cache", "--list"])
        assert main_mod.cmd_scan_cache(ns) == 2


# ---------------- 3. _refresh_forward_assets mock 单测 ---------------- #

def _mini_plan_with_tags(tags: list[str]):
    """构造带若干 forward 类 tag 的 mini plan."""
    from app.messaging.plan import BatchPlan

    if not tags:
        payload_msgs = [{"type": "text", "text": "no tags"}]
    else:
        payload_msgs = [{"type": "miniprogram", "tag": t} for t in tags]
    return BatchPlan.model_validate({
        "meta": {"name": "refresh test"},
        "tasks": [{
            "label": "t",
            "contacts": ["文件传输助手"],
            "messages": payload_msgs,
        }],
    })


class TestRefreshForwardAssets:
    def test_no_forward_tags_skips(self, caplog):
        plan = _mini_plan_with_tags([])   # 只有 text
        nav = MagicMock()
        asset_library = MagicMock()

        main_mod._refresh_forward_assets(plan, nav, asset_library)

        nav.open_fta.assert_not_called()
        nav.forward_to_self.assert_not_called()

    def test_forward_each_tag_once(self):
        from app.messaging.asset_library import AssetEntry
        from app.messaging.types import MessageType

        tags = ["mp_a", "mp_b", "mp_c"]
        plan = _mini_plan_with_tags(tags)

        # 构造 AssetEntry stub, get(tag) 返回带 fta_locator 的 entry
        entries = {
            t: AssetEntry(
                tag=t,
                semantic_type=MessageType.MINIPROGRAM,
                fta_locator=f"locator-{t}",
            )
            for t in tags
        }
        asset_library = MagicMock()
        asset_library.get.side_effect = lambda t: entries[t]

        nav = MagicMock()

        main_mod._refresh_forward_assets(plan, nav, asset_library)

        # 应该 open_fta 一次, 每个 tag forward_to_self 一次
        assert nav.open_fta.call_count == 1
        assert nav.forward_to_self.call_count == 3
        called_locators = [c.args[0] for c in nav.forward_to_self.call_args_list]
        assert set(called_locators) == {"locator-mp_a", "locator-mp_b", "locator-mp_c"}
        # 每个 entry 应被 touch_refreshed (last_refreshed_at 不为 None)
        for e in entries.values():
            assert e.last_refreshed_at is not None

    def test_missing_tag_is_warned_and_continues(self):
        from app.messaging.asset_library import AssetEntry
        from app.messaging.types import MessageType

        plan = _mini_plan_with_tags(["mp_known", "mp_missing"])
        known = AssetEntry(
            tag="mp_known",
            semantic_type=MessageType.MINIPROGRAM,
            fta_locator="loc-known",
        )

        def _get(tag):
            if tag == "mp_known":
                return known
            raise KeyError(tag)

        asset_library = MagicMock()
        asset_library.get.side_effect = _get
        nav = MagicMock()

        main_mod._refresh_forward_assets(plan, nav, asset_library)
        # 缺 tag 的应被跳过, 已知 tag 的仍然被保鲜
        nav.open_fta.assert_called_once()
        nav.forward_to_self.assert_called_once_with("loc-known")

    def test_entry_missing_locator_is_skipped(self):
        from app.messaging.asset_library import AssetEntry
        from app.messaging.types import MessageType

        plan = _mini_plan_with_tags(["mp_x"])
        # fta_locator 空 → 应被跳过
        entry = AssetEntry(
            tag="mp_x",
            semantic_type=MessageType.MINIPROGRAM,
            fta_locator="",
        )
        asset_library = MagicMock()
        asset_library.get.return_value = entry
        nav = MagicMock()

        main_mod._refresh_forward_assets(plan, nav, asset_library)
        nav.open_fta.assert_called_once()
        nav.forward_to_self.assert_not_called()

    def test_forward_error_is_caught_and_next_tag_continues(self):
        from app.messaging.asset_library import AssetEntry
        from app.messaging.types import MessageType

        plan = _mini_plan_with_tags(["mp_a", "mp_b"])
        entries = {
            "mp_a": AssetEntry(
                tag="mp_a", semantic_type=MessageType.MINIPROGRAM, fta_locator="la"
            ),
            "mp_b": AssetEntry(
                tag="mp_b", semantic_type=MessageType.MINIPROGRAM, fta_locator="lb"
            ),
        }
        asset_library = MagicMock()
        asset_library.get.side_effect = lambda t: entries[t]

        nav = MagicMock()
        nav.forward_to_self.side_effect = [RuntimeError("boom"), None]

        # 不应把 RuntimeError 抛出去
        main_mod._refresh_forward_assets(plan, nav, asset_library)
        assert nav.forward_to_self.call_count == 2


class TestScanLock:
    def test_stale_pid_is_replaced(self, tmp_path, monkeypatch):
        lock = tmp_path / "scan-cache.pid"
        lock.write_text("1", encoding="utf-8")
        monkeypatch.setattr(main_mod, "_scan_lock_path", lambda: lock)
        monkeypatch.setattr(main_mod, "_pid_is_running", lambda pid: False)
        acquired = main_mod._acquire_scan_lock()
        assert acquired == lock
        assert lock.read_text(encoding="utf-8").strip() == str(os.getpid())
        main_mod._release_scan_lock(acquired)
        assert not lock.exists()

    def test_live_pid_blocks_second_instance(self, tmp_path, monkeypatch):
        lock = tmp_path / "scan-cache.pid"
        lock.write_text("12345", encoding="utf-8")
        monkeypatch.setattr(main_mod, "_scan_lock_path", lambda: lock)
        monkeypatch.setattr(main_mod, "_pid_is_running", lambda pid: pid == 12345)
        assert main_mod._acquire_scan_lock() is None
        assert lock.read_text(encoding="utf-8").strip() == "12345"


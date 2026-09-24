from __future__ import annotations

import sys

from runtime.wework_re_android.label_store_cli import main


def test_label_store_cli_set_list_resolve_roundtrip(tmp_path, capsys, monkeypatch):
    path = tmp_path / "customer_labels.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "label_store_cli",
            "--path",
            str(path),
            "set",
            "--conv",
            "7685582584742596232",
            "--labels",
            "新客,测试5a",
        ],
    )
    assert main() == 0
    assert "ok set" in capsys.readouterr().out

    monkeypatch.setattr(
        sys,
        "argv",
        ["label_store_cli", "--path", str(path), "add", "--conv", "1002", "--label", "新客"],
    )
    assert main() == 0
    capsys.readouterr()

    monkeypatch.setattr(
        sys,
        "argv",
        ["label_store_cli", "--path", str(path), "resolve", "--tag", "新客"],
    )
    assert main() == 0
    resolved = capsys.readouterr().out.strip().splitlines()
    assert resolved == ["7685582584742596232", "1002"]

    monkeypatch.setattr(
        sys,
        "argv",
        ["label_store_cli", "--path", str(path), "list", "--json"],
    )
    assert main() == 0
    listed = capsys.readouterr().out
    assert "测试5a" in listed
    assert "7685582584742596232" in listed

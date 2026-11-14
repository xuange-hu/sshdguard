"""CLI, render, demo and entrypoint tests."""

from __future__ import annotations

import json

import pytest

from sshdguard import __version__, demo
from sshdguard.cli import main
from sshdguard.engine import run
from sshdguard.parser import parse
from sshdguard.render import brief, text, to_json, to_sarif
from sshdguard.rules import REGISTRY

# -- demo ---------------------------------------------------------------------


def test_demo_covers_every_rule():
    fired, total = demo.coverage()
    missing = sorted(item.id for item in REGISTRY if item.id not in fired)
    assert not missing, f"rules without a sample: {missing}"
    assert total == len(REGISTRY)


def test_demo_reports_sorted_names():
    assert demo.names() == sorted(demo.names())
    assert demo.reports()


def test_demo_corpora_all_find_something():
    for name, report in demo.reports():
        assert report.count > 0, f"{name} fired nothing"


# -- render -------------------------------------------------------------------


def _sample_report():
    return run(parse("PermitRootLogin yes\nPort 22\n"), target="sample")


def test_text_has_severity_rule_line_offset():
    out = text(_sample_report())
    assert "SHD001" in out
    assert "line 1" in out
    assert "saw:" in out
    assert "fix:" in out


def test_text_empty_report():
    out = text(run(parse("", source="clean"), target="clean"))
    assert "no findings" in out


def test_json_structure():
    data = json.loads(to_json(_sample_report()))
    assert data["source"] == "sample"
    assert data["summary"]["findings"] == len(data["findings"])
    assert set(data["summary"]["by_severity"]) == {"critical", "high", "medium", "low", "note"}
    for finding in data["findings"]:
        assert {"rule", "severity", "message", "line", "offset"} <= set(finding)


def test_sarif_structure():
    data = json.loads(to_sarif(_sample_report()))
    assert data["version"] == "2.1.0"
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "sshdguard"
    assert driver["informationUri"].endswith("/xuange-hu/sshdguard")
    rule_ids = {rule["id"] for rule in driver["rules"]}
    result_ids = {result["ruleId"] for result in data["runs"][0]["results"]}
    assert rule_ids == result_ids
    for result in data["runs"][0]["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1


def test_brief_one_line():
    line = brief(_sample_report())
    assert "risk=" in line


# -- CLI ----------------------------------------------------------------------


def test_scan_high_fail(tmp_path, capsys):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin yes\n", encoding="utf-8")
    assert main(["scan", str(target)]) == 1
    assert "SHD001" in capsys.readouterr().out


def test_scan_pass_below_threshold(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("Port 22\nAllowUsers deploy\n", encoding="utf-8")
    assert main(["scan", str(target), "--fail-on", "high"]) == 0


def test_scan_json(tmp_path, capsys):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin yes\n", encoding="utf-8")
    main(["scan", str(target), "--json", "--fail-on", "none"])
    data = json.loads(capsys.readouterr().out)
    assert data["findings"]


def test_scan_sarif(tmp_path, capsys):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin yes\n", encoding="utf-8")
    main(["scan", str(target), "--sarif", "--fail-on", "none"])
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"


def test_scan_directory_picks_sshd_configs(tmp_path):
    (tmp_path / "sshd_config").write_text("PermitRootLogin yes\n", encoding="utf-8")
    (tmp_path / "noise.txt").write_text("hello world\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--fail-on", "high"]) == 1


def test_scan_missing_path_exit_2(capsys):
    assert main(["scan", "/no/such/path"]) == 2
    assert "no such file" in capsys.readouterr().err


def test_scan_empty_directory_exit_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == 2
    assert "no sshd_config" in capsys.readouterr().err


def test_text_subcommand_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", type("S", (), {"read": staticmethod(lambda: "PermitRootLogin yes\n")})())
    assert main(["text"]) == 1
    assert "SHD001" in capsys.readouterr().out


def test_text_subcommand_arg(capsys):
    assert main(["text", "PermitRootLogin yes", "--fail-on", "critical"]) == 1
    assert "SHD001" in capsys.readouterr().out


def test_demo_command_exits_zero(capsys):
    assert main(["demo", "--quiet"]) == 0
    out = capsys.readouterr().out
    assert "rules fired: 45/45" in out


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert f"{len(REGISTRY)} rules" in out
    assert "SHD001" in out


def test_rules_command_json(capsys):
    main(["rules", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert len(data) == len(REGISTRY)


def test_explain(capsys):
    assert main(["explain", "shd001"]) == 0
    out = capsys.readouterr().out
    assert "PermitRootLogin yes" in out
    assert "why it matters" in out


def test_explain_unknown_rule(capsys):
    assert main(["explain", "XXX000"]) == 2
    assert "no rule" in capsys.readouterr().err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


# -- entrypoint / packaging contract ------------------------------------------


def test_console_scripts_resolve():
    from sshdguard import cli, mcp_server

    assert callable(cli.main)
    assert callable(mcp_server.main)


def test_manifest_matches_registry_size():
    from sshdguard.mcp_server import tool_manifest

    manifest = tool_manifest()
    assert len(manifest) == 6
    assert all(item["description"] for item in manifest)


def test_mcp_tool_names_are_prefixed():
    from sshdguard.mcp_server import tool_manifest

    names = [item["name"] for item in tool_manifest()]
    assert all(name.startswith("sshdguard_") for name in names)


def test_init_exports_engine_surface():
    import sshdguard

    assert callable(sshdguard.parse)
    assert callable(sshdguard.parse_file)
    assert callable(sshdguard.run)

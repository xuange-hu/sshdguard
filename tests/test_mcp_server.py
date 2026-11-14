"""MCP server tests. The optional ``mcp`` extra must not be required to run
the core package, so everything here is import-guarded."""

from __future__ import annotations

import pytest

mcp = pytest.importorskip("mcp")

from sshdguard.mcp_server import build_server, tool_manifest  # noqa: E402


def test_build_server_registers_six_tools():
    server = build_server()
    # FastMCP 1.x exposes the registry synchronously via _tool_manager
    listed = server._tool_manager.list_tools()
    assert len(listed) == len(tool_manifest())


def test_manifest_descriptions_are_real_prose():
    for item in tool_manifest():
        assert len(item["description"]) > 40, item["name"]


def test_text_tool_end_to_end():
    from sshdguard.mcp_server import sshdguard_text

    out = sshdguard_text("PermitRootLogin yes\n", fail_on="critical")
    assert out.startswith("FAIL")
    assert "SHD001" in out


def test_text_tool_pass():
    from sshdguard.mcp_server import sshdguard_text

    out = sshdguard_text("AllowUsers deploy\n", fail_on="critical")
    assert out.startswith("PASS")


def test_rules_tool_filter():
    from sshdguard.mcp_server import sshdguard_rules

    out = sshdguard_rules(stage=3)
    assert "SHD070" in out
    assert "stage 1" not in out


def test_explain_tool_unknown():
    from sshdguard.mcp_server import sshdguard_explain

    assert "Known ids" in sshdguard_explain("NOPE")


def test_demo_tool():
    from sshdguard.mcp_server import sshdguard_demo

    out = sshdguard_demo()
    assert "rules fired: 45/45" in out


def test_scan_tool_missing_path():
    from sshdguard.mcp_server import sshdguard_scan

    assert "no such file" in sshdguard_scan("/no/such/path")


def test_sarif_tool_not_a_file():
    from sshdguard.mcp_server import sshdguard_sarif

    assert "not a file" in sshdguard_sarif("/no/such/path")

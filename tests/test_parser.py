"""Parser tests: tokens, quotes, scopes, includes, unknowns, bad Match lines."""

from __future__ import annotations

from sshdguard.parser import KNOWN_KEYWORDS, MULTI_KEYWORDS, looks_like_sshd_config, parse, parse_file, tokenize


def entry(app, keyword, occurrence=0):
    """The occurrence-th entry for a keyword across all scopes."""
    found = [entry for scope in app.scopes for entry in scope.entries if entry.keyword == keyword]
    return found[occurrence]


def test_tokenize_simple():
    assert tokenize("PermitRootLogin yes") == ["PermitRootLogin", "yes"]


def test_tokenize_quoted_value():
    assert tokenize('ForceCommand "internal-sftp -u 077"') == ["ForceCommand", "internal-sftp -u 077"]


def test_tokenize_unterminated_quote_swallows_line():
    assert tokenize('ForceCommand "internal-sftp') == ["ForceCommand", "internal-sftp"]


def test_tokenize_multiple_spaces():
    assert tokenize("Port   22\t\n") == ["Port", "22"]


def test_parse_empty_text():
    app = parse("")
    assert app.main is not None
    assert app.main.entries == []
    assert app.line_count == 1


def test_comments_and_blanks_skipped():
    app = parse("# comment\n\n   \nPort 22\n")
    assert [entry.keyword for entry in app.main.entries] == ["PORT"]


def test_keyword_case_normalized():
    app = parse("permitrootlogin yes\nPERMITROOTLOGIN yes\n")
    assert app.main.all("PERMITROOTLOGIN") and len(app.main.all("PERMITROOTLOGIN")) == 2


def test_byte_offset_points_at_keyword():
    text = "# lead\n  PasswordAuthentication yes\n"
    app = parse(text)
    entry = app.main.entries[0]
    header = b"# lead\n"
    assert entry.offset == len(header) + 2
    assert entry.length == len("PasswordAuthentication")


def test_offset_is_byte_based_not_char_based():
    text = "# 注释行\nPort 22\n"
    app = parse(text)
    entry = app.main.entries[0]
    header = "# 注释行\n".encode()
    assert entry.offset == len(header)


def test_main_scope_entries():
    app = parse("Port 22\nX11Forwarding no\n")
    assert [entry.keyword for entry in app.main.entries] == ["PORT", "X11FORWARDING"]


def test_match_opens_new_scope():
    app = parse("PermitRootLogin no\nMatch User git\n    PasswordAuthentication yes\n")
    assert len(app.scopes) == 2
    assert app.match_scopes[0].criteria == "User git"
    assert app.match_scopes[0].entries[0].keyword == "PASSWORDAUTHENTICATION"


def test_match_scope_does_not_leak_into_main():
    app = parse("Match User git\n    PasswordAuthentication yes\n")
    assert app.main.entries == []
    assert len(app.match_scopes) == 1


def test_sequential_match_blocks():
    text = "Match User a\n    X11Forwarding yes\nMatch Group b\n    X11Forwarding no\n"
    app = parse(text)
    assert len(app.match_scopes) == 2
    assert app.match_scopes[1].criteria == "Group b"


def test_bare_match_is_recorded():
    app = parse("Match\n    PermitTTY yes\n")
    assert len(app.bad_matches) == 1
    assert "no criteria" in app.bad_matches[0].reason
    assert len(app.match_scopes) == 1


def test_unknown_criterion_recorded():
    app = parse("Match Banana xyz\n    X11Forwarding yes\n")
    assert len(app.bad_matches) == 1
    assert "unknown criterion" in app.bad_matches[0].reason


def test_criterion_without_value_recorded():
    app = parse("Match User\n    X11Forwarding yes\n")
    assert len(app.bad_matches) == 1
    assert "has no value" in app.bad_matches[0].reason


def test_valid_criteria_not_flagged():
    app = parse(
        "Match User git Group wheel LocalAddress 10.0.0.1 LocalPort 22 All\n    X11Forwarding yes\n"
    )
    assert app.bad_matches == []


def test_unknown_keyword_recorded():
    app = parse("BananaSplit yes\n")
    assert len(app.unknowns) == 1
    assert app.unknowns[0].keyword == "BananaSplit"
    assert app.main.entries == []


def test_known_keyword_not_unknown():
    app = parse("PasswordAuthentication no\nCiphers chacha20-poly1305@openssh.com\n")
    assert app.unknowns == []


def test_removed_keywords_still_parse_as_entries():
    app = parse("RSAAuthentication yes\nProtocol 1\nAuthorizedKeysFile2 .ssh/keys\n")
    assert len(app.main.entries) == 3
    assert app.unknowns == []


def test_include_records_reference():
    app = parse("Include /etc/ssh/sshd_config.d/*.missing\n")
    assert len(app.includes) == 1
    assert app.includes[0].resolved == []
    assert app.includes[0].in_match is False


def test_include_inside_match_flagged():
    app = parse("Match User backup\n    Include /etc/ssh/peers/*.conf\n")
    assert app.includes[0].in_match is True


def test_include_cycle_guard():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        a = Path(tmp) / "a.conf"
        b = Path(tmp) / "b.conf"
        a.write_text("Include b.conf\nPort 22\n", encoding="utf-8")
        b.write_text("Include a.conf\n", encoding="utf-8")
        app = parse_file(a)
        assert not any("depth" in e for e in app.errors)
        assert app.includes[0].resolved


def test_include_resolves_files_for_real(tmp_path):
    (tmp_path / "sshd_config").write_text("Include drop.conf\n", encoding="utf-8")
    (tmp_path / "drop.conf").write_text("PermitRootLogin yes\n", encoding="utf-8")
    app = parse_file(tmp_path / "sshd_config")
    assert not app.errors
    assert app.included_files == [str(tmp_path / "drop.conf")]
    assert entry(app, "PERMITROOTLOGIN").file == str(tmp_path / "drop.conf")


def test_parse_file_unreadable_is_an_error_not_a_crash(tmp_path):
    app = parse_file(tmp_path / "gone.conf")
    assert app.errors
    assert app.scopes  # still has a main scope


def test_looks_like_sshd_config_positive():
    assert looks_like_sshd_config("# sshd_config\nPort 22\n")


def test_looks_like_sshd_config_negative():
    assert not looks_like_sshd_config("function hello() {\n  return 1\n}\n")


def test_every_known_keyword_is_uppercase():
    assert all(k == k.upper() for k in KNOWN_KEYWORDS)


def test_multi_keywords_are_known():
    assert MULTI_KEYWORDS <= KNOWN_KEYWORDS

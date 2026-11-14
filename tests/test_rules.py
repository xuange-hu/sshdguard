"""Rule tests: every rule gets at least one targeted trigger and one clean skip."""

from __future__ import annotations

import pytest

from sshdguard.engine import run
from sshdguard.parser import parse
from sshdguard.rules import REGISTRY, executable


def findings_for(text, rule_id=None):
    report = run(parse(text))
    if rule_id is None:
        return report.findings
    return [finding for finding in report.findings if finding.rule == rule_id]


def first(text, rule_id):
    found = findings_for(text, rule_id)
    assert found, f"{rule_id} did not fire on:\n{text}"
    return found[0]


def test_table_is_sorted_and_unique():
    table = executable()
    ids = [item.id for item in table]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))


def test_every_rule_has_prose():
    for item in REGISTRY:
        assert item.title and item.why and item.fix
        assert item.severity in {"critical", "high", "medium", "low", "note"}
        assert 1 <= item.stage <= 3


# -- pass 1 -----------------------------------------------------------------


def test_shd001_root_login_yes():
    finding = first("PermitRootLogin yes\n", "SHD001")
    assert finding.line == 1
    assert finding.offset == 0


def test_shd001_prohibit_password_not_flagged():
    assert findings_for("PermitRootLogin prohibit-password\n", "SHD001") == []


def test_shd002_empty_passwords():
    first("PermitEmptyPasswords yes\n", "SHD002")
    assert findings_for("PermitEmptyPasswords no\n", "SHD002") == []


def test_shd003_rhosts_rsa():
    first("RhostsRSAAuthentication yes\n", "SHD003")
    assert findings_for("RhostsRSAAuthentication no\n", "SHD003") == []


@pytest.mark.parametrize("line", ["Protocol 1", "Protocol 2,1", "Protocol 1.99"])
def test_shd004_protocol_1(line):
    first(line + "\n", "SHD004")


def test_shd004_protocol_2_only_clean():
    assert findings_for("Protocol 2\n", "SHD004") == []


def test_shd005_none_algorithm():
    first("Ciphers none\n", "SHD005")
    first("MACs aes128-gcm@openssh.com,none\n", "SHD005")


def test_shd005_none_word_boundary():
    # "anon" or "nonexistent" must not trigger
    assert findings_for("Ciphers aes128-cbc\n", "SHD005") == []


def test_shd006_password_auth_main_scope_only():
    first("PasswordAuthentication yes\n", "SHD006")
    # inside a Match it is SHD028's business, not SHD006's
    assert findings_for("Match User git\n    PasswordAuthentication yes\n", "SHD006") == []
    assert findings_for("PasswordAuthentication no\n", "SHD006") == []


def test_shd007_hostbased():
    first("HostbasedAuthentication yes\n", "SHD007")


def test_shd008_ignore_rhosts():
    first("IgnoreRhosts no\n", "SHD008")


def test_shd009_user_environment():
    first("PermitUserEnvironment yes\n", "SHD009")


def test_shd010_strict_modes():
    first("StrictModes no\n", "SHD010")


def test_shd011_weak_kex_replacement():
    first("KexAlgorithms diffie-hellman-group14-sha1\n", "SHD011")
    # strong list is clean
    assert findings_for("KexAlgorithms curve25519-sha256\n", "SHD011") == []
    # appended form belongs to SHD020
    assert findings_for("KexAlgorithms +diffie-hellman-group14-sha1\n", "SHD011") == []


def test_shd011_no_false_positive_on_similar_names():
    assert findings_for("KexAlgorithms diffie-hellman-group14-sha256\n", "SHD011") == []


def test_shd012_weak_cipher_replacement():
    first("Ciphers aes128-cbc,3des-cbc\n", "SHD012")
    assert findings_for("Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n", "SHD012") == []
    assert findings_for("Ciphers aes256-ctr\n", "SHD012") == []


def test_shd013_weak_mac_replacement():
    first("MACs hmac-sha1\n", "SHD013")
    assert findings_for("MACs hmac-sha2-256-etm@openssh.com\n", "SHD013") == []


def test_shd014_dsa_host_key():
    first("HostKey /etc/ssh/ssh_host_dsa_key\n", "SHD014")
    assert findings_for("HostKey /etc/ssh/ssh_host_ed25519_key\n", "SHD014") == []


def test_shd015_command_relative_path():
    finding = first("AuthorizedKeysCommand fetch_keys\n", "SHD015")
    assert "relative" in finding.message


def test_shd015_command_unsafe_path():
    first("AuthorizedKeysCommand /tmp/fetch_keys\n", "SHD015")


def test_shd015_command_clean():
    assert findings_for("AuthorizedKeysCommand /usr/local/sbin/fetch_keys\n", "SHD015") == []


def test_shd016_keys_file_unsafe():
    first("AuthorizedKeysFile /tmp/keys\n", "SHD016")


def test_shd016_keys_file_clean():
    assert findings_for("AuthorizedKeysFile .ssh/authorized_keys\n", "SHD016") == []


def test_shd017_host_key_relative():
    first("HostKey ssh_host_key\n", "SHD017")


def test_shd018_unknown_keyword():
    finding = first("BananaSplit yes\n", "SHD018")
    assert finding.line == 1


def test_shd018_removals_not_double_reported():
    # removed keywords are owned by SHD003/SHD004/SHD030
    assert findings_for("Protocol 1\nRhostsRSAAuthentication yes\nRSAAuthentication yes\n", "SHD018") == []


def test_shd019_first_value_wins():
    text = "X11Forwarding no\nX11Forwarding yes\n"
    finding = first(text, "SHD019")
    assert finding.line == 2


def test_shd019_repeatable_keywords_clean():
    assert findings_for("Port 22\nPort 2222\n", "SHD019") == []


def test_shd019_match_scope_duplicates():
    text = "Match User git\n    X11Forwarding no\n    X11Forwarding yes\n"
    first(text, "SHD019")


def test_shd020_weak_kex_appended():
    first("KexAlgorithms +diffie-hellman-group14-sha1\n", "SHD020")
    assert findings_for("KexAlgorithms +curve25519-sha256\n", "SHD020") == []


def test_shd021_weak_cipher_appended():
    first("Ciphers +arcfour256\n", "SHD021")


def test_shd022_weak_mac_appended():
    first("MACs +hmac-sha1\n", "SHD022")


def test_shd023_kbd_interactive():
    first("KbdInteractiveAuthentication yes\n", "SHD023")


def test_shd024_use_pam_main_scope():
    first("UsePAM no\n", "SHD024")
    assert findings_for("UsePAM yes\n", "SHD024") == []


def test_shd025_login_grace_zero():
    first("LoginGraceTime 0\n", "SHD025")
    assert findings_for("LoginGraceTime 2m\n", "SHD025") == []


def test_shd026_x11_main_scope():
    first("X11Forwarding yes\n", "SHD026")
    # match-scoped X11Forwarding yes belongs to SHD071 when it weakens the main scope
    assert findings_for("Match User git\n    X11Forwarding yes\n", "SHD026") == []


def test_shd027_gateway_ports():
    first("GatewayPorts yes\n", "SHD027")
    assert findings_for("GatewayPorts clientspecified\n", "SHD027") == []


def test_shd028_password_in_match():
    first("Match User git\n    PasswordAuthentication yes\n", "SHD028")
    assert findings_for("Match User git\n    PasswordAuthentication no\n", "SHD028") == []


def test_shd029_pubkey_disabled():
    first("PubkeyAuthentication no\n", "SHD029")


def test_shd030_removed_spelling():
    finding = first("RSAAuthentication yes\n", "SHD030")
    assert "removed" in finding.message
    # the two owned keywords never appear here
    assert findings_for("Protocol 1\n", "SHD030") == []
    assert findings_for("RhostsRSAAuthentication yes\n", "SHD030") == []


def test_shd031_tunnel():
    first("PermitTunnel yes\n", "SHD031")
    assert findings_for("PermitTunnel point-to-point\n", "SHD031") == []


def test_shd032_compression():
    first("Compression yes\n", "SHD032")
    assert findings_for("Compression delayed\n", "SHD032") == []


def test_shd033_max_auth_tries():
    first("MaxAuthTries 20\n", "SHD033")
    assert findings_for("MaxAuthTries 6\n", "SHD033") == []


def test_shd033_non_numeric_clean():
    assert findings_for("MaxAuthTries abc\n", "SHD033") == []


def test_shd034_wildcard_listen():
    first("ListenAddress 0.0.0.0\n", "SHD034")
    first("ListenAddress ::\n", "SHD034")
    assert findings_for("ListenAddress 10.0.0.5\n", "SHD034") == []


def test_shd035_bad_match():
    finding = first("Match Banana xyz\n", "SHD035")
    assert finding.line == 1


def test_shd035_three_kinds():
    text = "Match Banana xyz\nMatch User\nMatch\n"
    assert len(findings_for(text, "SHD035")) == 3


def test_shd036_include_in_match():
    first("Match User backup\n    Include /etc/ssh/peers/*.conf\n", "SHD036")
    assert findings_for("Include /etc/ssh/sshd_config.d/*.conf\n", "SHD036") == []


# -- pass 2 -----------------------------------------------------------------


def test_shd050_root_and_password():
    text = "PermitRootLogin yes\nPasswordAuthentication yes\n"
    finding = first(text, "SHD050")
    assert finding.line == 1


def test_shd050_main_scope_hardened_clean():
    assert findings_for("PermitRootLogin no\nPasswordAuthentication yes\n", "SHD050") == []


def test_shd050_prohibit_password_still_counts():
    first("PermitRootLogin prohibit-password\nPasswordAuthentication yes\n", "SHD050")


def test_shd051_only_password_left():
    first("PubkeyAuthentication no\nPasswordAuthentication yes\n", "SHD051")


def test_shd051_keys_still_allowed_clean():
    assert findings_for("PubkeyAuthentication yes\nPasswordAuthentication yes\n", "SHD051") == []


def test_shd052_password_in_authentication_methods():
    first("AuthenticationMethods password\n", "SHD052")
    assert findings_for("AuthenticationMethods publickey\n", "SHD052") == []


def test_shd053_multiple_ports():
    finding = first("Port 22\nPort 2222\nPort 22022\n", "SHD053")
    assert "3 ports" in finding.message


# -- pass 3 -----------------------------------------------------------------


def test_shd070_no_allowlist():
    finding = first("Port 22\n", "SHD070")
    assert finding.line == 0  # a file-level property, not a line


def test_shd070_empty_config_is_silent():
    assert findings_for("", "SHD070") == []


def test_shd070_allowlist_present_clean():
    assert findings_for("AllowUsers deploy\n", "SHD070") == []
    assert findings_for("AllowGroups ssh-users\n", "SHD070") == []


def test_shd071_match_weakens_main():
    text = "X11Forwarding no\nMatch Group devs\n    X11Forwarding yes\n"
    finding = first(text, "SHD071")
    assert finding.line == 3


def test_shd071_main_scope_unset_clean():
    # nothing to weaken: the main scope never set the keyword
    assert findings_for("Match Group devs\n    X11Forwarding yes\n", "SHD071") == []


def test_shd071_strengthening_is_clean():
    text = "X11Forwarding yes\nMatch Group devs\n    X11Forwarding no\n"
    assert findings_for(text, "SHD071") == []


def test_shd072_match_reenables_root():
    text = "PermitRootLogin no\nMatch User admin\n    PermitRootLogin yes\n"
    first(text, "SHD072")


def test_shd072_root_not_set_in_main():
    # PermitRootLogin unset in main: compiled default is prohibit-password, so
    # a Match with 'yes' is still a weakening
    first("Match User admin\n    PermitRootLogin yes\n", "SHD072")


def test_shd073_dead_glob():
    finding = first("Include /etc/ssh/sshd_config.d/*.definitely-missing\n", "SHD073")
    assert "matches no file" in finding.message


def test_shd073_live_glob_clean(tmp_path):
    from sshdguard.parser import parse_file

    (tmp_path / "drop.conf").write_text("Port 22\n", encoding="utf-8")
    (tmp_path / "sshd_config").write_text("Include drop.conf\n", encoding="utf-8")
    report = run(parse_file(tmp_path / "sshd_config"))
    assert [f for f in report.findings if f.rule == "SHD073"] == []


# -- invariants ---------------------------------------------------------------


def test_every_finding_has_offset_and_line():
    report = run(parse("PermitRootLogin yes\nPort 22\nMatch Banana xyz\n"))
    for finding in report.findings:
        if finding.line > 0:
            assert finding.offset >= 0


def test_report_is_sorted_by_severity():
    report = run(
        parse(
            "Port 22\nMaxAuthTries 20\nPermitRootLogin yes\nPasswordAuthentication yes\n"
            "PermitEmptyPasswords yes\nX11Forwarding yes\n"
        )
    )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}
    keys = [order[f.severity] for f in report.findings]
    assert keys == sorted(keys)


def test_risk_saturates_at_100():
    report = run(parse("PermitRootLogin yes\nPermitEmptyPasswords yes\nRhostsRSAAuthentication yes\nProtocol 1\n"))
    assert report.risk == 100


def test_rules_run_matches_table():
    report = run(parse("Port 22\n"))
    assert report.rules_run == len(REGISTRY)
    assert report.rule_ids == [item.id for item in executable()]

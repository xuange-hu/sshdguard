"""Built-in corpora that between them trigger every rule in the table.

One call proves the parser, the three passes and the whole rule table work
end to end, with no files of your own needed. The corpora are intentionally
outrageous: each line exists to trip exactly one rule, so a rule that stops
firing is a regression you can see by name.
"""

from __future__ import annotations

from .engine import run
from .parser import parse
from .rules import REGISTRY

_CORPORA: dict[str, str] = {
    "wide-open": "\n".join(
        [
            "# the kitchen sink: every line an auditor dreads, in one file",
            "PermitRootLogin yes",
            "PermitEmptyPasswords yes",
            "PasswordAuthentication yes",
            "KbdInteractiveAuthentication yes",
            "PubkeyAuthentication no",
            "HostbasedAuthentication yes",
            "IgnoreRhosts no",
            "PermitUserEnvironment yes",
            "StrictModes no",
            "UsePAM no",
            "X11Forwarding yes",
            "GatewayPorts yes",
            "PermitTunnel yes",
            "Compression yes",
            "LoginGraceTime 0",
            "MaxAuthTries 20",
            "ListenAddress 0.0.0.0",
            "RhostsRSAAuthentication yes",
            "Protocol 2,1",
            "Ciphers aes128-cbc,3des-cbc",
            "MACs hmac-sha1,hmac-md5",
            "KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
            "AuthorizedKeysCommand fetch_keys",
            "AuthorizedKeysFile /tmp/keys",
            "HostKey ssh_host_key",
            "HostKey /etc/ssh/ssh_host_dsa_key",
            "RSAAuthentication yes",
            "AuthenticationMethods password",
            "Port 22",
            "Port 2222",
            # duplicates: sshd took the first value, these lines are dead text
            "Ciphers +arcfour256",
            "MACs +hmac-sha1",
            "KexAlgorithms +diffie-hellman-group1-sha1",
            "Ciphers none",
            "BananaSplit yes",
        ]
    )
    + "\n",
    "match-override": "\n".join(
        [
            "# main scope looks hardened -- the Match blocks undo it",
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "X11Forwarding no",
            "AllowTcpForwarding no",
            "AllowUsers deploy",
            "Match User git",
            "    PasswordAuthentication yes",
            "Match Group devs",
            "    X11Forwarding yes",
            "    AllowTcpForwarding all",
            "Match User admin",
            "    PermitRootLogin yes",
            "Match Banana xyz",
            "    ForceCommand /bin/false",
            "Match User",
            "Match",
            "    PermitTTY yes",
        ]
    )
    + "\n",
    "include-traps": "\n".join(
        [
            "# includes that include nothing, and one inside a Match",
            "Include /etc/ssh/sshd_config.d/*.missing",
            "Port 22",
            "Match User backup",
            "    Include /etc/ssh/peers/*.conf",
            "    PasswordAuthentication no",
            "    PasswordAuthentication no",
        ]
    )
    + "\n",
    "defaults-only": "\n".join(
        [
            "# nothing pinned: the posture is whatever this OpenSSH build defaults to",
            "Port 22",
            "HostKey /etc/ssh/ssh_host_ed25519_key",
            "Subsystem sftp internal-sftp",
            "PrintMotd no",
        ]
    )
    + "\n",
}


def names() -> list[str]:
    return sorted(_CORPORA)


def reports() -> list[tuple[str, object]]:
    """(name, Report) for every corpus, in name order."""
    out = []
    for name in names():
        app = parse(_CORPORA[name], source=name)
        out.append((name, run(app, target=name)))
    return out


def coverage() -> tuple[set[str], int]:
    """Rule ids fired across all corpora, and the size of the table."""
    fired: set[str] = set()
    for _name, report in reports():
        fired |= report.fired
    return fired, len(REGISTRY)


__all__ = ["coverage", "names", "reports"]

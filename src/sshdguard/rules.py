"""The rule table, in three passes.

* Pass 1 reads one entry at a time: the auth toggles, the algorithm lists,
  the availability traps (unknown keyword, bad Match, relative HostKey).
* Pass 2 reads combinations: root plus password in the same scope, pubkey
  disabled while password stays on, first-obtained-value-wins duplicates.
* Pass 3 reads scopes and files against each other: a Match block that
  silently weakens main-scope hardening, an Include glob that matches
  nothing, a config that never pins its own posture.

Every rule yields an Issue with the line and byte offset it is talking about;
a rule that cannot name its own evidence does not ship.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from dataclasses import field as dc_field

from .model import App, Entry, Scope
from .parser import MULTI_KEYWORDS, REMOVED_KEYWORDS

WEAK_KEX = (
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha256",
    "rsa1024-sha1",
)
WEAK_CIPHERS = (
    "arcfour",
    "arcfour128",
    "arcfour256",
    "3des-cbc",
    "3des-ctr",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "rijndael-cbc@lysator.liu.se",
    "blowfish-cbc",
    "cast128-cbc",
)
WEAK_MACS = (
    "hmac-sha1",
    "hmac-sha1-96",
    "hmac-md5",
    "hmac-md5-96",
    "hmac-ripemd160",
    "hmac-ripemd160@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
    "hmac-md5-etm@openssh.com",
    "umac-32@openssh.com",
    "umac-64@openssh.com",
    "umac-32-etm@openssh.com",
)
ALGO_KEYWORDS = ("KEXALGORITHMS", "CIPHERS", "MACS")

# Per-keyword value strength, weakest first. Used by pass 3 to detect a Match
# block re-enabling something the main scope disabled. Keywords not listed
# have no well-ordered strength and are skipped.
STRENGTH: dict[str, tuple[str, ...]] = {
    "PERMITROOTLOGIN": ("yes", "prohibit-password", "forced-commands-only", "no"),
    "PERMITEMPTYPASSWORDS": ("yes", "no"),
    "PASSWORDAUTHENTICATION": ("yes", "no"),
    "PUBKEYAUTHENTICATION": ("no", "yes"),
    "KBDINTERACTIVEAUTHENTICATION": ("yes", "no"),
    "HOSTBASEDAUTHENTICATION": ("yes", "no"),
    "IGNORERHOSTS": ("no", "yes"),
    "STRICTMODES": ("no", "yes"),
    "PERMITUSERENVIRONMENT": ("yes", "no"),
    "X11FORWARDING": ("yes", "no"),
    "ALLOWAGENTFORWARDING": ("yes", "no"),
    "ALLOWTCPFORWARDING": ("all", "yes", "remote", "local", "no"),
    "GATEWAYPORTS": ("yes", "clientspecified", "no"),
    "PERMITTUNNEL": ("yes", "ethernet", "point-to-point", "no"),
    "USEPAM": ("no", "yes"),
}

# Values meaning "on" for auth toggles, for the combination rules.
YES = {"yes"}

UNSAFE_PATH_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/dev/")
UNSAFE_PATH_EXACT = ("/tmp", "/var/tmp", "/dev/shm")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    score: int
    stage: int  # 1 line, 2 combination, 3 scope/file
    why: str
    fix: str
    check: Callable[[Context], Iterator[Issue]]


@dataclass
class Issue:
    """One rule's complaint, with the bytes that caused it."""

    message: str
    line: int
    offset: int
    length: int = 0
    saw: str = ""
    fix: str = ""
    where: str = ""


@dataclass
class Context:
    """Everything a rule may look at."""

    app: App
    _weak_cache: dict[tuple[str, str, bool], list[str]] = dc_field(default_factory=dict)

    def scopes(self) -> list[Scope]:
        return self.app.scopes

    def main_scope(self) -> Scope | None:
        return self.app.main

    def weak_algorithms(self, entry: Entry, table: tuple[str, ...]) -> list[str]:
        """Which weak algorithm names appear in this entry's argument text.

        Matching is word-boundary based so ``hmac-sha1`` does not match inside
        ``hmac-sha1-etm@openssh.com`` twice and ``aes256-ctr`` is not tripped
        by ``aes256-cbc``. Cached per (keyword, args, table identity).
        """
        key = (entry.keyword, " ".join(entry.args), id(table))
        if key in self._weak_cache:
            return self._weak_cache[key]
        found: list[str] = []
        text = " ".join(entry.args).lower()
        for name in table:
            if re.search(rf"(?<![a-z0-9@.\-]){re.escape(name)}(?![a-z0-9@.\-])", text):
                found.append(name)
        self._weak_cache[key] = found
        return found


REGISTRY: list[Rule] = []


def rule(rule_id: str, title: str, severity: str, score: int, stage: int, why: str, fix: str) -> Callable:
    def decorate(fn: Callable) -> Callable:
        REGISTRY.append(
            Rule(id=rule_id, title=title, severity=severity, score=score, stage=stage, why=why, fix=fix, check=fn)
        )
        return fn

    return decorate


# ---------------------------------------------------------------------------
# pass 1 -- one entry at a time
# ---------------------------------------------------------------------------


def _iter_entries(ctx: Context) -> Iterator[tuple[Scope, Entry]]:
    for scope in ctx.scopes():
        for entry in scope.entries:
            yield scope, entry


@rule(
    "SHD001",
    "PermitRootLogin yes",
    "critical",
    33,
    1,
    "Direct root login with any authentication method is enabled. Root is the one account that always exists on the "
    "box, so an attacker gets an unguessable-off target with full privileges; most brute-force and botnet traffic "
    "tries it first.",
    "Set PermitRootLogin prohibit-password (keys only) or no, and use a non-root account with sudo.",
)
def _shd001(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "PERMITROOTLOGIN" and entry.args and entry.args[0].lower() == "yes":
            yield Issue(
                message="root can log in over SSH with any method, including a password",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD002",
    "PermitEmptyPasswords yes",
    "critical",
    33,
    1,
    "Accounts with a blank password can log in over SSH. Some system and service accounts ship with empty passwords, "
    "so this turns every one of them into a network-accessible login.",
    "Set PermitEmptyPasswords no (the compiled-in default).",
)
def _shd002(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "PERMITEMPTYPASSWORDS" and entry.args and entry.args[0].lower() == "yes":
            yield Issue(
                message="accounts with empty passwords may log in over SSH",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD003",
    "RhostsRSAAuthentication yes",
    "critical",
    33,
    1,
    "Trusts ~/.rhosts and /etc/hosts.equiv for SSHv1-style host-based authentication. A user who can write their "
    "rhosts file, or an attacker who controls a listed host name via DNS, gets in without any key.",
    "Remove the line; on modern OpenSSH it is rejected outright (RhostsRSAAuthentication was removed in 7.4).",
)
def _shd003(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "RHOSTSRSAAUTHENTICATION" and entry.args and entry.args[0].lower() == "yes":
            yield Issue(
                message="host-based rhosts authentication is enabled (protocol-1 era)",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD004",
    "Protocol 1",
    "critical",
    33,
    1,
    "The SSHv1 protocol is requested. SSHv1 has no integrity protection against active attacks and the server "
    "konwn-hosts model is weaker; OpenSSH removed support entirely in 7.6.",
    "Remove the Protocol line; modern sshd speaks SSHv2 only.",
)
def _shd004(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "PROTOCOL":
            continue
        versions = [piece.strip().lower() for arg in entry.args for piece in arg.split(",")]
        if "1" in versions or "1.99" in versions:
            yield Issue(
                message="SSH protocol version 1 is enabled or negotiated",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD005",
    "'none' algorithm negotiated",
    "critical",
    33,
    1,
    "The keyword 'none' appears in Ciphers, MACs or KexAlgorithms, disabling encryption or integrity on the "
    "transport. Every session is then readable and modifiable in flight.",
    "Remove 'none' from the algorithm lists; it exists only for debugging at build time.",
)
def _shd005(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword not in ALGO_KEYWORDS:
            continue
        text = " ".join(entry.args).lower()
        if re.search(r"(?<![a-z0-9@.\-])none(?![a-z0-9@.\-])", text):
            yield Issue(
                message=f"{entry.keyword.lower()} allows 'none' -- no encryption or no integrity",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD006",
    "PasswordAuthentication yes",
    "high",
    11,
    1,
    "Password authentication is enabled in the main scope. Every account becomes guessable over the network, and "
    "credential stuffing against exposed SSH endpoints is constant background noise.",
    "Set PasswordAuthentication no and deploy keys; if passwords must stay, restrict exposure with AllowUsers and "
    "fail2ban.",
)
def _shd006(ctx: Context) -> Iterator[Issue]:
    main = ctx.main_scope()
    if main is None:
        return
    for entry in main.entries:
        if entry.keyword == "PASSWORDAUTHENTICATION" and entry.args and entry.args[0].lower() in YES:
            yield Issue(
                message="password authentication is enabled globally",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )
            return


@rule(
    "SHD007",
    "HostbasedAuthentication yes",
    "high",
    11,
    1,
    "Host-based authentication trusts the client machine's identity. A compromised client host (or spoofed host "
    "name in the trusted table) yields access to every account it lists.",
    "Set HostbasedAuthentication no (the default).",
)
def _shd007(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "HOSTBASEDAUTHENTICATION" and entry.args and entry.args[0].lower() in YES:
            yield Issue(
                message="host-based authentication is enabled",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD008",
    "IgnoreRhosts no",
    "high",
    11,
    1,
    "Per-user ~/.shosts and /etc/hosts.equiv files are honoured for host-based authentication. Any user can then "
    "create a trust file and log in from a listed host without a key.",
    "Set IgnoreRhosts yes (the default).",
)
def _shd008(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "IGNORERHOSTS" and entry.args and entry.args[0].lower() == "no":
            yield Issue(
                message="per-user .shosts/.rhosts trust files are honoured",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD009",
    "PermitUserEnvironment yes",
    "high",
    11,
    1,
    "Accepts environment variables from the client (LANG and LC_* by default, everything via ~/.ssh/environment or "
    "authorized_keys environment= options). Variables like LD_PRELOAD, BASH_ENV or PYTHONPATH turn key insertion "
    "into code execution.",
    "Set PermitUserEnvironment no (the default).",
)
def _shd009(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "PERMITUSERENVIRONMENT" and entry.args and entry.args[0].lower() in YES:
            yield Issue(
                message="user-supplied environment variables are accepted (LD_PRELOAD et al.)",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD010",
    "StrictModes no",
    "high",
    11,
    1,
    "sshd skips permission and ownership checks on the user's home directory, .ssh and authorized_keys. A "
    "world-writable home or a .ssh directory someone else can write turns 'add a key' into an unprivileged local "
    "action.",
    "Set StrictModes yes (the default).",
)
def _shd010(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "STRICTMODES" and entry.args and entry.args[0].lower() == "no":
            yield Issue(
                message="ownership/permission checks on key files are skipped",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD011",
    "SHA-1 key exchange",
    "high",
    11,
    1,
    "The KexAlgorithms list names a SHA-1 kex. SHA-1 key exchange lacks the hardness of the modern curve and "
    "post-quantum methods and is a well-known downgrade target in scanning reports.",
    "Use curve25519-sha256 (and sntrup761x25519-sha512@openssh.com); remove the SHA-1 kex entries.",
)
def _shd011(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "KEXALGORITHMS":
            continue
        if entry.args and entry.args[0].startswith(("+", "^")):
            continue  # appended/prepended forms are SHD020's scope
        weak = ctx.weak_algorithms(entry, WEAK_KEX)
        if weak:
            yield Issue(
                message=f"weak key exchange listed: {', '.join(weak)}",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD012",
    "weak cipher (CBC / arcfour / 3DES)",
    "high",
    11,
    1,
    "The Ciphers list names a CBC-mode cipher, arcfour or 3DES. CBC ciphers are vulnerable to plaintext recovery "
    "under the classic TLS-style oracle attacks OpenSSH itself patched against (CVE-2008-5161 era), arcfour is a "
    "raw RC4 stream, 3DES is deprecated by every profile.",
    "List only chacha20-poly1305@openssh.com and aes*-gcm@openssh.com (or at least aes*-ctr).",
)
def _shd012(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "CIPHERS":
            continue
        if entry.args and entry.args[0].startswith(("+", "^")):
            continue  # appended/prepended forms are SHD021's scope
        weak = ctx.weak_algorithms(entry, WEAK_CIPHERS)
        if weak:
            yield Issue(
                message=f"weak cipher listed: {', '.join(weak)}",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD013",
    "weak MAC (SHA-1 / MD5 / 64-bit umac)",
    "high",
    7,
    1,
    "The MACs list names an SHA-1, MD5 or truncated umac MAC. These no longer provide meaningful integrity "
    "guarantees against a determined attacker.",
    "List hmac-sha2-256-etm@openssh.com and hmac-sha2-512-etm@openssh.com.",
)
def _shd013(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "MACS":
            continue
        if entry.args and entry.args[0].startswith(("+", "^")):
            continue  # appended/prepended forms are SHD022's scope
        weak = ctx.weak_algorithms(entry, WEAK_MACS)
        if weak:
            yield Issue(
                message=f"weak MAC listed: {', '.join(weak)}",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD014",
    "DSA host key",
    "high",
    7,
    1,
    "A HostKey line points at an ssh_host_dsa_key. DSA (1024-bit, SHA-1) keys are deprecated by OpenSSH itself "
    "and were removed from the default offer; keeping one invites downgrades and fails on modern builds.",
    "Remove the DSA HostKey line and generate Ed25519 (ssh-keygen -t ed25519).",
)
def _shd014(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "HOSTKEY":
            continue
        if entry.args and "dsa" in entry.args[0].lower():
            yield Issue(
                message="DSA host key referenced",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD015",
    "AuthorizedKeysCommand unsafe path",
    "high",
    7,
    1,
    "AuthorizedKeysCommand points at a relative path or a world-writable location. A relative path is resolved "
    "against root's PATH (undefined), and /tmp-style paths let any local user replace the command that decides "
    "which keys are trusted.",
    "Use an absolute path under /usr/local or /etc, owned by root and not world-writable.",
)
def _shd015(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword not in ("AUTHORIZEDKEYSCOMMAND", "AUTHORIZEDPRINCIPALSCOMMAND"):
            continue
        if not entry.args:
            continue
        command = entry.args[0]
        if not command.startswith("/"):
            yield Issue(
                message=f"{entry.keyword.lower()} uses a relative path ({command!r})",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )
        elif command.startswith(UNSAFE_PATH_PREFIXES) or command in UNSAFE_PATH_EXACT:
            yield Issue(
                message=f"{entry.keyword.lower()} lives in a world-writable location ({command!r})",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD016",
    "AuthorizedKeysFile unsafe location",
    "high",
    7,
    1,
    "AuthorizedKeysFile points into a world-writable location. Whoever can write that path decides who can log in "
    "as the affected user.",
    "Keep the default .ssh/authorized_keys, or use an absolute root-owned path.",
)
def _shd016(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "AUTHORIZEDKEYSFILE":
            continue
        for token in entry.args:
            if token.startswith(UNSAFE_PATH_PREFIXES) or token in UNSAFE_PATH_EXACT:
                yield Issue(
                    message=f"authorized keys read from a world-writable location ({token!r})",
                    line=entry.line,
                    offset=entry.offset,
                    length=entry.length,
                    saw=entry.raw.strip(),
                    where=entry.where,
                )
            elif token.startswith("/"):
                break  # first absolute entry wins; later tokens are dead text


@rule(
    "SHD017",
    "HostKey relative path",
    "high",
    7,
    1,
    "A HostKey line uses a relative path. sshd requires absolute paths; with this line the host key is silently "
    "not loaded, and on some builds ``sshd -t`` fails so a restart drops the service.",
    "Use the absolute path (e.g. /etc/ssh/ssh_host_ed25519_key).",
)
def _shd017(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "HOSTKEY":
            continue
        if entry.args and not entry.args[0].startswith("/"):
            yield Issue(
                message=f"host key path is relative ({entry.args[0]!r}) -- sshd requires absolute",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD018",
    "unknown keyword",
    "high",
    7,
    1,
    "The keyword is not part of sshd_config. Unlike most servers, sshd refuses to start on an unknown keyword: "
    "``sshd -t`` errors and a restart (package upgrade, reboot) leaves the machine without SSH.",
    "Fix or remove the line; verify with sshd -t before restarting.",
)
def _shd018(ctx: Context) -> Iterator[Issue]:
    for unknown in ctx.app.unknowns:
        yield Issue(
            message=f"unknown keyword {unknown.keyword!r} -- sshd -t fails and a restart drops the service",
            line=unknown.line,
            offset=unknown.offset,
            length=unknown.length,
            saw=unknown.keyword,
            where=unknown.where,
        )


@rule(
    "SHD019",
    "duplicate keyword (first wins)",
    "high",
    7,
    1,
    "The keyword appears again in the same scope. sshd uses the first obtained value, so the later line is dead "
    "text: the hardening someone wrote at the bottom of the file is not in effect, and readers believe it is. "
    "This is the sshd mirror of a bug class found in every 'append at the end' config workflow.",
    "Keep one occurrence per keyword per scope; delete or move the later one above the first.",
)
def _shd019(ctx: Context) -> Iterator[Issue]:
    for scope in ctx.scopes():
        seen: set[str] = set()
        for entry in scope.entries:
            if entry.keyword in ("MATCH",):
                continue
            if entry.keyword in seen:
                if entry.keyword in MULTI_KEYWORDS:
                    continue  # legitimately repeatable
                yield Issue(
                    message=f"{entry.keyword.lower()} appears again -- sshd already took the first value, this line is dead",
                    line=entry.line,
                    offset=entry.offset,
                    length=entry.length,
                    saw=entry.raw.strip(),
                    where=entry.where,
                )
            else:
                seen.add(entry.keyword)


@rule(
    "SHD020",
    "weak kex appended with +",
    "medium",
    3,
    1,
    "KexAlgorithms uses the '+' (append to default) form and appends a SHA-1 kex. Appending does not remove the "
    "strong defaults, but it advertises the weak method to clients and scanners as acceptable.",
    "Remove the appended entry; if a legacy client needs it, scope it with a Match block.",
)
def _shd020(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "KEXALGORITHMS":
            continue
        if not entry.args or not entry.args[0].startswith("+"):
            continue
        weak = ctx.weak_algorithms(entry, WEAK_KEX)
        if weak:
            yield Issue(
                message=f"weak key exchange appended to defaults: {', '.join(weak)}",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD021",
    "weak cipher appended with +",
    "medium",
    3,
    1,
    "Ciphers uses the '+' (append to default) form and appends a CBC/arcfour/3DES cipher. The weak method is then "
    "offered in every handshake, which is what scanners and downgrade-mitM probing look for.",
    "Remove the appended entry.",
)
def _shd021(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "CIPHERS":
            continue
        if not entry.args or not entry.args[0].startswith("+"):
            continue
        weak = ctx.weak_algorithms(entry, WEAK_CIPHERS)
        if weak:
            yield Issue(
                message=f"weak cipher appended to defaults: {', '.join(weak)}",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD022",
    "weak MAC appended with +",
    "medium",
    3,
    1,
    "MACs uses the '+' (append to default) form and appends an SHA-1/MD5-era MAC.",
    "Remove the appended entry.",
)
def _shd022(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "MACS":
            continue
        if not entry.args or not entry.args[0].startswith("+"):
            continue
        weak = ctx.weak_algorithms(entry, WEAK_MACS)
        if weak:
            yield Issue(
                message=f"weak MAC appended to defaults: {', '.join(weak)}",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD023",
    "KbdInteractiveAuthentication yes",
    "medium",
    3,
    1,
    "Keyboard-interactive (PAM conversation) authentication is enabled. On its own it is a supported method, but "
    "combined with password authentication it doubles the guessing surface and usually re-opens what PasswordAuthen-"
    "tication no tried to close.",
    "Set KbdInteractiveAuthentication no unless a PAM-based second factor is actually configured.",
)
def _shd023(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "KBDINTERACTIVEAUTHENTICATION" and entry.args and entry.args[0].lower() in YES:
            yield Issue(
                message="keyboard-interactive (PAM) authentication is enabled",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD024",
    "UsePAM no",
    "medium",
    3,
    1,
    "PAM is disabled. Account checks (expiry, lockout, pam_faillock), password policy and any MFA stack wired "
    "through PAM silently stop applying to SSH logins.",
    "Set UsePAM yes on Linux.",
)
def _shd024(ctx: Context) -> Iterator[Issue]:
    main = ctx.main_scope()
    if main is None:
        return
    for entry in main.entries:
        if entry.keyword == "USEPAM" and entry.args and entry.args[0].lower() == "no":
            yield Issue(
                message="PAM checks disabled for SSH logins",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )
            return


@rule(
    "SHD025",
    "LoginGraceTime 0",
    "medium",
    3,
    1,
    "Unauthenticated sessions may wait forever. Each one holds a connection slot; the pre-auth slots are the "
    "resource MaxStartups protects, and 0 turns a slow-loris-style hold into an unbounded outage primitive.",
    "Set LoginGraceTime to 30s-2m (the default is 2m).",
)
def _shd025(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "LOGINGRACETIME" and entry.args and entry.args[0] in ("0", "0s", "0m"):
            yield Issue(
                message="unauthenticated connections may wait indefinitely",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD026",
    "X11Forwarding yes",
    "medium",
    3,
    1,
    "X11 forwarding is on. The X11 channel carries keystrokes between hosts without authentication between "
    "clients on the server side; on a shared box it widens the post-login attack surface (xauth trust, cookie "
    "theft) for everyone who can log in.",
    "Set X11Forwarding no unless the workflow needs it.",
)
def _shd026(ctx: Context) -> Iterator[Issue]:
    main = ctx.main_scope()
    if main is None:
        return
    for entry in main.entries:
        if entry.keyword == "X11FORWARDING" and entry.args and entry.args[0].lower() in YES:
            yield Issue(
                message="X11 forwarding is enabled globally",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )
            return


@rule(
    "SHD027",
    "GatewayPorts yes",
    "medium",
    3,
    1,
    "Remote port forwards bind to wildcard addresses by default. Any user who can SSH in publishes a listener on "
    "every interface of the server, bypassing perimeter controls.",
    "Set GatewayPorts no (the default), or clientspecified with per-user policy.",
)
def _shd027(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "GATEWAYPORTS" and entry.args and entry.args[0].lower() in YES:
            yield Issue(
                message="remote forwards bind to all interfaces",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD028",
    "PasswordAuthentication yes inside Match",
    "medium",
    3,
    1,
    "A Match block re-enables password authentication for its criteria. If the criteria are broader than one "
    "service account, the group-wide password surface is back.",
    "Restrict the Match criteria to the exact accounts that need it, or switch them to keys.",
)
def _shd028(ctx: Context) -> Iterator[Issue]:
    for scope in ctx.app.match_scopes:
        for entry in scope.entries:
            if entry.keyword == "PASSWORDAUTHENTICATION" and entry.args and entry.args[0].lower() in YES:
                yield Issue(
                    message=f"password authentication re-enabled for {scope.label}",
                    line=entry.line,
                    offset=entry.offset,
                    length=entry.length,
                    saw=entry.raw.strip(),
                    where=entry.where,
                )


@rule(
    "SHD029",
    "PubkeyAuthentication no",
    "medium",
    3,
    1,
    "Public-key authentication is disabled, pushing every login onto passwords (or host-based methods). Key-based "
    "auth is the single control that makes SSH brute-force economically pointless.",
    "Set PubkeyAuthentication yes (the default).",
)
def _shd029(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "PUBKEYAUTHENTICATION" and entry.args and entry.args[0].lower() == "no":
            yield Issue(
                message="public-key authentication is disabled",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD030",
    "keyword removed by OpenSSH",
    "note",
    1,
    1,
    "The keyword was removed or renamed by OpenSSH. On a modern build the line is rejected like any unknown "
    "keyword: sshd -t fails and a restart drops the service.",
    "Delete the line or use its modern spelling.",
)
def _shd030(ctx: Context) -> Iterator[Issue]:
    owned = {"RHOSTSRSAAUTHENTICATION", "PROTOCOL"}  # SHD003/SHD004 own these
    removed_titles = {
        "RSAAUTHENTICATION": "removed in OpenSSH 7.0",
        "AUTHORIZEDKEYSFILE2": "merged into AuthorizedKeysFile in 5.9",
        "USEPRIVILEGESEPARATION": "removed in OpenSSH 7.5",
        "AFSTOKENPASSING": "removed long ago",
        "CHALLENGERESPONSEAUTHENTICATION": "renamed KbdInteractiveAuthentication in 8.7",
        "HOSTBASEDKEYTYPES": "renamed HostbasedAcceptedAlgorithms in 8.5",
        "PUBKEYACCEPTEDKEYTYPES": "renamed PubkeyAcceptedAlgorithms in 8.5",
    }
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword in REMOVED_KEYWORDS and entry.keyword not in owned:
            yield Issue(
                message=f"{entry.keyword.lower()} is a removed spelling ({removed_titles.get(entry.keyword, 'obsolete')})",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD031",
    "PermitTunnel yes",
    "low",
    1,
    1,
    "layer-2/layer-3 tunnels may be established over SSH. A tun device hands the client an interface inside the "
    "server's network -- a pivot point that bypasses the SSH chokepoint entirely.",
    "Set PermitTunnel no (the default), or point-to-point for a specific need.",
)
def _shd031(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "PERMITTUNNEL" and entry.args and entry.args[0].lower() in YES:
            yield Issue(
                message="SSH tunnels may create network interfaces",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD032",
    "Compression yes",
    "low",
    1,
    1,
    "Compression is forced on (the default is delayed, after authentication). Pre-auth compression enlarges the "
    "pre-authentication code path and was historically the source of memory-corruption advisories.",
    "Set Compression no, or leave the delayed default.",
)
def _shd032(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword == "COMPRESSION" and entry.args and entry.args[0].lower() in YES:
            yield Issue(
                message="compression forced on for all sessions including pre-auth",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD033",
    "MaxAuthTries excessive",
    "low",
    1,
    1,
    "A very high MaxAuthTries lets each connection attempt many passwords, multiplying the brute-force rate a "
    "single connection achieves before the disconnect (which is what most rate limiters key on).",
    "Keep MaxAuthTries at the default 6 or lower.",
)
def _shd033(ctx: Context) -> Iterator[Issue]:
    for _scope, entry in _iter_entries(ctx):
        if entry.keyword != "MAXAUTHTRIES" or not entry.args:
            continue
        try:
            value = int(entry.args[0])
        except ValueError:
            continue
        if value > 10 or value == 0:
            yield Issue(
                message=f"MaxAuthTries {value} -- each connection gets a large guessing budget",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD034",
    "ListenAddress wildcard",
    "note",
    1,
    1,
    "The daemon binds to all interfaces. Not a finding by itself -- but combined with weak authentication it is "
    "the difference between 'misconfigured service' and 'internet-exposed misconfigured service'.",
    "Bind to specific addresses where the topology allows it.",
)
def _shd034(ctx: Context) -> Iterator[Issue]:
    main = ctx.main_scope()
    if main is None:
        return
    for entry in main.entries:
        if entry.keyword != "LISTENADDRESS" or not entry.args:
            continue
        address = entry.args[0]
        if address in ("0.0.0.0", "::") or address.startswith("0.0.0.0:") or address.startswith("::"):
            yield Issue(
                message=f"listening on every interface ({address})",
                line=entry.line,
                offset=entry.offset,
                length=entry.length,
                saw=entry.raw.strip(),
                where=entry.where,
            )


@rule(
    "SHD035",
    "Match criteria sshd cannot parse",
    "high",
    7,
    1,
    "The Match line uses an unknown criterion or a criterion with no value. sshd -t fails on the first bad Match, "
    "so a restart drops the service -- and everything after the Match line is dead text meanwhile.",
    "Fix the criteria against sshd_config(5) MATCH CRITERIA; verify with sshd -t.",
)
def _shd035(ctx: Context) -> Iterator[Issue]:
    for bad in ctx.app.bad_matches:
        yield Issue(
            message=f"Match block cannot be parsed ({bad.reason})",
            line=bad.line,
            offset=bad.offset,
            length=bad.length,
            saw=f"Match {bad.criteria}".strip(),
            where=bad.where,
        )


@rule(
    "SHD036",
    "Include inside Match",
    "low",
    1,
    1,
    "An Include appears inside a Match block. Everything in the included file now applies only to that scope, "
    "including main-scope keywords it was written for -- the exact opposite of what the file was written to do.",
    "Move the Include above any Match block, or rewrite the included file for the scope.",
)
def _shd036(ctx: Context) -> Iterator[Issue]:
    for include in ctx.app.includes:
        if include.in_match:
            yield Issue(
                message="Include inside a Match block: included directives apply to that scope only",
                line=include.line,
                offset=include.offset,
                length=include.length,
                saw=include.pattern,
                where=include.where,
            )


# ---------------------------------------------------------------------------
# pass 2 -- keyword combinations inside one scope
# ---------------------------------------------------------------------------


@rule(
    "SHD050",
    "root + password in one scope",
    "critical",
    33,
    2,
    "The same scope allows root login and password authentication. That combination is the single most brute-"
    "forced thing on the internet; it does not need a zero-day, only a dictionary.",
    "PermitRootLogin prohibit-password (or no), or PasswordAuthentication no -- at least one of the two.",
)
def _shd050(ctx: Context) -> Iterator[Issue]:
    for scope in ctx.scopes():
        root = scope.first("PERMITROOTLOGIN")
        password = scope.first("PASSWORDAUTHENTICATION")
        if (
            root is not None
            and password is not None
            and root.args
            and password.args
            and root.args[0].lower() in ("yes", "prohibit-password")
            and password.args[0].lower() in YES
        ):
            yield Issue(
                message=f"{scope.label}: root can log in with a password",
                line=root.line,
                offset=root.offset,
                length=root.length,
                saw=f"{root.raw.strip()} + {password.raw.strip()}",
                where=root.where,
            )


@rule(
    "SHD051",
    "pubkey off, password on",
    "high",
    11,
    2,
    "The same scope disables public-key authentication and enables passwords. Keys are the control that makes "
    "online guessing pointless; with them off, the whole estate's SSH auth strength is 'the password policy'.",
    "Re-enable PubkeyAuthentication and deploy keys before disabling passwords.",
)
def _shd051(ctx: Context) -> Iterator[Issue]:
    for scope in ctx.scopes():
        pubkey = scope.first("PUBKEYAUTHENTICATION")
        password = scope.first("PASSWORDAUTHENTICATION")
        if (
            pubkey is not None
            and password is not None
            and pubkey.args
            and password.args
            and pubkey.args[0].lower() == "no"
            and password.args[0].lower() in YES
        ):
            yield Issue(
                message=f"{scope.label}: only password guessing remains as an auth method",
                line=pubkey.line,
                offset=pubkey.offset,
                length=pubkey.length,
                saw=f"{pubkey.raw.strip()} + {password.raw.strip()}",
                where=pubkey.where,
            )


@rule(
    "SHD052",
    "AuthenticationMethods includes password",
    "medium",
    3,
    2,
    "AuthenticationMethods names password as an acceptable factor. The directive is meant to enforce strong "
    "combinations (e.g. publickey,keyboard-interactive); listing password alone or in a chain weakens the intent "
    "and documents the weakness.",
    "Require publickey or keyboard-interactive (with MFA) in the list.",
)
def _shd052(ctx: Context) -> Iterator[Issue]:
    for scope in ctx.scopes():
        for entry in scope.entries:
            if entry.keyword != "AUTHENTICATIONMETHODS" or not entry.args:
                continue
            methods = " ".join(entry.args).lower()
            if "password" in methods and "publickey" not in methods:
                yield Issue(
                    message=f"authentication can complete with password only ({methods})",
                    line=entry.line,
                    offset=entry.offset,
                    length=entry.length,
                    saw=entry.raw.strip(),
                    where=entry.where,
                )


@rule(
    "SHD053",
    "multiple ports advertised",
    "low",
    1,
    2,
    "sshd listens on more than one port. Each is another thing to inventory, firewall and log; secondary ports "
    "are exactly where forgotten daemons and stale hardening accumulate.",
    "Keep one Port unless a migration is actually in flight.",
)
def _shd053(ctx: Context) -> Iterator[Issue]:
    main = ctx.main_scope()
    if main is None:
        return
    ports = main.all("PORT")
    if len(ports) > 1:
        values = ", ".join(entry.args[0] for entry in ports if entry.args)
        yield Issue(
            message=f"sshd listens on {len(ports)} ports ({values})",
            line=ports[1].line,
            offset=ports[1].offset,
            length=ports[1].length,
            saw=ports[1].raw.strip(),
            where=ports[1].where,
        )


# ---------------------------------------------------------------------------
# pass 3 -- scopes, includes and the file as a whole
# ---------------------------------------------------------------------------


@rule(
    "SHD070",
    "no account allowlist",
    "medium",
    3,
    3,
    "No AllowUsers/AllowGroups/DenyUsers/DenyGroups anywhere in the config. Every account in /etc/passwd with a "
    "usable credential can log in from wherever the daemon listens.",
    "Add AllowGroups (or AllowUsers) naming exactly the accounts that need SSH.",
)
def _shd070(ctx: Context) -> Iterator[Issue]:
    allowlist = {"ALLOWUSERS", "ALLOWGROUPS", "DENYUSERS", "DENYGROUPS"}
    main = ctx.main_scope()
    if main is None or not main.entries:
        return  # an empty config is not a posture decision; say nothing
    for entry in main.entries:
        if entry.keyword in allowlist:
            return
    yield Issue(
        message="no AllowUsers/AllowGroups/DenyUsers/DenyGroups -- every account may authenticate",
        line=0,
        offset=0,
        saw="(absent)",
        fix="Add e.g. AllowGroups ssh-users",
    )


@rule(
    "SHD071",
    "Match weakens main-scope hardening",
    "high",
    11,
    3,
    "A Match block sets a keyword to a weaker value than the main scope. This is a real sshd behavior, not a "
    "guess: Match values override the main scope for the criteria, so the hardening at the top of the file does "
    "not apply to exactly the group the block names.",
    "Align the Match value with the main scope, or justify the exception with the narrowest criteria.",
)
def _shd071(ctx: Context) -> Iterator[Issue]:
    main = ctx.main_scope()
    if main is None:
        return
    for scope in ctx.app.match_scopes:
        for entry in scope.entries:
            if entry.keyword == "PERMITROOTLOGIN":
                continue  # owned by SHD072
            ladder = STRENGTH.get(entry.keyword)
            if ladder is None or not entry.args:
                continue
            main_entry = main.first(entry.keyword)
            if main_entry is None or not main_entry.args:
                continue
            try:
                main_idx = ladder.index(main_entry.args[0].lower())
                match_idx = ladder.index(entry.args[0].lower())
            except ValueError:
                continue
            if match_idx < main_idx:
                yield Issue(
                    message=f"Match block weakens {entry.keyword.lower()}: "
                    f"{entry.args[0]} for {scope.label} vs {main_entry.args[0]} in main scope",
                    line=entry.line,
                    offset=entry.offset,
                    length=entry.length,
                    saw=entry.raw.strip(),
                    where=entry.where,
                )


@rule(
    "SHD072",
    "Match re-enables root login",
    "critical",
    33,
    3,
    "A Match block sets PermitRootLogin to a weaker value than the main scope. The 'root is locked out' posture "
    "read at the top of the file silently does not apply to this block's criteria.",
    "Keep PermitRootLogin out of Match blocks, or set it to the same (or stricter) value.",
)
def _shd072(ctx: Context) -> Iterator[Issue]:
    main = ctx.main_scope()
    if main is None:
        return
    ladder = STRENGTH["PERMITROOTLOGIN"]
    main_entry = main.first("PERMITROOTLOGIN")
    main_idx = ladder.index(main_entry.args[0].lower()) if main_entry and main_entry.args and main_entry.args[0].lower() in ladder else len(ladder)
    for scope in ctx.app.match_scopes:
        for entry in scope.entries:
            if entry.keyword != "PERMITROOTLOGIN" or not entry.args:
                continue
            try:
                match_idx = ladder.index(entry.args[0].lower())
            except ValueError:
                continue
            if match_idx < main_idx:
                yield Issue(
                    message=f"Match block re-enables root login for {scope.label}",
                    line=entry.line,
                    offset=entry.offset,
                    length=entry.length,
                    saw=entry.raw.strip(),
                    where=entry.where,
                )


@rule(
    "SHD073",
    "Include matches nothing",
    "medium",
    3,
    3,
    "The Include glob resolved to zero files. Hardening written into an included file that was renamed, moved or "
    "never deployed silently does not apply -- the config reads like it includes something, and it includes "
    "nothing.",
    "Fix the glob path; check with sshd -T which configuration is actually in effect.",
)
def _shd073(ctx: Context) -> Iterator[Issue]:
    for include in ctx.app.includes:
        if include.pattern and not include.resolved:
            yield Issue(
                message=f"Include glob matches no file: {include.pattern!r}",
                line=include.line,
                offset=include.offset,
                length=include.length,
                saw=include.pattern,
                where=include.where,
            )


@rule(
    "SHD074",
    "posture not pinned",
    "note",
    1,
    3,
    "The config never states PasswordAuthentication, PermitRootLogin, KbdInteractiveAuthentication or the "
    "algorithm lists: the posture is whatever the compiled-in default of the installed OpenSSH is. A distro "
    "upgrade that changes defaults (they have before) changes the security posture with no config diff.",
    "Pin PasswordAuthentication no, PermitRootLogin prohibit-password and the algorithm lists explicitly.",
)
def _shd074(ctx: Context) -> Iterator[Issue]:
    main = ctx.main_scope()
    if main is None or not main.entries:
        return  # an empty config is not a posture decision; say nothing
    present = {entry.keyword for entry in main.entries}
    pinned = present & {"PASSWORDAUTHENTICATION", "PERMITROOTLOGIN", "KBDINTERACTIVEAUTHENTICATION"}
    if not pinned:
        yield Issue(
            message="config sets no auth-method keyword -- posture follows the installed OpenSSH's defaults",
            line=0,
            offset=0,
            saw="(absent)",
            fix="Add explicit PasswordAuthentication / PermitRootLogin lines",
        )


def executable() -> list[Rule]:
    """The table in id order, so reports are byte-stable between runs."""
    return sorted(REGISTRY, key=lambda item: item.id)


__all__ = ["REGISTRY", "Rule", "executable"]

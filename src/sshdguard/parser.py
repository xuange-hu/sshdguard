"""Parse sshd_config into scopes, includes, unknowns and bad Match blocks.

The grammar is small on purpose: keyword-argument pairs, one per line, ``#``
comment lines, double-quoted arguments, ``Match`` blocks and ``Include``
globs. Everything sshd would reject is recorded rather than raised, because
the record is evidence: an unknown keyword means ``sshd -t`` fails and a
restart can take the service down.

Known differences from sshd that are deliberate here:

* Relative ``Include`` paths resolve against the scanned file's directory,
  not against ``/etc/ssh`` -- a scanner must not read a system directory the
  operator never asked about.
* OpenSSH accepts no trailing comments; a token starting with ``#`` mid-line
  is therefore kept as an argument and will trip the unknown-keyword rule,
  which is exactly what sshd does.
"""

from __future__ import annotations

import glob as _glob
from pathlib import Path

from .model import App, BadMatch, Entry, IncludeRef, Scope, Unknown

# Every keyword in sshd_config(5) as of OpenSSH 10.x, upper-case. Aliases of
# removed spellings live in REMOVED below and are owned by dedicated rules.
KNOWN_KEYWORDS = {
    "ACCEPTENV",
    "ADDKEYSTOAGENT",
    "ADDRESSFAMILY",
    "ALLOWAGENTFORWARDING",
    "ALLOWGROUPS",
    "ALLOWLISTEN",
    "ALLOWSTREAMLOCALFORWARDING",
    "ALLOWTCPFORWARDING",
    "ALLOWUSERS",
    "AUTHENTICATIONMETHODS",
    "AUTHORIZEDKEYSCOMMAND",
    "AUTHORIZEDKEYSFILE",
    "AUTHORIZEDPRINCIPALSCOMMAND",
    "AUTHORIZEDPRINCIPALSFILE",
    "BANNER",
    "CASIGNATUREALGORITHMS",
    "CHANNELTIMEOUT",
    "CHROOTDIRECTORY",
    "CIPHERS",
    "CLIENTALIVECOUNTMAX",
    "CLIENTALIVEINTERVAL",
    "COMPRESSION",
    "CONNECTIONATTEMPTS",
    "DENYGROUPS",
    "DENYUSERS",
    "EXPOSEAUTHINFO",
    "FINGERPRINTHASH",
    "FORCECOMMAND",
    "GATEWAYPORTS",
    "GSSAPIAUTHENTICATION",
    "GSSAPICLEANUPCREDENTIALS",
    "GSSAPIDELEGATECREDENTIALS",
    "GSSAPIKEYEXCHANGE",
    "GSSAPISTORECREDENTIALSONREKEY",
    "GSSAPISTRICTACCEPTORCHECK",
    "HOSTBASEDAUTHENTICATION",
    "HOSTBASEDACCEPTEDALGORITHMS",
    "HOSTKEY",
    "HOSTKEYAGENT",
    "HOSTKEYALGORITHMS",
    "IGNOREUSERKNOWNHOSTS",
    "IGNORERHOSTS",
    "INCLUDE",
    "IPQOS",
    "KBDINTERACTIVEAUTHENTICATION",
    "KERBEROSAUTHENTICATION",
    "KERBEROSORGETPASS",
    "KERBEROSTICKETCLEANUP",
    "KEYREVOCATIONLIST",
    "KEXALGORITHMS",
    "LISTENADDRESS",
    "LOGINGRACETIME",
    "LOGLEVEL",
    "LOGVERBOSE",
    "MACS",
    "MATCH",
    "MAXAUTHTRIES",
    "MAXAUTHTRIESLOG",
    "MAXEXCEPTIONS",
    "MAXSESSIONS",
    "MAXSTARTUPS",
    "PASSWORDAUTHENTICATION",
    "PERMITEMPTYPASSWORDS",
    "PERMITLISTEN",
    "PERMITOPEN",
    "PERMITROOTLOGIN",
    "PERMITTTY",
    "PERMITTUNNEL",
    "PERMITUSERENVIRONMENT",
    "PERMITUSERRC",
    "PIDFILE",
    "PORT",
    "PRINTMOTD",
    "PUBKEYAUTHENTICATION",
    "PUBKEYACCEPTEDALGORITHMS",
    "PUBKEYAUTHOPTIONS",
    "REKEYLIMIT",
    "REQUIREDRSAKEYSIZE",
    "REVOKEDKEYS",
    "SETENV",
    "SECURITYKEYPROVIDER",
    "STRICTMODES",
    "SUBSYSTEM",
    "SYSLOGFACILITY",
    "TCPKEEPALIVE",
    "TRUSTEDUSERCAKEYS",
    "USEDNS",
    "USEPAM",
    "X11DISPLAYOFFSET",
    "X11FORWARDING",
    "X11MAXDISPLAYS",
    "X11USELOCALHOST",
}

# Spellings sshd no longer accepts. Each is owned by a rule; the unknown-keyword
# rule deliberately skips them to avoid double reporting.
REMOVED_KEYWORDS = {
    "RSAAUTHENTICATION",  # OpenSSH 7.0
    "RHOSTSRSAAUTHENTICATION",  # OpenSSH 7.4
    "AUTHORIZEDKEYSFILE2",  # OpenSSH 5.9 (moved into AuthorizedKeysFile)
    "PROTOCOL",  # OpenSSH 7.6 (SSHv1 support dropped)
    "USEPRIVILEGESEPARATION",  # OpenSSH 7.5 (always on now)
    "AFSTOKENPASSING",  # OpenSSH 3.x era
    "CHALLENGERESPONSEAUTHENTICATION",  # renamed KbdInteractiveAuthentication in 8.7
    "HOSTBASEDKEYTYPES",  # renamed HostbasedAcceptedAlgorithms in 8.5
    "PUBKEYACCEPTEDKEYTYPES",  # renamed PubkeyAcceptedAlgorithms in 8.5
}

# Match criteria (sshd_config(5) MATCH CRITERIA). "all" takes no value and
# may appear inside a criteria list.
MATCH_CRITERIA = {
    "USER",
    "GROUP",
    "HOST",
    "LOCALADDRESS",
    "LOCALPORT",
    "RDOMAIN",
    "INVALID-USER",
    "ALL",
}

# Keywords sshd accepts more than one of inside one scope. Every other keyword
# is first-obtained-value-wins, so a second occurrence is dead text.
MULTI_KEYWORDS = {
    "PORT",
    "LISTENADDRESS",
    "HOSTKEY",
    "ACCEPTENV",
    "SETENV",
    "SUBSYSTEM",
    "ALLOWUSERS",
    "DENYUSERS",
    "ALLOWGROUPS",
    "DENYGROUPS",
    "INCLUDE",
}

MAX_INCLUDE_DEPTH = 8


def tokenize(line: str) -> list[str]:
    """Split a config line into tokens, resolving double quotes.

    sshd treats ``"a b"`` as one argument; unterminated quotes swallow the rest
    of the line, which is also what sshd does.
    """
    tokens: list[str] = []
    buf: list[str] = []
    in_quote = False
    has_token = False
    for char in line:
        if char == '"':
            in_quote = not in_quote
            has_token = True
        elif char in (" ", "\t", "\n", "\r"):
            if in_quote:
                buf.append(char)
            elif has_token:
                tokens.append("".join(buf))
                buf = []
                has_token = False
        else:
            buf.append(char)
            has_token = True
    if has_token or buf:
        tokens.append("".join(buf))
    return tokens


def _byte_offset_of(text: str, line_index: int) -> int:
    """Byte offset of the start of line ``line_index`` (0-based)."""
    return len("\n".join(text.split("\n")[:line_index]).encode("utf-8")) + (line_index if line_index else 0)


def _split_lines(text: str) -> list[tuple[int, str, int]]:
    """(1-based line number, line text, byte offset of the line)."""
    out: list[tuple[int, str, int]] = []
    offset = 0
    for number, line in enumerate(text.split("\n"), start=1):
        out.append((number, line, offset))
        offset += len(line.encode("utf-8")) + 1
    return out


def looks_like_sshd_config(text: str) -> bool:
    """Cheap shape test for directory scans: at least one known keyword."""
    for _number, line, _offset in _split_lines(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens = tokenize(stripped)
        if tokens and tokens[0].upper() in KNOWN_KEYWORDS:
            return True
    return False


class _Parser:
    def __init__(self) -> None:
        self.app = App()
        self._depth = 0
        self._visited: set[str] = set()

    def parse(self, text: str, source: str = "<text>") -> App:
        self.app = App(source=source, size=len(text.encode("utf-8")))
        self.app.lines = text.split("\n")
        root = Scope(criteria="", line=0, file="")
        self.app.scopes.append(root)
        self._feed(text, root, file_label="")
        return self.app

    # -- internal ---------------------------------------------------------

    def _feed(self, text: str, scope: Scope, file_label: str) -> None:
        """Read every line of ``text`` into ``scope``, recursing on Match and
        Include. Included files land in the scope the Include appeared in."""
        self._depth += 1
        try:
            if self._depth > MAX_INCLUDE_DEPTH:
                self.app.errors.append(f"include depth exceeded at {file_label or self.app.source}")
                return
            for number, line, line_offset in _split_lines(text):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                tokens = tokenize(stripped)
                if not tokens:
                    continue
                keyword = tokens[0].upper()
                # Byte offset of the keyword token: line offset + its column.
                column = len(line[: len(line) - len(line.lstrip())].encode("utf-8"))
                kw_offset = line_offset + column
                kw_length = len(tokens[0].encode("utf-8"))

                if keyword == "MATCH":
                    scope = self._open_match(tokens, number, file_label, kw_offset, kw_length) or scope
                    continue
                if keyword == "INCLUDE":
                    self._handle_include(tokens, number, file_label, kw_offset, kw_length, scope)
                    continue

                entry = Entry(
                    keyword=keyword,
                    raw=line,
                    args=tokens[1:],
                    line=number,
                    offset=kw_offset,
                    length=kw_length,
                    file=file_label,
                )
                if keyword in REMOVED_KEYWORDS:
                    # Still an Entry: rules SHD003/SHD004 own the dangerous
                    # ones; a generic removed-keyword rule catches the rest.
                    scope.entries.append(entry)
                elif keyword in KNOWN_KEYWORDS:
                    scope.entries.append(entry)
                else:
                    self.app.unknowns.append(
                        Unknown(
                            keyword=tokens[0],
                            line=number,
                            offset=kw_offset,
                            length=kw_length,
                            file=file_label,
                        )
                    )
        finally:
            self._depth -= 1

    def _open_match(self, tokens: list[str], number: int, file_label: str, offset: int, length: int) -> Scope:
        """Open a new scope; returns it so the feed loop keeps appending here."""
        criteria = " ".join(tokens[1:]).strip()
        if not criteria:
            self.app.bad_matches.append(
                BadMatch(
                    criteria="",
                    line=number,
                    offset=offset,
                    length=length,
                    file=file_label,
                    reason="Match with no criteria",
                )
            )
            scope = Scope(criteria="ALL (bare Match)", line=number, file=file_label)
            self.app.scopes.append(scope)
            return scope
        # Criteria come in pairs (criterion, value); "all" and "invalid-user"
        # may stand alone. Anything odd is what sshd -t chokes on.
        problems: list[str] = []
        i = 0
        words = tokens[1:]
        while i < len(words):
            word = words[i].upper()
            if word not in MATCH_CRITERIA:
                problems.append(f"unknown criterion {words[i]!r}")
                break
            if word in {"ALL", "INVALID-USER"}:
                i += 1
                continue
            if i + 1 >= len(words):
                problems.append(f"criterion {words[i]!r} has no value")
                break
            i += 2
        if problems:
            self.app.bad_matches.append(
                BadMatch(
                    criteria=criteria,
                    line=number,
                    offset=offset,
                    length=length,
                    file=file_label,
                    reason="; ".join(problems),
                )
            )
        scope = Scope(criteria=criteria, line=number, file=file_label)
        self.app.scopes.append(scope)
        return scope

    def _handle_include(
        self, tokens: list[str], number: int, file_label: str, offset: int, length: int, scope: Scope
    ) -> None:
        pattern = tokens[1] if len(tokens) > 1 else ""
        ref = IncludeRef(
            pattern=pattern,
            resolved=[],
            line=number,
            offset=offset,
            length=length,
            file=file_label,
            in_match=not scope.is_main,
        )
        self.app.includes.append(ref)
        if not pattern:
            return
        # Relative globs resolve against the scanned file's own directory.
        base = Path(file_label or self.app.source)
        base_dir = base.parent if base.parent != Path("") else Path(".")
        candidate = pattern if Path(pattern).is_absolute() else str(base_dir / pattern)
        matches = sorted(_glob.glob(candidate))
        if not matches:
            return  # SHD073 reports the dead glob; nothing to feed.
        for path in matches:
            if not Path(path).is_file():
                continue
            label = path
            real = str(Path(path).resolve())
            if real in self._visited:
                ref.resolved.append(label)
                continue  # cycle guard: record, do not recurse
            self._visited.add(real)
            ref.resolved.append(label)
            self.app.included_files.append(label)
            try:
                text = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.app.errors.append(f"cannot read {label}: {exc}")
                continue
            self._feed(text, scope, file_label=label)


def parse(text: str, source: str = "<text>") -> App:
    """Parse sshd_config text into the model."""
    return _Parser().parse(text, source=source)


def parse_file(path: str | Path) -> App:
    """Parse a file from disk. Unreadable files become an empty app with an
    error recorded -- a scanner must not crash on one bad file in a tree."""
    target = Path(path)
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        app = App(source=str(target))
        app.errors.append(f"cannot read {target}: {exc}")
        app.scopes.append(Scope(criteria="", line=0, file=""))
        return app
    return parse(text, source=str(target))


__all__ = [
    "KNOWN_KEYWORDS",
    "MULTI_KEYWORDS",
    "REMOVED_KEYWORDS",
    "looks_like_sshd_config",
    "parse",
    "parse_file",
    "tokenize",
]

"""What a parsed sshd_config is made of.

Everything carries the line number and the byte offset it came from. A finding
that cannot point at the characters it is talking about is an opinion, so the
offsets are recorded at parse time, before any rule runs.

sshd's own reading order matters and is modeled here: directives live in
scopes (the main scope, then one scope per ``Match`` block), and inside a
scope ``sshd uses the first obtained value`` -- the opposite of sudoers, where
the last match wins. A later line under the same keyword is not a tweak; it is
dead text, and that difference is the point of pass 2.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field


@dataclass
class Entry:
    """One ``Keyword args...`` line, inside a scope."""

    keyword: str  # canonical upper-case keyword as written (alias forms kept)
    raw: str  # the whole line, unmodified
    args: list[str]  # argument tokens, quotes already resolved
    line: int
    offset: int  # byte offset of the keyword token within its file
    length: int  # byte length of the keyword token
    file: str  # file label ("" for the root file)

    @property
    def where(self) -> str:
        return f"{self.file}:{self.line}" if self.file else str(self.line)


@dataclass
class Scope:
    """The main scope (criteria == "") or one ``Match`` block."""

    criteria: str  # criteria text as written; "" for the main scope
    line: int  # line the Match appeared on (0 for main scope)
    file: str
    entries: list[Entry] = dc_field(default_factory=list)

    @property
    def is_main(self) -> bool:
        return not self.criteria

    @property
    def label(self) -> str:
        return "main scope" if self.is_main else f"Match {self.criteria}"

    def first(self, keyword: str) -> Entry | None:
        """sshd semantics: the first obtained value wins, later ones are dead."""
        for entry in self.entries:
            if entry.keyword == keyword:
                return entry
        return None

    def all(self, keyword: str) -> list[Entry]:
        return [entry for entry in self.entries if entry.keyword == keyword]


@dataclass
class IncludeRef:
    """One ``Include`` line and what its glob actually resolved to."""

    pattern: str
    resolved: list[str]  # file labels the glob matched, in sshd's order
    line: int
    offset: int
    length: int
    file: str
    in_match: bool  # directives in the target land inside the current Match scope

    @property
    def where(self) -> str:
        return f"{self.file}:{self.line}" if self.file else str(self.line)


@dataclass
class Unknown:
    """A keyword sshd would reject: on OpenSSH 7+ ``sshd -t`` fails and the
    service may not start. Recorded at parse time, reported by a rule."""

    keyword: str
    line: int
    offset: int
    length: int
    file: str

    @property
    def where(self) -> str:
        return f"{self.file}:{self.line}" if self.file else str(self.line)


@dataclass
class BadMatch:
    """A ``Match`` block whose criteria sshd cannot parse (unknown criterion
    or a criterion with no value). Same availability consequence: sshd -t fails."""

    criteria: str
    line: int
    offset: int
    length: int
    file: str
    reason: str

    @property
    def where(self) -> str:
        return f"{self.file}:{self.line}" if self.file else str(self.line)


@dataclass
class App:
    """A whole sshd_config (root file plus every file its Includes resolved to)."""

    source: str = "<text>"
    lines: list[str] = dc_field(default_factory=list)
    scopes: list[Scope] = dc_field(default_factory=list)
    includes: list[IncludeRef] = dc_field(default_factory=list)
    unknowns: list[Unknown] = dc_field(default_factory=list)
    bad_matches: list[BadMatch] = dc_field(default_factory=list)
    errors: list[str] = dc_field(default_factory=list)
    included_files: list[str] = dc_field(default_factory=list)
    size: int = 0

    @property
    def line_count(self) -> int:
        return len(self.lines)

    @property
    def main(self) -> Scope | None:
        for scope in self.scopes:
            if scope.is_main:
                return scope
        return None

    @property
    def match_scopes(self) -> list[Scope]:
        return [scope for scope in self.scopes if not scope.is_main]


@dataclass
class Finding:
    """One rule's opinion about one place in the config."""

    rule: str
    severity: str  # critical | high | medium | low | note
    message: str
    line: int
    offset: int
    length: int = 0
    saw: str = ""
    fix: str = ""
    where: str = ""
    score: int = 1

    @property
    def end(self) -> int:
        return self.offset + max(self.length, 0)

    def sort_key(self) -> tuple:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}
        return (order.get(self.severity, 5), self.line, self.offset, self.rule)


@dataclass
class Report:
    """The result of running every rule over one file."""

    source: str
    app: App
    findings: list[Finding] = dc_field(default_factory=list)
    rules_run: int = 0
    rule_ids: list[str] = dc_field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def risk(self) -> int:
        """0-100. Criticals saturate quickly: three of them is already a bad day."""
        return min(100, sum(f.score for f in self.findings))

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def by_rule(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.rule] = out.get(finding.rule, 0) + 1
        return out

    @property
    def fired(self) -> set[str]:
        return {f.rule for f in self.findings}


__all__ = ["App", "BadMatch", "Entry", "Finding", "IncludeRef", "Report", "Scope", "Unknown"]

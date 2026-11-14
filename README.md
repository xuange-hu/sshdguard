# sshdguard

[![CI](https://github.com/xuange-hu/sshdguard/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/sshdguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/badge/pypi-v0.1.0-blue)](https://pypi.org/project/sshdguard/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

**Zero-dependency sshd_config security auditor. 45 rules in three passes, evidence-first with line numbers and byte offsets, SARIF for GitHub code scanning, MCP tools for agents.**

Read the config the way an attacker does -- and the way `sshd` itself does:

- **Pass 1 -- one line at a time.** `PermitRootLogin yes`, empty passwords, SHA-1 key exchange, CBC ciphers, relative `HostKey` paths, keywords `sshd` would refuse to start on.
- **Pass 2 -- combinations.** Root + password in the same scope, pubkey disabled while passwords stay on. Each alone is a finding; together they are the most brute-forced thing on the internet.
- **Pass 3 -- scopes and files against each other.** A `Match` block that silently re-enables what the top of the file disabled, an `Include` glob that matches nothing, a config that never pins its own posture.

The sshd-specific trap this tool is built around: **sshd uses the first obtained value**. A hardening line appended at the bottom of the file is dead text, and every reader believes it is in effect. SHD019 catches exactly that.

## Quick start

```bash
git clone https://github.com/xuange-hu/sshdguard
cd sshdguard && pip install .
sshdguard demo                 # 4 built-in configs that fire all 45 rules
sshdguard scan /etc/ssh        # audit a live tree
sshdguard rules                # the full table
```

Exit code 0 = clean at `--fail-on` (default `high`), 1 = findings, 2 = input unreadable. CI-ready.

## One file, no dependencies

The core runs on CPython 3.10+ with nothing installed: no PyYAML, no OpenSSH bindings, no network. The box that runs `sshd` is usually the least provisioned one in the estate -- the audit has to run there (air-gapped, minimal images, rescue shells). The MCP server is an optional extra (`pip install "sshdguard[mcp]"`).

## What a finding looks like

```
[high     ] SHD019  duplicate keyword (first wins)
           duplicate x11forwarding appears again -- sshd already took the first value, this line is dead
           line 14, offset 0x1d2+5  (sshd_config)
           saw:   X11Forwarding yes
           fix:   Keep one occurrence per keyword per scope; delete or move the later one above the first.
```

Every finding carries the rule id, the line, the byte offset, the exact bytes that caused it and the fix. `sshdguard explain SHD019` prints the full reasoning.

## Machine-readable output

```bash
sshdguard scan /etc/ssh --json      # structured report
sshdguard scan /etc/ssh --sarif     # SARIF 2.1.0 for GitHub code scanning
```

## MCP server (for Claude Code / Cursor / Cline)

```bash
uvx --from "sshdguard[mcp]" sshdguard-mcp     # stdio server, 6 tools
```

| tool | what it does |
|---|---|
| `sshdguard_scan` | audit a file or a directory tree |
| `sshdguard_text` | audit config text from a PR or a conversation |
| `sshdguard_rules` | the rule table, filterable by stage and severity |
| `sshdguard_explain` | one rule: what, why, fix |
| `sshdguard_sarif` | SARIF 2.1.0 for code-scanning upload |
| `sshdguard_demo` | the built-in corpora, end to end |

## GitHub Action

```yaml
- uses: xuange-hu/sshdguard@v1
  with:
    path: deploy/sshd_config
    fail-on: high
```

## The rules

[docs/rules.md](docs/rules.md) is the full table, generated from the source. Highlights:

| id | severity | what it catches |
|---|---|---|
| SHD001 | critical | `PermitRootLogin yes` |
| SHD002 | critical | `PermitEmptyPasswords yes` |
| SHD005 | critical | `none` in Ciphers/MACs/KexAlgorithms |
| SHD018 | high | unknown keyword (`sshd -t` fails; a restart drops the service) |
| SHD019 | high | duplicate keyword -- later line is dead text (first value wins) |
| SHD050 | critical | root + password in one scope |
| SHD072 | critical | a Match block re-enables root login |

## Known scope

- Static analysis of the config text, not of the running daemon: `sshd -T` output, host key permissions and the PAM stack are out of scope. Complement (not replace) a live scan (`ssh-audit`) with this one.
- Relative `Include` paths resolve against the scanned file's directory, not `/etc/ssh` -- a scanner must not read a system directory it was never pointed at.
- Removed-keyword spellings (`Protocol`, `RSAAuthentication`, ...) are flagged as their own rule, not as unknown keywords, to keep the evidence precise.

## Development

```bash
pip install .[mcp] pytest ruff
pytest               # 138+ tests
ruff check src/ tests/
sshdguard demo       # 45/45 rules fired, asserted in CI
```

## License

MIT -- see [LICENSE](LICENSE).

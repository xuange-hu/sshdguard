# Changelog

## 0.1.0 - 2026-11-15

First release.

- **Three passes, not one grep.** Pass 1 audits each line: auth toggles,
  algorithm lists, availability traps. Pass 2 reads combinations inside one
  scope (root + password, pubkey off + password on) and the
  first-obtained-value-wins duplicates. Pass 3 reads scopes and files against
  each other: Match blocks that silently weaken main-scope hardening, dead
  `Include` globs, a posture that is never pinned.
- **45 deterministic rules** with severity, reasoning and a concrete fix.
  `sshdguard explain SHD019` prints all three.
- **Evidence first.** Every finding names the line, the byte offset, the byte
  length and the raw text. Unknown keywords and bad Match criteria — the ones
  that make `sshd -t` fail and a restart drop the service — are reported with
  the exact bytes.
- **Zero runtime dependencies**, Python 3.10+. CLI, JSON and SARIF 2.1.0
  output, `--fail-on` exit-code gate (`0` / `1` / `2`), and an optional `mcp`
  extra with 6 tools (pinned `>=1.2,<2`).
- **Built-in demo corpus**: four sshd_config files fire all 45 rules; a test
  pins full coverage so a new rule cannot ship without a sample.
- **146 tests** pass on a bare clone with only `pytest` installed; `ruff`
  clean. CI covers Python 3.10-3.13, the MCP tool manifest, the exit-code
  contract with real files, SARIF parsing and a fresh-clone bootstrap.

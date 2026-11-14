# 传播文案（待轩哥本人确认后发布；自动化不代发）

项目：github.com/xuange-hu/sshdguard
钩子句：`git clone https://github.com/xuange-hu/sshdguard && cd sshdguard && pip install . && sshdguard demo`
一句话：Zero-dependency sshd_config auditor — 45 rules, three passes, byte-offset evidence, SARIF, 6 MCP tools.

---

## Show HN

**Title:** Show H: sshdguard – zero-dependency sshd_config auditor with byte-offset evidence

**Body:**

I built sshdguard because the two things that actually bite you in sshd_config are invisible to grep and invisible to most linters:

1. **sshd uses the first obtained value.** Append `X11Forwarding no` at the bottom of the file and it does nothing — the earlier `yes` already won. Every "append at the end" hardening workflow produces dead text, and everyone reviewing the file believes it's in effect.

2. **Match blocks override the main scope.** A `Match User admin / PermitRootLogin yes` quietly re-opens root login for exactly the account you least want it on, three lines after `PermitRootLogin no`.

Also: unknown keywords and malformed Match criteria make `sshd -t` fail, which means a reboot leaves the box without SSH. Those are availability bugs hiding in a security config.

sshdguard parses the file the way sshd does (scopes, first-value-wins, Include globs) and runs 45 rules in three passes. Every finding carries the line, byte offset and the exact bytes — plus `sshdguard explain SHD019` for the reasoning.

Zero runtime dependencies, Python 3.10+. It's built to run on the machine that runs sshd, which is usually the least provisioned box in the estate (no PyYAML, no network, rescue-shell-friendly). SARIF output for GitHub code scanning; a 6-tool MCP server if you want an agent to do the reading.

Four built-in demo configs fire all 45 rules:

    git clone https://github.com/xuange-hu/sshdguard && cd sshdguard && pip install . && sshdguard demo

Static analysis of the config, not the running daemon — it complements (not replaces) a live scan like ssh-audit. Feedback welcome, especially on false positives from real-world configs.

---

## Reddit r/sysadmin

**Title:** I wrote a static auditor for sshd_config that catches "hardening lines that don't do anything"

**Body:**

Two sshd traps that burn people regularly:

- sshd takes the **first** value it sees for most keywords. That "PasswordAuthentication no" you appended at the bottom? Dead text if it's set anywhere above. SSHD019 flags the duplicate and tells you which line won.
- A `Match` block re-enables whatever the top of the file disabled, for its criteria only. Root login + password auth re-enabled inside a Match block is the single most brute-forced combination on the internet, and it looks like hardening while reading top-down.

It also flags the lines that make `sshd -t` fail (unknown keywords, bad Match criteria) — the ones that turn "config tweak" into "no SSH after reboot".

45 rules, three passes, zero dependencies, Python 3.10+. Text mode takes a file, a directory, or stdin, so it works in Ansible/CI pipelines too (`--fail-on high` exit-code gate, SARIF if you use GitHub code scanning):

    git clone https://github.com/xuange-hu/sshdguard && cd sshdguard && pip install .
    sshdguard scan /etc/ssh
    sshdguard demo    # no config needed, fires all 45 rules

Static config analysis — it won't see what a running daemon negotiated; pair with ssh-audit for that. Repo + docs: https://github.com/xuange-hu/sshdguard

---

## Reddit r/netsec

**Title:** sshdguard: static analysis of sshd_config — first-value-wins duplicates, Match-scope overrides, dead Include globs (45 rules, zero deps)

**Body:**

Paper: the sshd config file has three classes of latent misconfiguration that line-oriented checks miss:

1. **Scope semantics** — sshd's servconf applies the first obtained value per keyword per scope; later lines are dead text, not overrides (the opposite of sudoers).
2. **Cross-scope weakening** — Match blocks set weaker values that silently override main-scope hardening for the block's criteria.
3. **Availability as a security property** — unknown keywords / malformed Match criteria fail `sshd -t`; a package upgrade that triggers a restart leaves the host without remote access.

sshdguard models scopes, Include globs (with cycle guards) and the value-strength ladder per keyword, and emits findings with byte offsets. 45 rules, three passes, CPython 3.10+ stdlib only, SARIF 2.1.0, MCP server optional. Demo corpora trigger all 45 rules and CI pins the coverage.

https://github.com/xuange-hu/sshdguard

Known scope: static only — it reads the config, not the negotiated state; `sshd -T` and host-key permissions are out of scope by design.

---

## X（发布串，4 条）

**1/4** 我写了个 sshd_config 的静态审计器：sshdguard。起因是两个几乎没人注意的语义：sshd 取**第一个**值——你追加在文件末尾的加固行是死文本；Match 块会把主作用域关掉的东西悄悄打开。45 条规则，每条结论带行号和字节偏移。github.com/xuange-hu/sshdguard

**2/4** 最危险的一类不是"配置错"，而是"配置看起来生效了"。SHD019 抓重复关键字（第一行赢了，后面全是死文本）；SHD071/072 抓 Match 块削弱主作用域——`PermitRootLogin no` 三行之后 `Match User admin / PermitRootLogin yes`，读起来像加固，实际是开门。

**3/4** 还有一类可用性问题：未知关键字和写坏的 Match 让 `sshd -t` 直接失败——包升级触发重启，机器就没有 SSH 了。这类结论和暴力破解面一起输出，都带证据字节。

**4/4** 零依赖，Python 3.10+，专跑在 sshd 所在的那台最没供给的机器上。`pip install . && sshdguard demo` 一次跑出 45/45 规则覆盖；SARIF 接 code scanning，MCP server 给 agent 用。静态分析，和 ssh-audit 互补不替代。

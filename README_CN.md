# sshdguard

[![CI](https://github.com/xuange-hu/sshdguard/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/sshdguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/badge/pypi-v0.1.0-blue)](https://pypi.org/project/sshdguard/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

**零依赖的 sshd_config 安全审计器。45 条规则三遍扫描，证据式输出（行号 + 字节偏移），SARIF 接入 GitHub code scanning，附带 MCP 工具供 agent 调用。**

按攻击者的方式读配置——也是 `sshd` 自己读配置的方式：

- **第一遍：逐行。** `PermitRootLogin yes`、空密码登录、SHA-1 密钥交换、CBC 密码套件、相对路径 `HostKey`、会让 `sshd` 拒绝启动的关键字。
- **第二遍：关键字组合。** 同一作用域里 root + 密码登录、公钥关闭而密码开着。单看每条都是问题，组合起来就是全网被爆破最多的入口。
- **第三遍：作用域与文件之间。** `Match` 块悄悄重新打开文件顶部关掉的东西、`Include` 的 glob 一个文件都没匹配到、从头到尾没有钉死任何安全姿态的配置。

本项目围绕的 sshd 专属陷阱：**sshd 取第一个出现的值（first obtained value wins）**。写在文件末尾的加固行是死文本，而所有读配置的人都以为它生效了。SHD019 专门抓这个。

## 三步跑通

```bash
git clone https://github.com/xuange-hu/sshdguard
cd sshdguard && pip install .
sshdguard demo                 # 内置 4 份配置，45 条规则全部命中
sshdguard scan /etc/ssh        # 审计线上目录
sshdguard rules                # 规则总表
```

退出码：0 = 在 `--fail-on`（默认 `high`）之上无结论，1 = 有结论，2 = 输入读不了。可直接做 CI 门禁。

## 单文件结构，零依赖

核心只依赖 CPython 3.10+ 标准库：不用 PyYAML、不绑 OpenSSH、不联网。跑 `sshd` 的机器通常是资产里供给最差的一台——审计必须能在那里跑（离线内网、极简镜像、救援 shell）。MCP server 是可选 extra（`pip install "sshdguard[mcp]"`）。

## 一条结论长什么样

```
[high     ] SHD019  duplicate keyword (first wins)
           duplicate x11forwarding appears again -- sshd already took the first value, this line is dead
           line 14, offset 0x1d2+5  (sshd_config)
           saw:   X11Forwarding yes
           fix:   Keep one occurrence per keyword per scope; delete or move the later one above the first.
```

每条结论都带规则 ID、行号、字节偏移、触发它的原始字节和修复建议。`sshdguard explain SHD019` 输出完整推理。

## 机器可读输出

```bash
sshdguard scan /etc/ssh --json      # 结构化报告
sshdguard scan /etc/ssh --sarif     # SARIF 2.1.0，接 GitHub code scanning
```

## MCP server（供 Claude Code / Cursor / Cline 调用）

```bash
uvx --from "sshdguard[mcp]" sshdguard-mcp     # stdio 服务，6 个工具
```

| 工具 | 作用 |
|---|---|
| `sshdguard_scan` | 审计单个文件或目录树 |
| `sshdguard_text` | 直接审计配置文本（PR、对话里贴的） |
| `sshdguard_rules` | 规则总表，可按 stage / severity 过滤 |
| `sshdguard_explain` | 单条规则：查什么、为什么、怎么修 |
| `sshdguard_sarif` | 输出 SARIF 供 code scanning 上传 |
| `sshdguard_demo` | 内置语料端到端演示 |

## GitHub Action

```yaml
- uses: xuange-hu/sshdguard@v1
  with:
    path: deploy/sshd_config
    fail-on: high
```

## 规则表

[docs/rules.md](docs/rules.md) 是从源码生成的全表。重点规则：

| id | 级别 | 查什么 |
|---|---|---|
| SHD001 | critical | `PermitRootLogin yes` |
| SHD002 | critical | `PermitEmptyPasswords yes` |
| SHD005 | critical | Ciphers/MACs/KexAlgorithms 里出现 `none` |
| SHD018 | high | 未知关键字（`sshd -t` 直接失败；重启即掉线） |
| SHD019 | high | 重复关键字——后一行是死文本（首个值生效） |
| SHD050 | critical | 同一作用域 root + 密码 |
| SHD072 | critical | Match 块重新打开 root 登录 |

## 已知边界

- 静态分析配置文本，不分析运行中的守护进程：`sshd -T` 的实际生效值、宿主密钥文件权限、PAM 栈都不在范围内。与在线扫描（如 `ssh-audit`）互补而非替代。
- 相对路径的 `Include` 以被扫描文件所在目录解析，而不是 `/etc/ssh`——扫描器不该擅自去读没人让它读的系统目录。
- 已移除的关键字旧拼写（`Protocol`、`RSAAuthentication`……）单独设规则报告，不混入未知关键字，保证证据精确。

## 开发

```bash
pip install .[mcp] pytest ruff
pytest               # 138+ 测试
ruff check src/ tests/
sshdguard demo       # 45/45 规则命中，CI 断言
```

## 许可

MIT——见 [LICENSE](LICENSE)。

# Rule table

45 rules in three passes. Stage 1 = one line, stage 2 = keyword
combinations inside one scope, stage 3 = Match scopes, Includes and the file
as a whole.  prints the same prose as this page.

## Stage 1

| id | severity | score | title |
|---|---|---|---|
| SHD001 | critical | 33 | PermitRootLogin yes |
| SHD002 | critical | 33 | PermitEmptyPasswords yes |
| SHD003 | critical | 33 | RhostsRSAAuthentication yes |
| SHD004 | critical | 33 | Protocol 1 |
| SHD005 | critical | 33 | 'none' algorithm negotiated |
| SHD006 | high | 11 | PasswordAuthentication yes |
| SHD007 | high | 11 | HostbasedAuthentication yes |
| SHD008 | high | 11 | IgnoreRhosts no |
| SHD009 | high | 11 | PermitUserEnvironment yes |
| SHD010 | high | 11 | StrictModes no |
| SHD011 | high | 11 | SHA-1 key exchange |
| SHD012 | high | 11 | weak cipher (CBC / arcfour / 3DES) |
| SHD013 | high | 7 | weak MAC (SHA-1 / MD5 / 64-bit umac) |
| SHD014 | high | 7 | DSA host key |
| SHD015 | high | 7 | AuthorizedKeysCommand unsafe path |
| SHD016 | high | 7 | AuthorizedKeysFile unsafe location |
| SHD017 | high | 7 | HostKey relative path |
| SHD018 | high | 7 | unknown keyword |
| SHD019 | high | 7 | duplicate keyword (first wins) |
| SHD020 | medium | 3 | weak kex appended with + |
| SHD021 | medium | 3 | weak cipher appended with + |
| SHD022 | medium | 3 | weak MAC appended with + |
| SHD023 | medium | 3 | KbdInteractiveAuthentication yes |
| SHD024 | medium | 3 | UsePAM no |
| SHD025 | medium | 3 | LoginGraceTime 0 |
| SHD026 | medium | 3 | X11Forwarding yes |
| SHD027 | medium | 3 | GatewayPorts yes |
| SHD028 | medium | 3 | PasswordAuthentication yes inside Match |
| SHD029 | medium | 3 | PubkeyAuthentication no |
| SHD030 | note | 1 | keyword removed by OpenSSH |
| SHD031 | low | 1 | PermitTunnel yes |
| SHD032 | low | 1 | Compression yes |
| SHD033 | low | 1 | MaxAuthTries excessive |
| SHD034 | note | 1 | ListenAddress wildcard |
| SHD035 | high | 7 | Match criteria sshd cannot parse |
| SHD036 | low | 1 | Include inside Match |

## Stage 2

| id | severity | score | title |
|---|---|---|---|
| SHD050 | critical | 33 | root + password in one scope |
| SHD051 | high | 11 | pubkey off, password on |
| SHD052 | medium | 3 | AuthenticationMethods includes password |
| SHD053 | low | 1 | multiple ports advertised |

## Stage 3

| id | severity | score | title |
|---|---|---|---|
| SHD070 | medium | 3 | no account allowlist |
| SHD071 | high | 11 | Match weakens main-scope hardening |
| SHD072 | critical | 33 | Match re-enables root login |
| SHD073 | medium | 3 | Include matches nothing |
| SHD074 | note | 1 | posture not pinned |

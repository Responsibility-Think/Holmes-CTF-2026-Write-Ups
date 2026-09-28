---
type: writeup
title: "HTB Holmes 2026 — Last Light: Golden Ticket Extraction from an ELF Core, RBCD Backdoor, Unflushed EVTX Carve"
platform: Hack The Box
event: "Holmes CTF 2026: The Reichenbach Directive"
challenge: Last Light
category: forensics
subcategory: sherlock-dfir
difficulty: insane
points: 1000
status: draft
app: "LastLight.zip — memory.elf (3.28 GB QEMU/libvirt ELF64 core, Win2019 17763), ntdsutil/ (ntds.dit + SYSTEM + SECURITY), Security.evtx (23 MB), Sysmon%4Operational.evtx (32 MB)"
mitre:
  - T1558.001
  - T1134.001
  - T1134.003
  - T1550.003
  - T1003.003
  - T1003.006
  - T1098.002
  - T1207
  - T1070.001
  - T1021.002
  - T1569.002
  - T1484.001
tags:
  - writeup
  - HTB
  - Security
  - DFIR
  - Incident_Response
  - forensics
  - Windows
  - Active_Directory
  - Memory_Forensics
  - Kerberos
related:
  - "[[HTB]]"
  - "[[00_MOC-HTB-Holmes2026-Reichenbach-Directive-Event]]"
  - "[[HTB-Holmes2026-Borrowed-Name-AdaptixC2-RC4-Profile-Key-ResetNightmare]]"
  - "[[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]]"
  - "[[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]]"
  - "[[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]]"
  - "[[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]]"
  - "[[HTB-Holmes2026-Poisoned-Branch-Backdoored-Git-Repo-XOR-Mettle-ZipCrypto]]"
aliases:
  - Last Light
  - Holmes 2026 Last Light
  - Sherlock 09
created: 2026-09-20T19:37:30.439Z
---

# Last Light — Golden Ticket Extraction from an ELF Core, RBCD Backdoor, Unflushed EVTX Carve

> [!warning] Partially solved — 2026-09-20 · 7 of 10 flags
> **No `HTB{}` string exists for this room** — it is question-graded. Sherlock 09 of the event · insane · 1000 points. The final Sherlock of the Reichenbach Directive.
> The room is three separate problems sharing one memory image: **recover Kerberos tickets from a QEMU ELF core without a minidump**, **carve an event that was never flushed to disk**, and **read `_TOKEN` structures the plugin set does not expose**.
> Flags 1, 2 and 10 remain open after **25 wrong submissions** (§14 logs every one). §16 records the tooling to try next; §14.5 records why the count got that high.

> [!info] Scenario, verbatim
> SCENARIO NAME
> 9 - Last Light
> The story will unfold through the PDFs provided with each challenge's downloadable ZIP.
>
> All characters, locations, and events are fictional. Any resemblance to real people, places, or events is purely coincidental.
>
> All addresses are in truncated format (0x123) not canonical format (0xffff123)
>
> **Supplied artifact:** `LastLight.zip` → `memory.elf`, `ntdsutil/Active Directory/ntds.dit`, `ntdsutil/registry/{SYSTEM,SECURITY}`, `C/Windows/System32/winevt/logs/Security.evtx`, `C/Windows/System32/winevt/logs/Microsoft-Windows-Sysmon%4Operational.evtx`, story PDF, `conclusion/` (gated).
> **Docker instance:** password gate at `/unlock`, conclusion at `/dossier`. Server-side check, properly gated (401 without session). Not bypassable.

---

## Flags — Answers

| # | Question | Answer | Method |
|---|---|---|---|
| 1 | SHA256 of the service agent | **OPEN** | four candidates rejected — see §14.2, §15.1 |
| 2 | Golden ticket `0xaddress:md5sum` (ccache) | **md5 half: `3ac801f1d8b33160433b6af6f680ec88`** · address unresolved | pypykatz via hand-written Volatility 3 plugin |
| 3 | KDCChecksum Signature hash | `b63742148ab83e91d38dd632b5b1fb99` | `describeTicket --rc4 <child krbtgt NT>` → PAC buffer type 7 |
| 4 | Address of the stolen `_TOKEN` | `0xca8ddc130830` | volshell, `_TOKEN.TokenType == 2` |
| 5 | ImpersonationLevel:LogonID | `2:0xa616a` | same `_TOKEN`, `ImpersonationLevel` + `AuthenticationId.LowPart` |
| 6 | ThreadId running the stolen token | `4968` | `_ETHREAD.ClientSecurity.ImpersonationData & ~0x7` |
| 7 | RBCD machine account:SID | `svc_bkup$:S-1-5-21-2253468260-689643353-167204612-1140` | SD blob carved from memory at file offset `0x2ee9d79f` |
| 8 | `_ROOT_` domain SID | `S-1-5-21-3066635835-107521988-671693545` | `windows.getsids` — the prefix carrying `-519` |
| 9 | SubjectLogonId:LogonType | `0x3f213b:3` | 5136 carved from an unflushed EVTX chunk at `0x1397c924` |
| 10 | Password attack `prepare:reset` LogonIDs | **OPEN** | seven pairs + two representation variants rejected — see §14.4, §15.3 |

---

## 0. How the seven flags were obtained

1. `impacket-secretsdump LOCAL` against `ntds.dit` + `SYSTEM` + `SECURITY` → krbtgt keys, every machine account, PEK. **This is the prerequisite for flags 2, 3 and 7 and it should be step one in any room shipping a DIT.**
2. `windows.getsids` → two domain SIDs in process tokens; the one carrying `-519` Enterprise Admins is the forest root (flag 8).
3. `windows.handles --pid 3376 | grep Token` → three `_TOKEN` objects; volshell reads `TokenType`, `ImpersonationLevel`, `AuthenticationId` (flags 4, 5). `_ETHREAD.ClientSecurity` on each of four threads → one non-null (flag 6).
4. Raw scan of `memory.elf` for the RBCD security-descriptor bytes → `svc_bkup$` RID 1140 (flag 7).
5. Scan for `ElfChnk\0` windows containing `msDS-AllowedToActOnBehalfOfOtherIdentity` UTF-16 → one unflushed Security chunk → the 5136 that never reached disk (flag 9).
6. MemProcFS mount → pypykatz driven through a hand-written Volatility 3 plugin → 29 tickets exported → `describeTicket` with the child krbtgt RC4 hash → the one PAC with an ExtraSid (flag 3, and flag 2's md5).

---

## 1. Environment

| Item | Value |
|---|---|
| Host | `dc02.core.diogenes.htb`, Windows Server 2019, build 17763 |
| Image | ELF64 core (`virsh dump` / QEMU), 3.28 GB, one PT_LOAD of `0xbb600000` at pa `0x200000`, file offset `0x1cd924` |
| Capture time | `2026-09-09 22:40:38 UTC` (`windows.info` SystemTime) |
| Child domain | `DIOCORE` / `core.diogenes.htb` — `S-1-5-21-2253468260-689643353-167204612` |
| Forest root | `DIOGENES.HTB` — `S-1-5-21-3066635835-107521988-671693545` |
| Root DC | `192.168.56.11` (**not** `.10` as Borrowed Name implied) |
| C2 host | `192.168.56.1` |
| WS02 | `192.168.56.22` |

**Clock anomaly.** Boot-time processes stamp `2026-09-10 03:26`; later processes stamp `2026-09-09 20:26`. Children precede parents by ~7 hours. Do not assume a shared clock between the memory image and the evtx files. This is Chapter 14's "individual events looked valid, but their timing was wrong."

---

## 2. Timeline

All times UTC. Sources: `Security.evtx` (disk), the MemProcFS-recovered Security log (memory), decrypted PAC `Logon Time` fields, and `windows.pstree`.

| Time | Event | Source |
|---|---|---|
| **2026-09-08** | | |
| 20:58:14–20:58:20 | Domain build. `VAGRANT$` / `0x3e7` creates builtin groups, 19 × 4720. | Security.evtx |
| 21:22:25 | `DIOGENES$` trust account created (RID 1001→1104). | 4742 |
| 21:25:38 | `krbtgt` UAC changes from ANONYMOUS LOGON `0x3e6`. | 4738 ×3 |
| 21:42:28–21:42:59 | Administrator (`0x305b5d` + `0x305a06`) bulk-resets 18 accounts, 1.5 s apart. **Provisioning, not the attack.** | 4738/4724 |
| 21:46:12 | `administrator` from **192.168.56.11** — DCSync (`1131f6ab` Get-Changes-All). | 4662, 4624 type 3 |
| 22:01:52, 22:19:27 | Two further bulk-reset passes. | 4738/4724 |
| 22:05:30, 22:22:44 | DCSync repeated from `.11`. | 4662 |
| 22:24:03 | `enable-forensics.ps1 -Role DC` run by `vagrant` — auditpol, wevtutil, Sysmon install. **The evidence collection is itself in the evidence.** | Sysmon EID 1 |
| **2026-09-09** | | |
| 19:02:17 | Domain **password policy changed** (`MaxPasswordAge`). Subject `0x3e7`. | 4739 |
| 19:16:44 | ANONYMOUS LOGON `0x3e6` writes 4738 against `jreed` and `ncole`. | 4738 ×2 |
| 19:31:44 | `0x3e6` modifies `Administrators` and `Denied RODC Password Replication Group`. | 4735 ×3 |
| 19:42:58 | `afenwick` NTLM from workstation `unhappy-meal` — **the Borrowed Name C2 host**. | 4776 |
| 20:24:41 | **Sysmon log ends.** Zero EID 1 records in the entire file. | Sysmon |
| 20:46:48.271 | `afenwick` (`0x17c514`) sets **her own UPN to `jreed`**. | 4738 |
| 20:46:48.272 | `afenwick` (`0x17c514`) clears the UPN. | 4738 |
| 20:46:48.272 | ANONYMOUS LOGON `0x3e6` — `jreed` PasswordLastSet. | 4738 |
| 20:46:48.273 | `afenwick` (`0x17c569`) **changes `jreed`'s password**. | 4723 |
| 20:46:48 | `jreed` requests a TGT — **etype 0x17 (RC4), downgraded** from afenwick's 0x12. | 4768 |
| **20:49:57** | **`svc_bkup` executes from `\\dc02\ADMIN$\svc_bkup`**, parent `services.exe` (596). PsExec-style remote service. | pstree |
| 22:13:55 | `VBoxService.exe` → `lsass.exe` process access. | Sysmon (memory only) |
| 22:17:32 | `afenwick` session logoff. | 4634 |
| 22:17:40 | `jreed` NTLM V2 logon from `192.168.56.1`. | 4624 type 3 |
| **22:17:41** | **Golden ticket forged**: `Administrator@CORE.DIOGENES.HTB`, RC4, ExtraSid = root Enterprise Admins, expires 2036. LUID **`0xa616a`**. | PAC Logon Time |
| **22:19:51** | Second golden ticket: `Administrator@DIOGENES.HTB` (root realm), RC4, session key `KTnoxYUfXkJiLZBo`, expires 2036. | plaintext KRB-CRED |
| 22:35:44 | `afenwick` (`0x3e2bd5`) **creates machine account `svc_bkup$`** via `SeMachineAccountPrivilege`. | 4741/4724/4742 (memory only) |
| **22:38:38** | `jreed` NTLM V2 from `192.168.56.1` → LogonId **`0x3f213b`**. | 4624 type 3 (memory only) |
| **22:38:41** | **RBCD written** to `CN=DC02,OU=Domain Controllers`. `AttributeValue` renders as `Malformed Security Descriptor`. **Never flushed to disk.** | 5136 rid 38668 (memory only) |
| 22:40:38 | Memory captured. | windows.info |

**The token steal and the golden ticket are the same session.** LUID `0xa616a` is both the stolen `_TOKEN`'s `AuthenticationId` (flag 5) and the logon session pypykatz found the `Administrator@CORE` golden ticket in. Flags 2, 4, 5 and 6 describe one action.

---

## 3. The unflushed EVTX carve

The single most transferable technique in this room.

The Security log on disk runs to `2026-09-10 03:26` — **past** the intrusion — and contains 1,655 events for 09-09. It does **not** contain the RBCD write, the `svc_bkup$` creation, the 4723 against `jreed`, or `jreed`'s 4624. Those records were in the EventLog service's in-memory chunk buffer when the image was taken and never reached the file.

Method:

```python
# 1. find EVTX chunks in the raw image that contain the target string
pat  = "msDS-AllowedToActOnBehalfOfOtherIdentity".encode("utf-16-le")
chunk = b"ElfChnk\x00"
# sliding 64 MB read with a 70 KB carry; a chunk is 64 KB
# → CHUNK w/ RBCD at 0x1397c924

# 2. walk records inside the chunk
#    header: magic '**\0\0' (4) | size (4) | record id (8) | FILETIME (8)
#    NB: the timestamp is at +16, not +24
```

Record ids, timestamps and substituted values are all readable without a full binary-XML parser. `strings -el` on the carved chunk gives the template field names in order; the substitution values follow the `SubjectDomainName` string, so `SubjectLogonId` is the 8-byte LE value immediately after `DIOCORE`.

**MemProcFS does this properly.** `/tmp/mpfs/sys/eventlog/eventlog_parsed/Security.txt` is a fully repaired, human-readable render of every EVTX chunk found in memory — including all four records the manual carve found and the on-disk file lacks. **Mount MemProcFS before hand-carving anything.** The manual carve cost roughly fifteen exchanges; the parsed file would have produced the same records in one.

---

## 4. Token analysis without a token plugin

Volatility 3 2.28.2 has no plugin that prints `_TOKEN` internals. `windows.privileges` shows privileges, `windows.getsids` shows SIDs, neither shows type or impersonation level.

```
windows.handles --pid 3376 | grep Token
  0xca8ddb257060  0xd8   0x48     TOKEN_QUERY|TOKEN_DUPLICATE
  0xca8ddc130060  0x3a8  0xf01ff  TOKEN_ALL_ACCESS
  0xca8ddc130830  0x3ac  0xe      TOKEN_IMPERSONATE   (+3 more handles)
```

In volshell:

```python
k = context.modules['kernel']
for off in (...):
    t = k.object(object_type="_TOKEN", offset=off, absolute=True)
    print(hex(off), int(t.TokenType), int(t.ImpersonationLevel), hex(t.AuthenticationId.LowPart))
# 0xca8ddb257060  Type=1 Imp=0 LogonId=0x3e7     ← 3376's own primary token
# 0xca8ddc130060  Type=1 Imp=2 LogonId=0xa616a   ← DuplicateTokenEx product
# 0xca8ddc130830  Type=2 Imp=2 LogonId=0xa616a   ← the stolen impersonation token
```

Three traps, all of which cost time:

- **`dt("_TOKEN", offset)` hangs.** The variable-length `Privileges` and `SidHash` arrays make the renderer walk forever. Read named fields instead.
- **`proc.Token.Object.vol.offset` returns the field's address, not the object's.** `_EPROCESS.Token` is an `EX_FAST_REF`; read the 8 bytes at that address and mask `& ~0xF`.
- **`_ETHREAD.ClientSecurity.ImpersonationData` is also packed** — low 2 bits are the impersonation level, bit 2 is `EffectiveOnly`. Mask `& ~0x7`. Exactly one of 3376's four threads had a non-null value: TID 4968 → `0xca8ddc130830`, corroborating flag 4 independently.

---

## 5. Kerberos ticket extraction from an ELF core

The hard problem of the room. "Without dumping LSASS" reads as a constraint but is actually a pointer at the intended tool.

**What does not work:**

- pypykatz `lsa minidump` — needs a real minidump; a Volatility `memmap --dump` is raw and fails the signature check.
- pypykatz `lsa rekall` — `ModuleNotFoundError: rekall`.
- MemProcFS `/pid/604/minidump/minidump.dmp` — I/O error, never materialises on this build.
- MemProcFS `regsecrets` plugin — Windows-only install path.
- Manual KRB-CRED carving — finds six blobs in lsass, five of which decrypt, **none of which is the extra-SID ticket**. The right ticket's KRB-CRED wrapper does not exist in memory; pypykatz synthesises it.

**What works** — write the missing Volatility 3 plugin. pypykatz ships the reader (`pypykatz/commons/readers/volatility3/volreader.py`) but not the plugin wrapper; the author's comment says it lives in "a separate project" that is not packaged.

```python
# ~/tools/volplugins/pypykatz_vol3.py
from volatility3.framework import interfaces
from volatility3.framework.interfaces import plugins as vplugins
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from pypykatz.commons.readers.volatility3.volreader import Vol3Reader, vol3_treegrid
from pypykatz.pypykatz import pypykatz

class Pypykatz(vplugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name='pslist', component=pslist.PsList,
                                            version=pslist.PsList._version),
            requirements.StringRequirement(name='kerberos_dir', description='ticket output dir',
                                           optional=True, default=None),
        ]

    def run(self):
        reader  = Vol3Reader(self, 2)          # (plugin_obj, framework_version)
        sysinfo = reader.get_sysinfo()
        mimi    = pypykatz(reader, sysinfo)
        mimi.start()
        kd = self.config.get('kerberos_dir', None)
        if kd:
            mimi.export_ticket(kd)
        return vol3_treegrid(mimi)
```

```
vol -p ~/tools/volplugins -f memory.elf pypykatz_vol3.Pypykatz --kerberos-dir ./kerb
# → 29 .kirbi files, named by realm/client/service
```

**Four failure modes before it ran**, each worth remembering:

1. `interfaces.plugins.PluginInterface` as the base class registers the *module* but not the *class*. Use `from volatility3.framework.interfaces import plugins as vplugins` and subclass `vplugins.PluginInterface`.
2. `PluginRequirement(version=(2,0,0))` fails against pslist 3.0.1. Use `VersionRequirement(component=..., version=pslist.PsList._version)`.
3. **Two Volatility installs.** `vol` was pipx's venv; pypykatz was in the system site-packages. Discovery and import resolved different framework instances, so the subclass check silently failed. Fix: `~/.local/share/pipx/venvs/volatility3/bin/python -m pip install pypykatz`.
4. Volatility swallows plugin import errors. `PYTHONPATH=<dir> python3 -c "import <plugin>"` under *the interpreter `vol` uses* is the only way to see them.

Then:

```
impacket-ticketConverter X.kirbi X.ccache
impacket-describeTicket X.ccache --rc4 <child krbtgt NT hash>
```

The child krbtgt RC4 hash decrypts **every** CORE-realm ticket in the image — which is itself the proof of forgery, since a legitimately issued TGT and a golden ticket are structurally identical and differ only in that the forger's key is the one you have.

The extra-SID ticket:

```
TGT_CORE.DIOGENES.HTB_Administrator_krbtgt_CORE.DIOGENES.HTB_47f3dcfb
  User Name        : Administrator          User Realm : CORE.DIOGENES.HTB
  Start / End      : 2026-09-09 22:17:41 → 2036-09-06   (10-year lifetime)
  KeyType          : rc4_hmac
  Groups           : 513, 512, 520, 518, 519
  User Flags       : (32) LOGON_EXTRA_SIDS
  Extra SID Count  : 1
  Extra SIDs       : S-1-5-21-3066635835-107521988-671693545-519 Enterprise Admins
  ServerChecksum   : hmac_md5  5cc2da157cb1c50b8f555401bea362af
  KDCChecksum      : hmac_md5  b63742148ab83e91d38dd632b5b1fb99   ← flag 3
  ccache md5       : 3ac801f1d8b33160433b6af6f680ec88              ← flag 2, md5 half
```

**Distinguishing real from forged in bulk:** four `DC02$` TGTs also report `LOGON_EXTRA_SIDS`, but their extra SID is `S-1-5-9 Enterprise Domain Controllers` — which is what a DC's own TGT legitimately carries. Filter on the SID's *domain prefix*, not on the presence of the flag.

---

## 6. RBCD

`msDS-AllowedToActOnBehalfOfOtherIdentity` never appears in `Security.evtx` — not as an LDAP display name, not as schema GUID `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79`, and there are no 4670s. The eight 5136s on disk are all `servicePrincipalName` TERMSRV churn; the thirteen 4742s are SPN registrations from the build day.

The write is in memory twice over:

- as the **security descriptor** at file offset `0x2ee9d79f` — an SD header plus exactly one grantee SID, `...-1140` = `svc_bkup$` (flag 7)
- as the **5136 event** in the unflushed chunk at `0x1397c924`, rid 38668, subject `jreed`, LogonId `0x3f213b` (flag 9)

`AttributeValue` renders as `Malformed Security Descriptor` — the operator wrote a non-canonical SD, which is [Inference] why the event never normalised and flushed.

---

## 7. Docker gate

`/app.js` posts to `/unlock`, then fetches `/dossier`. Both are server-side. `curl -i /dossier` without a session returns `401 {"error":"sealed"}` — properly gated. `conclusion/Conclusion.txt` on disk says only "enter the value of the final flag in the LastLight challenge." No bypass, no client-side key derivation, nothing to reverse.

---

## 8. Toolchain used

| Purpose | Tool | Note |
|---|---|---|
| DIT + hive secrets | `impacket-secretsdump ... LOCAL` | apt build v0.14.0.dev0; quote the `Active Directory` path |
| Domain SIDs | `windows.getsids` + regex on the raw SECURITY hive | the hive scan gave a false third SID; `getsids` is authoritative |
| Process / token structures | Volatility 3 2.28.2 `volshell` | `gp(pid=)`, `dt`, `k.object(..., absolute=True)` |
| Handles, privileges, sessions | `windows.handles`, `windows.privileges`, `windows.sessions` | `windows.threads` takes no args and shows no security context |
| Memory filesystem, forensic pass | MemProcFS 5.18.11 | needs **libfuse2**, which Kali no longer packages — extract `libfuse.so.2` from the Debian `libfuse2_2.9.9-6+b1` .deb into `/usr/local/lib` |
| Recovered event logs | MemProcFS `/sys/eventlog/eventlog_parsed/` | **the single biggest time-saver in the room** |
| Reconstructed files | MemProcFS `/forensic/files/` and `/pid/<n>/modules/<mod>/pefile.dll` | two different reconstructions, different hashes |
| Binary search in a process | MemProcFS `/pid/<n>/search/bin/` | write hex to `search.txt`, read `result.txt`; `addr-min`/`addr-max` persist between searches — reset them |
| Ticket extraction | pypykatz 0.6.13 + hand-written vol3 plugin | §5 |
| Ticket parsing | `impacket-ticketConverter`, `impacket-describeTicket` | `--rc4` / `--aes`, not `-k` |
| EVTX (disk) | `python-evtx` 0.8.1 via pip | Kali's `python3-evtx` package is broken — missing `Evtx._vendor`; the console script also fails on `No module named 'scripts'` |
| EVTX (memory) | custom `ElfChnk` scanner | §3 |

**Tools that were tried and did not apply:** `evtx_dump` (Rust, not packaged for this arch via pipx), `rekall`, `dissect.esedb` (pipx refuses libraries — use pip), MemProcFS `regsecrets`.

---

## 9. Method notes

- **Mount MemProcFS first.** It supplies recovered event logs, reconstructed files, per-process minidumps, a live binary-search interface and a forensic timeline in 42 seconds. Every manual carve in this room duplicated something it already had.
- **`-forensic 1` costs 42 s on 3.2 GB.** There is no reason to run without it.
- **A parsed event log that reaches past the intrusion is not a complete event log.** The on-disk Security.evtx ends after the attack and is still missing the four decisive records. File mtime, last-event timestamp and completeness are three different things — I asserted the first implied the third and was wrong twice.
- **`<EventID Qualifiers="">4724</EventID>`** — the attribute breaks every naive `grep 'EventID>4724<'`. Split records on `(?=<Event xmlns=)` and regex within each.
- **Splitting a `python-evtx` XML dump on `<?xml` yields one record.** There are no XML declarations in that output. Split on `<Event xmlns=`.
- **Sparse FUSE-backed files read differently under `seek()` than under a large sequential read.** A needle found at an offset during a linear scan can read as zeros when seeked directly. Verify inside the buffer you searched.
- **Two installs of the same library in different interpreters is a silent failure mode**, not a loud one. When a plugin system "finds" your module but not your class, check which Python each side is using before debugging the code.
- **Don't submit intermediate findings.** Three of this room's rejections were values I had established as evidence but never as answers — the child domain SID, a bare `svc_bkup`, the legitimate admin's LogonId.

---

## 10. Cross-room links

- **`unhappy-meal`** — Borrowed Name's operator workstation, appears here in a 4776 against `afenwick` at 19:42:58 on 09-09.
- **`afenwick`** — Borrowed Name's UPN-write privesc victim; here she performs the **same UPN swap** (setting her own `userPrincipalName` to `jreed`) at 20:46:48. Same technique, second room.
- **`svc_bkup`** — Borrowed Name ends with the agent launched from `\\dc02\ADMIN$\svc_bkup` and 29 seconds of beacon traffic. This room is what happened next, from the DC's side.
- **Root DC is `192.168.56.11`,** not `.10`. Borrowed Name's note records `dc01.diogenes.htb (192.168.56.10)`; the DCSync logons in this room's Security log come from `.11`. **One of the two notes is wrong — worth reconciling.**

---

## 11. MITRE mapping

`T1558.001` Golden Ticket · `T1134.001` Token Impersonation/Theft · `T1134.003` Make and Impersonate Token · `T1550.003` Pass the Ticket · `T1003.003` NTDS · `T1003.006` DCSync · `T1098.002` Additional Delegation (RBCD) · `T1207` Rogue DC / machine account creation · `T1070.001` Clear Windows Event Logs (by implication — the RBCD event never flushed) · `T1021.002` SMB/Admin Shares · `T1569.002` Service Execution · `T1484.001` Group Policy / domain policy modification (4739).

---

## 12. Detection opportunities

- **A TGT with a ten-year lifetime.** Both golden tickets expire in 2036. Domain policy maxes TGT lifetime at 10 hours by default; anything beyond the policy ceiling is forged, full stop, and it is a one-line check against any ticket cache.
- **An `ExtraSid` whose domain prefix is not the ticket's own realm and is not `S-1-5-9`.** Cross-domain Enterprise Admins in a child-realm TGT has no legitimate production case.
- **A plaintext session key made of printable ASCII.** `KTnoxYUfXkJiLZBo` is a hand-typed 16-char string. Real session keys are random bytes.
- **`kerberos.DLL` loaded by a process with no authentication role.** A backup agent linking the Kerberos SSP is definitionally wrong.
- **A service whose `ImagePath` is a UNC path to `ADMIN$`.** Same tell as Borrowed Name, different room.
- **4739 password-policy change immediately before a reset campaign.** The policy change is the enabler and it is far rarer than the resets.
- **A machine account created by a user account with `SeMachineAccountPrivilege` outside provisioning windows** — and `ms-DS-MachineAccountQuota > 0` is why it was possible.

---

## 13. Containment (what the room asks narratively)

1. Reset `krbtgt` **twice**, in both `core.diogenes.htb` and `diogenes.htb`, with the mandated interval — every ticket in §5 is valid until 2036 otherwise.
2. Delete `svc_bkup$` (RID 1140) and clear `msDS-AllowedToActOnBehalfOfOtherIdentity` on `CN=DC02,OU=Domain Controllers`.
3. Reset `jreed`, `afenwick`, `rfairfax`; audit `userPrincipalName` self-write across the directory.
4. Set `ms-DS-MachineAccountQuota` to 0.
5. Preserve — the RBCD event exists only in volatile memory. A reboot destroys the only record of the backdoor's authorship.

---

## 14. Wrong submissions — complete log

**Twenty-five**, which is nearly double the rest of the event combined (13 across five rooms). Recorded in full because the three open flags will be re-attempted and every line below is an answer that does **not** need retrying.

### 14.1 Intermediate findings submitted as answers (3)

| Submitted | For flag | What it actually was |
|---|---|---|
| `S-1-5-21-2253468260-689643353-167204612` | 8 | the **child** domain SID |
| `svc_bkup` | 7 | the process name, not the SAM name; correct answer needs `$` and the SID |
| `0xa6049` | 5 | the **legitimate** RDP admin's LogonId, not the stolen token's |

Cause: values established as evidence during analysis, submitted as though they were answers. None had been proposed as an answer.

### 14.2 Flag 1 — SHA256 candidates (4)

| Submitted | Source |
|---|---|
| `f54257d2f164a8c643b8afc7dee9f2730b2fdb7a1a8337535471839156b4fdc3` | MemProcFS `/forensic/files/ROOT/dc02/ADMIN$/…-svc_bkup` (file-object cache, 103,936 B) |
| `dbc9e4a9171bbcac1cb86b78e635af418d7142f89ada268917d9eb134dd7e456` | MemProcFS `/pid/3376/modules/svc_bkup/pefile.dll` (PE reconstruction, 103,936 B) |
| `1c19c05d41fbfc64c5724c0539f452530e729ae2e4eaf797e6a9e4766c1a1692` | Volatility `windows.dumpfiles` ImageSectionObject (107,520 B) |
| `9f99ab838fecd33254a77a634d400e31308d5269cb79b3a624e0b2f877464297` | MemProcFS `/pid/3376/minidump/minidump.dmp` (process dump, not the binary) |

The first two differ in exactly 258 bytes, **all in `.idata`** — the loader-patched IAT — which establishes the file-object copy as the unpatched on-disk image. It was still rejected. Whatever the grader hashed, it is not any reconstruction this toolchain produces.

### 14.3 Flag 2 — address × md5 combinations (11)

Addresses tried: `0x22747394084` and `0x2274739409e` (the **root-realm** ticket — wrong ticket), `0x22746f1e71c` (computed ticket byte 0), `0x22746f1e780` (start of the contiguous run, ticket byte 100), `0x22746f1e8ac` (verified needle anchor, ticket byte 400).

md5s tried:

| Hash | Container |
|---|---|
| `a77229812cca399449b901fa114167ae` | Impacket ccache, root-realm ticket |
| `57078fd488fcf954d7f7e5551b948dec` | raw kirbi, root-realm ticket |
| `f900e188b50496832c41b482eee5dab6` | raw DER Ticket, root-realm ticket |
| `3ac801f1d8b33160433b6af6f680ec88` | **Impacket** ccache, correct (extra-SID) ticket |
| `bd55a03b5af39a0a850d9693ba556855` | **minikerberos** ccache, correct ticket |

Not yet submitted: `24f015400c0b3242068ec1b290b7eb53` — minikerberos ccache containing **all 29 tickets aggregated**. pypykatz maintains one `CCACHE` object across the whole export (`pypykatz.py:41`, `:337-338`), so an aggregate file is what the tool natively produces; the question's singular phrasing argued against it.

### 14.4 Flag 10 — LogonId pairs and representations (7)

| Submitted | Reasoning at the time |
|---|---|
| `0x3e7:0x3e6` | the only two non-owner, non-admin sessions in the on-disk log |
| `0x3e6:0x3e7` | reversed |
| `0x17c514:0x17c569` | afenwick's UPN-swap session, then her reset session |
| `0x17c569:0x17c514` | reversed |
| `0x3e6:0x17c569` | ANONYMOUS 4738 as prepare, afenwick 4723 as reset |
| `0x3e6:0x17c514` | the remaining permutation |
| `0x305b5d:0x305a06` | the 09-08 Administrator pair (both RID-500) |

Plus two representation variants of the leading candidate: `0x000000000017c514:0x000000000017c569` (zero-padded, as the event renders it) and `17c514:17c569` (bare hex). Both rejected, which **eliminates the representation hypothesis** — the pair itself is wrong, not its form.

### 14.5 What the log actually shows

Three distinct failure shapes. The first is the event's known class; the other two became MOC §4 classes 6 and 7.

1. **Format, not content** (MOC §4.1) — accounts for §14.1 only.
2. **Ambiguous referent** (MOC §4, class 6) — flag 2. The ticket is positively identified, decrypted, and its PAC read; "the memory address of the ticket" has at least five defensible meanings in an LSA ticket cache (KRB-CRED start, Ticket ASN.1 start, first mapped byte, cache-entry structure pointer, logon-session pointer) and two serializers produce different ccache bytes for the same ticket. Five addresses × two containers did not converge.
3. **Exhaustive enumeration of a wrong hypothesis** (MOC §4, class 7) — flag 10. Seven pairs and two representations drawn from a three-LogonId cluster that was almost certainly the wrong cluster. The cost of being wrong about *which events constitute "the password attack"* was nine submissions, because each new permutation felt cheap.

**The operational lesson is 3, not 2.** Once four permutations of the same small set have failed, the set is wrong — further permutations are not analysis. The stopping rule should be: *after two rejections from one evidence cluster, go find a different cluster before submitting a third.*

---

## 15. Open flags — state of the evidence

### 15.1 Flag 1 — SHA256 of the service agent

The agent is `svc_bkup`, PID 3376, executed from `\\dc02\ADMIN$\svc_bkup`, parent `services.exe` (596), started `2026-09-09 20:49:57`, base `0x7ff745a00000`, size `0x23000` (143,360 mapped / **103,936 on disk** per its section table: `.reloc` raw offset `0x19400` + raw size `0x200` = `0x19600`).

Build characteristics: stripped, no version resource, no PDB path, sections `.text .data .rdata .eh_fram .pdata .xdata .bss .idata .tls .reloc` — **MinGW/GCC, not MSVC**. Imports `SspiCli.dll`, `wininet.dll`, `Ws2_32.dll`, `kerberos.DLL`, `dhcpcsvc.DLL`.

Two reconstructions exist and differ in **exactly 258 bytes, all in `.idata`** — i.e. the loader-patched IAT. That means the file-object copy (`f54257d2…`) *is* the unpatched on-disk image. It was rejected anyway.

Sysmon has **zero EID 1 records** and ends at 20:24:41 — 25 minutes before the agent ran. The hash is not in the logs.

### 15.2 Flag 2 — golden ticket address

**The ticket is certain. The address representation is not, and neither is the container.**

| Address | What it is | Status |
|---|---|---|
| `0x22746f1e8ac` | verified location of ticket byte 400 (needle match, 4 independent slices) | rejected × both md5s |
| `0x22746f1e780` | start of the contiguous run — ticket byte 100 | rejected × both md5s |
| `0x22746f1e71c` | computed ticket byte 0 — **reads as zeros in the dump** | rejected × both md5s |
| `0x22747394084` / `0x2274739409e` | the *root-realm* ticket, wrong ticket | rejected |
| *cache-entry structure pointer* | never recovered — see §16.2/16.3 | **untried** |

Ticket bytes 0–99 are zeroed in memory while 100–1078 are intact, and the boundary is not page-aligned. pypykatz reconstructs the header from the LSA structure rather than reading it inline. **[Inference] the grader's address is a structure pointer, not the blob address.**

pypykatz's object model discards the pointer: `KerberosTicket` exposes only `EClientName`, `ServiceName`, `TicketFlags`, `TicketEncType`, `TicketKvno`, `KeyType`; `KerberosCredential` and `LogonSession` expose only `luid`. Nothing carries an address.

LUID of the session holding it: **`0xa616a`**.

### 15.3 Flag 10 — prepare:reset LogonIDs

The cluster is certain; the pairing is not. At `2026-09-09 20:46:48`, in order:

| rid | EID | Subject | LogonId | Target |
|---|---|---|---|---|
| 37536 | 4768 | — | — | afenwick TGT (AES256) |
| 37537 | 4769 | — | — | afenwick → DC02$ |
| 37539 | 4738 | afenwick | `0x17c514` | afenwick — **UPN set to `jreed`** |
| 37540 | 4768 | — | — | afenwick TGT again |
| 37541 | 4738 | afenwick | `0x17c514` | afenwick — UPN cleared |
| 37542 | 4738 | ANONYMOUS LOGON | `0x3e6` | jreed — PasswordLastSet |
| 37543 | **4723** | afenwick | `0x17c569` | **jreed — password change** |
| 37544 | 4634 | — | — | afenwick `0x17c569` logoff |
| 37545 | 4768 | — | — | **jreed TGT, etype 0x17 (RC4 downgrade)** |
| 37546 | 4634 | — | — | afenwick `0x17c514` logoff |

Only three LogonIds are present, **every ordered pair of them has been rejected**, and so has the 09-08 `0x305b5d:0x305a06` Administrator pair and two representation variants. The cluster is wrong, not the formatting.

**The one thing never done:** an event-ID histogram of the **MemProcFS-recovered** `Security.txt`. Every histogram in this session ran against the on-disk `security.xml`. The recovered log demonstrably contains records the disk file lacks — rids 37543 (4723) and 38620 (4724) both came from it — and it was only ever grepped for `4723|4724|4738`. A 4794 (DSRM password set), a second 4723 cluster, or anything targeting **`ncole`** — the second victim of the `0x3e6` 4738s at 19:16:44, never investigated — would not have been seen.

```bash
awk '{print $4}' /tmp/mpfs/sys/eventlog/eventlog_parsed/Security.txt \
  | sort -n | uniq -c | sort -rn | head -40
# compare the record count against security.xml's 29,810 — the delta is the unexamined set
```

---

## 16. Tooling to try next

Ordered by expected value.

1. **`-license-accept-elastic-license-2-0` on MemProcFS.** Yara rules were disabled for the entire session. Elastic's ruleset flags credential-theft tooling and injected agents by signature. 42 seconds to re-run, and it may name the agent — which could reframe flag 1 entirely.
   ```
   ./memprocfs -device memory.elf -mount /tmp/mpfs -forensic 1 -license-accept-elastic-license-2-0
   cat /tmp/mpfs/forensic/findevil/findevil.txt
   ```
2. **Patch `volreader.py` to record the read address.** `Vol3Reader` seeks to each ticket before parsing it; adding a `print(hex(self.current_position))` at the ticket read gives the exact address pypykatz used. This is the direct answer to flag 2's address half and it is ~3 lines.
3. **`KIWI_KERBEROS_LOGON_SESSION` walk.** pypykatz's `alsadecryptor/packages/kerberos/` templates define the structure per build. Walking the session list for LUID `0xa616a` and reading the ticket-cache entry pointer gives the mimikatz-equivalent address.
4. **Windows VM + real mimikatz / Rubeus.** `mimikatz # kerberos::list /export` on a restored image prints ticket addresses in exactly the form the question asks for, and writes `.kirbi` in the layout the grader most likely hashed. The strongest single move if a Windows analysis VM is available.
5. **MemProcFS `regsecrets` plugin on Windows.** Same reasoning — it is a pypykatz wrapper and its ccache output may differ byte-for-byte from Impacket's.
6. ~~**Rebuild the ccache with `minikerberos` rather than Impacket.**~~ **Done — both containers rejected against all three addresses.** Recorded because the finding is useful: the two serializers produce different bytes for the same ticket (`3ac801f1…` vs `bd55a03b…`), and `CCACHE.add_kirbi()` takes a `Kirbi` object, not bytes:
   ```python
   from minikerberos.common.ccache import CCACHE
   from minikerberos.common.kirbi import Kirbi
   cc = CCACHE(); cc.add_kirbi(Kirbi.from_file('X.kirbi')); cc.to_file('X.mk.ccache')
   ```
   **Still untried:** the aggregate `24f015400c0b3242068ec1b290b7eb53` (all 29 tickets in one minikerberos ccache), which is what pypykatz's single persistent `CCACHE` object natively emits.
7. **`$MFT` / `$J` from the memory image** for flag 1 — `windows.mftscan` may carry `svc_bkup`'s file record with a hash-bearing `$EA` or ADS, and MemProcFS's `/forensic/ntfs/` tree was only spot-checked.
8. **Remaining EVTX chunks.** 28 chunks were indexed by one filter; the `PasswordLastSet` sweep found hits in regions whose chunk headers never resolved. A full `ElfChnk\0` enumeration of the image, then MemProcFS-style repair of each, would settle flag 10 by exhaustion.

---

## 17. Open items

1. **`solves` omitted** — not read off the platform.
2. **`category` unverified** — carried forward from the other five notes.
3. **Root DC address conflicts with Borrowed Name** (§10). `.11` here, `.10` there.
4. **`rfairfax` is a root-domain user with a cached logon on DC02 and three tickets in lsass**, including `TGT_DIOGENES.HTB_rfairfax_krbtgt_CORE.DIOGENES.HTB` — a root user holding a *child* krbtgt TGT. Not characterised. Possibly a second forged identity.
5. **The `VBoxService.exe → lsass.exe` process access at 22:13:55** (Sysmon EID 10, memory only) was not examined. Four minutes before the golden ticket. VBoxService is a guest-additions binary and has no business opening lsass.
6. **`explorer.exe` PID 2420 flagged `SYSTEM_IMPERSONATION` by MemProcFS findevil**, TID 4612. Never followed up.
7. **`Microsoft.Acti` PID 2408 has ~40 `PE_PATCHED` findevil hits.** Uncharacterised; possibly .NET JIT, possibly not.
8. **The second golden ticket** (`Administrator@DIOGENES.HTB`, root realm, `0x22747394084`) cannot be decrypted — the root krbtgt key is not in DC02's DIT. Its PAC is unread.
9. **Docker instance state** — whether it expired before flag 10 was solved is not recorded.

---

## Cross-references

- [[00_MOC-HTB-Holmes2026-Reichenbach-Directive-Event]] — event index; this room supplies its §4 classes **6 (ambiguous referent)** and **7 (exhaustive enumeration of a wrong hypothesis)**, both distinct from §4.1's format failures
- [[HTB-Holmes2026-Borrowed-Name-AdaptixC2-RC4-Profile-Key-ResetNightmare]] — Sherlock 08; direct predecessor. `svc_bkup`, `afenwick`, `unhappy-meal` and the UPN-write technique all continue here
- [[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]] — Sherlock 01
- [[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]] — Sherlock 02; origin of the answer-format-is-literal rule
- [[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]] — Sherlock 04
- [[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]] — Sherlock 07
- [[HTB-Holmes2026-Poisoned-Branch-Backdoored-Git-Repo-XOR-Mettle-ZipCrypto]] — Sherlock 05; `afenwick` and `jreed` appear there on the DIOGENES roster with their real directorates, which is the identity context this room's UPN swap exploits
- [[00_ctf-writeup-standard]] — structure this note conforms to
- [[HTB]]

---

## Change Log

- 2026-09-20 — Note created. Seven of ten flags solved and recorded; scenario captured verbatim. **All 25 wrong submissions logged in §14** with the exact string, the flag, and the reasoning at the time — 3 intermediate findings, 4 hash candidates, 11 address×md5 combinations, 7 LogonId pairs and representations. §14.5 identifies three distinct failure shapes and proposes two additions to the MOC taxonomy: **ambiguous referent** (the finding is correct and the question's noun has several defensible readings) and **exhaustive enumeration of a wrong hypothesis** (after two rejections from one evidence cluster, change cluster rather than permute). `status: draft` — resumable per §16. `created` stamped from a real fetched UTC clock (container clock, not the vault host's). `updated` omitted per `02_frontmatter-standard` §1 (plugin-owned, not hand-stamped). `solves` and `category` unverified (§17.1–2). **Root DC address conflicts with the Borrowed Name note (§17.3)** — `.11` here from three 4624s, `.10` there; one of the two needs correcting, and this note should not be treated as authoritative on that point until it is reconciled.

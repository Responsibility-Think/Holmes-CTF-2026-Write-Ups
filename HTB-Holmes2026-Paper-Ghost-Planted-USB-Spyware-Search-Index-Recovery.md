---
type: writeup
title: "HTB Holmes 2026 — Paper Ghost: Planted USB Spyware and Windows Search Index Recovery"
platform: Hack The Box
event: "Holmes CTF 2026: The Reichenbach Directive"
challenge: Paper Ghost
category: forensics
subcategory: sherlock-dfir
difficulty: easy
points: 975
status: complete
app: "PaperGhost.zip — 28.8 MB KAPE triage of CO-LT-0469 (Windows 10 19045), targets RegistryHives + LNKFilesAndJumpLists + SRUM, plus an out-of-target Windows.edb"
mitre:
  - T1091
  - T1200
  - T1036.005
  - T1204.002
  - T1123
  - T1125
  - T1005
  - T1552.001
  - T1041
  - T1199
tags:
  - writeup
  - HTB
  - Security
  - DFIR
  - Incident_Response
  - forensics
  - Windows
  - Log_Analysis
related:
  - "[[HTB]]"
  - "[[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]]"
  - "[[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]]"
aliases:
  - Paper Ghost
  - Holmes 2026 Paper Ghost
created: 2026-09-20T08:55:17.237Z
updated: 2026-09-20T08:55:17.237Z
---

# Paper Ghost — Planted USB Spyware, Windows Search Index Recovery

> [!success] Solved — 2026-09-20 04:47 (platform clock) · 9 of 9 flags
> **No `HTB{}` string exists for this room** — it is question-graded. Sherlock 04 of the event · easy · 975 points.
> The room is built on one artifact class: **`Windows.edb`'s `System_Search_AutoSummary` field, which retains up to 1,024 characters of indexed document text after the document itself is gone.**

> [!info] Scenario, verbatim
> SCENARIO NAME
> 4 - Paper Ghost
> The story will unfold through the PDFs provided with each challenge's downloadable ZIP.
>
> All characters, locations, and events are fictional. Any resemblance to real people, places, or events is purely coincidental.
>
> **Supplied artifact:** `PaperGhost.zip` → `Holmes CTF 2026 - Sherlock 04 - The False Employee.pdf` **and a real KAPE triage tree.** Unlike Bottle Out, the evidence is in the download.

---

## Flags — Answers

| # | Question | Answer | Method |
|---|---|---|---|
| 1 | When did Clara Voss first connect the device Elias Venn left at her desk? | `2026-08-19 15:35:50` | `USBSTOR\...\Properties\{83da6326}\0064` + `0065` |
| 2 | What serial number did the dropped device leave behind? | `RS200000000627E4&0` | USBSTOR instance ID, **`&0` included** |
| 3 | Full path of the payload | `E:\CO-LT-0469 update package\update.exe` | UserAssist + SRUM `\Device\HarddiskVolume5` |
| 4 | At what exact timestamp did she execute the malicious package? | `2026-08-19 15:36:25` | UserAssist `Count`, run count 1 |
| 5 | Asset name that surfaced as the device name on connection | `CO-USB-0091` | `SOFTWARE\Microsoft\Windows Portable Devices\Devices` → `FriendlyName` |
| 6 | At what time did microphone capture begin? | `2026-08-19 15:38:08` | NTUSER `ConsentStore\microphone\NonPackaged` → `LastUsedTimeStart` |
| 7 | For how many seconds did the webcam stream? | `127` | same key under `webcam`, Stop − Start |
| 8 | Decimal megabytes of outbound traffic to the C2 | `172.064531` | SRUM `{973F5D5C-…}` `BytesSent` ÷ 1,000,000 |
| 9 | Credentials for a developer working on DIOGENES tickets | `tainsworth:D10g3n3s_T1ck3ts#2026` | `Windows.edb` AutoSummary for `EXT-0419.pdf` |

All timestamps are **UTC as stored in the registry**. The host is Pacific (`ActiveTimeBias 420`), so local is UTC−7; the grader wanted UTC.

---

## 0. How the flags were obtained

1. Unpacked `PaperGhost.zip` — 126 files, 150 MB uncompressed. Read the ConsoleLog for host metadata: **CO-LT-0469**, Windows 10 19045, KAPE targets `RegistryHives,LNKFilesAndJumpLists,SRUM`.
2. Parsed every `.lnk` with `LnkParse3`. Four PDFs under `C:\Users\cvoss\Desktop\DIOGENES_26`, none of which exist in the triage. Established the folder and its creation time.
3. Walked `SYSTEM\ControlSet001\Enum\USBSTOR` and `\Enum\USB` with `python-registry`. One mass-storage device: a Lexar, `VID_21C4&PID_0CD1`, serial `RS200000000627E4`. Read its `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064/0065/0066/0067` for install and arrival/removal times — **flag 1**.
4. `SOFTWARE\Microsoft\Windows Portable Devices\Devices` gave the volume label as `FriendlyName` — **flag 5**.
5. Shellbags from `UsrClass.dat` enumerated the USB's directory tree (`Drivers\{BadgNFC,Chipset}`, `CO-LT-0469 update package`, `Utils\Logs`).
6. **Parsed `Windows.edb` with `dissect.esedb`.** `SystemIndex_PropertyStore` holds 2,068 records; 42 carry `4625-System_Search_AutoSummary`. Six of those are the deleted DIOGENES_26 documents, with their text intact — **flag 9**, plus the entire narrative of the room.
7. SRUM `{973F5D5C-1D90-4944-BE8E-24B94231A174}` (network usage), joined against `SruDbIdMapTable`, produced one row for `\device\harddiskvolume5\co-lt-0469 update package\update.exe` — **flags 3 and 8**.
8. BAM held no entry for `update.exe`; **UserAssist did** — `E:\CO-LT-0469 update package\update.exe`, run count 1 — **flag 4**.
9. `NTUSER\...\CapabilityAccessManager\ConsentStore\{microphone,webcam}\NonPackaged` carried per-binary `LastUsedTimeStart` / `LastUsedTimeStop` for the same executable — **flags 6 and 7**.

---

## 1. Shape of the challenge

A KAPE triage, not a disk image. That single fact sets the difficulty: there is no `$MFT` to carve, no Prefetch, and **no event logs at all**. Every question has exactly one artifact that answers it, and the room is a test of whether you know which.

| Question class | Artifact that answers it |
|---|---|
| Device identity & first connect | `SYSTEM\Enum\USBSTOR` device Properties GUIDs |
| Device label | `SOFTWARE\Microsoft\Windows Portable Devices` |
| Execution time | UserAssist (BAM had rotated) |
| Capture windows | `CapabilityAccessManager\ConsentStore` |
| Exfil volume | SRUM network usage |
| Deleted document content | `Windows.edb` AutoSummary |

The tell that the room is about the search index: KAPE was run with `--target RegistryHives,LNKFilesAndJumpLists,SRUM`, and **`Windows.edb` is in none of those targets.** The author added `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\` deliberately. An artifact present outside the stated collection scope is a signpost.

---

## 2. The triage collection

```
[2026-08-20 01:21:10 | INF] Command line: --tsource C: --tdest ...\KAPE\Triage
                            --tflush --target RegistryHives,LNKFilesAndJumpLists,SRUM --gui
[2026-08-20 01:21:10 | INF] System info: Machine name: CO-LT-0469, 64-bit: true,
                            User: CyberJunkie OS: "Windows10" (10.0.19045)
```

> [!note] The profile was renamed after collection
> The ConsoleLog and CopyLog reference `C:\Users\CyberJunkie` throughout; the copied tree is `C:\Users\cvoss`. SRUM's `SruDbIdMapTable` still carries **both** — `\Device\HarddiskVolume3\Users\CyberJunkie\...\OneDrive.exe` and `\Device\HarddiskVolume3\Users\cvoss\...\OneDrive.exe` as separate AppIds. Same profile, renamed by the author to fit the story. A `CyberJunkie` path in SRUM is not a second user.

Timezone, from `SYSTEM\ControlSet001\Control\TimeZoneInformation`: `TimeZoneKeyName = Pacific Standard Time`, `ActiveTimeBias = 420` → local is **UTC−7**. Registry and SRUM values are UTC; the grader accepted UTC unmodified.

---

## 3. The USB

```
SYSTEM\ControlSet001\Enum\USBSTOR\Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00\
    RS200000000627E4&0
        FriendlyName = Lexar USB Flash Drive USB Device
        ContainerID  = {c12e83c9-7a97-53d0-ac60-72526287e69e}
        Properties\{83da6326-97a6-4088-9453-a1923f573b29}\
            0064 InstallDate      2026-08-19T15:35:50.428691Z
            0065 FirstInstallDate 2026-08-19T15:35:50.428691Z
            0066 LastArrival      2026-08-19T15:51:06.432548Z
            0067 LastRemoval      2026-08-19T15:51:06.557507Z
```

Mounted as **E:** (`MountedDevices\\DosDevices\E:` → `_??_USBSTOR#Disk&Ven_Lexar#RS200000000627E4&0#…`), which reconciles with SRUM's `\Device\HarddiskVolume5`.

The device carries a **second volume**, `F:`, labelled `VTOYEFI` in Windows Portable Devices. That is Ventoy's EFI partition — **the drop USB was built with Ventoy**, which is how a single stick presents a bootable multi-image layout alongside a plain data partition. Not asked about, and worth knowing.

### Shellbags — what was on the stick

From `UsrClass.dat` `BagMRU`:

```
BagMRU\0\3            /E:\
BagMRU\0\3\0          Drivers
BagMRU\0\3\0\0          BadgNFC
BagMRU\0\3\0\1          Chipset
BagMRU\0\3\1          CO-LT-0469 update package
BagMRU\0\3\2          Utils
BagMRU\0\3\2\0          Logs
```

Browsed 15:35:59 → 15:36:18 UTC, nine seconds before execution. `BadgNFC` under `Drivers` is the only folder whose name has nothing to do with a driver update; nothing else in the triage explains it.

> [!warning] Flag 2 is the answer-format trap of this room
> The serial as a bare string is `RS200000000627E4`. **The accepted answer is `RS200000000627E4&0`** — the full USBSTOR instance ID, `&0` included. `RegRipper`'s `usbstor` plugin prints the key name verbatim, and the answer key was evidently built from that output.
>
> This is the *same* failure as Bottle Out flag 4 (`Tactical RMM Agent v.2.11.0`, where the period after `v` was literal). Rule, stated once for both: **submit the string exactly as the artifact renders it. Normalization is the fallback, never the first submission.**

---

## 4. Execution and the capture windows

BAM (`SYSTEM\ControlSet001\Services\bam\State\UserSettings`) has **no entry for `update.exe`** — its newest entries are 2026-08-20 08:16, the reboot before collection, and the 2026-08-19 entries that survive are `cmd.exe` at 13:44:09 and `rundll32.exe` at 15:51:06. BAM rotates; it is not a reliable execution record days later.

**UserAssist carried it.** `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`, ROT13-decoded:

```
2026-08-19T15:36:25.705Z   runs 1   E:\CO-LT-0469 update package\update.exe
2026-08-19T15:34:51.288Z   runs 1   {9E3995AB-…}\TaskBar\Microsoft Edge.lnk
2026-08-19T15:38:27.497Z   runs 6   MSEdge
2026-08-19T15:50:46.041Z   runs 6   Microsoft.Windows.Explorer
```

Run count 1 and an Explorer-launched path — this is a double-click from the mounted USB, 35 seconds after the last shellbag write.

### The capture windows

`NTUSER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\`:

```
microphone\NonPackaged\E:#CO-LT-0469 update package#update.exe
    LastUsedTimeStart  2026-08-19T15:38:08.113179Z
    LastUsedTimeStop   2026-08-19T15:41:03.258924Z      →  175.15 s

webcam\NonPackaged\E:#CO-LT-0469 update package#update.exe
    LastUsedTimeStart  2026-08-19T15:42:28.681431Z
    LastUsedTimeStop   2026-08-19T15:44:35.661981Z      →  126.98 s
```

Path separators are `#`, not `\` — that is how the ConsentStore encodes a NonPackaged binary's path, and it is what makes these keys greppable for a drive letter.

> [!note] Flag 7's rounding
> The exact delta is **126.980550 s**. The accepted answer is **`127`** — i.e. the author truncated both stamps to whole seconds *before* subtracting (`15:44:35 − 15:42:28`), rather than subtracting at full precision and truncating. Submitted `127` first on that reasoning; it took.

Note the asymmetry: the microphone ran for 175 s and the webcam for 127 s, and only the webcam duration was asked for. Both are recoverable from the same key pair.

---

## 5. The ghost documents

This is the room's actual subject. `C:\Users\cvoss\Desktop\DIOGENES_26` and everything in it is gone from the triage — only the LNKs and jumplist entries survive as *references*. **The text survives in the search index.**

`Windows.edb` → `SystemIndex_PropertyStore`, 2,068 records, 598 columns. The field is `4625-System_Search_AutoSummary`, populated on 42 records and **capped at 1,024 characters**. Six of them are the DIOGENES_26 set:

| WorkID | Item | What the summary yields |
|---|---|---|
| 86 | `DIOGENES_26` (folder) | creation 2026-08-19T13:42:30Z |
| 87 | `DIOGENES_Contractor_Assignments.csv` | contractor roster EXT-0419 … EXT-0424 |
| 88 | `Driver Update Package.pdf` | **the lure** |
| 89 | `EXT-0419.pdf` | **flag 9** |
| 90 | `IT_Asset_Inventory.csv` | asset table incl. CO-LT-0431 |
| 92 | `IT_SUPPORT.pdf` | **Elias Venn's onboarding record** |
| 93 | `Schedule.pdf` | Clara Voss's week of 28 July |

### The lure — `Driver Update Package.pdf`

Reads as a Ministerial Briefing Office IT-support package addressed to asset CO-LT-0469, user cvoss, classification OFFICIAL. Contents: `update.exe`. Instructions: insert the USB, *"Open Q4_Briefing_Notes to begin the update"*, allow the installer to complete, **return the USB to the Floor 4 spares cabinet (Cabinet 4C)**. The last step is the operational detail — the device was meant to be returned, i.e. recovered, not abandoned.

### The false employee — `IT_SUPPORT.pdf`

```
Full name:        Elias Venn
Contractor ID:    EXT-0431
Role:             IT Support (Field)
Assigned floor:   Floor 4 — Ministerial Briefing Office
Reporting line:   Standard contractor pipeline (GRUNER onboarding packet)
Asset assigned:   CO-LT-0431 (Lenovo ThinkPad E14)
Badge access:     Floor 4, 07:00–19:00, weekdays
Delivery address: Unit 14, Silvertown East Yard (per contractor file)
First day:        30 July 2026
References:       verified, passed
```

**Silvertown** is the same location Bottle Out's chapter text puts Watson's recovered effects at. The contractor's delivery address is the operation's own yard.

### Flag 9 — `EXT-0419.pdf`

```
Name:                Tom Ainsworth
Contractor ID:       EXT-0419
Internal server:     srv-diogenes-tickets-01.internal
Username:            tainsworth
Password:            D10g3n3s_T1ck3ts#2026
Access scope:        EXT-3 (ticketing host only)
Assigned repository: parse_diogenese_tickets
Supervisor path:     OBERSTEIN service path
```

A plaintext credential pair on a junior minister's desktop, recovered from a deleted PDF via the search index. The question's framing — *"contractors NAPOLEON may now hunt"* — is the point: the spyware's take was a target list.

> [!important] The transferable fact
> **Windows Search indexes file *contents*, and `System_Search_AutoSummary` persists that text in `Windows.edb` after the file is deleted.** Deleting a document does not remove it from the index until the crawler notices — and on a machine imaged shortly after, it has not noticed. 1,024 characters per item, which is roughly the first page of a PDF.
>
> This is a first-page-only oracle. Everything past the cap is unrecoverable from this artifact, and no other artifact in this triage carries it.

---

## 6. Exfiltration

SRUM `{973F5D5C-1D90-4944-BE8E-24B94231A174}`, AppId resolved through `SruDbIdMapTable`:

```
2026-08-19T15:50:00Z  \device\harddiskvolume5\co-lt-0469 update package\update.exe
                      BytesSent 172,064,531   BytesRecvd 615,595
```

172,064,531 ÷ 1,000,000 = **172.064531 MB**. The answer mask `***.******` — three digits, six decimals — is itself the confirmation that decimal MB is wanted: the MiB figure (164.093…) does not fit the mask.

Application resource usage (`{D10CA2FE-…FA89}`) has the same binary at 15:51 with `ForegroundBytesRead 37,607,424`. SRUM's timestamps bucket to the minute, which is why flags 4, 6 and 7 all had to come from the registry instead.

One row, one binary, no other unexplained network talker in the table. Everything else on 2026-08-19 is Edge, EdgeUpdate and OneDrive.

---

## 7. Timeline

All UTC; local is UTC−7.

| UTC | Event | Source |
|---|---|---|
| 08-19 12:47 | `cvoss` profile first-logon app registrations | UserAssist |
| 08-19 13:24:25 | `Driver Update Package.pdf` written | index / LNK |
| 08-19 13:28:44 | `IT_SUPPORT.pdf` written | index / LNK |
| 08-19 13:30:51 | `Schedule.pdf` written | index / LNK |
| 08-19 13:39:31 | `EXT-0419.pdf` written | index / LNK |
| 08-19 13:42:30 | `DIOGENES_26` folder created on the Desktop | LNK |
| 08-19 13:44:45 | USB composite device `VID_0C45&PID_636B` "REDRAGON Live Camera" installs | `SYSTEM\Enum\USB` |
| 08-19 **15:35:50** | **Lexar `RS200000000627E4&0` connected, mounts E:** | USBSTOR `0064`/`0065` |
| 08-19 15:35:59–15:36:18 | E:\ browsed — `Drivers`, `CO-LT-0469 update package`, `Utils` | shellbags |
| 08-19 **15:36:25** | **`E:\CO-LT-0469 update package\update.exe` executed** | UserAssist |
| 08-19 15:38:08 → 15:41:03 | **microphone capture, 175 s** | ConsentStore |
| 08-19 15:42:28 → 15:44:35 | **webcam capture, 127 s** | ConsentStore |
| 08-19 15:50 | **172.06 MB outbound to C2** | SRUM |
| 08-19 15:51:06 | Lexar last arrival and last removal | USBSTOR `0066`/`0067` |
| 08-20 08:21:10 | KAPE triage collected | ConsoleLog |

Fifteen minutes and sixteen seconds from insertion to removal. Execution 35 seconds after the last folder was opened; first capture 103 seconds after execution.

---

## 8. Final payload

Reproduction, from the supplied ZIP to all nine answers. Container had `python3` with `LnkParse3`, `python-registry`, `dissect.esedb`, `olefile`.

```bash
cd /home/claude && mkdir -p pg
unzip -q PaperGhost.zip -d pg
pdftotext -layout "pg/Holmes CTF 2026 - Sherlock 04 - The False Employee.pdf" -

# flags 1, 2 — USB identity and first connect
python3 - <<'PY'
from Registry import Registry; import struct, datetime
def ft(b): return (datetime.datetime(1601,1,1)+datetime.timedelta(
    microseconds=struct.unpack('<Q', b[:8])[0]//10)).isoformat()
s = Registry.Registry('pg/PaperGhost/Triage/C/Windows/System32/config/SYSTEM')
k = s.open(r'ControlSet001\Enum\USBSTOR\Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00'
           r'\RS200000000627E4&0\Properties\{83da6326-97a6-4088-9453-a1923f573b29}')
for sk in k.subkeys():
    for v in sk.values(): print(sk.name(), ft(v.raw_data()))
PY

# flag 5 — device name on connection
#   SOFTWARE\Microsoft\Windows Portable Devices\Devices\SWD#WPDBUSENUM#_??_USBSTOR#...
#   → FriendlyName = CO-USB-0091

# flag 4 — execution time (UserAssist, ROT13 value names, FILETIME at offset 60)
# flags 6, 7 — NTUSER\...\CapabilityAccessManager\ConsentStore\{microphone,webcam}\NonPackaged

# flag 9 — deleted document text from the search index
python3 - <<'PY'
from dissect.esedb import EseDB
db = EseDB(open('pg/PaperGhost/Triage/C/ProgramData/Microsoft/search/data/'
                'applications/windows/Windows.edb','rb'))
t = db.table('SystemIndex_PropertyStore')
for r in t.records():
    s = r.get('4625-System_Search_AutoSummary')
    if s and 'DIOGENES' in str(r.get('4447-System_ItemPathDisplay') or ''):
        print(r.get('4447-System_ItemPathDisplay')); print(s); print('---')
PY

# flags 3, 8 — SRUM network usage, AppId joined through SruDbIdMapTable
#   TimeStamp is an OLE automation date stored as int64:
#   struct.unpack('<d', struct.pack('<q', v))[0] → days since 1899-12-30
```

---

## 9. Tools & techniques

`python3` · `LnkParse3` 1.5 · `python-registry` 1.4 · `dissect.esedb` · `olefile` · `pdftotext` · `unzip`

**Concepts:** KAPE triage target semantics (an artifact outside the stated targets is a signpost) · USBSTOR device-Properties GUID `{83da6326}` subkeys `0064`/`0065`/`0066`/`0067` as first-install / arrival / removal · Windows Portable Devices `FriendlyName` as the volume label · shellbag reconstruction of removable-media trees · UserAssist as the execution record when BAM has rotated and Prefetch was not collected · `CapabilityAccessManager\ConsentStore` NonPackaged keys as per-binary microphone/webcam capture windows · SRUM ESE parsing with OLE-automation-date decoding and `SruDbIdMapTable` joins · **`Windows.edb` `System_Search_AutoSummary` as a post-deletion document-text oracle**

---

## 10. MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| Replication Through Removable Media | T1091 | payload delivered and executed from `E:\CO-LT-0469 update package\` |
| Hardware Additions | T1200 | the device was physically introduced to the target's desk by a person on-site |
| Masquerading: Match Legitimate Name or Location | T1036.005 | `update.exe` inside a folder named for the target asset, accompanied by a forged IT briefing PDF |
| User Execution: Malicious File | T1204.002 | UserAssist run count 1 from an Explorer double-click |
| Audio Capture | T1123 | ConsentStore microphone 15:38:08 → 15:41:03 |
| Video Capture | T1125 | ConsentStore webcam 15:42:28 → 15:44:35 |
| Data from Local System | T1005 | DIOGENES contractor roster, asset inventory and personnel files on the Desktop |
| Unsecured Credentials: Credentials In Files | T1552.001 | `tainsworth:D10g3n3s_T1ck3ts#2026` plaintext in `EXT-0419.pdf` |
| Exfiltration Over C2 Channel | T1041 | 172,064,531 bytes sent by `update.exe`, SRUM |
| Trusted Relationship | T1199 | contractor onboarding and badge access used to reach Floor 4 |

> [!warning] Honest scope
> IDs assigned without access to the live ATT&CK matrix. **T1199 is the weakest** — Elias Venn's contractor status comes entirely from `IT_SUPPORT.pdf` recovered out of the search index, which is scenario narrative; no host artifact evidences a trusted-relationship abuse. **T1091 and T1200 overlap and only one is likely correct**: T1091 describes malware propagating via removable media, while the facts here (a person hand-delivers a prepared device) fit T1200 better; both are listed because the room supports either reading and the distinction was not resolved. T1123 and T1125 are the two strongest — the ConsentStore records the capability access directly, per binary, with start and stop.
>
> No technique covers the defender-side move the room is actually about — recovering deleted document text from the Windows Search index. That is a collection capability, not an adversary behaviour, and ATT&CK has no slot for it.

---

## 11. Detection / blue-team notes

**Detection.** Any one of these is sufficient on its own:

- **A `NonPackaged` entry under `ConsentStore\microphone` or `ConsentStore\webcam` whose path is on a removable drive.** A binary on `E:` requesting camera and microphone access is not a driver update. This key is per-binary, carries start *and* stop times, and nothing in a normal software install touches it.
- **Any executable running from removable media at all** — `\Device\HarddiskVolumeN\` in SRUM where N is not the system volume.
- **Outbound volume disproportionate to the process.** 172 MB from a process whose stated purpose is a driver update, in one SRUM bucket, with 615 KB inbound. The send/receive ratio is the signal, not the absolute number.
- **A Ventoy-built USB in an office environment.** `VTOYEFI` as a volume label on a stick handed over by a contractor is a prepared multi-boot device, not vendor media.
- **Sequence.** USB mount → shellbag writes → UserAssist execution → ConsentStore capture → SRUM egress, all inside sixteen minutes, all attributable to one path string.

**For responders — the collection lesson.** This triage's default KAPE targets would have answered **five** of the nine questions. `Windows.edb` answered one outright and supplied the entire narrative context for the rest, and it is in none of the three targets used. **Add the Windows Search index to any triage profile for a suspected data-theft or insider case** — it is the only artifact in a standard triage that carries *document content* rather than document metadata, and it survives deletion of the document.

**On the wipe.** Nothing here was wiped, but the documents were removed from disk before collection and the index still had them. The general form: the search indexer is a second copy of the first kilobyte of every indexed document on the machine, and almost nobody clears it.

---

## 12. Method notes

- **Submit the artifact string, not a normalized one.** Flag 2 cost a submission on `RS200000000627E4` when the answer was `RS200000000627E4&0`. Bottle Out cost three submissions on the literal period in `v.2.11.0`. Same rule, second event: **the raw rendering is the first submission; normalization is the fallback.**
- **Read the collection log before the artifacts.** The KAPE command line named its three targets in the first 200 bytes of `ConsoleLog.txt`, which immediately identified `Windows.edb` as deliberately out-of-scope. That one line pointed at the room's core artifact before anything was parsed.
- **Scope registry dumps before printing.** A `re.search('cvoss', path)` filter over the property store printed ~450 `AppData\Local\Packages\…` rows and buried the six that mattered. Filter to the field of interest (`AutoSummary` present) rather than to the path.
- **A missing artifact class is information.** No EVTX and no Prefetch in the tree meant execution evidence had to be UserAssist, BAM or SRUM before a single key was read. Enumerating what *wasn't* collected narrowed the search faster than searching.
- **The answer-format mask validated the unit.** `***.******` on flag 8 confirmed decimal MB over MiB without a second submission.

---

## 13. Blind alleys — eliminated, do not re-walk

- **BAM for the execution time.** `ControlSet001\Services\bam\State\UserSettings` has no `update.exe` entry; its 2026-08-19 survivors are `cmd.exe` 13:44:09 and `rundll32.exe` 15:51:06. BAM rotates and is not a two-day-old execution record. UserAssist had it.
- **SRUM for the execution time.** SRUM buckets to the minute (`15:51:00`), which cannot answer a `hh:mm:ss` question.
- **`EMDMgmt` for the volume label.** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt` does not exist on this host. Windows Portable Devices is the surviving source.
- **The Partmgr disk signature as "the serial."** `...\Device Parameters\Partmgr\SnapshotDataCache` yields MBR signature `6A41C78E`, and `DiskId {61486a41-9be3-11f1-8640-000c29177a52}`. Neither is the answer; both are Windows-side identifiers, not something the device carries.
- **Recovering page 2 of any DIOGENES PDF.** AutoSummary is capped at 1,024 characters. `SystemIndex_Gthr` (2,072 rows) holds crawl metadata, not text. There is no second copy in this triage.

---

## 14. Open items

1. **`category: forensics` unverified** — inherited from the Sherlock siblings, not read off the Holmes platform page. The page the answers were submitted against showed POINTS and DIFFICULTY but no category field. Confirm and correct.
2. **`solves` omitted** — not read off the platform.
3. **The "REDRAGON Live Camera" USB composite device is uncharacterised.** `VID_0C45&PID_636B`, serial `SN0001`, video + audio interfaces, first install 2026-08-19T13:44:45Z — **two hours before the Lexar**, and forty-five seconds after the DIOGENES_26 folder was created. Its `LastArrival` is 15:42:19, eleven seconds before the webcam capture starts. That is very likely the camera the spyware actually streamed, but the link was never proven and it answers no question.
4. **`Drivers\BadgNFC` on the USB is unexplained.** An NFC-badge-related folder on a stick delivered by a man carrying a contractor badge, on a floor with badge-controlled access. Nothing else in the triage references it.
5. **`CO-LT-0427` vs `CO-LT-0469`.** `IT_Asset_Inventory.csv` assigns cvoss asset CO-LT-0427; the host is CO-LT-0469 and the lure PDF is addressed to CO-LT-0469. Whether this is the "small inconsistency" the story chapter refers to, or author drift, was not determined.
6. **`SystemIndex_Gthr` (2,072 rows) and the `GatherLogs` `.gthr` / `.Crwl` files were never parsed.** They record crawl history and may date the indexing of the deleted documents independently of the PropertyStore.
7. **The microphone capture (175 s) is longer than the webcam capture (127 s) and was not asked about.** Recorded here because it is in the same key pair and a future reader will wonder.
8. **`Utils\Logs` on the USB.** Present in shellbags, contents unknown — the stick itself is not in evidence.

---

## Cross-references

- [[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]] — Sherlock 02 of the same event; source of the answer-format-is-literal rule that flag 2 re-proved here, and the Silvertown location that `IT_SUPPORT.pdf`'s delivery address matches
- [[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]] — Sherlock 01 of the same event; answer-mask-as-constraint technique
- [[00_ctf-writeup-standard]] — structure this note conforms to
- [[HTB]]

---

## Change Log

- 2026-09-20 — Note created. All nine flags solved and recorded; scenario captured verbatim. `category` and `solves` marked unverified pending a read of the platform page (§14.1–2). Flag 2's `&0` suffix recorded as the second instance of the literal-string rule first earned on Bottle Out flag 4.

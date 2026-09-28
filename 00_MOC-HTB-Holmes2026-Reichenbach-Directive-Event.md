---
type: moc
title: "HTB Holmes 2026 — The Reichenbach Directive: Event MOC and Cross-Room Method"
platform: Hack The Box
event: "Holmes CTF 2026: The Reichenbach Directive"
category: forensics
subcategory: sherlock-dfir
status: in-progress
tags:
  - MOC
  - HTB
  - Security
  - DFIR
  - Incident_Response
  - forensics
  - Methodology
related:
  - "[[HTB]]"
  - "[[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]]"
  - "[[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]]"
  - "[[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]]"
  - "[[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]]"
  - "[[HTB-Holmes2026-Borrowed-Name-AdaptixC2-RC4-Profile-Key-ResetNightmare]]"
  - "[[HTB-Holmes2026-Poisoned-Branch-Backdoored-Git-Repo-XOR-Mettle-ZipCrypto]]"
  - "[[HTB-Holmes2026-Last-Light-Golden-Tickets-RBCD-Unflushed-EVTX-Carve]]"
  - "[[HTB-Holmes2026-Whisper-Chain-Live-XMPP-PubSub-Dispatcher-PerNode-AES]]"
  - "[[HTB-Holmes2026-Silent-Passenger-MQTT-Push-Update-Staged-Dex-Loader-PARTIAL]]"
  - "[[staged-dex-loader-constant-recovery]]"
  - "[[unknown-binary-triage-workflow]]"
aliases:
  - Reichenbach Directive
  - Holmes 2026 MOC
  - Holmes CTF 2026
created: 2026-09-20T09:18:01.409Z
updated: 2026-09-20T09:18:01.409Z
---

# The Reichenbach Directive — Event MOC and Cross-Room Method

> [!info] Scope of this note
> All nine of the event's Sherlocks are documented in this vault. Every cross-room claim below is drawn from the nine notes listed. Where a pattern appears in only two rooms it is marked as such.

---

## 1. Room index

| # | Challenge | Difficulty | Flags | Core artifact class | Note |
|---|---|---|---|---|---|
| 01 | Silent Dividend | medium · 975 | 10/10 | trojanised Electron installer, LuaJIT implant, Sepolia contract | [[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]] |
| 02 | Bottle Out | unverified | 10/10 | E01 disk image, partial wipe | [[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]] |
| 03 | Whisper Chain | medium · 975 | 7/8 | live Prosody XMPP server — MUC archives + PubSub command dispatcher | [[HTB-Holmes2026-Whisper-Chain-Live-XMPP-PubSub-Dispatcher-PerNode-AES]] |
| 04 | Paper Ghost | easy · 975 | 9/9 | KAPE triage + out-of-target `Windows.edb` | [[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]] |
| 05 | Poisoned Branch | medium · 1000 | 15/15 | backdoored internal git repo + UAC Linux triage + live attacker web server | [[HTB-Holmes2026-Poisoned-Branch-Backdoored-Git-Repo-XOR-Mettle-ZipCrypto]] |
| 06 | Silent Passenger | hard · 1000 | 10/20 | TOPWAY/Allwinner Android head-unit firmware + live MQTT push-update channel | [[HTB-Holmes2026-Silent-Passenger-MQTT-Push-Update-Staged-Dex-Loader-PARTIAL]] |
| 07 | Iron Feather | hard · 1000 | 17/17 | PX4 firmware + encrypted dataman/ULog | [[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]] |
| 08 | Borrowed Name | insane · 1000 | 12/12 | AdaptixC2 beacon capture + FAT32 lure + NTLM evtx | [[HTB-Holmes2026-Borrowed-Name-AdaptixC2-RC4-Profile-Key-ResetNightmare]] |
| 09 | Last Light | insane · 1000 | 7/10 | QEMU ELF64 memory core + NTDS/hives + Security & Sysmon evtx | [[HTB-Holmes2026-Last-Light-Golden-Tickets-RBCD-Unflushed-EVTX-Carve]] |

**97 of 111 flags across nine rooms, 3 rooms incomplete.** Every room is question-graded; no `HTB{}` string exists in any of them. **Event result: 7,800 points, 225th of 5,637 teams** — read off the HTB certificate of participation (17–21 Sep 2026), not recalled. **Poisoned Branch is the first room in the event submitted clean** — 15 of 15 first-attempt. **Last Light is its inverse:** 7 of 10 at a cost of 25 wrong submissions. **Whisper Chain is second at 24** — 20 of them on a single flag.

---

## 2. Narrative spine

What the nine rooms establish, with the artifact each fact came from. Everything here is recovered evidence or scenario text, not inference, unless labelled.

**The operation** is codenamed by fragments: `AUTH=NAPOLEON` and `SETTLEMENT_REFERENCE=SR-4821` in Silent Dividend's decrypted payload; `DIOGENES` as the ticketing programme and `OBERSTEIN` as a supervisor path in Paper Ghost's recovered PDFs.

**Funding** (Sherlock 01) — a fake settlement client, `TrustSettle 1.0.0.exe`, drains wallets via unlimited `approve()` to an attacker contract, with its payload key served from a public Sepolia contract so the operator can re-task without redistributing the binary.

**Comms** (Sherlock 02) — a jailer, **Abel Stokes** (`abel.stokes@hotmail.com`, recovered from a WebAuthn credential), runs a purpose-built operator profile: OpenVPN to `18.156.81.166:7577` under an `NPLN-CA` certificate, Gajim Portable on `murknet.htb` as `spurio9@murknet.htb`, and a Tactical RMM agent beaconing to `api.antimattercommunication.xyz`. The chat client is wiped; everything that describes it survives.

**Collection** (Sherlock 04) — **Elias Venn**, a fabricated contractor (`EXT-0431`, delivery address **Unit 14, Silvertown East Yard**), hands **Clara Voss** a Ventoy-built USB. `update.exe` runs mic and webcam capture and exfiltrates 172 MB. The take is a target list: contractor credentials, asset inventory, and `tainsworth:D10g3n3s_T1ck3ts#2026` for `srv-diogenes-tickets-01.internal`.

**The developer pivot** (Sherlock 05) — **Sebastian Moran** (`cbass.Moran@blackpearl2026.htb`) publishes a backdoored repository, `diogenes-ticket-parser`, to the organisation's own forge at `devforge.internal:3000`, alongside a benign decoy repo pushed eight minutes earlier under a near-identical author identity. **Tom Ainsworth** clones and runs it; a Metasploit Mettle implant carried in the repo as a repeating-XOR blob (`calibration.bin` keyed by `diogenes.jpg`) is reconstructed at runtime to `~/.cache/.ticket-parser/.integrity` and calls back to `203.0.113.10:31337`. Moran searches `Work_Stuff/ONBOARDING`, exfiltrates `Gov_HR_Continuity_Emergency_Callout_Roster.pdf`, deletes the original, and packages the take as `LOOT.zip` on his own server at `BlackPearl2026.htb:9999`. **The roster is a ten-row Whitehall call-out directory with home addresses**, one row — `Sarah Kemp`, DIO-1648, Identity Operations — with its position redacted and its handling marked `CONFIDENTIAL`.

**Movement and delivery** (Sherlocks 06 and 07, chapters 09–10) — the relay is a car in the **Pavilion Road car park**, plates false, head unit repurposed; its tasking references an aerial asset. **Sherlock 06 is that head unit** — a TOPWAY/Allwinner Android 8.1 infotainment board whose vendor MQTT push-update channel (`tcp://mqtt.car.cardoor.cn:1883`, credentials `dofun`/`dofun666666` compiled into every unit in the fleet) carries a retained instruction installing `com.tw.jar1`, a four-stage reflective dex loader whose final task repurposes the vehicle as a proxy relay. A quadcopter launches from a secured roof at 51.4997/-0.1608, flies a 24-item PX4 mission into Hyde Park, releases a payload at 2 m AGL at 51.50356/-0.16084, and is brought down over Knightsbridge by an injected `MAV_CMD_INJECT_FAILURE`.

**Intrusion** (Sherlock 08) — the DIOGENES network itself. A mounted `.img` lure delivers an AdaptixC2 beacon to `afenwick` on `WS02` in `core.diogenes.htb`. Inside seventeen minutes the operator enumerates the directory, finds a `WriteProperty` ACE on his own `userPrincipalName`, takes his own NetNTLMv2 with an `internal_monologue` BOF, resets `jreed`'s password through a UPN-collision Kerberos flaw (`CVE-2026-27912`), and hijacks the `defragsvc` svchost group on `DC02` to land a SYSTEM beacon. The operator's own host is `unhappy-meal` at `192.168.56.1`.

**The three evidence-level cross-room links:** **Silvertown** appears as the location of Watson's recovered effects in Bottle Out's chapter text *and* as Elias Venn's contractor delivery address in Paper Ghost's `IT_SUPPORT.pdf`. **DIOGENES** appears as the ticketing programme `srv-diogenes-tickets-01.internal` in Paper Ghost's exfiltrated target list *and* as the compromised forest `core.diogenes.htb` / `diogenes.htb` in Borrowed Name — the collection phase's stolen target list and the intrusion's actual domain name the same programme. **[Inference]** the hostnames themselves differ (`.internal` vs `.htb`), so this is a programme-name join, not a host join; no artifact ties the two machines. **The third, and the strongest: `cvoss_exfil`.** Sherlock 05's `LOOT.zip` contains a 41-byte file named for Clara Voss holding `tainsworth:d10g3n3s_T1ck3ts#2026:forever` — the same credential Paper Ghost recovered from Voss's workstation, now in the possession of the operator who compromised Ainsworth. **The filename names the source room, the credential names the target, and the artifact sits in both rooms' evidence.** Unlike Silvertown (chapter text on one side) and DIOGENES (a programme name, not a host), this is one string recovered from two separate collections. **[Unverified]** the Paper Ghost note records the leading character as `D`, this room's artifact as `d`; one of the two is a transcription error and the Paper Ghost artifact has not been re-read. Secondary: Ainsworth's contractor ID on the roster export is `EXT-0419` against Elias Venn's fabricated `EXT-0431` — **[Inference]** same series, twelve apart, nothing proves a shared issuer.

Those are the only evidence-level joins between rooms recorded in these notes; the rest of the spine is chapter narrative.

**[Inference]** The geography of Sherlock 07 — launch and planned landing at 51.4997/-0.1608, one block from Pavilion Road — puts the drone's rooftop and the relay car within a few hundred metres of each other in Knightsbridge. Not proven by any artifact.

**Unresolved across rooms:** `command.murknet.htb` (Bottle Out, an unexplained cert SAN), `Drivers\BadgNFC` (Paper Ghost, an NFC folder on a stick delivered by a badge-carrying man), and what the drone actually released (Iron Feather, actuator 1 with no payload topic logged).

---

## 3. Cross-room method — the transferable rules

Twelve principles, each earned in at least two rooms — except §3.11 and §3.12, which are single-room entries and are marked as such. These are the reason to keep the notes, not the flag tables.

### 3.1 Submit the string exactly as the artifact renders it

Four rooms, ten submissions burned.

| Room | Flag | Rejected | Accepted |
|---|---|---|---|
| Bottle Out | 4 | `Tactical RMM Agent v2.11.0` | `Tactical RMM Agent v.2.11.0` |
| Paper Ghost | 2 | `RS200000000627E4` | `RS200000000627E4&0` |
| Iron Feather | 5 | `PBKDF2` | `PBKDF2-HMAC-SHA256` |
| Borrowed Name | 6 | `Internal Monologue` · `InternalMonologue` · `Internal Monologue Attack` | `internal_monologue` |
| Borrowed Name | 1 | `AdaptixC2` · `192.168.56.1:8818` · `192.168.56.1` · `unhappy-meal` | `adaptix` |

The rule stated once for all four: **the raw rendering is the first submission; normalization is the fallback, never the opener.** The Bottle Out case is punctuation in the answer-format hint taken literally. The Paper Ghost case is a tool's key-name output (`RegRipper`'s `usbstor`) copied verbatim into the answer key. The Iron Feather case is the inverse — the bare term was *under*-specified, and the qualified form took.

**Borrowed Name adds casing and separator to the list of things that are literal, and names the discriminator.** Flag 6 asks for a "(named) attack". The technique's published name is the Internal Monologue Attack; the operator invoked a BOF whose filename is `internal_monologue`, and that is what graded. **When the answer names a capability the operator invoked, submit the name of the file the operator invoked, not the name of the technique it implements.**

Generalisation: when an answer is a string that some tool prints, ask **which tool the author ran**, and submit that tool's output. When it is a term of art, submit the most fully qualified form. For the one case in this event where the artifact's own rendering was the *wrong* answer, see §3.11.

**Poisoned Branch extends the rule from submission to discovery, and adds the decoy case.** Two additions, neither of which cost a submission because both were caught before one was spent:

- **The operator's capitalisation is data on both sides of the flag box.** `LOOT.zip` was missed by `loot` and `Loot` in a hand-built wordlist and found only when all-caps variants were added. The same literalness that governs what you type into the answer field governs what you type into a wordlist.
- **When two artifacts answer one question with near-identical strings, the malicious object's rendering is the answer.** Flag 2's two Moran identities — `cbass.Moran@blackpearl2026.htb` (malicious repo, misspelled name, lowercase `c`) and `Cbass.Moran@blackpearl2026.htb` (benign repo, correct name, uppercase `C`) — differ by one letter's case and one letter's order. **The benign repo exists to supply the wrong one.** Reading only one repo, or normalising, loses the flag.

### 3.2 The answer format is a constraint, not decoration

Silent Dividend used the `**.****,*.****` mask to pin the flag offset to bytes 42–83 of an 84-byte plaintext, and confirmed a 14-character Solidity short string against storage slot 3's trailing `0x1c`. Bottle Out resolved `?:\?????\????\?????` to `C:\Users\spur\Gajim` — the four-character username was the discriminator. Paper Ghost used `***.******` to confirm decimal MB over MiB without a second submission.

**Iron Feather extends this: the requested precision selects the source artifact.** Flag 10 asks 5 decimal places and comes from the mission plan; flags 11, 12 and 15 ask 7 and come from telemetry. When two artifacts answer the same question and diverge below the requested precision, the precision is telling you which artifact class the author read.

### 3.3 Protection is applied to the data, never to what describes or unlocks it

The single most productive idea in the event.

| Room | Protected | What survived, unprotected |
|---|---|---|
| Silent Dividend | payload command, encrypted in the binary | the key, readable by anyone via one `eth_call` |
| Bottle Out | Gajim directory, `Remove-Item -Recurse -Force` | Prefetch loaded-directory list, MFT entries, `Security.evtx` 4688, registry hives |
| Paper Ghost | DIOGENES PDFs, deleted from disk | `Windows.edb` `System_Search_AutoSummary` — the first 1,024 characters of each |
| Poisoned Branch | exfiltrated roster, ZipCrypto-encrypted `LOOT.zip` | a readable copy of one archive member, in the same directory |
| Iron Feather | dataman and flight log, AES-256-GCM | the key derivation, compiled into the shipped firmware |
| Borrowed Name | the whole C2 session, RC4 under per-agent session keys | the listener key, in cleartext 16 bytes past the ciphertext it decrypts, inside the dropped beacon |

Stated as a rule: **anti-forensics that targets one object does not target the metadata that describes it, and encryption that ships with its own key schedule is encoding.** In four of the six rooms the answer to "what was destroyed" was reachable from something the operator did not think of as data.

Borrowed Name is the strongest form of it, because the key is **per-listener, not per-agent**: one recovered dropper decrypts every beacon that listener ever produced, in this capture and in any other. **Recovered implant plus captured traffic equals plaintext** — attempt that before any behavioural inference from packet sizes and timing.

**Poisoned Branch adds a cryptographic variety of the same failure.** In the first four instances the unprotected sibling was a *key* or a *description* — informational leakage. Here the operator's `README.txt` is both a member of the encrypted archive and a readable file in the directory beside it, which makes ZipCrypto's Biham–Kocher known-plaintext attack immediate and the password irrelevant. Extended rule: **for legacy ZIP encryption, a readable copy of any member is equivalent to the key.** Twelve known bytes are sufficient; this room supplied seventy-six.

The room also supplies the cleanest demonstration in the event of why this class matters: **the password was strong and it bought nothing.** It survived rockyou, an exhaustive printable search to twelve characters and 184,877 targeted combinations. The break did not go through it. **Where a known-plaintext attack exists, key strength is not a control** — which is the generalisation of §3.3 from "they left the key lying around" to "the protection was never load-bearing in the first place."

### 3.4 Enumerate what is *not* present before searching what is

Paper Ghost: no EVTX and no Prefetch in the KAPE tree, so execution evidence had to be UserAssist, BAM or SRUM before a single key was read. Bottle Out: the survived/did-not-survive table was built first and drove every subsequent tool choice. Iron Feather: `PX4ULENC` has zero hits in the binary, which immediately said the ULog encryptor was not shipped and the shared salt was the intended route.

Corollary from Paper Ghost: **an artifact present outside the stated collection scope is a signpost.** KAPE was run with `--target RegistryHives,LNKFilesAndJumpLists,SRUM` and `Windows.edb` is in none of them. The author put it there on purpose, and it carried the room.

### 3.5 A null result on a transformed container proves nothing

Bottle Out lost 11 minutes and nearly a wrong conclusion to a `bstrings` sweep over a 12.96 GB E01 that returned zero hits for `PUSH_REPLY` — a string sitting at offset `0xbc0` of a file inside that image. EnCase block compression defeats raw string search. Silent Dividend: `strings` on the NSIS installer for `cdef` returns only LZMA byte coincidences. Iron Feather: both evidence files are ciphertext after byte 60.

**Poisoned Branch adds a fourth mechanism and the nastiest one: per-field encoding inside a plaintext file.** `auditd` stores any EXECVE argument containing whitespace or special characters as an unquoted hex string. `grep wget audit.log` returns a record that reads as `wget -q -O authorized_keys` — a syntactically invalid invocation with no URL — while the two arguments carrying flags 7 and 8 sit in the same line as hex. The file is ASCII, the log is not encrypted or compressed, and substring search still fails. `ausearch -i` decodes natively; a raw-log parser must branch on `a\d+=[0-9A-F]+`.

**Compression, packing, encryption and per-field encoding all break substring search identically. Absence of a hit in a transformed container is not evidence of absence of the string.**

### 3.6 Decide early whether a layer is reachable statically, then stub-and-run

Silent Dividend's most expensive lesson: two flags were locked behind an obfuscator that decrypts its strings inside its own VM dispatch loop. Porting both outer encodings statically answered neither; an instrumented LuaJIT harness with `ffi` replaced by a logging proxy answered both in minutes.

Iron Feather is the mirror image. The 384-round mixer *is* statically reachable, because it is a pure function of compiled constants — so it was transcribed instruction-by-instruction and run, without ever being understood. Magic-multiply divisions were replicated as literal 64-bit arithmetic rather than rewritten as `%` and `/`, removing the only place a transcription could silently diverge.

**Rule: reimplement when the transform is closed over constants you can read; instrument and run when it depends on runtime state you cannot.** Understanding the algorithm is optional in both cases.

### 3.7 Look for a verification primitive before submitting anything

Iron Feather's AES-GCM tag verified on both files, which retroactively proved four separately-graded flags — the function RVA, the round count, the KDF and the cipher — before any of them was submitted. Silent Dividend had the same structure available and used it as a cross-check: the offline crib-drag predicted four characters that the on-chain key later confirmed.

**When an artifact contains an authenticated or self-checking construction, route the uncertain answers through it.** It converts inference into proof for free, and it is the only mechanism in a question-graded room that gives feedback without spending a submission.

### 3.8 "Cleaner" is not "correct" — prefer the artifact the scenario's premise allows

Iron Feather's three-submission failure. `vehicle_global_position_groundtruth` is exactly constant after impact while the EKF solution wanders across six distinct 7-dp values; stability was read as evidence of authorial intent. It was actually evidence that the topic is a **simulator artifact that would not exist in a genuine recovered flight log**.

The same trap in milder form elsewhere: Bottle Out flag 4 has three authoritative sources for a version string (PE version resource, Prefetch filename, service `DisplayName`) and none of them produces the accepted answer alone. Paper Ghost flag 4 has three execution artifacts (BAM, SRUM, UserAssist) and only one has the record at `hh:mm:ss` resolution.

**When several artifacts answer one question, the tiebreak is which one a real responder would hold, at the resolution the question demands.** Not which one is tidiest.

### 3.9 Anchor on the event record, then read state at that instant

Iron Feather's positional flags are all `vehicle_global_position` sampled at a logged event: `landed`→false for takeoff, the `DO_SET_ACTUATOR` command timestamp for the release, the altitude floor for impact. Bottle Out's event 4688 records supplied the OpenVPN config and log paths that no longer existed in the MFT; the paths came from the *event*, the content from the file the event named. Paper Ghost's ConsentStore `LastUsedTimeStart`/`Stop` pairs are per-binary event boundaries, and SRUM's minute-bucketing is precisely why they could not answer flags 4, 6 or 7.

**Find the record that timestamps the event, then read the state artifact at that timestamp.** Averaging, taking the last sample, or taking a convenient sample are all wrong when the question asks "where was it when X happened".

### 3.10 A correction to one answer invalidates the model, not just the answer

Iron Feather, stated plainly because it cost a submission that should not have: after flags 12 and 15 were corrected from groundtruth to event-instant EKF sampling, flag 11 was resubmitted using the *arming* timestamp rather than liftoff — applying the new source but the old event model. The pattern was visible and was not re-applied backwards.

Bottle Out has the procedural cousin: `Abel Stokes` was already present in a paste while three further searches were being drafted, costing two exchanges. Rule from that note, which generalises: **any output over a few hundred lines gets a regex sweep before it gets read**, and **any corrected assumption gets re-applied to every answer built on it, not only to the one that failed.**

---

### 3.11 The answer-format hint outranks the artifact — but only when it specifies a representation

Borrowed Name flag 10 is the one place in this event where §3.1 inverts. The lateral-movement BOF's argument and its own console output both read `\\dc02\ADMIN$\svc_bkup`; the accepted answer is `\\192.168.56.11\ADMIN$\svc_bkup`. The artifact's rendering was rejected and the normalised form took, because the hint reads `\\IP\Share\...` — it names the representation.

The discriminator is whether the hint **specifies a form**. `(SID)`, `(md5 hash)`, `(CVE-****-*****)` and `\\IP\Share\...` all do, and where they do they override how the artifact happens to render. `(string)` specifies nothing.

**Corollary — a bare `(string)` hint is a warning, not a hint.** Borrowed Name flag 1 burned four submissions, each defensible from evidence: the framework name, the callback address with port, the address alone, and the operator's machine name recovered from the NTLM log. Nothing in `(string)` narrows any of them. When the hint carries no representation, enumerate the naming variants before submitting and open with the most minimal lowercase form.

---

### 3.12 A live host is an evidence source with an expiry — work it first

*Two rooms — Poisoned Branch and Silent Passenger.*

Five of that room's fifteen flags (11–15) exist only on a 24-hour instance at `10.129.4.236`; nothing in the 200 MB download answers them. Ten flags are in a static triage collection that will still be there next month. **The correct sequencing is perishable-first**, and it was not followed — the offline analysis ran to completion before the VPN was connected. It cost nothing only because the box stayed up. Two of the room's open items are now permanently unclosable because the instance was released before they were pulled.

Two sub-points that generalise:

- **The question text is part of the brief.** Flag 7 reads "*set the spawned vm IP to this URL in your /etc/hosts to complete the challenge*". That sentence declares that the answer is a hostname, that a web service is listening, and that the rest of the room is behind it — before any evidence is opened. This is §4.5's "read the brief" applied to the flag list rather than the scenario PDF.
- **Enumerate what the live host gates before spending time offline.** Reading the flag list for questions that name the *attacker's* infrastructure or the *attacker's* actions on their own machine ("while preparing the listener", "the file the attacker is keeping") identifies the perishable set in about a minute.

**Silent Passenger is the case where ignoring this cost the room.** Eighteen of its twenty flags existed only on a five-port Docker instance; the 563 MB download answered two. The session reassembled a 900 MB filesystem and decompiled three stages before mapping a single port, and closed at 10/20 with the instance expired. Poisoned Branch cost nothing only because the box stayed up. **Map every port to a protocol before opening the download** — five `curl` calls and one `nc` take a minute and reframe the room.

---

## 4. Recurring failure taxonomy

Eight classes, drawn from the method notes across all nine rooms. Worth reading before starting a room, not after. **Classes 1–5 come from the first six rooms. Classes 6 and 7 are Last Light's, and between them they account for 22 of that room's 25 wrong submissions. Class 8 is Silent Passenger's.**

1. **Format, not content.** Eleven of the thirteen wrong submissions from the event's first six rooms were correct findings in the wrong string, casing or unit — all thirteen from five of those six; **Poisoned Branch added none**, having checked each answer against the artifact's literal rendering before submitting rather than after a rejection: `v.2.11.0`, `&0`, `PBKDF2`, straight-line vs ground-track metres, plus Borrowed Name's seven — three spellings of `internal_monologue` and four namings of `adaptix`. **Last Light adds three** (its §14.1 — evidence values submitted as answers), taking this class to **14 of the event's 38 wrong submissions**. **The analysis was done; the submission was not.**
2. **Source selection between equally valid artifacts.** Groundtruth vs EKF; Prefetch vs version resource vs service name; BAM vs SRUM vs UserAssist. Costs multiple submissions each time because every candidate looks defensible.
3. **Reasoning about a container from its metadata.** Bottle Out: "~1 MB archive" reasoned to "config and log files", and the megabyte was JPEG story art. Paper Ghost: browser databases with plausible file sizes, schema-only. **Size is not evidence of use, and archive size is not evidence of content.**
4. **Tool-capability gaps mistaken for absence of evidence.** Bottle Out: FTK Imager's orphan tree silently omits a file whose MFT parent record was reused; Autopsy's `$OrphanFiles` enumerates by entry number and found it immediately. That one difference was six flags versus nine. **When a tool returns nothing, establish whether it *can* return the thing.**
5. **Not reading the brief.** Bottle Out: eight exchanges debugging VPN connectivity while the challenge page said "RDP into the analysis VM" and gave the credentials. Poisoned Branch is the positive case: flag 7's own question text names `/etc/hosts` and a spawned VM, which declares the shape of the room's second half before any evidence is opened. Paper Ghost: the KAPE command line in the first 200 bytes of `ConsoleLog.txt` named the room's core artifact as deliberately out-of-scope. **The collection log and the challenge page are evidence.**
6. **Ambiguous referent — the finding is right and the question's noun is not.** Last Light flag 2: the golden ticket was positively identified, decrypted with the child krbtgt hash, and its PAC read in full — and eleven address×md5 combinations were still rejected. "The memory address of the ticket" has at least five defensible meanings in an LSA ticket cache (KRB-CRED start, Ticket ASN.1 start, first mapped byte, cache-entry structure pointer, logon-session pointer), and two serializers — Impacket and minikerberos — produce different ccache bytes for the same ticket. **Distinct from class 1:** there the finding was right and the *string* was wrong; here the finding is right and the *object being named* is undetermined. When a question names a structure rather than a value, establish which structure before enumerating representations.
7. **Exhaustive enumeration of a wrong hypothesis.** Last Light flag 10: seven LogonId pairs plus two representation variants, all drawn from one three-session cluster at 20:46:48 that was almost certainly the wrong cluster. Each permutation felt cheap, so nine submissions went to re-ordering the same evidence rather than finding different evidence — and the one thing never done was an event-ID histogram of the *memory-recovered* Security log, which is known to hold records the disk log lacks. **Stopping rule: after two rejections from a single evidence cluster, change cluster before submitting a third.**
8. **Protocol-gated — the analysis is finished and the remaining answers need a client you have not written.** Silent Passenger flags 13–20. Every artifact was recovered and every transform correctly ported through four stages; the chain then required speaking a length-prefixed binary protocol (`com.a.b.a.an.a()`, magic `25746`, opcode `101`) to a service whose only feedback on a malformed frame is a TCP reset. **Distinct from 1–5, which concern evidence, and from 6–7, which concern reasoning about a correct finding** — here nothing further was reachable by reading. Corollary: in a room with live infrastructure, map every port to a protocol before beginning static work. The static chain is restartable; the instance is not.

---

## 5. Toolchain by artifact class

Consolidated from the nine rooms; a starting kit rather than an inventory.

| Artifact class | Tools | First move |
|---|---|---|
| Raw disk image (E01) | FTK Imager (mount, block device RO), Autopsy `$OrphanFiles`, `MFTECmd` | mount, never extract; MFT to CSV and query it |
| Windows triage tree | `python-registry`, `LnkParse3`, `dissect.esedb`, `EvtxECmd`, `PECmd`, `RECmd`, `bstrings` | read the collection log; enumerate what is missing |
| Search index | `dissect.esedb` on `Windows.edb` → `SystemIndex_PropertyStore` | filter on `4625-System_Search_AutoSummary` present |
| Packed installer | `7z`, custom ASAR parser | identify the packer chain before any `strings` |
| Obfuscated script | stubbed-module harness in the native runtime | decide static vs dynamic before porting anything |
| On-chain component | `cast` (Foundry), raw JSON-RPC, `pyevmasm` | `eth_getCode` then cut the metadata trailer |
| Stripped ELF | `objdump`, `readelf --dyn-syms`, rel32 call-site scan | locate functions by their calls to exported library symbols |
| Encrypted container | `pycryptodome`, reimplemented KDF | find the AEAD tag and let it be the oracle |
| Flight log (ULog) | `pyulog` with `message_name_filter_list` | print `logged_messages` and `vehicle_command` first |
| C2 packet capture | `scapy` stream reassembly, the framework's own source from GitHub | identify the framework, then read its source for the wire format |
| Mounted-image lure (`.img` / `.iso`) | `pyfatfs` at the partition offset, `pefile` | extract by offset; no loop mount, no root |
| Windows event log | `python-evtx` | pivot on `ProcessName` + `ProcessPID` against network-side identity |
| Linux live-response triage (UAC) | `ausearch -i`, raw `audit.log` parser, `ss`/`ps` text captures, `bodyfile.txt` | read the UAC banner, then `auditctl -l` — the rule set tells you what exists |
| Git repository as evidence | `git log --pretty=fuller --stat`, `git ls-tree -r --long`, `git show HEAD:<path>` | never trust the working tree; the payload may exist only in the pack |
| Encrypted ZIP archive | `bkcrack` (not in Kali repos), `zip2john`/`john`, `7z l` | `-L` for the encryption type *before* any wordlist run; `cmplen − 12` for ZipCrypto |
| Split Android firmware image | `dumpe2fs -h`, `cat` + `head -c`, `debugfs -R "dump …"` | reassemble to the **superblock's** declared size, not the files' total; extract by path, never loop-mount |
| Staged Android dex loader | `jadx`, `blobtriage.py`, `dexconst.py` (`strings` / `arrays` / `keys`) — [[staged-dex-loader-constant-recovery]] | auto-detect the string transform before reading the decoder method; parse `byte[]` literals out of the decompiler output rather than retyping them |
| MQTT command channel | `mosquitto_sub -i <id> -u <u> -P <p> -t '#' -v -d` | SUBACK `0` vs `128` is a free ACL oracle; a null client ID is dropped silently with no CONNACK |
| Unidentified binary / carved blob | `blobtriage.py` — [[unknown-binary-triage-workflow]] | identify it, or rule out the entire static-transform family in seconds; a size of `N × 4096 + 32` is framing, not payload |

---

## 6. Open threads

Carried from the six notes; anything here is a lead, not a finding.

1. ~~**`command.murknet.htb`** — Bottle Out §14.3. A cert SAN that is not a standard XMPP subdomain and is referenced nowhere else in the image.~~ **Closed by Whisper Chain §6** — it is a PubSub service, identity `Murknet Command Dispatcher`, carrying one node per operation of AES-256-CBC command blobs under per-node keys. Bottle Out saw the SAN because the certificate describes infrastructure the wiped host never reached.
2. **`Drivers\BadgNFC`** — Paper Ghost §14.4. NFC-badge folder on a stick delivered by a man with contractor badge access to a badge-controlled floor.
3. **`SYS_FAILURE_EN`** — Iron Feather §15.2. `parameter_update` in the ULog would date the enabling of failure injection, which is the strongest untested lead in that room.
4. **`CO-LT-0427` vs `CO-LT-0469`** — Paper Ghost §14.5. Asset inventory disagrees with the host and the lure PDF.
5. **`MpCmdRun.exe` at 12:30:51 UTC** — Bottle Out §14.4. Seven minutes before the wipe, uncharacterised; the Defender operational log was never read.
6. **`dc01.diogenes.htb` (`192.168.56.10`)** — Borrowed Name §17.5. The parent domain's DC was resolved and queried for domain information two minutes before the DACL read, then never touched again. The capture ends before any cross-domain action.
7. **The RDP session at 19:42:58** — Borrowed Name §17.3. `afenwick`'s credentials were used interactively from the C2 host fifty minutes *before* the beacon stole them, after one failure at 19:20:17. Either the operator re-derived what he already had, or two phases of the operation did not share notes.
8. **Silent Passenger's registration protocol** — Sherlock 06 §12.2. `an.a()` is fully decompiled and the frame shape known; ports 30469/30519 accept TCP and reset on it. Flags 13–20 are all downstream of the UID it returns. Also open from that room: flag 6's reflective entry point (`com.c.j.qbh.wa:2039` is the untested candidate, §12.1), flag 12's generated config target (§12.3), and the two unidentified firmware blobs (§11).
9. **`difficulty`, `points` and `solves` unverified** on Bottle Out; `category` unverified across all six; `solves` omitted everywhere. Poisoned Branch's `difficulty` and `points` *are* verified from the challenge page.
10. **`d10g3n3s` vs `D10g3n3s`** — Poisoned Branch §17.4. The DIOGENES ticketing credential is recorded with a different leading case in the Paper Ghost note and in Poisoned Branch's `cvoss_exfil`. One is a transcription error. **This is load-bearing** — the credential is the event's strongest cross-room join and is cited in §2.
11. **`/home/moran/repos/` and the deleted `toss/`** — Poisoned Branch §17.7. Both named in the operator's surviving bash history, neither enumerated before the instance expired. `repos/` plausibly holds pre-push copies of both internal repositories.
12. **Two timestamp inconsistencies on Tom's host** — Poisoned Branch §17.5–6. `authorized_keys` is stamped five days before the `wget` that wrote it; `LOOT.zip` is stamped two days before the exfiltration it contains. **[Unverified]** whether these are authoring artifacts or findings.
13. **`Sarah Kemp` (DIO-1648)** — Poisoned Branch §7. The only roster row with a redacted position and a `CONFIDENTIAL` handling marking, in Identity Operations. Whatever her role is, the operator now has her home address, and no room in this vault explains why that row is marked differently.

---

## Cross-references

- [[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]]
- [[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]]
- [[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]]
- [[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]]
- [[HTB-Holmes2026-Borrowed-Name-AdaptixC2-RC4-Profile-Key-ResetNightmare]]
- [[HTB-Holmes2026-Poisoned-Branch-Backdoored-Git-Repo-XOR-Mettle-ZipCrypto]]
- [[HTB-Holmes2026-Last-Light-Golden-Tickets-RBCD-Unflushed-EVTX-Carve]]
- [[HTB-Holmes2026-Whisper-Chain-Live-XMPP-PubSub-Dispatcher-PerNode-AES]]
- [[HTB-Holmes2026-Silent-Passenger-MQTT-Push-Update-Staged-Dex-Loader-PARTIAL]]
- [[staged-dex-loader-constant-recovery]] — `technique` note: constant recovery from staged dex loaders, derived from Sherlock 06
- [[unknown-binary-triage-workflow]] — `technique` note: identifying an unknown binary, or ruling out the static-transform family
- [[00_ctf-writeup-standard]]
- [[HTB]]

---

## Change Log

- 2026-09-21 — §5 gains a row for unidentified-binary triage, and both `technique` notes spun out of this event are now linked: [[staged-dex-loader-constant-recovery]] and [[unknown-binary-triage-workflow]]. The staged-dex-loader row was also corrected — it listed `crack` as a `dexconst` subcommand, which stopped being true when the tooling was split into `blobtriage.py` (general triage) and `dexconst.py` (Java/dex constants). `related` and Cross-references carry both notes.
- 2026-09-21 — Silent Passenger (Sherlock 06, hard, 10/20) added; the event is now fully indexed. §1 gains row 06; flag total 87 → **97 of 111**, and the line now carries the event result (7,800 pts, 225th of 5,637) sourced from the participation certificate rather than recalled. Scope callout rewritten — it previously asserted that Sherlock 06 was not attempted, which became false the moment the writeup was filed beside it. §2 header six → nine and the movement paragraph gains the head unit as Sherlock 06's artifact. §3.12 promoted from single-room to two-room and gains the **cost** case: this is the first room where perishable-first was not followed and the room was lost because of it. §4 header seven → eight, **new class 8 (protocol-gated)**. §5 header six → nine, three toolchain rows added. §6.8 open thread replaced — the Sherlock 06 gap is closed and three of that room's own threads take its place. `related` and Cross-references updated. **Not changed:** frontmatter `status: in-progress` (still outside the `02_frontmatter-standard` §1 enum), the absent `moc` extension fields (`domain`, `scope`, `cert`, `course`, `last_audited`), and the note's location under `40_Writeups/` rather than the §3 `moc` path pattern — all three carried forward from prior entries and reported rather than fixed, per E5. `updated:` left untouched per §1 (plugin-owned, not hand-stamped).
- 2026-09-20 — Note created after Iron Feather. Indexes four of seven Sherlocks; §1 and §6.6 record the three rooms not attempted. Method rules §3.1–3.10 each cite at least two rooms. `type: moc` and the `status` value need checking against `Governance/02_frontmatter-standard.md` before filing.
- 2026-09-20 — Borrowed Name (Sherlock 08, insane, 12/12) added. §1 gains row 08; flag total 46 → 58; scope callout and §2/§4/§5/§6 headers four → five. §2 gains the intrusion paragraph and a second evidence-level cross-room join (DIOGENES, labelled as a programme-name join). §3.1 gains two rows, a recount to ten burned submissions, and the tool-filename sub-rule. §3.3 gains a row and the per-listener-key corollary. **New §3.11** records the one case in this event where the answer-format hint outranked the artifact's rendering, with the bare-`(string)` corollary. §4.1 recount 4-of-6 → 11-of-13. §5 gains three toolchain rows. §6 gains two threads and renumbers 6–7 to 8–9. `related` and Cross-references updated. **Not changed:** frontmatter `status: in-progress` (not in the §1 enum) and the absent `moc` extension fields (`domain`, `scope`, `cert`, `course`, `last_audited`) — both remain non-conformant and are carried forward from the entry above. `updated:` left untouched per `02_frontmatter-standard` §1 (plugin-owned, not hand-stamped).
- 2026-09-20 — Poisoned Branch (Sherlock 05, medium, 15/15) added. §1 gains row 05; flag total 58 → 73; scope callout and §2/§4/§5/§6 headers five → six; not-attempted list 03/05/06 → 03/06. §1 records the event's first clean room. §2 gains the developer-pivot paragraph and **a third evidence-level cross-room join, `cvoss_exfil`, which is the strongest recorded and supersedes Silvertown and DIOGENES in strength** — carrying an unresolved case discrepancy against the Paper Ghost note, flagged in §6.10. §3.1 gains a discovery-side corollary and the decoy-author case but **no table rows** (zero wrong submissions). §3.3 gains a row, a recount (three-of-five → four-of-six) and a cryptographic sub-class (known plaintext as key-equivalent; strong password as no control). §3.5 gains per-field hex encoding as a fourth transform mechanism. **New §3.12** records live-host evidence expiry and perishable-first sequencing, marked single-room. §4.1 denominator annotated — count unchanged at 11 of 13, now across five of six rooms. §4.5 gains a positive instance. §5 gains three toolchain rows. §6 gains four threads (10–13) and amends 8–9. `related` and Cross-references updated. **Not changed:** frontmatter `status: in-progress` (still not in the §1 enum — verified this session against `02_frontmatter-standard`, which permits `active|stub|draft|complete|closed`), the absent `moc` extension fields, and the note's location under `40_Writeups/` rather than the §3 `moc` path pattern. `updated:` left untouched per §1. Post-write correction in the same session: §2's lead-in read "The two evidence-level cross-room links" after a third was appended; changed to "three."

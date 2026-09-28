---
type: writeup
title: "HTB Holmes 2026 — Whisper Chain: Live XMPP Server, PubSub Command Dispatcher, Per-Node AES Keys"
platform: Hack The Box
event: "Holmes CTF 2026: The Reichenbach Directive"
challenge: Whisper Chain
category: forensics
subcategory: sherlock-dfir
difficulty: medium
points: 975
status: closed
app: "Live Prosody XMPP server at 10.129.4.251 (murknet.htb) — no downloadable evidence; WhisperChain.zip contains only the story PDF"
mitre:
  - T1071.001
  - T1573.001
  - T1552.001
  - T1589.001
  - T1593.001
  - T1213
  - T1078
tags:
  - writeup
  - HTB
  - Security
  - DFIR
  - Incident_Response
  - forensics
  - Network_Forensics
  - OSINT
related:
  - "[[HTB]]"
  - "[[00_MOC-HTB-Holmes2026-Reichenbach-Directive-Event]]"
  - "[[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]]"
  - "[[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]]"
  - "[[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]]"
  - "[[HTB-Holmes2026-Poisoned-Branch-Backdoored-Git-Repo-XOR-Mettle-ZipCrypto]]"
  - "[[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]]"
  - "[[HTB-Holmes2026-Borrowed-Name-AdaptixC2-RC4-Profile-Key-ResetNightmare]]"
  - "[[HTB-Holmes2026-Last-Light-Golden-Tickets-RBCD-Unflushed-EVTX-Carve]]"
aliases:
  - Whisper Chain
  - Holmes 2026 Whisper Chain
  - Sherlock 03
created: 2026-09-21T12:16:47.965Z
---

# Whisper Chain — Live XMPP Server, PubSub Command Dispatcher, Per-Node AES Keys

> [!warning] Incomplete
> **7/8 flags.** Flag 8 (*latest operation name + objective*) unsolved after ~15 submissions. §12 records every string tried and why the reasoning failed, because that is the transferable part of this note.

The PDF `/Title` leaks the working name again: `Holmes CTF 2026 - Sherlock 03 - XMPP Threat Intelligence`. Bottle Out's leaked the same way (`Sherlock 02 - XMPP Server Forensics`). **Read PDF metadata on every scenario ZIP in this event.**

---

## Flags — Answers

| # | Question | Answer | Source |
|---|---|---|---|
| 1 | TLS SANs, primary first then alphabetical | `murknet.htb,command.murknet.htb,groups.murknet.htb,upload.murknet.htb` | `openssl s_client -starttls xmpp` |
| 2 | Public channels, alphabetical | `Infrastructure,Random,Resources,Rules` | MUC `disco#info` **display names**, not JID localparts |
| 3 | APT member credentials | `zytglogge88@murknet.htb:TickTock24!` | PDF metadata + public-room password paste |
| 4 | Social media URL | `https://stonedforums.htb/@porlock` | Wayback-archived threat report |
| 5 | XMR wallet, first operation | `429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye` | `op_sparkling` command-4 |
| 6 | Nickname of the kidnapper | `dynamite` | `op_snatch` role assignment + delivery report |
| 7 | Where Watson was kidnapped | `Victoria Station` | `op_snatch` command-5 |
| 8 | Latest operation + objective | **UNSOLVED** | — |

**Prior-room carryover that solved flag 1 outright:** Bottle Out recovered the same self-signed certificate from `Cert_store\DL20CMLRBAODGIIY` on the wiped laptop. The four SANs matched the live server exactly. Verified before submitting — 15 seconds, and the note said the cert came off a different scenario's disk image.

---

## 0. How the flags were obtained

1. `openssl s_client -starttls xmpp -xmpphost murknet.htb` → SAN list → flag 1.
2. `spurio9@murknet.htb` / `spur999!*` (from Bottle Out) → SASL `<account-disabled/>`. **Not a wrong password** — the account is deliberately dead.
3. Stream features advertise `<register xmlns='http://jabber.org/features/iq-register'/>` → in-band registration → own account → public rooms.
4. `disco#items` on `groups.murknet.htb` → four public rooms. `disco#info` on each → **display names**, which is what flag 2 wants.
5. `resources` room: *"imagine leaking your damn username through a pdf"* → `exiftool` on every uploaded PDF → `Operational_Onboarding_Guide_v3.2.pdf` carries `Creator: swissclock`, `Author: zytglogge88@murknet.htb`.
6. `infra` room: rattlesnake pastes four historical temp passwords; doctor orders immediate rotation; swissclock answers *"will do soon."* `TickTock24!` still works for `zytglogge88` → flag 3.
7. Re-auth as zytglogge88 → **two private MUCs appear**: `op_snatch`, `op_sparkling`.
8. `command.murknet.htb` = "Murknet Command Dispatcher" → PubSub nodes `op_snatch` and `op_sparkling`, items are `U2FsdGVkX1` blobs.
9. `op_sparkling` chat names a threat-intel blog, rattlesnake says he *"nuked it"*, doctor answers *"nothing is ever truly deleted once enough eyes have seen it"* → Wayback → the report contains `decrypt_command.sh` with hard-coded key `BLACKFENLOTTE`, and the `@porlock` profile → flag 4.
10. `BLACKFENLOTTE` opens `op_sparkling` → flag 5.
11. `op_snatch` does **not** open with it. RSM-paged 1:1 MAM archive → rattlesnake DM: *"The new key is SHALLOWBLUE"* → `op_snatch` opens → flags 6, 7.

---

## 1. Shape of the challenge

No disk image, no capture, no triage tree. The evidence **is** a running service, and everything is reached by protocol, not by parsing. That is a first in this event.

```
22/tcp   OpenSSH 9.6p1
443/tcp  nginx 1.24.0  — decoy page, "Nothing remains but echoes"
5222/tcp XMPP client (STARTTLS)
5269/tcp XMPP server-to-server
5281/tcp Prosody HTTP, vhost-routed (400 on missing Host header)
```

Vhost behaviour on 5281 is itself evidence: `murknet.htb` and `upload.murknet.htb` return "Prosody is running!"; `groups.` and `command.` return **"Unknown host"** — they are XMPP components with no HTTP vhost. That distinction saved a wasted path sweep.

---

## 2. The client was the whole fight

Nearly half the session went to XMPP client tooling, and none of it was the puzzle.

| Attempt | Outcome |
|---|---|
| `pip install slixmpp` | PEP 668 externally-managed-environment |
| `apt install python3-slixmpp` | 404s — stale apt index |
| venv + slixmpp 1.17 | `xep_0363` needs `aiohttp`; `ClientXMPP.process()` removed in 1.17 |
| `apt install gajim` | 404 cascade, same stale index |
| stdlib socket + ssl, raw XML | **worked first try** |

**Rule:** on a stale Kali, `sudo apt update` before any install, and for XMPP prefer a ~120-line stdlib client over a library. Raw stanzas over `ssl.wrap_socket` are simpler than any binding, log every byte to a file for grepping, and have no version drift. The dumper is in `evidence/`.

Corollary already in the event method: `needrestart`'s "daemons using outdated libraries" dialog will offer `lightdm.service` and `dbus.service`. Restarting either kills X and every terminal mid-room.

---

## 3. Registration is the intended entry, not a bypass

`<account-disabled/>` on the carried-over credential is a designed signal. The stream features advertise in-band registration in the same response that rejects the login:

```xml
<stream:features>
  <register xmlns='http://jabber.org/features/iq-register'/>
  <mechanisms><mechanism>PLAIN</mechanism>…</mechanisms>
```

`<iq type='set'><query xmlns='jabber:iq:register'><username/><password/></query></iq>` → account. The onboarding PDF confirms this is the documented member workflow: *"Register a new account. Join and read the #rules channel. Wait to be added to the operation channels to which you belong."*

Later probe: registering 15 nickname-shaped usernames (`doctor`, `colonel`, `rattlesnake`…) all returned `type='result'`, i.e. **created**, not `conflict`. The chat aliases are not account names — real JIDs follow `word+digits` (`zytglogge88`, `snake6288`, `spurio9`). No user enumeration available.

---

## 4. Flag 2 — the answer is the display name

`disco#items` returns JIDs; `disco#info` returns identities. The question asks for *names*, and the hint is `(string,string,string,string)` — not `(fqdn,…)`.

```
<item name='Infrastructure' jid='infra@groups.murknet.htb'/>
<item name='Random'         jid='random@groups.murknet.htb'/>
<item name='Resources'      jid='resources@groups.murknet.htb'/>
<item name='Rules'          jid='rules@groups.murknet.htb'/>
```

`infra,random,resources,rules` was submitted first and rejected. **The hint's field type told us which of the two renderings to use** — §3.11 of the event MOC, applied correctly for once.

---

## 5. Flags 3 & 4 — the credential chain

Two independent OPSEC failures, each planted in a public room and each flagged in dialogue:

- `resources`: *"clean metadata?" / "checked twice" / "imagine leaking your damn username through a pdf"* → run `exiftool` on every upload.
- `infra`: rattlesnake pastes `KillBill2025! K4w4Bong424! Northwind225! TickTock24!`; doctor: *"everyone who ever received one of those passwords rotates it NOW!"*; swissclock: *"will do soon"*; doctor: *"not 'soon'. NOW!"*

swissclock is `zytglogge88` (Bern's Zytglogge clock tower — the alias and the JID encode the same referent). `TickTock24!` is the thematically matching password and the one that worked. Four candidates, testable in 30 seconds.

Flag 4 came from the Wayback copy of the report rattlesnake deleted. The answer mask `*****://************.***/********` resolves cleanly: `https` / `stonedforums` (12) / `htb` (3) / `@porlock` (8). **The mask was sufficient to validate the answer before submitting.**

---

## 6. The dispatcher — `command.murknet.htb`

MOC open thread #1 is closed. `command.murknet.htb` is a PubSub service, identity `Murknet Command Dispatcher`, with one node per operation:

```
node op_snatch     — pubsub#description "OpSnatch Command Dispatcher"    — 10 items
node op_sparkling  — pubsub#description "OpSparkling Command Dispatcher" —  8 items
```

Items are `<command-N xmlns='urn:murknet:command'>` carrying base64 `Salted__` blobs. This is the "usual source" / "alternate route" referenced constantly in chat and formalised in Rule IX: *"If an instruction is meant to be acted upon, it will arrive by another route."*

**Node visibility is not affiliation-gated.** A brand-new throwaway account sees both nodes and can read both. Tested explicitly — this is how we ruled out a hidden third operation.

### Per-node keys, not a rotation timeline

| Node | Key | KDF |
|---|---|---|
| `op_sparkling` | `BLACKFENLOTTE` | PBKDF2, 120 000 iterations, SHA-256 |
| `op_snatch` | `SHALLOWBLUE` | same |

Both keys are `openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256`, and the leaked `decrypt_command.sh` base64-decodes **before** invoking openssl — so no `-a` flag.

`BLACKFENLOTTE` is the leaked key from the archived report. `SHALLOWBLUE` is the replacement, announced in a 1:1 DM: *"The decryptor itself isn't the important part. We're rotating the key. The new key is SHALLOWBLUE."*

---

## 7. MAM paging — the mistake that cost the most

The DM carrying `SHALLOWBLUE` is on **page 1** of a four-page archive. A bare `urn:xmpp:mam:2` query returns one page and the server sent **no `complete=` attribute at all** on the MUC archives.

```xml
<iq type='set' id='mp0'><query xmlns='urn:xmpp:mam:2' queryid='p0'>
  <set xmlns='http://jabber.org/protocol/rsm'><max>50</max><after>LAST-UID</after></set>
</query></iq>
```

Loop on `<last>` until `complete='true'`. Paged properly:

- 1:1 archive: 4 pages → the `SHALLOWBLUE` DM
- `op_sparkling`: 7 pages (355 lines was **one page**)
- `op_snatch`: 6 pages

**Rule for the MOC:** *before submitting anything derived from a paged protocol, verify the paging terminated.* Flag 8 was attacked from an incomplete archive for six submissions before this was checked.

---

## 8. `op_snatch` decrypted — flags 6 & 7

```
command-1   Operation started
command-2   Watson just left his house and got into his car: a red Ford Fiesta,
            license plate WT609DXT
command-3   He just stopped at Pembridge Square
command-4   Watson got back in the car and turned onto Bayswater Road.
            Stay right on his heels!
command-5   He's about to enter Victoria Station. He must not reach the tracks. Act NOW
command-6   Heading toward Silvertown, here are the coordinates:
            51°30'17.6 N, 0°02'05.1 E
command-7   Avoid Great Dover Street, it's full of police officers because of a demonstration
command-8   Sector B. Row 6. Container number: 75JM77. Watchword: Chaos Is Order
command-9   Take the car to the junkyard. The junkyard is in Walton-on-Thames.
            Ask for Richard.
command-10  Start cleanup process IMMEDIATELY
```

**Flag 7 cost three wrong submissions to a question I misread.** "Where has Watson been kidnapped" is the *abduction point* (command-5, Victoria Station), not the *holding site* (command-8, container 75JM77). `75JM77`, the full container string, and a normalised form were all submitted first.

Flag 6: colonel assigns *"Dynamite handles transport. Spur handles custody after delivery."* dynamite announces *"I'm starting the operation now"*, goes dark for an hour, returns with *"Delivery completed without problems."* spur receives the package afterward. The kidnapper is **dynamite**; spur is the jailer, and spur is Bottle Out's Abel Stokes.

---

## 9. `op_sparkling` decrypted — flag 5 and the IOC set

```
command-1  Operation started
command-2  Evilginx server available at 185.203.11.109 — Use ONLY this server for phishing
command-3  BTC: 1BfQc4twbZrUSrtKdwW8TtSN6o1SUezWkX
                1BcanTJpHtyNnRvPFpuTqGwN1BcxuXKGpN
                1BHoNZGGAkpLaNmVHbYdnoyib8NgodSkRD
command-4  XMR: 429x3WVq1uc…7uwye
command-5  Bank account credentials must be sent here https://submit-creds.murknet.htb:9099
command-6  New C2 server for BalanceRAT 34.54.165.186
command-7  Disposable numbers: 447348624600 447424907088 447459603196 447424061435
command-8  Phishing domains: micr0soft-st0re.com update-vpn.azzure.com mailservice-gmail.com
```

`1BfQc4twbZrUSrtKdwW8TtSN6o1SUezWkX` also appears in the archived report's IOC table as the campaign's Bitcoin wallet — an independent confirmation that the blog and the dispatcher describe the same operation.

---

## 10. The archived report

`http://security.billblog.co.uk/threat/BalanceRAT-analysis-and-attribution`, dead live, recovered via:

```
http://archive.org/wayback/available?url=security.billblog.co.uk/threat/BalanceRAT-analysis-and-attribution
→ http://web.archive.org/web/20260805080606/…
```

A full Northbridge-branded threat report on **BalanceRAT** / campaign **Ghost Balance**, attributing to the alias **Porlock**. Two things matter operationally:

1. §"More artifacts" ships `decrypt_command.sh` verbatim with `KEY='BLACKFENLOTTE'`.
2. §9 "Final OSINT pivot" gives `https://stonedforums.htb/@porlock` → flag 4.

The in-story deletion is the hint. doctor's *"you've solved a symptom, not the problem… don't confuse removal with disappearance"* is the room telling the analyst to go to the archive.

---

## 11. Timeline

| Order | Operation | Node key | Evidence |
|---|---|---|---|
| 1st | **Sparkling** — financial collection via BalanceRAT | `BLACKFENLOTTE` (leaked, pre-rotation) | flag 5 accepted as "first operation" |
| 2nd | **Snatch** — abduction of Watson | `SHALLOWBLUE` (post-rotation) | rotation announced during Sparkling |

The key rotation orders the two operations independently of any timestamp, and flag 5's grading confirms Sparkling is first.

---

## 12. Flag 8 — unsolved, and the full list of failures

**Question:** *"What is the name of the latest operation that the APT is planning, and what is its objective? (Operation name,Objective)"*

Every string submitted:

| Name half | Objective half | Result |
|---|---|---|
| `Sparkling Op` | full doctor line | wrong |
| `Operation Sparkling` | full doctor line | wrong |
| `op_sparkling` | — | wrong |
| `Sparkling Op` | — | wrong |
| `op_snatch` | — | wrong |
| `snatch` | — | wrong |
| `Sparkling` | full doctor line | wrong |
| `Operation Sparkling` | `collect wallet material and online banking credentials` | wrong |
| `Operation Sparkling` | `identify worthwhile victims` | wrong |
| `Operation Sparkling` | `identify worthwhile victims and collect wallet material and online banking credentials` | wrong |
| `OpSparkling` | full doctor line | wrong |
| `Operation Sparkling` | `Financial access` | wrong |
| `Operation Sparkling` | `self-funding` | wrong |
| `Operation Sparkling` | `collect wallet material and online banking credentials to fund other operations` | wrong |
| `Sparkling` | `Financial access` | wrong |
| `Operation Sparkling` | `steal cryptocurrency wallets and banking credentials` | wrong |
| `op_sparkling` | full doctor line | wrong |
| `Operation Snatch` | `Kidnap Watson` | wrong |
| `Operation Snatch` | `kidnapping` | wrong |
| `Operation Snatch` | `Kidnap Dr. Watson` | wrong |

"full doctor line" = `identify worthwhile victims collect wallet material online banking credentials and anything that can later be exchanged for funding` — the only objective statement in evidence, `op_sparkling` message 3, verbatim, no punctuation.

### Everything enumerated and ruled out

- Six MUC rooms, no seventh. Confirmed from `rinfo.xml` and `cmd_raw.xml`.
- Two PubSub nodes, no third. Confirmed from a throwaway account — visibility is not affiliation-gated.
- All three MAM archives paged to `complete='true'`.
- 18 dispatcher commands, all decrypted.
- `file_share` has no directory index; every uploaded URL in the full 599-line archive was fetched; only five PDFs exist.
- `disco#info` on all six rooms for `roomname` / `roominfo_description` — both give `Operation Sparkling` and `Operation Snatch`.
- vCards empty. Dispatcher does not support MAM. `pubsub#owner configure` denied.
- 15 nickname-shaped usernames all registrable, so no account enumeration.

### Every rendering of each name that exists in evidence

| Operation | Renderings |
|---|---|
| Sparkling | `op_sparkling` (JID), `Sparkling Op` (doctor, chat), `Sparkling` (DM), `Operation Sparkling` (`disco` identity + `roomconfig_roomname` + `roominfo_description`), `OpSparkling` (`pubsub#description`) |
| Snatch | `op_snatch` (JID), `Operation Snatch` (`disco` identity + `roomconfig_roomname` + `roominfo_description`), `OpSnatch` (`pubsub#description`) |

### Where the reasoning went wrong

1. **Submitted from an incomplete archive.** The MUC MAM returned no `complete=` attribute on the first dump and 355 lines were treated as the whole room. Six submissions were spent before paging was verified.
2. **Treated `(Operation name,Objective)` as a specifying hint.** It names two fields but specifies the form of neither — the same trap as the bare-`(string)` corollary in MOC §3.11. That should have capped submissions at two or three pending new evidence. It got twenty.
3. **Misread `item-not-found` as proof of absence.** Prosody returns `item-not-found` rather than `forbidden` for unaffiliated nodes precisely to avoid disclosure, so the node-guessing probe proved nothing. The throwaway-account test was the one that actually settled it, and it came much later.
4. **Anchored on Sparkling for too long**, then over-corrected to Snatch, both times generating permutations instead of finding a new artifact. Once the name was verified from two server-side sources and the objective had exactly one source sentence, the correct move was to stop and seek evidence, not to enumerate phrasings.

### Leads for a re-attempt

- `OpSnatch` and `OpSparkling` (the `pubsub#description` forms) were never paired with an objective.
- The `op_snatch` room never states an objective in words — doctor deflects with *"The objective has value far beyond what most of you understand."* If Snatch is the intended answer, the objective may come from the scenario PDF's post-solve content rather than from the server.
- Untested: whether the grader splits on the first comma only, which would make a comma-bearing objective parse differently.

---

## 13. Blind alleys — eliminated, do not re-walk

1. **The `random` room's abandoned textile factory.** Lights at night, a white van, tunnels, "somebody is squatting there", and doctor closing it down with *"it's just an abandoned building."* Reads exactly like a planted holding site. It is scenery — cost three submissions on flag 7.
2. **`75JM77` as the kidnapping location.** It is the *holding* container, not where Watson was taken.
3. **`spur` as the kidnapper.** He is the jailer. dynamite drives.
4. **Guessed PubSub node names** (`op_final`, `op_reichenbach`, `op_endgame`, …) — all `item-not-found`, which as noted is not evidence either way.
5. **Cracking `op_snatch` with a chat-derived wordlist** before finding `SHALLOWBLUE`. The key was in an unpaged MAM page, not in anything guessable.
6. **`file_share` directory listing.** Prosody serves by UUID only; no index exists.

---

## 14. Tools & techniques

| Need | Tool |
|---|---|
| TLS SANs over XMPP | `openssl s_client -starttls xmpp -xmpphost <vhost>` |
| Service map | `nmap -sV -p- --min-rate 2000` |
| Vhost behaviour on Prosody HTTP | `curl -sk -H 'Host: <vhost>' https://IP:5281/` |
| XMPP client | ~120-line stdlib `socket` + `ssl` raw-stanza dumper (in `evidence/`) |
| PDF metadata | `exiftool` |
| PDF text | `pdftotext -layout` (`poppler-utils`) |
| Deleted web content | `archive.org/wayback/available?url=` then `web.archive.org/web/<ts>/` |
| CryptoJS/OpenSSL blobs | `openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256` |

Useful discriminator: `U2FsdGVkX1` is base64 `Salted__`. If `-md md5` with no `-pbkdf2` fails, try PBKDF2 — and check whether the source script base64-decodes before calling openssl, which decides the `-a` flag.

---

## 15. MITRE ATT&CK

| Tactic | Technique | Behaviour |
|---|---|---|
| Command and Control | T1071.001 · Web Protocols | Dispatcher commands over XMPP PubSub |
| Command and Control | T1573.001 · Symmetric Cryptography | AES-256-CBC per-node command encryption |
| Credential Access | T1552.001 · Credentials In Files | Temp passwords pasted into a public MUC |
| Collection | T1213 · Data from Information Repositories | Operational tasking held in MUC archives and PubSub nodes |
| Initial Access | T1078 · Valid Accounts | Unrotated temp password on `zytglogge88` |
| Reconnaissance | T1589.001 · Gather Victim Identity: Credentials | Alias-to-account pivot via PDF metadata |

> [!note] Caveat
> IDs assigned without access to the live ATT&CK matrix. T1213 is the weakest — the "repository" is a chat archive, which the technique covers only loosely.

---

## 16. Detection / blue-team notes

- **In-band registration on a production XMPP server is the whole intrusion path here.** `mod_register` open to the internet turns a stale credential into full internal chat access. Disable it or gate it behind an invite token.
- **MUC display names and `roominfo_description` leak operational context to anyone who can `disco`.** A room named `op_snatch` with the description `Operation Snatch` is readable metadata even before membership.
- **PubSub nodes were readable by an unaffiliated throwaway account.** Node access model should be `whitelist`/`publishers`, not open.
- **PDF metadata survives every upload.** `Creator` and `Author` fields tied an alias to an account in one step.
- **Deleting a published report does not retract it.** The in-story lesson is the real one: assume archive coverage.

---

## 17. Open items

1. **Flag 8** — see §12. The objective string is the unknown; the name is server-verified for both operations.
2. **`snake6288@murknet.htb` (rattlesnake)** — his account did not accept any of the four leaked temp passwords. If he rotated, the four-password list is exhausted; if there is a fifth credential path, it was not found.
3. **`dang`** — appears in `infra` and `random`, in neither operation room. Unexplained affiliate.
4. **`Watchword: Chaos Is Order`** (command-8) — never used for anything. Bottle Out's SAM hive recorded `UserPasswordHint: Chaos` for the `spur` account. Possibly a cross-room key that was never needed here.
5. **`submit-creds.murknet.htb:9099`** — never probed; not in the cert SANs and outside the scanned range for vhost testing.
6. **Walton-on-Thames junkyard, "ask for Richard"** — a named contact with no other appearance in this event.
7. **`command-11` onward** — the dispatcher was read once. If the box publishes further commands over its uptime, a later fetch could differ.

---

## Cross-references

- [[00_MOC-HTB-Holmes2026-Reichenbach-Directive-Event]] — event index; this room closes its §6 open thread 1 (`command.murknet.htb`)
- [[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]] — Sherlock 02; **same server.** Supplied the TLS certificate that answered flag 1 outright and the burned `spurio9` account; `spur` is this room's jailer
- [[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]] — Sherlock 04; Silvertown appears in both
- [[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]] — Sherlock 01
- [[HTB-Holmes2026-Poisoned-Branch-Backdoored-Git-Repo-XOR-Mettle-ZipCrypto]] — Sherlock 05
- [[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]] — Sherlock 07
- [[HTB-Holmes2026-Borrowed-Name-AdaptixC2-RC4-Profile-Key-ResetNightmare]] — Sherlock 08
- [[HTB-Holmes2026-Last-Light-Golden-Tickets-RBCD-Unflushed-EVTX-Carve]] — Sherlock 09; supplies the MOC §4 class 7 rule (stop permuting a rejected cluster) that §12 of this note fires on
- [[00_ctf-writeup-standard]] — structure this note conforms to
- [[HTB]]

---

## Change Log

- 2026-09-21 — Note created after Whisper Chain (Sherlock 03, medium, 975, **7/8**). §12 records all twenty flag-8 submissions and four reasoning failures verbatim, per the event's format-not-content taxonomy. Closes MOC open thread #1 (`command.murknet.htb` = PubSub dispatcher). New cross-room evidence join: `op_snatch` command-6 places Watson at Silvertown (51°30'17.6"N, 0°02'05.1"E), tying Bottle Out's chapter text and Paper Ghost's contractor delivery address to a dispatcher artifact. `status: closed` per `02_frontmatter-standard` §1 — engaged, documented, one flag unsolved, and not resumable (event closed, instance expired); contrast Last Light's `draft`, which is resumable per its §16. `created` stamped from a real fetched UTC clock (container clock, not the vault host's). `updated` omitted per `02_frontmatter-standard` §1 (plugin-owned, not hand-stamped). `difficulty`/`points` from the challenge page; `solves` omitted; `category: forensics` carried forward unverified as in sibling notes.

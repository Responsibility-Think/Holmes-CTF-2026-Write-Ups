# Holmes CTF 2026 — Write-Ups

Write-ups from **Hack The Box Holmes CTF 2026: The Reichenbach Directive**, a blue-team event (17–21 September 2026).

Each note documents the full method, not just the solve path — the reasoning that led nowhere, the negative results worth proving, and the wrong submissions with the reason each one was made. Where a room went incomplete, the write-up says so and records how far it got.

Nine Sherlocks, all DFIR. **Result: 225th of 5,637 teams · 7,800 points · 97 of 111 flags** — played solo as `Project_Hydra_Strike`.

---

## Index

### Sherlocks

| # | Challenge | Difficulty | Points | Flags | Focus | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 01 | [Silent Dividend](HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle.md) | medium | 800 / 800 | 10 / 10 | Electron Preload Dropper Onchain Key Oracle | Solved |
| 02 | [Bottle Out](HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM.md) | — | 1000 / 1000 | 10 / 10 | Wiped Laptop Gajim XMPP TacticalRMM | Solved |
| 03 | [Whisper Chain](HTB-Holmes2026-Whisper-Chain-Live-XMPP-PubSub-Dispatcher-PerNode-AES.md) | medium | 850 / 975 | 7 / 8 | Live XMPP PubSub Dispatcher PerNode AES | **Partial** |
| 04 | [Paper Ghost](HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery.md) | easy | 950 / 950 | 9 / 9 | Planted USB Spyware Search Index Recovery | Solved |
| 05 | [Poisoned Branch](HTB-Holmes2026-Poisoned-Branch-Backdoored-Git-Repo-XOR-Mettle-ZipCrypto.md) | medium | 1000 / 1000 | 15 / 15 | Backdoored Git Repo XOR Mettle ZipCrypto | Solved |
| 06 | [Silent Passenger](HTB-Holmes2026-Silent-Passenger-MQTT-Push-Update-Staged-Dex-Loader-PARTIAL.md) | hard | 500 / 1000 | 10 / 20 | MQTT Push Update Staged Dex Loader | **Partial** |
| 07 | [Iron Feather](HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF.md) | hard | 1000 / 1000 | 17 / 17 | PX4 Encrypted Dataman ULog Custom KDF | Solved |
| 08 | [Borrowed Name](HTB-Holmes2026-Borrowed-Name-AdaptixC2-RC4-Profile-Key-ResetNightmare.md) | insane | 1000 / 1000 | 12 / 12 | AdaptixC2 RC4 Profile Key ResetNightmare | Solved |
| 09 | [Last Light](HTB-Holmes2026-Last-Light-Golden-Tickets-RBCD-Unflushed-EVTX-Carve.md) | insane | 700 / 1000 | 7 / 10 | Golden Tickets RBCD Unflushed EVTX Carve | **Partial** |

### Event method

| Note | Content |
| --- | --- |
| [The Reichenbach Directive — Event MOC](00_MOC-HTB-Holmes2026-Reichenbach-Directive-Event.md) | Cross-room narrative, twelve transferable method rules, a failure taxonomy of the event's wrong submissions, and a toolchain by artifact class |

---

## Notes

- **Points** are the final scoreboard values, earned / available. HTB scores dynamically, so a few notes record a different value at solve time (Silent Dividend shows 975 → 800; Paper Ghost records 975 against a final 950).
- **Partial** here means the room was flagged, but not completely — some questions were answered and accepted, others were not. This differs from the Cyber Apocalypse 2026 repo, where Partial meant worked but never flagged. Each partial write-up records the unsolved questions, every rejected submission, and where the reasoning stalled.
- Every room is question-graded; no `HTB{}` string exists in any of them. Answers are published because the event has closed.
- **Difficulty** for Bottle Out was not captured from the platform and is shown as `—`.
- The notes are published as written in an Obsidian vault. `[[wikilinks]]` and callouts render as plain text on GitHub, and links to notes outside this set (`HTB`, `00_ctf-writeup-standard`, the technique notes) point into the vault, not into this repo.
- MITRE ATT&CK mappings appear in every note's frontmatter. Several are explicitly flagged as weak or unverified in the note; treat them as working hypotheses rather than citations.

## Use

Licensed CC BY 4.0 — reuse freely with attribution. Challenge names, prose, and artefacts remain the property of Hack The Box.

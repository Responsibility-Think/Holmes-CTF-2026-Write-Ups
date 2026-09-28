---
type: writeup
title: "HTB Holmes 2026 — Iron Feather: PX4 Encrypted Dataman/ULog, Custom KDF, MAVLink Failure Injection"
platform: Hack The Box
event: "Holmes CTF 2026: The Reichenbach Directive"
challenge: Iron Feather
category: forensics
subcategory: sherlock-dfir
difficulty: hard
points: 1000
status: complete
app: "IronFeather.zip — 71 MB: stripped PX4_SITL ELF (9.8 MB, static OpenSSL), dataman.encrypted (1.15 MB), flight.ulg.encrypted (65.6 MB), story PDF"
mitre:
  - T1027
  - T1588.002
  - T0855
  - T0831
  - T0827
  - T0879
tags:
  - writeup
  - HTB
  - Security
  - DFIR
  - Incident_Response
  - forensics
  - Reverse_Engineering
  - Cryptography
related:
  - "[[HTB]]"
  - "[[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]]"
  - "[[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]]"
  - "[[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]]"
aliases:
  - Iron Feather
  - Holmes 2026 Iron Feather
created: 2026-09-20T09:18:01.409Z
updated: 2026-09-20T09:18:01.409Z
---

# Iron Feather — PX4 Encrypted Dataman/ULog, Custom KDF, MAVLink Failure Injection

> [!success] Solved — 2026-09-20 05:05 (platform clock) · 17 of 17 flags
> **No `HTB{}` string exists for this room** — it is question-graded. Sherlock 07 of the event · hard · 1000 points.
> The room is two challenges bolted together: **recover an AES-256-GCM key from a stripped binary by reimplementing a 384-round custom mixing function**, then **do UAS flight-record forensics on the decrypted PX4 artifacts**.

> [!info] Scenario, verbatim
> SCENARIO NAME
> 7 - Iron Feather
> The story will unfold through the PDFs provided with each challenge's downloadable ZIP.
>
> All characters, locations, and events are fictional. Any resemblance to real people, places, or events is purely coincidental.
>
> **Supplied artifact:** `IronFeather.zip` → `Holmes CTF 2026 - Sherlock 07 - Mission Vault.pdf`, `px4`, `dataman.encrypted`, `flight.ulg.encrypted`. Unlike Bottle Out, the evidence is in the download.

---

## Flags — Answers

| # | Question | Answer | Method |
|---|---|---|---|
| 1 | Eight-byte ASCII magic of the encrypted datastore | `PX4DMENC` | `movabs $0x434e454d44345850,%rax` at `0x16ff1e` |
| 2 | Authenticated encryption algorithm | `AES-256-GCM` | `EVP_aes_256_gcm` at `0x1700e0` |
| 3 | RVA of the custom key-derivation function | `0x170af0` | `call 170af0` from the decrypt path at `0x1700c6` |
| 4 | Rounds in the custom 32-bit mixing loop | `384` | `cmp $0x17f,%edx; jne` with counter starting at 0 |
| 5 | Standard KDF producing the AES key | `PBKDF2-HMAC-SHA256` | `PKCS5_PBKDF2_HMAC(…, 8192, EVP_sha256(), 32, …)` |
| 6 | AES-256 key for the supplied image | `a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce` | KDF reimplemented in Python; GCM tag verifies |
| 7 | Active mission bank | `0` | `mission_s.mission_dataman_id = 6` = `DM_KEY_WAYPOINTS_OFFBOARD_0` |
| 8 | Mission items in the active bank | `24` | 24 × 60-byte slots from offset 8472; `mission_result.seq_total` |
| 9 | Mission item triggering payload release | `10` | `DO_SET_ACTUATOR` (187) with `param1 = 1.0` |
| 10 | Intended landing point | `51.49970,-0.16080` | mission item 23, `NAV_LAND` (21) |
| 11 | Takeoff point | `51.4996987,-0.1607999` | `vehicle_global_position` at `landed`→false, 287.072 s |
| 12 | Position at payload release | `51.5035602,-0.1608417` | `vehicle_global_position` at 446.656 s |
| 13 | Injected MAVLink command | `MAV_CMD_INJECT_FAILURE` | `vehicle_command` id 420, `src_sys=0 src_comp=0` |
| 14 | Distance, release → injection | `277` | ground-track length, `vehicle_local_position` NE |
| 15 | Crash site | `51.5016938,-0.1620929` | `vehicle_global_position` at impact, 525.85 s |
| 16 | Disarm after the crash | `576.968` | `actuator_armed.armed` 1→0; `vehicle_status.arming_state`→1 |
| 17 | Road closest to the crash site | `Knightsbridge` | crash falls between 153 and 100 Knightsbridge |

All times are **seconds since boot**, as stored in the ULog. `time_ref_utc = 0`, so no wall-clock mapping exists in the log; the logger filename says `2026-09-10/09_50_55.ulg` and that is the only date reference.

---

## 0. How the flags were obtained

1. Unpacked `IronFeather.zip` — **four files, and three of them are evidence.** Read the PDF (chapters 09–10; narrative only, no technical hint).
2. Hex-dumped both `.encrypted` files. Identical 16-byte field at offset `0x10` in both → shared salt → **one key decrypts both.**
3. `strings`/byte-grep for `PX4DMENC` → two hits at `0x16ff20` and `0x170444`, both **inside `.text`** as `movabs` immediates, not in `.rodata`. Binary is stripped but exports OpenSSL symbols via `.dynsym`.
4. Byte-scanned `.text` for `E8` rel32 calls to `PKCS5_PBKDF2_HMAC` (`0x32e830`) and `EVP_aes_256_gcm` (`0x326100`). One PBKDF2 call site: `0x170d74`. That located the KDF function.
5. Disassembled `0x170af0`–`0x170db4`. Read the argument marshalling off the register moves: **PBKDF2-HMAC-SHA256, 104-byte password, 16-byte salt, 8192 iterations, 32-byte output.** The password is built entirely from constants — **the salt is the only input.**
6. Transcribed the 384-round ARX mixing loop instruction-by-instruction into Python, pulled the four constant tables out of `.rodata`, and reproduced the 32-byte prefix of the password.
7. Read the decrypt routine at `0x16fe20` for the container layout. **The GCM tag is at offset 44, not at the end of the file**, and the AAD is the first 44 bytes.
8. Decrypted both files. **GCM tag verified on both** — that single check retroactively certified flags 2, 3, 4, 5 and 6.
9. Recovered the dataman key-region table from `.rodata` (`0x6f09a0` sizes, `0x6f0a00` counts) and used it to locate bank 0 at file offset 8472 and the mission state at 1208472.
10. Parsed the 24 × 56-byte `mission_item_s` records and the 40-byte `mission_s`.
11. Parsed the ULog with `pyulog`, filtered to 16 topics, and read every answer off a logged **event instant** rather than a convenient sample.

---

## 1. Shape of the challenge

Two disciplines in series, with a hard gate between them. Nothing in the flight-forensics half is reachable until the crypto half is finished, and the crypto half has no partial credit — the key is right or the tag fails.

| Stage | Artifact | Discipline |
|---|---|---|
| Container | `PX4DMENC` / `PX4ULENC` headers | format reversing |
| Key | `0x170af0`, 384-round mixer + PBKDF2 | static RE, algorithm reimplementation |
| Mission plan | `dataman.bin`, `mission_item_s` × 24 | PX4 storage-layout knowledge |
| Flight record | `flight.ulg`, 87 uORB topics | ULog / MAVLink forensics |
| Ground truth | London street geography | OSINT / geolocation |

The structural fact that makes this room hard: **the key is not in the evidence, it is in the tool that wrote the evidence.** The operator shipped the firmware image alongside the encrypted stores, which is the same mistake pattern as Silent Dividend's on-chain key oracle — protection applied to the data, not to the thing that unlocks it.

---

## 2. Container format

Both files share one 60-byte header. Layout, read off the decrypt routine at `0x16fe20`:

```
offset  size  field
0x00       8  magic          "PX4DMENC" / "PX4ULENC"
0x08       4  version        1
0x0c       4  plaintext_len  little-endian uint32
0x10      16  salt           IDENTICAL in both supplied files
0x20      12  GCM nonce      per-file
0x2c      16  GCM tag        <-- NOT at end of file
0x3c     ...  ciphertext     plaintext_len bytes
```

`file_size = 60 + plaintext_len` for both files, which is the quickest structural confirmation.

AAD is `header[0:44]` — the decrypt routine calls `EVP_DecryptUpdate` with `out = NULL`, `inl = 0x2c` before feeding ciphertext:

```asm
1702d7:  lea    0x28(%rsp),%rdx        ; outl
1702dc:  xor    %esi,%esi              ; out = NULL  -> AAD mode
1702de:  mov    $0x2c,%r8d             ; inl = 44
1702e4:  mov    %r14,%rcx              ; in  = header buffer
1702ef:  call   EVP_DecryptUpdate
```

> [!note] `PX4ULENC` is not in the binary
> Byte-grep finds `PX4DMENC` twice and `PX4ULENC` zero times. The shipped `px4` only implements the dataman container; the ULog was encrypted by a tool that was not supplied. **This does not matter** — the salt is shared, so the key derived from the dataman header decrypts the ULog too. The absence of the string is an argument for reading the format off the *file*, not the binary.

---

## 3. The custom KDF — flags 3, 4, 5, 6

Function at **`0x170af0`**, signature `bool derive_key(const uint8_t *salt16, uint8_t *out32)`. RVA equals file offset throughout this binary (`.text` is at vaddr `0x110000`, file offset `0x110000`).

Three phases:

**Phase 1 — 384-round ARX mix over a fixed 8×uint32 state.**

Initial state, from `0x6edf80` (32 bytes), is ASCII read as little-endian dwords: `meta stor age- v1.0 xP4- sitl posi x-dm`. Constants in registers on entry: `0x9e3779b9` (golden ratio, decremented by `0x61c88647` each round), `0xde3814a6`, `0x8de43612`, `0x0b`.

Three lookup tables in `.rodata`:

| Address | Size | Use |
|---|---|---|
| `0x6f0a40` | 48 bytes | rotate-count source, indexed `(x + i) mod 48` |
| `0x6f0a80` | 32 × u32 | `T_bx` |
| `0x6f0b00` | 32 × u32 | `T_bp` |

The loop terminator is `cmp $0x17f,%edx; jne 170ba0`, with the counter entering at 0 and the first iteration jumped into mid-body at `0x170c02`. Counter runs 0..383 → **384 rounds**. The `0x17f` is the tempting wrong answer.

Two divisions are done by magic-multiply and must be replicated exactly, not approximated: `mul 0xaaaaaaaaaaaaaaab; shr $5` is `mod 48`, and `imul $0x6bca1af3; sar $35` is `div 19` (the rotate count is `(i mod 19) + 1`).

**Phase 2 — extraction into the password buffer.** Eight dwords: `buf[0] = s[0] ^ 0x33020b01`, then for `k = 1..7`, `buf[k] = T_bp[(0x10 + 7(k-1)) & 0x1f] ^ s[k] ^ rol32(T_bx[(0x11 + 13(k-1)) & 0x1f], k+1)`.

**Phase 3 — 72 bytes of literal constants appended**, from `0x6edfa0` (64 bytes) plus `movabs $0x6fb14a9923de7508`. Password is 104 bytes total; **only the first 32 are computed, and none of it depends on the salt.**

Then:

```asm
170d50:  call   EVP_sha256
170d55:  push   %r14                   ; out   = arg1
170d57:  mov    $0x2000,%r8d           ; iter  = 8192
170d5d:  mov    %r15,%rdi              ; pass
170d60:  push   $0x20                  ; keylen = 32
170d62:  mov    0x18(%rsp),%rdx        ; salt  = arg0
170d6a:  mov    $0x10,%ecx             ; saltlen = 16
170d6f:  mov    $0x68,%esi             ; passlen = 104
170d74:  call   PKCS5_PBKDF2_HMAC
```

Derived password (constant for this build):

```
696a8765f43ab74975728e713ecdd6d21cff4e65ae186769e854709fd0b61c87
7413d92ea8650cf13b9742cd58e6218ab40f73da369c51e217e249832cb5610e
d8349f7205c15aed6813a74df02b965ebc410ad37f25e98456ab30c71d926bf4
0875de23994ab16f
```

Salt `60c200309e3f464c11d14645a355bfe8` → key `a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce`.

> [!important] The AEAD tag is a free correctness oracle
> GCM verification succeeding on **both** files proves the entire chain at once: the right function (`0x170af0`), the right round count (384), the right KDF and parameters, and the right cipher. Four question-graded flags went from *inferred* to *proved* with one check, before any of them was submitted. **When an artifact contains an authenticated construction, reimplement rather than merely read — the tag turns reverse-engineering into a pass/fail test.**

---

## 4. Dataman layout — flags 7, 8

`dataman.bin` is 1,208,528 bytes and is **99.7% zeros**. Six non-zero runs. The layout is not guessable from the data; it comes from two tables in `.rodata`:

```
0x6f09a0  size_t per_item_size[10] = {60,60,12,36,36,12,60,60,44,12}
0x6f0a00  uint32 g_key_sizes[10]   = {32,32, 1,64,64, 1,10000,10000,1,1}
```

Ten keys is the PX4 v1.15 enumeration. Cumulative offsets reproduce the file exactly:

| Key | Enum | Count × slot | Offset range |
|---|---|---|---|
| 0 | `DM_KEY_SAFE_POINTS_0` | 32 × 60 | 0 – 1,920 |
| 1 | `DM_KEY_SAFE_POINTS_1` | 32 × 60 | 1,920 – 3,840 |
| 2 | `DM_KEY_SAFE_POINTS_STATE` | 1 × 12 | 3,840 – 3,852 |
| 3 | `DM_KEY_FENCE_POINTS_0` | 64 × 36 | 3,852 – 6,156 |
| 4 | `DM_KEY_FENCE_POINTS_1` | 64 × 36 | 6,156 – 8,460 |
| 5 | `DM_KEY_FENCE_POINTS_STATE` | 1 × 12 | 8,460 – 8,472 |
| 6 | `DM_KEY_WAYPOINTS_OFFBOARD_0` | 10000 × 60 | **8,472 – 608,472** |
| 7 | `DM_KEY_WAYPOINTS_OFFBOARD_1` | 10000 × 60 | 608,472 – 1,208,472 |
| 8 | `DM_KEY_MISSION_STATE` | 1 × 44 | 1,208,472 – 1,208,516 |
| 9 | `DM_KEY_COMPAT` | 1 × 12 | 1,208,516 – 1,208,528 |

Each slot is a 4-byte length header (`38 00 00 00` = 56) followed by the item. Bank 1 is entirely zero.

`mission_s` at `0x12709c`, 40 bytes, decoded against the observed values:

```
timestamp             500,000,128 us
current_seq           18            <- matches mission_result at end of flight
land_start_index      23
land_index            23
mission_id            0xE654B741    <- matches mission_result.mission_id = 3864311617
geofence_id           0
safe_points_id        0
count                 24            <- flag 8
mission_dataman_id    6             <- DM_KEY_WAYPOINTS_OFFBOARD_0, i.e. bank 0 -> flag 7
fence_dataman_id      4
safe_points_dataman_id 0
```

> [!warning] Flag 7 stores the key enum, not the bank index
> `mission_dataman_id` is **6**, because PX4 v1.15 stores the dataman key. The accepted answer is **`0`** — the question asks which of the *two banks* is active, and `DM_KEY_WAYPOINTS_OFFBOARD_0` is bank 0. Physical placement agrees: the 24 items start at offset 8,472, the first byte of key 6's region.

---

## 5. The mission — flags 9, 10

24 items, bank 0. Abridged:

| Seq | `nav_cmd` | Lat, Lon | Alt | Note |
|---|---|---|---|---|
| 0 | 22 `NAV_TAKEOFF` | 51.4997, -0.1608 | 15 | |
| 1 | 178 `DO_CHANGE_SPEED` | — | — | 4.5 m/s |
| 2–6 | 16 `NAV_WAYPOINT` | northbound | 24→26 | outbound leg |
| 7 | 178 `DO_CHANGE_SPEED` | — | — | **2.2 m/s — slowing for the drop** |
| 8 | 16 `NAV_WAYPOINT` | 51.50355, -0.16045 | 12 | descending |
| 9 | 16 `NAV_WAYPOINT` | 51.5035598, -0.1608362 | **2** | 3 s hold at 2 m AGL |
| **10** | **187 `DO_SET_ACTUATOR`** | — | — | **`param1 = 1.0` — release** |
| 11 | 93 `NAV_DELAY` | — | — | 2 s |
| 12 | 187 `DO_SET_ACTUATOR` | — | — | `param1 = 0.0` — reset |
| 13 | 178 `DO_CHANGE_SPEED` | — | — | 4.8 m/s — egress |
| 14–20 | 16 `NAV_WAYPOINT` | westbound then south | 18→20 | return leg |
| 21 | 178 `DO_CHANGE_SPEED` | — | — | 2 m/s |
| 22 | 16 `NAV_WAYPOINT` | 51.5001, -0.16086 | 6 | final approach |
| 23 | 21 `NAV_LAND` | **51.4997, -0.1608** | 0 | flag 10 |

187 is `MAV_CMD_DO_SET_ACTUATOR`, **not** `DO_LAND_START` (which is 189). Getting that wrong makes items 10 and 12 look like a duplicated landing marker instead of a set/reset pair around a 2-second delay.

The profile is unambiguous even without the log: slow to 2.2 m/s, descend to 2 m, hold 3 s, fire actuator 1, wait 2 s, reset, accelerate to 4.8 m/s and leave by a different route. That is a delivery, planned as one.

> [!note] Flag 9 numbering
> `10` is the 0-based dataman slot / PX4 `seq`. QGroundControl displays the same item 1-based as **11**. The grader wanted the PX4 sequence number.

---

## 6. The flight — flags 11 to 16

`flight.ulg` is 65.6 MB, 87 topics, 292 s of flight. Sixteen topics answer everything.

The 18 `logged_messages` are the fastest orientation in the room:

```
285.260  [navigator] Executing Mission
285.260  [navigator] Climb to 15.0 meters above home
287.084  [commander] Takeoff detected
517.208  [health_and_arming_checks] Low battery
517.988  [failsafe] Failsafe activated: entering Hold for 5 seconds
520.764  [failure] inject failure unit: motor (101), type: off (1), instance: 0
520.764  [failure_injection_manager] Injected: motor off, all instances
520.772  [control_allocator] Stopping motors (4095)
522.992  [failsafe] Failsafe activated
576.968  [commander] Disarmed by internal command
```

### The injection — flag 13

`vehicle_command` holds 18 records. Seventeen come from `src_sys=255` (GCS) or `src_sys=1` (the onboard navigator executing mission items). One does not:

```
520.764  cmd=420  param1=101  param2=1  param3=0   src_sys=0  src_comp=0  tgt_sys=0  tgt_comp=0
```

`420` is `MAV_CMD_INJECT_FAILURE`; `101` is the motor failure unit, `1` is type `off`, `0` is all instances. **The `src_sys=0, src_comp=0` is the forensic tell** — a valid MAVLink participant never has system ID 0, which is the broadcast/unset value. Everything legitimate in this log is 255 or 1.

Motors stop 8 ms later. The aircraft was at 67 m.

### Positions — flags 11, 12, 15

Every position answer is `vehicle_global_position` sampled at a **logged event instant**:

| Flag | Event | Timestamp | Answer |
|---|---|---|---|
| 11 | `vehicle_land_detected.landed` → false (`vehicle_status.takeoff_time` = 287084000) | 287.072 | `51.4996987,-0.1607999` |
| 12 | `vehicle_command` 187 `param1=1.0` | 446.656 | `51.5035602,-0.1608417` |
| 15 | altitude floor / touchdown | 525.848 | `51.5016938,-0.1620929` |

See §10 for the three submissions this cost and why.

### Distance — flag 14

Straight-line horizontal displacement release→injection is **224 m** (haversine 224.03, WGS84 local 224.25, `vehicle_local_position` NE 224.03 — all agree, all rejected). The accepted answer is the **ground-track length, 277 m**: 276.7 m integrating `vehicle_local_position` NE, 277.1 m integrating `vehicle_global_position` geodetically. Stable under decimation from 125 Hz to 1 Hz (276.45–276.71), so it is not a noise artefact.

The drone flew a dog-leg — west along the top of the box, then south — so path and displacement differ by 24%.

### Disarm — flag 16

`actuator_armed.armed` 1→0 and `vehicle_status.arming_state`→1 both at **576.968**, matching `[commander] Disarmed by internal command`. Note that `vehicle_land_detected.landed` does not go true until **577.312**, i.e. **after** disarm and 51 s after actual ground contact — the land detector never fired on impact because the vehicle was in failsafe with motors stopped.

---

## 7. Where it crashed — flag 17

Crash at `51.5016938,-0.1620929`. Two addresses bracket it:

- **Paxton's Head, 153 Knightsbridge** (odd numbers, south side) — 51.50160, -0.16233
- **One Hyde Park, 100 Knightsbridge** (even numbers, north side) — 51.50188, -0.16197

The crash sits between them, on the A4 carriageway. Answer: **`Knightsbridge`**.

The nearest competitor was `Edinburgh Gate`, the relocated Hyde Park entrance road running north from Knightsbridge at roughly longitude -0.1622 — about 15 m west of the crash. Also in range: `Wellington Court, 116 Knightsbridge` at 51.50180, -0.16242.

Geographic reading of the whole flight: launch and planned landing at 51.4997, -0.1608 — a rooftop in the Knightsbridge block between Sloane Street and Brompton Road. Outbound north-east into Hyde Park, drop at 51.50356, -0.16084 at 2 m AGL, then west and back south along -0.1621 for a different return path. Brought down over Knightsbridge itself, 220 m short of home.

---

## 8. Timeline

All seconds since boot. `time_ref_utc = 0`; the logger filename gives `2026-09-10 09:50:55` as the only date anchor.

| t (s) | Event | Source |
|---|---|---|
| 284.664 | `DO_SET_MODE` (29/4/4) from GCS `src_sys=255` | `vehicle_command` |
| 285.256 | `COMPONENT_ARM_DISARM` param1=1 from GCS; log opens | `vehicle_command` |
| 285.260 | `Executing Mission`, home set 51.4996985/-0.1607997 | `home_position` |
| **287.072** | **liftoff — `landed`→false** | `vehicle_land_detected` |
| 300.984 | seq 2, speed 4.5 m/s | `mission_result` |
| 412.224 | seq 8, speed 2.2 m/s | `navigator_mission_item` |
| 429.016 | seq 9 — 2 m AGL hold over the drop point | `navigator_mission_item` |
| **446.656** | **`DO_SET_ACTUATOR param1=1.0` — payload released** | `vehicle_command` |
| 448.672 | actuator reset, speed 4.8 m/s, egress | `vehicle_command` |
| 500.336 | seq 18 — last mission item reached | `mission_result` |
| 517.208 | low battery | `logged_messages` |
| 517.988 | failsafe — Hold for 5 s | `logged_messages` |
| **520.764** | **`MAV_CMD_INJECT_FAILURE` from `src_sys=0`** | `vehicle_command` |
| 520.772 | `control_allocator: Stopping motors (4095)` | `logged_messages` |
| 522.992 | failsafe, `nav_state`→18 | `vehicle_status` |
| **525.85** | **impact, from 67 m** | `vehicle_global_position` alt floor |
| **576.968** | **disarmed by internal command** | `actuator_armed` |
| 577.312 | `landed` finally true | `vehicle_land_detected` |
| 577.968 | log ends | — |

Descent from 67 m to ground took **5.1 seconds**. The low-battery failsafe at 517.988 is 2.8 s before the injection, which is close enough to be either coincidence or the operator waiting for cover.

---

## 9. Final payload

Reproduction, from the supplied ZIP to all seventeen answers.

```bash
cd ~/iron && unzip IronFeather.zip
pip install --break-system-packages capstone pyelftools pycryptodome pyulog

# --- locate the KDF (no symbols; scan .text for rel32 calls to OpenSSL) ---
readelf --dyn-syms -W px4 | grep -E 'PKCS5_PBKDF2_HMAC$|EVP_aes_256_gcm$'
#   0x32e830 PKCS5_PBKDF2_HMAC   0x326100 EVP_aes_256_gcm
python3 - <<'PY'
import struct
d=open('px4','rb').read(); base=0x110000; size=0x590032
for i in range(base, base+size-5):
    if d[i]==0xE8:
        t=(i)+5+struct.unpack('<i',d[i+1:i+5])[0]
        if t in (0x32e830,0x326100): print(hex(i),hex(t))
PY
objdump -d --start-address=0x170af0 --stop-address=0x170dc0 px4

# --- derive the key (see kdf.py; emulates the 384-round mixer) ---
python3 kdf.py
#   AES-256 key : a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce

# --- decrypt: tag at offset 44, AAD = header[0:44] ---
python3 - <<'PY'
from Crypto.Cipher import AES; import struct
key=bytes.fromhex('a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce')
for fn,out in [('dataman.encrypted','dataman.bin'),('flight.ulg.encrypted','flight.ulg')]:
    d=open(fn,'rb').read(); n=struct.unpack('<I',d[12:16])[0]
    c=AES.new(key,AES.MODE_GCM,nonce=d[32:44]); c.update(d[:44])
    open(out,'wb').write(c.decrypt_and_verify(d[60:60+n], d[44:60]))
    print('OK',out)
PY

# --- mission: bank 0 starts at 8472, 60-byte slots, 56-byte mission_item_s ---
python3 - <<'PY'
import struct
d=open('dataman.bin','rb').read()
for i in range(24):
    b=8472+i*60+4
    lat,lon=struct.unpack_from('<dd',d,b); p=struct.unpack_from('<7f',d,b+16)
    nav=struct.unpack_from('<H',d,b+44)[0]
    print(i,nav,'%.7f %.7f'%(lat,lon),'alt=%.1f'%p[6],['%g'%x for x in p[:6]])
print('mission_s:',struct.unpack_from('<QiIIIIIHBBB',d,0x12709c))
PY

# --- flight: read state topics at logged EVENT instants, never at convenience ---
python3 - <<'PY'
from pyulog import ULog; import numpy as np
keep=['vehicle_command','vehicle_global_position','vehicle_local_position',
      'vehicle_land_detected','actuator_armed','mission_result','home_position']
u=ULog('flight.ulg', message_name_filter_list=keep)
D={d.name:{k:np.array(v) for k,v in d.data.items()} for d in u.data_list}
for m in u.logged_messages: print('%.3f'%(m.timestamp/1e6), m.message)
vc=D['vehicle_command']
for i in range(len(vc['timestamp'])):
    print('%.6f cmd=%d src=%d/%d'%(vc['timestamp'][i]/1e6, vc['command'][i],
          vc['source_system'][i], vc['source_component'][i]))
g=D['vehicle_global_position']; t=g['timestamp']/1e6
at=lambda ts:(lambda i:'%.7f,%.7f'%(g['lat'][i],g['lon'][i]))(int(np.argmin(abs(t-ts))))
print('takeoff',at(287.072),'release',at(446.656),'crash',at(525.848))
lp=D['vehicle_local_position']; tl=lp['timestamp']/1e6
a,b=(int(np.argmin(abs(tl-x))) for x in (446.656,520.764))
print('ground track %.2f m'%np.sum(np.hypot(np.diff(lp['x'][a:b+1]),np.diff(lp['y'][a:b+1]))))
PY
```

---

## 10. Method notes

- **The precision the question asks for is a source selector.** Flag 10 wants 5 dp and comes from the mission plan (`51.49970,-0.16080`, exactly the stored double). Flags 11/12/15 want 7 dp and come from telemetry. When two artifacts answer the same question and disagree below the requested precision, the requested precision is telling you which artifact class the author read. This is the answer-mask-as-constraint technique from Silent Dividend, applied to decimal places instead of character counts.
- **"Cleaner" is not "correct". Prefer the artifact a real responder would hold.** Three submissions were burned on `vehicle_global_position_groundtruth`, chosen because it is exactly constant post-impact while the EKF solution wanders across six distinct 7-dp values. The stability was read as evidence of intent; it was actually evidence that it is a **simulator artifact that would not exist in a genuine recovered log**. The EKF noise was not a defect in the source — it meant the *event timestamp* had to be pinned precisely. Rule: when picking between two artifacts answering one question, ask which one survives the scenario's own premise.
- **Anchor on the event, not on the state.** Once flags 12 and 15 landed on "state topic sampled at a logged event instant", flag 11 should have followed immediately. It did not — arming (285.256) was submitted instead of liftoff (287.072), repeating the mistake one layer down after the pattern was already visible. **When a correction reveals a pattern, re-audit every answer built on the old model, not just the one that failed.**
- **Read the verb, not the units.** Flag 14's "how far did the drone **travel**" is path length; "horizontal metres" only excludes the vertical component. Straight-line displacement was 224 m and felt right because it is the default thing a script computes. The question said travel.
- **Bare terms get qualified.** Flag 5 as `PBKDF2` was rejected; `PBKDF2-HMAC-SHA256` took. Third instance of the answer-format rule in this event — see the MOC.
- **Reimplement, do not read.** The 384-round loop was transcribed instruction-by-instruction rather than understood. Understanding it was never necessary; the GCM tag decided correctness. Two magic-multiply divisions (`mod 48`, `div 19`) were replicated as literal 64-bit arithmetic rather than as `%` and `/`, which removed the only place a transcription could have silently diverged.

---

## 11. Blind alleys — eliminated, do not re-walk

- **`vehicle_global_position_groundtruth` for any position answer.** Present in the log, perfectly stable, and wrong for all three. Same for the first `vehicle_gps_position` fix, which happens to round to the same rejected takeoff value.
- **`home_position` for flag 11.** `51.4996985,-0.1607997` is the home fix at arming and matches the first `vehicle_global_position` sample exactly. The question wants liftoff, 1.8 s later.
- **Straight-line distance for flag 14.** 224 m by three independent methods, all rejected.
- **`0x17f` = 383 for flag 4.** The comparison value is not the round count.
- **`0x170ae0` for flag 3.** A four-instruction stub immediately above the KDF that returns a pointer to the error-string buffer. The call site at `0x1700c6` disambiguates.
- **Tag at end-of-file.** The obvious GCM layout guess. `file_size - plaintext_len = 60`, not 44+16 appended; the tag is inside the header.
- **187 as `DO_LAND_START`.** It is `DO_SET_ACTUATOR`. 189 is `DO_LAND_START`, and there is no `DO_LAND_START` in this mission at all.
- **Searching the binary for `PX4ULENC`.** Zero hits. The ULog encryptor was not shipped.
- **`strings` on the encrypted files.** Both are AES-GCM ciphertext end to end after byte 60. A null result proves nothing, as in Bottle Out §9.

---

## 12. MITRE ATT&CK

Mixed Enterprise and ICS, because the operational half of this room is a control-system attack and the Enterprise matrix has no vocabulary for it.

| Technique | ID | Matrix | Evidence |
|---|---|---|---|
| Obfuscated Files or Information | T1027 | Enterprise | AES-256-GCM datastore and flight log behind a bespoke KDF |
| Obtain Capabilities: Tool | T1588.002 | Enterprise | purpose-built PX4 fork with an encrypted-dataman container the upstream project does not have |
| Unauthorized Command Message | T0855 | ICS | `MAV_CMD_INJECT_FAILURE` from `src_sys=0, src_comp=0` |
| Manipulation of Control | T0831 | ICS | commanded motor-off on a live airframe at 67 m |
| Loss of Control | T0827 | ICS | control allocator stops all four motors 8 ms after the command |
| Damage to Property | T0879 | ICS | uncontrolled descent to street level |

> [!warning] Honest scope
> IDs assigned without access to the live ATT&CK matrix. **T1588.002 is the weakest** — the modified firmware is inferred from the presence of container code that is not in upstream PX4, not from any acquisition evidence. **The ICS mappings are by analogy**: ATT&CK for ICS targets industrial process control, and a MAVLink-controlled UAS is not an ICS asset class in the matrix, but `T0855` describes the mechanism here more exactly than anything in Enterprise. **No technique covers the payload release** — mission-planned actuator actuation for delivery is the adversary's *objective*, not a technique, and the artifacts do not say what was released. The room's own subject, recovering an encrypted flight record by deriving the key from the tool that wrote it, is a defender capability with no ATT&CK slot.

---

## 13. Detection / blue-team notes

**On the command injection.** The single highest-value check in this log is one line of Python:

- **`vehicle_command.source_system == 0` or `source_component == 0` is never legitimate.** MAVLink system ID 0 is the broadcast/unset value; a real GCS is 255 and the onboard navigator is 1. Seventeen of eighteen commands in this log are 255 or 1. Alert on any other value, and alert unconditionally on 0.
- **`MAV_CMD_INJECT_FAILURE` (420) on a production airframe is always an incident.** It exists for SITL and bench testing. PX4 gates it behind the `SYS_FAILURE_EN` parameter — that parameter being enabled on a flying aircraft is itself the finding, and it is recoverable from `parameter_update` in the log.
- Command lineage is the pattern, not any single record: mode set → arm (both `src_sys=255`), then mission-driven commands (`src_sys=1`) for 235 seconds, then one command from nowhere.

**On the encrypted stores.** Key material derived entirely from constants compiled into the binary is **not key management** — anyone with the binary has the key, forever, for every device in the fleet, and rotation requires a firmware push. The salt being identical across two independently produced files means even the per-file uniqueness the design implies is absent. If this pattern appears in a real product, treat every artifact it has ever produced as plaintext.

**For responders holding a UAS log.**

- `vehicle_command` is the audit trail. Read it before anything else, with source system and component printed.
- The `logged_messages` stream (18 records here) reconstructs the whole incident in under a screen. It is the `Security.evtx` of a flight log.
- `vehicle_land_detected` is not a crash detector. It fired 51 s after impact here because the vehicle was in failsafe with motors stopped. Derive impact from the altitude floor in `vehicle_global_position`.
- Mission intent lives in `dataman`, not in the log. The log shows what the aircraft *did*; the datastore shows what it was *told to do*, including items it never reached. Both were needed here — flags 9 and 10 are only in the datastore, flags 11–16 only in the log.

---

## 14. Tools & techniques

`objdump` · `readelf` · `python3` · `pycryptodome` · `pyulog` 1.x · `capstone` / `pyelftools` (installed, ultimately unused) · `pdftotext`

**Concepts:** rel32 call-site scanning to locate functions in a stripped binary via exported library symbols · reading function signatures off register marshalling at a known libc/OpenSSL call · transcribing an ARX mixing loop instruction-by-instruction instead of reverse-engineering it · magic-multiply division recognition (`mod 48`, `div 19`) · AEAD tag verification as a correctness oracle for a reimplemented KDF · AAD reconstruction from `EVP_DecryptUpdate(out=NULL)` · recovering a binary file layout from the writer's own size/count tables in `.rodata` · PX4 dataman key regions and `mission_item_s` / `mission_s` on-disk layout · `MAV_CMD` numbering traps (187 vs 189) · ULog topic triage via `message_name_filter_list` · event-instant sampling of state topics · MAVLink source-system provenance as an injection indicator · ground-track integration vs straight-line displacement · address-parity geolocation (odd/even street numbering to place a point on a carriageway)

---

## 15. Open items

1. **`ver_sw = da414713fc7da42796bf1e767f44f6de8122cc67` not resolved.** The PX4 commit hash is in `msg_info_dict`. Whether it maps to an upstream commit, and therefore whether the encrypted-dataman code is a fork or a patch, was not checked.
2. **`parameter_update` never examined.** `SYS_FAILURE_EN` must have been set for `MAV_CMD_INJECT_FAILURE` to be honoured, and the parameter log would date that change. This is the strongest untested lead in the room.
3. **What was released is unknown.** `gripper` has exactly one record (`command=0` at t=0.276) and no actuator payload topic was logged. The drop is only visible as `DO_SET_ACTUATOR` on actuator 1.
4. **The 2.8 s gap between low-battery failsafe (517.988) and injection (520.764) is uncharacterised.** Whether the operator was waiting for a plausible cause of loss, or the timing is incidental, is not determinable from these artifacts.
5. **`telemetry_status` never examined.** It may carry the link the injected command arrived on, which would separate a radio-side injection from an onboard one.
6. **`solves` omitted** — not read off the platform.
7. **The 48-byte table at `0x6f0a40` overlaps the 72-byte password tail at `0x6edfa0`.** Last 32 bytes of the tail equal the first 32 of the table. Probably compiler constant-pooling, not meaningful, but not confirmed.
8. **Flag 17 answered from Google Places point data, not road geometry.** The Knightsbridge / Edinburgh Gate margin is roughly 7 m vs 15 m; the conclusion rests on odd/even street numbering bracketing the point, not on a measured distance to a centreline.

---

## Cross-references

- [[00_MOC-HTB-Holmes2026-Reichenbach-Directive-Event]] — event index and the cross-room method that this room re-proved three times
- [[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]] — Sherlock 01; the answer-mask-as-constraint technique, and the same "key lives outside the protected artifact" structure
- [[HTB-Holmes2026-Bottle-Out-Wiped-Laptop-Gajim-XMPP-TacticalRMM]] — Sherlock 02; origin of the answer-format-is-literal rule that flag 5 re-proved
- [[HTB-Holmes2026-Paper-Ghost-Planted-USB-Spyware-Search-Index-Recovery]] — Sherlock 04; second instance of the same rule, and the "enumerate what was not collected" discipline
- [[00_ctf-writeup-standard]] — structure this note conforms to
- [[HTB]]

---

## Change Log

- 2026-09-20 — Note created. All seventeen flags solved and recorded; scenario captured verbatim. Four wrong submissions recorded in §10 and §11 (groundtruth source ×3, straight-line distance ×1, bare `PBKDF2` ×1). `solves` marked unverified pending a read of the platform page (§15.6). MITRE table mixes Enterprise and ICS IDs — flagged for frontmatter-standard review before filing.
- 2026-09-20 — Cross-references: MOC backlink corrected from `[[HTB-Holmes2026-Reichenbach-Directive-Event-MOC]]` (never resolved — matches neither the filename nor any of the MOC's aliases) to `[[00_MOC-HTB-Holmes2026-Reichenbach-Directive-Event]]`. Dead since the note was filed; the other five Holmes notes already used the correct form. No content changed.

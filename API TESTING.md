## 1. Fundamentals & Core Concepts

An **Application Programming Interface (API)** acts as the structured communication abstraction layer between distinct software systems. While traditional web application testing looks closely at rendered HTML frontends, **API testing** focuses on uncovering vulnerabilities within the decoupled underlying data-exchange interfaces (typically JSON or XML microservices).

### The Core Risk Landscape

Vulnerabilities within public or internal APIs can undermine the foundational pillars of security:

- **Confidentiality:** Unauthorized access to underlying user databases or system configurations.
    
- **Integrity:** Direct modification of server-side data models, pricing, or administrative privileges.
    
- **Availability:** Flooding specific processing-heavy endpoints to exhaust backend infrastructure resources.
    

## 2. Detection & Attack Surface Mapping

Mapping the attack surface of an API requires identifying explicit and implicit endpoint locations, parsing acceptable parameter schemas, and hunting for developer documentation.

### Core Architecture & API Recon

- **Endpoint Identification:** Locate exact Uniform Resource Identifiers (URIs) indicating resource routing paths (e.g., `GET /api/v1/books`).
    
- **Transaction Constraints:** Systematically audit endpoints to extract:
    
    - **Input Formats:** Mandatory vs. optional key-value parameters.
        
    - **Protocol Verbs:** Accepted HTTP methods (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`).
        
    - **Media Types:** Supported content formats specified via the `Content-Type` header.
        
    - **Access Rules:** Implemented rate-limiting mechanisms and authentication schemas.
        

### Discovering API Documentation

Developers frequently use structured definitions to coordinate application layouts. Finding these files provides a highly detailed map of hidden endpoints.

- **Common Documentation Entrypoints:**
    
    - `/api` | `/api/v1` | `/api/v2`
        
    - `/swagger/index.html` | `/swagger/v1`
        
    - `/openapi.json` | `/swagger.json`
        
- **Directory Traversal Strategies:** When discovering an active asset path like `/api/swagger/v1/users/123`, systematically truncate the route segments to expose root schema endpoints:
    
    1. `/api/swagger/v1/users`
        
    2. `/api/swagger/v1`
        
    3. `/api/swagger`
        
    4. `/api`
        
- **Tooling Integration:** Utilize **Burp Suite Scanner** or specialized extensions like **JS Link Finder** to find hidden paths in client-side bundles (`*.js`).
    

## 3. Vulnerability Class Analysis

### Server-Side Parameter Pollution (SSPP)

Server-Side Parameter Pollution occurs when a web application unsafely inserts raw user input into an internal API request string without validation or contextual encoding. This allows an attacker to inject backend query syntax control characters (like `&`, `=`, `#`) to alter query execution.

#### Injection Mechanics

Consider a public application executing an internal query: `GET /internal/search?name=USER_INPUT&publicProfile=true`

- **Truncation (`%23` / `#`):** Submitting a URL-encoded hash sign drops subsequent backend query logic.
    
    - _Input:_ `peter%23`
        
    - _Backend Request:_ `GET /internal/search?name=peter#&publicProfile=true` (The server discards everything after the `#`, ignoring enforcement parameters like `publicProfile=true`).
        
- **Parameter Injection (`%26` / `&`):** Injecting an encoded ampersand lets an attacker insert brand-new query key-value pairs into the backend request.
    
    - _Input:_ `peter%26email=hacker@evil.com`
        
    - _Backend Request:_ `GET /internal/search?name=peter&email=hacker@evil.com&publicProfile=true`
        
- **Parameter Overriding:** Submitting an duplicate variable name string to change existing backend parameter constraints.
    
    - _Input:_ `peter%26name=carlos`
        
    - _Backend Request:_ `GET /internal/search?name=peter&name=carlos&publicProfile=true`
        

#### Multi-Technology Override Resolution

The impact of duplicate parameters varies across backend server engines:

|Server Technology Engine|Duplicate Parameter Parsing Resolution|
|---|---|
|**PHP** / **Apache**|Parses the **last** instance only (e.g., uses `carlos`).|
|**Node.js** / **Express**|Parses the **first** instance only (e.g., uses `peter`).|
|**ASP.NET**|**Combines** both values into a comma-separated array (e.g., uses `peter,carlos`).|

### Hidden Method & Content-Type Exploitation

Applications frequently restrict structural configurations on standard production interfaces, but leave secondary endpoint method handlers unprotected.

- **HTTP Verb Cycling:** Use the `OPTIONS` method or swap out conventional verb protocols to expose unmonitored processing logic.
    
    - _Safe Baseline:_ `GET /api/tasks` -> List of objects.
        
    - _Privileged Pivot:_ `POST /api/tasks` or `DELETE /api/tasks/1`.
        
- **Content-Type Splitting:** Altering the incoming data structure can bypass edge application filters or trigger verbose error states.
    
    - _JSON to XML:_ Converting data structures from `application/json` to `application/xml` via tools like the **Content Type Converter** BApp can bypass input validation filters if the backend parses alternative formats less securely.
        

### Mass Assignment (Auto-Binding)

Mass Assignment occurs when web application frameworks automatically map a client's incoming JSON request parameters directly onto internal database objects or code models without an explicit field allow-list.

#### Identification Matrix

1. Analyze object schemas returned via read hooks:
    
    JSON
    
    ```
    /* GET /api/users/123 response */
    { "id": 123, "name": "John", "isAdmin": false }
    ```
    
2. Correlate these properties with update endpoints (`PATCH /api/users/update`).
    
3. Inject internal fields into the update payload to try and alter privileged properties:
    
    JSON
    
    ```
    /* PATCH /api/users/update malicious payload */
    { "name": "John", "isAdmin": true }
    ```
    
### Server-Side Parameter Pollution in REST URL Paths

In a RESTful architecture, internal API configurations routinely route parameters directly inside the URL path syntax blocks (e.g., `/api/v1/users/{username}/profile`) rather than appending variables inside traditional query parameter key blocks.

When user-controlled input fields are nested inside these paths without sanitization or URL-safe character escaping, an attacker can manipulate the structured API call using path traversal characters (`../`) or truncation flags (`#`, `?`).

- **Path Traversal (`../`):** Allows an attacker to break out of the intended resource folder structure and hit alternative API paths.
    
- **Path Truncation (`%23` / `#` or `%3F` / `?`):** Forces the backend client loader to treat the rest of the pre-configured system path as a fragment or a query string, cutting off backend validation properties.
    

### Server-Side Parameter Pollution in Structured Data Formats (JSON/XML)

API servers frequently handle internal inter-service data transfers using structured payload data types like JSON objects or XML sheets. If incoming user input strings are appended directly into these data structures without proper encoding, an attacker can break out of the initial variable string wrapper to inject custom attributes into the parsed payload.

#### Injection Breakouts in JSON Payloads

Consider an application that updates a user's profile metadata by building an internal request:

JSON

```
PATCH /users/7312/update {"name":"USER_INPUT"}
```

If an attacker injects quote delimiters, commas, and replacement keys, they can alter the internal object schema properties completely:

- **Malicious Form Input:** `peter","access_level":"administrator`
    
- **Resulting Backend Request:** ```json PATCH /users/7312/update {"name":"peter","access_level":"administrator"}
    

If the JSON parser processes the payload sequentially and resolves duplicate keys or prioritizes the last set value, administrative privileges or object properties can be modified.
## 4. Solutions & Payloads

### Lab 1: Exploiting an API endpoint using documentation

- **Vulnerability:** Exposed Swagger documentation via structural path truncation.
    
- **Solution Steps:**
    
    1. Intercept `PATCH /api/user/wiener` inside Burp Repeater.
        
    2. Truncate the target variable parameter path downwards to **`/api`** and send the request.
        
    3. Analyze the exposed API configuration manual. Use the definition constraints to execute a direct management extraction:
        
        HTTP
        
        ```
        DELETE /api/user/carlos HTTP/1.1
        Host: YOUR-LAB-ID.web-security-academy.net
        ```
        

### Lab 2: Exploiting server-side parameter pollution in a query string

- **Vulnerability:** Internal parameter manipulation via unencoded query syntax injections.
    
- **Solution Steps:**
    
    1. Send the `POST /forgot-password` request to Burp Intruder.
        
    2. Inject a custom parameter block combined with a trailing truncation key: `username=administrator%26field=§x§%23`.
        
    3. Run the attack using the **Server-side variable names** payload list to identify valid internal parameter values (**reset_token**).
        
    4. Extract the token value by updating the request query string in Repeater:
        
        Plaintext
        
        ```
        username=administrator%26field=reset_token%23
        ```
        
    5. Submit the extracted token via your browser at `/forgot-password?reset_token=TOKEN` to overwrite the administrator credentials.
        

### Lab 3: Finding and exploiting an unused API endpoint

- **Vulnerability:** Unprotected `PATCH` processing handler allowing parameter updates.
    
- **Solution Steps:**
    
    1. Intercept `GET /api/products/1/price` and change the verb to `OPTIONS` to confirm that the `PATCH` method is available.
        
    2. Change the request method to `PATCH`, configure the proper media type header `Content-Type: application/json`, and supply a targeted modification payload to change the item's cost:
        
        JSON
        
        ```
        { "price": 0 }
        ```
        
    3. Reload the product web view, add the items to your shopping cart, and check out.
        

### Lab 4: Exploiting a mass assignment vulnerability

- **Vulnerability:** Object auto-binding allows clients to update restricted properties.
    
- **Solution Steps:**
    
    1. Observe the order details via `GET /api/checkout`. Note the internal tracking attribute `"chosen_discount": 0` inside the response data model.
        
    2. Inject this parameter directly into the item addition or cart update JSON submission payload:
        
        JSON
        
        ```
        { "username": "wiener", "chosen_discount": 100 }
        ```
        
    **3**. Submit the request to apply the 100% discount, then finalize the purchase flow.

### Lab 5: Exploiting server-side parameter pollution in a REST URL

- **Vulnerability:** Path manipulation and traversal vulnerabilities in a backend REST route handle.
    
- **Solution Steps:**
    
    1. Submit a password reset sequence for the targeted account `administrator` and capture the `POST /forgot-password` request using Burp Suite.
        
    2. Fuzz the variable parameter within Repeater using truncation payloads to analyze error anomalies:
        
        - `username=administrator%23` yields an `Invalid route` block error, indicating local path truncation.
            
        - `username=./administrator` yields the standard page baseline, indicating that the value maps straight into an operational filesystem path.
            
    3. Execute systematic directory escalation mappings backward across the route interface until you find the structural boundary root layer (`../../../../%23` yields a `Not found` status).
        
    4. Fuzz filenames at this boundary layer to download the system's primary documentation mapping specification:
        
        Plaintext
        
        ```
        username=../../../../openapi.json%23
        ```
        
        The application discloses an unexposed REST routing schema definition: `/api/internal/v1/users/{username}/field/{field}`.
        
    5. Construct a path sequence using the discovered endpoint mapping to target the system token retrieval variables while traversing out of the versioning constraints:
        
        Plaintext
        
        ```
        username=../../v1/users/administrator/field/passwordResetToken%23
        ```
        
    1. Extract the valid `passwordResetToken` value from the response payload, pass it to your browser at `/forgot-password?passwordResetToken=TOKEN`, and alter the administrative user password to delete the target profile.

## 5. Automated Testing Toolkit

To effectively discover and analyze hidden API interfaces, integrate these core automation tools into your technical environment:

- **Burp Intruder:** Use it to brute-force route endpoints, iterate through alternative HTTP verbs, and fuzz hidden parameters.
    
- **Param Miner (BApp Extension):** Automates the process of guessing up to 65,536 inline query and header parameter variables simultaneously.
    
- **Content Type Converter (BApp Extension):** Instantly restructures request data blocks between XML and JSON formats to test for format-parsing vulnerabilities.
    
- **Postman / SoapUI:** Ideal tools for importing machine-readable schema definition files (like OpenAPI specs) to test and interact with endpoints.


## 6. Remediation & Prevention Defense Models

To secure internal APIs against parameter pollution and structured data format injections, apply the following engineering defense rules:

### 1. Context-Aware Output Encoding

Never construct server-side URLs, query strings, or JSON strings using raw string concatenation.

- **For Paths/Queries:** Run user input through safe URL encoding functions (e.g., `encodeURIComponent()` in Node.js or `URLEncoder.encode()` in Java) to ensure characters like `?`, `&`, `#`, and `/` are treated as literal values, not syntax overrides.
    
- **For Structured Payloads:** Always build JSON or XML blocks using native object serializers and parsers (e.g., `JSON.stringify()` or safe XML object wrappers) rather than stitching text elements together manually.
    

### 2. Strict Input Allow-listing

- Validate all incoming client variables against strict data type formats, lengths, and character sets using input-validation schemas (e.g., JSON Schema, Joi, or Zod).
    
- Enforce explicit, narrow allow-lists for paths and parameters. Reject any inbound strings containing atypical Control characters outright.
    

### 3. Decoupled Object Schemas (Data Transfer Objects)

To prevent mass assignment and auto-binding vulnerabilities:

- Do not allow frameworks to bind raw HTTP request data fields straight to database models.
    
- Implement explicit **Data Transfer Objects (DTOs)** or model maps that strictly define which specific properties are modifiable by the client role context.
    

Would you like to examine the exact differences between how various JSON parsing engines handle duplicate key injections during format pollution attacks?
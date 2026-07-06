## 1. Fundamentals & Core Concepts (GraphQL)

### What is GraphQL?

**GraphQL** is an API query language and runtime designed to streamline data transfers between clients and backend servers. Unlike REST architectures—which require hitting multiple resource-specific paths—GraphQL utilizes a **single endpoint** (typically via a `POST` request) where the client explicitly defines the structural shape of the data it requires.

### Core Operation Types

GraphQL communications are strictly split into three main operational frameworks:

- **Queries:** Used exclusively for fetching records. (Functional equivalent to a REST `GET` request).
    
- **Mutations:** Used to add, modify, or delete backend records. (Functional equivalent to REST `POST`, `PUT`, or `DELETE` requests).
    
- **Subscriptions:** Long-lived, bidirectional connections (typically implemented via **WebSockets**) that allow servers to proactively push real-time micro-updates to clients without constant polling.
    

### The Contract: GraphQL Schemas

The **Schema** serves as the explicit blueprint or contract between the frontend and backend layers. Written in human-readable Schema Definition Language (SDL), it specifies every available object type, field parameter, and relational layout.

GraphQL

```
# Example Schema Definition Layout
type Product {
    id: ID!          # The '!' operator explicitly marks this field as non-nullable (mandatory)
    name: String!
    description: String!
    price: Int
}
```

## 2. Attack Surface Syntax Components

To identify control flows and potential manipulation points within a target GraphQL service, audit these core architectural components:

### 1. Fields

Fields represent individual pieces of queryable data nested inside an object type. The response returned by the server explicitly mirrors the specific fields requested by the client.

### 2. Arguments

Arguments are key-value validation filters attached directly to specific fields to isolate specific objects.

> ⚠️ **Access Control Risk:** If user-supplied field arguments (such as `id: 123`) directly control object lookup operations without rigorous server-side authorization checks, the endpoint is highly vulnerable to **Insecure Direct Object References (IDOR)**.

### 3. Variables

Variables allow developers to separate dynamic argument values from the core query string, dumping them into a separate JSON object dictionary. This enables query reuse and prevents raw string concatenation.

JSON

```
/* Dynamic Variable Pass Dictionary */
{
  "id": 1
}
```

### 4. Aliases

By default, a GraphQL query object cannot declare multiple properties with the exact same name. **Aliases** let you bypass this rule by mapping custom identifier headers directly to redundant operations, letting you extract multiple data blocks in one round trip.

GraphQL

```
# Bypassing identical property restrictions via Aliases
query getProductDetails {
    product1: getProduct(id: "1") { name }
    product2: getProduct(id: "2") { name }
}
```

### 5. Fragments

Fragments are reusable structural blocks of shared fields belonging to a specific type. Changing fields inside a single fragment automatically updates every query that references it.

### 6. Introspection

**Introspection** is a built-in GraphQL utility that allows clients to query the server for comprehensive structural information about its own schema definitions, mutations, and field parameters.

- **Security Impact:** If left enabled in production, introspection allows an attacker to automatically map out the complete backend layout, uncovering hidden fields, structural properties, and administrative entry points.
  
  ## 2.1. Detection & Attack Surface Mapping (GraphQL)

### Finding GraphQL Endpoints

Because GraphQL uses a centralized endpoint architecture, discovering the interface URL is necessary to map out the application's attack surface.

#### Probing with Universal Queries

The most reliable method to confirm a GraphQL endpoint is by dispatching a **Universal Query**. Every valid GraphQL server possesses a reserved, system-level metadata field named `__typename`. This field returns the queried object’s structure type as a literal string.

GraphQL

```
# Universal Query Probe Payload
query { __typename }
```

- **Expected Successful Signature:** `{"data": {"__typename": "query"}}`
    
- **Handling Error Deviations:** Production instances frequently discard arbitrary requests with error messages such as `"query not present"`. This specific error message structure can confirm that a GraphQL parsing engine is active behind that path.
    

#### Standard Suffix Wordlist & Traversal Paths

When running directory fuzzing, look for the following common endpoint routes:

- `/graphql`
    
- `/api`
    
- `/api/graphql`
    
- `/graphql/api`
    
- `/graphql/graphql`
    
- _Note:_ If these root directories fail to respond, append API versioning directories (e.g., `/api/v1`, `/graphql/v1`).
    

#### HTTP Method Cycling

Secure production specifications should restrict operations to `POST` requests paired with a `Content-Type: application/json` header to mitigate Cross-Site Request Forgery (CSRF) vectors. However, legacy configurations or misconfigurations may accept `GET` calls or `POST` requests formatted as `application/x-www-form-urlencoded`. If standard discovery fails, re-test endpoints by passing the universal query via a URL parameters block:

Plaintext

```
GET /api?query=query{__typename}
```

## 3. Vulnerability Class Analysis (GraphQL)

### Exploiting Unsanitized Field Arguments (IDOR)

When fields rely on client-supplied arguments to query explicit records directly, a missing access control check can expose private data models.

GraphQL

```
# 1. Baseline Request (Discovers a sequential ID gap between products 2 and 4)
query { products { id name listed } }

# 2. Exploitation Target (Direct argument injection to fetch a hidden unlisted product)
query { product(id: 3) { id name listed } }
```

### Schema Reconstruction & Bypassing Introspection Defenses

Introspection allows an engineer to download the internal structure of the schema via the root query element `__schema`.

#### Structural Discovery Probes

JSON

```
/* Minimal Introspection Check */
{
    "query": "{__schema{queryType{name}}}"
}
```

If a complete layout extraction is successful via the native `IntrospectionQuery` structure, the data can be imported directly into toolings like visualizers to trace relations between types, mutations, and privileged control attributes.

#### Evading Regex Blocklists

To disable introspection, developers sometimes implement a perimeter regular expression filter to drop inbound traffic strings containing the literal phrase `__schema`. Attackers can often bypass flawed pattern validation rules by injecting GraphQL-ignored white-space control entities (such as commas, newlines, or carriage returns) that break the regular expression pattern matching while remaining syntax-valid to the underlying engine.

GraphQL

```
# Newline Breakout Injection
query {
    __schema
    { queryType { name } }
}
```

### Rate Limit Evasion via Query Aliasing

Standard web application firewalls (WAFs) and rate-limit counters track incoming traffic volumes based on **HTTP request frequencies** mapped to distinct origin IPs. Because GraphQL supports aliases, a client can nest dozens of distinct operational requests inside a **single HTTP POST body structure**.

The engine executes each aliased operation sequentially in a single execution cycle, enabling large-scale brute-force attacks or credential stuffing without triggering request-count thresholds.
### GraphQL Cross-Site Request Forgery (CSRF)

Cross-Site Request Forgery (CSRF) vulnerabilities allow an attacker to trick a victim's browser into executing unauthorized state-changing operations on an active web application session. In a GraphQL context, this usually involves forcing the victim's session to process a malicious `mutation`.

#### The Vulnerability Driver: Content-Type Laxity

- **The Baseline Defense:** Native GraphQL architectures generally utilize `POST` requests encapsulating a payload content type of `application/json`. Browsers restrict cross-origin programmatic layout mapping for JSON contents via the Same-Origin Policy (SOP) unless explicitly permitted by Cross-Origin Resource Sharing (CORS) rules.
    
- **The Vulnerability:** If the server-side parsing framework handles incoming mutations using alternative, legacy transport types—specifically **`application/x-www-form-urlencoded`** or standard **`GET` query variables**—the API drops its content protection barrier. An attacker can then use standard HTML `<form>` inputs or client-side vectors to trigger background mutations.
## 5. Solutions & Payloads (GraphQL)

### Lab 1: Accessing private GraphQL posts

- **Vulnerability:** Unprotected Introspection access paired with sequential IDOR argument vulnerabilities.
    
- **Solution Steps:**
    
    1. Send the blog retrieval query `POST /graphql/v1` to Burp Repeater.
        
    2. Overwrite the query payload with Burp’s default Introspection block (`GraphQL > Set introspection query`) to map the structural objects.
        
    3. Locate the hidden `postPassword` field within the schema metadata of the `BlogPost` object.
        
    4. Alter the query parameters inside the GraphQL tab to extract the password from the hidden index item (`id: 3`):
        
        GraphQL
        
        ```
        query getSpecificPost {
            getBlogPost(id: 3) {
                id
                title
                postPassword
            }
        }
        ```
        

### Lab 2: Accidental exposure of private GraphQL fields

- **Vulnerability:** Introspection exposure reveals hidden administrative data-retrieval properties.
    
- **Solution Steps:**
    
    1. Intercept the standard mutation tracking account credentials under `POST /graphql` and execute a complete Introspection query download.
        
    2. Map out the schema functions inside the Burp Site Map (`Target > Site Map > Save GraphQL queries`).
        
    3. Uncover a sensitive query definition named `getUser(id: ...)` that drops explicit parameter records including usernames and passwords.
        
    4. Send the target query to Repeater, change the dynamic structural `id` parameter variable to administrative indexes (`id: 1`), and extract the cleartext administrator password.
        

### Lab 3: Finding a hidden GraphQL endpoint

- **Vulnerability:** Active GET-parameter query handling combined with a flawed regex filter blocklist on `__schema`.
    
- **Solution Steps:**
    
    1. Fuzz path directories via URL parameter queries to identify hidden API routes. Discovering `GET /api` returns a `"Query not present"` warning, which confirms a GraphQL parser is present.
        
    2. Verify the endpoint structure by passing an encoded version of the universal query: `/api?query=query{__typename}`.
        
    3. The application blocklist rejects the word `__schema`. Evade this validation check by encoding a newline control element (`%0a`) directly into the payload array right after the targeted structural term:
        
        Plaintext
        
        ```
        /api?query=query%20IntrospectionQuery%20%7B%0D%0A%20%20__schema%0a%20%7B%0D%0A%20%20%20%20queryType%20%7B...%7D%0D%0A%20%20%7D%0D%0A%7D
        ```
        
    4. Extract the schema definitions, locate the `deleteOrganizationUser(input: {id: 3})` mutation structure, and execute the call via the browser to remove user `carlos`.
        

### Lab 4: Bypassing GraphQL brute force protections

- **Vulnerability:** Request rate-limit bypass via structural operation Aliasing.
    
- **Solution Steps:**
    
    1. Identify that individual login mutations under `POST /graphql` trigger rate limit error blocks after a few sequential attempts.
        
    2. Construct a multi-aliased dictionary mutation block inside a single request wrapper payload, mapping each entry to a unique password string from the target dictionary list:
        
        GraphQL
        
        ```
        mutation EvasionBruteforce {
            attempt1: login(input:{username: "carlos", password: "first_password"}) { token success }
            attempt2: login(input:{username: "carlos", password: "second_password"}) { token success }
            # ... repeat for all passwords in the list
        }
        ```
        
    3. Dispatch the unified request payload packet, parse the response objects for a `"success": true` flag, and use the associated login token.
        

Would you like to review how to structure batch processing queries for GraphQL engines that explicitly restrict max alias counts?

### Lab 5: Performing CSRF exploits over GraphQL

- **Vulnerability:** The GraphQL mutation endpoint lacks anti-CSRF token parameters and runs mutations passed via `application/x-www-form-urlencoded` payloads.
    
- **Solution Steps:**
    
    1. Intercept the `POST /graphql` request used to update user email profiles.
        
    2. Within Burp Repeater, switch the transport framework format twice by selecting **Change request method** from the right-click menu.
        
    3. Convert the request body format to a URL-encoded key-value block matching standard web forms:
        
        Plaintext
        
        ```
        query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22attacker%40evil.com%22%7D%7D
        ```
        
    4. Pass this formatted query through the Burp Suite engagement toolkit wrapper (**Engagement tools > Generate CSRF PoC**).
        
    5. Host the generated exploit code wrapper containing the self-submitting form on the delivery server to force a profile update on the target session.
        

## 6. Remediation & Prevention Defense Models (GraphQL)

To protect production GraphQL endpoints against configuration exposures, brute-force evasion, and cross-site attacks, implement these defensive controls:

### 1. Enforce Content-Type Hardening

- Explicitly configure the webserver to reject any inbound mutations that do not strictly provide a `Content-Type: application/json` header.
    
- Disable `GET` parameter fallback processing for queries and mutations to block cross-origin browser transport actions.
    

### 2. Implementation of Anti-CSRF Protection

- Ensure that state-changing GraphQL endpoints use custom request headers (such as `X-Requested-With`) or require a valid cryptographic Anti-CSRF token verified on every backend state alteration attempt.
    

### 3. Restricting Information Leakage

- **Disable Introspection:** If the interface is reserved for private internal systems, turn off the `__schema` lookup framework in production environments.
    
- **Suppression of Suggestions:** Turn off the Apollo suggestion engine (`hideSchemaDetailsFromClientErrors: true`) to prevent automated schema mapping and field discovery attacks.
    

### 4. Query Complexity Controls & Resource Limiting

To counter brute-force attempts via query aliasing and Denial-of-Service (DoS) vectors through deeply nested queries, apply these operational constraints:

- **Query Depth Limiting:** Enforce a strict ceiling on the number of nested query levels permitted per execution to prevent server resource exhaustion.
    
- **Operation Limits:** Define explicit thresholds restricting the maximum number of fields, variables, and aliases allowed in a single payload.
    
- **Cost Analysis Engine:** Implement an abstract calculation system that evaluates the computational complexity of a query _before_ execution. If a query's estimated load exceeds the authorized safety budget, drop the request automatically.
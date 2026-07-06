### JWT Anatomy and Architecture

JSON Web Tokens (JWTs) are a standardized framework (RFC 7519) designed to securely transmit self-contained JSON state objects ("claims") between client applications and identity providers. Because all essential context parameters reside directly within client-side memory spaces, backend services do not need to maintain persistent server-side session stores, facilitating high availability across stateless, distributed architectures.

A standard token consists of three distinct string strings separated by dot delimiters (`.`):

- **Header:** A Base64URL-encoded JSON block providing technical metadata about the token format and the cryptographic configuration used to secure it (e.g., specifying the signature algorithm parameter `alg`).
    
- **Payload:** A Base64URL-encoded JSON block containing the actual session statement properties ("claims"), such as user identification hooks (`sub`), expiration thresholds (`exp`), or system authorization flags (`role`).
    
- **Signature:** A cryptographic hash computed across both the encoded header and payload elements using a server-side signing key. This layer prevents tampering; modifying any single character within the preceding headers or payload blocks invalidates the signature verification process.
    

### Flawed JWT Signature Verification

Because identity backends remain stateless, they rely implicitly on incoming token signatures to ensure state data integrity. If verification functions are improperly implemented, the backend will parse data fields within unverified or modified tokens.

#### 1. Signature Processing Omissions

Vulnerabilities can arise if developers mistake structural data formatting utilities for validation layers. For instance, in Node.js runtime setups, a developer may invoke a raw decoding function (such as `jsonwebtoken.decode()`) instead of the true cryptographic routine (`jsonwebtoken.verify()`). This leaves the signature unvalidated, allowing an attacker to change payload claim strings (e.g., swapping a user identity parameter `sub` from `user` to `administrator`) to gain unauthorized access.

#### 2. Acceptance of Unsecured JWTs (`alg: none`)

The JWT standard supports an unsecured mode where data requires no signing verification. This state is declared by setting the algorithm header property to `"alg": "none"`.

JSON

```
// Unsecured Token Header Concept
{
    "alg": "none",
    "typ": "JWT"
}
```

If a backend system blindly accepts user-controlled header declarations without an internal enforcement policy, an attacker can rewrite the `alg` value to `none`, completely strip the signature segment from the end of the string (retaining the trailing dot delimiter `.`), and force arbitrary payload claim changes.

#### 3. Symmetric Secret Key Brute-Forcing

Symmetric verification algorithms like **HS256** (HMAC + SHA-256) use a shared passphrase string to generate and verify signatures. If a developer uses a weak passphrase, default code snippet placeholder, or predictable corporate key, an attacker can execute local brute-force attacks against intercepted signatures using dedicated cracking tools like Hashcat.

Bash

```
# Hashcat command syntax for cracking JWT symmetric keys using a wordlist
hashcat -a 0 -m 16500 <target_jwt> /path/to/wordlist.txt
```

Because this validation check runs locally on the attacker's hardware rather than generating remote network requests to the target web app, millions of candidate keys can be evaluated per second. Discovering the secret passphrase allows an attacker to arbitrarily sign forged payloads.

### JWT Header Parameter Injections

The JWS specification permits optional parameters inside the metadata header (JOSE header) to help applications identify matching verification keys. If these parameters are trusted without strict validation, attackers can manipulate the signature verification process.

JSON

```
// Vulnerable JWT Header containing Injection Parameters
{
    "alg": "RS256",
    "typ": "JWT",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "n": "yy1wpYmffgXBxhAU..."
    }
}
```

#### 1. Embedded Public Key Injection (`jwk`)

The **`jwk` (JSON Web Key)** parameter allows an application to embed a public verification key directly within the token header. If a vulnerable backend uses whatever key is provided in the token rather than matching it against an internal allow-list of trusted public keys, an attacker can sign a forged payload using their own custom RSA private key and embed the corresponding public key in the `jwk` header parameter to bypass authentication.

#### 2. External Key Set URL Injection (`jku`)

The **`jku` (JWK Set URL)** parameter specifies an external web address where the verification engine can fetch a collection of trusted keys (a JWK Set). If the application fails to restrict this parameter to trusted target domains, an attacker can host a malicious JWK Set on an external exploit server, inject that URL into the `jku` header parameter, and sign the forged token using the matching private key.

### JWT Header Parameter Injections (Continuation)

#### 3. Key ID Parameter Path Traversal (`kid`)

The **`kid` (Key ID)** header parameter provides an arbitrary identifier string used by a server to look up the correct verification cryptographic key from its local filesystem or an internal database key set. If the backend uses this identifier string directly inside filesystem read operations without sanitization, it introduces a path traversal vector.

An attacker can exploit this behavior by forcing the verification engine to traverse out of the intended keys directory and reference a predictable, static system file instead.

JSON

```
// Token Header Executing a Path Traversal via the Key ID
{
    "kid": "../../../../../../../dev/null",
    "typ": "JWT",
    "alg": "HS256"
}
```

If the target system relies on a symmetric algorithm like **HS256**, it will read the targeted file's contents as a raw passphrase string. By targeting a consistently empty system file like `/dev/null` on Linux distributions, the file contents return an empty string (`""`). Consequently, an attacker can generate a completely valid forged signature by signing the modified token using an empty string as the symmetric key passphrase.

> 💡 **Additional Attack Surfaces:** If the application looks up the `kid` parameter value within a backend database query instead of the local filesystem, the parameter becomes a high-severity entry point for SQL Injection (SQLi) payloads.

### Additional High-Interest Header Parameters

Beyond key location vectors, secondary header fields can be abused to pivot into alternative vulnerability classes if baseline signature verification checks are bypassed or broken:

- **`cty` (Content Type):** Used to declare the media type of the token's payload. If signature validation is subverted, changing this header metadata parameter to specialized MIME types like `text/xml` or `application/x-java-serialized-object` can force the backend parsing logic into processing dangerous inputs, leading to **XML External Entity (XXE)** or **Insecure Deserialization** exploits.
    
- **`x5c` (X.509 Certificate Chain):** Allows public key certificates or certificate chains to be embedded explicitly into the token layout. Attackers can leverage this parameter to pass spoofed or rogue self-signed digital certificates (similar to a `jwk` injection). Complexities in X.509 certificate parsing libraries historically present distinct buffer and configuration risks (e.g., CVE-2017-2800 and CVE-2018-2633).
    

### JWT Algorithm Confusion Attacks

**Algorithm Confusion** (or key confusion) occurs when an identity backend can be manipulated into verifying an asymmetric token signature using a symmetric algorithm routine instead.

#### The Asymmetric vs. Symmetric Paradox

- **Asymmetric Algorithms (e.g., RS256):** Rely on a private key to generate signatures and a mathematically linked public key to verify them. The public key is non-sensitive and often exposed via public API endpoints so external systems can validate issued tokens.
    
- **Symmetric Algorithms (e.g., HS256):** Use a single shared secret passphrase to both generate and verify signatures; this string must remain strictly confidential.
    

#### Exploitation Mechanics

Vulnerabilities occur when developers use generic, algorithm-agnostic signature verification libraries that determine the validation math based purely on the token's internal `alg` header parameter. Consider a vulnerable abstraction flow:

JavaScript

```
// Simplified generic library verification logic
function verify(token, secretOrPublicKey) {
    let algorithm = token.getAlgHeader();
    if (algorithm == "RS256") {
        // Process secretOrPublicKey argument as an RSA Asymmetric Key object
    } else if (algorithm == "HS256") {
        // Process secretOrPublicKey argument as a raw Symmetric Passphrase String
    }
}
```

If the web application hardcodes the system's RSA public key string as the standard secondary configuration parameter (`verify(incomingToken, rsaPublicKey)`), a major flaw exposes itself:

1. The attacker changes the token's header from `"alg": "RS256"` to `"alg": "HS256"`.
    
2. The attacker modifies the payload claims (e.g., changing `"sub": "administrator"`).
    
3. The attacker signs this forged token with the symmetric **HS256** algorithm, using the server's publicly available **RSA Public Key string** as the literal signature password passphrase.
    
4. Upon ingestion, the generic verification library reads `"alg": "HS256"`. Following its logic branch, it treats the provided configuration argument (the RSA public key) as a literal, flat HMAC secret string.
    
5. The signature checks out successfully because the attacker used that exact same public key string to sign the token on their local machine.
    

Plaintext

```
⚠️ CRITICAL FOR ATTACK SUCCESS: The public key used to local-sign the HMAC payload must precisely mirror the backend copy down to the byte level—including exact encoding structure layouts (e.g., X.509 PEM format) and trailing whitespaces or non-printing carriage return characters (\n).
```

## 5. Solutions & Payloads (JWT) (Continuation)

### Lab 20: JWT authentication bypass via kid header path traversal

- **Vulnerability:** Unsanitized database key look-up allows directory traversal via the `kid` parameter, enabling an arbitrary file verification attack using `/dev/null`.
    
- **Solution Steps:**
    
    1. Intercept an authenticated session request and send it to Burp **Repeater**.
        
    2. In the **JWT Editor Keys** tab, click **New Symmetric Key**, click **Generate**, and manually overwrite the generated `"k"` value string property to an empty string (`""`). Save the key configuration.
        
    3. Return to the request tab and alter the session token header to inject a path traversal sequence targeting the empty virtual file system path:
        
        JSON
        
        ```
        { "alg": "HS256", "typ": "JWT", "kid": "../../../../../../../dev/null" }
        ```
        
    4. Modify the payload identity parameter value to `"sub": "administrator"`.
        
    5. Click **Sign**, choose the blank symmetric key, select **Don't modify header**, and send the request.
        
    6. Execute the administrative user deletion request from the resulting panel response to complete the lab.

## 4. Solutions & Payloads (JWT)

### Lab 1: JWT authentication bypass via flawed signature verification

- **Vulnerability:** The server decodes incoming token payloads without executing cryptographic validation checks against the signature string.
    
- **Solution Steps:**
    
    1. Intercept a legitimate `GET /my-account` request inside Burp Suite and send it to **Repeater**.
        
    2. Highlight the second segment of the session cookie value (the payload block) to load it inside the **Inspector** panel.
        
    3. Modify the identifier value inside the subject parameter claim from `"sub": "wiener"` to `"sub": "administrator"`.
        
    4. Click **Apply changes**, modify the destination directory path to `/admin`, and execute the request to access the restricted administrative interface.
        

### Lab 2: JWT authentication bypass via unsecured tokens

- **Vulnerability:** The identity verification gateway accepts unsigned tokens that specify an algorithm value of `none`.
    
- **Solution Steps:**
    
    1. Extract a valid session JWT token from an authenticated application request.
        
    2. Modify the token's header block using the **Inspector** panel to set the algorithm type parameter to `none`:
        
        JSON
        
        ```
        {"alg": "none", "typ": "JWT"}
        ```
        
    3. Alter the payload data layer to change the user identifier value to administrative contexts: `"sub": "administrator"`.
        
    4. Strip the cryptographic signature string from the third segment of the JWT, ensuring the final dot delimiter remains intact (`header.payload.`).
        
    5. Pass the modified token string to the application server to access the administrative panel at `/admin`.
        

### Lab 3: JWT authentication bypass via weak signing key

- **Vulnerability:** The application uses a weak symmetric secret key (`secret1`) to sign and verify HMAC session tokens, leaving it vulnerable to offline brute-force attacks.
    
- **Solution Steps:**
    
    1. Capture an authenticated session cookie and save the complete raw token string.
        
    2. Run **Hashcat** using the specialized JWT mode module (`-m 16500`) against a wordlist of common secret strings:
        
        Bash
        
        ```
        hashcat -a 0 -m 16500 eyJhbGciOiJIUzI1Ni... secrets_wordlist.txt
        ```
        
    3. Take the recovered symmetric string key (`secret1`), base64-encode it, and import it into the **Burp JWT Editor Keys** extension tab as a **New Symmetric Key**.
        
    4. Modify the target application token's payload identifier string value to read `"sub": "administrator"`.
        
    5. Use the imported symmetric key to re-sign the modified token structure, then submit the forged token to the backend server.
        

### Lab 4: JWT authentication bypass via jwk header injection

- **Vulnerability:** The verification engine trusts public keys embedded inside the user-controlled `jwk` header parameter without validating their source.
    
- **Solution Steps:**
    
    1. Open the **JWT Editor Keys** panel within Burp Suite and click **New RSA Key** to generate a custom cryptographic key pair.
        
    2. Intercept an administrative request path link (`/admin`) and pass it into **Repeater**.
        
    3. In the extension's JWT editor tab, modify the identity subject string to `"sub": "administrator"`.
        
    4. Select **Attack > Embedded JWK**, specify your generated RSA key structure, and verify that the public key data block is injected into the token's header.
        
    5. Send the modified request to bypass the authentication check and access the backend administration panel.
        

### Lab 5: JWT authentication bypass via jku header injection

- **Vulnerability:** The backend server fetches verification keys from untrusted external domains specified in the `jku` header parameter.
    
- **Solution Steps:**
    
    1. Generate a new custom RSA key pair within the **JWT Editor Keys** workbench area.
        
    2. Right-click the newly generated key structure and select **Copy Public Key as JWK**.
        
    3. Navigate to your external exploit delivery server and paste the public key details into an empty JSON keys array:
        
        JSON
        
        ```
        {"keys": [ { "kty": "RSA", "e": "AQAB", ... } ]}
        ```
        
    4. Save the payload and copy the explicit URL location of the hosted file.
        
    5. In Burp Repeater, intercept the administrative target request and modify the token's header by adding a `jku` parameter pointing to your exploit server URL, while updating the `kid` to match your public key ID.
        
    6. Change the token payload identity sub claim to `"sub": "administrator"`, sign the final token using your private RSA key, and submit it to complete the lab.

### Lab 6: JWT authentication bypass via algorithm confusion

- **Vulnerability:** The application uses an algorithm-agnostic verification function, allowing an attacker to pass an asymmetric public key string as an HMAC secret.
    
- **Solution Steps:**
    
    1. Fetch the server's public key by browsing directly to the standard target asset path location: `/jwks.json`. Copy the public JWK object details.
        
    2. In the **JWT Editor Keys** panel, click **New RSA Key**, paste the copied JWK payload, choose the **PEM** structure radio button, and copy the resulting public key PEM text block to your clipboard.
        
    3. Pass the PEM text block into the **Decoder** tab and select **Base64-encode**.
        
    4. Return to **JWT Editor Keys**, click **New Symmetric Key**, click **Generate**, and replace the placeholder signature value inside the `"k"` parameter with your raw Base64-encoded PEM string. Save the configuration.
        
    5. In **Repeater**, rewrite the header value to `"alg": "HS256"`, alter the payload identity to `"sub": "administrator"`, and click **Sign** using the symmetric public-key passphrase proxy wrapper.
        
    6. Submit the request to bypass access controls and access the `/admin` path.
        

### Lab 7: JWT authentication bypass via algorithm confusion with no exposed key

- **Vulnerability:** Algorithm confusion vulnerability combined with hidden key infrastructure. Public key strings can be mathematically derived by analyzing signature deltas from multiple tokens.
    
- **Solution Steps:**
    
    1. Capture two distinct valid session tokens by logging in, logging out, and logging back in again. Save both raw strings.
        
    2. Run a cryptographic derivation container utility (such as `sig2n`) inside your local terminal execution context to calculate the public key modulus `n`:
        
        Bash
        
        ```
        docker run --rm -it portswigger/sig2n <token1> <token2>
        ```
        
    3. The derivation script outputs several potential public keys along with sample pre-signed tokens. Test the generated sample tokens inside **Repeater** against `/my-account` until a `200 OK` response isolates the working X.509 key format structure.
        
    4. Copy the identified working Base64-encoded X.509 public key string from the terminal log, go to **JWT Editor Keys**, create a **New Symmetric Key**, and paste the key string directly into the `"k"` property field.
        
    5. In your `/admin` Repeater request, change the algorithm parameter block header to `"alg": "HS256"`, change the internal target identifier payload to `"sub": "administrator"`, and click **Sign** with the newly saved key structure.
        
    6. Dispatch the forged token payload to gain full administrator status.
        

## 5. Remediation & Prevention Defense Models (JWT)

### Core Protection Engineering Requirements

1. **Modern, Strict Library Configurations:** Implement robust, modern JWT management engines that completely isolate or deprecate unauthenticated method calls. Ensure parsing wrappers explicitly block asymmetric-to-symmetric key mutations during evaluation.
    
2. **Strict Algorithm Enforcement:** Never rely on user-supplied header properties (`alg`) to dictate backend verification logic. Force the application to use a hardcoded, immutable algorithm verification standard (e.g., executing _only_ `RS256` validation logic regardless of what the token header says).
    
3. **Strict Parameter Validation:** If headers like `jku` or `kid` are utilized, enforce rigid validation:
    
    - Maintain a strict host allow-list for external key distribution URLs (`jku`).
        
    - Sanitize or filter directory traversal sequences (`../`) and non-alphanumeric patterns from the Key ID (`kid`) field.
        

### Operational Identity Best Practices

- **Enforce Token Expiration (`exp`):** Always implement brief validity windows on issued tokens to limit replay and exploitation windows.
    
- **Bind Audience Parameters (`aud`):** Populate the audience claim field to ensure authorization credentials cannot be reused across cross-domain environments.
    
- **Avoid Parameter Leakage:** Never pass session JWT tokens within insecure GET URL string parameters where they risk exposure via browser logs or referrer headers.
    
- **Revocation Architectures:** Maintain a server-side denylist or real-time verification mapping to gracefully invalidate or revoke tokens immediately upon user logout requests.
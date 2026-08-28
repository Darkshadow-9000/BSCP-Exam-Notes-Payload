BSCP Exam Cheatsheet & Payloads

    Personal cheatsheet for Burp Suite Certified Practitioner (BSCP) Exam

📋 Exam Structure

The BSCP exam consists of two web applications, two hours each. Each application has three stages:

Stage 1: Get Access to Any User

Goal: Obtain access to any user account

Common Vulnerabilities:

    XSS (Cross-Site Scripting)
    DOM-based vulnerabilities
    Authentication bypasses
    Web cache poisoning
    HTTP Host header attacks
    HTTP request smuggling

Stage 2: Privilege Escalation

Goal: Promote yourself to administrator or steal admin data

Common Vulnerabilities:

    SQL Injection
    CSRF (Cross-Site Request Forgery)
    Insecure deserialization
    OAuth authentication flaws
    JWT attacks
    Access control vulnerabilities

Stage 3: File System Access

Goal: Read /home/carlos/secret from the file system

Common Vulnerabilities:

    SSRF (Server-Side Request Forgery)
    XXE (XML External Entity) injection
    OS command injection
    SSTI (Server-Side Template Injection)
    Directory/Path traversal
    Insecure deserialization
    File upload vulnerabilities

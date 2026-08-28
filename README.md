# 🎯 BSCP Exam Cheatsheet & Payloads

> **Personal cheatsheet for Burp Suite Certified Practitioner (BSCP) Exam**
>
> *A comprehensive guide to help aspiring security professionals ace the BSCP certification exam. Built by hackers, for hackers.*

---

## 📋 Exam Structure Overview

The **BSCP exam** consists of **two independent web applications**, with **two hours per application**. Each application contains **three mandatory stages** that must be completed sequentially.

| Stage | Goal | Time Limit |
|-------|------|-----------|
| **Stage 1** | Gain Access to Any User Account | Part of 2 hrs |
| **Stage 2** | Escalate Privileges to Admin | Part of 2 hrs |
| **Stage 3** | Read `/home/carlos/secret` | Part of 2 hrs |

---

## 🔓 Stage 1: Get Access to Any User

### **Goal:** Obtain access to any user account

### **Common Vulnerabilities:**

| Vulnerability | Description | Payload Tip |
|---|---|---|
| **XSS (Cross-Site Scripting)** | Inject malicious scripts into web pages | Test input fields for `<script>alert(1)</script>` |
| **DOM-based Vulnerabilities** | Unsafe DOM manipulation | Check browser console & trace data flow |
| **Authentication Bypasses** | Weak login mechanisms | Try SQL injection, default creds, logic flaws |
| **Web Cache Poisoning** | Exploit caching headers | Manipulate `X-Forwarded-Host`, `Host` headers |
| **HTTP Host Header Attacks** | Abuse host header processing | Use `Host: attacker.com` or `X-Forwarded-Host` |
| **HTTP Request Smuggling** | Desynchronize proxy/server requests | Test `CL.TE`, `TE.CL`, `TE.TE` techniques |

### **💡 Tips & Tricks for Stage 1:**

- ✅ **Always check the HTML source** – Look for hidden values, comments, and encoded data
- ✅ **Test every input field** – Even "read-only" fields can be exploited
- ✅ **Use Burp's Collaborator** – Detect out-of-band vulnerabilities (SSRF, XXE, etc.)
- ✅ **Check response headers** – Look for `Set-Cookie`, `Location`, `X-Custom-Header`
- ✅ **Intercept all requests** – Don't miss API calls, WebSocket connections, or AJAX requests
- ✅ **Look for information disclosure** – Stack traces, API keys, usernames in responses
- ✅ **Test authentication reset** – Weak email verification or token reuse

---

## ⚡ Stage 2: Privilege Escalation

### **Goal:** Promote yourself to administrator or steal admin data

### **Common Vulnerabilities:**

| Vulnerability | Description | Exploitation Tip |
|---|---|---|
| **SQL Injection** | Inject SQL commands into queries | Test: `' OR '1'='1`, `UNION SELECT`, time-based blind |
| **CSRF (Cross-Site Request Forgery)** | Force user actions without consent | Check for missing CSRF tokens, weak token validation |
| **Insecure Deserialization** | Deserialize untrusted data | Look for serialized objects in cookies/parameters |
| **OAuth Authentication Flaws** | Exploit OAuth flow vulnerabilities | Check redirect URIs, scope validation, state parameter |
| **JWT Attacks** | Manipulate JSON Web Tokens | Try `none` algorithm, key confusion, weak secrets |
| **Access Control Vulnerabilities** | Bypass authorization checks | Test parameter tampering, direct object references (IDOR) |

### **💡 Tips & Tricks for Stage 2:**

- ✅ **Analyze user roles/permissions** – Look at JWT claims, cookies, session tokens
- ✅ **Test IDOR vulnerabilities** – Change user IDs: `/user/1`, `/user/2`, `/user/admin`
- ✅ **Intercept admin requests** – See what privileges admins actually have
- ✅ **Check for privilege escalation chains** – Combine multiple low-impact bugs
- ✅ **Decode JWT tokens** – Use [jwt.io](https://jwt.io) or Burp's decoder
- ✅ **Look for default admin accounts** – Check for `/admin`, `/administrator`, default credentials
- ✅ **Test email parameter manipulation** – Change email to admin's email in password reset
- ✅ **Check CSRF protection** – Missing tokens = easy CSRF exploitation

---

## 📁 Stage 3: File System Access

### **Goal:** Read `/home/carlos/secret` from the file system

### **Common Vulnerabilities:**

| Vulnerability | Description | Payload Example |
|---|---|---|
| **SSRF (Server-Side Request Forgery)** | Make server perform unintended requests | `http://localhost:8080`, `file:///etc/passwd` |
| **XXE (XML External Entity) Injection** | Exploit XML parsers | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` |
| **OS Command Injection** | Execute arbitrary system commands | `; cat /home/carlos/secret`, `\| ls -la` |
| **SSTI (Server-Side Template Injection)** | Inject template syntax | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` |
| **Directory/Path Traversal** | Access files outside intended directory | `../../../etc/passwd`, `....//....//etc/passwd` |
| **Insecure Deserialization** | RCE via unsafe deserialization | Java gadgets, PHP object injection |
| **File Upload Vulnerabilities** | Upload malicious files | PHP shells, JSP shells, polyglot files |

### **💡 Tips & Tricks for Stage 3:**

- ✅ **Start with SSRF** – Try to access `localhost`, `127.0.0.1`, internal IPs
- ✅ **Test all file upload endpoints** – Check for execution permissions (PHP, JSP, ASP, etc.)
- ✅ **Use XXE for file reading** – Combine XXE with parameter entities for SSRF
- ✅ **Fuzz for template injection** – Test `{{}}`, `${}`, `<%%>`, `#{}`
- ✅ **Check error messages** – Stack traces often reveal file paths and technologies
- ✅ **Use polyglot files** – Combine image + PHP to bypass extension filters
- ✅ **Test path traversal variations** – `../`, `..\\`, `....//`, `..%252f`
- ✅ **Check for null byte injection** – Some systems: `file.php%00.jpg`
- ✅ **Monitor all responses** – The secret might be in response headers, comments, or error pages

---

## 🛠️ Essential Tools & Resources

| Tool | Purpose |
|------|---------|
| **Burp Suite Community** | Primary web proxy & testing tool |
| **Burp Intruder** | Automated fuzzing and brute-forcing |
| **Repeater** | Manual request manipulation |
| **Decoder** | Encode/decode data (Base64, URL, JWT, etc.) |
| **Collaborator** | Out-of-band vulnerability detection |

---

## 🔑 General Exam Tips

1. **⏱️ Time Management** – Stage 3 is often the hardest; don't get stuck on Stage 1
2. **📝 Take Notes** – Document every finding, bypass, and payload that works
3. **🔍 Enumeration First** – Thoroughly map the application before exploiting
4. **🔄 Test Systematically** – Go through OWASP Top 10 methodically
5. **🧠 Think Like a Developer** – Understand how the app works to find flaws
6. **🚨 Check Error Handling** – Weak error handling = information disclosure
7. **💾 Burp Extensions** – Use helpful extensions (Logger++, Autorize, etc.)
8. **🎯 Focus on the Goal** – Each stage has a specific objective
9. **📊 Document Your Path** – Screenshot exploits; shows your methodology
10. **🔐 Try Common Bypasses** – Default credentials, SQL injection, CSRF bypasses

---

## 🚀 Useful Payloads & Techniques

### **SQL Injection Starters:**
```
' OR '1'='1
' OR 1=1 --
' UNION SELECT NULL, NULL, NULL --
'; DROP TABLE users; --
```

### **XSS Starters:**
```
<script>alert(1)</script>
<img src=x onerror="alert(1)">
<svg onload="alert(1)">
javascript:alert(1)
```

### **SSRF Starters:**
```
http://localhost
http://127.0.0.1
http://169.254.169.254/latest/meta-data/
file:///etc/passwd
```

### **Path Traversal Starters:**
```
../../../etc/passwd
....//....//....//etc/passwd
..%252f..%252fetc%252fpasswd
```

---

## 📚 How to Use This Repository

1. **Study the stages** – Understand each vulnerability type
2. **Review payloads** – Memorize common exploitation techniques
3. **Practice on PortSwigger** – Use [PortSwigger Web Security Academy](https://portswigger.net/web-security) labs
4. **Build muscle memory** – Repetition is key to success
5. **Share and improve** – Contribute new payloads and techniques

---

## 👥 Contributing

This repository is a community effort. If you discover new bypasses, payloads, or techniques during your exam prep or after passing:

- Fork this repo
- Add your findings
- Submit a pull request

Together, we build better resources for the security community!

---

## ⚖️ Disclaimer

This repository is for **educational purposes only**. Use this knowledge responsibly and only on systems you have permission to test. Unauthorized access to computer systems is illegal.

**Happy hacking! 🚀**

---

*Last Updated: 2026* 

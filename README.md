# Browser Key Authentication — prototype

A working **vanilla HTML/CSS/JavaScript frontend** and **Node.js backend** demonstrating password-encrypted private keys and **per-request public-key signatures**. No npm packages, frameworks, crypto libraries, or external services are required. Node's built-in `node:http` is sufficient for this small API, so Express is deliberately not included.

> **A prototype, not a production identity system.** Use `localhost` for testing. HTTPS and further operational hardening are required before exposing this service to other machines.

## Requirements and start

- Node.js **20 or newer** (tested using Node 22).
- A current browser with Web Crypto and IndexedDB (Chrome, Edge, Firefox, Safari).

1. Extract the ZIP.
2. Open a terminal in the extracted `browser-key-auth-prototype` folder.
3. Run:

   ```bash
   npm start
   ```

   You can also run `node backend/server.js` directly; npm is optional and installs nothing.

4. Open **http://localhost:3000/** in the browser **on the same computer**. Do not use a `file://` URL or `http://127.0.0.1:3000`: the prototype intentionally checks that the page origin is exactly `http://localhost:3000`.

The Node terminal prints **random, per-run invitation codes** for these hardcoded allowlisted emails:

- `alice@example.com`
- `bob@example.com`

The console shows the **actual invitation codes**. They are **not hardcoded, shipped to the browser, or exposed through an unauthenticated API**. Email delivery is not implemented; the admin supplies the code manually for this local prototype.

The Node backend serves the static frontend and API from the **same origin**, avoiding CORS complexity. It listens on `127.0.0.1` by default, not on the public network.

### Try the complete flow

1. **Register:** Expand **Register a new account**, enter `alice@example.com`, paste the matching one-time code from the Node terminal, and select a password of at least 12 characters. Click **Authorize and register**. The server validates the invitation *before* the browser generates the key pair. On success the status changes to **Unlocked**.
2. **Make a protected request:** Click **GET /api/private/me**. The log should show **HTTP 200** and your email. Click **POST signed note** with a note and then **GET /api/private/notes**. The note should appear.
3. **Try the attacks:** Click **Replay last signed request**, **Tamper with signed body**, and **Unsigned request**. All should report **HTTP 401**. The replay test should report `CHALLENGE_USED`; tampering should report `BAD_SIGNATURE`; an unsigned request should report `AUTH_REQUIRED`.
4. **Lock/unlock:** Click **Lock now**. Your private key is discarded from the page's active JavaScript state. Enter a *wrong* password (it should fail), then the correct password (it should unlock). A page refresh also locks it.
5. **Export:** Click **Export encrypted backup**. Save the resulting JSON file. It contains the email, public key, PBKDF2 parameters and an **AES-GCM encrypted PKCS#8 private key**—not the plaintext private key.
6. **Delete:** Click **Delete local key**, then confirm. Status becomes **No local key**. **This deletes the browser copy only**; the server still recognizes that public key.
7. **Import:** Expand **Import an encrypted key backup**, select the JSON backup, enter its password, and click **Validate and import**. The restored key can immediately sign requests. This also works from another browser if you securely transfer the encrypted backup and password.
8. **Persist across restarts:** Restart Node. Existing public keys and notes remain in `backend/data/db.json` (a tiny JSON stand-in for a future database). Browser private keys remain in IndexedDB, still encrypted and locked until a password is entered.

After registering, the server does not show another invitation for that same email. Re-registration is intentionally blocked; use the encrypted backup for recovery on another browser.

## Folder layout

```text
browser-key-auth-prototype/
├── README.md
├── package.json     Node scripts, zero dependencies
├── frontend/
│   ├── index.html     HTML UI
│   ├── styles.css     CSS only
│   └── app.js         IndexedDB + Web Crypto + request signing
├── backend/
│   ├── server.js      Node HTTP server + built-in crypto
│   ├── .gitignore
│   └── data/db.json   Created after registration; never commit real user data
└── tests/
    ├── auth.test.js           HTTP integration/security tests
    └── browser-crypto.test.js Browser cryptography functions tested via Node Web Crypto
```

## How it works

**Key creation and local storage:** The browser generates an ECDSA P-256 key pair. For encryption it derives an AES-256-GCM key from the user's password via PBKDF2-HMAC-SHA256 with a fresh 16-byte salt and **600,000 iterations**, and uses a fresh 12-byte AES-GCM IV. It wraps the private key in encrypted PKCS#8 form. **Only the encrypted private key and the public key** go into IndexedDB. The encryption authenticates the email and public-key identity as associated data. Registration sends **only the public key** to the Node backend. The plaintext private key is present transiently during initial creation; the initial generated key is extractable solely so the browser can encrypt/wrap it.

**Unlocking:** After entering a password, `crypto.subtle.unwrapKey()` decrypts and imports the private key with **`extractable: false`** and only the `sign` usage. The app also signs and verifies a local check message to ensure the backup's public/private key pair matches. The unlocked `CryptoKey` is kept in JavaScript memory, **not persisted in its unlocked form**. A page refresh or Lock button removes the application's reference. Non-extractable **does not** stop malicious same-origin JavaScript from *using* the unlocked key, nor does it guarantee OS/hardware-level protection.

**Registration authorization:** The Node backend has a hardcoded allowlist. A randomly generated, per-email invitation code is printed only on the server terminal. `/api/enroll/start` checks the email + code and issues a five-minute enrollment token/challenge. The frontend then generates its key pair, encrypts the private key locally, and signs a registration proof. `/api/enroll/finish` verifies the new public key and signature, atomically consumes the enrollment token, persists the public key, and invalidates that email's invitation. A code represents **invitation possession**, not independently verified ownership of the email inbox. Production systems should use verified email ownership or a trusted admin issuance workflow.

**Every protected API request** (there is **no login session or bearer cookie**):

1. Client calls `POST /api/challenge` with the registered email.
2. Server returns 32 random bytes encoded as a base64url nonce (expires in 60 seconds).
3. Client signs the following UTF-8 string with ECDSA P-256 + SHA-256, with each field separated by a newline:

   ```text
   AUTH-DEMO-V1
   http://localhost:3000
   alice@example.com
   <nonce>
   POST
   /api/private/notes
   <base64url SHA256 of exact HTTP body bytes>
   ```

4. Client sends the actual API request with `X-Auth-Email`, `X-Auth-Nonce`, and `X-Auth-Signature` headers, including the body when needed.
5. Backend consumes the nonce **once**, checks that it belongs to that email and has not expired, reconstructs the signed message from the **actual HTTP method, raw request URL and raw body bytes**, verifies the signature against the registered public key, and only then executes the operation.

The signature is bound to the **server origin, user, nonce, method, URL (including query), and body hash**. Intercepted signed requests cannot be successfully replayed *after the nonce is consumed*; intercepted messages are still subject to active relay/race attacks without proper TLS. Request signing adds an extra round trip per protected operation.

### API endpoints

| Method + path | Authentication | Purpose |
|---|---|---|
| `GET /api/health` | None | Local health check |
| `POST /api/enroll/start` | Email + one-time invitation | Authorize enrollment and issue challenge |
| `POST /api/enroll/finish` | Enrollment token + new key's signature | Register user's public key |
| `POST /api/challenge` | Registered email (non-secret) | Issue a short-lived per-request nonce |
| `GET /api/private/me` | Signed request | Return account identity |
| `GET /api/private/notes` | Signed request | Read own sample notes |
| `POST /api/private/notes` | Signed request | Create own sample note |

The notes are test data for authentication, **not end-to-end encrypted**. They are stored in readable form in the demo server's JSON file.

## Automated tests (no test dependencies)

From the project root run:

```bash
npm test
```

Or without npm, from the project root:

```bash
node --test tests/*.test.js
```

Tests cover: unauthorized enrollment, successful public-key registration, missing signatures, signed GET/POST, challenge replay, altered request bodies, account isolation, wrong-key signatures, Origin rejection, encrypted key export format, correct/wrong decryption passwords, non-extractable imported keys, and tampered backups. They use only Node's standard library.

## Important security boundaries

- **HTTPS** is required for remote use. Plain HTTP is acceptable only for this `localhost` demonstration; `localhost` is treated as a secure context by modern browsers. TLS protects delivered JavaScript, request confidentiality, and active on-path attacks not stopped by signed nonces alone.
- **An unlocked key is usable by malicious same-origin JavaScript**, even when marked non-extractable. XSS, malicious browser extensions, compromised frontend delivery, and full device compromise are not solved by this design. We include a restrictive Content Security Policy and avoid `innerHTML`, but those do not guarantee immunity.
- **A copied encrypted backup can be brute-forced offline** if the password is weak. PBKDF2 slows attempts but is not a substitute for a strong, unique passphrase; it is used because it is native in browsers, not because it is the strongest available KDF.
- **The server stores public keys, not passwords or private keys.** A database-only breach cannot by itself produce valid signatures. However, an attacker who can *modify* the database may replace public keys; production requires access control, integrity monitoring, backups, and secure enrollment/key rotation.
- **A stolen unlocked browser context can sign requests.** Our per-request design avoids replay of stolen bearer cookies by not using bearer cookies, but does not prevent a live attacker or malicious script from signing new requests while a key is unlocked.
- **Backend challenges and invitations live in process memory.** For multiple Node instances, use shared atomic nonce storage (for example Redis/DB transactions). In-memory rate limits are only a demonstration, not an anti-abuse system. The JSON storage uses synchronous atomic file replacement and is intended for a single instance.
- **Deletion is not revocation.** Delete local key removes the browser copy but leaves its registered public key. Production needs admin-authenticated key revocation, replacement and account recovery. For a complete local reset, stop Node, delete `backend/data/db.json`, restart Node, and then delete local browser keys or use a fresh browser profile. **This also erases demo notes.**
- **Registration failure after local storage:** The browser stores the encrypted key before sending the final registration proof so a successful registration will not lose its key if storage fails. If the network fails after the local key is saved, a local encrypted key may exist even though registration is incomplete. You can export the backup, delete that local entry, and register again if the server has not registered the email. If registration did complete, restore the same backup instead.
- **Production upgrades:** Add verified enrollment, proper authorization/business rules, safe admin recovery/revocation, durable distributed nonce consumption, observability, operational rate limiting, and secure HTTPS deployment before putting real users/data behind this service. Security review is strongly recommended.

## Change port / deploy behind an HTTPS reverse proxy

By default: `HOST=127.0.0.1`, `PORT=3000`, `APP_ORIGIN=http://localhost:3000`. The browser must visit the exact configured origin. If you change the port, set `APP_ORIGIN` to the same origin. For example:

```bash
# Linux/macOS
PORT=4000 APP_ORIGIN=http://localhost:4000 node backend/server.js
```

```powershell
# Windows PowerShell, from project root
$env:PORT = '4000'
$env:APP_ORIGIN = 'http://localhost:4000'
node .\backend\server.js
```

For remote deployment, configure `APP_ORIGIN=https://your-real-hostname`, place Node behind an HTTPS reverse proxy, and make sure it preserves the expected `Host` header. This prototype intentionally does not contain a TLS certificate manager.

## Replacing the demo database

In `backend/server.js`, replace the `loadDatabase()` and `saveDatabase()` JSON-file layer and the in-memory challenge/invitation maps with real persistence (e.g. MongoDB), using a repository/data-access layer. Preserve: one-time atomic challenge use, registered public-key lookups, per-account notes/permissions, key uniqueness, enrollment authorization, and the signature/nonce validation. The cryptographic protocol does not depend on MongoDB.

## Reference

- [MDN — Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 9421 — HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) (conceptual guidance; this prototype's educational wire format is **not** a conforming implementation of RFC 9421)

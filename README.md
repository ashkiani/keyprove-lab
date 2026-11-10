# KeyProve Lab — RFC 9421 prototype

A working **vanilla HTML/CSS/JavaScript frontend** and **Node.js backend** demonstrating password-encrypted private keys and **RFC 9421 HTTP Message Signatures on every protected API request**. No npm packages, frameworks, crypto libraries, or external services are required. Node's built-in `node:http` is sufficient for this small API, so Express is deliberately not included.

> **A prototype, not a production identity system.** Use `localhost` for testing. HTTPS and further operational hardening are required before exposing this service to other machines.

## Requirements and start

- Node.js **20 or newer** (tested using Node 22).
- A current browser with Web Crypto and IndexedDB (Chrome, Edge, Firefox, Safari).

1. Extract the ZIP.
2. Open a terminal in the extracted `keyprove-lab-rfc9421` folder.
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

### Upgrading from the original prototype

If you previously registered `alice@example.com` or `bob@example.com`, your browser still has its password-encrypted private key, and the original Node server has the matching public key in its created `backend/data/db.json` file. To retain both:

1. Stop the old Node server.
2. **Copy the old `backend/data/db.json` into the new project's `backend/data/db.json`**, or replace the source files in your existing directory **without deleting its data file**. It is excluded from Git/ZIP on purpose because it is runtime data.
3. Start the updated backend with `npm start` at the **same** `http://localhost:3000` origin. Your old IndexedDB keys and encrypted backups are still usable; no re-enrollment is needed. Do not run both versions on the same port.

Without the original server database, the newly started backend will not recognize the existing public key even though your browser still has the encrypted private key. Keep a backup of both the encrypted key file and server data before upgrading. Requests from a still-open old frontend tab will fail until reloaded because the old `X-Auth-*` signing format is no longer accepted.

### Try the complete flow

1. **Register:** Expand **Register a new account**, enter `alice@example.com`, paste the matching one-time code from the Node terminal, and select a password of at least 12 characters. Click **Authorize and register**. The server validates the invitation *before* the browser generates the key pair. On success the status changes to **Unlocked**.
2. **Make a protected request:** Click **GET /api/private/me**. The log should show **HTTP 200** and your email. Click **POST signed note** with a note and then **GET /api/private/notes**. The note should appear.
3. **Try the attacks:** Click **Replay last signed request**, **Tamper with signed body**, and **Unsigned request**. All should report **HTTP 401**. The replay test reports `CHALLENGE_USED`, body tampering reports `BAD_DIGEST` (RFC 9530), and an unsigned request reports `AUTH_REQUIRED`.
4. **Lock/unlock:** Click **Lock now**. Your private key is discarded from the page's active JavaScript state. Enter a *wrong* password (it should fail), then the correct password (it should unlock). A page refresh also locks it.
5. **Export:** Click **Export encrypted backup**. Save the resulting JSON file. It contains the email, public key, PBKDF2 parameters and an **AES-GCM encrypted PKCS#8 private key**—not the plaintext private key.
6. **Delete:** Click **Delete local key**, then confirm. Status becomes **No local key**. **This deletes the browser copy only**; the server still recognizes that public key.
7. **Import:** Expand **Import an encrypted key backup**, select the JSON backup, enter its password, and click **Validate and import**. The restored key can immediately sign requests. This also works from another browser if you securely transfer the encrypted backup and password.
8. **Persist across restarts:** Restart Node. Existing public keys and notes remain in `backend/data/db.json` (a tiny JSON stand-in for a future database). Browser private keys remain in IndexedDB, still encrypted and locked until a password is entered.

After registering, the server does not show another invitation for that same email. Re-registration is intentionally blocked; use the encrypted backup for recovery on another browser.

## Folder layout

```text
keyprove-lab/
├── README.md
├── package.json     Node scripts, zero dependencies
├── frontend/
│   ├── index.html     HTML UI
│   ├── styles.css     CSS only
│   ├── app.js         IndexedDB + Web Crypto + request signing
│   └── http-signatures.js  Shared RFC 9421 request-signing profile
├── backend/
│   ├── server.js      Node HTTP server + built-in crypto
│   ├── .gitignore
│   └── data/db.json   Created after registration; never commit real user data
└── tests/
    ├── auth.test.js           HTTP integration/security tests
    ├── browser-crypto.test.js Browser cryptography functions tested via Node Web Crypto
    └── http-signatures.test.js RFC 9421 reference vector + Structured Fields tests
```

## How it works

**Key creation and local storage:** The browser generates an ECDSA P-256 key pair. For encryption it derives an AES-256-GCM key from the user's password via PBKDF2-HMAC-SHA256 with a fresh 16-byte salt and **600,000 iterations**, and uses a fresh 12-byte AES-GCM IV. It wraps the private key in encrypted PKCS#8 form. **Only the encrypted private key and the public key** go into IndexedDB. The encryption authenticates the email and public-key identity as associated data. Registration sends **only the public key** to the Node backend. The plaintext private key is present transiently during initial creation; the initial generated key is extractable solely so the browser can encrypt/wrap it.

**Unlocking:** After entering a password, `crypto.subtle.unwrapKey()` decrypts and imports the private key with **`extractable: false`** and only the `sign` usage. The app also signs and verifies a local check message to ensure the backup's public/private key pair matches. The unlocked `CryptoKey` is kept in JavaScript memory, **not persisted in its unlocked form**. A page refresh or Lock button removes the application's reference. Non-extractable **does not** stop malicious same-origin JavaScript from *using* the unlocked key, nor does it guarantee OS/hardware-level protection.

**Registration authorization:** The Node backend has a hardcoded allowlist. A randomly generated, per-email invitation code is printed only on the server terminal. `/api/enroll/start` checks the email + code and issues a five-minute enrollment token/challenge. The frontend then generates its key pair, encrypts the private key locally, and signs a registration proof. `/api/enroll/finish` verifies the new public key and signature, atomically consumes the enrollment token, persists the public key, and invalidates that email's invitation. A code represents **invitation possession**, not independently verified ownership of the email inbox. Production systems should use verified email ownership or a trusted admin issuance workflow.

**Every protected API request** (there is **no login session or bearer cookie**):

1. Client calls `POST /api/challenge` with the registered email.
2. Server returns an unpredictable, one-time, 32-byte nonce (base64url) valid for 60 seconds.
3. Browser calculates an **RFC 7638 JWK SHA-256 thumbprint** from the existing public key to use as a stable `keyid`. This does not alter or re-encrypt the local backup.
4. Browser constructs the RFC 9421 `Signature-Input` Inner List with required `created`, `nonce`, `keyid`, `alg="ecdsa-p256-sha256"`, and `tag="keyprove-v1"` parameters. `@method` and `@target-uri` are always covered; POST also covers `content-type` and `content-digest`.
5. POST requests contain an RFC 9530 `Content-Digest: sha-256=:...:` computed over **the exact HTTP body bytes**. The browser generates the RFC 9421 signature base and signs it with the existing unlocked ECDSA P-256 private key using SHA-256.
6. Browser sends normal RFC 9421 `Signature-Input` and `Signature` headers (no `X-Auth-*` headers). The signature bytes are the standard 64-byte P1363/`r || s` ECDSA representation encoded as an RFC Structured Field byte sequence (standard Base64).
7. Backend parses/validates signature metadata, checks the registered `keyid`, consumes the one-time challenge, enforces mandatory component coverage, validates the body digest against the received bytes, builds the **same RFC 9421 signature base**, and verifies the public-key signature before executing the request.

Illustrative signed POST request (placeholders are not valid signatures):

```http
POST /api/private/notes HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Content-Digest: sha-256=:<BASE64_SHA256_OF_BODY>:
Signature-Input: sig1=("@method" "@target-uri" "content-type" "content-digest");created=1794330000;nonce="<NONCE>";keyid="jwk-sha256-<JWK_THUMBPRINT>";alg="ecdsa-p256-sha256";tag="keyprove-v1"
Signature: sig1=:<BASE64_SIGNATURE>:

{"text":"Hello"}
```

The RFC 9421 signature base for that request has the following structure:

```text
"@method": POST
"@target-uri": http://localhost:3000/api/private/notes
"content-type": application/json
"content-digest": sha-256=:<BASE64_SHA256_OF_BODY>:
"@signature-params": ("@method" "@target-uri" "content-type" "content-digest");created=1794330000;nonce="<NONCE>";keyid="jwk-sha256-<JWK_THUMBPRINT>";alg="ecdsa-p256-sha256";tag="keyprove-v1"
```

**Supported RFC 9421 profile, not a general-purpose RFC 9421 toolkit:** KeyProve generates valid RFC 9421 request signatures for the specific component sets above. The verifier deliberately accepts **only one signature labelled `sig1`**, requires exactly the specified metadata and coverage, and supports only ECDSA P-256/SHA-256. It does not implement arbitrary covered component identifiers, request signature negotiation (`Accept-Signature`), other signature algorithms, multiple signatures, or response signing. Such signatures may be RFC-compliant but are intentionally rejected by KeyProve's stricter application policy. This profile follows the RFC's mechanism and is tested against the RFC's official ECDSA P-256 example, **but the prototype has not been independently security audited or certified**.

**Backward compatibility:** Existing v1 IndexedDB encrypted key records, exports, and server JSON databases remain readable without re-registration **provided you retain the original server database**. The previous custom `AUTH-DEMO-V1` / `X-Auth-*` request authentication **is intentionally replaced**, not accepted alongside RFC 9421. Both sides must run the updated version. New request signatures cannot be replayed after challenge consumption; signed request-body metadata cannot be substituted without detection.

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

Tests cover: unauthorized enrollment, successful public-key registration, RFC 9421 signed GET/POST using the actual frontend signer, challenge replay, altered request bodies/digests, path/header tampering, malformed and under-covered signatures, algorithm/tag enforcement, account isolation, wrong-key signatures, Origin rejection, and encryption/decryption of non-extractable private keys. The RFC signing tests additionally verify the **official ECDSA P-256 reference signature from RFC 9421 Appendix B.2.4**. They use only Node's standard library.

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
- [RFC 9421 — HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html), especially §§2.3, 2.5, 3.3.4, 4 and Appendix B.2.4
- [RFC 9530 — Digest Fields](https://www.rfc-editor.org/rfc/rfc9530.html)
- [RFC 7638 — JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
- [RFC 8941 — Structured Field Values for HTTP](https://www.rfc-editor.org/rfc/rfc8941.html) (base field format; current update is RFC 9651)

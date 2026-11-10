# Changelog

## 1.1.0 — RFC 9421 signing profile

**Preserved unchanged:** existing v1 encrypted private-key bundle format, PBKDF2-SHA256 and AES-GCM encryption, IndexedDB storage, password unlock, non-extractable imported private keys, encrypted backup export/import, email allowlist and one-time admin invitations, registration signature, signed notes, lock/unlock, server JSON database schema, and mandatory per-request challenges.

**Updated:**
- Replaced custom `AUTH-DEMO-V1` signing string with RFC 9421 signature bases.
- Replaced `X-Auth-*` request headers with RFC 9421 `Signature-Input` and `Signature` Structured Fields.
- Added RFC 9530 `Content-Digest` covering exact POST body bytes and signed `content-type`.
- Added `keyid` using RFC 7638 SHA-256 JWK thumbprint (derived from existing registered public keys, no DB migration).
- Added mandatory signed `created`, `nonce`, `keyid`, `alg`, `tag` metadata.
- Preserved mandatory 60-second one-time server nonces and atomically consumed challenges.
- Added a shared browser/Node request-signing helper module (`frontend/http-signatures.js`).
- Added official RFC 9421 Appendix B.2.4 ECDSA vector verification and additional negative security tests.
- Updated interface title and README.

**Migration:** Deploy browser and Node code together. Existing registered users and encrypted backups work without re-enrollment. Old signed requests are rejected, and public keys are not changed. For the same origin (`http://localhost:3000`), IndexedDB entries are automatically reused. **Preserve or copy the original `backend/data/db.json` into the new project**; it contains the registered public keys and demo notes and is intentionally not bundled in the ZIP.

**Scope:** KeyProve implements a constrained RFC 9421 request-signing/verifying profile for its application, **not** a general RFC 9421 implementation accepting arbitrary algorithms, signature labels, components, multiple signatures, or signed responses. This is still a prototype requiring security review and production hardening.

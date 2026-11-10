/**
 * Browser Key Authentication prototype — zero third-party dependencies.
 * HTTP: built-in node:http. Cryptography: built-in node:crypto.
 * Local JSON simulates the user database. Replace it with a DB later.
 */
import { createServer } from 'node:http';
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify as verifySignature } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const FRONTEND = join(HERE, '../frontend');
const APP_ORIGIN = process.env.APP_ORIGIN || 'http://localhost:3000';
const EXPECTED_HOST = new URL(APP_ORIGIN).host;
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_FILE = process.env.DEMO_DATA_FILE || join(HERE, 'data', 'db.json');
const ALLOWED_EMAILS = ['alice@example.com', 'bob@example.com']; // Demo admin allowlist.
const ENROLL_TTL_MS = 5 * 60_000;
const REQUEST_TTL_MS = 60_000;
const RATE_WINDOW_MS = 60_000;
const pendingEnrollments = new Map();
const pendingChallenges = new Map();
const rateBuckets = new Map();
const inviteCodes = new Map();

function loadDatabase() {
  if (!existsSync(DATA_FILE)) return { users: {}, notes: {} };
  const parsed = JSON.parse(readFileSync(DATA_FILE, 'utf8'));
  if (!parsed || !parsed.users || typeof parsed.users !== 'object' || !parsed.notes
      || typeof parsed.notes !== 'object') throw new Error('Invalid demo database');
  return parsed;
}
let db = loadDatabase();
function saveDatabase() {
  mkdirSync(dirname(DATA_FILE), { recursive: true });
  const temp = `${DATA_FILE}.${process.pid}.tmp`;
  writeFileSync(temp, JSON.stringify(db, null, 2) + '\n', { mode: 0o600 });
  renameSync(temp, DATA_FILE);
}
function emailOf(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9._+\-]{0,63}@[a-z0-9.-]{1,190}\.[a-z]{2,30}$/.test(email)
    && !email.includes('..') ? email : null;
}
function token(n = 32) { return randomBytes(n).toString('base64url'); }
function sha256B64(bytes) { return createHash('sha256').update(bytes).digest('base64url'); }
function equalSecret(a, b) {
  const h1 = createHash('sha256').update(String(a)).digest();
  const h2 = createHash('sha256').update(String(b)).digest();
  return timingSafeEqual(h1, h2);
}
function b64url(value, length) {
  return typeof value === 'string' && value.length === length && /^[A-Za-z0-9_-]+$/.test(value);
}
function publicKeyFromJwk(jwk) {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk) || jwk.kty !== 'EC'
      || jwk.crv !== 'P-256' || !b64url(jwk.x, 43) || !b64url(jwk.y, 43)
      || Object.hasOwn(jwk, 'd')) throw new Error('Expected an ECDSA P-256 public key');
  const normalized = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  const key = createPublicKey({ key: normalized, format: 'jwk' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('Unsupported public key');
  }
  return { jwk: normalized, key };
}
function verifyP256(key, message, signature) {
  if (!b64url(signature, 86)) return false;
  const sig = Buffer.from(signature, 'base64url');
  return sig.length === 64 && verifySignature('sha256', Buffer.from(message, 'utf8'),
    { key, dsaEncoding: 'ieee-p1363' }, sig);
}
function registrationMessage(email, enrollToken, challenge, jwk) {
  return ['ENROLL-V1', APP_ORIGIN, email, enrollToken, challenge, jwk.x, jwk.y].join('\n');
}
function requestMessage(email, nonce, method, pathAndQuery, bodyHash) {
  return ['AUTH-DEMO-V1', APP_ORIGIN, email, nonce, method, pathAndQuery, bodyHash].join('\n');
}
function rateLimit(name, identity, max) {
  const k = `${name}:${identity}`;
  let bucket = rateBuckets.get(k);
  const now = Date.now();
  if (!bucket || bucket.expires <= now) bucket = { count: 0, expires: now + RATE_WINDOW_MS };
  bucket.count++;
  rateBuckets.set(k, bucket);
  return bucket.count <= max;
}

for (const email of ALLOWED_EMAILS) {
  if (!db.users[email]) inviteCodes.set(email, token(18));
}

const securityHeaders = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
};
function response(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(value));
}
function deny(res, status, code, message) {
  response(res, status, { ok: false, code, message });
}
class HttpError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
async function parseBody(req) {
  if (!/^application\/json(?:\s*;|\s*$)/i.test(req.headers['content-type'] || '')) {
    throw new HttpError(415, 'CONTENT_TYPE', 'Expected application/json');
  }
  const parts = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 16 * 1024) throw new HttpError(413, 'TOO_LARGE', 'JSON body exceeds 16 KB');
    parts.push(chunk);
  }
  const rawBody = Buffer.concat(parts);
  let body;
  try { body = JSON.parse(rawBody.toString('utf8')); }
  catch { throw new HttpError(400, 'BAD_JSON', 'Invalid JSON'); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new HttpError(400, 'BAD_JSON', 'Expected a JSON object');
  }
  return { body, rawBody };
}
function signedIdentity(req, rawBody) {
  const email = emailOf(req.headers['x-auth-email']);
  const nonce = req.headers['x-auth-nonce'];
  const signature = req.headers['x-auth-signature'];
  if (!email || !nonce || !signature || !db.users[email]) {
    throw new HttpError(401, 'AUTH_REQUIRED', 'Signed request required');
  }
  const pending = pendingChallenges.get(nonce);
  pendingChallenges.delete(nonce); // Synchronous one-time consumption BEFORE applying the requested action.
  if (!pending || pending.email !== email || pending.expires < Date.now()) {
    throw new HttpError(401, 'CHALLENGE_USED', 'Challenge missing, expired, or already used');
  }
  try {
    const { key } = publicKeyFromJwk(db.users[email].publicKey);
    const msg = requestMessage(email, nonce, req.method, req.url, sha256B64(rawBody));
    if (!verifyP256(key, msg, signature)) {
      throw new HttpError(401, 'BAD_SIGNATURE', 'Signature does not match this request');
    }
  } catch (err) {
    if (err instanceof HttpError) throw err;
    throw new HttpError(401, 'BAD_SIGNATURE', 'Signature verification failed');
  }
  return email;
}

function handleEnrollmentStart(req, res, body) {
  const email = emailOf(body.email);
  const code = body.inviteCode;
  if (!rateLimit('enroll-ip', req.socket.remoteAddress, 10)
      || !rateLimit('enroll-email', email || 'invalid', 10)) {
    return deny(res, 429, 'RATE_LIMIT', 'Too many enrollment attempts. Try again later.');
  }
  if (!email || typeof code !== 'string' || db.users[email] || !inviteCodes.has(email)
      || !equalSecret(code, inviteCodes.get(email))) {
    return deny(res, 403, 'ENROLL_DENIED', 'Registration not authorized. Ask the administrator.');
  }
  const enrollmentToken = token();
  const challenge = token();
  pendingEnrollments.set(enrollmentToken, { email, challenge, expires: Date.now() + ENROLL_TTL_MS });
  response(res, 200, { ok: true, token: enrollmentToken, challenge, expiresInSeconds: 300 });
}
function handleEnrollmentFinish(res, body) {
  const email = emailOf(body.email);
  const enrollmentToken = body.token;
  if (!email || !b64url(enrollmentToken, 43)) {
    return deny(res, 400, 'BAD_INPUT', 'Invalid enrollment payload');
  }
  const pending = pendingEnrollments.get(enrollmentToken);
  pendingEnrollments.delete(enrollmentToken);
  if (!pending || pending.email !== email || pending.expires < Date.now()
      || db.users[email] || !inviteCodes.has(email)) {
    return deny(res, 403, 'ENROLL_EXPIRED', 'Enrollment expired or account already registered');
  }
  try {
    const { jwk, key } = publicKeyFromJwk(body.publicKey);
    if (!verifyP256(key, registrationMessage(email, enrollmentToken, pending.challenge, jwk), body.signature)) {
      return deny(res, 403, 'BAD_SIGNATURE', 'Invalid registration signature');
    }
    db.users[email] = { publicKey: jwk, createdAt: new Date().toISOString() };
    db.notes[email] = [];
    saveDatabase();
    inviteCodes.delete(email);
    response(res, 201, { ok: true, email });
  } catch (err) {
    return deny(res, 400, 'BAD_KEY', 'Invalid public key or signature');
  }
}
function handleChallenge(req, res, body) {
  const email = emailOf(body.email);
  if (!email || !db.users[email]) return deny(res, 404, 'NOT_REGISTERED', 'Account is not registered');
  if (!rateLimit('challenge-ip', req.socket.remoteAddress, 120)
      || !rateLimit('challenge-email', email, 120)) {
    return deny(res, 429, 'RATE_LIMIT', 'Too many challenge requests');
  }
  const nonce = token();
  pendingChallenges.set(nonce, { email, expires: Date.now() + REQUEST_TTL_MS });
  response(res, 200, { ok: true, nonce, expiresInSeconds: 60 });
}
function handlePrivate(req, res, route, body, rawBody) {
  const email = signedIdentity(req, rawBody);
  if (route === '/api/private/me' && req.method === 'GET') {
    return response(res, 200, { ok: true, email, registeredAt: db.users[email].createdAt,
      mechanism: 'ECDSA P-256 signed requests' });
  }
  if (route === '/api/private/notes' && req.method === 'GET') {
    return response(res, 200, { ok: true, notes: db.notes[email] || [] });
  }
  if (route === '/api/private/notes' && req.method === 'POST') {
    const text = body?.text;
    if (typeof text !== 'string' || !text.trim() || text.length > 240) {
      return deny(res, 400, 'BAD_NOTE', 'Text must contain 1–240 characters');
    }
    const note = { id: token(12), text: text.trim(), createdAt: new Date().toISOString() };
    const notes = db.notes[email] || (db.notes[email] = []);
    notes.push(note);
    saveDatabase();
    return response(res, 201, { ok: true, note });
  }
  return deny(res, 404, 'NOT_FOUND', 'Unknown endpoint');
}
function serveFrontend(res, route) {
  const files = {
    '/': ['index.html', 'text/html; charset=utf-8'],
    '/index.html': ['index.html', 'text/html; charset=utf-8'],
    '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
    '/styles.css': ['styles.css', 'text/css; charset=utf-8']
  };
  const entry = files[route];
  if (!entry) return deny(res, 404, 'NOT_FOUND', 'Unknown page');
  res.writeHead(200, { 'Content-Type': entry[1] });
  res.end(readFileSync(join(FRONTEND, entry[0])));
}

const server = createServer(async (req, res) => {
  for (const [name, value] of Object.entries(securityHeaders)) res.setHeader(name, value);
  try {
    // Host + Origin checks guard against DNS rebinding and cross-origin browser requests.
    if (req.headers.host !== EXPECTED_HOST) {
      return deny(res, 403, 'BAD_HOST', 'Unexpected Host header');
    }
    if (req.headers.origin && req.headers.origin !== APP_ORIGIN) {
      return deny(res, 403, 'BAD_ORIGIN', 'Unexpected Origin header');
    }
    const url = new URL(req.url, APP_ORIGIN);
    const route = url.pathname;
    if (route === '/api/health' && req.method === 'GET') {
      return response(res, 200, { ok: true, name: 'Browser Key Auth demo' });
    }
    // Do not permit GET requests with bodies (the signature always covers an empty GET body).
    if (req.method === 'GET' && (req.headers['transfer-encoding']
        || Number(req.headers['content-length'] || 0) > 0)) {
      return deny(res, 400, 'GET_BODY', 'GET requests cannot have a body');
    }
    const isApiPost = req.method === 'POST' && route.startsWith('/api/');
    const parsed = isApiPost ? await parseBody(req) : { body: null, rawBody: Buffer.alloc(0) };
    if (route === '/api/enroll/start' && isApiPost) return handleEnrollmentStart(req, res, parsed.body);
    if (route === '/api/enroll/finish' && isApiPost) return handleEnrollmentFinish(res, parsed.body);
    if (route === '/api/challenge' && isApiPost) return handleChallenge(req, res, parsed.body);
    if (route.startsWith('/api/private/') && (req.method === 'GET' || req.method === 'POST')) {
      return handlePrivate(req, res, route, parsed.body, parsed.rawBody);
    }
    if (route.startsWith('/api/')) return deny(res, 404, 'NOT_FOUND', 'Unknown API endpoint');
    if (req.method !== 'GET') return deny(res, 405, 'METHOD', 'Method not allowed');
    return serveFrontend(res, route);
  } catch (err) {
    if (err instanceof HttpError) return deny(res, err.status, err.code, err.message);
    console.error('Unexpected server error:', err);
    return deny(res, 500, 'INTERNAL_ERROR', 'Unexpected server error');
  }
});

const cleaner = setInterval(() => {
  const now = Date.now();
  for (const [key, value] of pendingEnrollments) if (value.expires < now) pendingEnrollments.delete(key);
  for (const [key, value] of pendingChallenges) if (value.expires < now) pendingChallenges.delete(key);
  for (const [key, value] of rateBuckets) if (value.expires < now) rateBuckets.delete(key);
}, 60_000);
cleaner.unref();

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  server.listen(PORT, HOST, () => {
    console.log(`\nBrowser Key Auth prototype: ${APP_ORIGIN}`);
    console.log(`Demo JSON database: ${DATA_FILE}`);
    console.log('One-time invitation codes (server terminal only):');
    if (inviteCodes.size === 0) console.log('  No eligible unregistered users.');
    for (const [email, code] of inviteCodes) console.log(`  ${email}  =>  ${code}`);
    console.log('Local HTTP is for localhost testing. Deploy with HTTPS only.\n');
  });
}
export { server, requestMessage, registrationMessage };

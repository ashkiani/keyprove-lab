'use strict';

// Vanilla JS + browser-native Web Crypto + IndexedDB. No crypto dependencies.
const DB_NAME = 'browser-key-auth-v1';
const STORE = 'encryptedKeys';
const ITERATIONS = 600_000;
const utf8 = new TextEncoder();
const $ = (id) => document.getElementById(id);
let indexedDb;
let localBundles = [];
let activeEmail = null;
let activePrivateKey = null; // non-extractable CryptoKey, in RAM only
let lastSignedRequest = null;

function toB64url(arrayBuffer) {
  const b = new Uint8Array(arrayBuffer);
  let raw = '';
  for (const byte of b) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function fromB64url(value, maxLength = 8192) {
  if (typeof value !== 'string' || value.length > maxLength || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid base64url data in encrypted backup');
  }
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const str = atob(base64 + '='.repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(str, (c) => c.charCodeAt(0));
}
function normalizedEmail(value) { return value.trim().toLowerCase(); }
function bundleAAD(bundle) {
  return utf8.encode(JSON.stringify(['browser-key-auth-backup', 1,
    bundle.email, bundle.publicKey.x, bundle.publicKey.y]));
}
function validateBundle(bundle) {
  if (!bundle || bundle.type !== 'browser-key-auth-backup' || bundle.version !== 1
    || typeof bundle.email !== 'string' || bundle.email !== normalizedEmail(bundle.email)
    || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(bundle.email)
    || bundle.publicKey?.kty !== 'EC' || bundle.publicKey?.crv !== 'P-256'
    || fromB64url(bundle.publicKey.x, 100).length !== 32
    || fromB64url(bundle.publicKey.y, 100).length !== 32
    || bundle.encryption?.kdf !== 'PBKDF2-SHA256'
    || bundle.encryption?.cipher !== 'AES-256-GCM'
    || !Number.isInteger(bundle.encryption.iterations)
    || bundle.encryption.iterations < 600_000 || bundle.encryption.iterations > 2_000_000
    || fromB64url(bundle.encryption.salt, 100).length !== 16
    || fromB64url(bundle.encryption.iv, 100).length !== 12
    || fromB64url(bundle.encryption.wrappedPrivateKey).length < 80) {
    throw new Error('Not a valid v1 encrypted key backup');
  }
  if (Object.hasOwn(bundle.publicKey, 'd')) throw new Error('Backup public key must not contain a private component');
  return bundle;
}
async function deriveWrappingKey(password, salt, iterations) {
  const input = await crypto.subtle.importKey('raw', utf8.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, input,
    { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']
  );
}
async function encryptKeyPair(pair, password, email) {
  const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const bundle = {
    type: 'browser-key-auth-backup', version: 1, email,
    publicKey: { kty: 'EC', crv: 'P-256', x: publicKey.x, y: publicKey.y },
    encryption: {
      kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, salt: toB64url(salt),
      cipher: 'AES-256-GCM', iv: toB64url(iv), wrappedPrivateKey: ''
    }
  };
  const wrappingKey = await deriveWrappingKey(password, salt, ITERATIONS);
  const wrapped = await crypto.subtle.wrapKey(
    'pkcs8', pair.privateKey, wrappingKey,
    { name: 'AES-GCM', iv, additionalData: bundleAAD(bundle), tagLength: 128 }
  );
  bundle.encryption.wrappedPrivateKey = toB64url(wrapped);
  return bundle;
}
async function unlockBundle(bundle, password) {
  validateBundle(bundle);
  const wrappingKey = await deriveWrappingKey(password,
    fromB64url(bundle.encryption.salt), bundle.encryption.iterations);
  // unwrapKey decrypts and imports in one operation; resulting private key cannot be exported.
  const privateKey = await crypto.subtle.unwrapKey(
    'pkcs8', fromB64url(bundle.encryption.wrappedPrivateKey), wrappingKey,
    {
      name: 'AES-GCM', iv: fromB64url(bundle.encryption.iv),
      additionalData: bundleAAD(bundle), tagLength: 128
    },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const publicKey = await crypto.subtle.importKey('jwk', bundle.publicKey,
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  // Prove the decrypted private key actually matches the bundled public key.
  const testMessage = utf8.encode('BROWSER-KEY-AUTH-LOCAL-PAIR-CHECK-V1');
  const testSignature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, testMessage);
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, testSignature, testMessage)) {
    throw new Error('Private and public key do not match');
  }
  return privateKey;
}
function openStore() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: 'email' });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
function storeOp(mode, fn) {
  return new Promise((resolve, reject) => {
    const tx = indexedDb.transaction(STORE, mode);
    const request = fn(tx.objectStore(STORE));
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => resolve(request.result);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
  });
}
async function reloadBundles() {
  localBundles = await storeOp('readonly', store => store.getAll());
  localBundles.sort((a, b) => a.email.localeCompare(b.email));
  updateView();
}
function findBundle(email) { return localBundles.find(b => b.email === email); }
function updateView() {
  const selected = $('account').value;
  const hasKeys = localBundles.length > 0;
  $('stored-section').hidden = !hasKeys;
  $('unlocked-section').hidden = !activePrivateKey;
  $('api-locked').hidden = !!activePrivateKey;
  $('api-unlocked').hidden = !activePrivateKey;
  $('unlock-form').hidden = !!activePrivateKey;
  $('replay-test').disabled = !lastSignedRequest || !activePrivateKey;
  $('tamper-test').disabled = !activePrivateKey;
  $('status').textContent = activePrivateKey ? 'Unlocked' : hasKeys ? 'Locked' : 'No local key';
  $('status').className = `status${activePrivateKey ? ' ready' : ''}`;
  $('account').replaceChildren();
  for (const bundle of localBundles) {
    const option = document.createElement('option');
    option.value = bundle.email;
    option.textContent = bundle.email;
    $('account').append(option);
  }
  if (hasKeys) $('account').value = (activeEmail && findBundle(activeEmail)) ? activeEmail
    : (findBundle(selected) ? selected : localBundles[0].email);
  $('unlocked-account').textContent = activePrivateKey ? `Unlocked as ${activeEmail}` : '';
}
function show(message, type = '') {
  const el = $('notice');
  el.hidden = false;
  el.className = `notice ${type}`;
  el.textContent = message;
}
function log(message, details) {
  const time = new Date().toLocaleTimeString();
  const line = `[${time}] ${message}${details ? '\n' + JSON.stringify(details, null, 2) : ''}`;
  const el = $('log');
  el.textContent = (el.textContent === 'Ready.' ? '' : el.textContent + '\n\n') + line;
  el.scrollTop = el.scrollHeight;
}
function lock() {
  activeEmail = null;
  activePrivateKey = null;
  lastSignedRequest = null;
  $('unlock-password').value = '';
  $('notes').hidden = true;
  $('notes').replaceChildren();
  updateView();
}
async function requestJson(path, { method = 'GET', body, headers = {} } = {}) {
  const response = await fetch(path, {
    method, cache: 'no-store', headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
    ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) })
  });
  let data;
  try { data = await response.json(); } catch { data = { code: 'NON_JSON', message: 'Non-JSON response' }; }
  return { status: response.status, ok: response.ok, data };
}
function checked(response) {
  if (!response.ok) throw new Error(`${response.status} ${response.data.code}: ${response.data.message}`);
  return response.data;
}
async function b64Digest(text) {
  return toB64url(await crypto.subtle.digest('SHA-256', utf8.encode(text)));
}
async function authHeaders(email, privateKey, nonce, method, path, bodyText) {
  const digest = await b64Digest(bodyText);
  const message = ['AUTH-DEMO-V1', window.location.origin, email, nonce, method, path, digest].join('\n');
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, utf8.encode(message));
  return { 'X-Auth-Email': email, 'X-Auth-Nonce': nonce, 'X-Auth-Signature': toB64url(sig) };
}
async function signedRequest(method, path, body, { remember = true } = {}) {
  if (!activePrivateKey || !activeEmail) throw new Error('Unlock a private key first');
  const key = activePrivateKey;
  const email = activeEmail;
  const bodyText = body === undefined ? '' : JSON.stringify(body);
  const { nonce } = checked(await requestJson('/api/challenge', { method: 'POST', body: { email } }));
  const headers = await authHeaders(email, key, nonce, method, path, bodyText);
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await requestJson(path, {
    method, headers,
    ...(body === undefined ? {} : { body: bodyText })
  });
  if (remember) lastSignedRequest = { method, path, headers, bodyText, hasBody: body !== undefined };
  updateView();
  log(`${method} ${path} → HTTP ${response.status}`, response.data);
  return checked(response);
}
async function withButton(button, operation) {
  button.disabled = true;
  try { await operation(); } catch (err) { show(err.message || String(err), 'error'); log(`ERROR: ${err.message || err}`); }
  finally { button.disabled = false; }
}
async function register(event) {
  event.preventDefault();
  const button = event.submitter || $('register-form').querySelector('button');
  await withButton(button, async () => {
    const email = normalizedEmail($('register-email').value);
    const inviteCode = $('register-invite').value.trim();
    const password = $('register-password').value;
    if (password !== $('register-password-confirm').value) throw new Error('Passwords do not match');
    if (password.length < 12) throw new Error('Use at least 12 characters');
    if (findBundle(email)) throw new Error('This email already has a local key. Export or delete it first.');
    // Server confirms email + one-time invitation before the browser generates any key pair.
    const { token, challenge } = checked(await requestJson('/api/enroll/start',
      { method: 'POST', body: { email, inviteCode } }));
    show('Enrollment authorized. Creating and encrypting a key pair locally…');
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const bundle = await encryptKeyPair(pair, password, email);
    const message = ['ENROLL-V1', window.location.origin, email, token, challenge,
      bundle.publicKey.x, bundle.publicKey.y].join('\n');
    const signature = toB64url(await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, utf8.encode(message)));
    // Persist the encrypted key BEFORE server registration, to avoid a registered account
    // with no local key if the browser fails to store it. If the server call fails, keep the
    // bundle for backup/manual recovery. Never save an unencrypted private key.
    await storeOp('readwrite', store => store.add(bundle));
    await reloadBundles();
    const result = await requestJson('/api/enroll/finish', { method: 'POST',
      body: { email, token, publicKey: bundle.publicKey, signature } });
    checked(result);
    activePrivateKey = await unlockBundle(bundle, password);
    activeEmail = email;
    lastSignedRequest = null;
    updateView();
    $('register-form').reset();
    $('register-details').open = false;
    show(`Registered ${email}. Only its public key was sent to the server. Export your encrypted backup.`, 'good');
    log(`Registration successful for ${email}. The private key is non-extractable while unlocked.`);
  });
  $('register-password').value = '';
  $('register-password-confirm').value = '';
  $('register-invite').value = '';
}
async function unlock(event) {
  event.preventDefault();
  await withButton($('unlock-button'), async () => {
    const bundle = findBundle($('account').value);
    if (!bundle) throw new Error('Choose a stored account');
    try { activePrivateKey = await unlockBundle(bundle, $('unlock-password').value); }
    catch { throw new Error('Could not decrypt key. Wrong password or damaged backup.'); }
    activeEmail = bundle.email;
    lastSignedRequest = null;
    $('unlock-password').value = '';
    updateView();
    show(`Unlocked ${activeEmail}. Requests can now be cryptographically signed.`, 'good');
    log(`Local private key unlocked: ${activeEmail} (never transmitted to the server).`);
  });
}
async function importBackup(event) {
  event.preventDefault();
  const button = event.submitter;
  await withButton(button, async () => {
    const file = $('import-file').files?.[0];
    if (!file || file.size > 16_000) throw new Error('Select an encrypted backup smaller than 16 KB');
    const bundle = validateBundle(JSON.parse(await file.text()));
    const password = $('import-password').value;
    const key = await unlockBundle(bundle, password).catch(() => {
      throw new Error('Backup cannot be decrypted or keys do not match. Check its password and contents.');
    });
    if (findBundle(bundle.email) && !confirm(`Replace the existing encrypted key for ${bundle.email}?`)) return;
    await storeOp('readwrite', store => store.put(bundle));
    lock();
    activePrivateKey = key;
    activeEmail = bundle.email;
    await reloadBundles();
    $('import-form').reset();
    $('import-details').open = false;
    show(`Encrypted key restored for ${bundle.email}. The server must already recognize its public key.`, 'good');
    log(`Imported and unlocked encrypted backup for ${bundle.email}.`);
  });
  $('import-password').value = '';
}
async function exportBackup() {
  const bundle = findBundle($('account').value);
  if (!bundle) throw new Error('No encrypted key selected');
  const file = new Blob([JSON.stringify(bundle, null, 2) + '\n'], { type: 'application/json' });
  const url = URL.createObjectURL(file);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `encrypted-key-${bundle.email.replace(/[^a-z0-9.-]/gi, '_')}.json`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  show('Exported an ENCRYPTED key backup. Keep both the file and its password safe.', 'good');
  log(`Encrypted backup exported for ${bundle.email}; no plaintext private key exported.`);
}
async function deleteLocal() {
  const email = $('account').value;
  if (!email) return;
  if (!confirm(`Delete the encrypted key for ${email} from THIS browser?\n\nThis does not unregister or revoke its public key on the server. Make a backup first.`)) return;
  lock();
  await storeOp('readwrite', store => store.delete(email));
  await reloadBundles();
  show(`Deleted local encrypted key for ${email}. Server account remains registered.`, 'good');
  log(`Local key deleted for ${email}; server registration unchanged.`);
}
function renderNotes(notes) {
  const target = $('notes');
  target.replaceChildren();
  for (const note of notes) {
    const item = document.createElement('div');
    item.className = 'note';
    const date = document.createElement('small');
    date.textContent = new Date(note.createdAt).toLocaleString();
    const contents = document.createElement('span');
    contents.textContent = note.text; // never put user-controlled text in innerHTML
    item.append(date, contents);
    target.append(item);
  }
  if (!notes.length) target.textContent = 'No notes yet.';
  target.hidden = false;
}
async function replayTest() {
  if (!lastSignedRequest || !activePrivateKey) throw new Error('Perform a signed request first');
  const saved = lastSignedRequest;
  const result = await requestJson(saved.path, { method: saved.method, headers: saved.headers,
    ...(saved.hasBody ? { body: saved.bodyText } : {}) });
  log(`REPLAY TEST → HTTP ${result.status}`, result.data);
  show(result.status === 401 && result.data.code === 'CHALLENGE_USED'
    ? 'Replay correctly rejected: the challenge was already consumed.'
    : `Unexpected replay result: HTTP ${result.status}`, result.status === 401 ? 'good' : 'error');
}
async function tamperTest() {
  if (!activePrivateKey) throw new Error('Unlock first');
  const path = '/api/private/notes';
  const { nonce } = checked(await requestJson('/api/challenge', {
    method: 'POST', body: { email: activeEmail }
  }));
  // Sign one request body, then deliberately transmit a different one.
  const original = JSON.stringify({ text: 'ORIGINAL: this text was signed' });
  const headers = await authHeaders(activeEmail, activePrivateKey, nonce, 'POST', path, original);
  headers['Content-Type'] = 'application/json';
  const result = await requestJson(path, { method: 'POST',
    body: JSON.stringify({ text: 'TAMPERED: this text was NOT signed' }), headers });
  log(`BODY TAMPERING TEST → HTTP ${result.status}`, result.data);
  show(result.status === 401 && result.data.code === 'BAD_SIGNATURE'
    ? 'Body tampering correctly rejected: the signed body hash does not match.'
    : `Unexpected tampering result: HTTP ${result.status}`, result.status === 401 ? 'good' : 'error');
}

async function start() {
  if (!window.isSecureContext || !crypto?.subtle || !indexedDB) {
    show('Web Crypto and IndexedDB require a secure browser context. Open http://localhost:3000 (not a file:// URL), or use HTTPS.', 'error');
    $('status').textContent = 'Unsupported context';
    return;
  }
  indexedDb = await openStore();
  await reloadBundles();
  log('Application loaded. Browser-side keys are encrypted in IndexedDB.');
}
$('register-form').addEventListener('submit', register);
$('unlock-form').addEventListener('submit', unlock);
$('import-form').addEventListener('submit', importBackup);
$('account').addEventListener('change', () => { lock(); updateView(); });
$('lock-button').addEventListener('click', () => { lock(); show('Locked. You must enter the password to sign again.'); });
$('export-button').addEventListener('click', () => exportBackup().catch(err => show(err.message, 'error')));
$('delete-button').addEventListener('click', () => deleteLocal().catch(err => show(err.message, 'error')));
$('me-button').addEventListener('click', () => withButton($('me-button'), async () => {
  await signedRequest('GET', '/api/private/me');
}));
$('notes-button').addEventListener('click', () => withButton($('notes-button'), async () => {
  const data = await signedRequest('GET', '/api/private/notes');
  renderNotes(data.notes);
}));
$('note-form').addEventListener('submit', event => {
  event.preventDefault();
  const button = event.submitter;
  withButton(button, async () => {
    await signedRequest('POST', '/api/private/notes', { text: $('note-text').value });
    $('note-text').value = '';
    const data = await signedRequest('GET', '/api/private/notes');
    renderNotes(data.notes);
  });
});
$('unsigned-test').addEventListener('click', () => withButton($('unsigned-test'), async () => {
  const result = await requestJson('/api/private/me');
  log(`UNSIGNED TEST → HTTP ${result.status}`, result.data);
  show(result.status === 401 && result.data.code === 'AUTH_REQUIRED'
    ? 'Unsigned request correctly rejected.' : `Unexpected result: HTTP ${result.status}`,
  result.status === 401 ? 'good' : 'error');
}));
$('replay-test').addEventListener('click', () => withButton($('replay-test'), replayTest));
$('tamper-test').addEventListener('click', () => withButton($('tamper-test'), tamperTest));
$('clear-log').addEventListener('click', () => { $('log').textContent = 'Ready.'; });
start().catch(err => { show(`Startup failed: ${err.message}`, 'error'); log(err.message); });

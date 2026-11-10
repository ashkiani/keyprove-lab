import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash, webcrypto } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { fileURLToPath } from 'node:url';
import {
  COVERED_GET, COVERED_POST, SIGNATURE_ALGORITHM, SIGNATURE_TAG,
  signatureInput, signatureBase, signatureHeader, contentDigest, jwkThumbprintSource
} from '../frontend/http-signatures.js';

const crypto = webcrypto;
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const utf8 = new TextEncoder();
const b64url = value => Buffer.from(value).toString('base64url');

// Run the actual authHeaders() function extracted from frontend/app.js using
// Web Crypto, against the actual backend over HTTP. The helper module is shared;
// independent RFC test vectors live in http-signatures.test.js.
const browser = readFileSync(join(root, 'frontend/app.js'), 'utf8');
const browserAuthCode = browser.slice(browser.indexOf('function bytesToBase64('),
  browser.indexOf('async function signedRequest('));
assert.ok(browserAuthCode.includes('async function authHeaders('));
function browserSigner(origin, identity) {
  return runInNewContext(`const utf8 = new TextEncoder();\n${browserAuthCode}\nauthHeaders`, {
    crypto, TextEncoder, btoa, URL, window: { location: { origin } },
    toB64url: b64url, findBundle: () => ({ publicKey: identity.jwk }),
    COVERED_GET, COVERED_POST, SIGNATURE_ALGORITHM, SIGNATURE_TAG,
    signatureInput, signatureBase, signatureHeader, contentDigest, jwkThumbprintSource
  });
}
async function unusedPort() {
  const socket = createServer();
  await new Promise(r => socket.listen(0, '127.0.0.1', r));
  const port = socket.address().port;
  await new Promise(r => socket.close(r));
  return port;
}
async function http(base, route, method = 'GET', body, headers = {}) {
  const res = await fetch(base + route, {
    method, headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
    ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) })
  });
  return { status: res.status, data: await res.json(), headers: res.headers };
}
async function makeUser(base, origin, email, code) {
  const enroll = await http(base, '/api/enroll/start', 'POST', { email, inviteCode: code });
  assert.equal(enroll.status, 200, JSON.stringify(enroll.data));
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const p = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const jwk = { kty: 'EC', crv: 'P-256', x: p.x, y: p.y };
  const msg = ['ENROLL-V1', origin, email, enroll.data.token, enroll.data.challenge, jwk.x, jwk.y].join('\n');
  const sig = b64url(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, utf8.encode(msg)));
  const finish = await http(base, '/api/enroll/finish', 'POST',
    { email, token: enroll.data.token, publicKey: jwk, signature: sig });
  assert.equal(finish.status, 201, JSON.stringify(finish.data));
  return { ...pair, jwk };
}
async function makeHeaders(base, origin, email, identity, method, path, bodyText = '', signer = identity.privateKey) {
  const challenge = await http(base, '/api/challenge', 'POST', { email });
  assert.equal(challenge.status, 200, JSON.stringify(challenge.data));
  return browserSigner(origin, identity)(email, signer, challenge.data.nonce, method, path, bodyText);
}

// Exercise the exact identity, enrollment, and per-request signing flow.
test('existing enrollment, RFC 9421 signed API, replay, tampering and account isolation', async () => {
  const folder = mkdtempSync(join(tmpdir(), 'keyprove-rfc9421-test-'));
  const dbFile = join(folder, 'db.json');
  const port = await unusedPort();
  const origin = `http://localhost:${port}`;
  const base = origin;
  const child = spawn(process.execPath, [join(root, 'backend/server.js')], {
    env: { ...process.env, PORT: String(port), APP_ORIGIN: origin, DEMO_DATA_FILE: dbFile },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let consoleOutput = '';
  child.stdout.on('data', data => { consoleOutput += data.toString(); });
  child.stderr.on('data', data => { consoleOutput += data.toString(); });
  try {
    for (let i = 0; i < 100 && !consoleOutput.includes('Local HTTP is for localhost testing'); i++) {
      if (child.exitCode !== null) throw new Error(`Server exited early: ${consoleOutput}`);
      await new Promise(r => setTimeout(r, 50));
    }
    assert.match(consoleOutput, /One-time invitation codes/);
    const invite = email => {
      const escaped = email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const result = consoleOutput.match(new RegExp(`${escaped}\\s+=>\\s+([A-Za-z0-9_-]+)`));
      assert.ok(result, `Invite missing for ${email}: ${consoleOutput}`);
      return result[1];
    };
    const health = await http(base, '/api/health');
    assert.equal(health.status, 200);
    assert.match(health.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal((await fetch(base + '/http-signatures.js')).status, 200);
    assert.equal((await http(base, '/api/private/me')).data.code, 'AUTH_REQUIRED');
    assert.equal((await http(base, '/api/enroll/start', 'POST', {
      email: 'notallowed@example.com', inviteCode: 'abc'
    })).status, 403);
    assert.equal((await http(base, '/api/enroll/start', 'POST', {
      email: 'alice@example.com', inviteCode: 'wrong'
    })).status, 403);

    const alice = await makeUser(base, origin, 'alice@example.com', invite('alice@example.com'));
    const bob = await makeUser(base, origin, 'bob@example.com', invite('bob@example.com'));
    assert.equal((await http(base, '/api/enroll/start', 'POST', {
      email: 'alice@example.com', inviteCode: invite('alice@example.com')
    })).status, 403);
    const databaseText = readFileSync(dbFile, 'utf8');
    assert.match(databaseText, /"publicKey"/);
    assert.doesNotMatch(databaseText, /"privateKey"|"password"|"keyid"/);

    const aHeaders = await makeHeaders(base, origin, 'alice@example.com', alice, 'GET', '/api/private/me');
    assert.match(aHeaders['Signature-Input'], /^sig1=\("@method" "@target-uri"\);created=/);
    assert.match(aHeaders.Signature, /^sig1=:[A-Za-z0-9+/]{86}==:$/);
    const me = await http(base, '/api/private/me', 'GET', undefined, aHeaders);
    assert.equal(me.status, 200, JSON.stringify(me.data));
    assert.equal(me.data.email, 'alice@example.com');
    assert.match(me.data.mechanism, /RFC 9421/);
    const replay = await http(base, '/api/private/me', 'GET', undefined, aHeaders);
    assert.equal(replay.status, 401);
    assert.equal(replay.data.code, 'CHALLENGE_USED');

    const goodText = JSON.stringify({ text: 'original note' });
    const wrongText = JSON.stringify({ text: 'modified note' });
    const tamperHeaders = await makeHeaders(base, origin, 'alice@example.com', alice,
      'POST', '/api/private/notes', goodText);
    const tamper = await http(base, '/api/private/notes', 'POST', wrongText, tamperHeaders);
    assert.equal(tamper.status, 401);
    assert.equal(tamper.data.code, 'BAD_DIGEST');
    const badDigestHeaders = await makeHeaders(base, origin, 'alice@example.com', alice,
      'POST', '/api/private/notes', goodText);
    badDigestHeaders['Content-Digest'] = contentDigest(createHash('sha256').update('wrong').digest('base64'));
    const corruptedDigest = await http(base, '/api/private/notes', 'POST', goodText, badDigestHeaders);
    assert.equal(corruptedDigest.data.code, 'BAD_DIGEST');

    const goodHeaders = await makeHeaders(base, origin, 'alice@example.com', alice,
      'POST', '/api/private/notes', goodText);
    const add = await http(base, '/api/private/notes', 'POST', goodText, goodHeaders);
    assert.equal(add.status, 201, JSON.stringify(add.data));
    assert.equal((await http(base, '/api/private/notes', 'POST', goodText, goodHeaders)).status, 401);
    const aliceNotes = await makeHeaders(base, origin, 'alice@example.com', alice, 'GET', '/api/private/notes');
    const list = await http(base, '/api/private/notes', 'GET', undefined, aliceNotes);
    assert.equal(list.status, 200, JSON.stringify(list.data));
    assert.deepEqual(list.data.notes.map(n => n.text), ['original note']);

    const bobNotes = await makeHeaders(base, origin, 'bob@example.com', bob, 'GET', '/api/private/notes');
    assert.deepEqual((await http(base, '/api/private/notes', 'GET', undefined, bobNotes)).data.notes, []);
    const mismatch = await makeHeaders(base, origin, 'alice@example.com', alice,
      'GET', '/api/private/me', '', bob.privateKey);
    assert.equal((await http(base, '/api/private/me', 'GET', undefined, mismatch)).data.code, 'BAD_SIGNATURE');

    const pathHeaders = await makeHeaders(base, origin, 'alice@example.com', alice,
      'GET', '/api/private/me');
    assert.equal((await http(base, '/api/private/me?extra=1', 'GET', undefined, pathHeaders)).data.code,
      'BAD_SIGNATURE');
    const typeHeaders = await makeHeaders(base, origin, 'alice@example.com', alice,
      'POST', '/api/private/notes', goodText);
    typeHeaders['Content-Type'] = 'application/json; charset=utf-8';
    assert.equal((await http(base, '/api/private/notes', 'POST', goodText, typeHeaders)).data.code, 'BAD_SIGNATURE');

    const badAlg = await makeHeaders(base, origin, 'alice@example.com', alice, 'GET', '/api/private/me');
    badAlg['Signature-Input'] = badAlg['Signature-Input'].replace('ecdsa-p256-sha256', 'hmac-sha256');
    assert.equal((await http(base, '/api/private/me', 'GET', undefined, badAlg)).data.code, 'BAD_SIGNATURE');
    const badTag = await makeHeaders(base, origin, 'alice@example.com', alice, 'GET', '/api/private/me');
    badTag['Signature-Input'] = badTag['Signature-Input'].replace('keyprove-v1', 'other-app');
    assert.equal((await http(base, '/api/private/me', 'GET', undefined, badTag)).data.code, 'BAD_SIGNATURE');
    const stale = await makeHeaders(base, origin, 'alice@example.com', alice, 'GET', '/api/private/me');
    stale['Signature-Input'] = stale['Signature-Input'].replace(/created=\d+/, 'created=1000');
    assert.equal((await http(base, '/api/private/me', 'GET', undefined, stale)).data.code, 'BAD_SIGNATURE');
    const missingCoverage = await makeHeaders(base, origin, 'alice@example.com', alice,
      'POST', '/api/private/notes', goodText);
    missingCoverage['Signature-Input'] = missingCoverage['Signature-Input'].replace(' "content-digest"', '');
    assert.equal((await http(base, '/api/private/notes', 'POST', goodText, missingCoverage)).data.code,
      'BAD_SIGNATURE');
    const duplicateParams = await makeHeaders(base, origin, 'alice@example.com', alice, 'GET', '/api/private/me');
    duplicateParams['Signature-Input'] += ';nonce="second"';
    assert.equal((await http(base, '/api/private/me', 'GET', undefined, duplicateParams)).data.code, 'BAD_SIGNATURE');
    const malformed = await makeHeaders(base, origin, 'alice@example.com', alice, 'GET', '/api/private/me');
    malformed.Signature = 'sig1=:broken:';
    assert.equal((await http(base, '/api/private/me', 'GET', undefined, malformed)).data.code, 'BAD_SIGNATURE');

    // Old custom wire protocol no longer authenticates a request.
    const oldWire = await http(base, '/api/private/me', 'GET', undefined, {
      'X-Auth-Email': 'alice@example.com', 'X-Auth-Nonce': 'old', 'X-Auth-Signature': 'old'
    });
    assert.equal(oldWire.data.code, 'AUTH_REQUIRED');
    assert.equal((await http(base, '/api/challenge', 'POST', { email: 'alice@example.com' }, {
      Origin: 'http://evil.example'
    })).status, 403);
  } finally {
    child.kill('SIGTERM');
    rmSync(folder, { recursive: true, force: true });
  }
});

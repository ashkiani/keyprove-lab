import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash, webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const crypto = webcrypto;
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const utf8 = new TextEncoder();
const sha256 = value => createHash('sha256').update(value).digest('base64url');
const b64 = value => Buffer.from(value).toString('base64url');

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
  const sig = b64(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, utf8.encode(msg)));
  const finish = await http(base, '/api/enroll/finish', 'POST',
    { email, token: enroll.data.token, publicKey: jwk, signature: sig });
  assert.equal(finish.status, 201, JSON.stringify(finish.data));
  return pair;
}

async function makeHeaders(base, origin, email, privateKey, method, path, bodyText = '') {
  const challenge = await http(base, '/api/challenge', 'POST', { email });
  assert.equal(challenge.status, 200);
  const msg = ['AUTH-DEMO-V1', origin, email, challenge.data.nonce, method, path, sha256(Buffer.from(bodyText))].join('\n');
  const sig = b64(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, utf8.encode(msg)));
  return { 'X-Auth-Email': email, 'X-Auth-Nonce': challenge.data.nonce, 'X-Auth-Signature': sig };
}

test('enrollment, signatures, replay prevention, body binding, account isolation', async () => {
  const folder = mkdtempSync(join(tmpdir(), 'browser-key-auth-test-'));
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
    const invite = (email) => {
      const escaped = email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const result = consoleOutput.match(new RegExp(`${escaped}\\s+=>\\s+([A-Za-z0-9_-]+)`));
      assert.ok(result, `Invite missing for ${email}: ${consoleOutput}`);
      return result[1];
    };
    const health = await http(base, '/api/health');
    assert.equal(health.status, 200);
    assert.match(health.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal((await http(base, '/api/private/me')).status, 401);
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
    assert.doesNotMatch(databaseText, /"privateKey"|"password"/);

    const aHeaders = await makeHeaders(base, origin, 'alice@example.com', alice.privateKey, 'GET', '/api/private/me');
    const me = await http(base, '/api/private/me', 'GET', undefined, aHeaders);
    assert.equal(me.status, 200);
    assert.equal(me.data.email, 'alice@example.com');
    const replay = await http(base, '/api/private/me', 'GET', undefined, aHeaders);
    assert.equal(replay.status, 401);
    assert.equal(replay.data.code, 'CHALLENGE_USED');

    const goodText = JSON.stringify({ text: 'original note' });
    const wrongText = JSON.stringify({ text: 'modified note' });
    const tamperHeaders = await makeHeaders(base, origin, 'alice@example.com', alice.privateKey,
      'POST', '/api/private/notes', goodText);
    const tamper = await http(base, '/api/private/notes', 'POST', wrongText, tamperHeaders);
    assert.equal(tamper.status, 401);
    assert.equal(tamper.data.code, 'BAD_SIGNATURE');

    const goodHeaders = await makeHeaders(base, origin, 'alice@example.com', alice.privateKey,
      'POST', '/api/private/notes', goodText);
    const add = await http(base, '/api/private/notes', 'POST', goodText, goodHeaders);
    assert.equal(add.status, 201);
    assert.equal((await http(base, '/api/private/notes', 'POST', goodText, goodHeaders)).status, 401);
    const aliceNotes = await makeHeaders(base, origin, 'alice@example.com', alice.privateKey,
      'GET', '/api/private/notes');
    const list = await http(base, '/api/private/notes', 'GET', undefined, aliceNotes);
    assert.equal(list.status, 200);
    assert.deepEqual(list.data.notes.map(n => n.text), ['original note']);

    const bobNotes = await makeHeaders(base, origin, 'bob@example.com', bob.privateKey, 'GET', '/api/private/notes');
    assert.deepEqual((await http(base, '/api/private/notes', 'GET', undefined, bobNotes)).data.notes, []);

    const mismatch = await makeHeaders(base, origin, 'alice@example.com', bob.privateKey, 'GET', '/api/private/me');
    assert.equal((await http(base, '/api/private/me', 'GET', undefined, mismatch)).data.code, 'BAD_SIGNATURE');
    assert.equal((await http(base, '/api/challenge', 'POST', { email: 'alice@example.com' }, {
      Origin: 'http://evil.example'
    })).status, 403);
  } finally {
    child.kill('SIGTERM');
    rmSync(folder, { recursive: true, force: true });
  }
});

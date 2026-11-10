import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { fileURLToPath } from 'node:url';

// Exercise the ACTUAL browser encryption/decryption functions from app.js with
// Node's standards-compatible Web Crypto API. No DOM or test dependencies.
const js = readFileSync(fileURLToPath(new URL('../frontend/app.js', import.meta.url)), 'utf8');
const functions = js.slice(js.indexOf('function toB64url('), js.indexOf('function openStore()'));
if (!functions.includes('async function unlockBundle(')) throw Error('Could not load browser crypto functions');
const helpers = runInNewContext(`const ITERATIONS = 600000; const utf8 = new TextEncoder();\n${functions}\n({encryptKeyPair, unlockBundle, validateBundle})`, {
  crypto: webcrypto, TextEncoder, btoa, atob
});

test('encrypted private key requires correct password and imports as non-extractable', async () => {
  const pair = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const password = 'a sufficiently long test passphrase 2026';
  const bundle = await helpers.encryptKeyPair(pair, password, 'alice@example.com');
  assert.equal(bundle.version, 1);
  assert.equal(bundle.encryption.kdf, 'PBKDF2-SHA256');
  assert.equal(bundle.encryption.iterations, 600000);
  assert.equal(JSON.stringify(bundle).includes('PRIVATE KEY'), false);
  const key = await helpers.unlockBundle(bundle, password);
  assert.equal(key.extractable, false);
  assert.deepEqual(key.usages, ['sign']);
  const challenge = new TextEncoder().encode('random challenge');
  const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, challenge);
  assert.equal(await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, sig, challenge), true);
  await assert.rejects(webcrypto.subtle.exportKey('pkcs8', key), /extractable|InvalidAccess/i);
  await assert.rejects(helpers.unlockBundle(bundle, 'totally wrong passphrase'));
});

test('AES-GCM rejects modification of encrypted backup or its public-key binding', async () => {
  const pair = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const password = 'second sufficiently long password';
  const bundle = await helpers.encryptKeyPair(pair, password, 'bob@example.com');
  const tamperedEmail = structuredClone(bundle);
  tamperedEmail.email = 'alice@example.com';
  await assert.rejects(helpers.unlockBundle(tamperedEmail, password));
  const tamperedPrivate = structuredClone(bundle);
  const value = tamperedPrivate.encryption.wrappedPrivateKey;
  tamperedPrivate.encryption.wrappedPrivateKey = (value[0] === 'A' ? 'B' : 'A') + value.slice(1);
  await assert.rejects(helpers.unlockBundle(tamperedPrivate, password));
});

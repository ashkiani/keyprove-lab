/**
 * KeyProve's intentionally narrow RFC 9421 HTTP Message Signatures profile.
 * No third-party dependencies. The same signature-base/Structured Field logic
 * is used by browser and Node; independent RFC 9421 vectors are in tests.
 *
 * Supported signing profile: one `sig1` request signature, ECDSA P-256/SHA-256,
 * @method + @target-uri, additionally content-type + content-digest for POST.
 * Metadata: created, nonce, keyid, alg, tag. No response signatures or
 * general-purpose RFC 8941 parser are claimed. Other conformant signatures
 * may be rejected as outside this application's verification policy.
 */
export const SIGNATURE_LABEL = 'sig1';
export const SIGNATURE_TAG = 'keyprove-v1';
export const SIGNATURE_ALGORITHM = 'ecdsa-p256-sha256';
export const COVERED_GET = Object.freeze(['@method', '@target-uri']);
export const COVERED_POST = Object.freeze(['@method', '@target-uri', 'content-type', 'content-digest']);
const ALLOWED_PARAMS = new Set(['created', 'nonce', 'keyid', 'alg', 'tag']);
const OWS = /^[ \t]+|[ \t]+$/g;

function fail(detail) { throw new Error(`Invalid HTTP signature: ${detail}`); }
function sfString(value) {
  if (typeof value !== 'string' || !/^[\x20-\x7e]*$/.test(value)) fail('non-ASCII Structured Field string');
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}
function sfInteger(value) {
  if (!Number.isSafeInteger(value) || Math.abs(value) > 999999999999999) fail('invalid Structured Field integer');
  return String(value);
}
export function serializeInnerList(components, parameters) {
  if (!Array.isArray(components) || !components.length || new Set(components).size !== components.length) {
    fail('duplicate or empty covered components');
  }
  const members = components.map(sfString).join(' ');
  const seen = new Set();
  let output = `(${members})`;
  for (const [key, value] of parameters) {
    if (!ALLOWED_PARAMS.has(key) || seen.has(key)) fail('unknown or duplicate signature parameter');
    seen.add(key);
    output += `;${key}=${key === 'created' ? sfInteger(value) : sfString(value)}`;
  }
  return output;
}
export function signatureInput(components, parameters) {
  return `${SIGNATURE_LABEL}=${serializeInnerList(components, parameters)}`;
}
export function signatureBase({ components, parameters, method, targetUri, fields = {}, status }) {
  const lines = [];
  if (!Array.isArray(components) || new Set(components).size !== components.length) fail('duplicate components');
  for (const name of components) {
    let value;
    switch (name) {
      case '@method': value = method; break;
      case '@target-uri': value = targetUri; break;
      // @status included for verification of the official RFC ECDSA test vector;
      // the KeyProve application itself only signs HTTP requests.
      case '@status': value = status === undefined ? undefined : String(status); break;
      default:
        if (!/^[a-z][a-z0-9-]*$/.test(name)) fail('unsupported component');
        value = fields[name];
        if (typeof value === 'string') value = value.replace(OWS, '');
    }
    if (typeof value !== 'string' || !/^[\x20-\x7e]*$/.test(value)) fail(`missing or invalid ${name}`);
    lines.push(`${sfString(name)}: ${value}`);
  }
  lines.push(`"@signature-params": ${serializeInnerList(components, parameters)}`);
  return lines.join('\n'); // RFC 9421 §2.5: no newline after final line.
}

// Purpose-built RFC 8941 parser for a single Dictionary member whose value is
// an Inner List of String Items and the five typed metadata parameters above.
// It parses typed Structured Fields, not a regex extracted from the header.
export function parseSignatureInput(header) {
  if (typeof header !== 'string' || header.length > 2048) fail('missing or oversized Signature-Input');
  let i = 0;
  const skipOWS = () => { while (header[i] === ' ' || header[i] === '\t') i++; };
  const readString = () => {
    if (header[i++] !== '"') fail('expected string');
    let result = '';
    while (i < header.length) {
      let c = header[i++];
      if (c === '"') return result;
      if (c === '\\') {
        c = header[i++];
        if (c !== '"' && c !== '\\') fail('invalid string escape');
      }
      if (!c || !/^[\x20-\x7e]$/.test(c)) fail('invalid string character');
      result += c;
    }
    fail('unterminated string');
  };
  const readKey = () => {
    const m = /^[a-z*][a-z0-9_.*-]*/.exec(header.slice(i));
    if (!m) fail('invalid dictionary/parameter key');
    i += m[0].length;
    return m[0];
  };
  skipOWS();
  if (readKey() !== SIGNATURE_LABEL || header[i++] !== '=' || header[i++] !== '(') {
    fail('expected sig1 Inner List');
  }
  const components = [];
  while (header[i] !== ')') {
    if (components.length >= 12) fail('too many components');
    components.push(readString());
    if (header[i] === ')') break;
    if (header[i] !== ' ') fail('expected Inner List separator');
    while (header[i] === ' ') i++;
    if (header[i] === ')') fail('trailing Inner List space');
  }
  if (header[i++] !== ')' || components.length === 0 || new Set(components).size !== components.length) {
    fail('invalid covered component list');
  }
  const parameters = [];
  const parsed = Object.create(null);
  while (header[i] === ';') {
    i++;
    const key = readKey();
    if (!ALLOWED_PARAMS.has(key) || Object.hasOwn(parsed, key)) fail('duplicate or unsupported parameter');
    if (header[i++] !== '=') fail('missing parameter value');
    let value;
    if (key === 'created') {
      const match = /^-?(?:0|[1-9][0-9]{0,14})/.exec(header.slice(i));
      if (!match) fail('invalid timestamp');
      i += match[0].length;
      value = Number(match[0]);
      sfInteger(value);
    } else value = readString();
    parameters.push([key, value]);
    parsed[key] = value;
  }
  skipOWS();
  if (i !== header.length) fail('unexpected header suffix or multiple signatures');
  if (parameters.length !== 5 || ![...ALLOWED_PARAMS].every(k => Object.hasOwn(parsed, k))) {
    fail('missing required metadata');
  }
  return { components, parameters, metadata: parsed };
}
export function signatureHeader(signatureBytesBase64) {
  if (typeof signatureBytesBase64 !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBytesBase64)) {
    fail('bad signature bytes');
  }
  return `${SIGNATURE_LABEL}=:${signatureBytesBase64}:`;
}
export function parseSignatureHeader(header) {
  if (typeof header !== 'string' || header.length > 256) fail('missing or oversized Signature');
  const m = /^[ \t]*sig1=:([A-Za-z0-9+/]+={0,2}):[ \t]*$/.exec(header);
  if (!m || m[1].length !== 88 || !m[1].endsWith('==')) fail('expected 64-byte P-256 signature');
  return m[1];
}
export function contentDigest(sha256Base64) {
  if (typeof sha256Base64 !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(sha256Base64)) {
    fail('expected SHA-256 digest');
  }
  return `sha-256=:${sha256Base64}:`;
}
export function parseContentDigest(header) {
  if (typeof header !== 'string' || header.length > 160) fail('missing Content-Digest');
  // Only one sha-256 member with no extra parameters is supported by this profile.
  const m = /^[ \t]*sha-256=:([A-Za-z0-9+/]{43}=):[ \t]*$/.exec(header);
  if (!m) fail('invalid Content-Digest dictionary');
  return m[1];
}
// RFC 7638 JWK thumbprint JSON: deterministic keyid, compatible with existing
// v1 encrypted backups and existing database user public-key records.
export function jwkThumbprintSource(jwk) {
  if (jwk?.kty !== 'EC' || jwk?.crv !== 'P-256'
      || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') fail('invalid JWK');
  return JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y });
}

'use strict';

const { generatePassword } = require('./index.js');

let passed = 0;
let failed = 0;

function assert(description, fn) {
  try {
    fn();
    console.log(`  ✓ ${description}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${description}`);
    console.log(`    ${err.message}`);
    failed++;
  }
}

console.log('\npassword-kit-js — generatePassword tests\n');

// ─── Output shape ────────────────────────────────────────────────────────────

assert('returns a string', () => {
  const pwd = generatePassword(12);
  if (typeof pwd !== 'string') throw new Error(`expected string, got ${typeof pwd}`);
});

assert('returns correct length (8)', () => {
  const pwd = generatePassword(8);
  if (pwd.length !== 8) throw new Error(`expected 8, got ${pwd.length}`);
});

assert('returns correct length (16)', () => {
  const pwd = generatePassword(16);
  if (pwd.length !== 16) throw new Error(`expected 16, got ${pwd.length}`);
});

assert('returns correct length (64)', () => {
  const pwd = generatePassword(64);
  if (pwd.length !== 64) throw new Error(`expected 64, got ${pwd.length}`);
});

assert('returns correct length (128)', () => {
  const pwd = generatePassword(128);
  if (pwd.length !== 128) throw new Error(`expected 128, got ${pwd.length}`);
});

// ─── Default charset (uppercase + lowercase + numbers, no symbols) ────────────

assert('default: uses only uppercase, lowercase, and digits', () => {
  const allowed = /^[A-Za-z0-9]+$/;
  for (let i = 0; i < 50; i++) {
    const pwd = generatePassword(20);
    if (!allowed.test(pwd)) throw new Error(`unexpected character in: ${pwd}`);
  }
});

// ─── Randomness ──────────────────────────────────────────────────────────────

assert('two calls with the same length return different passwords', () => {
  const a = generatePassword(20);
  const b = generatePassword(20);
  if (a === b) throw new Error('got identical passwords — extremely unlikely unless broken');
});

// ─── Length validation ───────────────────────────────────────────────────────

assert('throws RangeError for length 0', () => {
  try { generatePassword(0); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}`);
  }
});

assert('throws RangeError for length 3 (below minimum)', () => {
  try { generatePassword(3); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}`);
  }
});

assert('throws RangeError for length 129 (above maximum)', () => {
  try { generatePassword(129); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}`);
  }
});

assert('throws TypeError for a string argument', () => {
  try { generatePassword('12'); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}`);
  }
});

assert('throws TypeError for a float argument', () => {
  try { generatePassword(8.5); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}`);
  }
});

assert('accepts minimum valid length (4)', () => {
  const pwd = generatePassword(4);
  if (pwd.length !== 4) throw new Error(`expected 4, got ${pwd.length}`);
});

// ─── Custom options: single character type ───────────────────────────────────

assert('uppercase only: contains only A–Z', () => {
  const pwd = generatePassword(20, { uppercase: true, lowercase: false, numbers: false });
  if (!/^[A-Z]+$/.test(pwd)) throw new Error(`unexpected chars in: ${pwd}`);
});

assert('lowercase only: contains only a–z', () => {
  const pwd = generatePassword(20, { uppercase: false, lowercase: true, numbers: false });
  if (!/^[a-z]+$/.test(pwd)) throw new Error(`unexpected chars in: ${pwd}`);
});

assert('numbers only: contains only 0–9', () => {
  const pwd = generatePassword(10, { uppercase: false, lowercase: false, numbers: true });
  if (!/^[0-9]+$/.test(pwd)) throw new Error(`unexpected chars in: ${pwd}`);
});

assert('symbols only: contains only symbol characters', () => {
  const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';
  const pwd = generatePassword(20, { uppercase: false, lowercase: false, numbers: false, symbols: true });
  for (const ch of pwd) {
    if (!SYMBOLS.includes(ch)) throw new Error(`unexpected char "${ch}" in: ${pwd}`);
  }
});

// ─── Custom options: combinations ────────────────────────────────────────────

assert('uppercase + numbers: contains only A–Z and 0–9', () => {
  const pwd = generatePassword(30, { uppercase: true, lowercase: false, numbers: true });
  if (!/^[A-Z0-9]+$/.test(pwd)) throw new Error(`unexpected chars in: ${pwd}`);
});

assert('lowercase + symbols: contains only a–z and symbol characters', () => {
  const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';
  const pwd = generatePassword(30, { uppercase: false, lowercase: true, numbers: false, symbols: true });
  for (const ch of pwd) {
    if (!/[a-z]/.test(ch) && !SYMBOLS.includes(ch)) {
      throw new Error(`unexpected char "${ch}" in: ${pwd}`);
    }
  }
});

assert('all types enabled: can contain any allowed character', () => {
  const all = /^[A-Za-z0-9!@#$%^&*()\-_=+\[\]{}|;:,.<>?]+$/;
  const pwd = generatePassword(50, { uppercase: true, lowercase: true, numbers: true, symbols: true });
  if (!all.test(pwd)) throw new Error(`unexpected chars in: ${pwd}`);
});

// ─── Options validation ──────────────────────────────────────────────────────

assert('throws Error when all types are disabled', () => {
  try {
    generatePassword(12, { uppercase: false, lowercase: false, numbers: false, symbols: false });
    throw new Error('no error thrown');
  } catch (err) {
    if (err.message !== 'at least one character type must be enabled') {
      throw new Error(`unexpected error: ${err.message}`);
    }
  }
});

// ─── Backward compatibility ──────────────────────────────────────────────────

assert('calling without options still works (backward compatible)', () => {
  const pwd = generatePassword(16);
  if (pwd.length !== 16) throw new Error(`expected length 16, got ${pwd.length}`);
});

// ─── Sample output ───────────────────────────────────────────────────────────

console.log('\nSample passwords:');
console.log(`  default (16):              ${generatePassword(16)}`);
console.log(`  symbols enabled (16):      ${generatePassword(16, { symbols: true })}`);
console.log(`  uppercase + numbers (16):  ${generatePassword(16, { uppercase: true, lowercase: false, numbers: true })}`);
console.log(`  lowercase only (16):       ${generatePassword(16, { uppercase: false, lowercase: true, numbers: false })}`);

// ─── Summary ─────────────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);

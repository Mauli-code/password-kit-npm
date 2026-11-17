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

// --- Output shape ---
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

// --- Character set ---
assert('uses only allowed characters (uppercase, lowercase, digits)', () => {
  const allowed = /^[A-Za-z0-9]+$/;
  for (let i = 0; i < 50; i++) {
    const pwd = generatePassword(20);
    if (!allowed.test(pwd)) throw new Error(`unexpected character in: ${pwd}`);
  }
});

// --- Randomness ---
assert('two calls with the same length return different passwords', () => {
  const a = generatePassword(20);
  const b = generatePassword(20);
  if (a === b) throw new Error('got identical passwords — extremely unlikely unless broken');
});

// --- Validation ---
assert('throws RangeError for length 0', () => {
  try {
    generatePassword(0);
    throw new Error('no error thrown');
  } catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}`);
  }
});

assert('throws RangeError for length 3 (below minimum)', () => {
  try {
    generatePassword(3);
    throw new Error('no error thrown');
  } catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}`);
  }
});

assert('throws RangeError for length 129 (above maximum)', () => {
  try {
    generatePassword(129);
    throw new Error('no error thrown');
  } catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}`);
  }
});

assert('throws TypeError for a string argument', () => {
  try {
    generatePassword('12');
    throw new Error('no error thrown');
  } catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}`);
  }
});

assert('throws TypeError for a float argument', () => {
  try {
    generatePassword(8.5);
    throw new Error('no error thrown');
  } catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}`);
  }
});

assert('accepts minimum valid length (4)', () => {
  const pwd = generatePassword(4);
  if (pwd.length !== 4) throw new Error(`expected 4, got ${pwd.length}`);
});

// --- Sample output ---
console.log('\nSample passwords:');
[8, 12, 16, 24].forEach(len => {
  console.log(`  length ${len.toString().padStart(3)}: ${generatePassword(len)}`);
});

// --- Summary ---
console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);

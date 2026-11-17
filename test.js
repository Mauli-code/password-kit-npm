'use strict';

const { generatePassword, generateMultiplePasswords, checkPasswordStrength } = require('./index.js');

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

// ─── generateMultiplePasswords ───────────────────────────────────────────────

assert('returns an array', () => {
  const result = generateMultiplePasswords(3, 12);
  if (!Array.isArray(result)) throw new Error(`expected array, got ${typeof result}`);
});

assert('returns correct count (1)', () => {
  const result = generateMultiplePasswords(1, 12);
  if (result.length !== 1) throw new Error(`expected 1, got ${result.length}`);
});

assert('returns correct count (5)', () => {
  const result = generateMultiplePasswords(5, 12);
  if (result.length !== 5) throw new Error(`expected 5, got ${result.length}`);
});

assert('returns correct count (10)', () => {
  const result = generateMultiplePasswords(10, 12);
  if (result.length !== 10) throw new Error(`expected 10, got ${result.length}`);
});

assert('each password has the correct length', () => {
  const result = generateMultiplePasswords(10, 20);
  for (const pwd of result) {
    if (pwd.length !== 20) throw new Error(`expected length 20, got ${pwd.length} in: ${pwd}`);
  }
});

assert('each password is a string', () => {
  const result = generateMultiplePasswords(5, 16);
  for (const pwd of result) {
    if (typeof pwd !== 'string') throw new Error(`expected string, got ${typeof pwd}`);
  }
});

assert('passwords are not all identical', () => {
  const result = generateMultiplePasswords(5, 16);
  const unique = new Set(result);
  if (unique.size === 1) throw new Error('all 5 passwords are identical — extremely unlikely unless broken');
});

assert('respects character options (symbols only)', () => {
  const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';
  const result = generateMultiplePasswords(5, 16, { uppercase: false, lowercase: false, numbers: false, symbols: true });
  for (const pwd of result) {
    for (const ch of pwd) {
      if (!SYMBOLS.includes(ch)) throw new Error(`unexpected char "${ch}" in: ${pwd}`);
    }
  }
});

assert('throws TypeError for non-integer count', () => {
  try { generateMultiplePasswords(2.5, 12); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}`);
  }
});

assert('throws RangeError for count 0', () => {
  try { generateMultiplePasswords(0, 12); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}`);
  }
});

assert('throws RangeError for count 101 (above maximum)', () => {
  try { generateMultiplePasswords(101, 12); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}`);
  }
});

assert('propagates invalid length error from generatePassword()', () => {
  try { generateMultiplePasswords(3, 200); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}`);
  }
});

// ─── Improved input validation ───────────────────────────────────────────────

// generatePassword — missing / bad length types
assert('throws TypeError for undefined length', () => {
  try { generatePassword(undefined); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws TypeError for null length', () => {
  try { generatePassword(null); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws TypeError for NaN length', () => {
  try { generatePassword(NaN); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws RangeError for negative length', () => {
  try { generatePassword(-1); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}: ${err.message}`);
  }
});

// generatePassword — invalid options type
assert('throws TypeError when options is a string', () => {
  try { generatePassword(12, 'uppercase'); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws TypeError when options is an array', () => {
  try { generatePassword(12, ['uppercase']); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws TypeError when options is a number', () => {
  try { generatePassword(12, 42); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

// generatePassword — non-boolean option values
assert('throws TypeError when options.uppercase is not a boolean', () => {
  try { generatePassword(12, { uppercase: 'yes' }); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws TypeError when options.symbols is a number', () => {
  try { generatePassword(12, { symbols: 1 }); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

// generateMultiplePasswords — missing / bad count types
assert('throws TypeError for undefined count', () => {
  try { generateMultiplePasswords(undefined, 12); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws TypeError for null count', () => {
  try { generateMultiplePasswords(null, 12); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws TypeError for NaN count', () => {
  try { generateMultiplePasswords(NaN, 12); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws RangeError for negative count', () => {
  try { generateMultiplePasswords(-1, 12); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof RangeError)) throw new Error(`expected RangeError, got ${err.constructor.name}: ${err.message}`);
  }
});

// checkPasswordStrength — invalid inputs
assert('throws TypeError for null password', () => {
  try { checkPasswordStrength(null); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws TypeError for number password', () => {
  try { checkPasswordStrength(12345); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

assert('throws TypeError for undefined password', () => {
  try { checkPasswordStrength(undefined); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}: ${err.message}`);
  }
});

// Valid usage still works after all new validation
assert('valid call still works after validation additions', () => {
  const pwd = generatePassword(16, { uppercase: true, lowercase: true, numbers: true, symbols: false });
  if (pwd.length !== 16) throw new Error(`expected 16, got ${pwd.length}`);
});

assert('valid generateMultiplePasswords still works', () => {
  const result = generateMultiplePasswords(3, 12, { symbols: true });
  if (result.length !== 3) throw new Error(`expected 3, got ${result.length}`);
});

// ─── checkPasswordStrength ───────────────────────────────────────────────────

assert('returns an object with strength, score, and reasons', () => {
  const result = checkPasswordStrength('Hello1!');
  if (typeof result !== 'object')         throw new Error('expected an object');
  if (typeof result.strength !== 'string') throw new Error('missing strength string');
  if (typeof result.score !== 'number')    throw new Error('missing score number');
  if (!Array.isArray(result.reasons))      throw new Error('missing reasons array');
});

// Weak: short, only lowercase
assert('weak — short lowercase-only password scores Weak', () => {
  const result = checkPasswordStrength('abc');
  if (result.strength !== 'Weak') throw new Error(`expected Weak, got ${result.strength}`);
  if (result.score > 2)           throw new Error(`expected score <= 2, got ${result.score}`);
});

// Weak: 8+ chars but only one type
assert('weak — 8 lowercase letters scores Weak', () => {
  const result = checkPasswordStrength('abcdefgh');
  if (result.strength !== 'Weak') throw new Error(`expected Weak, got ${result.strength}`);
});

// Medium: decent length, two or three types
assert('medium — mixed case + number, short, scores Medium', () => {
  const result = checkPasswordStrength('Hello1');
  if (result.strength !== 'Medium') throw new Error(`expected Medium, got ${result.strength}`);
  if (result.score < 3 || result.score > 4) throw new Error(`expected score 3–4, got ${result.score}`);
});

assert('medium — 8+ chars with uppercase, lowercase, number scores Medium', () => {
  const result = checkPasswordStrength('Hello123');
  if (result.strength !== 'Medium') throw new Error(`expected Medium, got ${result.strength}`);
});

// Strong: long, all character types
assert('strong — 12+ chars with all types scores Strong', () => {
  const result = checkPasswordStrength('Hello123!@#World');
  if (result.strength !== 'Strong') throw new Error(`expected Strong, got ${result.strength}`);
  if (result.score < 5)             throw new Error(`expected score >= 5, got ${result.score}`);
});

assert('strong — max score is 6', () => {
  const result = checkPasswordStrength('Abcdef1!ghijkl');
  if (result.score > 6) throw new Error(`score ${result.score} exceeds maximum of 6`);
});

// Score accuracy
assert('score increases with uppercase added', () => {
  const lower  = checkPasswordStrength('hello123');
  const mixed  = checkPasswordStrength('Hello123');
  if (mixed.score <= lower.score) throw new Error(`expected higher score with uppercase`);
});

assert('score increases with symbol added', () => {
  const noSym  = checkPasswordStrength('Hello123');
  const withSym = checkPasswordStrength('Hello123!');
  if (withSym.score <= noSym.score) throw new Error('expected higher score with symbol');
});

// Reasons
assert('reasons include "too short" for a short password', () => {
  const result = checkPasswordStrength('hi');
  if (!result.reasons.some(r => r.includes('too short'))) {
    throw new Error(`expected "too short" reason, got: ${result.reasons.join(', ')}`);
  }
});

assert('reasons include "contains symbols" when symbols present', () => {
  const result = checkPasswordStrength('Hello1!');
  if (!result.reasons.some(r => r.includes('contains symbols'))) {
    throw new Error(`expected "contains symbols" reason, got: ${result.reasons.join(', ')}`);
  }
});

assert('reasons include "no symbols" when symbols absent', () => {
  const result = checkPasswordStrength('Hello123');
  if (!result.reasons.some(r => r.includes('no symbols'))) {
    throw new Error(`expected "no symbols" reason, got: ${result.reasons.join(', ')}`);
  }
});

// Input validation
assert('throws TypeError for non-string input', () => {
  try { checkPasswordStrength(12345); throw new Error('no error thrown'); }
  catch (err) {
    if (!(err instanceof TypeError)) throw new Error(`expected TypeError, got ${err.constructor.name}`);
  }
});

assert('throws Error for empty string', () => {
  try { checkPasswordStrength(''); throw new Error('no error thrown'); }
  catch (err) {
    if (err.message !== 'password must not be empty') {
      throw new Error(`unexpected error: ${err.message}`);
    }
  }
});

// ─── Sample output ───────────────────────────────────────────────────────────

console.log('\nSample passwords:');
console.log(`  default (16):              ${generatePassword(16)}`);
console.log(`  symbols enabled (16):      ${generatePassword(16, { symbols: true })}`);
console.log(`  uppercase + numbers (16):  ${generatePassword(16, { uppercase: true, lowercase: false, numbers: true })}`);
console.log(`  lowercase only (16):       ${generatePassword(16, { uppercase: false, lowercase: true, numbers: false })}`);

console.log('\nSample — generateMultiplePasswords(5, 16):');
generateMultiplePasswords(5, 16).forEach((pwd, i) => console.log(`  ${i + 1}. ${pwd}`));

console.log('\nSample — checkPasswordStrength:');
['abc', 'Hello123', 'Hello123!@#World'].forEach(pwd => {
  const { strength, score, reasons } = checkPasswordStrength(pwd);
  console.log(`  "${pwd}"`);
  console.log(`    strength: ${strength}  score: ${score}/6`);
  console.log(`    reasons:  ${reasons.join(' | ')}`);
});

// ─── Summary ─────────────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);

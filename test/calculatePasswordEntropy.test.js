'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  calculatePasswordEntropy,
  generatePassword,
  generateMultiplePasswords,
  checkPasswordStrength,
  validatePassword,
} = require('../index.js');

// ─── Helper ───────────────────────────────────────────────────────────────────
// Pool sizes used in the formula (must match index.js constants).
const POOL_LOWER   = 26; // a–z
const POOL_UPPER   = 26; // A–Z
const POOL_DIGITS  = 10; // 0–9
const POOL_SYMBOLS = 26; // !@#$%^&*()-_=+[]{}|;:,.<>?

function expectedEntropy(length, pool) {
  return Math.round(length * Math.log2(pool) * 100) / 100;
}

// ─── Tests ────────────────────────────────────────────────────────────────────
describe('calculatePasswordEntropy()', () => {

  // ── Return shape ────────────────────────────────────────────────────────────
  describe('return shape', () => {
    it('returns an object', () => {
      assert.strictEqual(typeof calculatePasswordEntropy('hello'), 'object');
    });

    it('result has a numeric entropy property', () => {
      assert.strictEqual(typeof calculatePasswordEntropy('hello').entropy, 'number');
    });

    it('result has a string level property', () => {
      assert.strictEqual(typeof calculatePasswordEntropy('hello').level, 'string');
    });
  });

  // ── 1. Lowercase-only password ──────────────────────────────────────────────
  describe('lowercase-only password', () => {
    it('uses a pool of 26 for a lowercase-only password', () => {
      const { entropy } = calculatePasswordEntropy('hello');
      assert.strictEqual(entropy, expectedEntropy(5, POOL_LOWER));
    });

    it('pool does not include uppercase, digits, or symbols for lowercase input', () => {
      // If pool were 62 (lower+upper+digits) entropy would be higher.
      const { entropy } = calculatePasswordEntropy('hello');
      assert.ok(entropy < expectedEntropy(5, 62));
    });
  });

  // ── 2. Uppercase-only password ──────────────────────────────────────────────
  describe('uppercase-only password', () => {
    it('uses a pool of 26 for an uppercase-only password', () => {
      const { entropy } = calculatePasswordEntropy('HELLO');
      assert.strictEqual(entropy, expectedEntropy(5, POOL_UPPER));
    });

    it('uppercase-only and lowercase-only of the same length return equal entropy', () => {
      assert.strictEqual(
        calculatePasswordEntropy('HELLO').entropy,
        calculatePasswordEntropy('hello').entropy
      );
    });
  });

  // ── 3. Numeric password ─────────────────────────────────────────────────────
  describe('numeric password', () => {
    it('uses a pool of 10 for a digits-only password', () => {
      const { entropy } = calculatePasswordEntropy('12345');
      assert.strictEqual(entropy, expectedEntropy(5, POOL_DIGITS));
    });
  });

  // ── 4. Mixed uppercase and lowercase ────────────────────────────────────────
  describe('mixed-case password', () => {
    it('uses a pool of 52 (26 + 26) for upper + lower password', () => {
      const { entropy } = calculatePasswordEntropy('Hello');
      assert.strictEqual(entropy, expectedEntropy(5, POOL_LOWER + POOL_UPPER));
    });

    it('mixed-case entropy is higher than single-case entropy of the same length', () => {
      assert.ok(
        calculatePasswordEntropy('Hello').entropy >
        calculatePasswordEntropy('hello').entropy
      );
    });
  });

  // ── 5. Password containing numbers ──────────────────────────────────────────
  describe('password with numbers', () => {
    it('uses a pool of 62 (26+26+10) for lower + upper + digits', () => {
      const { entropy } = calculatePasswordEntropy('Hello1');
      assert.strictEqual(entropy, expectedEntropy(6, POOL_LOWER + POOL_UPPER + POOL_DIGITS));
    });

    it('adding a digit increases entropy compared to letters only', () => {
      assert.ok(
        calculatePasswordEntropy('Hello1').entropy >
        calculatePasswordEntropy('Hello').entropy
      );
    });
  });

  // ── 6. Password containing symbols ──────────────────────────────────────────
  describe('password with symbols', () => {
    it('uses a pool of 88 (26+26+10+26) for all four character types', () => {
      const pool = POOL_LOWER + POOL_UPPER + POOL_DIGITS + POOL_SYMBOLS; // 88
      const { entropy } = calculatePasswordEntropy('Hello@1');
      assert.strictEqual(entropy, expectedEntropy(7, pool));
    });

    it('adding a symbol increases entropy compared to no symbol', () => {
      assert.ok(
        calculatePasswordEntropy('Hello@1').entropy >
        calculatePasswordEntropy('Hello1a').entropy
      );
    });
  });

  // ── 7. Empty password ───────────────────────────────────────────────────────
  describe('empty password', () => {
    it('throws an Error for an empty string', () => {
      assert.throws(
        () => calculatePasswordEntropy(''),
        { message: 'password must not be empty' }
      );
    });
  });

  // ── 8. Invalid input types ───────────────────────────────────────────────────
  describe('invalid input types', () => {
    it('throws TypeError for a number', () => {
      assert.throws(() => calculatePasswordEntropy(12345), TypeError);
    });

    it('throws TypeError for null', () => {
      assert.throws(() => calculatePasswordEntropy(null), TypeError);
    });

    it('throws TypeError for undefined', () => {
      assert.throws(() => calculatePasswordEntropy(undefined), TypeError);
    });

    it('throws TypeError for a boolean', () => {
      assert.throws(() => calculatePasswordEntropy(true), TypeError);
    });

    it('throws TypeError for an array', () => {
      assert.throws(() => calculatePasswordEntropy(['hello']), TypeError);
    });

    it('throws TypeError for an object', () => {
      assert.throws(() => calculatePasswordEntropy({ password: 'hello' }), TypeError);
    });

    it('error message mentions "password must be a string"', () => {
      assert.throws(
        () => calculatePasswordEntropy(99),
        { message: 'password must be a string' }
      );
    });
  });

  // ── 9. Correct entropy calculation ──────────────────────────────────────────
  describe('correct entropy calculation', () => {
    it('entropy for "hello" is length(5) × log2(26) rounded to 2 dp', () => {
      const expected = expectedEntropy(5, 26); // 23.5
      assert.strictEqual(calculatePasswordEntropy('hello').entropy, expected);
    });

    it('entropy for "Hello@123" is length(9) × log2(88) rounded to 2 dp', () => {
      const pool = POOL_LOWER + POOL_UPPER + POOL_DIGITS + POOL_SYMBOLS; // 88
      const expected = expectedEntropy(9, pool); // 58.43
      assert.strictEqual(calculatePasswordEntropy('Hello@123').entropy, expected);
    });

    it('longer password of the same character types has higher entropy', () => {
      const short = calculatePasswordEntropy('Hello@1').entropy;
      const long  = calculatePasswordEntropy('Hello@123').entropy;
      assert.ok(long > short);
    });

    it('entropy is rounded to exactly two decimal places', () => {
      const { entropy } = calculatePasswordEntropy('Hello@123');
      const decimals = entropy.toString().split('.')[1] || '';
      assert.ok(decimals.length <= 2, `expected ≤2 dp, got "${entropy}"`);
    });
  });

  // ── 10. Correct entropy level classification ─────────────────────────────────
  describe('entropy level classification', () => {
    it('"hello" (entropy ~23.5) is classified as Low', () => {
      assert.strictEqual(calculatePasswordEntropy('hello').level, 'Low');
    });

    it('"Hello@123" (entropy ~58.43) is classified as Moderate', () => {
      assert.strictEqual(calculatePasswordEntropy('Hello@123').level, 'Moderate');
    });

    it('a 10-char all-type password is classified as High or Very High', () => {
      // pool = 88, length = 10 → entropy ≈ 64.92 → High
      const { level } = calculatePasswordEntropy('Hello@1234');
      assert.ok(level === 'High' || level === 'Very High');
    });

    it('a 13-char all-type password is classified as Very High', () => {
      // pool = 88, length = 13 → entropy ≈ 84.4 → Very High
      const { level } = calculatePasswordEntropy('Hello@1234abc');
      assert.strictEqual(level, 'Very High');
    });

    it('level is one of the four expected strings', () => {
      const allowed = ['Low', 'Moderate', 'High', 'Very High'];
      const { level } = calculatePasswordEntropy('Hello@123');
      assert.ok(allowed.includes(level), `unexpected level "${level}"`);
    });
  });

  // ── 11. Existing functions still working ────────────────────────────────────
  describe('existing functions are unchanged', () => {
    it('generatePassword() still generates a string of the correct length', () => {
      const pwd = generatePassword(16);
      assert.strictEqual(typeof pwd, 'string');
      assert.strictEqual(pwd.length, 16);
    });

    it('generateMultiplePasswords() still returns an array', () => {
      const passwords = generateMultiplePasswords(3, 12);
      assert.ok(Array.isArray(passwords));
      assert.strictEqual(passwords.length, 3);
    });

    it('checkPasswordStrength() still returns strength, score, and reasons', () => {
      const result = checkPasswordStrength('Hello123!');
      assert.ok('strength' in result);
      assert.ok('score' in result);
      assert.ok('reasons' in result);
    });

    it('validatePassword() still returns valid and errors', () => {
      const result = validatePassword('Hello@123', { requireUppercase: true });
      assert.ok('valid' in result);
      assert.ok('errors' in result);
    });
  });

});

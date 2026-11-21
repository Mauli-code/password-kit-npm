'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { validatePassword, generatePassword, generateMultiplePasswords, checkPasswordStrength } = require('../index.js');

describe('validatePassword()', () => {

  // ── 1. Valid password ──────────────────────────────────────────────────────
  describe('valid password', () => {
    it('returns valid:true and an empty errors array when all rules pass', () => {
      const result = validatePassword('Hello@123', {
        minLength:        8,
        requireUppercase: true,
        requireLowercase: true,
        requireNumber:    true,
        requireSymbol:    true,
      });
      assert.strictEqual(result.valid, true);
      assert.deepStrictEqual(result.errors, []);
    });

    it('returns an object with a boolean valid and an array errors', () => {
      const result = validatePassword('Hello@123', {});
      assert.strictEqual(typeof result.valid, 'boolean');
      assert.ok(Array.isArray(result.errors));
    });
  });

  // ── 2. Password shorter than minimum length ────────────────────────────────
  describe('minLength rule', () => {
    it('fails when the password is shorter than minLength', () => {
      const result = validatePassword('Hi1!', { minLength: 8 });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('at least 8')));
    });

    it('passes when the password exactly meets minLength', () => {
      const result = validatePassword('Hello1!X', { minLength: 8 });
      assert.strictEqual(result.valid, true);
    });
  });

  // ── 3. Password longer than maximum length ─────────────────────────────────
  describe('maxLength rule', () => {
    it('fails when the password exceeds maxLength', () => {
      // minLength must be <= maxLength, so we set both together.
      const result = validatePassword('Hello@123', { minLength: 4, maxLength: 6 });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('no more than 6')));
    });

    it('passes when the password exactly meets maxLength', () => {
      const result = validatePassword('Hello1', { minLength: 4, maxLength: 6 });
      assert.strictEqual(result.valid, true);
    });
  });

  // ── 4. Missing uppercase letter ────────────────────────────────────────────
  describe('requireUppercase rule', () => {
    it('fails when the password has no uppercase letter', () => {
      const result = validatePassword('hello@123', { requireUppercase: true });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('uppercase')));
    });

    it('passes when the password has at least one uppercase letter', () => {
      const result = validatePassword('Hello@123', { requireUppercase: true });
      assert.strictEqual(result.valid, true);
    });
  });

  // ── 5. Missing lowercase letter ────────────────────────────────────────────
  describe('requireLowercase rule', () => {
    it('fails when the password has no lowercase letter', () => {
      const result = validatePassword('HELLO@123', { requireLowercase: true });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('lowercase')));
    });

    it('passes when the password has at least one lowercase letter', () => {
      const result = validatePassword('Hello@123', { requireLowercase: true });
      assert.strictEqual(result.valid, true);
    });
  });

  // ── 6. Missing number ──────────────────────────────────────────────────────
  describe('requireNumber rule', () => {
    it('fails when the password has no digit', () => {
      const result = validatePassword('Hello@World', { requireNumber: true });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('number')));
    });

    it('passes when the password has at least one digit', () => {
      const result = validatePassword('Hello@123', { requireNumber: true });
      assert.strictEqual(result.valid, true);
    });
  });

  // ── 7. Missing symbol ──────────────────────────────────────────────────────
  describe('requireSymbol rule', () => {
    it('fails when the password has no symbol', () => {
      const result = validatePassword('Hello123', { requireSymbol: true });
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('symbol')));
    });

    it('passes when the password has at least one symbol', () => {
      const result = validatePassword('Hello@123', { requireSymbol: true });
      assert.strictEqual(result.valid, true);
    });
  });

  // ── 8. Multiple rules failing together ────────────────────────────────────
  describe('multiple failing rules', () => {
    it('reports all failing rules at once, not just the first one', () => {
      const result = validatePassword('hello', {
        minLength:        8,
        requireUppercase: true,
        requireNumber:    true,
      });
      assert.strictEqual(result.valid, false);
      // All three rules fail — we expect three errors.
      assert.strictEqual(result.errors.length, 3);
      assert.ok(result.errors.some(e => e.includes('at least 8')));
      assert.ok(result.errors.some(e => e.includes('uppercase')));
      assert.ok(result.errors.some(e => e.includes('number')));
    });
  });

  // ── 9. Invalid password type ──────────────────────────────────────────────
  describe('invalid password type', () => {
    it('throws TypeError when password is a number', () => {
      assert.throws(() => validatePassword(12345), TypeError);
    });

    it('throws TypeError when password is null', () => {
      assert.throws(() => validatePassword(null), TypeError);
    });

    it('throws TypeError when password is undefined', () => {
      assert.throws(() => validatePassword(undefined), TypeError);
    });

    it('throws TypeError when password is an array', () => {
      assert.throws(() => validatePassword(['hello']), TypeError);
    });

    it('throws TypeError when password is a boolean', () => {
      assert.throws(() => validatePassword(true), TypeError);
    });

    it('error message mentions "password must be a string"', () => {
      assert.throws(
        () => validatePassword(99),
        { message: 'password must be a string' }
      );
    });
  });

  // ── 10. Invalid rules object ──────────────────────────────────────────────
  describe('invalid rules object', () => {
    it('throws TypeError when rules is a string', () => {
      assert.throws(() => validatePassword('Hello@123', 'minLength:8'), TypeError);
    });

    it('throws TypeError when rules is an array', () => {
      assert.throws(() => validatePassword('Hello@123', ['minLength']), TypeError);
    });

    it('throws TypeError when rules is a number', () => {
      assert.throws(() => validatePassword('Hello@123', 42), TypeError);
    });

    it('throws TypeError for an unknown rule key', () => {
      assert.throws(
        () => validatePassword('Hello@123', { strictMode: true }),
        TypeError
      );
    });

    it('throws TypeError when minLength is not an integer', () => {
      assert.throws(
        () => validatePassword('Hello@123', { minLength: 8.5 }),
        TypeError
      );
    });

    it('throws TypeError when minLength is zero', () => {
      assert.throws(
        () => validatePassword('Hello@123', { minLength: 0 }),
        TypeError
      );
    });

    it('throws TypeError when maxLength is a string', () => {
      assert.throws(
        () => validatePassword('Hello@123', { maxLength: '10' }),
        TypeError
      );
    });

    it('throws TypeError when minLength exceeds maxLength', () => {
      assert.throws(
        () => validatePassword('Hello@123', { minLength: 10, maxLength: 6 }),
        TypeError
      );
    });

    it('throws TypeError when requireUppercase is not a boolean', () => {
      assert.throws(
        () => validatePassword('Hello@123', { requireUppercase: 'yes' }),
        TypeError
      );
    });

    it('throws TypeError when requireSymbol is a number', () => {
      assert.throws(
        () => validatePassword('Hello@123', { requireSymbol: 1 }),
        TypeError
      );
    });
  });

  // ── 11. Default rules ─────────────────────────────────────────────────────
  describe('default rules', () => {
    it('accepts an empty rules object without throwing', () => {
      assert.doesNotThrow(() => validatePassword('Hello@123', {}));
    });

    it('accepts omitted rules without throwing', () => {
      assert.doesNotThrow(() => validatePassword('Hello@123'));
    });

    it('passes an 8-character password under default rules', () => {
      // Default minLength is 8; no character-type requirements by default.
      const result = validatePassword('Hello123');
      assert.strictEqual(result.valid, true);
    });

    it('fails a 7-character password under default rules', () => {
      // Default minLength is 8.
      const result = validatePassword('Hello12');
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('at least 8')));
    });

    it('handles an empty password string without throwing', () => {
      // Empty string is a valid JS string — it should produce a minLength error.
      const result = validatePassword('');
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('at least')));
    });
  });

  // ── 12. Existing functions still work ────────────────────────────────────
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
  });

});

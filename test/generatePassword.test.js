'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { generatePassword } = require('../index.js');

const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';

describe('generatePassword()', () => {

  describe('return type and length', () => {
    it('returns a string', () => {
      assert.strictEqual(typeof generatePassword(12), 'string');
    });

    it('returns correct length for 8 (minimum)', () => {
      assert.strictEqual(generatePassword(8).length, 8);
    });

    it('returns correct length for 16', () => {
      assert.strictEqual(generatePassword(16).length, 16);
    });

    it('returns correct length for 64', () => {
      assert.strictEqual(generatePassword(64).length, 64);
    });

    it('returns correct length for 128 (maximum)', () => {
      assert.strictEqual(generatePassword(128).length, 128);
    });
  });

  describe('default character set (uppercase + lowercase + numbers)', () => {
    it('contains only allowed characters by default', () => {
      for (let i = 0; i < 50; i++) {
        assert.match(generatePassword(20), /^[A-Za-z0-9]+$/);
      }
    });

    it('two calls return different passwords', () => {
      assert.notStrictEqual(generatePassword(20), generatePassword(20));
    });
  });

  describe('character options — single type', () => {
    it('uppercase only: contains only A–Z', () => {
      const pwd = generatePassword(20, { uppercase: true, lowercase: false, numbers: false });
      assert.match(pwd, /^[A-Z]+$/);
    });

    it('lowercase only: contains only a–z', () => {
      const pwd = generatePassword(20, { uppercase: false, lowercase: true, numbers: false });
      assert.match(pwd, /^[a-z]+$/);
    });

    it('numbers only: contains only 0–9', () => {
      const pwd = generatePassword(10, { uppercase: false, lowercase: false, numbers: true });
      assert.match(pwd, /^[0-9]+$/);
    });

    it('symbols only: contains only symbol characters', () => {
      const pwd = generatePassword(20, { uppercase: false, lowercase: false, numbers: false, symbols: true });
      for (const ch of pwd) {
        assert.ok(SYMBOLS.includes(ch), `unexpected character "${ch}"`);
      }
    });
  });

  describe('character options — combinations', () => {
    it('uppercase + numbers: contains only A–Z and 0–9', () => {
      const pwd = generatePassword(30, { uppercase: true, lowercase: false, numbers: true });
      assert.match(pwd, /^[A-Z0-9]+$/);
    });

    it('lowercase + symbols: contains only a–z and symbol characters', () => {
      const pwd = generatePassword(30, { uppercase: false, lowercase: true, numbers: false, symbols: true });
      for (const ch of pwd) {
        assert.ok(/[a-z]/.test(ch) || SYMBOLS.includes(ch), `unexpected character "${ch}"`);
      }
    });

    it('all types enabled: contains only allowed characters', () => {
      const pwd = generatePassword(50, { uppercase: true, lowercase: true, numbers: true, symbols: true });
      assert.match(pwd, /^[A-Za-z0-9!@#$%^&*()\-_=+\[\]{}|;:,.<>?]+$/);
    });
  });

  describe('length validation', () => {
    it('throws TypeError for undefined length', () => {
      assert.throws(() => generatePassword(undefined), TypeError);
    });

    it('throws TypeError for null length', () => {
      assert.throws(() => generatePassword(null), TypeError);
    });

    it('throws TypeError for NaN', () => {
      assert.throws(() => generatePassword(NaN), TypeError);
    });

    it('throws TypeError for a float', () => {
      assert.throws(() => generatePassword(8.5), TypeError);
    });

    it('throws TypeError for a string', () => {
      assert.throws(() => generatePassword('12'), TypeError);
    });

    it('throws RangeError for length 0', () => {
      assert.throws(() => generatePassword(0), RangeError);
    });

    it('throws RangeError for negative length', () => {
      assert.throws(() => generatePassword(-1), RangeError);
    });

    it('throws RangeError for length 7 (below minimum)', () => {
      assert.throws(() => generatePassword(7), RangeError);
    });

    it('throws RangeError for length 129 (above maximum)', () => {
      assert.throws(() => generatePassword(129), RangeError);
    });
  });

  describe('options validation', () => {
    it('throws TypeError when options is a string', () => {
      assert.throws(() => generatePassword(12, 'uppercase'), TypeError);
    });

    it('throws TypeError when options is an array', () => {
      assert.throws(() => generatePassword(12, ['uppercase']), TypeError);
    });

    it('throws TypeError when options is a number', () => {
      assert.throws(() => generatePassword(12, 42), TypeError);
    });

    it('throws TypeError when options.uppercase is not a boolean', () => {
      assert.throws(() => generatePassword(12, { uppercase: 'yes' }), TypeError);
    });

    it('throws TypeError when options.symbols is a number', () => {
      assert.throws(() => generatePassword(12, { symbols: 1 }), TypeError);
    });

    it('throws TypeError for unknown option key', () => {
      assert.throws(() => generatePassword(12, { specialMode: true }), TypeError);
    });

    it('throws Error when all character types are disabled', () => {
      assert.throws(
        () => generatePassword(12, { uppercase: false, lowercase: false, numbers: false, symbols: false }),
        { message: 'at least one character type must be enabled' }
      );
    });

    it('omitting options uses defaults (backward compatible)', () => {
      assert.strictEqual(generatePassword(16).length, 16);
    });
  });

  describe('guaranteed group coverage', () => {
    it('all 4 groups enabled: every password contains at least one char from each group', () => {
      for (let i = 0; i < 200; i++) {
        const pwd = generatePassword(8, { uppercase: true, lowercase: true, numbers: true, symbols: true });
        assert.ok(/[A-Z]/.test(pwd),          `missing uppercase in: ${pwd}`);
        assert.ok(/[a-z]/.test(pwd),          `missing lowercase in: ${pwd}`);
        assert.ok(/[0-9]/.test(pwd),          `missing number in: ${pwd}`);
        assert.ok(/[^A-Za-z0-9]/.test(pwd),  `missing symbol in: ${pwd}`);
      }
    });

    it('uppercase + numbers: every password contains at least one of each', () => {
      for (let i = 0; i < 200; i++) {
        const pwd = generatePassword(8, { uppercase: true, lowercase: false, numbers: true });
        assert.ok(/[A-Z]/.test(pwd), `missing uppercase in: ${pwd}`);
        assert.ok(/[0-9]/.test(pwd), `missing number in: ${pwd}`);
      }
    });

    it('lowercase + symbols: every password contains at least one of each', () => {
      const sym = '!@#$%^&*()-_=+[]{}|;:,.<>?';
      for (let i = 0; i < 200; i++) {
        const pwd = generatePassword(8, { uppercase: false, lowercase: true, numbers: false, symbols: true });
        assert.ok(/[a-z]/.test(pwd), `missing lowercase in: ${pwd}`);
        assert.ok([...pwd].some(ch => sym.includes(ch)), `missing symbol in: ${pwd}`);
      }
    });
  });

});

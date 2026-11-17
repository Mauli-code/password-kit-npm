'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { generateMultiplePasswords } = require('../index.js');

const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';

describe('generateMultiplePasswords()', () => {

  describe('return type and shape', () => {
    it('returns an array', () => {
      assert.ok(Array.isArray(generateMultiplePasswords(3, 12)));
    });

    it('every element is a string', () => {
      const result = generateMultiplePasswords(5, 12);
      for (const pwd of result) {
        assert.strictEqual(typeof pwd, 'string');
      }
    });
  });

  describe('count', () => {
    it('returns 1 password for count 1', () => {
      assert.strictEqual(generateMultiplePasswords(1, 12).length, 1);
    });

    it('returns 5 passwords for count 5', () => {
      assert.strictEqual(generateMultiplePasswords(5, 12).length, 5);
    });

    it('returns 10 passwords for count 10', () => {
      assert.strictEqual(generateMultiplePasswords(10, 12).length, 10);
    });

    it('returns 100 passwords for count 100 (maximum)', () => {
      assert.strictEqual(generateMultiplePasswords(100, 8).length, 100);
    });
  });

  describe('password length', () => {
    it('each password has the correct length', () => {
      const result = generateMultiplePasswords(10, 20);
      for (const pwd of result) {
        assert.strictEqual(pwd.length, 20);
      }
    });
  });

  describe('randomness', () => {
    it('passwords in the batch are not all identical', () => {
      const result = generateMultiplePasswords(5, 16);
      const unique = new Set(result);
      assert.ok(unique.size > 1, 'all 5 passwords are identical — extremely unlikely unless broken');
    });
  });

  describe('character options pass-through', () => {
    it('symbols only: each password contains only symbol characters', () => {
      const result = generateMultiplePasswords(5, 16, {
        uppercase: false, lowercase: false, numbers: false, symbols: true,
      });
      for (const pwd of result) {
        for (const ch of pwd) {
          assert.ok(SYMBOLS.includes(ch), `unexpected character "${ch}" in: ${pwd}`);
        }
      }
    });

    it('uppercase only: each password contains only A–Z', () => {
      const result = generateMultiplePasswords(5, 12, {
        uppercase: true, lowercase: false, numbers: false,
      });
      for (const pwd of result) {
        assert.match(pwd, /^[A-Z]+$/);
      }
    });
  });

  describe('count validation', () => {
    it('throws TypeError for undefined count', () => {
      assert.throws(() => generateMultiplePasswords(undefined, 12), TypeError);
    });

    it('throws TypeError for null count', () => {
      assert.throws(() => generateMultiplePasswords(null, 12), TypeError);
    });

    it('throws TypeError for NaN count', () => {
      assert.throws(() => generateMultiplePasswords(NaN, 12), TypeError);
    });

    it('throws TypeError for float count', () => {
      assert.throws(() => generateMultiplePasswords(2.5, 12), TypeError);
    });

    it('throws RangeError for count 0', () => {
      assert.throws(() => generateMultiplePasswords(0, 12), RangeError);
    });

    it('throws RangeError for negative count', () => {
      assert.throws(() => generateMultiplePasswords(-1, 12), RangeError);
    });

    it('throws RangeError for count 101 (above maximum)', () => {
      assert.throws(() => generateMultiplePasswords(101, 12), RangeError);
    });
  });

  describe('length validation (propagated from generatePassword)', () => {
    it('throws RangeError for invalid length', () => {
      assert.throws(() => generateMultiplePasswords(3, 200), RangeError);
    });

    it('throws TypeError for missing length', () => {
      assert.throws(() => generateMultiplePasswords(3, undefined), TypeError);
    });
  });

});

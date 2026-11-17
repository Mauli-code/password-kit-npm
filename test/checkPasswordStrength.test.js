'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { checkPasswordStrength } = require('../index.js');

describe('checkPasswordStrength()', () => {

  describe('return shape', () => {
    it('returns an object', () => {
      assert.strictEqual(typeof checkPasswordStrength('Hello1!'), 'object');
    });

    it('result has a strength string', () => {
      assert.strictEqual(typeof checkPasswordStrength('Hello1!').strength, 'string');
    });

    it('result has a numeric score', () => {
      assert.strictEqual(typeof checkPasswordStrength('Hello1!').score, 'number');
    });

    it('result has a reasons array', () => {
      assert.ok(Array.isArray(checkPasswordStrength('Hello1!').reasons));
    });

    it('score is between 0 and 6', () => {
      const { score } = checkPasswordStrength('Hello123!@#World');
      assert.ok(score >= 0 && score <= 6, `score ${score} is out of range`);
    });
  });

  describe('strength labels', () => {
    it('short, single-type password is Weak', () => {
      assert.strictEqual(checkPasswordStrength('abc').strength, 'Weak');
    });

    it('8 lowercase letters is Weak', () => {
      assert.strictEqual(checkPasswordStrength('abcdefgh').strength, 'Weak');
    });

    it('mixed case + number, short, is Medium', () => {
      assert.strictEqual(checkPasswordStrength('Hello1').strength, 'Medium');
    });

    it('8+ chars with uppercase, lowercase, number is Medium', () => {
      assert.strictEqual(checkPasswordStrength('Hello123').strength, 'Medium');
    });

    it('12+ chars with all character types is Strong', () => {
      assert.strictEqual(checkPasswordStrength('Hello123!@#World').strength, 'Strong');
    });
  });

  describe('scoring', () => {
    it('short password scores <= 2', () => {
      assert.ok(checkPasswordStrength('abc').score <= 2);
    });

    it('medium password scores 3–4', () => {
      const { score } = checkPasswordStrength('Hello1');
      assert.ok(score >= 3 && score <= 4, `expected 3–4, got ${score}`);
    });

    it('strong password scores >= 5', () => {
      assert.ok(checkPasswordStrength('Hello123!@#World').score >= 5);
    });

    it('score increases when uppercase is added', () => {
      const lower = checkPasswordStrength('hello123').score;
      const mixed = checkPasswordStrength('Hello123').score;
      assert.ok(mixed > lower);
    });

    it('score increases when symbol is added', () => {
      const noSym  = checkPasswordStrength('Hello123').score;
      const withSym = checkPasswordStrength('Hello123!').score;
      assert.ok(withSym > noSym);
    });

    it('score increases when length exceeds 12', () => {
      const short = checkPasswordStrength('Hello123').score;   // length 8
      const long  = checkPasswordStrength('Hello123abcd').score; // length 12
      assert.ok(long > short);
    });
  });

  describe('reasons', () => {
    it('includes "too short" reason for a short password', () => {
      const { reasons } = checkPasswordStrength('hi');
      assert.ok(reasons.some(r => r.includes('too short')));
    });

    it('includes "contains symbols" when symbols are present', () => {
      const { reasons } = checkPasswordStrength('Hello1!');
      assert.ok(reasons.some(r => r.includes('contains symbols')));
    });

    it('includes "no symbols" when symbols are absent', () => {
      const { reasons } = checkPasswordStrength('Hello123');
      assert.ok(reasons.some(r => r.includes('no symbols')));
    });

    it('includes "contains uppercase letters" for uppercase input', () => {
      const { reasons } = checkPasswordStrength('Hello');
      assert.ok(reasons.some(r => r.includes('contains uppercase letters')));
    });

    it('includes "no uppercase letters" for all-lowercase input', () => {
      const { reasons } = checkPasswordStrength('hello');
      assert.ok(reasons.some(r => r.includes('no uppercase letters')));
    });

    it('includes "contains numbers" when digits are present', () => {
      const { reasons } = checkPasswordStrength('hello1');
      assert.ok(reasons.some(r => r.includes('contains numbers')));
    });

    it('includes "no numbers" when digits are absent', () => {
      const { reasons } = checkPasswordStrength('Hello');
      assert.ok(reasons.some(r => r.includes('no numbers')));
    });
  });

  describe('input validation', () => {
    it('throws TypeError for a number', () => {
      assert.throws(() => checkPasswordStrength(12345), TypeError);
    });

    it('throws TypeError for null', () => {
      assert.throws(() => checkPasswordStrength(null), TypeError);
    });

    it('throws TypeError for undefined', () => {
      assert.throws(() => checkPasswordStrength(undefined), TypeError);
    });

    it('throws TypeError for an array', () => {
      assert.throws(() => checkPasswordStrength(['password']), TypeError);
    });

    it('throws Error for an empty string', () => {
      assert.throws(
        () => checkPasswordStrength(''),
        { message: 'password must not be empty' }
      );
    });
  });

});

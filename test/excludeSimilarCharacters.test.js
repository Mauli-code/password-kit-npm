'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { generatePassword, generateMultiplePasswords } = require('../index.js');

// The five characters that must never appear when the option is on.
const SIMILAR = '01lOI';

// Run enough iterations so a random false-positive is essentially impossible.
const ITERATIONS = 500;

describe('generatePassword() — excludeSimilarCharacters option', () => {

  // ── 1. Excluded characters never appear when the option is enabled ──────────
  describe('excluded characters never appear', () => {
    it('no similar character appears in any of 500 passwords (all types enabled)', () => {
      for (let i = 0; i < ITERATIONS; i++) {
        const pwd = generatePassword(16, {
          uppercase:               true,
          lowercase:               true,
          numbers:                 true,
          symbols:                 true,
          excludeSimilarCharacters: true,
        });
        for (const ch of SIMILAR) {
          assert.ok(
            !pwd.includes(ch),
            `found similar character "${ch}" in password: ${pwd}`
          );
        }
      }
    });

    it('"0" never appears with numbers enabled and excludeSimilarCharacters on', () => {
      for (let i = 0; i < ITERATIONS; i++) {
        const pwd = generatePassword(16, {
          uppercase:               false,
          lowercase:               false,
          numbers:                 true,
          excludeSimilarCharacters: true,
        });
        assert.ok(!pwd.includes('0'), `found "0" in: ${pwd}`);
      }
    });

    it('"1" never appears with numbers enabled and excludeSimilarCharacters on', () => {
      for (let i = 0; i < ITERATIONS; i++) {
        const pwd = generatePassword(16, {
          uppercase:               false,
          lowercase:               false,
          numbers:                 true,
          excludeSimilarCharacters: true,
        });
        assert.ok(!pwd.includes('1'), `found "1" in: ${pwd}`);
      }
    });

    it('"O" never appears with uppercase enabled and excludeSimilarCharacters on', () => {
      for (let i = 0; i < ITERATIONS; i++) {
        const pwd = generatePassword(16, {
          uppercase:               true,
          lowercase:               false,
          numbers:                 false,
          excludeSimilarCharacters: true,
        });
        assert.ok(!pwd.includes('O'), `found "O" in: ${pwd}`);
      }
    });

    it('"I" never appears with uppercase enabled and excludeSimilarCharacters on', () => {
      for (let i = 0; i < ITERATIONS; i++) {
        const pwd = generatePassword(16, {
          uppercase:               true,
          lowercase:               false,
          numbers:                 false,
          excludeSimilarCharacters: true,
        });
        assert.ok(!pwd.includes('I'), `found "I" in: ${pwd}`);
      }
    });

    it('"l" never appears with lowercase enabled and excludeSimilarCharacters on', () => {
      for (let i = 0; i < ITERATIONS; i++) {
        const pwd = generatePassword(16, {
          uppercase:               false,
          lowercase:               true,
          numbers:                 false,
          excludeSimilarCharacters: true,
        });
        assert.ok(!pwd.includes('l'), `found "l" in: ${pwd}`);
      }
    });
  });

  // ── 2. Default behavior is unchanged ────────────────────────────────────────
  describe('default behavior is unchanged', () => {
    it('omitting the option does not change the returned password length', () => {
      assert.strictEqual(generatePassword(16).length, 16);
    });

    it('similar characters CAN appear when the option is false (default)', () => {
      // Run enough attempts that at least one similar character will appear
      // in a numbers-only password (pool = 10, 2 of which are similar → 20% chance).
      let found = false;
      for (let i = 0; i < 200; i++) {
        const pwd = generatePassword(8, {
          uppercase: false,
          lowercase: false,
          numbers:   true,
        });
        if (pwd.includes('0') || pwd.includes('1')) {
          found = true;
          break;
        }
      }
      assert.ok(found, 'expected similar characters to appear without the option enabled');
    });

    it('setting excludeSimilarCharacters: false behaves the same as omitting it', () => {
      // Both calls should succeed and produce the correct length.
      const a = generatePassword(12, { excludeSimilarCharacters: false });
      const b = generatePassword(12);
      assert.strictEqual(a.length, 12);
      assert.strictEqual(b.length, 12);
    });
  });

  // ── 3. All enabled character groups are still represented ────────────────────
  describe('group coverage guarantee is preserved', () => {
    it('every password still contains at least one char from each enabled group', () => {
      // After filtering, uppercase still has 24 chars, lowercase 25, numbers 8.
      for (let i = 0; i < ITERATIONS; i++) {
        const pwd = generatePassword(8, {
          uppercase:               true,
          lowercase:               true,
          numbers:                 true,
          excludeSimilarCharacters: true,
        });
        // Must contain an uppercase letter that is not O or I.
        assert.ok(/[A-HJ-NP-Z]/.test(pwd), `missing uppercase in: ${pwd}`);
        // Must contain a lowercase letter that is not l.
        assert.ok(/[a-km-z]/.test(pwd), `missing lowercase in: ${pwd}`);
        // Must contain a digit that is not 0 or 1.
        assert.ok(/[2-9]/.test(pwd), `missing digit in: ${pwd}`);
      }
    });

    it('symbols group is still fully represented (no similar chars in symbols)', () => {
      for (let i = 0; i < ITERATIONS; i++) {
        const pwd = generatePassword(8, {
          uppercase:               false,
          lowercase:               false,
          numbers:                 false,
          symbols:                 true,
          excludeSimilarCharacters: true,
        });
        // All chars should be symbols — none are from SIMILAR.
        assert.ok(/^[^A-Za-z0-9]+$/.test(pwd), `non-symbol character found in: ${pwd}`);
      }
    });
  });

  // ── 4. generateMultiplePasswords() respects the option ───────────────────────
  describe('generateMultiplePasswords() with excludeSimilarCharacters', () => {
    it('no similar character appears in any of the generated passwords', () => {
      const passwords = generateMultiplePasswords(20, 16, {
        uppercase:               true,
        lowercase:               true,
        numbers:                 true,
        excludeSimilarCharacters: true,
      });
      for (const pwd of passwords) {
        for (const ch of SIMILAR) {
          assert.ok(
            !pwd.includes(ch),
            `found similar character "${ch}" in password: ${pwd}`
          );
        }
      }
    });

    it('returns the correct count and length', () => {
      const passwords = generateMultiplePasswords(5, 12, {
        excludeSimilarCharacters: true,
      });
      assert.strictEqual(passwords.length, 5);
      for (const pwd of passwords) {
        assert.strictEqual(pwd.length, 12);
      }
    });
  });

  // ── 5. Invalid option values throw a TypeError ───────────────────────────────
  describe('invalid option values', () => {
    it('throws TypeError when excludeSimilarCharacters is a string', () => {
      assert.throws(
        () => generatePassword(12, { excludeSimilarCharacters: 'yes' }),
        TypeError
      );
    });

    it('throws TypeError when excludeSimilarCharacters is a number', () => {
      assert.throws(
        () => generatePassword(12, { excludeSimilarCharacters: 1 }),
        TypeError
      );
    });

    it('error message mentions the option name', () => {
      assert.throws(
        () => generatePassword(12, { excludeSimilarCharacters: 'true' }),
        { message: 'options.excludeSimilarCharacters must be a boolean' }
      );
    });
  });

  // ── 6. Existing length validation still works ────────────────────────────────
  describe('length validation is unaffected', () => {
    it('throws RangeError for length below 8 even with the new option', () => {
      assert.throws(
        () => generatePassword(7, { excludeSimilarCharacters: true }),
        RangeError
      );
    });

    it('throws RangeError for length above 128 even with the new option', () => {
      assert.throws(
        () => generatePassword(129, { excludeSimilarCharacters: true }),
        RangeError
      );
    });

    it('generates a password at the minimum length of 8', () => {
      const pwd = generatePassword(8, { excludeSimilarCharacters: true });
      assert.strictEqual(pwd.length, 8);
    });
  });

});

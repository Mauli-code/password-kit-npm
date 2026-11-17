'use strict';

/**
 * password-kit-js
 * A lightweight utility kit for generating and validating passwords.
 */

const crypto = require('crypto');

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS   = '0123456789';

const DEFAULT_CHARSET = UPPERCASE + LOWERCASE + NUMBERS;

/**
 * Generates a cryptographically secure random password.
 *
 * @param {number} length - The desired password length (must be between 4 and 128).
 * @returns {string} The generated password.
 */
function generatePassword(length) {
  if (typeof length !== 'number' || !Number.isInteger(length)) {
    throw new TypeError('length must be an integer');
  }
  if (length < 4 || length > 128) {
    throw new RangeError('length must be between 4 and 128');
  }

  let password = '';
  for (let i = 0; i < length; i++) {
    const index = crypto.randomInt(0, DEFAULT_CHARSET.length);
    password += DEFAULT_CHARSET[index];
  }
  return password;
}

module.exports = { generatePassword };

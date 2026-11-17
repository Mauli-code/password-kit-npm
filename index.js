'use strict';

/**
 * password-kit-js
 * A lightweight utility kit for generating and validating passwords.
 */

const crypto = require('crypto');

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS   = '0123456789';
const SYMBOLS   = '!@#$%^&*()-_=+[]{}|;:,.<>?';

/**
 * Default character options — all types enabled.
 */
const DEFAULT_OPTIONS = {
  uppercase: true,
  lowercase: true,
  numbers:   true,
  symbols:   false,
};

/**
 * Generates a cryptographically secure random password.
 *
 * @param {number} length  - The desired password length (must be between 4 and 128).
 * @param {object} options - Which character types to include (optional).
 * @param {boolean} [options.uppercase=true]  - Include uppercase letters (A–Z).
 * @param {boolean} [options.lowercase=true]  - Include lowercase letters (a–z).
 * @param {boolean} [options.numbers=true]    - Include digits (0–9).
 * @param {boolean} [options.symbols=false]   - Include symbols (!@#$ …).
 * @returns {string} The generated password.
 */
function generatePassword(length, options) {
  // --- Validate length ---
  if (typeof length !== 'number' || !Number.isInteger(length)) {
    throw new TypeError('length must be an integer');
  }
  if (length < 4 || length > 128) {
    throw new RangeError('length must be between 4 and 128');
  }

  // --- Merge options with defaults ---
  const opts = Object.assign({}, DEFAULT_OPTIONS, options);

  // --- Build charset from enabled types ---
  let charset = '';
  if (opts.uppercase) charset += UPPERCASE;
  if (opts.lowercase) charset += LOWERCASE;
  if (opts.numbers)   charset += NUMBERS;
  if (opts.symbols)   charset += SYMBOLS;

  if (charset.length === 0) {
    throw new Error('at least one character type must be enabled');
  }

  // --- Generate password ---
  let password = '';
  for (let i = 0; i < length; i++) {
    const index = crypto.randomInt(0, charset.length);
    password += charset[index];
  }
  return password;
}

module.exports = { generatePassword };

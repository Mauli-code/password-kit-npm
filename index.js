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

/**
 * Generates multiple cryptographically secure random passwords.
 *
 * @param {number} count   - Number of passwords to generate (must be between 1 and 100).
 * @param {number} length  - Length of each password (must be between 4 and 128).
 * @param {object} options - Same character type options as generatePassword() (optional).
 * @returns {string[]} Array of generated passwords.
 */
function generateMultiplePasswords(count, length, options) {
  if (typeof count !== 'number' || !Number.isInteger(count)) {
    throw new TypeError('count must be an integer');
  }
  if (count < 1 || count > 100) {
    throw new RangeError('count must be between 1 and 100');
  }

  const passwords = [];
  for (let i = 0; i < count; i++) {
    passwords.push(generatePassword(length, options));
  }
  return passwords;
}

/**
 * Checks the strength of a given password.
 *
 * Scoring (1 point each):
 *   - Length >= 8
 *   - Length >= 12
 *   - Contains uppercase letters (A–Z)
 *   - Contains lowercase letters (a–z)
 *   - Contains numbers (0–9)
 *   - Contains symbols
 *
 * Score 0–2 → Weak | 3–4 → Medium | 5–6 → Strong
 *
 * Note: this is a basic heuristic check, not a full security audit.
 *
 * @param {string} password - The password to evaluate.
 * @returns {{ strength: string, score: number, reasons: string[] }}
 */
function checkPasswordStrength(password) {
  if (typeof password !== 'string') {
    throw new TypeError('password must be a string');
  }
  if (password.length === 0) {
    throw new Error('password must not be empty');
  }

  const reasons = [];
  let score = 0;

  // --- Length checks ---
  if (password.length >= 8) {
    score++;
    reasons.push('at least 8 characters');
  } else {
    reasons.push('too short (less than 8 characters)');
  }

  if (password.length >= 12) {
    score++;
    reasons.push('at least 12 characters');
  }

  // --- Character type checks ---
  if (/[A-Z]/.test(password)) {
    score++;
    reasons.push('contains uppercase letters');
  } else {
    reasons.push('no uppercase letters');
  }

  if (/[a-z]/.test(password)) {
    score++;
    reasons.push('contains lowercase letters');
  } else {
    reasons.push('no lowercase letters');
  }

  if (/[0-9]/.test(password)) {
    score++;
    reasons.push('contains numbers');
  } else {
    reasons.push('no numbers');
  }

  if (/[^A-Za-z0-9]/.test(password)) {
    score++;
    reasons.push('contains symbols');
  } else {
    reasons.push('no symbols');
  }

  // --- Determine strength label ---
  let strength;
  if (score <= 2) {
    strength = 'Weak';
  } else if (score <= 4) {
    strength = 'Medium';
  } else {
    strength = 'Strong';
  }

  return { strength, score, reasons };
}

module.exports = { generatePassword, generateMultiplePasswords, checkPasswordStrength };

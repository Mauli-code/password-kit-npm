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
 * Validates that a value is a plain object (not an array, null, or other type).
 * Returns an error message string if invalid, or null if valid.
 *
 * @param {*} value
 * @param {string} name - Name used in the error message.
 * @returns {string|null}
 */
function validateOptions(value, name) {
  if (value === undefined || value === null) return null; // optional — absence is fine
  if (typeof value !== 'object' || Array.isArray(value)) {
    return `${name} must be a plain object`;
  }
  const allowed = ['uppercase', 'lowercase', 'numbers', 'symbols'];
  // Reject unknown keys
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      return `unknown option "${key}" — allowed keys are: ${allowed.join(', ')}`;
    }
  }
  // Ensure known keys are booleans
  for (const key of allowed) {
    if (key in value && typeof value[key] !== 'boolean') {
      return `options.${key} must be a boolean`;
    }
  }
  return null;
}

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
  if (length === undefined || length === null) {
    throw new TypeError('length is required');
  }
  if (typeof length !== 'number' || isNaN(length) || !Number.isInteger(length)) {
    throw new TypeError('length must be a whole number (integer)');
  }
  if (length < 8 || length > 128) {
    throw new RangeError('length must be between 8 and 128');
  }

  // --- Validate options ---
  const optionsError = validateOptions(options, 'options');
  if (optionsError) throw new TypeError(optionsError);

  // --- Merge options with defaults ---
  const opts = Object.assign({}, DEFAULT_OPTIONS, options);

  // --- Build per-group and combined charsets ---
  const groups = [];
  if (opts.uppercase) groups.push(UPPERCASE);
  if (opts.lowercase) groups.push(LOWERCASE);
  if (opts.numbers)   groups.push(NUMBERS);
  if (opts.symbols)   groups.push(SYMBOLS);

  if (groups.length === 0) {
    throw new Error('at least one character type must be enabled');
  }

  // length is always >= 8 and groups.length is at most 4, so this never
  // triggers in practice — but it makes the constraint explicit.
  if (length < groups.length) {
    throw new RangeError(
      `length (${length}) must be at least ${groups.length} to include one character from each enabled group`
    );
  }

  const charset = groups.join('');

  // --- Guarantee one character from every enabled group ---
  const chars = [];
  for (const group of groups) {
    chars.push(group[crypto.randomInt(0, group.length)]);
  }

  // --- Fill remaining slots from the full charset ---
  while (chars.length < length) {
    chars.push(charset[crypto.randomInt(0, charset.length)]);
  }

  // --- Fisher-Yates shuffle using crypto.randomInt ---
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
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
  // --- Validate count ---
  if (count === undefined || count === null) {
    throw new TypeError('count is required');
  }
  if (typeof count !== 'number' || isNaN(count) || !Number.isInteger(count)) {
    throw new TypeError('count must be a whole number (integer)');
  }
  if (count < 1 || count > 100) {
    throw new RangeError('count must be between 1 and 100');
  }

  // length and options are validated inside generatePassword()
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

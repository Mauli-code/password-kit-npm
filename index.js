'use strict';

const crypto = require('crypto');

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS   = '0123456789';
const SYMBOLS   = '!@#$%^&*()-_=+[]{}|;:,.<>?';

const DEFAULT_OPTIONS = {
  uppercase: true,
  lowercase: true,
  numbers:   true,
  symbols:   false,
};

// Returns an error message string if options is invalid, otherwise null.
function validateOptions(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) {
    return 'options must be a plain object';
  }
  const allowed = ['uppercase', 'lowercase', 'numbers', 'symbols'];
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      return `unknown option "${key}" — allowed keys are: ${allowed.join(', ')}`;
    }
  }
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
 * @param {number} length  - Password length, between 8 and 128.
 * @param {object} [options] - Which character types to include.
 * @param {boolean} [options.uppercase=true]  - Include A–Z.
 * @param {boolean} [options.lowercase=true]  - Include a–z.
 * @param {boolean} [options.numbers=true]    - Include 0–9.
 * @param {boolean} [options.symbols=false]   - Include !@#$% …
 * @returns {string}
 */
function generatePassword(length, options) {
  if (length === undefined || length === null) {
    throw new TypeError('length is required');
  }
  if (typeof length !== 'number' || isNaN(length) || !Number.isInteger(length)) {
    throw new TypeError('length must be a whole number (integer)');
  }
  if (length < 8 || length > 128) {
    throw new RangeError('length must be between 8 and 128');
  }

  const optionsError = validateOptions(options);
  if (optionsError) throw new TypeError(optionsError);

  const opts = Object.assign({}, DEFAULT_OPTIONS, options);

  const groups = [];
  if (opts.uppercase) groups.push(UPPERCASE);
  if (opts.lowercase) groups.push(LOWERCASE);
  if (opts.numbers)   groups.push(NUMBERS);
  if (opts.symbols)   groups.push(SYMBOLS);

  if (groups.length === 0) {
    throw new Error('at least one character type must be enabled');
  }

  const charset = groups.join('');

  // Pick one character from each enabled group to guarantee coverage.
  const chars = groups.map(group => group[crypto.randomInt(0, group.length)]);

  // Fill remaining slots from the full charset.
  while (chars.length < length) {
    chars.push(charset[crypto.randomInt(0, charset.length)]);
  }

  // Fisher-Yates shuffle so the guaranteed characters aren't always at the front.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}

/**
 * Generates multiple cryptographically secure random passwords.
 *
 * @param {number} count   - Number of passwords, between 1 and 100.
 * @param {number} length  - Length of each password, between 8 and 128.
 * @param {object} [options] - Same options as generatePassword().
 * @returns {string[]}
 */
function generateMultiplePasswords(count, length, options) {
  if (count === undefined || count === null) {
    throw new TypeError('count is required');
  }
  if (typeof count !== 'number' || isNaN(count) || !Number.isInteger(count)) {
    throw new TypeError('count must be a whole number (integer)');
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
 * Checks the strength of a password string.
 *
 * Scoring — 1 point each:
 *   length >= 8, length >= 12, uppercase, lowercase, numbers, symbols
 *
 * Score 0–2 → Weak | 3–4 → Medium | 5–6 → Strong
 *
 * Note: basic heuristic only, not a security audit.
 *
 * @param {string} password
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

  let strength;
  if (score <= 2)      strength = 'Weak';
  else if (score <= 4) strength = 'Medium';
  else                 strength = 'Strong';

  return { strength, score, reasons };
}

module.exports = { generatePassword, generateMultiplePasswords, checkPasswordStrength };

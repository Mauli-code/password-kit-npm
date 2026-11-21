'use strict';

const crypto = require('crypto');

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS   = '0123456789';
const SYMBOLS   = '!@#$%^&*()-_=+[]{}|;:,.<>?';

// Characters that look alike and are easy to misread (zero/O, one/l/I).
const SIMILAR = '01lOI';

const DEFAULT_OPTIONS = {
  uppercase:               true,
  lowercase:               true,
  numbers:                 true,
  symbols:                 false,
  excludeSimilarCharacters: false,
};

// Returns an error message string if options is invalid, otherwise null.
function validateOptions(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) {
    return 'options must be a plain object';
  }
  const allowed = ['uppercase', 'lowercase', 'numbers', 'symbols', 'excludeSimilarCharacters'];
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
 * @param {boolean} [options.uppercase=true]               - Include A–Z.
 * @param {boolean} [options.lowercase=true]               - Include a–z.
 * @param {boolean} [options.numbers=true]                 - Include 0–9.
 * @param {boolean} [options.symbols=false]                - Include !@#$% …
 * @param {boolean} [options.excludeSimilarCharacters=false] - Remove 0, O, 1, l, I.
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

  // Build the list of character groups based on which types are enabled.
  let groups = [];
  if (opts.uppercase) groups.push(UPPERCASE);
  if (opts.lowercase) groups.push(LOWERCASE);
  if (opts.numbers)   groups.push(NUMBERS);
  if (opts.symbols)   groups.push(SYMBOLS);

  if (groups.length === 0) {
    throw new Error('at least one character type must be enabled');
  }

  // If excludeSimilarCharacters is on, strip look-alike characters from every group.
  if (opts.excludeSimilarCharacters) {
    groups = groups.map(group =>
      [...group].filter(ch => !SIMILAR.includes(ch)).join('')
    );

    // Guard: if any group ends up empty after filtering, skip it rather than
    // crashing. (With the current constants this cannot happen, but it is safer
    // to be explicit so future changes to SIMILAR or the charsets don't break things.)
    groups = groups.filter(group => group.length > 0);

    if (groups.length === 0) {
      throw new Error('all character groups became empty after excluding similar characters');
    }
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

// ─── validatePassword ────────────────────────────────────────────────────────

// All rule names that validatePassword() understands.
const ALLOWED_RULES = ['minLength', 'maxLength', 'requireUppercase', 'requireLowercase', 'requireNumber', 'requireSymbol'];

// Sensible defaults applied when rules are omitted.
const DEFAULT_RULES = {
  minLength:        8,
  maxLength:        128,
  requireUppercase: false,
  requireLowercase: false,
  requireNumber:    false,
  requireSymbol:    false,
};

/**
 * Validates a rules object and throws a descriptive TypeError for any problem.
 *
 * @param {object} rules
 */
function validateRules(rules) {
  if (rules === undefined || rules === null) return; // use defaults — that is fine

  if (typeof rules !== 'object' || Array.isArray(rules)) {
    throw new TypeError('rules must be a plain object');
  }

  for (const key of Object.keys(rules)) {
    if (!ALLOWED_RULES.includes(key)) {
      throw new TypeError(
        `unknown rule "${key}" — allowed rules are: ${ALLOWED_RULES.join(', ')}`
      );
    }
  }

  if ('minLength' in rules) {
    if (typeof rules.minLength !== 'number' || !Number.isInteger(rules.minLength) || rules.minLength < 1) {
      throw new TypeError('rules.minLength must be a positive integer');
    }
  }

  if ('maxLength' in rules) {
    if (typeof rules.maxLength !== 'number' || !Number.isInteger(rules.maxLength) || rules.maxLength < 1) {
      throw new TypeError('rules.maxLength must be a positive integer');
    }
  }

  // If both are provided, minLength must not exceed maxLength.
  const min = 'minLength' in rules ? rules.minLength : DEFAULT_RULES.minLength;
  const max = 'maxLength' in rules ? rules.maxLength : DEFAULT_RULES.maxLength;
  if (min > max) {
    throw new TypeError('rules.minLength cannot be greater than rules.maxLength');
  }

  for (const key of ['requireUppercase', 'requireLowercase', 'requireNumber', 'requireSymbol']) {
    if (key in rules && typeof rules[key] !== 'boolean') {
      throw new TypeError(`rules.${key} must be a boolean`);
    }
  }
}

/**
 * Checks whether a password satisfies the given policy rules.
 *
 * @param {string} password - The password to check.
 * @param {object} [rules]  - Policy rules (see README for available options).
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validatePassword(password, rules) {
  // 1. Validate password type first.
  if (typeof password !== 'string') {
    throw new TypeError('password must be a string');
  }

  // 2. Validate the rules object before using it.
  validateRules(rules);

  // 3. Merge caller-supplied rules over the defaults.
  const policy = Object.assign({}, DEFAULT_RULES, rules);

  const errors = [];

  // Length checks.
  if (password.length < policy.minLength) {
    errors.push(`Password must be at least ${policy.minLength} characters`);
  }

  if (password.length > policy.maxLength) {
    errors.push(`Password must be no more than ${policy.maxLength} characters`);
  }

  // Character-type checks — reuse the same regex patterns as checkPasswordStrength().
  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain an uppercase letter');
  }

  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain a lowercase letter');
  }

  if (policy.requireNumber && !/[0-9]/.test(password)) {
    errors.push('Password must contain a number');
  }

  if (policy.requireSymbol && !/[^A-Za-z0-9]/.test(password)) {
    errors.push('Password must contain a symbol');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

// ─── calculatePasswordEntropy ─────────────────────────────────────────────────

/**
 * Estimates the entropy of a password in bits using the formula:
 *
 *   entropy = passwordLength × log2(characterPoolSize)
 *
 * The pool size is the total number of distinct characters the password
 * could have been chosen from, estimated by which character types are
 * actually present:
 *
 *   Lowercase letters  → 26
 *   Uppercase letters  → 26
 *   Digits             → 10
 *   Symbols            → size of the SYMBOLS constant (26 characters)
 *
 * Any character that falls outside all four groups is counted once as
 * an "other" character and adds 1 to the pool size.
 *
 * Note: this is a theoretical upper bound assuming every character was
 * chosen randomly. Real human-created passwords are usually weaker.
 *
 * @param {string} password
 * @returns {{ entropy: number, level: string }}
 */
function calculatePasswordEntropy(password) {
  if (typeof password !== 'string') {
    throw new TypeError('password must be a string');
  }
  if (password.length === 0) {
    throw new Error('password must not be empty');
  }

  // Build the pool size from the character types that appear in the password.
  let pool = 0;
  if (/[a-z]/.test(password)) pool += LOWERCASE.length; // 26
  if (/[A-Z]/.test(password)) pool += UPPERCASE.length; // 26
  if (/[0-9]/.test(password)) pool += NUMBERS.length;   // 10
  if (/[^A-Za-z0-9]/.test(password)) pool += SYMBOLS.length; // 26

  // Any character that is not in the standard symbol set but is also not
  // alphanumeric (e.g. accented letters, emoji) bumps the pool by 1 each.
  for (const ch of password) {
    const isKnown =
      LOWERCASE.includes(ch) ||
      UPPERCASE.includes(ch) ||
      NUMBERS.includes(ch)   ||
      SYMBOLS.includes(ch);
    if (!isKnown) pool += 1;
  }

  // entropy = length × log2(pool)
  const entropy = Math.round(password.length * Math.log2(pool) * 100) / 100;

  // Classify the result.
  let level;
  if      (entropy < 40) level = 'Low';
  else if (entropy < 60) level = 'Moderate';
  else if (entropy < 80) level = 'High';
  else                   level = 'Very High';

  return { entropy, level };
}

module.exports = {
  generatePassword,
  generateMultiplePasswords,
  checkPasswordStrength,
  validatePassword,
  calculatePasswordEntropy,
};

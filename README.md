# password-kit-js

A lightweight utility kit for generating and validating passwords in Node.js.

- Generates cryptographically secure passwords using Node.js built-in `crypto`
- Supports uppercase, lowercase, numbers, and symbols
- Checks password strength with a human-readable score and reasons
- Zero external dependencies
- CommonJS — works in any Node.js project

---

## Installation

```bash
npm install password-kit-js
```

---

## Functions

| Function | Description |
|---|---|
| `generatePassword(length, options)` | Generate one secure password |
| `generateMultiplePasswords(count, length, options)` | Generate several passwords at once |
| `checkPasswordStrength(password)` | Check the strength of any password |

---

## Usage

### `generatePassword(length, options)`

Generates a single cryptographically secure password.

**Parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `length` | integer | Yes | Password length — must be between `4` and `128` |
| `options` | object | No | Which character types to include (see below) |

**Default options** — when `options` is omitted:

| Option | Default | Description |
|---|---|---|
| `uppercase` | `true` | Include A–Z |
| `lowercase` | `true` | Include a–z |
| `numbers` | `true` | Include 0–9 |
| `symbols` | `false` | Include `!@#$%^&*()-_=+[]{}|;:,.<>?` |

```js
const { generatePassword } = require('password-kit-js');

// Default — uppercase, lowercase, and numbers
const password = generatePassword(16);
console.log(password); // e.g. "aB3kR7tLmN2pQxWz"

// All character types enabled
const strong = generatePassword(20, {
  uppercase: true,
  lowercase: true,
  numbers:   true,
  symbols:   true,
});
console.log(strong); // e.g. "k@3Rp!mZ9#aB2$Lq7^Tn"

// Numbers only
const pin = generatePassword(6, {
  uppercase: false,
  lowercase: false,
  numbers:   true,
});
console.log(pin); // e.g. "483921"

// Lowercase letters only
const readable = generatePassword(12, {
  uppercase: false,
  lowercase: true,
  numbers:   false,
});
console.log(readable); // e.g. "krtxbmvnapqc"
```

---

### `generateMultiplePasswords(count, length, options)`

Generates several passwords at once and returns them as an array.

**Parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `count` | integer | Yes | Number of passwords — must be between `1` and `100` |
| `length` | integer | Yes | Length of each password — must be between `4` and `128` |
| `options` | object | No | Same character type options as `generatePassword()` |

```js
const { generateMultiplePasswords } = require('password-kit-js');

// Generate 5 passwords, each 16 characters long
const passwords = generateMultiplePasswords(5, 16);
console.log(passwords);
// [
//   "aB3kR7tLmN2pQxWz",
//   "Tz9mKpRqL4nWbXcY",
//   "Qr2NpLmTkB7wXzVa",
//   "Mn4KpRqTzL9bWcXy",
//   "Lp7NqRmTzK2bXcWa"
// ]

// Generate 3 passwords with symbols enabled
const withSymbols = generateMultiplePasswords(3, 12, { symbols: true });
console.log(withSymbols);
// [
//   "aB3@kR#tLm2!",
//   "Tz9$mK%pRqL4",
//   "Qr2^NpLm&TkB"
// ]
```

---

### `checkPasswordStrength(password)`

Checks the strength of a given password string. Returns a score out of 6, a strength label, and a list of reasons explaining the result.

**Parameter**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `password` | string | Yes | The password to evaluate |

**Scoring rules — 1 point for each criterion met:**

| Criterion | Points |
|---|---|
| Length ≥ 8 | +1 |
| Length ≥ 12 | +1 |
| Contains uppercase letters (A–Z) | +1 |
| Contains lowercase letters (a–z) | +1 |
| Contains numbers (0–9) | +1 |
| Contains symbols | +1 |

**Strength labels:**

| Score | Strength |
|---|---|
| 0–2 | `Weak` |
| 3–4 | `Medium` |
| 5–6 | `Strong` |

```js
const { checkPasswordStrength } = require('password-kit-js');

// Weak password
console.log(checkPasswordStrength('abc'));
// {
//   strength: 'Weak',
//   score: 1,
//   reasons: [
//     'too short (less than 8 characters)',
//     'no uppercase letters',
//     'contains lowercase letters',
//     'no numbers',
//     'no symbols'
//   ]
// }

// Medium password
console.log(checkPasswordStrength('Hello123'));
// {
//   strength: 'Medium',
//   score: 4,
//   reasons: [
//     'at least 8 characters',
//     'contains uppercase letters',
//     'contains lowercase letters',
//     'contains numbers',
//     'no symbols'
//   ]
// }

// Strong password
console.log(checkPasswordStrength('Hello123!@#World'));
// {
//   strength: 'Strong',
//   score: 6,
//   reasons: [
//     'at least 8 characters',
//     'at least 12 characters',
//     'contains uppercase letters',
//     'contains lowercase letters',
//     'contains numbers',
//     'contains symbols'
//   ]
// }
```

---

## Input Validation

All functions validate their inputs and throw descriptive errors for invalid arguments.

```js
const { generatePassword, generateMultiplePasswords, checkPasswordStrength } = require('password-kit-js');

// Missing length
generatePassword();
// TypeError: length is required

// Non-integer length
generatePassword(8.5);
// TypeError: length must be a whole number (integer)

// Length out of range
generatePassword(3);
// RangeError: length must be between 4 and 128

// Invalid options type
generatePassword(12, 'uppercase');
// TypeError: options must be a plain object

// Non-boolean option value
generatePassword(12, { uppercase: 'yes' });
// TypeError: options.uppercase must be a boolean

// All character types disabled
generatePassword(12, { uppercase: false, lowercase: false, numbers: false, symbols: false });
// Error: at least one character type must be enabled

// Missing count
generateMultiplePasswords();
// TypeError: count is required

// Count out of range
generateMultiplePasswords(0, 12);
// RangeError: count must be between 1 and 100

// Non-string password
checkPasswordStrength(12345);
// TypeError: password must be a string

// Empty password
checkPasswordStrength('');
// Error: password must not be empty
```

---

## Testing

```bash
npm test
```

Tests are written using Node.js built-in `node:test` and `node:assert` — no external libraries needed.

```
tests: 78 | pass: 78 | fail: 0
```

---

## Security Notes

- All passwords are generated using [`crypto.randomInt()`](https://nodejs.org/api/crypto.html#cryptorandomintmin-max), which is cryptographically secure. `Math.random()` is never used.
- No passwords are logged, stored, or transmitted by this package.
- This package has zero runtime dependencies, which minimises supply-chain risk.

---

## Strength Checker Limitations

`checkPasswordStrength()` is a simple heuristic tool, not a security audit:

- It does not check whether the password appears in known breach databases (e.g. Have I Been Pwned).
- It does not detect repeated characters, keyboard patterns, or dictionary words.
- A `Strong` score means the password meets common complexity guidelines, not that it is uncrackable.

For high-security applications, consider pairing this tool with a dedicated password analysis library.

---

## License

MIT © Mauli-code

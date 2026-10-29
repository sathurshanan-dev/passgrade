'use strict';

const COMMON = new Set([
  'password',
  'password1',
  'password123',
  '123456',
  '12345678',
  '123456789',
  '1234567890',
  'qwerty',
  'qwerty123',
  'admin',
  'admin123',
  'letmein',
  'welcome',
  'iloveyou',
  'abc123',
  '111111',
  '000000',
  'passw0rd',
  'p@ssw0rd',
  'monkey',
  'dragon',
]);

function checkPassword(password, options = {}) {
  if (typeof password !== 'string') {
    throw new TypeError('password must be a string');
  }

  if (
    options === null ||
    typeof options !== 'object' ||
    Array.isArray(options)
  ) {
    throw new TypeError('options must be an object');
  }

  const minLength = options.minLength ?? 12;

  if (!Number.isInteger(minLength) || minLength < 1) {
    throw new RangeError('minLength must be a positive integer');
  }

  const checks = {
    minLength: password.length >= minLength,
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    numbers: /\d/.test(password),
    symbols: /[^a-zA-Z0-9\s]/.test(password),
  };

  const normalized = password.toLowerCase();

  const common = COMMON.has(normalized);

  const repeated = /(.)\1{2,}/u.test(password);

  const sequence =
    /(?:0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwerty|asdf)/i.test(
      password,
    );

  const feedback = [];

  if (!checks.minLength) {
    feedback.push(`Use at least ${minLength} characters.`);
  }

  if (password.length < 16) {
    feedback.push('Consider a longer passphrase (16+ characters).');
  }

  if (repeated) {
    feedback.push('Avoid repeating the same character three or more times.');
  }

  if (sequence) {
    feedback.push('Avoid predictable sequences and keyboard patterns.');
  }

  if (common) {
    feedback.push('This is a commonly used password. Choose a unique one.');
  }

  let score = Math.min(password.length * 4, 64);

  score +=
    [checks.lowercase, checks.uppercase, checks.numbers, checks.symbols].filter(
      Boolean,
    ).length * 9;

  if (repeated) score -= 15;
  if (sequence) score -= 20;
  if (common) score = 0;

  score = Math.max(0, Math.min(100, score));

  const strength =
    score < 20
      ? 'Very Weak'
      : score < 40
        ? 'Weak'
        : score < 60
          ? 'Fair'
          : score < 80
            ? 'Strong'
            : 'Very Strong';

  return {
    score,
    strength,
    isValid: checks.minLength && !common && !repeated && !sequence,
    feedback,
    checks,
  };
}

module.exports = { checkPassword };

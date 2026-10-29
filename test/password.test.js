import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { checkPassword } from '../src/index.js';

const require = createRequire(import.meta.url);
const cjs = require('../src/index.cjs');

test('ESM and CommonJS exports agree', () => {
  const password = 'A long! passphrase 42';

  assert.deepEqual(checkPassword(password), cjs.checkPassword(password));
});

test('common passwords score zero', () => {
  const result = checkPassword('password123');

  assert.equal(result.score, 0);
  assert.equal(result.isValid, false);
});

test('strong password scores highly', () => {
  const result = checkPassword('Lake!Cedar9Moon#River');

  assert.equal(result.strength, 'Very Strong');
  assert.equal(result.isValid, true);
});

test('minimum length can be configured', () => {
  assert.equal(
    checkPassword('Sun!Moon7', { minLength: 8 }).checks.minLength,
    true,
  );

  assert.equal(
    checkPassword('Sun!Moon7', { minLength: 12 }).checks.minLength,
    false,
  );
});

test('invalid input throws', () => {
  assert.throws(() => checkPassword(null), TypeError);

  assert.throws(() => checkPassword('abc', { minLength: 0 }), RangeError);
});

test('empty password is invalid', () => {
  assert.equal(checkPassword('').isValid, false);
});

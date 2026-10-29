import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { checkBreachedPassword, analyzePassword } from '../src/index.js';

function sha1(password) {
  return createHash('sha1')
    .update(password, 'utf8')
    .digest('hex')
    .toUpperCase();
}

function mockResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/plain' },
  });
}

test('detects a breached password', async () => {
  const password = 'example-test-password';
  const hash = sha1(password);

  const mockFetch = async (url, options) => {
    assert.equal(
      url,
      `https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`,
    );

    assert.equal(options.headers['Add-Padding'], 'true');

    return mockResponse(`${hash.slice(5)}:42\r\n`);
  };

  const result = await checkBreachedPassword(password, {
    fetchImpl: mockFetch,
  });

  assert.equal(result.status, 'breached');
  assert.equal(result.breached, true);
  assert.equal(result.count, 42);
});

test('returns not_found when suffix is absent', async () => {
  const result = await checkBreachedPassword('example', {
    fetchImpl: async () => mockResponse(`${'A'.repeat(35)}:10\r\n`),
  });

  assert.equal(result.status, 'not_found');
  assert.equal(result.breached, false);
  assert.equal(result.count, 0);
});

test('ignores zero-count padding entries', async () => {
  const password = 'example';
  const suffix = sha1(password).slice(5);

  const result = await checkBreachedPassword(password, {
    fetchImpl: async () => mockResponse(`${suffix}:0\r\n`),
  });

  assert.equal(result.status, 'not_found');
  assert.equal(result.count, 0);
});

test('network failure produces unknown status', async () => {
  const result = await checkBreachedPassword('example', {
    fetchImpl: async () => {
      throw new Error('Network unavailable');
    },
  });

  assert.equal(result.status, 'unknown');
  assert.equal(result.breached, null);
});

test('HTTP errors produce unknown status', async () => {
  const result = await checkBreachedPassword('example', {
    fetchImpl: async () => mockResponse('Unavailable', 503),
  });

  assert.equal(result.status, 'unknown');
});

test('malformed responses produce unknown status', async () => {
  const result = await checkBreachedPassword('example', {
    fetchImpl: async () => mockResponse('not a valid hash suffix'),
  });

  assert.equal(result.status, 'unknown');
});

test('rejects invalid input', async () => {
  await assert.rejects(checkBreachedPassword(null), TypeError);

  await assert.rejects(checkBreachedPassword(''), RangeError);
});

test('combined analysis rejects breached passwords', async () => {
  const password = 'Lake!Cedar9Moon#River';
  const suffix = sha1(password).slice(5);

  const result = await analyzePassword(password, {
    fetchImpl: async () => mockResponse(`${suffix}:3\r\n`),
  });

  assert.equal(result.breach.status, 'breached');
  assert.equal(result.isValid, false);
});

test('combined analysis supports opt-out', async () => {
  const result = await analyzePassword('Lake!Cedar9Moon#River', {
    breachCheck: false,
  });

  assert.equal(result.breach.status, 'not_checked');
  assert.equal(result.isValid, true);
});

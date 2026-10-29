'use strict';

const { createHash } = require('node:crypto');

const API_URL = 'https://api.pwnedpasswords.com/range/';
const MAX_RESPONSE_BYTES = 256 * 1024;

class BreachCheckError extends Error {
  constructor(message, cause) {
    super(message, { cause });
    this.name = 'BreachCheckError';
  }
}

function validateOptions(options) {
  if (
    options === null ||
    typeof options !== 'object' ||
    Array.isArray(options)
  ) {
    throw new TypeError('options must be an object');
  }

  const { timeout = 10000, fetchImpl = globalThis.fetch } = options;

  if (!Number.isInteger(timeout) || timeout < 1) {
    throw new RangeError('timeout must be a positive integer');
  }

  if (typeof fetchImpl !== 'function') {
    throw new TypeError('fetch must be a function');
  }

  return { timeout, fetchImpl };
}

function hashPassword(password) {
  return createHash('sha1')
    .update(password, 'utf8')
    .digest('hex')
    .toUpperCase();
}

function findBreachCount(body, targetSuffix) {
  if (typeof body !== 'string') {
    throw new BreachCheckError('Invalid API response');
  }

  for (const line of body.split(/\r?\n/)) {
    if (!line.trim()) continue;

    const match = /^([A-Fa-f0-9]{35}):(\d+)$/.exec(line.trim());

    if (!match) {
      throw new BreachCheckError('Malformed breach database response');
    }

    if (match[1].toUpperCase() === targetSuffix) {
      const count = Number(match[2]);

      if (!Number.isSafeInteger(count)) {
        throw new BreachCheckError('Invalid breach occurrence count');
      }

      return count;
    }
  }

  return 0;
}

async function checkBreachedPassword(password, options = {}) {
  if (typeof password !== 'string') {
    throw new TypeError('password must be a string');
  }

  const { timeout, fetchImpl } = validateOptions(options);

  if (password.length === 0) {
    throw new RangeError('password must not be empty');
  }

  const hash = hashPassword(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  let response;

  try {
    response = await fetchImpl(`${API_URL}${prefix}`, {
      method: 'GET',
      headers: {
        'Add-Padding': 'true',
        Accept: 'text/plain',
      },
      signal: controller.signal,
      redirect: 'error',
      cache: 'no-store',
    });

    if (!response.ok) {
      throw new BreachCheckError(
        `Breach service returned HTTP ${response.status}`,
      );
    }

    const contentLength = response.headers?.get?.('content-length');

    if (
      contentLength !== null &&
      contentLength !== undefined &&
      Number(contentLength) > MAX_RESPONSE_BYTES
    ) {
      throw new BreachCheckError('Response too large');
    }

    // Bound the actual downloaded body as well.
    // Do not rely solely on Content-Length.
    const reader = response.body?.getReader?.();

    if (!reader) {
      throw new BreachCheckError('Streaming response unavailable');
    }

    const chunks = [];
    let bytes = 0;

    while (true) {
      const { done, value } = await reader.read();

      if (done) break;

      bytes += value.byteLength;

      if (bytes > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new BreachCheckError('Response too large');
      }

      chunks.push(value);
    }

    const body = Buffer.concat(chunks).toString('utf8');

    const count = findBreachCount(body, suffix);

    return {
      status: count > 0 ? 'breached' : 'not_found',
      breached: count > 0,
      count,
      source: 'Have I Been Pwned',
    };
  } catch (error) {
    // Invalid API responses, timeouts and network errors
    // must never be interpreted as "not breached".
    return {
      status: 'unknown',
      breached: null,
      count: null,
      source: 'Have I Been Pwned',
      error:
        error?.name === 'AbortError'
          ? 'Breach lookup timed out'
          : 'Breach lookup unavailable',
    };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  checkBreachedPassword,
  BreachCheckError,
};

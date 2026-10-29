'use strict';

const { checkPassword } = require('./core.cjs');
const { checkBreachedPassword } = require('./breach.cjs');

async function analyzePassword(password, options = {}) {
  const {
    breachCheck = true,
    timeout = 10000,
    fetchImpl,
    ...strengthOptions
  } = options;

  if (typeof breachCheck !== 'boolean') {
    throw new TypeError('breachCheck must be a boolean');
  }

  // Validate the password synchronously first.
  const strength = checkPassword(password, strengthOptions);

  if (!breachCheck) {
    return {
      ...strength,
      breach: {
        status: 'not_checked',
        breached: null,
        count: null,
      },
    };
  }

  const breach = await checkBreachedPassword(password, {
    timeout,
    fetchImpl,
  });

  const feedback = [...strength.feedback];

  if (breach.status === 'breached') {
    feedback.push(
      'This password appears in known breach data. ' +
        'Choose a different password.',
    );
  }

  if (breach.status === 'unknown') {
    feedback.push('Could not verify whether this password was breached.');
  }

  return {
    ...strength,
    // Unknown is not treated as successful validation.
    isValid: strength.isValid && breach.status === 'not_found',
    feedback,
    breach,
  };
}

module.exports = {
  checkPassword,
  checkBreachedPassword,
  analyzePassword,
};

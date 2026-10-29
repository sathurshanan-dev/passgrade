
# passgrade

A lightweight, dependency-free password strength checker
for JavaScript and Node.js.

## Features

- Password strength score from 0 to 100
- Five strength levels
- Common password detection
- Repeated character detection
- Predictable sequence detection
- Breached password detection
- Actionable feedback
- Customizable minimum length
- CommonJS and ES Module support

## Installation

```javascript
npm install passgrade
```

## Usage

```javascript
import { checkPassword } from 'passgrade';

const result = checkPassword('Lake!Cedar9Moon#River');

console.log(result);
```

## Options

```javascript
checkPassword('MyPassword123!', {
  minLength: 12
});
```

## API

```javascript
checkPassword(password, options?)
```

Returns:

- score: Number from 0 to 100
- strength: Strength classification
- isValid: Boolean
- feedback: Array of suggestions
- checks: Individual validation results

## Breached Password Detection

Passgrade supports privacy-preserving breached-password detection using the Have I Been Pwned Pwned Passwords API.

### Usage

```javascript
import { checkBreachedPassword } from "passgrade";

const result = await checkBreachedPassword(
  "example-test-password"
);

console.log(result.status);
console.log(result.breached);
console.log(result.count);
```

### Combined Password Analysis

```javascript
import { analyzePassword } from "passgrade";

const result = await analyzePassword(
  "example-test-password",
  {
    minLength: 12,
    breachCheck: true,
    timeout: 10000
  }
);

console.log(result);
```

### Integrate with Express.js

Here's an example registration validation endpoint:

```javascript
import express from 'express';
import { analyzePassword } from 'passgrade';

const app = express();

app.use(express.json({ limit: '16kb' }));

app.post('/register', async (req, res) => {
  const { password } = req.body ?? {};

  if (typeof password !== 'string') {
    return res.status(400).json({
      message: 'Password is required'
    });
  }

  // Bound work before calling the external service.
  if (password.length > 1024) {
    return res.status(400).json({
      message: 'Password exceeds input limit'
    });
  }

  try {
    const result = await analyzePassword(password, {
      minLength: 12,
      breachCheck: true
    });

    if (result.breach.status === 'unknown') {
      return res.status(503).json({
        message: 'Password screening temporarily unavailable'
      });
    }

    if (!result.isValid) {
      return res.status(400).json({
        message: 'Password does not meet requirements',
        feedback: result.feedback
      });
    }

    // Next: securely hash the password, create the user,
    // and complete registration. Do not store plaintext.

    return res.status(200).json({
      message: 'Password passed screening'
    });
  } catch {
    return res.status(500).json({
      message: 'Unable to validate password'
    });
  }
});

app.listen(3000);
```

### Privacy

Passgrade calculates a SHA-1 hash locally and sends only the first five hexadecimal characters to the HIBP range API.

The complete password and full hash are not transmitted.

The API response is compared locally, with padded responses requested to reduce information leakage.

### Breach Status

- `breached`: Found in known breach data.
- `not_found`: Not found in the available dataset.
- `unknown`: The lookup could not be completed.
- `not_checked`: Breach detection was disabled.

A `not_found` result does not guarantee that a password is secure.

### Requirements

- Node.js 18 or later.
- Internet access for live breach checks.
- No API key required.
- No additional runtime dependencies.

### Security Recommendations

Do not perform breach lookups on every keystroke. Run them when password entry is complete, such as when the field loses focus or the form is submitted.

Never log plaintext passwords, full password hashes, or sensitive authentication request bodies.

## Testing

npm test

## License

MIT

# Contributing to Space Proof Code (`@putervision/spc`)

Thank you for your interest in contributing to `@putervision/spc`! We welcome community contributions to expand language support, refine security pattern detectors, and improve static analysis performance.

---

## Code of Conduct & Standards

1. **Zero External Dependencies Policy**: `@putervision/spc` is built with pure Node.js native APIs (fs, path, crypto) and regex pattern matching algorithms. Do NOT introduce third-party npm dependencies.
2. **Local-First Privacy**: Ensure all new checks execute 100% locally without external network calls or telemetry tracking.
3. **Code Style**: ES2022+ standards, 2-space indentation, mandatory JSDoc annotations for exported and internal functions.

---

## Development Setup

```bash
# Clone the repository
git clone https://github.com/putervision/spc.git
cd spc

# Install development dependencies (Jest, ESLint, Prettier)
npm install

# Run unit and integration tests
npm test

# Run code formatting check & linting
npm run format:check
npm run lint

# Run self-scan analysis
npm run self-check
```

---

## Adding a New Language or Rule Module

To add support for a new programming language or security rule engine:

1. Create a pattern rule engine module in `lib/lang/<language>.js`.
2. Register the export in `LANGUAGE_PATTERNS` inside `lib/scanner.js`.
3. Add severities, categories, and documentation URLs in `lib/info.js`.
4. Add bad example code fixtures in `test/examples/bad-example.<ext>`.
5. Add unit test assertions in `test/scanner.test.js` and `test/patterns.test.js`.
6. Submit a Pull Request targeting `main`.

---

## Reporting Bugs & Security Vulnerabilities

- For standard bug reports or feature requests, please open a [GitHub Issue](https://github.com/putervision/spc/issues).
- For security vulnerability reports, please refer to [SECURITY.md](./SECURITY.md) and contact `security@putervision.com`.

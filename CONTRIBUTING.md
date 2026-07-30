# Contributing to Space Proof Code (`@putervision/spc`)

Thank you for your interest in contributing to **Space Proof Code (SPC)**! We welcome contributions that improve static analysis accuracy, expand language coverage, refine NASA Power of Ten rule enforcement, and enhance performance.

---

## Zero External Dependencies Rule

> [!IMPORTANT]
> **Strict Zero-Dependency Constraint**  
> `@putervision/spc` is built with **100% native Node.js code and pure regex AST parsers**. We do **NOT** accept new runtime dependencies in `package.json`. All scanner, formatter, and CLI logic must be written from scratch using standard Node.js built-ins (`fs`, `path`, `crypto`).

---

## How to Add a New Language Support

To add support for a new programming language:

1. Create a new pattern definition file in `lib/lang/<language>.js`.
2. Implement the required `LanguagePatterns` structure:
   ```javascript
   const NewLangPatterns = {
     extensions: ['.ext'],
     patterns: {
       recursion: /.../g,
       unbounded_loops: /.../g,
       multiple_returns: /.../g,
       // Include security patterns (unsafe_input, exposed_secrets, etc.)
     },
     function_regex: /^.../,
     ignore_functions: ['print'],
     critical_functions: ['read'],
     void_return_indicator: 'print',
   };

   module.exports = { NewLangPatterns };
   ```
3. Register the language in `lib/scanner.js` (`LANGUAGE_PATTERNS`).
4. Add test code samples in `test/examples/` and test cases in `test/patterns.test.js`.

---

## Local Development & Testing

```bash
# 1. Clone the repository
git clone https://github.com/putervision/spc.git
cd spc

# 2. Run unit tests
npm test

# 3. Run test coverage
npm run test:coverage

# 4. Self-scan codebase
npm run self-check

# 5. Verify npm package contents
npm pack --dry-run
```

---

## Code Style & Guidelines

- Use 2-space indentation, single quotes, and trailing semicolons.
- Ensure all regex patterns match multiline blocks cleanly without catastrophic backtracking.
- Write clear comments explaining rule heuristics and limitations.

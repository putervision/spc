# Space Proof Code - Tools to facilitate space-proofing code by identifying performance and security related issues.

[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/putervision/spc)

`@putervision/spc` is a command-line tool that analyzes codebases for performance and security issues, enforcing space-proofing principles inspired by NASA's Power of Ten rules for safety-critical software. Supporting JavaScript/TypeScript (`.js`, `.ts`), Python (`.py`), and C/C++ (`.c`, `.cpp`, `.h`) files, it helps developers build robust, reliable code for high-stakes environments like space missions, identifying vulnerabilities and inefficiencies that could compromise mission-critical systems.

1. [Install & Usage](#installation)
2. [Code Quality & Performance Rules](#code-quality-rules)
3. [Security Rules](#security-rules)
4. [Zero Dependencies](#zero-dependencies)
5. [Limitations](#limitations)
6. [Contributing](#contributing)
7. [License](#license)
8. [Author](#author)

Contact us via email: [code@putervision.com](mailto:code@putervision.com)

## Installation

To install the tool globally via npm:

```bash
# install space proof code globally
npm install -g @putervision/spc
```
Example usage for scanning code:
```bash
# use within a dir or specify a code path
space-proof-code [/path/to/code]
```

## Code Quality Rules

`@putervision/spc` enforces a set of code quality rules inspired by NASA's Power of Ten guidelines, tailored to ensure performance, reliability, and maintainability in space-ready software. These checks go beyond security to identify patterns that could degrade system efficiency or stability in high-stakes environments like space missions. Below are the key rules applied across JavaScript/TypeScript (`.js`, `.ts`), Python (`.py`), and C/C++ (`.c`, `.cpp`, `.h`) files:

1. **Simple Control Flow (`complex_flow`, `multiple_returns`, `nested_conditionals`)**
   - **Purpose**: Ensures code avoids complex control structures (e.g., multiple returns, deep nesting) that hinder verification and increase error risk.
   - **Example**:
     ```javascript
     function foo() { if (x) return 1; return 2; } // Flagged: multiple returns
     ```
     - Fix: Use a single return point.

2. **Bounded Loops (`unbounded_loops`)**
   - **Purpose**: Guarantees loops have predictable termination to prevent infinite execution, critical for real-time systems.
   - **Example**:
     ```python
     while True: print("loop") // Flagged: unbounded
     ```
     - Fix: Add a break condition (e.g., `while i < 10`).

3. **Static Memory Allocation (`dynamic_memory`)**
   - **Purpose**: Flags dynamic memory allocation after initialization, which can lead to fragmentation or exhaustion in constrained environments.
   - **Example**:
     ```c
     int* ptr = malloc(10); // Flagged: dynamic
     ```
     - Fix: Use static arrays (e.g., `int arr[10]`).

4. **Small Functions (`exceeds_max_lines`)**
   - **Purpose**: Limits function size (max 60 lines) for readability and testability, reducing cognitive load in mission-critical code.
   - **Example**:
     ```javascript
     function big() { /* 61+ lines */ } // Flagged: too long
     ```
     - Fix: Split into smaller functions.

5. **Scoped Variables (`global_vars`)**
   - **Purpose**: Encourages minimal variable scope to avoid unintended side effects, enhancing code predictability.
   - **Example**:
     ```javascript
     var global = 5; // Flagged: global scope
     ```
     - Fix: Use `let` or `const` within blocks.

6. **Checked Returns (`unchecked_return`)**
   - **Purpose**: Ensures all non-void function returns are used, catching errors that could go unnoticed in space systems.
   - **Example**:
     ```python
     requests.get("url") // Flagged: return ignored
     ```
     - Fix: Assign to a variable (e.g., `resp = requests.get("url")`).

7. **Avoid Dynamic Code (`eval_usage`)**
   - **Purpose**: Prohibits dynamic code execution (e.g., `eval`) that’s unpredictable and hard to verify, a risk in space environments.
   - **Example**:
     ```javascript
     eval("code"); // Flagged: unsafe
     ```
     - Fix: Use static logic instead.

8. **No Recursion (`recursion`)**
   - **Purpose**: Flags recursive calls that could exhaust stack space or complicate verification in resource-limited systems.
   - **Example**:
     ```c
     int factorial(int n) { return factorial(n-1); } // Flagged: recursive
     ```
     - Fix: Convert to iteration.

9. **Predictable Timing (`async_risk`, `set_timeout`)**
   - **Purpose**: Detects asynchronous or timing-dependent operations that introduce non-determinism, undesirable in real-time space software.
   - **Example**:
     ```javascript
     setTimeout(() => {}, 1000); // Flagged: timing-dependent
     ```
     - Fix: Use synchronous alternatives where possible.

10. **Minimal Imports (`import_risk`)**
    - **Purpose**: Flags wildcard imports in Python that can bloat code or introduce unexpected dependencies, reducing reliability.
    - **Example**:
      ```python
      from os import * // Flagged: wildcard
      ```
      - Fix: Import specific items (e.g., `from os import path`).

These rules help ensure code is efficient, verifiable, and stable—essential for space missions where every line must perform flawlessly.

## Security Rules

`@putervision/spc` performs security-focused checks to protect space-bound code from vulnerabilities, such as RF-based API injection from neighboring satellites. These rules identify patterns that could compromise system integrity, confidentiality, or availability in high-stakes environments where human intervention isn’t possible. Below are the security rules enforced by the tool:

1. **Unsafe Input (`unsafe_input`)**
   - **Purpose**: Flags unvalidated inputs that could allow malicious RF data to execute unchecked commands or exploits.
   - **Languages**: JavaScript (`req.body`), Python (`sys.argv`), C (`scanf`).
   - **Example**:
     ```javascript
     const data = req.body.payload; // Flagged: no validation
     ```
     - Fix: Add type checks (e.g., `if (typeof data === 'string')`).

2. **Network Calls (`network_call`)**
   - **Purpose**: Detects unsecured network operations that might accept untrusted RF data without encryption or authentication.
   - **Languages**: JavaScript (`fetch`), Python (`requests.get`), C (`socket`).
   - **Example**:
     ```python
     response = requests.get("http://space.api"); // Flagged: unsecured
     ```
     - Fix: Use HTTPS and validate responses.

3. **Weak Cryptography (`weak_crypto`)**
   - **Purpose**: Identifies weak cryptographic functions that could let attackers predict or bypass security, critical for RF comms.
   - **Languages**: JavaScript (`Math.random`), Python (`hashlib.md5`), C (`rand`).
   - **Example**:
     ```c
     int r = rand(); // Flagged: predictable RNG
     ```
     - Fix: Use `crypto.randomBytes` (JS) or `/dev/urandom` (C).

4. **Missing Authentication (`missing_auth`)**
   - **Purpose**: Flags API endpoints without middleware or checks, vulnerable to unauthorized RF access.
   - **Languages**: JavaScript (`app.post`), Python (`app.route`).
   - **Example**:
     ```javascript
     app.get("/data", (req, res) => res.send("OK")); // Flagged: no auth
     ```
     - Fix: Add `app.use(authMiddleware)`.

5. **No Error Handling (`no_error_handling`)**
   - **Purpose**: Detects async operations without error handling, risking silent failures in space systems.
   - **Languages**: JavaScript (async/await).
   - **Example**:
     ```javascript
     async function fetchData() { await fetch("url"); } // Flagged: no try/catch
     ```
     - Fix: Wrap in `try { ... } catch (e) { ... }`.

6. **Unsafe File Operations (`unsafe_file_op`)**
   - **Purpose**: Flags file operations without error checks, which could fail or be exploited via RF-injected paths.
   - **Languages**: JavaScript (`fs.readFile`), Python (`open`), C (`fopen`).
   - **Example**:
     ```javascript
     fs.readFile("data.txt"); // Flagged: no error handling
     ```
     - Fix: Use `.catch()` or try/catch.

7. **Insufficient Logging (`insufficient_logging`)**
   - **Purpose**: Ensures API endpoints or critical functions log activity, vital for tracing RF attacks in space.
   - **Languages**: JavaScript (`app.get`), Python (`@app.route`), C (functions).
   - **Example**:
     ```python
     @app.route("/data")
     def get_data(): return "OK" // Flagged: no logging
     ```
     - Fix: Add `print("Data accessed")`.

8. **Unsanitized Execution (`unsanitized_exec`)**
   - **Purpose**: Detects command execution with unsanitized inputs, risking RF-driven command injection.
   - **Languages**: JavaScript (`exec`), Python (`os.system`), C (`system`).
   - **Example**:
     ```javascript
     exec(`echo ${userInput}`); // Flagged: injection risk
     ```
     - Fix: Use parameterized commands (e.g., `["echo", userInput]`).

9. **Exposed Secrets (`exposed_secrets`)**
   - **Purpose**: Flags hardcoded secrets that could be extracted via RF attacks or memory dumps.
   - **Languages**: JavaScript (`apiKey = "..."`), Python, C (`char* key = "..."`).
   - **Example**:
     ```javascript
     const apiKey = "xyz123"; // Flagged: hardcoded
     ```
     - Fix: Use environment variables (`process.env.API_KEY`).

10. **Unrestricted CORS (`unrestricted_cors`)**
    - **Purpose**: Identifies overly permissive CORS configs that could allow unauthorized RF clients (if web-exposed).
    - **Languages**: JavaScript (`cors({ origin: "*" })`).
    - **Example**:
      ```javascript
      app.use(cors({ origin: "*" })); // Flagged: unrestricted
      ```
      - Fix: Specify trusted origins (e.g., `origin: "trusted.sat"`).

11. **Buffer Overflow Risk (`buffer_overflow_risk`)**
    - **Purpose**: Flags unsafe string operations in C that could be exploited via RF-injected data.
    - **Languages**: C (`strcpy`).
    - **Example**:
      ```c
      strcpy(dest, src); // Flagged: overflow risk
      ```
      - Fix: Use `strncpy` with length checks.

These rules enhance space-proofing by catching vulnerabilities that static analysis can identify, complementing runtime checks like authentication and input sanitization for a fully secure system.

## Zero Dependencies
- **Code from scratch**: We write all code from scratch to avoid potential issues introduced with a dependency chain. By skipping external libraries and frameworks, we dodge the risk of bugs, security holes, or breaking changes sneaking in from someone else’s code.

## Limitations
- **Regex-Based**: May miss complex cases (e.g., comments, nested scopes) without a full parser.
- **Language-Specific**: Some rules (e.g., pointers) apply only to C/C++.
- **False Positives**: Patterns like `while (true)` with a `break` might still flag.

## Contributing
- Report issues or suggest features via GitHub.
- To extend support for other languages, modify `LANGUAGE_PATTERNS` in `lib/scanner.js`.
## License
MIT License - see [LICENSE](LICENSE) for details.

## Author
PuterVision <code@putervision.com> - https://putervision.com
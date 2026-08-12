# Traditional Code Security Rules

`@putervision/spc` scans source code across 20 programming languages for critical security vulnerabilities, attack vectors, and high-risk anti-patterns.

---

## Security Vulnerability Rules

### Eval Usage (`eval_usage`)
- **Severity**: `5/5` | **Category**: `security`
- **Description**: Dynamic code execution (`eval`, `Function()`, `exec()`) allows arbitrary code injection.
- **Remedy**: Replace dynamic evaluation with safe static data parsing.

---

### Unsafe Input (`unsafe_input`)
- **Severity**: `4/5` | **Category**: `security`
- **Description**: Unsanitized user inputs or RF-transmitted commands passed directly into application logic.
- **Remedy**: Enforce strict schema validation and parameter bounds checking.

---

### SQL Injection (`sql_injection`)
- **Severity**: `5/5` | **Category**: `security`
- **Description**: Raw SQL queries constructed via string concatenation rather than parameterized queries.
- **Remedy**: Use prepared statements or ORM parameter binding.

---

### SSRF Risk (`ssrf_risk`)
- **Severity**: `4/5` | **Category**: `security`
- **Description**: User-controlled URLs passed to HTTP clients (`fetch`, `axios`, `curl`) enabling Server-Side Request Forgery.
- **Remedy**: Validate domain whitelists and restrict internal IP ranges.

---

### Deserialization Risk (`pickle_deserialize` / `deserialization_risk`)
- **Severity**: `5/5` | **Category**: `security`
- **Description**: Unsafe object deserialization (`pickle.load`, `ObjectInputStream`, `unserialize`, `Marshal.load`).
- **Remedy**: Use safe serialization formats such as JSON or Protocol Buffers.

---

### Command Injection (`unsanitized_exec` / `curl_pipe_bash`)
- **Severity**: `5/5` | **Category**: `security`
- **Description**: Passing unescaped strings into shell invocation commands (`exec`, `spawn`, `curl | bash`).
- **Remedy**: Pass arguments as fixed array vectors without invoking shell subshells.

---

### Exposed Secrets (`exposed_secrets`)
- **Severity**: `5/5` | **Category**: `security`
- **Description**: Hardcoded API keys, bearer tokens, private keys, or passwords embedded in source code.
- **Remedy**: Use environment variables or secure key vaults.

---

### Weak Crypto & Insecure Random (`weak_crypto` / `insecure_random`)
- **Severity**: `4/5` | **Category**: `security`
- **Description**: Use of broken cryptographic algorithms (`MD5`, `SHA1`) or non-cryptographic PRNGs (`Math.random()`, `rand()`) for security keys.
- **Remedy**: Use cryptographically secure algorithms (`SHA-256`, `AES-GCM`, `crypto.getRandomValues()`).

---

### XXE Injection (`xxe_injection`)
- **Severity**: `4/5` | **Category**: `security`
- **Description**: XML parsers evaluating external entity declarations in untrusted XML payloads.
- **Remedy**: Disable DTD evaluation and external entity resolution in XML parsers.

---

### Format String & Memory Vulnerabilities (`format_string` / `buffer_overflow_risk` / `use_after_free`)
- **Severity**: `4-5/5` | **Category**: `security`
- **Description**: C/C++ memory safety violations including format string specifiers, unsafe buffer functions (`strcpy`), and memory pointer reuse.
- **Remedy**: Use bounds-checked string utilities (`strncpy_s`) and RAII memory management.

# Space Proof Code - A tool to identify space-proofing issues in codebases

`@putervision/spc` is a command-line tool designed to analyze codebases for patterns that violate space-proofing principles, inspired by NASA's Power of Ten rules for safety-critical software. It supports JavaScript (`.js`), Python (`.py`), and C/C++ (`.c`, `.cpp`, `.h`) files, helping developers ensure their code is robust and reliable for high-stakes environments like space missions.

Contact us via email: [code@putervision.com](mailto:code@putervision.com)

## Installation

To install the tool globally via npm:

```bash
npm install -g @putervision/spc
```

## The 10 Guidelines Checked

This tool is inspired by NASA's "Power of Ten: Rules for Developing Safety-Critical Code" by Gerard J. Holzmann, adapted for general use across JavaScript, Python, and C/C++. Below are the 10 guidelines and how the tool checks for violations:

1. **Restrict to Simple Control Flow**
   - **Description**: Avoid complex constructs like `goto`, `break`, `continue`, or multiple returns that make code hard to verify.
   - **Check**: Flags `break`, `continue`, `goto` (C), and functions with multiple `return` statements.
   - **Example**: `if (x) return 1; return 2;` triggers "multiple_returns".

2. **All Loops Must Have a Fixed Upper Bound**
   - **Description**: Loops must terminate predictably to avoid infinite execution in critical systems.
   - **Check**: Detects unbounded loops like `while (true)` or `for (;;)` without clear exit conditions.
   - **Example**: `while (condition)` without a break condition is flagged.

3. **No Dynamic Memory Allocation After Initialization**
   - **Description**: Prevent runtime memory allocation (e.g., `malloc`, `new`) to avoid fragmentation or exhaustion.
   - **Check**: Flags `malloc` (C), `new` (JS), and `list()`/`dict()` (Python) as dynamic allocations.
   - **Example**: `let arr = new Array(10);` triggers "dynamic_memory".

4. **Keep Functions Small and Focused**
   - **Description**: Functions should fit on one page (max 60 lines) for readability and testability.
   - **Check**: Measures function length and flags those exceeding 60 lines.
   - **Example**: A 75-line function triggers a warning.

5. **Use at Least Two Assertions Per Function**
   - **Description**: Runtime checks catch errors early (though harder to enforce in this tool).
   - **Check**: Not directly enforced (requires AST parsing), but encourages manual review.
   - **Example**: No automatic flag; add assertions like `if (!x) throw Error()` manually.

6. **Declare Data Objects at the Smallest Possible Scope**
   - **Description**: Minimize variable scope to reduce side effects.
   - **Check**: Flags global declarations like `var x` (JS) or `global x` (Python).
   - **Example**: `var globalVar = 5;` triggers "global_vars".

7. **Check Return Values of All Non-Void Functions**
   - **Description**: Ensure function results are used to catch errors.
   - **Check**: Flags standalone function calls without assignment or condition (e.g., `foo();`).
   - **Example**: `getData();` triggers "Unchecked function return".

8. **Limit the Use of Preprocessor**
   - **Description**: Avoid macros or dynamic code that obscures logic (JS/Python use `eval` as analog).
   - **Check**: Flags `eval`, `Function` (JS), `exec` (Python), or `system` (C).
   - **Example**: `eval("code")` triggers "eval_usage".

9. **Restrict Pointer Use**
   - **Description**: Limit pointer dereferencing to one level (not directly applicable to JS/Python).
   - **Check**: In C, flags patterns like `**p` (not implemented here; regex-based).
   - **Example**: C-specific; JS/Python skip this rule.

10. **Compile with All Warnings Enabled and Clean**
    - **Description**: Treat warnings as errors and resolve them.
    - **Check**: Indirectly encourages clean code; tool flags risky patterns like `try/catch`.
    - **Example**: `try { ... }` triggers "try_catch" as a potential masking issue.

## Limitations
- **Regex-Based**: May miss complex cases (e.g., comments, nested scopes) without a full parser.
- **Language-Specific**: Some rules (e.g., pointers) apply only to C/C++.
- **False Positives**: Patterns like `while (true)` with a `break` might still flag.

## Contributing
- Report issues or suggest features via GitHub.
- To extend support for other languages, modify `LANGUAGE_PATTERNS` in `lib/checker.js`.
## License
MIT License - see [LICENSE](LICENSE) for details.

## Author
PuterVision <code@putervision.com>
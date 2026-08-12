# NASA Power of Ten & Reliability Rules

`@putervision/spc` enforces safety-critical code rules inspired by NASA's Power of Ten guidelines, tailored for space flight software and mission-critical applications.

---

## Rule Reference

### Recursion
- **Severity**: `4/5`
- **Category**: `nasa`
- **Description**: Recursive function calls risk stack overflow in memory-constrained environments. In real-time flight systems, deep call stacks cause non-deterministic memory usage.
- **Remedy**: Convert recursion to explicit iterative loops with bounded stack structures.

---

### Dynamic Memory
- **Severity**: `3/5`
- **Category**: `nasa`
- **Description**: Heap memory allocations (`malloc`, `new Array`, `new Object`) after initialization fragment heap memory and risk allocation failures.
- **Remedy**: Pre-allocate static memory buffers during system initialization.

---

### Complex Flow
- **Severity**: `2/5`
- **Category**: `nasa`
- **Description**: Unstructured control flow (`goto`, `break`, `continue`, multiple exits) complicates formal verification and static path testing.
- **Remedy**: Use single-entry, single-exit function structures.

---

### Async Risk
- **Severity**: `4/5`
- **Category**: `nasa`
- **Description**: Non-deterministic asynchronous constructs (`async`/`await`, promises, threads) introduce timing hazards in deterministic real-time loops.
- **Remedy**: Use synchronous, bounded execution threads with fixed deadline scheduling.

---

### Unbounded Loops
- **Severity**: `5/5`
- **Category**: `nasa`
- **Description**: Loops without fixed upper bounds (`while(true)`, unbounded `for` loops) can hang safety-critical event loops.
- **Remedy**: Enforce explicit loop iteration bounds with assertion caps.

---

### Global Variables
- **Severity**: `3/5`
- **Category**: `nasa`
- **Description**: Global mutable state introduces hidden dependencies and race conditions across thread tasks.
- **Remedy**: Scope state locally or pass references explicitly.

---

### Set Timeout / Timing Hazards
- **Severity**: `4/5`
- **Category**: `nasa`
- **Description**: Non-deterministic timers (`setTimeout`, `setInterval`) disrupt real-time control hardware loops.
- **Remedy**: Use hardware interrupts or deterministic clock ticks.

---

### Multiple Returns
- **Severity**: `2/5`
- **Category**: `quality`
- **Description**: Functions with multiple return statements increase path verification complexity.
- **Remedy**: Standardize on a single return point at the end of the function body.

---

### Nested Conditionals
- **Severity**: `2/5`
- **Category**: `quality`
- **Description**: Deeply nested `if/else` structures (3+ levels) exponentially increase cyclomatic complexity.
- **Remedy**: Refactor into guard clauses or table-driven logic.

---

### Exceeds Max Function Lines
- **Severity**: `3/5`
- **Category**: `quality`
- **Description**: Functions exceeding 60 lines (configurable) hinder unit testing and static verification.
- **Remedy**: Break large functions into modular helper functions.

---

### Unchecked Function Return
- **Severity**: `2/5` (standard) / `4/5` (critical functions)
- **Category**: `quality` / `security`
- **Description**: Ignoring function return values masks hardware errors and API failures.
- **Remedy**: Explicitly check return status or cast to `(void)` if intentionally ignored.

const AdaPatterns = {
  extensions: ['.ada', '.adb', '.ads'], // File extensions for Ada files (body and spec)
  patterns: {
    // Example: function Factorial (N : Integer) return Integer is begin return Factorial(N - 1); end;
    recursion:
      /(\w+)\s*\([^)]*\)\s*(?:return\s+[^;]*|is\s*begin)\s*(?:[^;]*?\b\1\s*\()/g,

    // Example: Arr : array (1 .. 100) of Integer;
    dynamic_memory: /\b(array\s*\([^)]*\)\s*of|new\s+\w+)/g,

    // Example: if X > 0 then return X; end if; goto Label;
    complex_flow:
      /^.*\b(goto\s+\w+|exit\s+\w+|return\s+[^;]+;\s*$(?:\s*return\s+[^;]+;)?|raise\s+[^;]+;\s*$(?:\s*(return|raise\s+[^;]+))?)/gm,

    // Example: task Foo is ... end Foo;
    async_risk: /\b(task\s+\w+|delay\s+\w+)/g,

    // Example: loop ... end loop;
    unbounded_loops: /\b(loop\s*(?!exit\s+when)[^;]*end\s+loop)/g,

    // Example: N/A (Ada lacks direct eval, but pragma can be risky)
    eval_usage: /\b(pragma\s+Import\s*\()/g,

    // Example: X : Integer := 5; (global scope)
    global_vars:
      /\b(\w+)\s*:\s*(constant\s+)?\w+\s*:=\s*[^;]+(?=;[^-]*--.*package)/g,

    // Example: begin exception when others => null; end;
    try_catch: /\bexception\s+when\b/g,

    // Example: delay 1.0;
    set_timeout: /\b(delay\s+\d+(\.\d+)?)/g,

    // Example: function Foo return Integer is begin if X then return 1; end if; return 2; end;
    multiple_returns:
      /(function|procedure)\s+\w+\s*(?:return\s+\w+)?\s*is\s*begin[^;]*return[^;]*return/g,

    // Example: if X then if Y then Do_Something; end if; end if;
    nested_conditionals: /(if\s+[^;]+then\s*(?:[^;]*if\s+[^;]+then[^;]*){1,})/g,

    // Security-specific patterns
    unsafe_input: /\b(Get\s*\(|Ada\.Text_IO\.Get\s*\()/g,
    network_call: /\b(Ada\.Sockets\.Receive\s*\()/g,
    weak_crypto: /\b(MD5|SHA1)\s*\(/g,
    unsafe_file_op: /\b(Open|Create|Write)\s*\([^,]*[^&]*\)/g,
    insufficient_logging: /\b(Put_Line\s*\([^;]*\))/g, // Simplified, assumes logging via Put_Line
    unsanitized_exec: /\b(Ada\.Command_Line\.Command_Name\s*\()/g,
    exposed_secrets:
      /(?:constant\s+)?\b(\w*(secret|key|password|token)\w*)\s*:=\s*['"][^'"]+['"]/gi,
    unrestricted_cors: null, // Not applicable in Ada
  },
  function_regex:
    /^(function|procedure)\s+\w+\s*(?:return\s+\w+)?\s*is\s*begin/,
  ignore_functions: ['Put_Line', 'Text_IO.Put'],
  critical_functions: ['Ada.Sockets.Receive', 'Ada.Text_IO.Get'],
  void_return_indicator: 'Ada.Text_IO.',
};

module.exports = { AdaPatterns };

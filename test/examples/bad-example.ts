// Triggers: recursion, complex_flow, multiple_returns, nested_conditionals, unsafe_input, exposed_secrets, unrestricted_cors, insufficient_logging, eval_usage, set_timeout, dynamic_memory, global_vars
function factorial(n) {
    factorial(n - 1); // recursion: recursive call risks stack overflow
    if (n > 0) return n; // complex_flow, multiple_returns: multiple return points
    return 0;
  }
  
  var globalVar = 5; // global_vars: global scope increases side effects
  
  const express = require("express");
  const cors = require("cors");
  const app = express();
  
  app.use(cors({ origin: "*" })); // unrestricted_cors: allows any RF client
  
  app.get("/data", (req, res) => {
    // insufficient_logging: no logging for RF tracing
    const userInput = req.body.data; // unsafe_input: unvalidated RF data
    if (userInput) {
      if (userInput.length > 0) {
        console.log("Nested"); // nested_conditionals: deep nesting complicates verification
      }
    }
    eval(userInput); // eval_usage: dynamic code execution is unpredictable
    setTimeout(() => res.send("OK"), 1000); // set_timeout: timing-dependent, non-deterministic
  });
  
  const apiKey = "xyz123"; // exposed_secrets: hardcoded secret extractable via RF
  
  let arr = new Array(100); // dynamic_memory: risky allocation in space constraints
  
  app.listen(3000);
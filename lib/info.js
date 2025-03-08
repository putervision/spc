/**
 * Defines urls, severity levels, and other relevant information for the various patterns.
 */
const PATTERN_INFO = {
  recursion: {
    url: 'https://github.com/putervision/spc#recursion',
    severity: 4,
  },
  dynamic_memory: {
    url: 'https://github.com/putervision/spc#dynamic-memory',
    severity: 3,
  },
  complex_flow: {
    url: 'https://github.com/putervision/spc#complex-flow',
    severity: 2,
  },
  async_risk: {
    url: 'https://github.com/putervision/spc#async-risk',
    severity: 4,
  },
  unbounded_loops: {
    url: 'https://github.com/putervision/spc#unbounded-loops',
    severity: 5,
  },
  eval_usage: {
    url: 'https://github.com/putervision/spc#eval-usage',
    severity: 5,
  },
  global_vars: {
    url: 'https://github.com/putervision/spc#global-vars',
    severity: 3,
  },
  try_catch: {
    url: 'https://github.com/putervision/spc#try-catch',
    severity: 2,
  },
  set_timeout: {
    url: 'https://github.com/putervision/spc#set-timeout',
    severity: 4,
  },
  multiple_returns: {
    url: 'https://github.com/putervision/spc#multiple-returns',
    severity: 2,
  },
  nested_conditionals: {
    url: 'https://github.com/putervision/spc#nested-conditionals',
    severity: 2,
  },
  unsafe_input: {
    url: 'https://github.com/putervision/spc#unsafe-input',
    severity: 4,
  },
  network_call: {
    url: 'https://github.com/putervision/spc#network-call',
    severity: 3,
  },
  weak_crypto: {
    url: 'https://github.com/putervision/spc#weak-crypto',
    severity: 4,
  },
  unsafe_file_op: {
    url: 'https://github.com/putervision/spc#unsafe-file-op',
    severity: 3,
  },
  insufficient_logging: {
    url: 'https://github.com/putervision/spc#insufficient-logging',
    severity: 2,
  },
  unsanitized_exec: {
    url: 'https://github.com/putervision/spc#unsanitized-exec',
    severity: 5,
  },
  exposed_secrets: {
    url: 'https://github.com/putervision/spc#exposed-secrets',
    severity: 5,
  },
  unrestricted_cors: {
    url: 'https://github.com/putervision/spc#unrestricted-cors',
    severity: 4,
  },
  checksum_mismatch: {
    url: 'https://github.com/putervision/spc#checksum-mismatch',
    severity: 4,
  },
  exceeds_max_func_lines: {
    url: 'https://github.com/putervision/spc#exceeds-max-function-lines',
    severity: 3,
  },
  unchecked_func_return_crit: {
    url: 'https://github.com/putervision/spc#unchecked-function-return-critical',
    severity: 4,
  },
  unchecked_func_return: {
    url: 'https://github.com/putervision/spc#unchecked-function-return',
    severity: 2,
  },
  import_risk: {
    url: 'https://github.com/putervision/spc#import-risk',
    severity: 3,
  },
  buffer_overflow_risk: {
    url: 'https://github.com/putervision/spc#buffer-overflow-risk',
    severity: 4,
  },
};

module.exports = { PATTERN_INFO };

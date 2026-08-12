/**
 * model.js - Static analysis rule engine for AI/LLM Model & Serving Configs.
 * Audits model_config.json, lora_config.yaml, tokenizer_config.json, Modelfile (Ollama),
 * and generation_config.json for unsafe deserialization, HTTP downloads, and exposed keys.
 */

const ModelPatterns = {
  language: 'model',
  category: 'agent',
  filenames: [
    'model_config.json',
    'lora_config.yaml',
    'lora_config.yml',
    'tokenizer_config.json',
    'generation_config.json',
    'Modelfile',
    'ollama.json',
  ],
  extensions: ['.gguf.json', '.model.json', '.yaml', '.yml'],
  patterns: {
    // Example: "weights_only": false or pickle_module loading
    // Detects unsafe PyTorch / Pickle model weights loading configurations
    unsafe_model_deserialization:
      /["']?weights_only["']?\s*:\s*false|torch\.load\([^)]*weights_only\s*=\s*False|pickle_module/gi,

    // Example: "host": "0.0.0.0:11434" or "bind": "0.0.0.0:8000"
    // Identifies model serving APIs bound to public interfaces without authentication
    insecure_model_endpoint:
      /["']?(host|bind|server_name|endpoint)["']?\s*:\s*["']?0\.0\.0\.0:\d+["']?/gi,

    // Example: FROM http://example.com/model.bin
    // Flags insecure HTTP (non-HTTPS) model weight downloads
    unauthenticated_model_download:
      /\bhttp:\/\/[^\s"']+\.(bin|safetensors|pt|pth|gguf|onnx)\b|\bfrom\s+http:\/\/[^\s"']+/gi,

    // Example: "temperature": 2.5 or "temperature": 3.0
    // Identifies excessively high model temperature in safety-critical agent configs
    unsafe_model_temperature:
      /["']?temperature["']?\s*:\s*([2-9]\.[0-9]+|[1-9]\d+\.[0-9]+)/gi,

    // Example: OPENAI_API_KEY = "sk-..." or ANTHROPIC_API_KEY
    // Detects hardcoded LLM provider API keys in model configuration files
    exposed_model_api_key:
      /["']?(openai|anthropic|cohere|replicate|groq|huggingface)_?api_?key["']?\s*:\s*["'][^"']{10,}["']/gi,

    // Example: Missing input length or token generation limits
    // Flags unconstrained max_tokens parameters that could cause resource exhaustion
    unvalidated_model_input:
      /["']?max_tokens["']?\s*:\s*(-1|99999999|unlimited)|["']?truncate_input["']?\s*:\s*false/gi,
  },
  function_regex: /"model_type"|"architectures"|FROM\s+/,
  ignore_functions: [],
  critical_functions: ['torch.load', 'pickle.load', 'fetch_weights'],
  void_return_indicator: 'N/A',
};

module.exports = { ModelPatterns };

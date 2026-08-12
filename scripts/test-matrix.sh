#!/usr/bin/env bash
# test-matrix.sh - Run SPC test matrix across supported Node.js versions (18, 20, 22) using nvm.

set -e

NODE_VERSIONS=("18" "20" "22")

# Load nvm if available
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
if [ -s "$NVM_DIR/nvm.sh" ]; then
  . "$NVM_DIR/nvm.sh" > /dev/null 2>&1
fi

if ! command -v nvm > /dev/null 2>&1 && [ ! -s "$NVM_DIR/nvm.sh" ]; then
  echo "⚠️ nvm (Node Version Manager) not detected at $NVM_DIR/nvm.sh"
  echo "Running test suite on current Node.js version ($(node -v))..."
  npm test
  exit 0
fi

echo "========================================================"
echo "🧪 Running SPC Test Matrix across Node versions: ${NODE_VERSIONS[*]}"
echo "========================================================"

FAILED_VERSIONS=()

for VER in "${NODE_VERSIONS[@]}"; do
  echo ""
  echo "--------------------------------------------------------"
  echo "▶️ Testing on Node.js $VER.x"
  echo "--------------------------------------------------------"

  # Ensure target version is installed via nvm
  if ! nvm exec "$VER" node -v > /dev/null 2>&1; then
    echo "Installing Node.js $VER via nvm..."
    nvm install "$VER"
  fi

  if nvm exec "$VER" ./node_modules/.bin/jest; then
    echo "✅ Node.js $VER.x test suite passed!"
  else
    echo "❌ Node.js $VER.x test suite failed!"
    FAILED_VERSIONS+=("$VER")
  fi
done

echo ""
echo "========================================================"
if [ ${#FAILED_VERSIONS[@]} -eq 0 ]; then
  echo "🎉 ALL NODE VERSIONS (${NODE_VERSIONS[*]}) PASSED MATRIX TEST!"
  echo "========================================================"
  exit 0
else
  echo "💥 MATRIX TEST FAILED on Node version(s): ${FAILED_VERSIONS[*]}"
  echo "========================================================"
  exit 1
fi

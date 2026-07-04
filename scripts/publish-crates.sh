#!/usr/bin/env bash
set -e

# Load env if it exists (for local testing)
if [ -f .env ]; then
  source .env
fi

if [ -z "$CARGO_REGISTRY_TOKEN" ]; then
  echo "CARGO_REGISTRY_TOKEN must be set"
  exit 1
fi

cargo login "$CARGO_REGISTRY_TOKEN"

# Find all crates
CRATES=$(find crates -name Cargo.toml -not -path "*/target/*" -not -path "*/embedded/*" -exec dirname {} \;)

# Keep trying until all succeed or we make no progress
while true; do
  PROGRESS=0
  PENDING=0
  for crate in $CRATES; do
    # Extract name and version
    CRATE_NAME=$(grep -m 1 "^name" "$crate/Cargo.toml" | cut -d '"' -f 2)
    CRATE_VERSION=$(grep -m 1 "^version" "$crate/Cargo.toml" | cut -d '"' -f 2)
    
    # Check if this exact version is already published on crates.io
    if curl -s "https://crates.io/api/v1/crates/$CRATE_NAME/$CRATE_VERSION" | grep -q '"version"'; then
      continue
    fi
    
    PENDING=1
    echo "Attempting to publish $CRATE_NAME v$CRATE_VERSION..."
    cd "$crate"
    # Allow dirty in case of local modifications or GitHub actions side-effects
    if cargo publish --allow-dirty; then
      PROGRESS=1
      echo "Successfully published $CRATE_NAME"
    else
      echo "Failed to publish $CRATE_NAME (will retry next pass)"
    fi
    cd - > /dev/null
  done
  
  if [ $PENDING -eq 0 ]; then
    echo "All crates published successfully!"
    break
  fi
  
  if [ $PROGRESS -eq 0 ]; then
    echo "Failed to make progress. Remaining crates have issues."
    exit 1
  fi
  
  echo "Made progress. Sleeping 10 seconds before next pass to let crates.io index..."
  sleep 10
done

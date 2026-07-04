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
    
    # Check if this exact version is already published on crates.io.
    # crates.io rejects requests without a User-Agent (data-access policy),
    # and a rejected check must not read as "unpublished" — that made the
    # v0.1.3 run re-attempt everything and exit 1 despite a full publish.
    if curl -s -A "TrustForge-release (github.com/KodyDennon/TrustForge)" \
        "https://crates.io/api/v1/crates/$CRATE_NAME/$CRATE_VERSION" | grep -q '"version"'; then
      continue
    fi

    PENDING=1
    echo "Attempting to publish $CRATE_NAME v$CRATE_VERSION..."
    cd "$crate"
    # Allow dirty in case of local modifications or GitHub actions side-effects
    OUTPUT=$(cargo publish --allow-dirty 2>&1) && STATUS=0 || STATUS=$?
    echo "$OUTPUT"
    if [ $STATUS -eq 0 ]; then
      PROGRESS=1
      echo "Successfully published $CRATE_NAME"
    elif echo "$OUTPUT" | grep -q "already exists"; then
      # Belt and braces: the version is on the index even if the
      # pre-check above missed it.
      PROGRESS=1
      echo "$CRATE_NAME v$CRATE_VERSION already on crates.io — skipping"
    elif echo "$OUTPUT" | grep -q "429 Too Many Requests"; then
      # crates.io rate-limits publishes (~1/min to existing crates).
      # Not fatal — wait a window out instead of burning passes.
      RATE_LIMITED=1
      echo "Rate-limited publishing $CRATE_NAME (will retry next pass)"
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
    if [ "${RATE_LIMITED:-0}" -eq 1 ] && [ "${STALLS:-0}" -lt 60 ]; then
      STALLS=$(( ${STALLS:-0} + 1 ))
      RATE_LIMITED=0
      echo "No progress due to rate limiting (stall $STALLS/60); sleeping 65s..."
      sleep 65
      continue
    fi
    echo "Failed to make progress. Remaining crates have issues."
    exit 1
  fi
  STALLS=0
  
  echo "Made progress. Sleeping 10 seconds before next pass to let crates.io index..."
  sleep 10
done

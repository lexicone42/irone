#!/usr/bin/env bash
# Deploy static frontend to S3 and invalidate CloudFront cache.
# Usage: ./scripts/deploy_frontend.sh [BUCKET] [DISTRIBUTION_ID]
set -euo pipefail

BUCKET="${1:-iris-frontend}"
DIST_ID="${2:-}"
FRONTEND_DIR="frontend"

if [[ ! -d "$FRONTEND_DIR" ]]; then
    echo "ERROR: $FRONTEND_DIR not found. Run from repo root." >&2
    exit 1
fi

echo "==> Syncing $FRONTEND_DIR → s3://$BUCKET/"
aws s3 sync "$FRONTEND_DIR" "s3://$BUCKET/" \
    --delete \
    --cache-control "public, max-age=3600" \
    --exclude "*.map"

# JS files change without filename hashing — use short cache + revalidation
echo "==> Setting cache headers for JS assets"
aws s3 sync "$FRONTEND_DIR/assets/" "s3://$BUCKET/assets/" \
    --exclude "*" --include "*.js" \
    --cache-control "public, max-age=300, must-revalidate"

# CSS and JSON are more stable
echo "==> Setting cache headers for CSS/JSON assets"
aws s3 sync "$FRONTEND_DIR/assets/" "s3://$BUCKET/assets/" \
    --exclude "*" --include "*.css" --include "*.json" \
    --cache-control "public, max-age=86400"

if [[ -n "$DIST_ID" ]]; then
    echo "==> Invalidating CloudFront distribution $DIST_ID"
    aws cloudfront create-invalidation \
        --distribution-id "$DIST_ID" \
        --paths "/*.html" "/assets/*"
    echo "==> Invalidation submitted."
else
    echo "==> No DISTRIBUTION_ID provided, skipping CloudFront invalidation."
fi

echo "==> Done."

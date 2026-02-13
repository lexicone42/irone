#!/usr/bin/env bash
# Deploy secdashboards to AWS Lambda.
#
# Usage:
#   ./scripts/deploy_lambda.sh              # full deploy (install + zip + upload + update)
#   ./scripts/deploy_lambda.sh --skip-install  # reuse existing /tmp/secdash-lambda (fast redeploy)
#
# Override defaults via environment:
#   SECDASH_LAMBDA_NAME   Lambda function name (auto-detected from 'secdash-web' prefix)
#   SECDASH_S3_BUCKET     S3 bucket for upload (auto-detected from Lambda's SECDASH_REPORT_BUCKET)
#   SECDASH_S3_KEY        S3 key for the zip (default: lambda/secdash-lambda.zip)
#   SECDASH_REGION        AWS region (default: us-west-2)

set -euo pipefail

REGION="${SECDASH_REGION:-us-west-2}"
S3_KEY="${SECDASH_S3_KEY:-lambda/secdash-lambda.zip}"
STAGING_DIR="/tmp/secdash-lambda"
ZIP_PATH="/tmp/secdash-lambda.zip"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKIP_INSTALL=false

for arg in "$@"; do
    case "$arg" in
        --skip-install) SKIP_INSTALL=true ;;
        --help|-h)
            head -10 "$0" | tail -8
            exit 0
            ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# --- Auto-detect Lambda function name ---
if [[ -z "${SECDASH_LAMBDA_NAME:-}" ]]; then
    echo "Detecting Lambda function name..."
    SECDASH_LAMBDA_NAME=$(
        aws lambda list-functions --region "$REGION" \
            --query "Functions[?starts_with(FunctionName, 'secdash-web')].FunctionName" \
            --output text 2>/dev/null | head -1
    )
    if [[ -z "$SECDASH_LAMBDA_NAME" ]]; then
        echo "ERROR: Could not find a Lambda function starting with 'secdash-web'."
        echo "Set SECDASH_LAMBDA_NAME explicitly."
        exit 1
    fi
    echo "  Found: $SECDASH_LAMBDA_NAME"
fi

# --- Auto-detect S3 bucket from Lambda env ---
if [[ -z "${SECDASH_S3_BUCKET:-}" ]]; then
    echo "Detecting S3 bucket from Lambda config..."
    SECDASH_S3_BUCKET=$(
        aws lambda get-function-configuration \
            --function-name "$SECDASH_LAMBDA_NAME" \
            --region "$REGION" \
            --query "Environment.Variables.SECDASH_REPORT_BUCKET" \
            --output text 2>/dev/null
    )
    if [[ -z "$SECDASH_S3_BUCKET" || "$SECDASH_S3_BUCKET" == "None" ]]; then
        echo "ERROR: Could not detect S3 bucket from Lambda env (SECDASH_REPORT_BUCKET)."
        echo "Set SECDASH_S3_BUCKET explicitly."
        exit 1
    fi
    echo "  Found: $SECDASH_S3_BUCKET"
fi

echo ""
echo "Deploy config:"
echo "  Lambda:  $SECDASH_LAMBDA_NAME"
echo "  Bucket:  $SECDASH_S3_BUCKET"
echo "  S3 key:  $S3_KEY"
echo "  Region:  $REGION"
echo ""

# --- Step 1: Install package + deps ---
if [[ "$SKIP_INSTALL" == true ]]; then
    if [[ ! -d "$STAGING_DIR" ]]; then
        echo "ERROR: --skip-install but $STAGING_DIR does not exist."
        exit 1
    fi
    echo "Skipping install (reusing $STAGING_DIR)"
else
    echo "Installing package and dependencies..."
    rm -rf "$STAGING_DIR"
    mkdir -p "$STAGING_DIR"
    uv pip install --target "$STAGING_DIR" "$PROJECT_ROOT" --quiet
    echo "  Installed to $STAGING_DIR"
fi

# --- Step 2: Zip ---
echo "Creating zip..."
rm -f "$ZIP_PATH"
(cd "$STAGING_DIR" && zip -qr "$ZIP_PATH" .)
ZIP_SIZE=$(du -h "$ZIP_PATH" | cut -f1)
echo "  $ZIP_PATH ($ZIP_SIZE)"

# --- Step 3: Upload to S3 ---
echo "Uploading to S3..."
aws s3 cp "$ZIP_PATH" "s3://$SECDASH_S3_BUCKET/$S3_KEY" --region "$REGION" --quiet
echo "  s3://$SECDASH_S3_BUCKET/$S3_KEY"

# --- Step 4: Update Lambda ---
echo "Updating Lambda function code..."
aws lambda update-function-code \
    --function-name "$SECDASH_LAMBDA_NAME" \
    --s3-bucket "$SECDASH_S3_BUCKET" \
    --s3-key "$S3_KEY" \
    --region "$REGION" \
    --query "LastModified" \
    --output text
echo "  Function updated."

# --- Step 5: Wait for update to complete ---
echo "Waiting for function to be ready..."
aws lambda wait function-updated \
    --function-name "$SECDASH_LAMBDA_NAME" \
    --region "$REGION"
echo "  Ready."

echo ""
echo "Deploy complete."

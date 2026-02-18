#!/usr/bin/env bash
# Deploy iris-rs Rust Lambdas to AWS.
#
# Usage:
#   ./scripts/deploy_rust_lambda.sh              # deploy both Lambdas
#   ./scripts/deploy_rust_lambda.sh web           # deploy only iris-web
#   ./scripts/deploy_rust_lambda.sh health        # deploy only iris-health-checker
#   ./scripts/deploy_rust_lambda.sh --skip-build  # reuse existing zips
#
# Override defaults via environment:
#   SECDASH_WEB_LAMBDA_NAME       Web Lambda function name (auto-detected)
#   SECDASH_HEALTH_LAMBDA_NAME    Health checker Lambda name (auto-detected)
#   SECDASH_S3_BUCKET             S3 bucket for upload (auto-detected from Lambda env)
#   SECDASH_S3_KEY_PREFIX         S3 key prefix (default: lambda/rust/)
#   SECDASH_REGION                AWS region (default: us-west-2)

set -euo pipefail

REGION="${SECDASH_REGION:-us-west-2}"
S3_KEY_PREFIX="${SECDASH_S3_KEY_PREFIX:-lambda/rust/}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IRIS_RS_DIR="$PROJECT_ROOT/iris-rs"
SKIP_BUILD=false
DEPLOY_WEB=true
DEPLOY_HEALTH=true

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        web) DEPLOY_HEALTH=false ;;
        health) DEPLOY_WEB=false ;;
        --help|-h)
            head -14 "$0" | tail -12
            exit 0
            ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# --- Auto-detect Lambda function names ---
if [[ "$DEPLOY_WEB" == true && -z "${SECDASH_WEB_LAMBDA_NAME:-}" ]]; then
    echo "Detecting web Lambda function name..."
    SECDASH_WEB_LAMBDA_NAME=$(
        aws lambda list-functions --region "$REGION" \
            --query "Functions[?starts_with(FunctionName, 'secdash-web')].FunctionName" \
            --output text 2>/dev/null | head -1
    )
    if [[ -z "$SECDASH_WEB_LAMBDA_NAME" ]]; then
        echo "ERROR: Could not find a Lambda function starting with 'secdash-web'."
        echo "Set SECDASH_WEB_LAMBDA_NAME explicitly."
        exit 1
    fi
    echo "  Found: $SECDASH_WEB_LAMBDA_NAME"
fi

if [[ "$DEPLOY_HEALTH" == true && -z "${SECDASH_HEALTH_LAMBDA_NAME:-}" ]]; then
    echo "Detecting health checker Lambda function name..."
    SECDASH_HEALTH_LAMBDA_NAME=$(
        aws lambda list-functions --region "$REGION" \
            --query "Functions[?starts_with(FunctionName, 'secdash-health')].FunctionName" \
            --output text 2>/dev/null | head -1
    )
    if [[ -z "$SECDASH_HEALTH_LAMBDA_NAME" ]]; then
        echo "ERROR: Could not find a Lambda function starting with 'secdash-health'."
        echo "Set SECDASH_HEALTH_LAMBDA_NAME explicitly."
        exit 1
    fi
    echo "  Found: $SECDASH_HEALTH_LAMBDA_NAME"
fi

# --- Auto-detect S3 bucket ---
if [[ -z "${SECDASH_S3_BUCKET:-}" ]]; then
    echo "Detecting S3 bucket from Lambda config..."
    DETECT_LAMBDA="${SECDASH_WEB_LAMBDA_NAME:-${SECDASH_HEALTH_LAMBDA_NAME:-}}"
    SECDASH_S3_BUCKET=$(
        aws lambda get-function-configuration \
            --function-name "$DETECT_LAMBDA" \
            --region "$REGION" \
            --query "Environment.Variables.SECDASH_REPORT_BUCKET" \
            --output text 2>/dev/null
    )
    if [[ -z "$SECDASH_S3_BUCKET" || "$SECDASH_S3_BUCKET" == "None" ]]; then
        echo "ERROR: Could not detect S3 bucket. Set SECDASH_S3_BUCKET explicitly."
        exit 1
    fi
    echo "  Found: $SECDASH_S3_BUCKET"
fi

echo ""
echo "Deploy config:"
[[ "$DEPLOY_WEB" == true ]] && echo "  Web Lambda:     $SECDASH_WEB_LAMBDA_NAME"
[[ "$DEPLOY_HEALTH" == true ]] && echo "  Health Lambda:  $SECDASH_HEALTH_LAMBDA_NAME"
echo "  Bucket:         $SECDASH_S3_BUCKET"
echo "  S3 prefix:      $S3_KEY_PREFIX"
echo "  Region:         $REGION"
echo ""

# --- Step 1: Build ---
if [[ "$SKIP_BUILD" == true ]]; then
    echo "Skipping build (reusing existing zips)"
else
    echo "Building release binaries with cargo-lambda..."
    (cd "$IRIS_RS_DIR" && cargo lambda build --release --output-format zip)
    echo "  Build complete."
fi

WEB_ZIP="$IRIS_RS_DIR/target/lambda/iris-web/bootstrap.zip"
HEALTH_ZIP="$IRIS_RS_DIR/target/lambda/iris-health-checker/bootstrap.zip"

# --- Helper: deploy one Lambda ---
deploy_lambda() {
    local name="$1"
    local zip_path="$2"
    local s3_key="$3"

    if [[ ! -f "$zip_path" ]]; then
        echo "ERROR: Zip not found: $zip_path"
        exit 1
    fi

    local zip_size
    zip_size=$(du -h "$zip_path" | cut -f1)
    echo "  Zip: $zip_path ($zip_size)"

    # Upload to S3
    echo "  Uploading to s3://$SECDASH_S3_BUCKET/$s3_key ..."
    aws s3 cp "$zip_path" "s3://$SECDASH_S3_BUCKET/$s3_key" --region "$REGION" --quiet

    # Update Lambda runtime to provided.al2023 (Rust custom runtime)
    echo "  Updating runtime to provided.al2023..."
    aws lambda update-function-configuration \
        --function-name "$name" \
        --runtime "provided.al2023" \
        --handler "bootstrap" \
        --region "$REGION" \
        --query "LastModified" \
        --output text

    # Wait for config update
    aws lambda wait function-updated --function-name "$name" --region "$REGION"

    # Update code
    echo "  Updating function code..."
    aws lambda update-function-code \
        --function-name "$name" \
        --s3-bucket "$SECDASH_S3_BUCKET" \
        --s3-key "$s3_key" \
        --region "$REGION" \
        --query "LastModified" \
        --output text

    # Wait for code update
    aws lambda wait function-updated --function-name "$name" --region "$REGION"
    echo "  Ready."
}

# --- Step 2: Deploy ---
if [[ "$DEPLOY_WEB" == true ]]; then
    echo ""
    echo "Deploying iris-web..."
    deploy_lambda "$SECDASH_WEB_LAMBDA_NAME" "$WEB_ZIP" "${S3_KEY_PREFIX}iris-web.zip"
fi

if [[ "$DEPLOY_HEALTH" == true ]]; then
    echo ""
    echo "Deploying iris-health-checker..."
    deploy_lambda "$SECDASH_HEALTH_LAMBDA_NAME" "$HEALTH_ZIP" "${S3_KEY_PREFIX}iris-health-checker.zip"
fi

echo ""
echo "Deploy complete."
[[ "$DEPLOY_WEB" == true ]] && echo "  iris-web:            $SECDASH_WEB_LAMBDA_NAME ($zip_size)"
[[ "$DEPLOY_HEALTH" == true ]] && echo "  iris-health-checker: $SECDASH_HEALTH_LAMBDA_NAME"

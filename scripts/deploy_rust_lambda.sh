#!/usr/bin/env bash
# Deploy irone-rs Rust Lambdas to AWS.
#
# Usage:
#   ./scripts/deploy_rust_lambda.sh              # deploy all Lambdas
#   ./scripts/deploy_rust_lambda.sh web           # deploy only irone-web
#   ./scripts/deploy_rust_lambda.sh health        # deploy only irone-health-checker
#   ./scripts/deploy_rust_lambda.sh worker        # deploy only irone-worker
#   ./scripts/deploy_rust_lambda.sh --skip-build  # reuse existing zips
#
# Override defaults via environment:
#   SECDASH_WEB_LAMBDA_NAME       Web Lambda function name (auto-detected)
#   SECDASH_HEALTH_LAMBDA_NAME    Health checker Lambda name (auto-detected)
#   SECDASH_WORKER_LAMBDA_NAME    Worker Lambda function name (auto-detected)
#   SECDASH_S3_BUCKET             S3 bucket for upload (auto-detected from Lambda env)
#   SECDASH_S3_KEY_PREFIX         S3 key prefix (default: lambda/rust/)
#   SECDASH_REGION                AWS region (default: us-west-2)

set -euo pipefail

REGION="${SECDASH_REGION:-us-west-2}"
S3_KEY_PREFIX="${SECDASH_S3_KEY_PREFIX:-lambda/rust/}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IRONE_RS_DIR="$PROJECT_ROOT/irone-rs"
SKIP_BUILD=false
DEPLOY_WEB=true
DEPLOY_HEALTH=true
DEPLOY_WORKER=true
TARGET_SPECIFIED=false

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        web) DEPLOY_HEALTH=false; DEPLOY_WORKER=false; TARGET_SPECIFIED=true ;;
        health) DEPLOY_WEB=false; DEPLOY_WORKER=false; TARGET_SPECIFIED=true ;;
        worker) DEPLOY_WEB=false; DEPLOY_HEALTH=false; TARGET_SPECIFIED=true ;;
        --help|-h)
            head -15 "$0" | tail -13
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

if [[ "$DEPLOY_WORKER" == true && -z "${SECDASH_WORKER_LAMBDA_NAME:-}" ]]; then
    echo "Detecting worker Lambda function name..."
    SECDASH_WORKER_LAMBDA_NAME=$(
        aws lambda list-functions --region "$REGION" \
            --query "Functions[?starts_with(FunctionName, 'secdash-worker')].FunctionName" \
            --output text 2>/dev/null | head -1
    )
    if [[ -z "$SECDASH_WORKER_LAMBDA_NAME" ]]; then
        echo "WARNING: Could not find a Lambda function starting with 'secdash-worker'."
        echo "Set SECDASH_WORKER_LAMBDA_NAME explicitly, or deploy CDK first."
        DEPLOY_WORKER=false
    else
        echo "  Found: $SECDASH_WORKER_LAMBDA_NAME"
    fi
fi

# --- Auto-detect S3 bucket ---
if [[ -z "${SECDASH_S3_BUCKET:-}" ]]; then
    echo "Detecting S3 bucket from Lambda config..."
    DETECT_LAMBDA="${SECDASH_WEB_LAMBDA_NAME:-${SECDASH_HEALTH_LAMBDA_NAME:-${SECDASH_WORKER_LAMBDA_NAME:-}}}"
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
[[ "$DEPLOY_WORKER" == true ]] && echo "  Worker Lambda:  $SECDASH_WORKER_LAMBDA_NAME"
echo "  Bucket:         $SECDASH_S3_BUCKET"
echo "  S3 prefix:      $S3_KEY_PREFIX"
echo "  Region:         $REGION"
echo ""

# --- Step 1: Build ---
if [[ "$SKIP_BUILD" == true ]]; then
    echo "Skipping build (reusing existing zips)"
else
    echo "Building release binaries with cargo-lambda..."
    (cd "$IRONE_RS_DIR" && cargo lambda build --release --output-format zip)
    echo "  Build complete."
fi

WEB_ZIP="$IRONE_RS_DIR/target/lambda/irone-web/bootstrap.zip"
HEALTH_ZIP="$IRONE_RS_DIR/target/lambda/irone-health-checker/bootstrap.zip"
WORKER_ZIP="$IRONE_RS_DIR/target/lambda/irone-worker/bootstrap.zip"

# --- Bundle Cedar policies into irone-web zip ---
CEDAR_SRC="$PROJECT_ROOT/../l42cognitopasskey/rust/cedar"
if [[ -d "$CEDAR_SRC" ]]; then
    echo "Bundling Cedar policies into irone-web zip..."
    # Create a temp dir with cedar/ structure, add to existing zip
    CEDAR_TMP=$(mktemp -d)
    cp -r "$CEDAR_SRC" "$CEDAR_TMP/cedar"
    (cd "$CEDAR_TMP" && zip -qr "$WEB_ZIP" cedar/)
    rm -rf "$CEDAR_TMP"
    echo "  Cedar policies bundled ($(du -sh "$CEDAR_SRC" | cut -f1))"
else
    echo "WARNING: Cedar policies not found at $CEDAR_SRC — deploying without authorization"
fi

# --- Bundle detection rules into irone-web zip ---
RULES_DIR="$IRONE_RS_DIR/rules"
if [[ -d "$RULES_DIR" ]]; then
    RULE_COUNT=$(find "$RULES_DIR" -name '*.yaml' | wc -l)
    if [[ "$RULE_COUNT" -gt 0 ]]; then
        echo "Bundling $RULE_COUNT detection rules into irone-web zip..."
        RULES_TMP=$(mktemp -d)
        cp -r "$RULES_DIR" "$RULES_TMP/rules"
        (cd "$RULES_TMP" && zip -qr "$WEB_ZIP" rules/)
        rm -rf "$RULES_TMP"
        echo "  Detection rules bundled."
    fi
fi

# --- Bundle detection rules into irone-worker zip ---
if [[ "$DEPLOY_WORKER" == true && -d "$RULES_DIR" ]]; then
    RULE_COUNT=$(find "$RULES_DIR" -name '*.yaml' | wc -l)
    if [[ "$RULE_COUNT" -gt 0 && -f "$WORKER_ZIP" ]]; then
        echo "Bundling $RULE_COUNT detection rules into irone-worker zip..."
        RULES_TMP=$(mktemp -d)
        cp -r "$RULES_DIR" "$RULES_TMP/rules"
        (cd "$RULES_TMP" && zip -qr "$WORKER_ZIP" rules/)
        rm -rf "$RULES_TMP"
        echo "  Detection rules bundled."
    fi
fi

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
    echo "Deploying irone-web..."
    deploy_lambda "$SECDASH_WEB_LAMBDA_NAME" "$WEB_ZIP" "${S3_KEY_PREFIX}irone-web.zip"
fi

if [[ "$DEPLOY_HEALTH" == true ]]; then
    echo ""
    echo "Deploying irone-health-checker..."
    deploy_lambda "$SECDASH_HEALTH_LAMBDA_NAME" "$HEALTH_ZIP" "${S3_KEY_PREFIX}irone-health-checker.zip"
fi

if [[ "$DEPLOY_WORKER" == true ]]; then
    echo ""
    echo "Deploying irone-worker..."
    deploy_lambda "$SECDASH_WORKER_LAMBDA_NAME" "$WORKER_ZIP" "${S3_KEY_PREFIX}irone-worker.zip"
fi

echo ""
echo "Deploy complete."
if [[ "$DEPLOY_WEB" == true ]]; then
    local_size=$(du -h "$WEB_ZIP" | cut -f1)
    echo "  irone-web:            $SECDASH_WEB_LAMBDA_NAME ($local_size)"
fi
if [[ "$DEPLOY_HEALTH" == true ]]; then
    echo "  irone-health-checker: $SECDASH_HEALTH_LAMBDA_NAME"
fi
if [[ "$DEPLOY_WORKER" == true ]]; then
    echo "  irone-worker:         $SECDASH_WORKER_LAMBDA_NAME"
fi

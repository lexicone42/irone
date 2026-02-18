#!/usr/bin/env bash
# Deploy iris Rust Lambdas via CDK.
#
# Usage:
#   ./scripts/deploy_cdk.sh              # build + deploy all stacks
#   ./scripts/deploy_cdk.sh --skip-build # reuse existing build output
#   ./scripts/deploy_cdk.sh --diff       # show diff without deploying
#
# Override defaults via environment:
#   SECDASH_REGION   AWS region (default: us-west-2)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IRIS_RS_DIR="$PROJECT_ROOT/iris-rs"
INFRA_DIR="$PROJECT_ROOT/infra"
REGION="${SECDASH_REGION:-us-west-2}"
SKIP_BUILD=false
DIFF_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --diff) DIFF_ONLY=true ;;
        --help|-h)
            head -10 "$0" | tail -8
            exit 0
            ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# --- Step 1: Build Rust Lambdas ---
if [[ "$SKIP_BUILD" == true ]]; then
    echo "Skipping build (reusing existing output)"
else
    echo "Building release binaries with cargo-lambda..."
    (cd "$IRIS_RS_DIR" && cargo lambda build --release)
    echo "  Build complete."
fi

# Verify bootstrap binaries exist
for crate in iris-web iris-health-checker; do
    bootstrap="$IRIS_RS_DIR/target/lambda/$crate/bootstrap"
    if [[ ! -f "$bootstrap" ]]; then
        echo "ERROR: Bootstrap not found: $bootstrap"
        echo "Run without --skip-build or build manually first."
        exit 1
    fi
    echo "  $crate: $(du -h "$bootstrap" | cut -f1)"
done

# iris-alerting may not exist yet (crate not built)
alerting_bootstrap="$IRIS_RS_DIR/target/lambda/iris-alerting/bootstrap"
if [[ -f "$alerting_bootstrap" ]]; then
    echo "  iris-alerting: $(du -h "$alerting_bootstrap" | cut -f1)"
else
    echo "  iris-alerting: not built (will use dummy placeholder)"
fi

# --- Step 2: Bundle Cedar policies into iris-web output ---
CEDAR_SRC="$PROJECT_ROOT/../l42cognitopasskey/rust/cedar"
WEB_LAMBDA_DIR="$IRIS_RS_DIR/target/lambda/iris-web"

if [[ -d "$CEDAR_SRC" ]]; then
    echo "Bundling Cedar policies into iris-web..."
    rm -rf "$WEB_LAMBDA_DIR/cedar"
    cp -r "$CEDAR_SRC" "$WEB_LAMBDA_DIR/cedar"
    echo "  Cedar policies: $(find "$WEB_LAMBDA_DIR/cedar" -type f | wc -l) files"
else
    echo "WARNING: Cedar policies not found at $CEDAR_SRC — deploying without authorization"
fi

# --- Step 3: CDK deploy ---
echo ""
cd "$INFRA_DIR"

# Ensure deps are installed
if [[ ! -d "node_modules" ]]; then
    echo "Installing CDK dependencies..."
    npm install
fi

if [[ "$DIFF_ONLY" == true ]]; then
    echo "Running cdk diff..."
    npx cdk diff --all
else
    echo "Deploying via CDK..."
    npx cdk deploy --all --require-approval never
fi

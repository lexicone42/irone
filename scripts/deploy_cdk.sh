#!/usr/bin/env bash
# Deploy irone Rust Lambdas via CDK.
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
IRONE_RS_DIR="$PROJECT_ROOT/irone-rs"
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
    (cd "$IRONE_RS_DIR" && cargo lambda build --release)
    echo "  Build complete."
fi

# Verify bootstrap binaries exist
for crate in irone-web irone-health-checker irone-worker irone-alerting; do
    bootstrap="$IRONE_RS_DIR/target/lambda/$crate/bootstrap"
    if [[ ! -f "$bootstrap" ]]; then
        echo "WARNING: Bootstrap not found: $bootstrap (will use dummy placeholder)"
    else
        echo "  $crate: $(du -h "$bootstrap" | cut -f1)"
    fi
done

# --- Step 2: Bundle assets into Lambda output directories ---
CEDAR_SRC="$PROJECT_ROOT/../l42cognitopasskey/rust/cedar"
WEB_LAMBDA_DIR="$IRONE_RS_DIR/target/lambda/irone-web"
RULES_DIR="$IRONE_RS_DIR/rules"

# Cedar policies → irone-web
if [[ -d "$CEDAR_SRC" ]]; then
    echo "Bundling Cedar policies into irone-web..."
    rm -rf "$WEB_LAMBDA_DIR/cedar"
    cp -r "$CEDAR_SRC" "$WEB_LAMBDA_DIR/cedar"
    echo "  Cedar policies: $(find "$WEB_LAMBDA_DIR/cedar" -type f | wc -l) files"
else
    echo "WARNING: Cedar policies not found at $CEDAR_SRC — deploying without authorization"
fi

# Detection rules → irone-web, irone-worker, irone-alerting
if [[ -d "$RULES_DIR" ]]; then
    RULE_COUNT=$(find "$RULES_DIR" -name '*.yaml' | wc -l)
    for crate in irone-web irone-worker irone-alerting; do
        crate_dir="$IRONE_RS_DIR/target/lambda/$crate"
        if [[ -f "$crate_dir/bootstrap" ]]; then
            rm -rf "$crate_dir/rules"
            cp -r "$RULES_DIR" "$crate_dir/rules"
            echo "  Bundled $RULE_COUNT rules into $crate"
        fi
    done
else
    echo "WARNING: Detection rules not found at $RULES_DIR"
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

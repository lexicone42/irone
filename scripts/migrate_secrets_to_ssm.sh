#!/usr/bin/env bash
# One-time migration: copy secrets from Secrets Manager / Lambda env vars
# into SSM Parameter Store SecureString parameters.
#
# Prerequisites:
#   - AWS CLI v2 configured with appropriate permissions
#   - Secrets Manager secrets secdash/service-token and secdash/session-secret-key exist
#   - Lambda function secdash-web-FastAPIHandlerC4831E27-KlK3BmblmlcV exists
#
# Usage: ./scripts/migrate_secrets_to_ssm.sh [--dry-run]

set -euo pipefail

REGION="us-west-2"
LAMBDA_FUNCTION="secdash-web-FastAPIHandlerC4831E27-KlK3BmblmlcV"
DRY_RUN="${1:-}"

info() { echo "==> $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# --- 1. Read service token from Secrets Manager ---
info "Reading service token from Secrets Manager (secdash/service-token)..."
SERVICE_TOKEN=$(aws secretsmanager get-secret-value \
  --secret-id "secdash/service-token" \
  --region "$REGION" \
  --query 'SecretString' --output text) || die "Failed to read secdash/service-token"
[ -n "$SERVICE_TOKEN" ] || die "Service token is empty"
info "  Got service token (${#SERVICE_TOKEN} chars)"

# --- 2. Read session secret from Secrets Manager ---
info "Reading session secret from Secrets Manager (secdash/session-secret-key)..."
SESSION_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "secdash/session-secret-key" \
  --region "$REGION" \
  --query 'SecretString' --output text) || die "Failed to read secdash/session-secret-key"
[ -n "$SESSION_SECRET" ] || die "Session secret is empty"
info "  Got session secret (${#SESSION_SECRET} chars)"

# --- 3. Read Cognito client secret from Lambda env vars ---
info "Reading Cognito client secret from Lambda environment..."
COGNITO_SECRET=$(aws lambda get-function-configuration \
  --function-name "$LAMBDA_FUNCTION" \
  --region "$REGION" \
  --query 'Environment.Variables.SECDASH_COGNITO_CLIENT_SECRET' --output text) || die "Failed to read Lambda env"
[ -n "$COGNITO_SECRET" ] && [ "$COGNITO_SECRET" != "None" ] || die "Cognito client secret is empty"
info "  Got Cognito client secret (${#COGNITO_SECRET} chars)"

# --- 4. Create SSM SecureString parameters ---
create_param() {
  local name="$1" value="$2"
  if [ "$DRY_RUN" = "--dry-run" ]; then
    info "[DRY RUN] Would create SSM parameter: $name (${#value} chars)"
    return
  fi
  info "Creating SSM parameter: $name"
  aws ssm put-parameter \
    --name "$name" \
    --type SecureString \
    --value "$value" \
    --region "$REGION" \
    --overwrite 2>/dev/null || \
  aws ssm put-parameter \
    --name "$name" \
    --type SecureString \
    --value "$value" \
    --region "$REGION"
}

create_param "/secdash/service-token"        "$SERVICE_TOKEN"
create_param "/secdash/session-secret-key"   "$SESSION_SECRET"
create_param "/secdash/cognito-client-secret" "$COGNITO_SECRET"

# --- 5. Verify ---
if [ "$DRY_RUN" != "--dry-run" ]; then
  info "Verifying SSM parameters exist..."
  for param in /secdash/service-token /secdash/session-secret-key /secdash/cognito-client-secret; do
    aws ssm get-parameter --name "$param" --region "$REGION" --query 'Parameter.Name' --output text \
      || die "Verification failed for $param"
  done
  info "All 3 SSM parameters created successfully."
  echo ""
  info "Next steps:"
  info "  1. Deploy CDK:  ./scripts/deploy_cdk.sh"
  info "  2. Verify Lambda logs show 'loaded secret from SSM Parameter Store'"
  info "  3. Confirm login works at https://irone.lexicone.com"
fi

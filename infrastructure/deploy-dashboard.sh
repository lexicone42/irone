#!/bin/bash
# Deploy the health dashboard
# Usage: ./deploy-dashboard.sh [stack-name]

set -e

STACK_NAME="${1:-secdash-health}"
REGION="${AWS_REGION:-us-west-2}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Deploying health dashboard stack: $STACK_NAME"

# Deploy the SAM template
sam build --template-file "$SCRIPT_DIR/health-dashboard.yaml"
sam deploy \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
    --resolve-s3 \
    --no-confirm-changeset

# Get outputs
echo "Retrieving stack outputs..."
API_ENDPOINT=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`ApiEndpoint`].OutputValue' \
    --output text)

CLIENT_ID=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`UserPoolClientId`].OutputValue' \
    --output text)

USER_POOL_ID=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' \
    --output text)

DASHBOARD_BUCKET=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`DashboardBucket`].OutputValue' \
    --output text)

DASHBOARD_URL=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`DashboardUrl`].OutputValue' \
    --output text)

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# Generate the cognito domain
COGNITO_DOMAIN="secdash-health-${ACCOUNT_ID}.auth.${REGION}.amazoncognito.com"

echo ""
echo "Stack outputs:"
echo "  API Endpoint: $API_ENDPOINT"
echo "  User Pool ID: $USER_POOL_ID"
echo "  Client ID: $CLIENT_ID"
echo "  Dashboard Bucket: $DASHBOARD_BUCKET"
echo "  Dashboard URL: $DASHBOARD_URL"
echo "  Cognito Domain: $COGNITO_DOMAIN"

# Update the static HTML with correct config
echo ""
echo "Updating dashboard config..."
STATIC_DIR="$SCRIPT_DIR/dashboard-static"
TEMP_FILE=$(mktemp)

# Use sed to replace config values (more portable than template strings)
sed -e "s|ACCOUNT_ID|$ACCOUNT_ID|g" \
    -e "s|REGION|$REGION|g" \
    -e "s|CLIENT_ID|$CLIENT_ID|g" \
    -e "s|API_ID|$(echo "$API_ENDPOINT" | sed 's|https://||' | cut -d. -f1)|g" \
    "$STATIC_DIR/index.html" > "$TEMP_FILE"

mv "$TEMP_FILE" "$STATIC_DIR/index.html"

# Upload static files to S3
echo ""
echo "Uploading static files to S3..."
aws s3 sync "$STATIC_DIR" "s3://$DASHBOARD_BUCKET/" \
    --region "$REGION" \
    --cache-control "max-age=3600"

# Invalidate CloudFront cache
DISTRIBUTION_ID=$(aws cloudfront list-distributions \
    --query "DistributionList.Items[?Origins.Items[?DomainName=='${DASHBOARD_BUCKET}.s3.${REGION}.amazonaws.com']].Id" \
    --output text 2>/dev/null || echo "")

if [ -n "$DISTRIBUTION_ID" ] && [ "$DISTRIBUTION_ID" != "None" ]; then
    echo "Invalidating CloudFront cache..."
    aws cloudfront create-invalidation \
        --distribution-id "$DISTRIBUTION_ID" \
        --paths "/*" > /dev/null
fi

echo ""
echo "Deployment complete!"
echo ""
echo "Next steps:"
echo "  1. Create user: aws cognito-idp admin-create-user --user-pool-id $USER_POOL_ID --username bryan.egan@gmail.com --user-attributes Name=email,Value=bryan.egan@gmail.com Name=email_verified,Value=true"
echo "  2. Set temporary password for first login, then register passkey"
echo "  3. Access dashboard at: $DASHBOARD_URL"

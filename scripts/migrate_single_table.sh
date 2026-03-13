#!/usr/bin/env bash
# Backfill record_type="investigation" on existing secdash_investigations items.
#
# Safe to run multiple times (idempotent). Skips items that already have
# record_type set or that have a "dr#" id prefix (detection runs).
#
# Usage: ./scripts/migrate_single_table.sh [--dry-run]

set -euo pipefail

TABLE="secdash_investigations"
REGION="${AWS_REGION:-us-west-2}"
DRY_RUN=false

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "DRY RUN — no changes will be made"
fi

echo "Scanning $TABLE for items missing record_type..."

TOTAL=0
UPDATED=0
SKIPPED=0

# Scan all items, page by page
LAST_KEY=""
while true; do
    if [[ -z "$LAST_KEY" ]]; then
        RESULT=$(aws dynamodb scan \
            --table-name "$TABLE" \
            --region "$REGION" \
            --projection-expression "id,record_type" \
            --output json 2>&1)
    else
        RESULT=$(aws dynamodb scan \
            --table-name "$TABLE" \
            --region "$REGION" \
            --projection-expression "id,record_type" \
            --exclusive-start-key "$LAST_KEY" \
            --output json 2>&1)
    fi

    # Process each item
    ITEMS=$(echo "$RESULT" | jq -c '.Items[]')
    while IFS= read -r item; do
        TOTAL=$((TOTAL + 1))
        ID=$(echo "$item" | jq -r '.id.S')
        HAS_TYPE=$(echo "$item" | jq -r '.record_type.S // empty')

        # Skip if already has record_type
        if [[ -n "$HAS_TYPE" ]]; then
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        # Skip detection runs (dr# prefix)
        if [[ "$ID" == dr#* ]]; then
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        if $DRY_RUN; then
            echo "  [dry-run] Would set record_type=investigation on $ID"
        else
            aws dynamodb update-item \
                --table-name "$TABLE" \
                --region "$REGION" \
                --key "{\"id\":{\"S\":\"$ID\"}}" \
                --update-expression "SET record_type = :rt" \
                --expression-attribute-values '{":rt":{"S":"investigation"}}' \
                --output text > /dev/null
            echo "  Updated $ID"
        fi
        UPDATED=$((UPDATED + 1))
    done <<< "$ITEMS"

    # Check for more pages
    LAST_KEY=$(echo "$RESULT" | jq -c '.LastEvaluatedKey // empty')
    if [[ -z "$LAST_KEY" || "$LAST_KEY" == "null" ]]; then
        break
    fi
done

echo ""
echo "Done! Scanned $TOTAL items, updated $UPDATED, skipped $SKIPPED"

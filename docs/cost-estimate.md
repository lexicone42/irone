# irone AWS Cost Estimate

Last updated: 2026-02-23

## Monthly Cost Breakdown (~$80/mo after optimizations)

| Service | Monthly Est. | Notes |
|---|---|---|
| CodeBuild | ~$21 | CI builds (spiky, not irone-specific) |
| AWS Glue | ~$8 | Security Lake catalog (4 US regions) |
| Lambda | ~$13 | 4 functions (web, health, worker, alerting) |
| S3 | ~$6 | Security Lake data + report bucket + frontend |
| Security Hub | ~$7 | Finding ingestion + compliance checks |
| CloudTrail | ~$7 | Management events |
| Security Lake | ~$4 | OCSF normalization (4 US regions) |
| KMS | ~$2 | Encryption keys (4 regions) |
| SQS | ~$2 | Security Lake internal queues |
| Cost Explorer | ~$3 | API calls |
| GuardDuty | ~$3 | Threat detection |
| Route 53 | ~$2 | Hosted zone + DNS |
| CloudWatch | ~$1 | Logs + metrics |
| Other (EC2, Config, etc.) | ~$4 | |
| **Total** | **~$83/mo** | |

## Key Cost Drivers

### Security Lake (was ~$35/mo, now ~$16/mo)
- Deployed in **4 US regions** (us-west-2, us-east-1, us-east-2, us-west-1)
- Previously in 17 regions; 13 non-US regions disabled 2026-02-23
- Each region runs: Glue catalog, KMS CMK, SQS queues, S3 storage
- Data sources: CloudTrail, VPC Flow, Route53, Security Hub, Lambda Execution, EKS Audit
- 4 AWS accounts contributing data

### Alerting Lambda (~$3/mo)
- Detection schedule: **every 60 minutes** (24 runs/day)
- Each run: ~512s @ 1024MB scanning 37 rules via Iceberg
- Freshness schedule: every 15 minutes (96 runs/day, ~0.5s each)
- GB-seconds/day: (512 * 1 * 24) + (0.5 * 1 * 96) = 12,336 GB-s
- Cost: 12,336 * $0.0000166667 = ~$0.21/day = ~$6.30/mo (includes free tier offset)

### Other Lambdas (~$10/mo combined)
- **secdash-web**: API handler, ~1-2ms warm, called per API request
- **secdash-health-checker**: Every 15 min, ~10s per run
- **secdash-worker**: On-demand (Step Functions), ~60-120s per investigation

## Optimization History

| Date | Change | Savings |
|---|---|---|
| 2026-02-23 | Disabled Security Lake in 13 non-US regions | ~$20/mo |
| 2026-02-23 | Changed detection schedule from 15min to 60min | ~$9/mo |

## Future Optimization Options

- **Disable non-us-west-2 US regions**: If no activity in us-east-1/2 or us-west-1, save ~$8/mo more
- **Reduce Security Hub standards**: Disable compliance checks if only used as finding aggregator, save ~$3/mo
- **Parallel detection runs**: Scan Iceberg table once, apply all 37 rule filters — would cut Lambda time from ~512s to ~15s
- **GuardDuty**: Review if still needed alongside irone detections

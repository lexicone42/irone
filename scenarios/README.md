# Incident Scenarios for Interview Prep

Mock investigation scenarios that exercise the full irone pipeline:
detection → graph → enrichment → patterns → AI analysis → playbook response.

Each scenario includes:
- **Situation**: What triggered the alert
- **Investigation artifacts**: Graph, timeline, patterns, anomalies
- **Analysis walkthrough**: How to narrate the investigation in an interview
- **Key talking points**: Architecture decisions and tradeoffs to highlight

## Scenarios

1. **Compromised IAM Access Keys** — Classic credential theft via phishing, lateral movement through AWS services
2. **K8s Container Escape** — Privileged pod → node access → cluster-admin RBAC escalation
3. **Insider Data Exfiltration** — Legitimate user with excessive access exfils S3 data before resignation
4. **Supply Chain Attack** — Malicious Lambda layer injection via compromised CI/CD

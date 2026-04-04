# MITRE ATT&CK Detection Coverage Map

53 detection rules covering 50 unique MITRE ATT&CK techniques across AWS, EKS, and GCP.

## Coverage by Tactic

### Initial Access (TA0001)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Valid Accounts: Cloud | T1078.004 | Root Console Login, Cross-Account Role, STS AssumeRole, GitHub OIDC, GetFederationToken, Console Login, GCP IAM Policy | AWS, GCP |
| Valid Accounts: Default | T1078.001 | EKS RBAC Escalation, EKS SA Token Request | EKS |
| Exploit Public-Facing App | T1190 | Security Hub Critical Finding | AWS |
| External Remote Services | T1133 | EKS NodePort/LoadBalancer Exposure | EKS |

### Persistence (TA0003)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Account Manipulation | T1098 | IAM Privilege Escalation, S3 ACL, MFA Change, GCP IAM Policy | AWS, GCP |
| Additional Cloud Credentials | T1098.001 | Access Key Created, OIDC Provider, Roles Anywhere, GCP SA Key, EKS SA Token | AWS, GCP, EKS |
| Modify Auth Process | T1556.006 | MFA Device Modification | AWS |
| Create Account: Cloud | T1136.003 | IAM User/Role Creation | AWS |
| Implant Container Image | T1525 | ECR Image Poisoning | AWS |
| Event Triggered Execution | T1546 | Lambda Layer Backdoor | AWS |
| SAML Token Forge | T1606.002 | SAML Provider Manipulation | AWS |
| Scheduled Task: Container | T1053.007 | EKS DaemonSet, EKS CronJob | EKS |

### Privilege Escalation (TA0004)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Valid Accounts: Cloud | T1078.004 | (same as Initial Access) | AWS, GCP |
| Container Escape | T1611 | EKS Privileged Pod | EKS |
| Deploy Container | T1610 | EKS Privileged Pod | EKS |

### Defense Evasion (TA0005)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Impair Defenses: CloudTrail | T1562.008 | CloudTrail Tampering, GCP Audit Log Tampering | AWS, GCP |
| Impair Defenses: Tools | T1562.001 | GuardDuty Tampering, Security Tools, Org Policy | AWS |
| Modify Cloud Compute | T1578.002 | EBS Snapshot Sharing, Unusual Region | AWS |
| Unused Cloud Regions | T1535 | Unusual Region, EC2 Launch | AWS |

### Credential Access (TA0006)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Unsecured Credentials: IMDS | T1552.005 | Stolen Instance Credentials, EC2 User Data | AWS |
| Unsecured Credentials: Cloud | T1552.004 | Secrets/Parameter Retrieval | AWS |
| Unsecured Credentials: K8s | T1552.007 | EKS Secret Access | EKS |
| Brute Force | T1110 | Console Login Failure, Cognito Auth Failure | AWS |
| Adversary-in-the-Middle | T1557 | VPC Traffic Mirroring | AWS |
| Network Sniffing | T1040 | VPC Traffic Mirroring | AWS |

### Discovery (TA0007)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Cloud Infra Discovery | T1580 | API Permission Enum, Resource Enum, GCP Compute Enum | AWS, GCP |
| Cloud Service Discovery | T1526 | API Permission Enum, GCP Compute Enum | AWS, GCP |
| Account Discovery | T1087 | Account/Resource Enumeration | AWS |
| Network Scanning | T1046 | Port Scan Detection | AWS |

### Execution (TA0002)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Command/Script Interpreter | T1059 | SSM Command Execution, Lambda Layer | AWS |
| Exec into Container | T1609 | EKS kubectl exec | EKS |
| Serverless Execution | T1648 | Lambda Invocation Spike | AWS |

### Collection (TA0009)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Data from Cloud Storage | T1530 | S3 Data Collection, GCP Bucket Public | AWS, GCP |
| Data Staged | T1537 | S3 Replication, GCP Bucket Public | AWS, GCP |

### Exfiltration (TA0010)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Exfil Over Web Service | T1041 | Large Outbound Transfer | AWS |
| Exfil Over Alternative Protocol | T1048 | Large Outbound, DNS Tunneling | AWS |

### Impact (TA0040)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Data Destruction | T1485 | Cloud Data Destruction | AWS |
| Data Encrypted for Impact | T1486 | KMS Key Policy Tampering | AWS |
| Inhibit System Recovery | T1490 | KMS Key Policy Tampering | AWS |
| Endpoint DoS | T1499 | Lambda Execution Failure | AWS |

### Command and Control (TA0011)
| Technique | ID | Rules | Platform |
|-----------|-----|-------|----------|
| Application Layer: DNS | T1071.004 | DNS Tunneling, NXDOMAIN Spike | AWS |
| Dynamic Resolution | T1568.002 | NXDOMAIN Spike | AWS |

## Coverage Summary

| Tactic | Techniques Covered | Rules |
|--------|-------------------|-------|
| Initial Access | 4 | 9 |
| Persistence | 8 | 14 |
| Privilege Escalation | 3 | 5 |
| Defense Evasion | 4 | 7 |
| Credential Access | 6 | 8 |
| Discovery | 4 | 5 |
| Execution | 3 | 4 |
| Collection | 2 | 3 |
| Exfiltration | 2 | 3 |
| Impact | 4 | 4 |
| Command and Control | 2 | 3 |
| **Total** | **42 tactics** | **53 rules** |

## Platform Distribution

| Platform | Rules | Severity Breakdown |
|----------|-------|--------------------|
| AWS | 40 | 12 critical, 17 high, 9 medium, 2 low |
| EKS | 8 | 2 critical, 4 high, 2 medium |
| GCP | 5 | 2 critical, 2 high, 1 medium |

## Notable Gaps (opportunities for new rules)

| Gap | MITRE Technique | Why It Matters |
|-----|----------------|----------------|
| **Lateral Movement** | T1550 (Pass the Hash/Token) | No rules for session token replay or cross-service lateral movement |
| **Resource Hijacking** | T1496 (Cryptomining) | Common post-compromise activity, especially in K8s |
| **Log Injection** | T1565.001 (Data Manipulation) | Attacker writes fake logs to mislead investigation |
| **Cloud API abuse** | T1106 | Automated tooling (Pacu, ScoutSuite) fingerprinting |
| **Container image scanning** | - | No runtime image integrity checks |
| **Terraform/IaC tampering** | T1584.006 | Infrastructure-as-code pipeline compromise |

## Interview Talking Point

"We have 53 rules covering 42 MITRE techniques across 11 tactics. The heaviest coverage is in Persistence and Credential Access because that's where most cloud attacks concentrate — the attacker's goal is to establish durable access. Our gaps are in Lateral Movement and Resource Hijacking, which I'd prioritize next. The platform split is 40 AWS, 8 EKS, 5 GCP — the K8s rules are new and specifically target the MITRE Container Matrix, which has different technique IDs than the Enterprise matrix."

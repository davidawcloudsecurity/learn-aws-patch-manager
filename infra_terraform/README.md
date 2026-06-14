# AWS Patch Manager + ASG + Managed AD (Windows)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  VPC (172.16.0.0/16)                                            │
│                                                                 │
│  ┌─────────────────────┐    ┌─────────────────────┐            │
│  │ Public Subnet AZ-a  │    │ Public Subnet AZ-b  │            │
│  │   NAT Gateway       │    │                     │            │
│  └─────────────────────┘    └─────────────────────┘            │
│                                                                 │
│  ┌─────────────────────┐    ┌─────────────────────┐            │
│  │ Private Subnet AZ-a │    │ Private Subnet AZ-b │            │
│  │                     │    │                     │            │
│  │  ┌───────────────┐  │    │  ┌───────────────┐  │            │
│  │  │ Managed AD DC │  │    │  │ Managed AD DC │  │            │
│  │  └───────────────┘  │    │  └───────────────┘  │            │
│  │                     │    │                     │            │
│  │  ┌───────────────┐  │    │  ┌───────────────┐  │            │
│  │  │ Win ASG Inst. │  │    │  │ Win ASG Inst. │  │            │
│  │  │ (AD-Joined)   │  │    │  │ (AD-Joined)   │  │            │
│  │  └───────────────┘  │    │  └───────────────┘  │            │
│  └─────────────────────┘    └─────────────────────┘            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

SSM Patch Manager ──► Maintenance Window ──► AWS-RunPatchBaseline
                          (Sunday 2AM UTC)
                               │
                               ▼
                    Targets: tag:PatchGroup = "Windows-Production"
```

## How It Works

1. **AWS Managed Microsoft AD** is deployed across 2 AZs in private subnets
2. **DHCP Options** point VPC DNS to the AD domain controllers
3. **Launch Template** tags instances with `ADJoin=true`
4. **SSM Association** watches for `ADJoin=true` tag and runs `aws:domainJoin`
5. **ASG** launches Windows instances in private subnets → they auto-join AD
6. **Patch Manager** runs `AWS-RunPatchBaseline` every Sunday at 2 AM via maintenance window

## Prerequisites

- Terraform >= 1.0
- AWS CLI configured with appropriate permissions
- Permissions needed:
  - `ds:*` (Directory Service)
  - `ec2:*` (VPC, ASG, Launch Templates)
  - `ssm:*` (Systems Manager)
  - `iam:*` (Roles, Profiles)

## Usage

```bash
# Set the AD admin password (never commit this)
export TF_VAR_ad_admin_password='YourStr0ngP@ssword!'

# Initialize and apply
terraform init
terraform plan
terraform apply
```

## Important Notes

- **Managed AD takes ~30 minutes to provision**
- AD admin password must be set via environment variable or a secrets file
- Instances are in private subnets — use SSM Session Manager for access (no RDP over internet)
- NAT Gateway provides outbound internet for patching
- The patch baseline auto-approves Critical/Security updates after 7 days

## Cost Considerations

| Resource | Approximate Cost |
|----------|-----------------|
| Managed AD (Standard) | ~$72/month |
| NAT Gateway | ~$32/month + data |
| t3.medium (per instance) | ~$30/month |
| SSM Patch Manager | Free |

## Patching Strategy

This uses **mutable in-place patching** — instances are patched while running.
For immutable patching (golden AMI refresh), you would:
1. Patch a source AMI using SSM Automation
2. Update the Launch Template AMI ID
3. Trigger an ASG instance refresh

## Session Notes — What We Learned

### Sysprep and ASG

- Every instance launched from an AMI in an ASG gets a **unique hostname** via Sysprep (e.g., `EC2AMAZ-ABC`, `EC2AMAZ-XYZ`)
- This is critical for AD join — without Sysprep, all instances would have the same SID, causing AD conflicts
- The unique hostname proves a fresh machine was created from the AMI

### Sticky Sessions vs Instance Refresh

**The problem:**
- ALB sticky sessions keep a user on the same instance (via cookie)
- When ASG Instance Refresh terminates that instance, the sticky cookie points to a dead target
- ALB routes user to a different instance → **session is lost**

**Demo flow:**
1. User logs in on `EC2AMAZ-ABC`, session stored in IIS memory (InProc)
2. Session counter increments on each refresh (proves stickiness works)
3. Trigger `aws autoscaling start-instance-refresh`
4. ASG launches new instance, terminates the original
5. User refreshes → lands on `EC2AMAZ-XYZ` → session gone, back to login

**Key insight:** Sticky sessions only work while the server is alive. They do NOT survive instance replacement.

### Solutions for Session Persistence

| Approach | How | Best For |
|----------|-----|----------|
| Redis/ElastiCache | `<sessionState mode="Custom" customProvider="Redis">` | Most web apps |
| SQL Server | `<sessionState mode="SQLServer">` | .NET shops with RDS |
| DynamoDB | Custom session provider | Serverless-friendly |
| JWT/Cookie auth | Stateless tokens, no server session | Modern APIs, SPAs |

### Post-Redirect-Get (PRG) Pattern

- After a form POST (login), always redirect with HTTP 302 to avoid "Resubmit form?" on refresh
- This is a **code-level** issue, not infrastructure
- Pattern: `POST /login` → process → `302 GET /` → render page

### IIS Commands Reference

```powershell
# Restart IIS
iisreset

# Remote restart via SSM
aws ssm send-command \
  --document-name "AWS-RunPowerShellScript" \
  --targets "Key=tag:PatchGroup,Values=Windows-Production" \
  --parameters '{"commands":["iisreset"]}'

# Trigger instance refresh
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name learn-patch-asg-ad-windows-asg \
  --preferences '{"MinHealthyPercentage":50}'
```

### ALB Health Check

- Path: `/` (serves `default.aspx` as IIS default document)
- Matcher: `200-399`
- No separate health check endpoint needed

### AD Domain Join Flow

```
Instance Launch → Tag: ADJoin=true
       ↓
SSM Association detects tag
       ↓
SSM Document runs aws:domainJoin
       ↓
Instance joins corp.learn-patch.local
       ↓
Sysprep hostname (EC2AMAZ-XXX) becomes computer name in AD
```

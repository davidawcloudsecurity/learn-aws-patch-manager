# How to check for AD join
```
# Check AD Domain Join Status

$computerSystem = Get-WmiObject -Class Win32_ComputerSystem

Write-Host "Computer Name : $($computerSystem.Name)"
Write-Host "Domain        : $($computerSystem.Domain)"
Write-Host "Part of Domain: $($computerSystem.PartOfDomain)"

if ($computerSystem.PartOfDomain) {
    Write-Host "`nThis machine IS joined to Active Directory domain: $($computerSystem.Domain)" -ForegroundColor Green

    # Additional AD details
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        Write-Host "Domain Controller: $($domain.PdcRoleOwner.Name)"
        Write-Host "Forest           : $($domain.Forest.Name)"
    } catch {
        Write-Host "Could not retrieve additional domain details: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "`nThis machine is NOT joined to Active Directory. It is in a workgroup: $($computerSystem.Domain)" -ForegroundColor Red
}
```

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

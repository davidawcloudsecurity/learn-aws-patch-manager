# Here's how to set up IIS on Windows Server 2019 via PowerShell (run as Administrator):
```
Here's how to set up IIS on Windows Server 2019 via PowerShell (run as Administrator):

**Step 1: Install IIS**

```powershell
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
```

This installs IIS with the management console. IIS starts automatically after install.

**Step 2: Verify it's running**

```powershell
Get-Service W3SVC
```

Should show `Running`. Then browse to `http://localhost` — you'll see the default IIS welcome page.

**Step 3: Deploy your site**

The default web root is:
```
C:\inetpub\wwwroot\
```

Drop your HTML/files there, or create a new site:

```powershell
# Create a folder for your site
New-Item -Path "C:\inetpub\mysite" -ItemType Directory

# Add a test page
Set-Content -Path "C:\inetpub\mysite\index.html" -Value "<h1>Hello from IIS</h1>"

# Create a new IIS site
Import-Module WebAdministration
New-IISSite -Name "MySite" -PhysicalPath "C:\inetpub\mysite" -BindingInformation "*:8080:"
```

This creates a site listening on port 8080.

**Step 4: Open the firewall**

```powershell
New-NetFirewallRule -DisplayName "Allow HTTP 80" -Direction Inbound -Port 80 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTP 8080" -Direction Inbound -Port 8080 -Protocol TCP -Action Allow
```

---

**Optional: Install ASP.NET support** (if hosting .NET apps like your TodoApp)

```powershell
Install-WindowsFeature -Name Web-Asp-Net45, Web-Net-Ext45, NET-Framework-45-ASPNET
```

For .NET Core / .NET 6+ apps, install the hosting bundle instead:
```powershell
# Download and install .NET Hosting Bundle
Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile "$env:TEMP\dotnet-install.ps1"
```
Or download the ASP.NET Core Hosting Bundle from https://dotnet.microsoft.com/download/dotnet

---

**Useful IIS commands:**

```powershell
# List all sites
Get-IISSite

# Stop/Start a site
Stop-IISSite -Name "MySite"
Start-IISSite -Name "MySite"

# Restart IIS entirely
iisreset
```

Since your ALB health check hits `/` on port 80, the default IIS site will respond with a 200 out of the box — so your ALB target group health checks will pass immediately after IIS is installed.

# Check AD Domain Join Status
```
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

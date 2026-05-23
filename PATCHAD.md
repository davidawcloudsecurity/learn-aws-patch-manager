# How to Join EC2 to AD
### Manual Join via PowerShell
```
Add-Computer -DomainName "corp.example.com" -OUPath "OU=Computers,OU=corp,DC=corp,DC=example,DC=com" -Credential (Get-Credential) -Restart
```
### SSM Run Command (no RDP needed)
```
# Use AWS-JoinDirectoryServiceDomain document
aws ssm send-command \
  --instance-ids "i-xxxxxxxxx" \
  --document-name "AWS-JoinDirectoryServiceDomain" \
  --parameters '{"directoryId":["d-xxxxxxxxxx"],"directoryName":["corp.example.com"],"dnsIpAddresses":["[IP_ADDRESS]","[IP_ADDRESS]"]}' \
  --output text
```
# Check Existing Domain
### Fastest
```
dsregcmd /status | findstr "DomainName"
nltest /dsgetdc:corp
```
### Get Domain Name
```
(Get-WmiObject Win32_ComputerSystem).Domain
```
### Get Current OU Path
```
(Get-ADComputer $env:COMPUTERNAME -Properties DistinguishedName).DistinguishedName
```
### Or without AD module:
```
gpresult /r | findstr "CN="
```
# How to use Sysprep
### Create an AMI using Windows Sysprep (main page)
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ami-create-win-sysprep.html
### Sysprep with EC2Launch v2 (Windows 2019/2022/2025)
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sysprep-using-ec2launchv2.html
### Sysprep with EC2Launch v1 (Windows 2016/2019)
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2launch-sysprep.html
### Troubleshoot Sysprep issues
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sysprep-troubleshoot.html
### Use EC2Launch v2 (recommended) — Sysprep files at:
C:\ProgramData\Amazon\EC2Launch\sysprep
### EC2Launch v1 — Sysprep files at:
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep
### Knowledge Center: Use Sysprep for custom AMIs
### Then click "Shutdown with Sysprep".
```
Flow
BeforeSysprep.cmd → Sysprep runs (uses Unattend.xml) → Shuts down
                                                          ↓
                                                    Create AMI
                                                          ↓
                                              New instance boots
                                                          ↓
                                    SysprepSpecialize.cmd runs
                                                          ↓
                              Randomize-LocalAdminPassword.ps1 runs
```
### Step one 
```
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\BeforeSysprep.cmd

C:\Windows\system32>reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnect
ions /t REG_DWORD /d 1 /f
The operation completed successfully.
```
### Step two
```
& "C:\ProgramData\Amazon\EC2-Windows\Launch\Scripts\InitializeInstance.ps1" -Schedule

TaskPath                                       TaskName                          State
--------                                       --------                          -----
\                                              Amazon Ec2 Launch - Instance I... Ready
```
### Step three. Shutdown
```
& "C:\ProgramData\Amazon\EC2-Windows\Launch\Scripts\SysprepInstance.ps1"

C:\Windows\system32>reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnect
ions /t REG_DWORD /d 1 /f
The operation completed successfully.
```
### Alternative. Not tested
```
C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:"C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml"
```
https://repost.aws/knowledge-center/sysprep-create-install-ec2-windows-amis

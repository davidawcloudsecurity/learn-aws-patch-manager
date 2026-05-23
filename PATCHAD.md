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
### Knowledge Center: Use Sysprep for custom AMIs
https://repost.aws/knowledge-center/sysprep-create-install-ec2-windows-amis

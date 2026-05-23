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

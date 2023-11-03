```bash
rustscan -a $IP
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/alvin/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.47.158:53
Open 10.129.47.158:80
Open 10.129.47.158:88
Open 10.129.47.158:135
Open 10.129.47.158:139
Open 10.129.47.158:389
Open 10.129.47.158:445
Open 10.129.47.158:464
Open 10.129.47.158:593
Open 10.129.47.158:636
Open 10.129.47.158:3268
Open 10.129.47.158:3269
Open 10.129.47.158:5985
Open 10.129.47.158:9389
Open 10.129.47.158:49664
Open 10.129.47.158:49668
Open 10.129.47.158:49674
Open 10.129.47.158:53876
Open 10.129.47.158:65133
Open 10.129.47.158:65142
[~] Starting Script(s)
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-03 12:41 NZDT
Initiating Ping Scan at 12:41
Scanning 10.129.47.158 [2 ports]
Completed Ping Scan at 12:41, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:41
Completed Parallel DNS resolution of 1 host. at 12:41, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:41
Scanning 10.129.47.158 [20 ports]
Discovered open port 445/tcp on 10.129.47.158
Discovered open port 139/tcp on 10.129.47.158
Discovered open port 135/tcp on 10.129.47.158
Discovered open port 53/tcp on 10.129.47.158
Discovered open port 80/tcp on 10.129.47.158
Discovered open port 49664/tcp on 10.129.47.158
Discovered open port 49674/tcp on 10.129.47.158
Discovered open port 464/tcp on 10.129.47.158
Discovered open port 65133/tcp on 10.129.47.158
Discovered open port 9389/tcp on 10.129.47.158
Discovered open port 593/tcp on 10.129.47.158
Discovered open port 65142/tcp on 10.129.47.158
Discovered open port 3268/tcp on 10.129.47.158
Discovered open port 49668/tcp on 10.129.47.158
Discovered open port 636/tcp on 10.129.47.158
Discovered open port 3269/tcp on 10.129.47.158
Discovered open port 88/tcp on 10.129.47.158
Discovered open port 5985/tcp on 10.129.47.158
Discovered open port 53876/tcp on 10.129.47.158
Discovered open port 389/tcp on 10.129.47.158
Completed Connect Scan at 12:41, 0.72s elapsed (20 total ports)
Nmap scan report for 10.129.47.158
Host is up, received syn-ack (0.38s latency).
Scanned at 2023-11-03 12:41:25 NZDT for 1s

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
49664/tcp open  unknown          syn-ack
49668/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
53876/tcp open  unknown          syn-ack
65133/tcp open  unknown          syn-ack
65142/tcp open  unknown          syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.92 seconds
```
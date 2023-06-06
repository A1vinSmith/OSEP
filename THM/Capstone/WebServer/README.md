[applications@corp.thereserve.loc](mailto:applications@corp.thereserve.loc)

From contact us page. It looks like the domain of the MailServer

# Create userlist
ChatGPT read the meet team page to get the raw list
```bash
sed 's/$/@corp.thereserve.loc/' usernames.txt > usernames-domain.txt
```
# Create password list
```bash
cat Capstone_Challenge_Resources/password_base_list.txt
TheReserve
thereserve
Reserve
reserve
CorpTheReserve
corpthereserve
Password
password
TheReserveBank
thereservebank
ReserveBank
reservebank
❯ cat Capstone_Challenge_Resources/password_policy.txt
The password policy for TheReserve is the following:

* At least 8 characters long
* At least 1 number
* At least 1 special character
```
It seems 10 chars minium with one number and one special char
```bash
crunch 10 10 -t Password%^ | grep -E ".*[\!@#$%^].*" > passwords.txt
```

# Bruteforce Mail Server
-> To Mail Server


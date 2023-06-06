# Register e-citizen
To register, you need to get in touch with the government through its e-Citizen communication portal that uses SSH for communication. Here are the SSH details provided:

**SSH Username**  

e-citizen  

**SSH Password**  

stabilitythroughcurrency  

**SSH IP**  

X.X.X.250  

Once you Start the network diagram at the start of the room will show the IP specific to your network. Use that information to replace the X values in your SSH IP. `10.200.X.250`

```bash
export E_citizen_SSH_IP=10.200.52.250
ssh e-citizen@$E_citizen_SSH_IP

Welcome to the e-Citizen platform!
Please make a selection:
[1] Register
[2] Authenticate
[3] Exit
Selection:1
Please provide your THM username: AlvinSmith
Creating email user
User has been succesfully created


=======================================
Thank you for registering on e-Citizen for the Red Team engagement against TheReserve.
Please take note of the following details and please make sure to save them, as they will not be displayed again.
=======================================
Username: AlvinSmith
Password: pg-j8eBONSI8uQmO
MailAddr: AlvinSmith@corp.th3reserve.loc
IP Range: 10.200.52.0/24
=======================================

These details are now active. As you can see, we have already purchased a domain for domain squatting to be used for phishing.
Once you discover the webmail server, you can use these details to authenticate and recover additional project information from your mailbox.
Once you have performed actions to compromise the network, please authenticate to e-Citizen in order to provide an update to the government. If your update is sufficient, you will be awarded a flag to indicate progress.
```

# Web Server (`10.200.52.13`) Linux
Let's start with the **external** server -> WebServer 

However, the SWIFT backend exposes an **internal** web application at [http://swift.bank.thereserve.loc/](http://swift.bank.thereserve.loc/) which TheReserve uses to facilitate transfers. The government has provided a general process for transfers. To transfer funds:  

1.  A customer makes a request that funds should be transferred and receives a transfer code.
2.  The customer contacts the bank and provides this transfer code.  
3.  An employee with the capturer role authenticates to the SWIFT application and _captures_ the transfer.
4.  An employee with the approver role reviews the transfer details and, if verified, _approves_ the transfer. This has to be performed from a jump host.  
5.  Once approval for the transfer is received by the SWIFT network, the transfer is facilitated and the customer is notified.

# VPN (`10.200.52.12`) Linux
As the name mentioned, it'll be used as our pivoting machine.

# Mail Server (`10.200.52.11`) Windows
WebMail Win server. SMTP open. 

# Others
### Host
```config
10.200.113.12 swift.bank.thereserve.loc
10.200.113.11 corp.th3reserve.loc
10.200.113.102 corp.thereserve.loc
```

### Helpful snippets
```bash
echo "0112564d-3487-4207-b2c7-1193425e98b7" | Set-Content C:\Windows\Temp\AlvinSmith.txt

echo "26d940c1-5be1-45f5-b43e-10a1f12bc23b" | Set-Content C:\Users\Administrator\AlvinSmith.txt

mv C:\Windows\Temp\AlvinSmith.txt \\ROOTDC.thereserve.loc\c$\Windows\Temp\AlvinSmith.txt

Invoke-Command -Session $session -ScriptBlock {echo "8020790e-920a-42ca-8205-956041a7b4d5" | Set-Content C:\Users\Administrator\AlvinSmith.txt}
```
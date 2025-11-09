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

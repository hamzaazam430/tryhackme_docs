
# Answer the questions below

Q: What is key 1?
A:

Q: What is key 2?
A:

Q: What is key 3?
A:

---
# WORKING


## NMAP SCAN


```
└──╼ $sudo nmap -O --osscan-guess -sV -p- 10.10.103.203 


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
Scanning 2 services on 10.10.103.203
Completed Service scan at 16:50, 14.82s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.103.203
Retrying OS detection (try #2) against 10.10.103.203
NSE: Script scanning 10.10.103.203.
Initiating NSE at 16:50
Completed NSE at 16:50, 4.31s elapsed
Initiating NSE at 16:50
Completed NSE at 16:50, 3.94s elapsed
Nmap scan report for 10.10.103.203
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




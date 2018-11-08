# Registry

## System

* Get Os Version: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentVersion
* Get Os Name: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName
* Get Service pack: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Windows\\CSDVersion 

## Update

* Get last computer successfull update
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Detect\\LastSuccessTime
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Detect\\LastSuccessTime
  
* Get WSUS server: HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer
* Get Auto Update status: HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\NoAutoUpdate
* Get usage of WSUS server: HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\UseWUServer

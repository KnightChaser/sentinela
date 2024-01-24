# sentinela
> Under development

## (TIP) Install Sysmon
- Go to official Sysinternals webpage and download Sysmon<br>
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Prepare your own `config.xml` for Sysmon or use recommended Sysmon modular configuration file
```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -OutFile C:\Windows\config.xml
```
- Start Sysmon with the prepared configuration file.
```powershell
./Sysmon64.exe –accepteula –i C:\Windows\config.xml   # 64 bits
./Sysmon.exe -accepteula -i C:\Windows\config.xml     # 32 bits
```
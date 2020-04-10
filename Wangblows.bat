@echo off
title CCDC meets Cyber Patriot
echo Checking if script contains Administrative rights...
net sessions
if %errorlevel%==0 (
echo Success!
) else (
echo Please run as Administrator.
pause
exit
)

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v "PowerShellVersion" /z >nul
If %ERRORLEVEL% == 1 (
	echo POWERSHELL NOT INSTALLED, please install before continuing
	pause>nul
	exit
)

:@@@INTITIAL SERVICE CONFIG@@@
start cmd.exe /c sc query >> C:\Services_Original.txt
if %errorlevel%==1 ( echo Failed to write Original Services >> C:\Users\Administrator\Artemis.txt
) else (
echo Outputted Original Service Configs.
)

:@@@FIREWALL BACKUP@@@
netsh advfirewall export "C:\Users\Administrator\Original_Firewall_Policy.wfw"
if %errorlevel%==1 echo "Failed to export firewall policy" >> C:\Users\Administrator\Artemis.txt

:@@@REGISTRY BACKUP@@@
@echo off
setlocal
for %%k in (lm cu cr u cc) do call :ExpReg %%k
goto :eof
:ExpReg
cd C:\Users\Administrator\Artemis.txt
reg.exe export hk%1 hk%1.reg > nul
if "%errorlevel%"=="1" (
  echo ^>^> Export --hk%1-- Failed.
) else (
  echo ^>^> Export --hk%1-- Success.
)
goto :eof
endlocal

:: Set stickykeys to CMD
takeown /f "%systemroot%\System32\sethc.exe"
takeown /f "%systemroot%\System32\cmd.exe"
icacls "%systemroot%\System32\sethc.exe" /grant %username%:f
icacls "%systemroot%\System32\cmd.exe" /grant %username%:f
ren "%systemroot%\System32\sethc.exe" "%systemroot%\System32\sethc1.exe"
copy "%systemroot%\System32\cmd.exe" "%systemroot%\System32\sethc.exe"

:@@@CURRENTLY RUNNING SERVICES@@@
start cmd.exe /c net start >> C:\Services_Started.txt
if %errorlevel%==1 echo Running services failed to write >> C:\Users\Administrator\Artemis.txt


::test michael is bi bi bii
:MENU
echo Choose An option:
echo 1. A bunch of automated things I guess
echo 2. List Processes
echo 3. Changing Password Policies
echo 4. Find Files
echo 5. Disable Remote Desktop
echo 6. Enable Auto-Update
echo 7. Disable Weak Services
echo 8. System Integrity Scan
echo 9. Powershell rootkit detection
echo 10. Full Auditing for Failure and Success
echo 11. Full Audit for Failure Only
echo 12. Full Audit for Success Only
echo 13. Secure NT Rights
echo 14. Automatic Password Change
echo 15. User Group Management
echo 16. User Enable or Disable
echo 17. Enable User Account Control
echo 18. Enable Windows Firewall
echo 19. Remove Packages and Update Packages (Needs work)
echo 20. Update Windows AppStore Apps (Needs work)
echo 21. SysInternals Autoruns and Process Explorer with VT Upload
echo 22. Clear Hosts File
echo 23. Enable Data Execution Prevention
echo 24. Run Security Programs
echo 25. Uninstall programs + features appwiz.cpl
echo 26. Set up Backup
echo 27. Other application settings
echo 28. Firefox security settings
echo 29. Check for prohibited/sketchy files Remove .zip, .exe, .msi
echo 30. Update all programs adlice program updater
echo 31. NoVirusThanks Sys Hardener
echo 32. Install Antivirus
echo 33. Harden Networking



set /p mo="Enter your choice: "
IF %mo%==33 goto Thirtythree
IF %mo%==32 goto Thirtytwo
IF %mo%==31 goto Thirtyone
IF %mo%==30 goto Thirty
IF %mo%==29 goto Twentynine
IF %mo%==28 goto Twentyeight
IF %mo%==27 goto Twentyseven
IF %mo%==26 goto Twentysix
IF %mo%==25 goto Twentyfive
IF %mo%==24 goto Twentyfour
IF %mo%==23 goto Twentythree
IF %mo%==22 goto Twentytwo
IF %mo%==21 goto Twentyone
IF %mo%==20 goto Twenty
IF %mo%==19 goto Nineteen
IF %mo%==18 goto Eighteen
IF %mo%==17 goto Seventeen
IF %mo%==15 goto Fifteen
IF %mo%==16 goto Sixteen
IF %mo%==14 goto Fourteen
IF %mo%==13 goto Thirteen
IF %mo%==12 goto Twelve
IF %mo%==11 goto Eleven
IF %mo%==10 goto Ten
IF %mo%==9 goto Nine
IF %mo%==8 goto Eight
IF %mo%==7 goto Seven
IF %mo%==6 goto Six
IF %mo%==5 goto Five
IF %mo%==4 goto Four
IF %mo%==3 goto Three
IF %mo%==2 goto Two
IF %mo%==1 goto One

:One
REM Automation found from all over the inter
REM Screensaver!
Reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f
Reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 1200 /f
Reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 1 /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers:AddPrinterDrivers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v Enable /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RunAsPPL" /v RunAsPPL /t REG_DWORD /d 1 /f

reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f

reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /t
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d /1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f 
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Remote Assistance" /v CreateEncryptedOnlyTickets /t REG_DWORD /d 1 /f


goto MENU

:Two
REM Listing possible penetrations
cd C:\
echo "STARTING TO OUTPUT PROCESS FILES DIRECTLY TO THE C:\ DRIVE!"
wmic process list brief > BriefProcesses.txt
if %errorlevel%==1 echo Brief Processes failed to write
wmic process list full >FullProcesses.txt
if %errorlevel%==1 echo Full Processes failed to write
wmic startup list full > StartupLists.txt
if %errorlevel%==1 echo Startup Processes failed to write
net start > StartedProcesses.txt
if %errorlevel%==1 echo Started processes failed to write
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run  Run.reg
if %errorlevel%==1 echo Run processes failed to write
goto MENU
:Three
echo "OUTPUT DONE, CHANGING PASSWORD POLICIES!"
REM Passwords must be 10 digits
net accounts /minpwlen:10
REM Passwords must be changed every 30 days
net accounts /maxpwage:30
REM Passwords can only be changed after 5 day has passed
net accounts /minpwage:5
REM Display current password policy
echo "CURRENT POLICY"
PAUSE
net accounts
goto MENU
:Four
REM Find file
@echo off
color 0f
cls
echo Flashing Disk to .flashed Files to reference....
dir /b /s "C:\Program Files\" > programfiles.flashed
dir /b /s "C:\Program Files (x86)\" >> programfiles.flashed
echo Program Files flashed
dir /b /s "C:\Users\" > users.flashed
dir /b /s "C:\Documents and Settings" >> users.flashed
echo User profiles flashed
dir /b /s "C:\" > c.flashed
echo C:\ Flashed
pause
echo Finding media files in C:\Users and/or C:\Documents and Settings...
findstr .mp3 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp3 > media_audio
findstr .ac3 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.ac3 >> media_audio
findstr .aac users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aac >> media_audio
findstr .aiff users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aiff >> media_audio
findstr .aif users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aif >> media_audio
findstr .flac users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.flac >> media_audio
findstr .m4a users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4a >> media_audio
findstr .m4p users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4p >> media_audio
findstr .midi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.midi >> media_audio
findstr .mp2 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp2 >> media_audio
findstr .m3u users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m3u >> media_audio
findstr .ogg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.ogg >> media_audio
findstr .vqf users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.vqf >> media_audio
findstr .wav users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wav >> media_audio
findstr .wma users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wma >> media_video
findstr .mp4 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp4 >> media_video
findstr .avi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.avi >> media_video
findstr .wmv  users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wmv >> media_video
findstr .vob users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.vob >> media_video
findstr .swf users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.swf >> media_video
findstr .srt users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.srt >> media_video
findstr .rm users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.rm >> media_video
findstr .mov users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mov >> media_video
findstr .mpg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mpg >> media_video
findstr .m4v users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4v >> media_video
findstr .flv users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.flv >> media_video
findstr .avi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.avi >> media_video
findstr .asx users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.asx >> media_video
findstr .asf users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.asf >> media_video
findstr .3gp users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.3gp >> media_video
findstr .3g2 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.3g2 >> media_video
REM BREAKLINE
findstr .gif users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.gif >> media_pics
findstr .png users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.png >> media_pics
findstr .bmp users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.bmp >> media_pics
findstr .jpg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .jpg >> media_pics
findstr .jpeg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .jpeg >> media_pics
C:\WINDOWS\system32\notepad.exe media_video
C:\WINDOWS\system32\notepad.exe media_audio
C:\WINDOWS\system32\notepad.exe media_pics
echo Finding Hacktools now...
findstr "Cain" c.flashed
if %errorlevel%==0 (
echo Cain detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "nmap" c.flashed
if %errorlevel%==0 (
echo Nmap detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "keylogger" c.flashed
if %errorlevel%==0 (
echo Potential keylogger detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Armitage" c.flashed
if %errorlevel%==0 (
echo Potential Armitage detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Metasploit" c.flashed
if %errorlevel%==0 (
echo Potential Metasploit framework detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Wireshark" c.flashed
if %errorlevel%==0 (
echo Potential Wireshark detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "netcat" c.flashed
if %errorlevel%==0 (
echo Potential netcat detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "orphcrack" c.flashed
if %errorlevel%==0 (
echo Potential orphcrack detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "passwords" c.flashed
if %errorlevel%==0 (
echo Potential passwords detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "lsass" c.flashed
if %errorlevel%==0 (
echo Potential lsass detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "r57" c.flashed
if %errorlevel%==0 (
echo Potential r57 detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "weevely" c.flashed
if %errorlevel%==0 (
echo Potential weevely detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "c99" c.flashed
if %errorlevel%==0 (
echo Potential c99 detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "b374k" c.flashed
if %errorlevel%==0 (
echo Potential password detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "caidao" c.flashed
if %errorlevel%==0 (
echo Potential password detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "php99eb" c.flashed
if %errorlevel%==0 (
echo Potential password detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "php9cba" c.flashed
if %errorlevel%==0 (
echo Potential password detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "README" c.flashed
if %errorlevel%==0 (
echo Potential README detected. Please take note, then press any key.
pause >NUL
)
cls
goto MENU

:Five
set /p rdpChk="Enable remote desktop (y/n)"
if %rdpChk%==y (
	echo Enabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=yes
	echo Please select "Allow connections only from computers running Remote Desktop with Network Level Authentication (more secure)"
	net stop UmRdpService
	net stop TermService
	net start UmRdpService
	net start TermService
	start SystemPropertiesRemote.exe /wait
	echo Enabled remote desktop
	goto MENU
)
if %rdpChk%==n (
	echo Disabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=no
	net stop UmRdpService
	net stop TermService
	start SystemPropertiesRemote.exe /wait
	echo Disabled remote desktop
	goto MENU
)
echo Invalid input %rdpChk%
goto :Five




:Six
REM Windows auomatic updates
echo "ENABLING AUTO-UPDATES"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 5 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
goto MENU

:Seven
REM Removing good ol' insecure stuff but not me. I may be insecure, but I am important. Or am I? I don't even know anymore
echo "DISABLING WEAK SERVICES"
dism /online /quiet /disable-feature /featurename:Printing-PrintToPDFServices-Features
dism /online /quiet /disable-feature /featurename:Printing-XPSServices-Features
dism /online /quiet /disable-feature /featurename:SearchEngine-Client-Package
dism /online /quiet /disable-feature /featurename:MSRDC-Infrastructure
dism /online /quiet /disable-feature /featurename:TIFFIFilter
dism /online /quiet /disable-feature /featurename:LegacyComponents
dism /online /quiet /disable-feature /featurename:DirectPlay
dism /online /quiet /disable-feature /featurename:SimpleTCP
dism /online /quiet /disable-feature /featurename:NetFx4Extended-ASPNET45
dism /online /quiet /disable-feature /featurename:WCF-Services45
dism /online /quiet /disable-feature /featurename:WCF-HTTP-Activation45
dism /online /quiet /disable-feature /featurename:WCF-TCP-Activation45
dism /online /quiet /disable-feature /featurename:WCF-Pipe-Activation45
dism /online /quiet /disable-feature /featurename:WCF-MSMQ-Activation45
dism /online /quiet /disable-feature /featurename:WCF-TCP-PortSharing45
dism /online /quiet /disable-feature /featurename:WAS-WindowsActivationService
dism /online /quiet /disable-feature /featurename:WAS-ProcessModel
dism /online /quiet /disable-feature /featurename:WAS-NetFxEnvironment
dism /online /quiet /disable-feature /featurename:WAS-ConfigurationAPI
dism /online /quiet /disable-feature /featurename:WCF-HTTP-Activation
dism /online /quiet /disable-feature /featurename:WCF-NonHTTP-Activation
dism /online /quiet /disable-feature /featurename:MSMQ-Container
dism /online /quiet /disable-feature /featurename:MSMQ-DCOMProxy
dism /online /quiet /disable-feature /featurename:MSMQ-Server
dism /online /quiet /disable-feature /featurename:MSMQ-ADIntegration
dism /online /quiet /disable-feature /featurename:MSMQ-HTTP
dism /online /quiet /disable-feature /featurename:MSMQ-Multicast
dism /online /quiet /disable-feature /featurename:MSMQ-Triggers
dism /online /quiet /disable-feature /featurename:IIS-CertProvider
dism /online /quiet /disable-feature /featurename:IIS-WindowsAuthentication
dism /online /quiet /disable-feature /featurename:IIS-DigestAuthentication
dism /online /quiet /disable-feature /featurename:IIS-ClientCertificateMappingAuthentication
dism /online /quiet /disable-feature /featurename:IIS-IISCertificateMappingAuthentication
dism /online /quiet /disable-feature /featurename:IIS-ODBCLogging
dism /online /quiet /disable-feature /featurename:NetFx3
dism /online /quiet /disable-feature /featurename:SMB1Protocol-Deprecation
dism /online /quiet /disable-feature /featurename:MediaPlayback
dism /online /quiet /disable-feature /featurename:WindowsMediaPlayer
dism /online /quiet /disable-feature /featurename:DataCenterBridging
dism /online /quiet /disable-feature /featurename:ServicesForNFS-ClientOnly
dism /online /quiet /disable-feature /featurename:ClientForNFS-Infrastructure
dism /online /quiet /disable-feature /featurename:NFS-Administration
dism /online /quiet /disable-feature /featurename:SmbDirect
dism /online /quiet /disable-feature /featurename:HostGuardian
dism /online /quiet /disable-feature /featurename:MultiPoint-Connector
dism /online /quiet /disable-feature /featurename:MultiPoint-Connector-Services
dism /online /quiet /disable-feature /featurename:MultiPoint-Tools
dism /online /quiet /disable-feature /featurename:Printing-Foundation-Features
dism /online /quiet /disable-feature /featurename:FaxServicesClientPackage
dism /online /quiet /disable-feature /featurename:Printing-Foundation-InternetPrinting-Client
dism /online /quiet /disable-feature /featurename:Printing-Foundation-LPDPrintService
dism /online /quiet /disable-feature /featurename:Printing-Foundation-LPRPortMonitor
dism /online /quiet /disable-feature /featurename:Windows-Identity-Foundation
dism /online /quiet /disable-feature /featurename:AppServerClient
dism /online /quiet /disable-feature /featurename:WorkFolders-Client
dism /online /quiet /disable-feature /featurename:Client-DeviceLockdown
dism /online /quiet /disable-feature /featurename:Client-EmbeddedShellLauncher
dism /online /quiet /disable-feature /featurename:Client-EmbeddedBootExp
dism /online /quiet /disable-feature /featurename:Client-EmbeddedLogon
dism /online /quiet /disable-feature /featurename:Client-KeyboardFilter
dism /online /quiet /disable-feature /featurename:Client-UnifiedWriteFilter
dism /online /quiet /disable-feature /featurename:SMB1Protocol
dism /online /quiet /disable-feature /featurename:SMB1Protocol-Client
dism /online /quiet /disable-feature /featurename:SMB1Protocol-Server
dism /online /quiet /disable-feature /featurename:Microsoft-Windows-Subsystem-Linux
dism /online /quiet /disable-feature /featurename:HypervisorPlatform
dism /online /quiet /disable-feature /featurename:VirtualMachinePlatform
dism /online /quiet /disable-feature /featurename:Client-ProjFS
dism /online /quiet /disable-feature /featurename:Microsoft-Windows-Client-EmbeddedExp-Package
dism /online /quiet /disable-feature /featurename:Containers-DisposableClientVM
dism /online /quiet /disable-feature /featurename:Microsoft-Hyper-V-All
dism /online /quiet /disable-feature /featurename:Microsoft-Hyper-V
dism /online /quiet /disable-feature /featurename:Microsoft-Hyper-V-Tools-All
dism /online /quiet /disable-feature /featurename:Microsoft-Hyper-V-Management-PowerShell
dism /online /quiet /disable-feature /featurename:Microsoft-Hyper-V-Hypervisor
dism /online /quiet /disable-feature /featurename:Microsoft-Hyper-V-Services
dism /online /quiet /disable-feature /featurename:Microsoft-Hyper-V-Management-Clients
dism /online /quiet /disable-feature /featurename:DirectoryServices-ADAM-Client
dism /online /quiet /disable-feature /featurename:Containers
dism /online /quiet /disable-feature /featurename:IIS-WebServerRole
dism /online /quiet /disable-feature /featurename:IIS-WebServer
dism /online /quiet /disable-feature /featurename:IIS-CommonHttpFeatures
dism /online /quiet /disable-feature /featurename:IIS-HttpErrors
dism /online /quiet /disable-feature /featurename:IIS-HttpRedirect
dism /online /quiet /disable-feature /featurename:IIS-ApplicationDevelopment
dism /online /quiet /disable-feature /featurename:IIS-NetFxExtensibility
dism /online /quiet /disable-feature /featurename:IIS-NetFxExtensibility45
dism /online /quiet /disable-feature /featurename:IIS-HealthAndDiagnostics
dism /online /quiet /disable-feature /featurename:IIS-HttpLogging
dism /online /quiet /disable-feature /featurename:IIS-LoggingLibraries
dism /online /quiet /disable-feature /featurename:IIS-RequestMonitor
dism /online /quiet /disable-feature /featurename:IIS-HttpTracing
dism /online /quiet /disable-feature /featurename:IIS-Security
dism /online /quiet /disable-feature /featurename:IIS-URLAuthorization
dism /online /quiet /disable-feature /featurename:IIS-RequestFiltering
dism /online /quiet /disable-feature /featurename:IIS-IPSecurity
dism /online /quiet /disable-feature /featurename:IIS-Performance
dism /online /quiet /disable-feature /featurename:IIS-HttpCompressionDynamic
dism /online /quiet /disable-feature /featurename:IIS-WebServerManagementTools
dism /online /quiet /disable-feature /featurename:IIS-ManagementScriptingTools
dism /online /quiet /disable-feature /featurename:IIS-IIS6ManagementCompatibility
dism /online /quiet /disable-feature /featurename:IIS-Metabase
dism /online /quiet /disable-feature /featurename:IIS-HostableWebCore
dism /online /quiet /disable-feature /featurename:IIS-StaticContent
dism /online /quiet /disable-feature /featurename:IIS-DefaultDocument
dism /online /quiet /disable-feature /featurename:IIS-DirectoryBrowsing
dism /online /quiet /disable-feature /featurename:IIS-WebDAV
dism /online /quiet /disable-feature /featurename:IIS-WebSockets
dism /online /quiet /disable-feature /featurename:IIS-ApplicationInit
dism /online /quiet /disable-feature /featurename:IIS-ASPNET
dism /online /quiet /disable-feature /featurename:IIS-ASPNET45
dism /online /quiet /disable-feature /featurename:IIS-ASP
dism /online /quiet /disable-feature /featurename:IIS-CGI
dism /online /quiet /disable-feature /featurename:IIS-ISAPIExtensions
dism /online /quiet /disable-feature /featurename:IIS-ISAPIFilter
dism /online /quiet /disable-feature /featurename:IIS-ServerSideIncludes
dism /online /quiet /disable-feature /featurename:IIS-CustomLogging
dism /online /quiet /disable-feature /featurename:IIS-BasicAuthentication
dism /online /quiet /disable-feature /featurename:IIS-HttpCompressionStatic
dism /online /quiet /disable-feature /featurename:IIS-ManagementConsole
dism /online /quiet /disable-feature /featurename:IIS-ManagementService
dism /online /quiet /disable-feature /featurename:IIS-WMICompatibility
dism /online /quiet /disable-feature /featurename:IIS-LegacyScripts
dism /online /quiet /disable-feature /featurename:IIS-LegacySnapIn
dism /online /quiet /disable-feature /featurename:IIS-FTPServer
dism /online /quiet /disable-feature /featurename:IIS-FTPSvc
dism /online /quiet /disable-feature /featurename:IIS-FTPExtensibility
dism /online /quiet /disable-feature /featurename:TFTP
dism /online /quiet /disable-feature /featurename:TelnetClient
dism /online /quiet /disable-feature /featurename:TelnetServer


:services
set servicesD=RemoteAccess CDPSvc mnmsrvc XboxGipSvc xbgm xboxgip XblAuthManager RasMan TabletInputService SNMP XblGameSave SNMPTrap HomeGroupListener lmhosts PlugPlay Spooler UevAgentService shpamsvc NetTcpPortSharing TrkWks iphlpsvc HomeGroupProvider BranchCache FDResPub Browser Telephony fdpHost TapiSrv Tlntsvr tlntsvr p2pimsvc simptcp fax msftpsvc iprip ftpsvc RemoteRegistry RasMan RasAuto seclogon MSFTPSVC W3SVC SMTPSVC Dfs TrkWks MSDTC DNS ERSVC NtFrs MSFtpsvc helpsvc HTTPFilter IISADMIN IsmServ WmdmPmSN Spooler RDSessMgr RPCLocator RsoPProv	ShellHWDetection ScardSvr Sacsvr TermService Uploadmgr VDS VSS WINS WinHttpAutoProxySvc SZCSVC CscService hidserv IPBusEnum PolicyAgent SCPolicySvc SharedAccess SSDPSRV Themes upnphost nfssvc nfsclnt MSSQLServerADHelper
set servicesM=dmserver SrvcSurg
set servicesG=Dhcp Dnscache NtLmSsp EventLog MpsSvc winmgmt wuauserv CryptSvc Schedule WdiServiceHost WdiSystemHost
echo Disabling bad services...
for %%a in (%servicesD%) do (
	echo Service: %%a
	sc stop "%%a"
	sc config "%%a" start= disabled
)
echo Disabled bad services.
echo Setting services to manual...
for %%b in (%servicesM%) do (
	echo Service: %%b
	sc config "%%b" start= demand
)
echo Set services to manual
echo Seting services to auto...
for %%c in (%servicesG%) do (
	echo Service: %%c
	sc config "%%c" start= auto
)
echo Started auto services
goto MENU

:Eight
REM START SYS INTEG SCAN!
echo "STARTING SYSTEM INTERGRITY SCAN"
echo "If it fails make sure you can access Sfc.exe"
Sfc.exe /scannow
goto MENU
:Nine
REM PowerShell RootKit detection start
echo "POWERSHELL ROOTKIT DETECTION WITH MALWAREBYTES ROOTKIT BETA (Requires powershell execution policy)"
REM Downloads MalwareBytes scan file
powershell Invoke-WebRequest -OutFile MBRTKit.exe https://data-cdn.mbamupdates.com/web/mbar-1.10.3.1001.exe
MBRTKit.exe
goto MENU


:Ten
auditpol /set /subcatergory: "Detailed File Share" /success:enable /failure:enable
auditpol /set /subcatergory: "File System" /success:enable /failure:enable
auditpol /set /subcatergory: "Security System Extension" /success:enable /failure:enable
auditpol /set /subcatergory: "System Integrity" /success:enable /failure:enable
auditpol /set /subcatergory: "Security State Change" /success:enable /failure:enable
auditpol /set /subcatergory: "Other System Events" /success:enable /failure:enable
auditpol /set /subcatergory: "System Integrity" /success:enable /failure:enable
auditpol /set /subcatergory: "Logon" /success:enable /failure:enable
auditpol /set /subcatergory: "Logoff" /success:enable /failure:enable
auditpol /set /subcatergory: "Account Lockout" /success:enable /failure:enable
auditpol /set /subcatergory: "Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcatergory: "Network Policy Server" /success:enable /failure:enable
auditpol /set /subcatergory: "Registry" /success:enable /failure:enable
auditpol /set /subcatergory: "SAM" /success:enable /failure:enable
auditpol /set /subcatergory: "Certification Services" /success:enable /failure:enable
auditpol /set /subcatergory: "Application Generated" /success:enable /failure:enable
auditpol /set /subcatergory: "Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcatergory: "Filtering Platform Packet Drop" /success:enable /failure:enable
auditpol /set /subcatergory: "Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcatergory: "Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcatergory: "Detailed File Share" /success:enable /failure:enable
auditpol /set /subcatergory: "Sensitive Privilege" /success:enable /failure:enable
auditpol /set /subcatergory: "Non Sensitive Privilege" /success:enable /failure:enable
auditpol /set /subcatergory: "Other Privilege Use Events" /success:enable /failure:enable
auditpol /set /subcatergory: "Process Termination" /success:enable /failure:enable
auditpol /set /subcatergory: "DPAPI Activity" /success:enable /failure:enable
auditpol /set /subcatergory: "RPC Activity" /success:enable /failure:enable
auditpol /set /subcatergory: "Process Creation" /success:enable /failure:enable
auditpol /set /subcatergory: "Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcatergory: "Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcatergory: "MPSSVC Rule-Level Policy" /success:enable /failure:enable
auditpol /set /subcatergory: "Filtering Platform Policy" /success:enable /failure:enable
auditpol /set /subcatergory: "Other Policy Change Events" /success:enable /failure:enable
auditpol /set /subcatergory: "User Account Management" /success:enable /failure:enable
auditpol /set /subcatergory: "Computer Account Management" /success:enable /failure:enable
auditpol /set /subcatergory: "Security Group Management" /success:enable /failure:enable
auditpol /set /subcatergory: "Distribution Group" /success:enable /failure:enable
auditpol /set /subcatergory: "Application Group Management" /success:enable /failure:enable
auditpol /set /subcatergory: "Other Account Management Events" /success:enable /failure:enable
auditpol /set /subcatergory: "Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcatergory: "Directory Service Replications" /success:enable /failure:enable
auditpol /set /subcatergory: "Detailed Directory Service Replications" /success:enable /failure:enable
auditpol /set /subcatergory: "Directory Service Access" /success:enable /failure:enable
auditpol /set /subcatergory: "Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcatergory: "Other Account Logon Events" /success:enable /failure:enable
auditpol /set /subcatergory: "Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcatergory: "Credential Validation" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"DS Access" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable
goto MENU

:Eleven
auditpol /set /category:"Account Logon" /success:disable /failure:enable
auditpol /set /category:"Account Management" /success:disable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:disable /failure:enable
auditpol /set /category:"DS Access" /success:disable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:disable /failure:enable
auditpol /set /category:"Object Access" /success:disable /failure:enable
auditpol /set /category:"Policy Change" /success:disable /failure:enable
auditpol /set /category:"Privilege Use" /success:disable /failure:enable
auditpol /set /category:"System" /success:disable /failure:enable
auditpol /set /category:* /success:disable
auditpol /set /category:* /failure:enable
goto MENU

:Twelve
auditpol /set /category:"Account Logon" /success:enable /failure:disable
auditpol /set /category:"Account Management" /success:enable /failure:disable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:disable
auditpol /set /category:"DS Access" /success:enable /failure:disable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:disable
auditpol /set /category:"Object Access" /success:enable /failure:disable
auditpol /set /category:"Policy Change" /success:enable /failure:disable
auditpol /set /category:"Privilege Use" /success:enable /failure:disable
auditpol /set /category:"System" /success:enable /failure:disable
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:disable
goto MENU

:Thirteen
echo Installing ntrights.exe to C:\Windows\System32
copy %path%\ntrights.exe C:\Windows\System32
if exist C:\Windows\System32\ntrights.exe (
	echo Installation succeeded, managing user rights..
	set remove=("Backup Operators" "Everyone" "Power Users" "Users" "NETWORK SERVICE" "LOCAL SERVICE" "Remote Desktop User" "ANONOYMOUS LOGON" "Guest" "Performance Log Users")
	for %%a in (%remove%) do (
			ntrights -U %%a -R SeNetworkLogonRight 
			ntrights -U %%a -R SeIncreaseQuotaPrivilege
			ntrights -U %%a -R SeInteractiveLogonRight
			ntrights -U %%a -R SeRemoteInteractiveLogonRight
			ntrights -U %%a -R SeSystemtimePrivilege
			ntrights -U %%a +R SeDenyNetworkLogonRight
			ntrights -U %%a +R SeDenyRemoteInteractiveLogonRight
			ntrights -U %%a -R SeProfileSingleProcessPrivilege
			ntrights -U %%a -R SeBatchLogonRight
			ntrights -U %%a -R SeUndockPrivilege
			ntrights -U %%a -R SeRestorePrivilege
			ntrights -U %%a -R SeShutdownPrivilege
		)
		ntrights -U "Administrators" -R SeImpersonatePrivilege
		ntrights -U "Administrator" -R SeImpersonatePrivilege
		ntrights -U "SERVICE" -R SeImpersonatePrivilege
		ntrights -U "LOCAL SERVICE" +R SeImpersonatePrivilege
		ntrights -U "NETWORK SERVICE" +R SeImpersonatePrivilege
		ntrights -U "Administrators" +R SeMachineAccountPrivilege
		ntrights -U "Administrator" +R SeMachineAccountPrivilege
		ntrights -U "Administrators" -R SeIncreaseQuotaPrivilege
		ntrights -U "Administrator" -R SeIncreaseQuotaPrivilege
		ntrights -U "Administrators" -R SeDebugPrivilege
		ntrights -U "Administrator" -R SeDebugPrivilege
		ntrights -U "Administrators" +R SeLockMemoryPrivilege
		ntrights -U "Administrator" +R SeLockMemoryPrivilege
		ntrights -U "Administrators" -R SeBatchLogonRight
		ntrights -U "Administrator" -R SeBatchLogonRight
		echo Managed User Rights
)
goto MENU

:Fourteen
echo Setting proper account properties...
wmic UserAccount set PasswordExpires=True
wmic UserAccount set PasswordChangeable=True
wmic UserAccount set PasswordRequired=True
@ECHO OFF
SETLOCAL EnableExtensions
FOR /F "TOKENS=2* delims==" %%G IN ('
        wmic USERACCOUNT where "status='OK'" get name/value  2^>NUL
    ') DO for %%g in (%%~G) do (
            net user %%~g Csunccdc420$69
			if %errorlevel%==1 echo "Did not change password for %%~g" >> C:\Users\Administrator\Artemis.txt
          )
endlocal
@ECHO OFF
SETLOCAL EnableExtensions
FOR /F "TOKENS=2* delims==" %%G IN ('
        wmic USERACCOUNT where "status='DEGRADED'" get name/value  2^>NUL
    ') DO for %%g in (%%~G) do (
            net user %%~g Csunccdc420$69
			if %errorlevel%==1 echo "Did not change password for %%~g" >> C:\Users\Administrator\Artemis.txt
          )
endlocal
goto MENU

:Fifteen
set /p groupOption="Use automatic or manual group management? (Recommended: Manual) (a/m)"
if %groupOption%==m (
start compmgmt.msc /wait
)
if %groupOption%==a (
@ECHO OFF
SETLOCAL EnableExtensions
FOR /F "TOKENS=2* delims==" %%G IN ('
        wmic USERACCOUNT where "status='OK'" get name/value  2^>NUL
    ') DO for %%g in (%%~G) do (
if %%~g==%username% (echo "Will not lose current user rights") else (
net localgroup Users %%~g /add
net localgroup Administrators %%~g /delete
net localgroup "Power Users" %%~g /delete
net localgroup "Access Control Assistance Operators" %%~g /delete
net localgroup "Backup Operators" %%~g /delete
net localgroup "Cryptographic Operators" %%~g /delete
net localgroup "Distributed COM Users" %%~g /delete
net localgroup "Event Log Readers" %%~g /delete
net localgroup Guests %%~g /delete
net localgroup "Hyper-V Administrators" %%~g /delete
REM net localgroup IIS_IUSRS
net localgroup "Network Configuration Operators" %%~g /delete
net localgroup "Performance Log Users" %%~g /delete
net localgroup "Performance Monitor Users" %%~g /delete
net localgroup "Remote Desktop Users" %%~g /delete
net localgroup "Remote Management Users" %%~g /delete
net localgroup "Replicator" %%~g /delete
net localgroup "System Managed Accounts Group" %%~g /delete
net localgroup Guests Guest /add
net localgroup Users Guest /delete)
			if %errorlevel%==1 echo "Did not remove %%~g from a group" >> C:\Users\Administrator\Artemis.txt
          )
endlocal
@ECHO OFF
SETLOCAL EnableExtensions
FOR /F "TOKENS=2* delims==" %%G IN ('
        wmic USERACCOUNT where "status='DEGRADED'" get name/value  2^>NUL
    ') DO for %%g in (%%~G) do (
if %%~g==%username% (echo "Will not lose current user rights") else (
net localgroup Users %%~g /add
net localgroup Administrators %%~g /delete
net localgroup "Power Users" %%~g /delete
net localgroup "Access Control Assistance Operators" %%~g /delete
net localgroup "Backup Operators" %%~g /delete
net localgroup "Cryptographic Operators" %%~g /delete
net localgroup "Distributed COM Users" %%~g /delete
net localgroup "Event Log Readers" %%~g /delete
net localgroup Guests %%~g /delete
net localgroup "Hyper-V Administrators" %%~g /delete
REM net localgroup IIS_IUSRS
net localgroup "Network Configuration Operators" %%~g /delete
net localgroup "Performance Log Users" %%~g /delete
net localgroup "Performance Monitor Users" %%~g /delete
net localgroup "Remote Desktop Users" %%~g /delete
net localgroup "Remote Management Users" %%~g /delete
net localgroup "Replicator" %%~g /delete
net localgroup "System Managed Accounts Group" %%~g /delete
net localgroup Guests Guest /add
net localgroup Users Guest /delete)
			if %errorlevel%==1 echo "Did not remove %%~g from a group" >> C:\Users\Administrator\Artemis.txt
          )
)
echo Invalid input %groupOption%
endlocal
goto Fifteen


:Sixteen
setlocal EnableDelayedExpansion
cls
net users
set /p a=Would you like to disable a user? [y/n]:
IF %a%==y (
cls
net users
set /p DISABLE=What is the name of the user?:
net user !DISABLE! /active:no
echo !DISABLE! has been disabled
set !DISABLE!=""
pause
endlocal
)
IF %a%==n (
	endlocal
goto MENU
)
goto :Sixteen

:Seventeen
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
goto MENU

:Eighteen
:@@@ENABLE WINDOWS FIREWALL
sc config MPSSVC start= auto
net start MPSSVC
netsh Advfirewall set allprofiles state on
netsh advfirewall set publicprofile state on
netsh advfirewall set domainprofile state on
netsh advfirewall set publicprofile state on
netsh advfirewall set privateprofile state on
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
netsh advfirewall set currentprofile logging allowedconnections enable
goto MENU


:Twentytwo
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
attrib +r +s C:\WINDOWS\system32\drivers\etc\hosts
goto MENU

:Twentythree
bcdedit.exe /set {current} nx AlwaysOn
goto MENU

:Twentyfour

goto MENU

:Twentyfive

goto MENU

:Twentysix

goto MENU

:Twentyseven

goto MENU

:Twentyeight
echo Firefox security
echo Refresh Firefox
echo Warn when try to install addons
echo Popup blocker
echo Remove bad extensions
echo Update Firefox

goto MENU

:Twentynine
REM Services
Net stop "Telnet"
sc config "Telnet" start=disabled
Net stop "Telephony"
sc config "Telephony" start=disabled
Net stop "RIP Listener"
sc config "RIP Listener" start=disabled
Net stop "SNMP Trap"
sc config "SNMP Trap" start=disabled
Net stop "Remote Registry"
sc config "Remote Registry" start=disabled

goto MENU

:Thirty

goto MENU

:Thirtyone

goto MENU

:Thirtytwo

goto MENU

:Thirtythree

echo "Turning the firewall on..."
netsh advfirewall set currentprofile state on

echo "Turning all states on the firewall on..."
netsh advfirewall set currentprofile set allprofile state on

echo "Setting Firewall Log MaxFileSize to 4096..."
netsh advfirewall set allprofile logging maxfilesize 4096

echo "Setting Firewall Log to log DROPPED connections..."
netsh advfirewall set allprofile logging droppedconnections enable

echo "Setting Firewall Log to log ALLOWED connections..."
netsh advfirewall set allprofile logging allowedconnections enable

echo "Disabling IPv6..."
reg add "HKLM\System\CurrentControlSet\services\TCPIP6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f

:@@@ENABLE WINDOWS FIREWALL
sc config MPSSVC start= auto
net start MPSSVC
netsh Advfirewall set allprofiles state on
netsh advfirewall set publicprofile state on
netsh advfirewall set domainprofile state on
netsh advfirewall set publicprofile state on
netsh advfirewall set privateprofile state on
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
netsh advfirewall set currentprofile logging allowedconnections enable
goto MENU

PAUSE >nul

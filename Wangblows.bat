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

::test michael is bi
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
echo 14. Automatic Password Change (Needs work)
echo 15. Automatic Group Management (Needs work)
echo 16. Harden PowerShell (Script Execution) (Needs work)
echo 17. Enable User Account Control (Needs work)
echo 18. Remove Capability (Needs work)
echo 19. Remove Packages and Update Packages (Needs work)
echo 20. Update Windows AppStore Apps (Needs work)
echo 21. NoVirusThanks Sys Hardener

CHOICE /C 123456789 /M "Enter your choice: "

if ERRORLEVEL 17 goto Seventeen
if ERRORLEVEL 13 goto Thirteen
if ERRORLEVEL 12 goto Twelve
if ERRORLEVEL 11 goto Eleven
if ERRORLEVEL 10 goto Ten
if ERRORLEVEL 9 goto Nine
if ERRORLEVEL 8 goto Eight
if ERRORLEVEL 7 goto Seven
if ERRORLEVEL 6 goto Six
if ERRORLEVEL 5 goto Five
if ERRORLEVEL 4 goto Four
if ERRORLEVEL 3 goto Three
if ERRORLEVEL 2 goto Two
if ERRORLEVEL 1 goto One

:One
REM Automation found from all over the interwebs, sources unknown, please open issue. sokme crap;
REM Turns off RDP

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
REM Failsafe
if %errorlevel%==1 netsh advfirewall firewall set service type = remotedesktop mode = disable
REM Windows auomatic updates
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f


echo Cleaning out the DNS cache...
ipconfig /flushdns
echo Writing over the hosts file...
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
if %errorlevel%==1 echo There was an error in writing to the hosts file (not running this as Admin probably)
REM Services
echo Showing you the services...
net start
echo Now writing services to a file and searching for vulnerable services...
net start > servicesstarted.txt
echo This is only common services, not nessecarily going to catch 100%
REM looks to see if remote registry is on
net start | findstr Remote Registry
if %errorlevel%==0 (
	echo Remote Registry is running!
	echo Attempting to stop...
	net stop RemoteRegistry
	sc config RemoteRegistry start=disabled
	if %errorlevel%==1 echo Stop failed... sorry...
) else ( 
	echo Remote Registry is already indicating stopped.
)
REM Remove all saved credentials
cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\*.*" /s /f /q
set SRVC_LIST=(RemoteAccess Telephony tlntsvr p2pimsvc simptcp fax msftpsvc)
	for %%i in %HITHERE% do net stop %%i
	for %%i in %HITHERE% sc config %%i start= disabled
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Telnet Server" new enable=no >NUL
netsh advfirewall firewall set rule name="netcat" new enable=no >NUL

reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /t
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d /1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f 
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
REM Common Policies
REM Restrict CD ROM drive
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
REM Automatic Admin logon
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
REM Logo message text
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d "Lol noobz pl0x don't hax, thx bae"
REM Logon message title bar
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "Dnt hax me"
REM Wipe page file from shutdown
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
REM LOL this is a key? Disallow remote access to floppie disks
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
REM Prevent print driver installs 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
REM Limit local account use of blank passwords to console
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
REM Auditing access of Global System Objects
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
REM Auditing Backup and Restore
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
REM Do not display last user on logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
REM UAC setting (Prompt on Secure Desktop)
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
REM Enable Installer Detection
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
REM Undock without logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
REM Maximum Machine Password Age
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
REM Disable machine account password changes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
REM Require Strong Session Key
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
REM Require Sign/Seal
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
REM Sign Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
REM Seal Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
REM Don't disable CTRL+ALT+DEL even though it serves no purpose
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f 
REM Restrict Anonymous Enumeration #1
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
REM Restrict Anonymous Enumeration #2
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f 
REM Idle Time Limit - 45 mins
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f 
REM Require Security Signature - Disabled pursuant to checklist
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f 
REM Enable Security Signature - Disabled pursuant to checklist
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f 
REM Disable Domain Credential Storage
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f 
REM Don't Give Anons Everyone Permissions
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
REM SMB Passwords unencrypted to third party? How bout nah
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
REM Null Session Pipes Cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
REM Remotely accessible registry paths cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
REM Remotely accessible registry paths and sub-paths cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
REM Restict anonymous access to named pipes and shares
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
REM Allow to use Machine ID for NTLM
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
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
findstr .mpeg4 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .mpeg4 >> media_video
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
findstr "Cain" programfiles.flashed
if %errorlevel%==0 (
echo Cain detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "nmap" programfiles.flashed
if %errorlevel%==0 (
echo Nmap detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "keylogger" programfiles.flashed
if %errorlevel%==0 (
echo Potential keylogger detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Armitage" programfiles.flashed
if %errorlevel%==0 (
echo Potential Armitage detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Metasploit" programfiles.flashed
if %errorlevel%==0 (
echo Potential Metasploit framework detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Shellter" programfiles.flashed
if %errorlevel%==0 (
echo Potential Shellter detected. Please take note, then press any key.
pause >NUL
)
cls
goto MENU
:Five
REM No Remote Desktop
echo "DISABLING REMOTE DESKTOP"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
goto MENU


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
REM Removing good ol' insecure stuff
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
set servicesD=RemoteAccess CDPSvc HomeGroupListener lmhosts PlugPlay Spooler UevAgentService shpamsvc NetTcpPortSharing TrkWks iphlpsvc HomeGroupProvider BranchCache FDResPub Browser Telephony fdpHost TapiSrv Tlntsvr tlntsvr p2pimsvc simptcp fax msftpsvc iprip ftpsvc RemoteRegistry RasMan RasAuto seclogon MSFTPSVC W3SVC SMTPSVC Dfs TrkWks MSDTC DNS ERSVC NtFrs MSFtpsvc helpsvc HTTPFilter IISADMIN IsmServ WmdmPmSN Spooler RDSessMgr RPCLocator RsoPProv	ShellHWDetection ScardSvr Sacsvr TermService Uploadmgr VDS VSS WINS WinHttpAutoProxySvc SZCSVC CscService hidserv IPBusEnum PolicyAgent SCPolicySvc SharedAccess SSDPSRV Themes upnphost nfssvc nfsclnt MSSQLServerADHelper
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

:Seventeen
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
goto MENU

PAUSE >nul

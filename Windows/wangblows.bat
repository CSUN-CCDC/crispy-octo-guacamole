@echo off
title 0A
title Cyber Patriot meets Hivestorm meets CCDC 
::Initilize variables
set mypath=%~dp0
::echo Checking if this script contains Administrative rights...
::net openfiles
::if %errorlevel%==0 (
::echo Success!
::) else (
::echo Please run as Administrator.
::pause
::exit 
::)
::Tes t 


mkdir C:\Wangblows

echo Enabling system restore...
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 0 /f
sc config srservice start= Auto
net start srservice
sc config VSS start= auto

copy /y %mypath%\LGPO.exe C:\Windows\System32\LGPO.exe
start %cd%\lgpo.exe /b C:\Wangblows\ /n "Policy Backup"
echo Make sure policy has been exported
pause


start regedit.exe
echo Make sure registry has been exported
pause

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v "PowerShellVersion" /z >nul
If %ERRORLEVEL% == 1 (
	echo POWERSHELL NOT INSTALLED, please install before continuing
	pause>nul
	exit
)

:@@@INTITIAL SERVICE CONFIG@@@
sc query >> C:\Wangblows\Services_Original.txt
if %errorlevel%==1 ( echo Failed to write Original Services >> C:\Wangblows\Wangblows.txt
) else (
echo Outputted Original Service Configs.
)

:@@@Listing possible penetrations@@@
echo "STARTING TO OUTPUT PROCESS FILES DIRECTLY TO THE C:\Wangblows\ DRIVE!"
wmic process list brief > C:\Wangblows\BriefProcesses.txt
if %errorlevel%==1 echo Brief Processes failed to write >> C:\Wangblows\Wangblows.txt
wmic process list full > C:\Wangblows\FullProcesses.txt
if %errorlevel%==1 echo Full Processes failed to write >> C:\Wangblows\Wangblows.txt
wmic startup list full > C:\Wangblows\StartupLists.txt
if %errorlevel%==1 echo Startup Processes failed to write >> C:\Wangblows\Wangblows.txt
net start > C:\Wangblows\StartedProcesses.txt
if %errorlevel%==1 echo Started processes failed to write >> C:\Wangblows\Wangblows.txt
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run  Run.reg
if %errorlevel%==1 echo Run processes failed to write >> C:\Wangblows\Wangblows.txt

:@@@FIREWALL BACKUP@@@
netsh advfirewall export "C:\Wangblows\Original_Firewall_Policy.wfw"
if %errorlevel%==1 echo "Failed to export firewall policy" >> C:\Wangblows\Wangblows.txt

:: Set stickykeys to CMD
takeown /f "%systemroot%\System32\sethc.exe"
takeown /f "%systemroot%\System32\utilman.exe"
takeown /f "%systemroot%\System32\cmd.exe"
icacls "%systemroot%\System32\sethc.exe" /grant %username%:f
icacls "%systemroot%\System32\cmd.exe" /grant %username%:f
icacls "%systemroot%\System32\utilman.exe" /grant %username%:f
icacls "%systemroot%\System32\cmd.exe" /grant %username%:f
move "%systemroot%\System32\sethc.exe" "%systemroot%\System32\sethc1.exe"
copy /y "%systemroot%\System32\cmd.exe" "%systemroot%\System32\sethc.exe"
move "%systemroot%\System32\utilman.exe" "%systemroot%\System32\utilman.exe"
copy /y "%systemroot%\System32\cmd.exe" "%systemroot%\System32\utilman.exe"

::@@@CURRENTLY RUNNING SERVICES@@@
net start >> C:\Wangblows\Services_Started.txt
if %errorlevel%==1 echo Running services failed to write >> C:\Wangblows\Wangblows.txt

:MENU
echo Choose an Option:
echo 2. Harden Networking
echo 3. Take Registry Backup
echo 5. Disable Remote Desktop
echo 6. Miscallaneous Registry Security Keys
echo 7. Disable Weak Services
echo 9. Powershell rootkit detection
echo 10. Audit
echo 14. Automatic Password Change
echo 18. Download and Install SysInternals
echo 22. Clear Hosts File
echo 24. Run Security Programs
echo 26. Set up Backup
echo 30. Update all programs using UCheck 
echo 31. Install Antivirus

set /p mo="Enter your choice: "
IF %mo%==69 goto Nice
IF %mo%==31 goto Thirtyone
IF %mo%==30 goto Thirty
IF %mo%==26 goto Twentysix
IF %mo%==24 goto Twentyfour
IF %mo%==22 goto Twentytwo
IF %mo%==19 goto Nineteen
IF %mo%==18 goto Eighteen
IF %mo%==14 goto Fourteen
IF %mo%==10 goto Ten
IF %mo%==9 goto Nine
IF %mo%==7 goto Seven
IF %mo%==6 goto Six
IF %mo%==5 goto Five
IF %mo%==3 goto Three
IF %mo%==2 goto Two


:Two
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

echo "Disabling Remote Assistance"
netsh advfirewall firewall set rule group="Remote Assistance" new enable=no


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
pause
goto MENU

:Three
echo Backup HKLM, HKCR, HKCU, HKU, HKCC manually
start regedit.exe /wait
pause
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
	pause
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
	pause
	goto MENU
)
echo Warning: Invalid input %rdpChk%
pause
goto :Five

:Six
REM Automation found from all over the inter
REM Screensaver!
::Testing if this line works
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RunAsPPL" /v RunAsPPL /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v  /t REG_MULTI_SZ /d "" /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /t
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f 

pause
goto MENU

:Seven

set /p option=Is IIS a critical service? (y/n):
IF %option%==y (
REM Removing good ol' insecure stuff but not me. I may be insecure, but I am important. Or am I? I don't even know anymore
echo "DISABLING WEAK SERVICES (works only Windows 8+)"
:services
set servicesD=RemoteAccess CDPSvc XboxGipSvc xbgm xboxgip XblAuthManager TabletInputService XblGameSave HomeGroupListener PlugPlay Spooler UevAgentService shpamsvc NetTcpPortSharing TrkWks iphlpsvc HomeGroupProvider BranchCache FDResPub Browser Telephony fdpHost TapiSrv Tlntsvr tlntsvr p2pimsvc simptcp fax msftpsvc iprip ftpsvc RemoteRegistry RasMan RasAuto seclogon MSFTPSVC W3SVC TrkWks MSDTC ERSVC NtFrs MSFtpsvc helpsvc HTTPFilter IsmServ Spooler RDSessMgr ScardSvr Sacsvr VDS VSS WINS SZCSVC CscServicehidserv SharedAccess upnphost nfssvc 
set servicesG=Dhcp Dnscache NtLmSsp EventLog MpsSvc winmgmt wuauserv CryptSvc Schedule WdiServiceHost WdiSystemHost 
echo Disabling bad services...
for %%a in (%servicesD%) do (
	echo Service: %%a
	sc stop "%%a"
	sc config "%%a" start= disabled
)
echo Disabled bad services.
echo "Disabling weak services 100% complete..."
echo "Restoring critical services 0% complete..."
echo Setting services to manual...
for %%b in (%servicesM%) do (
	echo Service: %%b
	sc config "%%b" start= demand
)
echo Set services to manual
echo "Restoring critical services 50% complete..."
echo Seting services to auto...
for %%c in (%servicesG%) do (
	echo Service: %%c
	sc config "%%c" start= auto
)
echo Started auto services...
echo "Restoring critical services 100% complete."
pause
goto MENU)
goto MENU

IF %option%==n (
REM Removing good ol' insecure stuff but not me. I may be insecure, but I am important. Or am I? I don't even know anymore
echo "DISABLING WEAK SERVICES"
echo on

:services
set servicesD=RemoteAccess CDPSvc XboxGipSvc xbgm xboxgip XblAuthManager TabletInputService XblGameSave HomeGroupListener PlugPlay Spooler UevAgentService shpamsvc NetTcpPortSharing TrkWks iphlpsvc HomeGroupProvider BranchCache FDResPub Browser Telephony fdpHost TapiSrv Tlntsvr tlntsvr p2pimsvc simptcp fax msftpsvc iprip ftpsvc RemoteRegistry RasMan RasAuto seclogon MSFTPSVC W3SVC TrkWks MSDTC ERSVC NtFrs MSFtpsvc helpsvc HTTPFilter IISADMIN IsmServ Spooler RDSessMgr ScardSvr Sacsvr VDS VSS WINS SZCSVC CscServicehidserv SharedAccess upnphost nfssvc
echo Disabling bad services...
for %%a in (%servicesD%) do (
	echo Service: %%a
	sc stop "%%a"
	sc config "%%a" start= disabled
)
echo Disabled bad services.
echo "Disabling weak services 100% complete..."
echo "Restoring critical services 0% complete..."
echo Setting services to manual...
for %%b in (%servicesM%) do (
	echo Service: %%b
	sc config "%%b" start= demand
)
echo Set services to manual
echo "Restoring critical services 50% complete..."
echo Seting services to auto...
for %%c in (%servicesG%) do (
	echo Service: %%c
	sc config "%%c" start= auto
)
echo Started auto services...
echo "Restoring critical services 100% complete."
pause
goto MENU)


:Nine
REM Some PowerShell Stuff for Win Servers
powershell Disable-PSRemoting
powershell Set-SmbServerConfiguration -EnableSMB1Protocol $false
powershell Set-SmbServerConfiguration –EnableSMB2Protocol $true
goto MENU


:Ten
auditpol /set /subcatergory: "Logon" /success:enable /failure:enable
auditpol /set /subcatergory: "Logoff" /success:enable /failure:enable
auditpol /set /subcatergory: "Account Lockout" /success:enable /failure:enable
auditpol /set /subcatergory: "Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcatergory: "Network Policy Server" /success:enable /failure:enable
auditpol /set /subcatergory: "Registry" /success:enable /failure:enable
auditpol /set /subcatergory: "SAM" /success:enable /failure:enable
auditpol /set /subcatergory: "Detailed File Share" /success:enable /failure:enable
auditpol /set /subcatergory: "Sensitive Privilege" /success:enable /failure:enable
auditpol /set /subcatergory: "Other Privilege Use Events" /success:enable /failure:enable
auditpol /set /subcatergory: "DPAPI Activity" /success:enable /failure:enable
auditpol /set /subcatergory: "RPC Activity" /success:enable /failure:enable
auditpol /set /subcatergory: "User Account Management" /success:enable /failure:enable
auditpol /set /subcatergory: "Security Group Management" /success:enable /failure:enable
auditpol /set /subcatergory: "Distribution Group" /success:enable /failure:enable

pause
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
			if %errorlevel%==1 echo "Did not change password for %%~g" >> C:\Wangblows\Wangblows.txt
          )
endlocal
@ECHO OFF
SETLOCAL EnableExtensions
FOR /F "TOKENS=2* delims==" %%G IN ('
        wmic USERACCOUNT where "status='DEGRADED'" get name/value  2^>NUL
    ') DO for %%g in (%%~G) do (
            net user %%~g Csunccdc420$69
			if %errorlevel%==1 echo "Did not change password for %%~g" >> C:\Wangblows\Wangblows.txt
          )
endlocal
pause
goto MENU



:Eighteen
powershell Invoke-WebRequest -OutFile SysinternalsSuite.zip https://download.sysinternals.com/files/SysinternalsSuite.zip
powershell Expand-Archive SysinternalsSuite.zip -DestinationPath C:\Windows\System32\
pause
goto MENU



:Twentytwo 
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
echo 127.0.0.1 localhost >> C:\Windows\System32\drivers\etc\hosts
echo localhost 127.0.0.1 >> C:\Windows\System32\drivers\etc\hosts
pause
goto MENU


:Twentyfour
echo Running RogueKillers
echo Running AdwCleaner
echo Farbar Service Scanner
echo HijackThis 
echo BlitzBlank 
echo Hitman Pro

pause
goto MENU


:Twentysix
start sdclt.exe /configure
pause
goto MENU


:Thirty
powershell Invoke-WebRequest -OutFile Ucheck.exe https://github.com/homunculus39/crispy-octo-guacamole/UCheck.exe
copy /y %cd%\Ucheck.exe  C:\Windows\System32\
start Ucheck.exe /wait
pause
goto MENU

:Thirtyone
echo "PowerShell downloading AVG anti-virus"
powershell Invoke-WebRequest -OutFile AVG.exe https://bits.avcdn.net/productfamily_ANTIVIRUS/insttype_FREE/platform_WIN_AVG/installertype_ONLINE/build_RELEASE
start AVG.exe /wait
pause

goto MENU


PAUSE >nul

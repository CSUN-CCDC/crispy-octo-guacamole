param([switch]$Elevated)
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

#Obtain Machine Purpose

$Purpose = Read-Host "What is the purpose of this machine? (Services... connected services for X company):"
$hostname = [System.Net.Dns]::GetHostName()
$hostname1 = HOSTNAME.EXE
$WindowsOS = (Get-CimInstance -Class Win32_OperatingSystem)
$WindowsOS1 = (Get-WmiObject win32_operatingsystem).caption
$WindowsOS2 = reg query "hklm\software\microsoft\windows nt\currentversion" /v ProductName
$WindowsOS4 = systeminfo | findstr /B /C:"OS Name"
$WindowsBuild = systeminfo | findstr /B /C:"OS Version"
$IPAddress = ipconfig | findstr /C:Address
$IPAddress2 = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress

$OpenPorts
nmap localhost -sV --open -oN parseme
$a,$b,$c,$d,$e,$f,$g = Get-Content .\parseme
$OpenPorts = $g[0..($g.count - 3)]



Add-Content C:\Inventory.txt $Purpose
Add-Content C:\Inventory.txt $hostname 
Add-Content C:\Inventory.txt $WindowsOS
Add-Content C:\Inventory.txt $WindowsBuild
Add-Content C:\Inventory.txt $IPAddress
Add-Content C:\Inventory.txt $OpenPorts




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

#Automatically install nmap

$ProgressPreference = "SilentlyContinue"

Try {
    Write-Host -BackgroundColor White -ForegroundColor Green "Silently downloading nmap... please wait..."
    $ProgressPreference = "SilentlyContinue"
    $client = new-object System.Net.WebClient
$client.DownloadFile("https://nmap.org/dist/nmap-7.91-setup.exe","C:\nmap.exe")
Write-Host -BackgroundColor White -ForegroundColor Green "Silently installing nmap... please wait..."
Start-Process -FilePath C:\nmap.exe -ArgumentList "/S" -Wait
Write-Host -BackgroundColor White -ForegroundColor Green "Nmap installed."

}Catch{
    Write-Warning -Message "Failed to install nmap, please check the nmap installation. 
    Below is an output of running the nmap command."
    Start-Process C:\nmap.exe
}

#Obtain Machine Purpose
$Purpose = Read-Host "What is the purpose of this machine? (These are the connected services for X company)"

Try {
    $WindowsOS = (Get-CimInstance -Class Win32_OperatingSystem)
} Catch {
Try {
    $WindowsOS3 = systeminfo | findstr /B /C:"OS Name"
} Catch {
    $WindowsOS1 = (Get-WmiObject win32_operatingsystem).caption
    }
Try {
    $WindowsOS2 = reg query "hklm\software\microsoft\windows nt\currentversion" /v ProductName
} Catch {
    }
}

Try {
    $Userlist = wmic useraccount get name
}Catch{

}

Try {
    $hostname = [System.Net.Dns]::GetHostName()
} Catch {
    $hostname1 = HOSTNAME.EXE
}
       
Try {
    $WindowsBuild = systeminfo | findstr /B /C:"OS Version"
}Catch {

    }
    
Try {
    $IPAddress = ipconfig | findstr /C:Address
}Catch{
    $IPAddress2 = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress
}

Try {
nmap localhost -sV -oN parseme
$a,$b,$c,$d,$e,$f,$g = Get-Content .\parseme
$OpenPorts = $g[0..($g.count - 3)]
}Catch{
    Write-Warning -Message "There was a problem identifying open ports. Please investigate."
}



Add-Content C:\Inventory.txt $Purpose
Add-Content C:\Inventory.txt $hostname
Add-Content C:\Inventory.txt $Userlist
Add-Content C:\Inventory.txt $WindowsOS
Add-Content C:\Inventory.txt $WindowsOS1
Add-Content C:\Inventory.txt $WindowsOS2
Add-Content C:\Inventory.txt $WindowsOS3
Add-Content C:\Inventory.txt $WindowsBuild
Add-Content C:\Inventory.txt $IPAddress
Add-Content C:\Inventory.txt $IPAddress2
Add-Content C:\Inventory.txt $OpenPorts

$wc = New-Object System.Net.WebClient
$resp = $wc.UploadFile("https://file.io","C:\Inventory.txt")
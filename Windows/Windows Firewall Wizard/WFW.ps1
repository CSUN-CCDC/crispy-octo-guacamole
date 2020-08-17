#Require -RunAsAdministrator
<#
Written by @1ncryption
This script is to walk you through the setup process for a local firewall deployment using my sexy firewwall strategies.
#>

function CheckService{
    param($ServiceName)
    $arrService = Get-Service -Name $ServiceName
    if ($arrService.Status -ne "Running"){
    Set-Service -Name $ServiceName -StartupType Automatic -Force
    Start-Service $ServiceName
    Write-Host "Starting " $ServiceName " service" 
    " |=|=|=|=|=|=|=|=|=|=|=|=|=|=|=| " 
    " Service is now started"
    }
    if ($arrService.Status -eq "running"){ 
    Write-Host "$ServiceName service is already started"
    }
    }
function Show-WFW-Menu {
    param (
        [string]$Title = 'WFW Menu'
    )
    title "Windows Firewall Wizard by @1ncryption"
    Clear-Host
    Write-Host "=|=|=|=|=|=|=|=|=|=|=|=|=|=|=|=| $Title |=|=|=|=|=|=|=|=|=|=|=|=|=|=|=|="
    Write-Host "Troubleshoot inactive / disabled Firewall"
    Write-Host "Check if Group Policy has interfered with Firewall"
    Write-Host ""
    Write-Host "" 
    Write-Host "Active Directory Domain Controller"
    Write-Host "Read Only Active Directory Domain Controller"
    Write-Host "Workstation with no services"
    Write-Host "Server"
    Write-Host "Q: Press 'Q' (case sensitive) to quit."
}

do
 {
    Show-WFW-Menu
    $selection = Read-Host "Please select an option."
    switch ($selection)
    {
    '1' {
        Clear-Host
        title Hello
        Write-Host "Stage 1/6: Performing factory reconfiguration of local firewall..."
        Start-Process -FilePath WindowsFirewall.diagcab -Verb RunAs -Wait
        Read-Host "Press Enter key to continue with automatic repairs if Windows Firewall still does not work..."
        CheckService("mpssvc")
        CheckService("bfe")
        reg import .\mpssvc.reg
        reg import .\mpsdrv.reg
    } '2' {
Write-Host -BackgroundColor "Black" -ForegroundColor "Lime"
        # Get Policystoresourcetype object and read to do next action
#Get-NetFirewallRule -PolicyStoreSource | Select-Object -ExpandProperty EndRange | Select-Object -ExpandProperty IPAddressToString
        'You chose option #2'
    } '3' {
      'You chose option #3'
    }
    }
    pause
 }
 until ($selection -eq 'q')
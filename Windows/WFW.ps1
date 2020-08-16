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
    " ---------------------- " 
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
    Clear-Host
    Write-Host "=|=|=|=|=|=|=|=|=|=|=|=|=|=|=|=| $Title |=|=|=|=|=|=|=|=|=|=|=|=|=|=|=|="
    Write-Host ""
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
        Write-Host "Stage 1/6: Obtaining local firewall health status..."
        CheckService("mpssvc")
        CheckService("bfe")

    } '2' {
    'You chose option #2'
    } '3' {
      'You chose option #3'
    }
    }
    pause
 }
 until ($selection -eq 'q')
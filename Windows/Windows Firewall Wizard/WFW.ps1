#Require -RunAsAdministrator
<#
Written by @1ncryption
This script is to walk you through the setup process for a local firewall deployment using my sexy firewwall strategies.
#>
# Load assembly
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
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
    Write-Host "1. Troubleshoot inactive / disabled Firewall"
    Write-Host "2. Check if Group Policy has interfered with Firewall"
    Write-Host "3. Active Directory Domain Controller"
    Write-Host "Read Only Active Directory Domain Controller"
    Write-Host "Workstation with no services"
    Write-Host "Server"
    Write-Host "Q: Press 'Q' (case sensitive) to quit."
}
   
do
 {
    Show-WFW-Menu
    $selection = Read-Host "Please select an option: "
    switch ($selection)
    {
    '1' {
        Clear-Host
        title "Troubleshoot inactive / disabled Firewall"
        Write-Warning "Performing factory reconfiguration of local firewall..."
        #Backup current configuration of firewall
        Write-Host -BackgroundColor Black -ForegroundColor Yellow "Your existing firewall configuration has been saved to: c:\Pre-advfirewallpolicy.wfw" -Foregroundcolor CYAN
        netsh advfirewall export "c:\Pre-advfirewallpolicy.wfw" | Out-Null
        Write-Host -BackgroundColor Black -ForegroundColor Yellow "Backed up rules to C:\Original-advfirewallpolicy.wfw"
        #Microsoft repair firewall
        Start-Process -FilePath WindowsFirewall.diagcab -Verb RunAs -Wait
        #Reinstall firewall service
        cmd.exe /c Rundll32.exe setupapi,InstallHinfSection Ndi-Steelhead 132 %windir%\inf\netrass.inf     
        Write-Host -BackgroundColor Black -ForegroundColor Green "Please confirm the firewall is operational. If not, press enter."
        CheckService("mpssvc")
        CheckService("bfe")
        netsh advfirewall set domainprofile state on
        netsh advfirewall set privateprofile state on
        netsh advfirewall set publicprofile state on
        
        [System.Windows.Forms.MessageBox]::Show("Message Text","Title",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Hand)
    } '2' {
Write-Host -BackgroundColor "Black" -ForegroundColor "Cyan"
        # Get Policystoresourcetype object and read to do next action
#Get-NetFirewallRule -PolicyStoreSource | Select-Object -ExpandProperty EndRange | Select-Object -ExpandProperty IPAddressToString
        gpresult.exe -z 
        'You chose option #2'
    } '3' {
      'You chose option #3'
    }
    }
    pause
 }
 until ($selection -eq 'q')
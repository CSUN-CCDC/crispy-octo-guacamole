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
    Write-Host "2. Auto Identify existing GPO firewall rules"
    Write-Host "3. Harden Active Directory Domain Controller"
    Write-Host "4. Read Only Active Directory Domain Controller"
    Write-Host "5. Workstation with no services"
    Write-Host "6. Server"
    Write-Host "Q: Press 'Q' (case sensitive) to quit."
}
   
do
 {
    Show-WFW-Menu
    $selection = Read-Host "Please select a number followed by enter (ex. 1): "
    switch ($selection)
    {
    '1' {
        Try {
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
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("There was an error during this process.","Troubleshoot inactive / disabled Firewall",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Hand)
            Write-Warning $Error[0]
        }

    } '2' {
    Clear-Host
    Try {
    gpresult.exe /R /Z
     
    # Get the string we want to search for 
    $string = Read-Host -Prompt "GPO Searcher: Enter string to find 'i.e. Firewall'" 
    
    # Set the domain to search for GPOs 
    $DomainName = $env:USERDNSDOMAIN 
    
    # Find all GPOs in the current domain 
    write-host "Finding all the GPOs in $DomainName" 
    Import-Module grouppolicy 
    $allGposInDomain = Get-GPO -All -Domain $DomainName 
    
    # Look through each GPO's XML for the string 
    Write-Host "Starting search...." 
    foreach ($gpo in $allGposInDomain) { 
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml 
        if ($report -match $string) { 
            Write-Warning "********** Match found in: $($gpo.DisplayName) **********" 
        } # end if 
        else { 
            Write-Host "No match in: $($gpo.DisplayName)" 
        } # end else 
    } # end foreach 
 
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("There was an error during this process.","Auto Identify existing GPO firewall rules",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Hand)
        Write-Warning $Error[0]
    }
    
        
    } '3' {
        Clear-Host
        Try {
            #Change Remote Address Any to Whitelisted software
      New-NetFirewallRule -DisplayName "Allow DNS Outbound" -Direction Outbound -Program "C:\Windows\System32\dns.exe" -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 53
      New-NetFirewallRule -DisplayName "Allow DNS Inbound" -Direction Inbound -Program "C:\Windows\System32\dns.exe" -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 53

      New-NetFirewallRule -DisplayName "Allow DNS Outbound TCP" -Direction Outbound -Program "C:\Windows\System32\dns.exe" -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 53
      New-NetFirewallRule -DisplayName "Allow DNS Inbound TCP" -Direction Inbound -Program "C:\Windows\System32\dns.exe" -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 53
      
      New-NetFirewallRule -DisplayName "Allow Kerberos Outbound TCP" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 88
      New-NetFirewallRule -DisplayName "Allow Kerberos Inbound TCP" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 88
      
      New-NetFirewallRule -DisplayName "Allow Kerberos Outbound" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 88
      New-NetFirewallRule -DisplayName "Allow Kerberos Inbound" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 88
      
      New-NetFirewallRule -DisplayName "Allow SMB Outbound" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 445
      New-NetFirewallRule -DisplayName "Allow SMB Inbound" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 445
      
      New-NetFirewallRule -DisplayName "DFSN, NetBIOS Session Service, NetLogon" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 445
      New-NetFirewallRule -DisplayName "DFSN, NetBIOS Session Service, NetLogon" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 445
      
      New-NetFirewallRule -DisplayName "LDAP Directory, Replication, User and Computer, Authentication, Group Policy, Trusts" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 389
      New-NetFirewallRule -DisplayName "LDAP Directory, Replication, User and Computer, Authentication, Group Policy, Trusts" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 389
      
      New-NetFirewallRule -DisplayName "LDAP Directory, Replication, User and Computer, Authentication, Group Policy, Trusts" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 389
      New-NetFirewallRule -DisplayName "LDAP Directory, Replication, User and Computer, Authentication, Group Policy, Trusts" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 389
      
      New-NetFirewallRule -DisplayName "Global Catalog, Directory, Replication, User and Computer Authentication, Group Policy, Trusts" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 3268
      New-NetFirewallRule -DisplayName "Global Catalog, Directory, Replication, User and Computer Authentication, Group Policy, Trusts" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 3268
      
      New-NetFirewallRule -DisplayName "Replication EPM" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 135
      New-NetFirewallRule -DisplayName "Replication EPM" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 135
      
      New-NetFirewallRule -DisplayName "Windows Time, Trusts" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 123
      New-NetFirewallRule -DisplayName "Windows Time, Trusts" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 123
      
      New-NetFirewallRule -DisplayName "DFS, Group Policy" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 138
      New-NetFirewallRule -DisplayName "DFS, Group Policy" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 138
      
      New-NetFirewallRule -DisplayName "User and Computer Authentication" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 137
      New-NetFirewallRule -DisplayName "User and Computer Authentication" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol UDP -LocalPort 137
      
      New-NetFirewallRule -DisplayName "User and Computer Authentication, Replication" -Direction Outbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 139
      New-NetFirewallRule -DisplayName "User and Computer Authentication, Replication" -Direction Inbound -RemoteAddress Any -Action Allow -Enabled True -InterfaceType Any -Profile Any -RemotePort Any -Protocol TCP -LocalPort 139
            
        }catch {
                [System.Windows.Forms.MessageBox]::Show("There was an error during this process.","Harden Active Directory
                + Domain Controller",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Hand)
                Write-Warning $Error[0]
            }
    }
    }
    pause
 }
 until ($selection -eq 'q')
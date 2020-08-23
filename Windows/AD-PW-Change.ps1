<#Authored by Twitter: @1ncrytion#>
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Web
[System.Web.Security.Membership]::GeneratePassword(16,2)
#Create list of AD Users
Get-ADUser -Filter * | select SamAccountName | Export-CSV -Path C:\Users\Administrator\PasswordSubmission.csv
(Get-Content C:\Users\Administrator\PasswordSubmission.csv) -replace '"' -replace "`n","`r`n" > Userlist.txt
#Parse each user in each line
$users = Get-Content -Encoding ascii -Path C:\Users\Administrator\Documents\Userlist.txt
ForEach ($user in $users) 
{
#Generate new hot and sexy passwords
$password = [System.Web.Security.Membership]::GeneratePassword(16,2)
$clearpwd = $password
#Keep a copy in var
$password = ConvertTo-SecureString -AsPlainText $password -Force
    # Set the default password for the current account
    Get-ADUser $user | Set-ADAccountPassword -NewPassword $password -Reset
    Write-Host “Password has been reset for the user: $user”
    Add-Content -Path C:\Users\Administrator\MasterPW.csv -Value "$user,$clearpwd`r" 
#CSV be ready matey
}
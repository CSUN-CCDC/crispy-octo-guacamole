# Enter a path to your import CSV file
$LocalUsers = Import-csv users.csv

foreach ($User in $LocalUsers) {
    $Username = $User.username
    $Password = $User.password

    # Check if the user account already exists locally
    if (Get-ADUser -F {SamAccountName -eq $Username}) {
        # If user does exist change password
        Set-LocalUser -Name $Username -Password `
	    (ConvertTo-SecureString -AsPlainText $Password -Force)
        Write-Output "$Username password was reset"
    } else {
        # If a user does not exist then create a new user
        New-LocalUser $Username -Password `
        (ConvertTo-SecureString -AsPlainText $Password -Force)
    }
}
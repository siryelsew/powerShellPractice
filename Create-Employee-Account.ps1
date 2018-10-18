#Requires -module ActiveDirectory

# Script for creating new hire AD accounts and accompanying hew hire info text output.

# Collect parameter info. The "Mandatory=$True" flags mean if the info is not provided, all info will be asked for specifically.
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$FirstName,

    [Parameter(Mandatory=$True,Position=2)]
    [string]$LastName,

    [Parameter(Mandatory=$True)]
    [ValidateSet("NY","CA","PA","AZ","Remote","Contractor")]
    [string]$Location,

    [Parameter(Mandatory=$false)]
    [string]$Department,

    [Parameter(Mandatory=$False)]
    [string]$NoAD,

    [Parameter(Mandatory=$False)]
    [switch]$MakeOU,

    [Parameter(Mandatory=$False)]
    [switch]$MakeGmail,

    [Parameter(Mandatory=$false)]
    [string]$Computer
)

# Function to handle exiting the program gracefully
Function pressAnyKey {
    if (-not $psISE) {
        Write-Host "`nPress any key to exit..."
        $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

Function Create-Password {										# [url]https://powersnippets.com/create-password/[/url]
	[CmdletBinding()]Param (									# Version 01.01.00, by iRon
		[Int]$Size = 8, [Char[]]$Complexity = "ULNS", [Char[]]$Exclude
	)
	$AllTokens = @(); $Chars = @(); $TokenSets = @{
		UpperCase = [Char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
		LowerCase = [Char[]]'abcdefghijklmnopqrstuvwxyz'
		Numbers   = [Char[]]'0123456789'
		Symbols   = [Char[]]'!"#$%&''()*+,-./:;<=>?@[\]^_`{|}~'
	}
	$TokenSets.Keys | Where {$Complexity -Contains $_[0]} | ForEach {
		$TokenSet = $TokenSets.$_ | Where {$Exclude -cNotContains $_} | ForEach {$_}
		If ($_[0] -cle "Z") {$Chars += $TokenSet | Get-Random}					#Character sets defined in uppercase are mandatory
		$AllTokens += $TokenSet
	}
	While ($Chars.Count -lt $Size) {$Chars += $AllTokens | Get-Random}
	($Chars | Sort-Object {Get-Random}) -Join ""								#Mix the (mandatory) characters and output string
}

# Static/Global info and the lookup tables
$adminName = $env:USERNAME
$domainName = (Get-ADDomain).distinguishedname
$domainNameShort = (Get-ADDomain).dnsroot
$currTime = Get-Date

# Make the various username permutations
$adName = ((-join($FirstName,".",$LastName)).ToLower()).replace(" ",'')
$displayName = -join($FirstName," ",$LastName)
$principalName = -join($adName,"@",$domainNameShort)
$emailAdd = -join($adName,"@domain.com")

# Generate the LogonWorkstations list
if ($Computer) {
    $Workstations = ($Computer)
}
else {
    $Workstations = ""
}

# Check to make sure the samaccountname/principal name is under 20 characters total so that they can log on properly
# This check will loop until the $adName provided is under 20 characters
While ($adName.Length -gt 20) {
    Write-Output "AD Name is too long, please enter a new name under 20 characters total."
    $adName = Read-Host "Shortened AD name"
}

# OU hashtable
$locOU = @{
    "AZ"            = "OU=AZ,";
    "CA"            = "OU=CA,";
    "NY"            = "OU=NY,";
    "PA"            = "OU=PA,";
    "remote"        = "OU=Remote,";
    "contractor"    = "OU=Contractor,"
}

# Look up the correct OU, Groups, and Gmail org for the user
$ouResult = $locOU[$location]

# Assemble the lookup data into a proper Distinguished Name
$fullOU = -Join($ouResult,$domainName)

# Output the account info in an easily usable format for new hire mailings
# TODO: Dig into the text formatting options to make this less ugly?
function NewHireMail {
    $infoTxt = "$displayName
$adName
Email: $adName@booker.com
Password for PC and Gmail: $adPass"

    $infoTxt | Out-File -FilePath "G:\My Drive\New Hires\$displayName.txt" -Append -NoClobber
}

# Keep a text log of users created via this script
function LogCreation {
    $logContent = "$adName created via NewHire script at $currTime by $adminName"
    $logContent | Out-File -FilePath "G:\My Drive\New Hires\BookerNewUserCreationLog.txt" -Append -NoClobber
}

# Creates the user's Gmail account and adds it to the basic office group for the location
function makeGAUser {

    $mailResult = @{
        "contractor"    = "Consultants"
        "consultants"   = "Consultants"
        "support"       = "Customer Experience Department"
        "executives"    = "Executives"
        "exec"          = "Executives"
        "finance"       = "Finance Department"
        "hr"            = "Human Resources"
        "marketing"     = "Marketing Department"
        "product"       = "Product Department"
        "sales"         = "Sales Department"
        "strategic"     = "Strategic Partnership"
        "tech"          = "Technology Department"
    }

    try {
        $googleAccountInfo = @{
            UserName                  = $adName
            GivenName                 = $FirstName
            FamilyName                = $LastName
            Password                  = $adPass
            ChangePasswordAtNextLogin = $true
            IncludeInDirectory        = $true
            OrgUnitPath               = "/$($mailResult[$department])"
        }
        New-GAUser @googleAccountInfo
        Write-Output "`nGoogle user $adName created."

        # Define the office mailing groups
        $mailGroups = @{
            "NY"     = "ny.office"
            "PA"     = "pa.office"
            "CA"     = "ca.office"
            "AZ"     = "az.office"
            "Remote" = "remote.employees"
        }

        # Feed the info to Grouper if they're not a contractor
        if ($location -ne "Contractor") {
            Grouper -users $adName -groups ($mailGroups.$location)
        }
    }
    catch {
        Write-Error "`n$_"
    }

}

# Generate user passwords
$adPass = Create-Password 10 uln
$secPass = $adPass | ConvertTo-SecureString -AsPlainText -Force

function ADCreation {
    # Check to make sure the user doesn't already exist in AD, if they don't, make the account.
    If (Get-ADUser -Filter { samaccountname -like $adName }) {
        Write-Output "User already exists in AD.`n"
        pressAnyKey
        Exit
    }
    else {
        try {
            $newUserInfo = @{
                name                  = $displayName
                GivenName             = $FirstName
                Surname               = $LastName
                SamAccountName        = $adname
                UserPrincipalName     = $principalName
                Path                  = $fullOU
                AccountPassword       = $secPass
                Enabled               = $true
                ChangePasswordAtLogon = $true
                EmailAddress          = $emailAdd
                LogonWorkstations     = $Workstations
            }

            Write-Output "Creating new AD user..."
            New-ADUser @newUserInfo -ErrorAction Stop
            Write-Output "$adName created.`n"
        }
        catch {
            Write-Error $_
        }

        # Make the Gmail account if we've flagged for it
        if ($makeGmail) {
            makeGAUser
        }

        #Get the mailing output
        NewHireMail

        # Write to the logfile and exit
        LogCreation
        pressAnyKey
        Exit  
    }
}

function checkOU {
    # Make sure the OU exists, or else the user creation function will fail
    if (Get-ADOrganizationalUnit -filter { distinguishedname -like $fullOU }) {
        ADCreation
    }
    # If the OU doesn't exist, see if we've added the "makeou" flag
    elseif (-not $makeou) {
        Write-Output "$fullOU does not exist."
        pressAnyKey
        Exit
    }
    elseif ($makeou) {
        try {
            $OUpathLength = ($fullOU.split(",")).count
            $newOUPath = ($fullOU.Split(",")[1..$OUpathLength]) -join ","
            New-ADOrganizationalUnit -name $hireDept -Path $newOUPath -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            ADCreation
        }
        catch {
            Write-Error $_
        }
    }
}

if ($NoAD) {
    $adpass = $NoAD
    # Check if we're creating the OSN account, run the related functions if so
    Write-Output "Creating text for new hire without making an AD account..."
        # Check Gmail flag
        if ($makeGmail) {
            makeGAUser
        }

        # Get the mailing output
        NewHireMail
        pressAnyKey
        Exit
}
else {
    checkOU
}
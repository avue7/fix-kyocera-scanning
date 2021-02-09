# AddZscanAndScansFolder
#
# This is a simple, interactive, powershell script to add the Zscan user that we use for our Kyocera printers. Once Zscan is 
# created it then attempts to add a new folder called Scans to the C drive root path. If one already exists, the user can 
# specify a new folder name. After creation of the shared folder, it will then add the neccessary permissions for the local
# user that has been created.
# 
# By: Athit Vue
# Date: 11/06/2020
# Last Updated: 12/16/2020

######################### SET-UP: ELEVATED ############################

# Sets up the script to run in elevated mode if not. This is to allow the batch script that is calling 
# this file to be able to run without it being in elevated mode. 

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; 
    exit 
}

######################### FUNCTION DEFINITIONS GOES HERE ################################

##
# ConfirmPassword
#
# Confirms if password is incorrect.
#
# @param <string> UserName The username to be created.
# @return <string> Password The confirmed password.
function ConfirmPassword($UserName) {
	$Password = Read-Host "	Enter $($UserName)'s password to create the account" -AsSecureString
	$ConfirmedPassword = Read-Host "	Confirm password" -AsSecureString
	
	$Password_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
	$ConfirmedPassword_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmedPassword))
	
	while ($Password_text -ne $ConfirmedPassword_text) {
		Write-Host "	Error: passwords do not match!" -fore red
		$Password = Read-Host "	Enter $($UserName)'s password to create the account" -AsSecureString
		$ConfirmedPassword = Read-Host "	Confirm password" -AsSecureString

		$Password_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
		$ConfirmedPassword_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmedPassword))

		if ($Password_text -eq $ConfirmedPassword_text) {
			break
		}	
	}
	return $Password
}

##
# PinToQuickAccess
#
# Pins the folder to the quick access toolbar.
#
# @param <string> FolderName the folder name of the folder to pin to the quick access toolbar. 
# @return <string> True or false if successful or not. 
function PinToQuickAccess($FolderName) {
  Try
  {
    Write-Host "        Pinning <$($FolderName)> folder to the 'Quick Access' toolbar..."
    $QA = New-Object -com Shell.Application -ErrorAction Stop
    $QA.Namespace("C:\$($FolderName)").Self.InvokeVerb("pintohome")
    Write-Host "        Successfully pinned <$($FolderName)> folder to the 'Quick Access' toolbar!" -fore Green
    Write-Host ""
  }
  Catch
  {
    Write-Host "        Error: cannot pin <$($FolderName)> folder to 'Quick Access' toolbar:" -fore Red
    Write-Host "        ==> $($_.Exception.Message)" -fore Red
    Write-Host ""
  }
}

##
# CreateNewLocalUser
#
# Creates a new local user to the local user group. First attempt will be hardcoded as Zscan. 
# If first attempt fails, user can then specify which user name. 
# 
# @param <string> UserName String name of the username
# @return <string> True or false if success or not
function CreateNewLocalUser($UserName) {
  Try
  {
	$Password = ConfirmPassword $UserName

    # I strongly not recommend it but if you insist and can keep this script secure you can 
    # hardcode the password below to make creations on multiple users' workstation a little quicker
    # by added your password in the quote below and uncommenting the prior line. 

    # $Password = ConvertTo-SecureString "" -AsPlainText -Force

	New-LocalUser $UserName -Password $Password -FullName "Kyocera Scanner" -Description "Local user account for Kyocera scanner." -ErrorAction Stop
	Write-Host " "
	return "true"
  }
  Catch
  {
	Write-Host "	Error: cannot create user <$($UserName)>: $($_.Exception.Message)" -fore red
	Write-Host " "
	return "false"
  }
}

##
# GetZscanLocalUser
#
# First method to run when script runs. Check and see if Zscan exists, if not automatically create him. 
# If account already exists need to return false to prompt what user would like to do. 
#
# @return <string> True or false True if zscan was created false if zscan already exists. 
function GetZscanLocalUser() {
  Try
  {
    $RetVal = Get-LocalUser -Name "Zscan" -ErrorAction Stop
    
    Write-Host "        Zscan user already exists!" -fore green
    return "false" 
  }
  Catch
  {
    Write-Host "        $($_.Exception.Message) Creating new Zscan user..." -fore red
    $RetVal = CreateNewLocalUser "Zscan"

    if ($RetVal -eq "true") {
        Write-Host "        New Zscan user created successfully!" -fore green
        return "true"
    } else {
        return "false"
    }
  }
}

##
# DeleteLocalUser
# 
# Deletes the local user account.
# 
# @param <string> UserName The string name of the local user account to delete.
# @return <string> True or false if deletion was successful or not.
function DeleteLocalUser($UserName) {
  Try
  {
	Remove-LocalUser -Name $UserName -ErrorAction Stop
	Write-Host " "
	Write-Host "	Deleted local user account <$($UserName)> successfully!" -fore green
	Write-Host " "
	return "true"
  }
  Catch
  {
	Write-Host "	Error: $($_.Exception.Message)" -fore red
	Write-Host " "
	return "false"	
  }
}

##
# CreateNewFolderInCDrive
# 
# Creates a new folder on the C drive. Argument first defaults to 'Scans' as folder name, then will 
# allow end-user to specify if 'Scans' folder already exist. 
# 
# @param <string> FolderName The name of the folder to be created
# @return <string> Returns string true or false if success or not
function CreateNewFolderInCDrive($FolderName) {
  Try
  {
    Write-Host "        Creating new <C:\$($FolderName)> folder..."
	New-Item -ItemType Directory -Path C:\$FolderName -ErrorAction Stop
	Write-Host "	New folder, <C:\$($FolderName)>, created successfully!" -fore green 
	return "true"
  }
  Catch 
  {
	Write-Host "	Error: $($_.Exception.Message)" -fore red

	$FolderItems = (Get-ChildItem C:\$FolderName | Measure-Object).Count 

	if($FolderItems -gt 0)
	{
		Write-Host "	==> The folder contains <$($FolderItems)> items." -fore red
	} elseif ($FolderItems -eq 0) {
		Write-Host "	==> The folder is empty." -fore red
	}
	
	Write-Host " "
	return "false"
  }
}

##
# CopyOverItemsToNewFolder
# 
# Copies over the items from Scans folder to new folder.
#
# @param <string> DestFolder The destination folder name
# @return <string> True or false if successful or not. 
function CopyOverItemsToNewFolder($OriginFolder, $DestFolder) {
  Try
  {
  	Copy-Item -Force -Recurse "C:\$($OriginFolder)\*" -Destination "C:\$($DestFolder)" -ErrorAction Stop
	Write-Host "	Successfully copied items from <C:\$($OriginFolder)> to <C:\$($DestFolder)>" -fore green
	return "true"	  
  }
  Catch
  {
	Write-Host "	Error:$($_.Exception.Message)" -fore red
	Write-Host " "
	return "false"
  }
}

##
# DeleteScansFolderInCDrive
#
# Deletes the Scans folder in root of C drive.
#
# @return <string> True or false if successful or not.
function DeleteScansFolderInCDrive($FolderName) {
  Try
  {
	Remove-Item "C:\$($FolderName)" -Recurse -ErrorAction Stop
    	Write-Host "	Successfully deleted the <C:\$($FolderName)> folder!" -fore Green
    	return "true"
  }
  Catch 
  {
    	Write-Host "	Error:$($_.Exception.Message)" -fore Red
    	Write-Host ""
    	return "false"
  }
}

##
# ShareFolderWithPermission
# 
# Shares a folder with permissions

# TODO: 1. See if we can do a new share folder by itself catch the error if any and send out. 
# 2. Next even if errors out we need to set the permission for the scans folder appropriately. 
# 3. Allow end-user to see all outputs one step at a time. 
function ShareFolder($FolderName, $NewUser) {
   Try
   {
        Write-Host "        Setting <$FolderName> folder as shared folder..."
        New-SmbShare -Name $FolderName -Path "C:\$($FolderName)" -ErrorAction Stop
        Write-Host "        Successfully set <$FolderName> folder as shared folder!" -fore Green
        Write-Host ""
        return "true"
   }
   Catch
   {
        Write-Host "        Error setting up <$($FolderName)> folder as a shared folder: $($_.Exception.Message)" -fore Red
        Write-Host ""
        return "false"
   }
}
##
# AddSecurityToSharedFolder
# 
# Adds the user to the shared folder in ACL.
#
# @param <string> FolderName The folder we need to add security allowance for.
# @param <string> NewUser The user to be added to the security allowance.
# @return <string> True or false if succeeded or not.
function AddSecurityToSharedFolder($FolderName, $NewUser) {
   Try
   {
        Write-Host "        Setting ACL Rules to <$($FolderName)> folder..."
        $ACL = Get-Acl "C:\$($FolderName)" -ErrorAction Stop
        $AR = New-Object System.Security.AccessControl.FileSystemAccessRule($($NewUser), "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow") -ErrorAction Stop
        $ACL.SetAccessRule($AR)
        Set-Acl "C:\$($FolderName)" $ACL -ErrorAction Stop
        Write-Host "        Successfully added ACL rules to the <$($FolderName)> folder!" -fore Green
        Write-Host ""
        return "true"
   }
   Catch 
   {
        Write-Host "        Error setting ACL security: $($_.Exception.Message)" -fore Red
        Write-Host ""
        return "false"
   }
}

##
# AddPermissionToShareFolder
#
# Adds permission to the shared folder.
#
# @param <string> $FolderName The name of the folder being shared.
# @param <string> $NewUser The user we want to give permissions to.
# @return <string> True or false if successfully set or not.
function AddPermissionToShareFolder($FolderName, $NewUser) {
   Try
   {
        Write-Host "        Setting permissions in shared folder <$($FolderName)> for user <$($NewUser)>..."
        Grant-SmbShareAccess -Name $FolderName -AccountName "$($env:COMPUTERNAME)\$($NewUser)" -AccessRight Full -Force -ErrorAction Stop
        Write-Host "        Successfully added permissions to the <$($FolderName)> folder for <$($NewUser)>!" -fore Green
        Write-Host " "

        $AddSecurityResponse = AddSecurityToSharedFolder $FolderName $NewUser

        if ($AddSecurityResponse -eq "true") {
            return "true"    
        } else {
            return "false"
        }
   }
   Catch 
   {
        Write-Host "        Error setting permissions to the <$($FolderName)> folder for user <$($NewUser)>!" -fore red
        Write-Host ""
        return "false"
   }
}

## 
# CheckForScansFolder
#
# Checks to see if scans folder already exist or not.
#
# @return <string> Returns true or false if scans folder already exist
function CheckForScansFolder() {
   Try
   {
        Test-Path C:\Scans -PathType Container -ErrorAction Stop
        Write-Host "        Scans folder already exists!" -fore green
        
        $FolderItems = (Get-ChildItem C:\Scans | Measure-Object).Count 

	    if($FolderItems -gt 0)
	    {
		    Write-Host "	==> The folder contains <$($FolderItems)> items." -fore green
	    } elseif ($FolderItems -eq 0) {
		    Write-Host "	==> The folder is empty." -fore green
    	}

        Write-Host ""
        return "true"
   }
   Catch
   {
        Write-Host "        Error: $($_.Exception.Message)" -fore red
        Write-Host ""
        return "false"
   }
}

##
# CreateScansShortCutOnDesktop
#
# Creates the scans or foldername shortcut for scanning on the desktop.
#
# @param <string> FolderName The foldername of the folder to create the shortcut for.
function CreateScansShortCutOnDesktop($FolderName) {
  Try 
  {
        Write-Host "        Creating shortcut on Desktop for the <$($FolderName)> folder..."
        $WshShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
        $Desktop = [System.Environment]::GetFolderPath('Desktop')
        $Lnk = $WshShell.CreateShortCut($Desktop+"\$($FolderName) - Shortcut.lnk")
        $Lnk.TargetPath = "C:\$($FolderName)"
        $Lnk.Save()

        Write-Host "        Successfully created shortcut for the <$($FolderName)> folder!" -fore Green
        Write-Host ""
  }
  Catch
  {
        Write-Host "        Error: Something happened can't create shortcut: $($_.Exception.Message)" -fore Red
        Write-Host ""
  }
}

##
# GetNetworkConnectionProfile
#
# This function will get the current connection that the computer is phyiscally connected to.
#
# @return <string> Returns the connection profile that the computer is connected to.
function GetNetworkConnectionProfile() {
  Try 
  {
        Write-Host "        Getting current network profile..."
        $NetworkProfile = Get-NetConnectionProfile | Select -ExpandProperty NetworkCategory -ErrorAction Stop
        return $NetworkProfile
  }
  Catch
  {
        Write-Host "        Error: Could not get connection profile: $($_.Exception.Message)" -fore Red
        Write-Host ""
        return "false"
  }
}

##
# ChangeNetworkProfileFromPublicToPrivate
#
# Changes the current network profile from public to private.
#
# @param <string> CurrentNetProfile
function ChangeNetworkProfileFromPublicToPrivate($CurrentNetProfile) {
  Try
  {
        $CurrentNetProfile = Set-NetConnectionProfile -NetworkCategory Private -PassThru | Select -ExpandProperty NetworkCategory -ErrorAction Stop 
        return $CurrentNetProfile     
  }
  Catch
  {
        Write-Host "        Error: Could not set network profile from PUBLIC to PRIVATE: $($_.Exception.Message)" -fore Red
        return "false"
  }
}

##
# SetFireWallRulesForFileAndPrinterSharing
#
# Enables the file and printer sharing at the firewall.
#
# @param <string> CurrentNetProfile The net profile(s) we want to turn on file
#                 and printer sharing for. 
# @param <string> ErrorCounter The counter for errors for final display.
# @return <string> True or false if enabled successfully or not. 
function SetFireWallRulesForFileAndPrinterSharing($CurrentNetProfile, $ErrorCounter) {
  Try
  {
        Write-Host "        Enabling 'File and Printer Sharing' for the <$($CurrentNetProfile)> profile(s)..."
        $EnableStatus = Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile $CurrentNetProfile -PassThru -ErrorAction Stop | Select -ExpandProperty Enabled
        Write-Host "        Successfully enabled 'File and Printer Sharing' for the <$($CurrentNetProfile)> profile(s)!" -fore Green
        Write-Host ""
        return $EnableStatus
  }
  Catch
  {
        Write-Host "        Error: enabling 'File and Printer Sharing' for <$($CurrentNetProfile)> profile(s) failed: $($_.Exception.Message)"
        $ErrorCounter = $ErrorCounter + 1
        Write-Host ""
        return "false"
  }
}

##
# TurnOnNetworkDiscovery
# 
# Turns on the network discovery for selected network profiles.
#
# @param <string> Profiles The profile or profiles that network discovery 
#                 should be turned on for.
# @param <string> ErrorCounter The counter for errors for final display.
# @return <string> True or false depending on if it was a success or not.
function TurnOnNetworkDiscovery($Profiles, $ErrorCounter) {
  Try 
  {
        Write-Host "        Enabling 'Turn on Network Discovery' for the <$($Profiles)> profile(s)..."
        $EnableStatus = Set-NetFireWallRule -DisplayGroup "Network Discovery" -Enabled True -Profile $Profiles -PassThru -ErrorAction Stop | Select -ExpandProperty Enabled 
        Write-Host "        Successfully enabled 'Turn on Network Discovery' for the <$($Profiles)> profile(s)!" -fore Green
        Write-Host ""
        return $EnableStatus
  }
  Catch
  {
        Write-Host "        Error: enabling 'Turn on Network Discovery' for <$($Profiles)> profile(s) failed: $($_.Exception.Message)"
        $ErrorCounter = $ErrorCounter + 1
        Write-Host ""
        return "false"  
  }
}

##########################################################################################

Write-Host ""
Write-Host "        #### Welcome! This script is to help re-apply the settings we have made on this computer" -fore green
Write-Host "        #### in order for the Kyocera scanner to scan to this computer." -fore green

Write-Output ""

Read-Host -Prompt "	Press <Enter> to continue..."

##### GLOBAL VARIABLES ######
$NewUser = "Zscan"
$FolderName = "Scans"
$ErrorCounter = 0
#############################

# CREATE THE LOCAL USER 

$Counter = 0
$RetVal = ""

Write-Host "        ########################### ZSCAN CREATION #############################" -fore DarkCyan
Write-Host ""

$RetVal = GetZscanLocalUser
Write-Host ""

if ($RetVal -eq "true") {
	Write-Host "	Local user $($NewUser) was created successfully!" -fore green
	
	# Ensure user password never expires. 
	try 
	{
		Set-LocalUser -Name $NewUser -PasswordNeverExpires $true -ErrorAction Stop
		Write-Host "	--> Successfully set PasswordNeverExpires to true" -fore green
	}
	Catch
	{
		Write-Host "	Error: $($_.Exception.Message)" -fore red
	}
	# Ensure user cannot change password
	try
	{
		Set-LocalUser -Name $NewUser -UserMayChangePassword $false -ErrorAction Stop
		Write-Host "	--> Successfully set UserMayChangePassword to false" -fore green
	}
	Catch
	{
		Write-Host "	Error: $($_.Exception.Message)" -fore red
	}
	# Ensure account never expires
	try
	{
		Set-LocalUser -Name $NewUser -AccountNeverExpires -ErrorAction Stop
		Write-Host "	--> Successfully set AccountNeverExpires" -fore green
	}
	Catch
	{
		Write-Host "	Error: $($_.Exception.Message)" -fore red
	}
    Write-Host ""
}

Write-Host "        ############################ SCANS FOLDER ##############################" -fore DarkCyan
Write-Host " "

# CREATE THE SCANS FOLDER
$CreateNewFolderRetVal = CreateNewFolderInCDrive $FolderName

if ($CreateNewFolderRetVal -eq "true") {
    write-Host " " 
    $CreateNewFolderRetVal = ShareFolder $FolderName $NewUser

    # If share folder success we can then set permissions
    if ($CreateNewFolderRetVal -eq "true") {	
        Write-Host "        ########################## FOLDER PERMISSIONS ##########################" -fore DarkCyan
        Write-Host ""
        $CreateNewFolderRetVal = AddPermissionToShareFolder $FolderName $NewUser
    } 
} else { 	
    Write-Host "        ########################## FOLDER PERMISSIONS ##########################" -fore DarkCyan
    Write-Host ""
    
    Write-Host "        Attempting to re-apply the correct permission settings for the <$($FolderName)> folder..."
    Write-Host ""
    
    $AddPermResponse = AddPermissionToShareFolder $FolderName $NewUser

    # Pointless to go on if permission cannot be set to shared folder
    if ($AddPermResponse -eq "false") {
        Write-Host ""
        Write-Host "        Sorry, I could not set permission to <$(FolderName)> folder. It is pointless to continue." -fore Red
        Write-Host "        Please call us at (530) 893 - 8714. Thank you!" -fore Red

        $Quit = Read-Host -Prompt "        Press (q) to quit..."
        Write-Host ""

        while ($Quit -ne "q" -Or $Quit -ne "Q") {
            $Quit = Read-Host -Prompt "        Press (q) to quit..."
            Write-Host ""
        }
    }
}


Write-Host "        ########################### SCANS SHORTCUT #############################" -fore DarkCyan
Write-Host ""

# Create shortcut for scans folder
CreateScansShortCutOnDesktop $FolderName
# Pin to quick access toolbar
PinToQuickAccess $FolderName

Write-Host "        ########################## NETWORK SETTINGS ############################" -fore DarkCyan
Write-Host ""

# Grab the computer's ipv4 address
$ComputerIP = Test-Connection ::1 -Cou 1 | select -ExpandProperty IPV4Address

# Get the current profile connection that the printer is connected to
$CurrentNetProfile = GetNetworkConnectionProfile

# Switch network profile to private if on public
if ($CurrentNetProfile -eq "false") {
    $ErrorCounter = $ErrorCounter + 1
} elseif ($CurrentNetProfile -eq "DomainAuthenticated" -Or $CurrentNetProfile -eq "Private") {
    Write-Host "        Current network profile is: <$($CurrentNetProfile)>. No need to switch profile!" -fore Green
} elseif ($CurrentNetProfile -eq "Public") { 
    # if network profile is public we must switch it to private
    Write-Host "        Current network profile is: <$($CurrentNetProfile)>. Switching profile to Private..."
    $CurrentNetProfile = ChangeNetworkProfileFromPublicToPrivate $CurrentNetProfile

    if ($CurrentNetProfile -eq "Private") {
        Write-Host "        Successfully switched network profile from <Public> to <Private>!" -fore Green
    } else {
        $ErrorCounter = $ErrorCounter + 1
        Write-Host "        Error: Could not switched network profile to Private: $($CurrentNetProfile)" -fore Red
    }
}

Write-Host ""

$FileAndPrinterSharingStatus = ""

# Check file and printer sharing for all profiles in the firewall.

$IncludeDomainProfile = $false
$IncludePrivateProfile = $false

# Enable for private and domain profiles if not set. 
if ($CurrentNetProfile -eq "DomainAuthenticated") {
    $IncludeDomainProfile = $true
    $IncludePrivateProfile = $true
} elseif ($CurrentNetProfile -eq "Private") {
    $IncludePrivateProfile = $true
}

if ($IncludeDomainProfile -and $IncludePrivateProfile) {
    $FileAndPrinterSharingStatus = SetFireWallRulesForFileAndPrinterSharing "Domain, Private" $ErrorCounter        
} elseif ($IncludePrivateProfile) {
    $FileAndPrinterSharingStatus = SetFireWallRulesForFileAndPrinterSharing "Private" $ErrorCounter
}

# Enable network discovery

$EnableNetworkDiscoveryStatus = $false

$IncludeDomainProfile = $false
$IncludePrivateProfile = $false
$IncludePublicProfile = $false

if ($CurrentNetProfile -eq "DomainAuthenticated") {
    $IncludeDomainProfile = $true
    $IncludePrivateProfile = $true
} elseif ($CurrentNetProfile -eq "Private") {
    $IncludePrivateProfile = $true
}
    
if ($IncludeDomainProfile -and $IncludePrivateProfile) {
    $EnableNetworkDiscoveryStatus = TurnOnNetworkDiscovery "Domain, Private" $ErrorCounter
} elseif ($IncludePrivateProfile) {
    $EnableNetworkDiscoveryStatus = TurnOnNetworkDiscovery "Private" $ErrorCounter
}

# Add to counter if any status is false
if ($FileAndPrinterSharingStatus -ne "true" -Or $EnableNetworkDiscoveryStatus -ne "true") {
    $ErrorCounter = $ErrorCounter + 1
}

Write-Host "        ########################################################################" -fore DarkCyan

Write-Host ""
Write-Host ""
Write-Host "        ========================================================================" -fore Red           
Write-Host "        ^_^_^_^_^_^_^_^_^_^_^_^_^_^ SCRIPT COMPLETED ^_^_^_^_^_^_^_^_^_^_^_^_^_^" -fore Yellow
Write-Host "        ========================================================================" -fore Red           
Write-Host ""
Write-Host "        Please use the following for the address book entry for this computer:" -fore DarkCyan
Write-Host ""
Write-Host "        SMB:" -fore DarkCyan
Write-Host "        ====> Host Name: " -NoNewLine -fore Green 
Write-Host "$($env:COMPUTERNAME)" -NoNewLine -fore Yellow
Write-Host " or " -NoNewLine -fore Green 
Write-Host "$($ComputerIP)" -fore Yellow
Write-Host "        ====> Port Number: " -NoNewLine -fore Green
Write-Host "445" -NoNewline -fore Yellow
Write-Host " or " -NoNewLine -for Green
Write-Host "139" -fore Yellow
Write-Host "        ====> Login User Name: " -NoNewLine -fore Green
Write-Host "$($NewUser)" -fore Yellow
Write-Host "        ====> Login Password: " -NoNewline -fore Green
Write-Host "(not display for security purpose)" -fore Yellow
Write-Host " "
Write-Host " "

####################### PUT ERRORS THAT REQUIRE MANUAL CHECKING HERE ##########################

if ($ErrorCounter > 0) {
    Write-Host "        ERRORS that need manual checking:" -fore Red
    # For network profile checking and switching.
    if ($CurrentNetProfile -ne "Private" -Or $CurrentNetProfile -ne "DomainAuthenticated") {
        Write-Host "        ====> Error: I was unable to help you switch the 'Network Profile' from 'Public' to 'Private'. " -fore Red
        Write-Host "                     You can change the profile to 'Private' by clicking on the Internet Icon near the clock. " -fore Red
        Write-Host "                     Then the network connection (SSID) where it says 'Connected' to change this." -fore Red
    }

    # For unable to enable file and printer sharing 
    if ($FileAndPrinterSharingStatus -eq "false") {
        Write-Host "        ====> Error: I had trouble enabling the 'File and Printer Sharing' allowance for this computer." -fore Red
        Write-Host "                     Please check the 'Advanced Sharing Settings' or 'Firewall' to allow for 'File and Printer Sharing'." -fore Red
    }

    # For unable to enable network discovery
    if ($EnableNetworkDiscoveryStatus -eq "false") {
        Write-Host "        ====> Error: I had trouble enabling the 'Turn on Network Discovery' allowance for this computer." -fore Red
        Write-Host "                     Please check the 'Advanced Sharing Settings" or "Firewall" to allow for "Turn on Network Discovery." -fore Red 
    }

    Write-Host ""
    Write-Host ""
}

Write-Host "        You may now scan a test page to this computer to see if scanning has resume." -fore Yellow
Write-Host ""
Write-Host "        If you still can't scan to this computer, please give us a call at: (530) 893-8714" -fore Yellow
Write-Host ""
Write-Host ""
Write-Host "        ========================================================================" -fore Red
Write-Host "        <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>" -fore Yellow
Write-Host "        ========================================================================" -fore Red          
Write-Host ""
Write-Host ""

Write-Host "        Current execution policy: " -NoNewline
#Set-ExecutionPolicy Restricted
Write-Host "$(Get-ExecutionPolicy)." -fore Yellow
Write-Host ""

#Write-Host "        Please note: " -fore Yellow
#Write-Host "        if you don't want to allow scripts to run on this computer,"
#Write-Host "        run command 'Get-ExecutionPolicy' in elevated-mode in PowerShell."
#Write-Host "        If return is other than 'Restricted', then in elevated-mode in PowerShell"
#Write-Host "        run 'Set-ExecutionPolicy Restricted'. This feature of Windows is not meant" 
#Write-Host "        to be a security system that restricts user actions. Instead it acts to set"
#Write-Host "        basic rules so users do not voilate them unintentionally."
#Write-Host " " 

$Quit = Read-Host -Prompt "        Press (q) to quit..."
Write-Host ""

while ($Quit -ne "q" -Or $Quit -ne "Q") {
   $Quit = Read-Host -Prompt "        Press (q) to quit..."
   Write-Host ""
}
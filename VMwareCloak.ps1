#################################################
## VMwareCloak.ps1: A script that attempts to hide the VMware Workstation hypervisor from malware by modifying registry keys, killing associated processes, and removing uneeded driver/system files.
## Written and tested on Windows 7 and Windows 10. Should work for Windows 11 as well!
## Many thanks to pafish for some of the ideas - https://github.com/a0rtega/pafish
##################################################
## Author: d4rksystem (Kyle Cucci)
## Version: 0.4
##################################################

# Define command line parameters
param (
    [switch]$all = $false,
    [switch]$reg = $false,
    [switch]$procs = $false,
    [switch]$files = $false
)

if ($all) {
    $reg = $true
    $procs = $true
    $files = $true
}

# Menu / Helper stuff
Write-Output ""
Write-Output "VMwareCloak.ps1 by @d4rksystem (Kyle Cucci)"
Write-Output "Usage: VMwareCloak.ps1 -<option>"
Write-Output "Example Usage: VMwareCloak.ps1 -all"
Write-Output "Options:"
Write-Output "all: Enable all options."
Write-Output "reg: Make registry changes."
Write-Output "procs: Kill processes."
Write-Output "files: Make file system changes."
Write-Output "Tips: Run as System or you will get a lot of errors!"
Write-Output "Warning: Only run in a virtual machine!"
Write-Output "*****************************************"
Write-Output ""

# -------------------------------------------------------------------------------------------------------
# Define random string generator function

function Get-RandomString {

    $charSet = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
    
    for ($i = 0; $i -lt 10; $i++ ) {
        $randomString += $charSet | Get-Random
    }

    return $randomString
}

# -------------------------------------------------------------------------------------------------------
# Stop VMware Processes

$process_list = "vmtoolsd", "vm3dservice", "VGAuthService", "VMwareService", "Vmwaretray", "Vmwareuser", "TPAutoConnSvc"

if ($procs) {

    Write-Output '[*] Attempting to kill VMware processes...'

    foreach ($p in $process_list) {

        $process = Get-Process "$p" -ErrorAction SilentlyContinue

        if ($process) {
            $process | Stop-Process -Force
            Write-Output "[*] $p process killed!"
        }

        if (!$process) {
            Write-Output "[!] $p process does not exist!"
        }
     }        
}

# -------------------------------------------------------------------------------------------------------
# Modify VMware registry keys

if ($reg) {

   # Remove or rename VMware-related registry keys

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System" -Name "SystemBiosVersion" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\DESCRIPTION\System\SystemBiosVersion..."
        Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System" -Name "SystemBiosVersion" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\DESCRIPTION\System\SystemBiosVersion does not seem to exist! Skipping this one...'
    }

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "BIOSVendor" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\DESCRIPTION\System\BIOS\BIOSVendor..."
	Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "BIOSVendor" -Value "American Megatrends International, LLC."

     } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\DESCRIPTION\System\BIOS\BIOSVendor does not seem to exist! Skipping this one...'
    }

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "BIOSVersion" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\DESCRIPTION\System\BIOS\BIOSVersion..."
        Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "BIOSVersion" -Value  1.70

     } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\DESCRIPTION\System\BIOS\BIOSVersion does not seem to exist! Skipping this one...'
    }

    if (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "SystemManufacturer" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\DESCRIPTION\System\BIOS\SystemManufacturer..."
        Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "SystemManufacturer" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\DESCRIPTION\System\BIOS\SystemManufacturer does not seem to exist! Skipping this one...'
    }
	
	if (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "SystemProductName" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\DESCRIPTION\System\BIOS\SystemProductName..."
        Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\BIOS" -Name "SystemProductName" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\DESCRIPTION\System\BIOS\SystemProductName does not seem to exist! Skipping this one...'
    }
	
	if (Get-ItemProperty -Path "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -Name "Identifier" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier..."
        Set-ItemProperty -Path "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -Name "Identifier" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier does not seem to exist! Skipping this one...'
    }

	if (Get-ItemProperty -Path "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -Name "Identifier" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier..."
        Set-ItemProperty -Path "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -Name "Identifier" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier does not seem to exist! Skipping this one...'
    }

	if (Get-ItemProperty -Path "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -Name "Identifier" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier..."
        Set-ItemProperty -Path "HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -Name "Identifier" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier does not seem to exist! Skipping this one...'
    }
	
	if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinSAT" -Name "PrimaryAdapterString" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinSAT\PrimaryAdapterString..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinSAT\" -Name "PrimaryAdapterString" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinSAT\PrimaryAdapterString does not seem to exist! Skipping this one...'
    }
	
	if (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\SystemInformation" -Name "SystemManufacturer" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\Control\SystemInformation\SystemManufacturer..."
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\SystemInformation" -Name "SystemManufacturer" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\ControlSet001\Control\SystemInformation\SystemManufacturer does not seem to exist! Skipping this one...'
    }
	
	if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "SystemManufacturer" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation\SystemManufacturer..."
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "SystemManufacturer" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation\SystemManufacturer does not seem to exist! Skipping this one...'
    }
	
	if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "SystemProductName" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation\SystemProductName..."
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "SystemProductName" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation\SystemProductName does not seem to exist! Skipping this one...'
    }

	if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\disk\Enum" -Name "0" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\CurrentControlSet\Services\disk\Enum\0..."
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\disk\Enum" -Name "0" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\CurrentControlSet\Services\disk\Enum\0 does not seem to exist! Skipping this one...'
    }	
	
	if (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\SystemInformation" -Name "SystemProductName" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\Control\SystemInformation\SystemProductName..."
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\SystemInformation" -Name "SystemProductName" -Value  $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\ControlSet001\Control\SystemInformation\SystemProductName does not seem to exist! Skipping this one...'
    }
		
   if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VMware User Process" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Removing Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VMware User Process..."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VMware User Process"

     } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VMware User Process does not seem to exist! Skipping this one...'
    }

    if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VMware VM3DService Process" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Removing Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VMware VM3DService Process..."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VMware VM3DService Process"

     } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VMware VM3DService Process does not seem to exist! Skipping this one...'
    }

    if (Get-ItemProperty -Path "HKLM:\SOFTWARE\RegisteredApplications" -Name "VMware Host Open" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Removing Reg Key HKLM:\SOFTWARE\RegisteredApplications\VMware Host Open"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\RegisteredApplications" -Name "VMware Host Open"

    } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\RegisteredApplications\VMware Host Open does not seem to exist, or has already been renamed! Skipping this one...'
    }

    if (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\RegisteredApplications" -Name "VMware Host Open" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Removing Reg Key HKLM:\SOFTWARE\WOW6432Node\RegisteredApplications\VMware Host Open"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\RegisteredApplications" -Name "VMware Host Open"

    } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\WOW6432Node\RegisteredApplications\VMware Host Open does not seem to exist, or has already been renamed! Skipping this one...'
    }
	
	if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration" -Name "OEMID" -ErrorAction SilentlyContinue) {

	Write-Output "[*] Modifying Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration\OEMID"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration" -Name "OEMID" -Value $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration\OEMID does not seem to exist, or has already been renamed! Skipping this one...'
    }
	
	if (Get-Item -Path "HKLM:\SOFTWARE\VMware, Inc." -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SOFTWARE\VMware, Inc."
        Rename-Item -Path "HKLM:\SOFTWARE\VMware, Inc." -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\VMware, Inc. does not seem to exist, or has already been renamed! Skipping this one...'
    }
	
	if (Get-Item -Path "HKLM:\SOFTWARE\Classes\Applications\VMwareHostOpen.exe" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Modifying Reg Key HKLM:\SOFTWARE\Classes\Applications\VMwareHostOpen.exe"
        Rename-Item -Path "HKLM:\SOFTWARE\Classes\Applications\VMwareHostOpen.exe" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\Classes\Applications\VMwareHostOpen.exe does not seem to exist, or has already been renamed! Skipping this one...'
    }

    if (Get-Item -Path "HKLM:\SOFTWARE\Classes\VMwareHostOpen.AssocURL" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Modifying Reg Key HKLM:\SOFTWARE\Classes\VMwareHostOpen.AssocURL"
        Rename-Item -Path "HKLM:\SOFTWARE\Classes\VMwareHostOpen.AssocURL" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\Classes\VMwareHostOpen.AssocURL does not seem to exist, or has already been renamed! Skipping this one...'
    }

    if (Get-Item -Path "HKLM:\SOFTWARE\Classes\VMwareHostOpen.AssocFile" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Modifying Reg Key HKLM:\SOFTWARE\Classes\VMwareHostOpen.AssocFile"
        Rename-Item -Path "HKLM:\SOFTWARE\Classes\VMwareHostOpen.AssocFile" -NewName $(Get-RandomString)

    } Else {

        Write-Output '[!] Reg Key HKLM:\SOFTWARE\Classes\VMwareHostOpen.AssocFile does not seem to exist, or has already been renamed! Skipping this one...'
    }
	
	if (Get-Item -Path "HKLM:\SYSTEM\ControlSet001\Services\VGAuthService" -ErrorAction SilentlyContinue) {

        Write-Output "[*] Renaming Reg Key HKLM:\SYSTEM\ControlSet001\Services\VGAuthService..."
        Rename-Item -Path "HKLM:\SYSTEM\ControlSet001\Services\VGAuthService" -NewName $(Get-RandomString)

     } Else {

        Write-Output '[!] Reg Key HKLM:\SYSTEM\ControlSet001\Services\VGAuthService does not seem to exist! Skipping this one...'
    }
}

# -------------------------------------------------------------------------------------------------------
# Rename VMware Files

if ($files) {
	
	# Rename VMware directories

	Write-Output "[*] Attempting to rename C:\Program Files\Common Files\VMware directory..."

    	$VMwareCommonFiles = "C:\Program Files\Common Files\VMware"

    	if (Test-Path -Path $VMwareCommonFiles) {
        	Rename-Item $VMwareCommonFiles "C:\Program Files\Common Files\$(Get-RandomString)"
   	 }

    	else {
			Write-Output "[!] C:\Program Files\Common Files\VMware directory does not exist!"
    	}

    	Write-Output "[*] Attempting to rename C:\Program Files\VMware directory..."

    	$VMwareProgramDir = "C:\Program Files\VMware"

    	if (Test-Path -Path $VMwareProgramDir) {
        	Rename-Item $VMwareProgramDir "C:\Program Files\$(Get-RandomString)"
    	}

     	else {
        	Write-Output "[!] C:\Program Files\VMware directory does not exist!"
   	}
	
	# Rename VMware driver files

    Write-Output "[*] Attempting to rename VMware driver files in C:\Windows\System32\drivers\..."
	
	$path = "C:\Windows\System32\drivers\"
	
	$file_list ="vmhgfs.sys",
		"vmmemctl.sys",
		"vmmouse.sys",
		"vmrawdsk.sys",
		"vmusbmouse.sys"
	
    	foreach ($file in $file_list) {

		Write-Output "[*] Attempting to rename $file..."
		
		try {
			# We are renaming these files, as opposed to removing them, because Windows doesn't care if we just rename them :)
			Rename-Item "$path$file" "$path$(Get-RandomString).sys" -ErrorAction Stop
		}
		
		catch {
			Write-Output "[!] File does not seem to exist! Skipping..."
		}
	}

	$wildcardPattern = "vm3*.sys"
	$filesToRename = Get-ChildItem -Path $path -Filter $wildcardPattern
	
	foreach ($file in $filesToRename) {
   
    		Write-Output "[*] Attempting to rename $file..."
			Rename-Item "$path$file" "$path$(Get-RandomString).dll"
	}
	
	# Rename VMware system files (System32)
	
    Write-Output "[*] Attempting to rename DLL files in C:\Windows\System32\..."
	
	$path = "C:\Windows\System32\"
	
	$file_list = "vmhgfs.dll", "VMWSU.DLL"

    	foreach ($file in $file_list) {

		Write-Output "[*] Attempting to rename $file..."
		
		try {
			Rename-Item "$path$file" "$path$(Get-RandomString).dll" -ErrorAction Stop
		}
		
		catch {
			Write-Output "[!] File does not seem to exist! Skipping..."
		}
	}
	
	$wildcardPattern1 = "vm3*.dll"
	$wildcardPattern2 = "vmGuestLib*.dll"
	
	$filesToRename1 = Get-ChildItem -Path $path -Filter $wildcardPattern1
	$filesToRename2 = Get-ChildItem -Path $path -Filter $wildcardPattern2
	
	foreach ($file in $filesToRename1) {
   
    		Write-Output "[*] Attempting to rename $file..."
    		Rename-Item "$path$file" "$path$(Get-RandomString).dll"
	}
	
	foreach ($file in $filesToRename2) {
   
    		Write-Output "[*] Attempting to rename $file..."
    		Rename-Item "$path$file" "$path$(Get-RandomString).dll"
	}
	
	# Rename VMware system files (SysWOW64)
	
    Write-Output "[*] Attempting to rename system files in C:\Windows\SysWOW64\..."
	
	$path = "C:\Windows\SysWOW64\"
	
	$file_list = "vmhgfs.dll", "VMWSU.DLL"

    	foreach ($file in $file_list) {

		Write-Output "[*] Attempting to rename $file..."
		
		try {
			Rename-Item "$path$file" "$path$(Get-RandomString).dll" -ErrorAction Stop
		}
		
		catch {
			Write-Output "[!] File does not seem to exist! Skipping..."
		}
	}
	
	$wildcardPattern1 = "vm3*.dll"
	$wildcardPattern2 = "vmGuestLib*.dll"
	
	$filesToRename1 = Get-ChildItem -Path $path -Filter $wildcardPattern1
	$filesToRename2 = Get-ChildItem -Path $path -Filter $wildcardPattern2
	
	foreach ($file in $filesToRename1) {
   
    		Write-Output "[*] Attempting to rename $file..."
    		Rename-Item "$path$file" "$path$(Get-RandomString).dll"
	}
	
	foreach ($file in $filesToRename2) {
   
    		Write-Output "[*] Attempting to rename $file..."
    		Rename-Item "$path$file" "$path$(Get-RandomString).dll"
	}
}
	
Write-Output ""
Write-Output "** Done!" 
Write-Output "** Did you recieve a lot of access errors? You should run as System!"
Write-Output "** Spot any bugs or issues? DM me on Twitter or open an issues on Github! :)"


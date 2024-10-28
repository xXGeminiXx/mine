# Shotgun Approach: COD6 Ultimate Fixer Script
# Comprehensive Troubleshooting Script for COD Black Ops 6

# Define the total number of sections
$totalSections = 21

# Set up logging
$logFile = "$PSScriptRoot\COD6_Troubleshooting_Log.txt"
Start-Transcript -Path $logFile -Append

# Ensure the script is running with elevated permissions
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator."
    Stop-Transcript
    Exit
}

# Function to prompt for each task
Function Prompt-Task {
    param([string]$Message)
    do {
        $response = Read-Host "$Message (Y/N)"
    } while ($response -notmatch "^[yYnN]$")
    Return ($response -match "^[yY]$")
}

# Function to write section headers
Function Write-Section {
    param([int]$sectionNumber, [string]$sectionTitle)
    Write-Host ""
    Write-Host "=== Section $sectionNumber of ${totalSections}: $sectionTitle ===" -ForegroundColor Cyan
}

# Section 1: Create a System Restore Point
$sectionNumber = 1
$sectionTitle = "Create a System Restore Point"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Creating a system restore point..."
    try {
        Checkpoint-Computer -Description "COD6 Troubleshooting Restore Point" -RestorePointType "MODIFY_SETTINGS"
        Write-Host "System restore point created successfully."
    } catch {
        Write-Warning "Failed to create a system restore point. You may need to enable System Protection."
    }
}

# Section 2: Reinstall Windows Store and Xbox App Components
$sectionNumber++
$sectionTitle = "Reinstall Windows Store and Xbox App components"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Resetting Windows Store and Xbox app components..."

    # Uninstall Microsoft Store and Xbox App packages
    Get-AppxPackage -AllUsers Microsoft.WindowsStore | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.XboxApp | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.GamingApp | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers Microsoft.XboxGamingOverlay | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

    # Reinstall Microsoft Store package
    $storePackagePath = "C:\Windows\SystemApps\Microsoft.WindowsStore_*"
    $storePackage = Get-ChildItem -Path $storePackagePath -Directory | Select-Object -First 1
    if ($storePackage) {
        Add-AppxPackage -DisableDevelopmentMode -Register "$($storePackage.FullName)\AppxManifest.xml" -ErrorAction SilentlyContinue
    } else {
        Write-Warning "Microsoft.WindowsStore package not found."
    }

    # Reinstall Xbox App packages
    $xboxPackages = Get-ChildItem "C:\Program Files\WindowsApps\" -Directory | Where-Object { $_.Name -like "Microsoft.Xbox*" -or $_.Name -like "Microsoft.GamingApp*" }
    foreach ($package in $xboxPackages) {
        $appxManifest = "$($package.FullName)\AppxManifest.xml"
        if (Test-Path $appxManifest) {
            Add-AppxPackage -DisableDevelopmentMode -Register $appxManifest -ErrorAction SilentlyContinue
        } else {
            Write-Warning "AppxManifest.xml not found for package: $($package.Name)"
        }
    }

    # Clear Store cache
    wsreset.exe

    Write-Host "Windows Store and Xbox components reset completed."
}

# Section 3: Ensure C:\ Drive is Decompressed
$sectionNumber++
$sectionTitle = "Ensure C:\ drive is decompressed"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Checking and decompressing C:\ if needed..."
    
    # Suppress errors and access denied messages
    $compactProcess = Start-Process -FilePath "compact.exe" -ArgumentList "/u /a /f /s:C:\" -RedirectStandardError "$null" -NoNewWindow -Wait -ErrorAction SilentlyContinue
    
    Write-Host "Drive decompression checked and applied where necessary."
}

# Section 4: Set Broad Permissions for Folders
$sectionNumber++
$sectionTitle = "Set broad permissions for 'C:\Games' and temp folders"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Setting broad permissions on 'C:\Games' and temp folders..."

    $paths = @(
        "C:\Games",
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            # Set full control permissions for Everyone
            icacls $path /grant 'Everyone:(OI)(CI)F' /T /C | Out-Null
            Write-Host "Permissions set for $path."
        } else {
            Write-Warning "$path not found."
        }
    }

    Write-Host "Permissions verified and set."
}

# Section 5: Check and Adjust Antivirus Settings
$sectionNumber++
$sectionTitle = "Check for antivirus software that may interfere"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Checking for antivirus software..."

    # Check for third-party antivirus products
    try {
        $antivirusProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    } catch {
        Write-Warning "Failed to query antivirus products: $_"
        $antivirusProducts = @()
    }

    if ($antivirusProducts -and $antivirusProducts.Count -gt 0) {
        foreach ($av in $antivirusProducts) {
            Write-Host "Detected antivirus software: $($av.displayName)"
            if (Prompt-Task "Would you like to exclude Call of Duty folders from $($av.displayName) scanning?") {
                Write-Host "Please manually add exclusions in $($av.displayName) for the following paths:"
                Write-Host "C:\Games"
                Write-Host "$env:ProgramFiles\WindowsApps"
            }
        }
    } else {
        Write-Host "No third-party antivirus software detected."
    }

    # Check for Windows Defender
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        Write-Host "Windows Defender is enabled."
        if (Prompt-Task "Would you like to exclude Call of Duty folders from Windows Defender scanning?") {
            # Add exclusions to Windows Defender
            Add-MpPreference -ExclusionPath "C:\Games", "$env:ProgramFiles\WindowsApps"
            Write-Host "Exclusions added to Windows Defender."
        }
    } catch {
        Write-Warning "Windows Defender may not be available or you do not have the necessary permissions."
    }

    Write-Host "Antivirus check completed."
}

# Section 6: Check for and Uninstall Potentially Conflicting Software
$sectionNumber++
$sectionTitle = "Check for and uninstall potentially conflicting software"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Scanning for potentially conflicting software..."

    $conflictingSoftware = @(
        "MSI Afterburner",
        "RivaTuner Statistics Server",
        "Discord",
        "Overwolf",
        "EVGA Precision X",
        "NZXT CAM",
        "ASUS GPU Tweak",
        "Logitech Gaming Software",
        "SteelSeries Engine",
        "OBS Studio",
        "XSplit",
        "Game Bar"
    )

    foreach ($software in $conflictingSoftware) {
        $app = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%$software%'" -ErrorAction SilentlyContinue
        if ($app) {
            Write-Warning "Found installed software: $($app.Name)"
            if (Prompt-Task "Do you want to uninstall $($app.Name)?") {
                Write-Host "Uninstalling $($app.Name)..."
                $app.Uninstall() | Out-Null
                Write-Host "$($app.Name) has been uninstalled."
            }
        }
    }

    Write-Host "Conflicting software check completed."
}

# Section 7: Adjust Virtual Memory Settings
$sectionNumber++
$sectionTitle = "Adjust virtual memory settings"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Adjusting virtual memory settings..."

    # Get system drive (usually C:)
    $systemDrive = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty SystemDrive

    # Set virtual memory to system managed size
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-ItemProperty -Path $RegPath -Name "PagingFiles" -Value "$systemDrive\pagefile.sys 0 0"

    Write-Host "Virtual memory settings adjusted to system-managed size."
}

# Section 8: Check for Overclocking
$sectionNumber++
$sectionTitle = "Check for CPU and GPU overclocking settings"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Checking for overclocking settings..."

    # Check CPU overclocking using WMI
    $cpuClock = Get-WmiObject -Namespace "root\cimv2" -Class Win32_Processor | Select-Object -First 1 -Property MaxClockSpeed, CurrentClockSpeed
    If ($cpuClock.MaxClockSpeed -ne $cpuClock.CurrentClockSpeed) {
        Write-Warning "CPU may be overclocked. Max Clock Speed: $($cpuClock.MaxClockSpeed) MHz, Current Clock Speed: $($cpuClock.CurrentClockSpeed) MHz"
    } Else {
        Write-Host "CPU is running at stock speeds."
    }

    # Check GPU overclocking (NVIDIA only)
    $nvidiaSmiPath = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    If (Test-Path $nvidiaSmiPath) {
        $gpuData = & $nvidiaSmiPath --query-gpu=clocks.max.graphics,clocks.current.graphics --format=csv,noheader,nounits
        $gpuClocks = $gpuData -split ","
        If ($gpuClocks[0] -ne $gpuClocks[1]) {
            Write-Warning "GPU may be overclocked. Max Graphics Clock: $($gpuClocks[0]) MHz, Current Graphics Clock: $($gpuClocks[1]) MHz"
        } Else {
            Write-Host "GPU is running at stock speeds."
        }
    } Else {
        Write-Host "GPU overclocking check is not available or GPU is not NVIDIA."
    }

    Write-Host "Overclocking check completed."
}

# Section 9: Install/Repair Microsoft Visual C++ Redistributables
$sectionNumber++
$sectionTitle = "Install or repair Microsoft Visual C++ Redistributables"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Installing Microsoft Visual C++ Redistributables..."

    # URLs for Visual C++ Redistributables
    $vcRedistUrls = @(
        "https://aka.ms/vs/17/release/vc_redist.x64.exe",
        "https://aka.ms/vs/17/release/vc_redist.x86.exe"
    )

    foreach ($url in $vcRedistUrls) {
        $fileName = Split-Path $url -Leaf
        $outputPath = "$env:TEMP\$fileName"
        Invoke-WebRequest -Uri $url -OutFile $outputPath -ErrorAction SilentlyContinue

        # Install or repair the redistributable
        if (Test-Path $outputPath) {
            Start-Process -FilePath $outputPath -ArgumentList "/install /passive /norestart" -Wait
            # Clean up
            Remove-Item -Path $outputPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Warning "Failed to download $fileName."
        }
    }

    Write-Host "Microsoft Visual C++ Redistributables installation completed."
}

# Section 10: Reinstall Call of Duty
$sectionNumber++
$sectionTitle = "Reinstall Call of Duty"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle? (You may need Xbox App)") {
    Write-Host "Attempting to reinstall Call of Duty..."

    # Uninstall Call of Duty via its package name
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*Activision.COD*" } | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

    Write-Host "Please reinstall Call of Duty through the Xbox App or Microsoft Store."
}

# Section 11: Run DISM and SFC Scans
$sectionNumber++
$sectionTitle = "Run DISM and SFC scans"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Running DISM and SFC scans..."

    Dism /Online /Cleanup-Image /CheckHealth
    Dism /Online /Cleanup-Image /ScanHealth
    Dism /Online /Cleanup-Image /RestoreHealth
    sfc /scannow

    Write-Host "DISM and SFC scans completed."
}

# Section 12: Reset Network and Background Services
$sectionNumber++
$sectionTitle = "Reset network and background services"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Resetting network and essential services..."
    
    # Reset Winsock and IP settings
    netsh winsock reset | Out-Null
    netsh int ip reset | Out-Null

    # Suppress "Access is denied" messages
    Try {
        netsh advfirewall reset | Out-Null
    } Catch {
        Write-Warning "Could not reset firewall settings: $_"
    }
    
    $services = @("wuauserv", "cryptSvc", "bits", "msiserver")
    foreach ($service in $services) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    }
    
    Rename-Item -Path "C:\Windows\SoftwareDistribution" -NewName "SoftwareDistribution.old" -ErrorAction SilentlyContinue
    Rename-Item -Path "C:\Windows\System32\catroot2" -NewName "Catroot2.old" -ErrorAction SilentlyContinue
    
    foreach ($service in $services) {
        Start-Service -Name $service -ErrorAction SilentlyContinue
    }
    
    Write-Host "Network and services reset completed."
}

# Section 13: Perform a Comprehensive DirectX Reinstallation
$sectionNumber++
$sectionTitle = "Perform a comprehensive DirectX reinstallation"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Reinstalling DirectX..."

    # Remove existing DirectX user components (Note: System DirectX files cannot be uninstalled)
    # Deleting user-level DirectX redistributable files
    $dxFiles = @(
        "$env:SystemRoot\System32\D3DX9_*.dll",
        "$env:SystemRoot\System32\D3DX10_*.dll",
        "$env:SystemRoot\System32\D3DX11_*.dll",
        "$env:SystemRoot\SysWOW64\D3DX9_*.dll",
        "$env:SystemRoot\SysWOW64\D3DX10_*.dll",
        "$env:SystemRoot\SysWOW64\D3DX11_*.dll"
    )

    foreach ($filePattern in $dxFiles) {
        Get-ChildItem -Path $filePattern -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    }

    # Download and install the DirectX End-User Runtimes (June 2010)
    $directxUrl = "https://download.microsoft.com/download/9/3/1/931B0D18-2B6B-43EF-BA9A-6D8296B53104/directx_Jun2010_redist.exe"
    $directxInstaller = "$env:TEMP\directx_Jun2010_redist.exe"
    try {
        Invoke-WebRequest -Uri $directxUrl -OutFile $directxInstaller -ErrorAction Stop
    } catch {
        Write-Warning "Failed to download DirectX End-User Runtimes: $_"
        Write-Host "Please download it manually from: https://www.microsoft.com/en-us/download/details.aspx?id=8109"
        Write-Host "Then place the installer at: $directxInstaller"
        return
    }

    # Extract the installer contents
    $extractFolder = "$env:TEMP\DXRedist"
    New-Item -ItemType Directory -Path $extractFolder -Force | Out-Null
    Start-Process -FilePath $directxInstaller -ArgumentList "/Q /T:$extractFolder" -Wait

    # Install DirectX
    $dxSetup = Join-Path $extractFolder "DXSETUP.exe"
    if (Test-Path $dxSetup) {
        Start-Process -FilePath $dxSetup -ArgumentList "/silent" -Wait
    } else {
        Write-Warning "DXSETUP.exe not found. DirectX installation may not have been extracted properly."
    }

    # Clean up
    Remove-Item -Path $directxInstaller -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $extractFolder -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "DirectX reinstallation completed."
}

# Section 14: Analyze Service Bindings
$sectionNumber++
$sectionTitle = "Analyze service bindings for atvi-randgrid_msstore"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Analyzing service bindings..."

    # Check for services related to Activision or Call of Duty
    $services = Get-Service | Where-Object { $_.Name -like "*atvi*" -or $_.DisplayName -like "*Activision*" }
    if ($services) {
        $services | Format-Table -AutoSize
        Write-Host "Found Activision-related services. Restarting these services..."

        foreach ($service in $services) {
            try {
                Restart-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Could not restart service: $($service.Name)"
            }
        }
    } else {
        Write-Host "No Activision-related services found."
    }

    Write-Host "Service bindings analysis completed."
}

# Section 15: Check for Windows and Driver Updates
$sectionNumber++
$sectionTitle = "Check for Windows and driver updates"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Checking for Windows updates..."
    try {
        Install-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
        Get-WindowsUpdate -Install -AcceptAll -AutoReboot -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not check for Windows updates automatically. Please check manually via Settings > Update & Security."
    }

    Write-Host "Please ensure all your drivers, especially graphics and sound drivers, are up to date."
    Write-Host "Visit the manufacturer's website for the latest drivers."
}

# Section 16: Perform Kernel and Driver Compatibility Checks
<# $sectionNumber++
$sectionTitle = "Perform kernel and driver compatibility checks"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Warning "Enabling Driver Verifier can cause system instability. Proceed with caution."
    If (Prompt-Task "Do you want to proceed with enabling Driver Verifier?") {
        Write-Host "Enabling Driver Verifier to check for driver issues..."

        # Enable driver verification
        verifier /reset
        verifier /standard /all

        Write-Host "Driver Verifier enabled. Please reboot your system for changes to take effect."
        Write-Host "If you experience BSODs after reboot, you can disable Driver Verifier by:"
        Write-Host "1. Booting into Safe Mode."
        Write-Host "2. Opening Command Prompt as Administrator."
        Write-Host "3. Running 'verifier /reset'."
        Write-Host "4. Rebooting your system."
    } else {
        Write-Host "Skipped enabling Driver Verifier."
    }
} #>

# Section 17: Set Up Advanced Kernel Debugging Tools
$sectionNumber++
$sectionTitle = "Set up advanced kernel debugging tools"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Setting up Windows Debugging Tools..."

    # Install Windows SDK Debugging Tools (Requires internet connection)
    $sdkInstaller = "$env:TEMP\winsdksetup.exe"
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2120843" -OutFile $sdkInstaller -ErrorAction SilentlyContinue

    if (Test-Path $sdkInstaller) {
        Start-Process -FilePath $sdkInstaller -ArgumentList "/features + /quiet" -Wait
        Write-Host "Windows Debugging Tools installed."

        # Provide detailed instructions
        Write-Host "You can use WinDbg to analyze crash dumps located in C:\Windows\Minidump or generated by the game."
        Write-Host "To analyze a crash dump:"
        Write-Host "1. Open WinDbg as Administrator."
        Write-Host "2. Click on 'File' -> 'Open Crash Dump' and select the dump file."
        Write-Host "3. In the command input, type '!analyze -v' and press Enter."
        Write-Host "This will provide detailed information about the crash."
    } else {
        Write-Warning "Failed to download Windows SDK installer."
    }

    Write-Host "Advanced kernel debugging tools setup completed."
}

# Section 18: Search Event Viewer for Errors
$sectionNumber++
$sectionTitle = "Search Event Viewer for recent Call of Duty related errors"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Searching Event Viewer for errors..."

    # Define specific event sources and IDs related to Call of Duty
    $eventSources = @("Call of Duty", "cod.exe", "cod6.exe", "ATVI Crash Handler", "Game Crash")

    # Get events from Application log related to Call of Duty in the last 24 hours
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Application';
        Level = 2; # Error
        StartTime = (Get-Date).AddDays(-1)
    } | Where-Object {
        $eventSources -contains $_.ProviderName -or
        $_.Message -match 'Call of Duty|cod\.exe|cod6\.exe|ATVI Crash Handler|Game Crash'
    }

    if ($events) {
        Write-Warning "Found the following errors related to Call of Duty:"
        foreach ($event in $events) {
            Write-Host "Time: $($event.TimeCreated)"
            Write-Host "Source: $($event.ProviderName)"
            Write-Host "Event ID: $($event.Id)"
            Write-Host "Message: $($event.Message)"
            Write-Host "-----"
        }
    } else {
        Write-Host "No Call of Duty related errors found in the Event Viewer."
    }

    Write-Host "Event Viewer search completed."
}

# Section 19: Schedule Memory Diagnostic Test
$sectionNumber++
$sectionTitle = "Schedule a Memory Diagnostic test on next reboot"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Scheduling Windows Memory Diagnostic..."

    # Schedule memory diagnostic without immediate reboot
    $mdsched = "$env:windir\system32\MdSched.exe"
    if (Test-Path $mdsched) {
        Start-Process -FilePath $mdsched -ArgumentList "/runmemorydiagnostic" -Wait
        Write-Host "Memory Diagnostic scheduled. It will run on the next reboot."
    } else {
        Write-Warning "Memory Diagnostic tool not found."
    }
}

# Section 20: Check Disk Integrity
$sectionNumber++
$sectionTitle = "Check disk integrity using chkdsk"
Write-Section $sectionNumber $sectionTitle
If (Prompt-Task "$sectionTitle?") {
    Write-Host "Checking disk integrity..."

    # Get system drive (usually C:)
    $systemDrive = (Get-PSDrive -PSProvider 'FileSystem' | Where-Object { $_.Root -eq [System.Environment]::SystemDirectory.Substring(0,3) }).Name + ":"

    # Schedule chkdsk on next reboot without prompting
    chkdsk $systemDrive /f /r /x /b /perf /scan | Out-Null

    Write-Host "Disk check scheduled. It may run on next reboot if necessary."
}

# Section 21: Final Cleanup and Recommendations
$sectionNumber++
$sectionTitle = "Final cleanup and recommendations"
Write-Section $sectionNumber $sectionTitle
Write-Host "Performing final cleanup..."

# Clear temporary files
If (Prompt-Task "Would you like to clear temporary files to free up space?") {
    Write-Host "Clearing temporary files..."
    try {
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Temporary files cleared."
    } catch {
        Write-Warning "Failed to clear some temporary files."
    }
}

Write-Host ""
Write-Host "Script execution completed. A system reboot is recommended to apply changes."
Stop-Transcript

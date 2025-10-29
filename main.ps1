# Hardware Device Scanner
# Target: VEN_046D&DEV_C53B (Xim Matrix)
# Exhaustive search across all Windows device tracking systems

#Requires -RunAsAdministrator

# Define search parameters
$VendorID = "046D"
$DeviceID = "C53B"
$SearchPattern = "*046D*C53B*"
$OutputFile = "$env:USERPROFILE\Desktop\DeviceScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Track findings
$global:DetectionResults = @()

# Initialize log
function Write-Log {
    param($Message, [switch]$NoTimestamp)
    if ($NoTimestamp) {
        Write-Host $Message
        Add-Content -Path $OutputFile -Value $Message
    } else {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $LogMessage = "[$Timestamp] $Message"
        Write-Host $LogMessage
        Add-Content -Path $OutputFile -Value $LogMessage
    }
}

function Add-Detection {
    param($Location, $Details)
    $global:DetectionResults += [PSCustomObject]@{
        Location = $Location
        Details = $Details
    }
}

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Log "==========================================" -NoTimestamp
Write-Log "Hardware Device Scanner" -NoTimestamp
Write-Log "Searching for: Xim Matrix" -NoTimestamp
Write-Log "Target IDs: VEN_$VendorID & DEV_$DeviceID" -NoTimestamp
Write-Log "==========================================" -NoTimestamp
Write-Log "Computer: $env:COMPUTERNAME" -NoTimestamp
Write-Log "User: $env:USERNAME" -NoTimestamp
Write-Log "Administrator: $isAdmin" -NoTimestamp
Write-Log "Scan Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -NoTimestamp
Write-Log "==========================================" -NoTimestamp
Write-Log "" -NoTimestamp

# Section 1: ALL PnP Devices (including hidden/disconnected)
Write-Log "[1/16] Scanning PnP Devices..." -NoTimestamp
try {
    $AllDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -match $VendorID -and $_.InstanceId -match $DeviceID
    }
    
    if ($AllDevices) {
        Write-Log ">>> DETECTED: $($AllDevices.Count) matching device(s)"
        foreach ($Device in $AllDevices) {
            Add-Detection "PnP Devices" "$($Device.FriendlyName) - $($Device.InstanceId)"
            Write-Log "    Name: $($Device.FriendlyName)"
            Write-Log "    Status: $($Device.Status)"
            Write-Log "    Present: $($Device.Present)"
            Write-Log "    Class: $($Device.Class)"
            Write-Log "    Instance ID: $($Device.InstanceId)"
        }
    } else {
        Write-Log "    No matches found"
        # Log all USB devices found for reference
        Write-Log "    All USB-related devices found:"
        $AllUSBDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.InstanceId -match "USB\\" -or $_.Class -eq "USB"
        }
        foreach ($Device in $AllUSBDevices) {
            Write-Log "      - $($Device.FriendlyName) | $($Device.InstanceId)"
        }
    }
} catch {
    Write-Log "    ERROR: $($_.Exception.Message)"
}
Write-Log "" -NoTimestamp

# Section 2: Device Property Details
Write-Log "[2/16] Scanning Device Properties..." -NoTimestamp
try {
    $Devices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -match $VendorID -and $_.InstanceId -match $DeviceID
    }
    
    if ($Devices) {
        foreach ($Device in $Devices) {
            Add-Detection "Device Properties" "$($Device.FriendlyName)"
            Write-Log ">>> DETECTED: $($Device.FriendlyName)"
        }
    } else {
        Write-Log "    No matches found"
    }
} catch {
    Write-Log "    ERROR: $($_.Exception.Message)"
}
Write-Log "" -NoTimestamp

# Section 3: Registry - Detailed Search with Error Handling
Write-Log "[3/16] Scanning Registry..." -NoTimestamp
$RegPaths = @(
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Enum\USB"; Name="USB"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Enum\HID"; Name="HID"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Enum\BTHENUM"; Name="Bluetooth"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"; Name="USB Storage"},
    @{Path="HKLM:\SYSTEM\ControlSet001\Enum\USB"; Name="ControlSet001-USB"},
    @{Path="HKLM:\SYSTEM\ControlSet001\Enum\HID"; Name="ControlSet001-HID"},
    @{Path="HKLM:\SYSTEM\ControlSet002\Enum\USB"; Name="ControlSet002-USB"},
    @{Path="HKLM:\SYSTEM\ControlSet002\Enum\HID"; Name="ControlSet002-HID"}
)

foreach ($RegEntry in $RegPaths) {
    try {
        if (Test-Path $RegEntry.Path) {
            $FoundMatch = $false
            Write-Log "    Scanning $($RegEntry.Name)..."
            $AllKeys = Get-ChildItem -Path $RegEntry.Path -ErrorAction SilentlyContinue
            
            foreach ($Key in $AllKeys) {
                # Log all USB devices found
                if ($RegEntry.Name -like "*USB*") {
                    Write-Log "      Found: $($Key.PSChildName)"
                }
                
                if ($Key.PSChildName -match $VendorID -and $Key.PSChildName -match $DeviceID) {
                    $FoundMatch = $true
                    Add-Detection "Registry - $($RegEntry.Name)" "$($Key.PSChildName)"
                    Write-Log ">>> DETECTED in $($RegEntry.Name): $($Key.PSChildName)"
                }
                
                Get-ChildItem -Path $Key.PSPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.PSChildName -match $VendorID -and $_.PSChildName -match $DeviceID) {
                        $FoundMatch = $true
                        Add-Detection "Registry - $($RegEntry.Name)" "$($_.PSChildName)"
                        Write-Log ">>> DETECTED in $($RegEntry.Name) (nested): $($_.PSChildName)"
                    }
                }
            }
        }
    } catch {}
}
Write-Log "    Registry scan complete"
Write-Log "" -NoTimestamp

# Section 4: Registry MountedDevices
Write-Log "[4/16] Scanning Mounted Devices..." -NoTimestamp
try {
    $MountedPath = "HKLM:\SYSTEM\MountedDevices"
    if (Test-Path $MountedPath) {
        $Props = Get-ItemProperty -Path $MountedPath -ErrorAction SilentlyContinue
        $Props.PSObject.Properties | ForEach-Object {
            if ($_.Value -is [byte[]]) {
                $StringValue = [System.Text.Encoding]::Unicode.GetString($_.Value)
                if ($StringValue -match $VendorID -and $StringValue -match $DeviceID) {
                    Add-Detection "Mounted Devices" $_.Name
                    Write-Log ">>> DETECTED: $($_.Name)"
                }
            }
        }
    }
    Write-Log "    Complete"
} catch {
    Write-Log "    ERROR: $($_.Exception.Message)"
}
Write-Log "" -NoTimestamp

# Section 5: Driver Store
Write-Log "[5/16] Scanning Driver Store..." -NoTimestamp
$DriverStorePath = "$env:SystemRoot\System32\DriverStore\FileRepository"
if (Test-Path $DriverStorePath) {
    try {
        $InfFiles = Get-ChildItem -Path $DriverStorePath -Filter "*.inf" -Recurse -ErrorAction SilentlyContinue
        foreach ($Inf in $InfFiles) {
            $Content = Get-Content -Path $Inf.FullName -Raw -ErrorAction SilentlyContinue
            if ($Content -match $VendorID -and $Content -match $DeviceID) {
                Add-Detection "Driver Store" $Inf.Name
                Write-Log ">>> DETECTED: $($Inf.Name)"
            }
        }
        Write-Log "    Complete"
    } catch {
        Write-Log "    ERROR: $($_.Exception.Message)"
    }
}
Write-Log "" -NoTimestamp

# Section 6: INF Cache
Write-Log "[6/16] Scanning INF Cache..." -NoTimestamp
$InfPath = "$env:SystemRoot\INF"
if (Test-Path $InfPath) {
    try {
        $InfFiles = Get-ChildItem -Path $InfPath -Filter "*.inf" -ErrorAction SilentlyContinue
        foreach ($Inf in $InfFiles) {
            $Content = Get-Content -Path $Inf.FullName -Raw -ErrorAction SilentlyContinue
            if ($Content -match $VendorID -and $Content -match $DeviceID) {
                Add-Detection "INF Cache" $Inf.Name
                Write-Log ">>> DETECTED: $($Inf.Name)"
            }
        }
        Write-Log "    Complete"
    } catch {
        Write-Log "    ERROR: $($_.Exception.Message)"
    }
}
Write-Log "" -NoTimestamp

# Section 7: SetupAPI Logs - Comprehensive Search
Write-Log "[7/16] Scanning SetupAPI Logs..." -NoTimestamp
$SetupLogs = @(
    "$env:windir\inf\setupapi.dev.log",
    "$env:windir\inf\setupapi.app.log",
    "$env:windir\setupapi.log"
)

foreach ($LogPath in $SetupLogs) {
    if (Test-Path $LogPath) {
        try {
            $LogContent = Get-Content -Path $LogPath -ErrorAction SilentlyContinue
            for ($i = 0; $i -lt $LogContent.Count; $i++) {
                if ($LogContent[$i] -match $VendorID) {
                    $StartIndex = [Math]::Max(0, $i - 5)
                    $EndIndex = [Math]::Min($LogContent.Count - 1, $i + 10)
                    $Context = $LogContent[$StartIndex..$EndIndex] -join "`n"
                    
                    if ($Context -match $DeviceID) {
                        Add-Detection "SetupAPI Log" (Split-Path $LogPath -Leaf)
                        Write-Log ">>> DETECTED in $(Split-Path $LogPath -Leaf) at line $($i + 1)"
                        break
                    }
                }
            }
        } catch {}
    }
}
Write-Log "    Complete"
Write-Log "" -NoTimestamp

# Section 8: Event Log - Device Installation
Write-Log "[8/16] Scanning Event Logs..." -NoTimestamp
$EventLogs = @(
    @{LogName='Microsoft-Windows-Kernel-PnP/Configuration'; IDs=@(400,410,420)},
    @{LogName='Microsoft-Windows-UserPnp/DeviceInstall'; IDs=@()},
    @{LogName='Setup'; IDs=@()}
)

foreach ($EventLog in $EventLogs) {
    try {
        $Filter = @{LogName = $EventLog.LogName}
        if ($EventLog.IDs.Count -gt 0) {
            $Filter['ID'] = $EventLog.IDs
        }
        
        $Events = Get-WinEvent -FilterHashtable $Filter -MaxEvents 5000 -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -match $VendorID -and $_.Message -match $DeviceID
        }
        
        if ($Events) {
            Add-Detection "Event Log" $EventLog.LogName
            Write-Log ">>> DETECTED in $($EventLog.LogName): $($Events.Count) event(s)"
        }
    } catch {}
}
Write-Log "    Complete"
Write-Log "" -NoTimestamp

# Section 9: System Event Log
Write-Log "[9/16] Scanning System Events..." -NoTimestamp
try {
    $SysEvents = Get-WinEvent -FilterHashtable @{LogName = 'System'} -MaxEvents 5000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match $VendorID -and $_.Message -match $DeviceID
    }
    
    if ($SysEvents) {
        Add-Detection "System Event Log" "$($SysEvents.Count) events"
        Write-Log ">>> DETECTED: $($SysEvents.Count) system event(s)"
    } else {
        Write-Log "    No matches found"
    }
} catch {
    Write-Log "    ERROR: $($_.Exception.Message)"
}
Write-Log "" -NoTimestamp

# Section 10: Search all HardwareID and CompatibleIDs
Write-Log "[10/16] Scanning Hardware IDs..." -NoTimestamp
$EnumPath = "HKLM:\SYSTEM\CurrentControlSet\Enum"
try {
    if (Test-Path $EnumPath) {
        Get-ChildItem -Path $EnumPath -Recurse -Depth 4 -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $Props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                $HardwareIDs = @($Props.HardwareID)
                $CompatIDs = @($Props.CompatibleIDs)
                
                $AllIDs = $HardwareIDs + $CompatIDs
                foreach ($ID in $AllIDs) {
                    if ($ID -match $VendorID -and $ID -match $DeviceID) {
                        Add-Detection "Hardware ID" $ID
                        Write-Log ">>> DETECTED: $ID"
                    }
                }
            } catch {}
        }
    }
    Write-Log "    Complete"
} catch {
    Write-Log "    ERROR: $($_.Exception.Message)"
}
Write-Log "" -NoTimestamp

# Section 11: WMI Searches
Write-Log "[11/16] Scanning WMI..." -NoTimestamp
try {
    $WMIDevices = Get-WmiObject -Class Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {
        $_.DeviceID -match $VendorID -and $_.DeviceID -match $DeviceID
    }
    
    if ($WMIDevices) {
        Add-Detection "WMI" "$($WMIDevices.Count) device(s)"
        Write-Log ">>> DETECTED: $($WMIDevices.Count) WMI device(s)"
    } else {
        Write-Log "    No matches found"
    }
} catch {
    Write-Log "    ERROR: $($_.Exception.Message)"
}
Write-Log "" -NoTimestamp

# Section 12: Composite USB Devices (Parent/Child)
Write-Log "[12/16] Scanning USB Composites..." -NoTimestamp
try {
    # Check specifically for USB Composite Devices
    $CompositeDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $_.Class -eq "USB" -or $_.FriendlyName -like "*USB Composite Device*"
    }
    
    Write-Log "    All USB Composite and USB Class Devices:"
    foreach ($Device in $CompositeDevices) {
        Write-Log "      - $($Device.FriendlyName) | $($Device.InstanceId) | Status: $($Device.Status)"
        
        # Check the device's instance ID for our target VID/PID
        if ($Device.InstanceId -match $VendorID -and $Device.InstanceId -match $DeviceID) {
            Add-Detection "USB Composite Device" "$($Device.FriendlyName) - $($Device.InstanceId)"
            Write-Log ">>> DETECTED: $($Device.FriendlyName)"
            Write-Log "    Instance ID: $($Device.InstanceId)"
            Write-Log "    Status: $($Device.Status)"
            Write-Log "    Present: $($Device.Present)"
        }
        
        # Also check all devices under Universal Serial Bus controllers
        if ($Device.InstanceId -match "USB\\VID_$VendorID" -and $Device.InstanceId -match "PID_$DeviceID") {
            Add-Detection "USB Controller Device" "$($Device.FriendlyName) - $($Device.InstanceId)"
            Write-Log ">>> DETECTED in USB Controllers: $($Device.FriendlyName)"
            Write-Log "    Instance ID: $($Device.InstanceId)"
        }
    }
    
    # Specifically check USB Composite Device entries
    $USBComposite = Get-PnpDevice -FriendlyName "USB Composite Device" -ErrorAction SilentlyContinue
    Write-Log "    Specific USB Composite Device check:"
    foreach ($USB in $USBComposite) {
        Write-Log "      - Instance ID: $($USB.InstanceId)"
        if ($USB.InstanceId -match $VendorID -and $USB.InstanceId -match $DeviceID) {
            Add-Detection "USB Composite Device (Direct Match)" $USB.InstanceId
            Write-Log ">>> DETECTED: USB Composite Device"
            Write-Log "    Instance ID: $USB.InstanceId"
            Write-Log "    Hardware ID: $(($USB | Get-PnpDeviceProperty -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue).Data)"
        }
    }
    
    Write-Log "    Complete"
} catch {
    Write-Log "    ERROR: $($_.Exception.Message)"
}
Write-Log "" -NoTimestamp

# Section 13: Device Installation Logs
Write-Log "[13/16] Scanning Device Installation..." -NoTimestamp
$DevInstallPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceInstall"
try {
    if (Test-Path $DevInstallPath) {
        Get-ChildItem -Path $DevInstallPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $Props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                $Props.PSObject.Properties | ForEach-Object {
                    if ($_.Value -match $VendorID -and $_.Value -match $DeviceID) {
                        Add-Detection "Device Installation" $_.Name
                        Write-Log ">>> DETECTED: Installation record"
                    }
                }
            } catch {}
        }
    }
    Write-Log "    Complete"
} catch {
    Write-Log "    ERROR: $($_.Exception.Message)"
}
Write-Log "" -NoTimestamp

# Section 14: Device Parameters
Write-Log "[14/16] Scanning Device Parameters..." -NoTimestamp
$ParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses"
try {
    if (Test-Path $ParamsPath) {
        Get-ChildItem -Path $ParamsPath -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -match $VendorID -and $_.PSChildName -match $DeviceID) {
                Add-Detection "Device Parameters" $_.PSChildName
                Write-Log ">>> DETECTED: Device parameter"
            }
        }
    }
    Write-Log "    Complete"
} catch {
    Write-Log "    ERROR: $($_.Exception.Message)"
}
Write-Log "" -NoTimestamp

# Section 15: Raw Device Scan (All Classes)
Write-Log "[15/16] Scanning Device Classes..." -NoTimestamp
$DeviceClasses = @("HIDClass", "USB", "Mouse", "Keyboard", "System", "Net", "Media", "Bluetooth")
foreach ($Class in $DeviceClasses) {
    try {
        $Devices = Get-PnpDevice -Class $Class -ErrorAction SilentlyContinue
        
        if ($Devices) {
            Write-Log "    $Class devices found:"
            foreach ($Device in $Devices) {
                Write-Log "      - $($Device.FriendlyName) | $($Device.InstanceId)"
                
                if ($Device.InstanceId -match $VendorID -and $Device.InstanceId -match $DeviceID) {
                    Add-Detection "Device Class - $Class" $Device.FriendlyName
                    Write-Log ">>> DETECTED in $Class : $($Device.FriendlyName)"
                }
            }
        }
    } catch {}
}
Write-Log "    Complete"
Write-Log "" -NoTimestamp

# Section 16: Check for Logitech Devices (VID 046D)
Write-Log "[16/16] Scanning Logitech Devices..." -NoTimestamp
try {
    $LogitechDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -match "046D"
    }
    
    if ($LogitechDevices) {
        Write-Log "    All Logitech (VID 046D) devices found:"
        foreach ($Device in $LogitechDevices) {
            Write-Log "      - $($Device.FriendlyName) | $($Device.InstanceId) | Status: $($Device.Status)"
            
            if ($Device.InstanceId -match $DeviceID) {
                Add-Detection "Logitech Device Match" $Device.FriendlyName
                Write-Log ">>> DETECTED: $($Device.FriendlyName) - $($Device.InstanceId)"
            }
        }
    } else {
        Write-Log "    No Logitech devices found"
    }
} catch {
    Write-Log "    ERROR: $($_.Exception.Message)"
}
Write-Log "" -NoTimestamp

# Summary
Write-Log "" -NoTimestamp
Write-Log "==========================================" -NoTimestamp
Write-Log "SCAN COMPLETE" -NoTimestamp
Write-Log "==========================================" -NoTimestamp
Write-Log "" -NoTimestamp

if ($global:DetectionResults.Count -gt 0) {
    Write-Log "RESULT: YES - XIM MATRIX DETECTED" -NoTimestamp
    Write-Log "" -NoTimestamp
    Write-Log "Detection Summary:" -NoTimestamp
    Write-Log "Total Detections: $($global:DetectionResults.Count)" -NoTimestamp
    Write-Log "" -NoTimestamp
    Write-Log "Found in the following locations:" -NoTimestamp
    
    $LocationGroups = $global:DetectionResults | Group-Object -Property Location
    foreach ($Group in $LocationGroups) {
        Write-Log "  [$($Group.Name)]" -NoTimestamp
        foreach ($Item in $Group.Group) {
            Write-Log "    - $($Item.Details)" -NoTimestamp
        }
    }
} else {
    Write-Log "RESULT: NO - XIM MATRIX NOT DETECTED" -NoTimestamp
    Write-Log "" -NoTimestamp
    Write-Log "No traces of the target device were found on this system." -NoTimestamp
}

Write-Log "" -NoTimestamp
Write-Log "Log saved to: $OutputFile" -NoTimestamp
Write-Log "==========================================" -NoTimestamp

Write-Host "`n" -NoNewline
if ($global:DetectionResults.Count -gt 0) {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "XIM MATRIX DETECTED" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Found in $($LocationGroups.Count) location(s)" -ForegroundColor Yellow
} else {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "NO DETECTION" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
}
Write-Host "Log file: $OutputFile" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Gray
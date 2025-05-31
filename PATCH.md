Here's the modified script with dynamic naming and URL handling:

```powershell
param(
    [Parameter(Mandatory=$false)]  # Changed to false since we have default values or remove the default values and use $true
    [string]$KBNumber = "5055175",
    [Parameter(Mandatory=$false)]  # Changed to false since we have default values
    [string]$DownloadURL = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/updt/2025/03/windows10.0-kb5055175-x64-ndp48_df5de1b5f2a6394b4d40391d6ea8fed4415f806f.msu",
    [string]$TempPath = "C:\temp"
)

# Set error action and create log file
$ErrorActionPreference = "Stop"
$logFile = "$TempPath\update_install_KB${KBNumber}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param($Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Host $logMessage
    Add-Content -Path $logFile -Value $logMessage
}

function Test-Internet {
    $testUrls = @(
        $DownloadURL
    )
    
    foreach ($url in $testUrls) {
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 -Method Head  # Added -Method Head for efficiency
            if ($response.StatusCode -eq 200) {
                Write-Log "Successfully verified download URL accessibility"
                return $true
            }
        }
        catch {
            Write-Log "Failed to connect to download URL: $url"
            Write-Log "Error: $_"
            return $false
        }
    }
    return $false
}

function Remove-ExistingKB {
    param (
        [string]$kbNumber
    )
    
    try {
        $installed = Get-HotFix -Id $kbNumber -ErrorAction SilentlyContinue
        
        if ($installed) {
            Write-Log "Found existing KB$kbNumber, attempting to remove..."
            
            $dismResult = Start-Process "DISM.exe" -ArgumentList "/Online /Remove-Package /PackageName:Package_for_KB$kbNumber /quiet /norestart" -Wait -PassThru -NoNewWindow
            
            if ($dismResult.ExitCode -eq 0) {
                Write-Log "Successfully removed KB$kbNumber using DISM"
                return $true
            }
            
            $wusaResult = Start-Process "wusa.exe" -ArgumentList "/uninstall /kb:$kbNumber /quiet /norestart" -Wait -PassThru -NoNewWindow
            
            if ($wusaResult.ExitCode -eq 0) {
                Write-Log "Successfully removed KB$kbNumber using wusa"
                return $true
            }
            
            Write-Log "Failed to remove KB$kbNumber"
            return $false
        }
        else {
            Write-Log "KB$kbNumber not found, proceeding with installation"
            return $true
        }
    }
    catch {
        Write-Log "Error checking/removing KB$kbNumber: $_"
        return $false
    }
}

try {
    # Extract filename from URL
    $msuFileName = [System.IO.Path]::GetFileName($DownloadURL)
    Write-Log "MSU Filename: $msuFileName"

    # Check internet connectivity
    Write-Log "Checking internet connectivity..."
    if (-not (Test-Internet)) {
        throw "No internet connectivity detected"
    }
    Write-Log "Internet connectivity confirmed"

    # Create temp directory if it doesn't exist
    if (-not (Test-Path $TempPath)) {
        New-Item -ItemType Directory -Path $TempPath
        Write-Log "Created directory: $TempPath"
    }
    
    # Change to temp directory
    Set-Location $TempPath
    
    # Clean up any existing files
    if (Test-Path $msuFileName) {
        Remove-Item $msuFileName -Force
        Write-Log "Removed existing MSU file"
    }
    Get-ChildItem -Filter "*.cab" | Remove-Item -Force
    Write-Log "Cleaned up existing CAB files"

    # Remove existing KB if installed
    if (-not (Remove-ExistingKB $KBNumber)) {
        throw "Failed to remove existing KB$KBNumber"
    }
    
    # Download the MSU file
    Write-Log "Starting download of $msuFileName"
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $DownloadURL -OutFile $msuFileName -UseBasicParsing
        Write-Log "Download completed successfully"
    }
    catch {
        throw "Failed to download MSU file: $_"
    }

    # Verify file exists and has content
    if (-not (Test-Path $msuFileName) -or (Get-Item $msuFileName).Length -eq 0) {
        throw "Downloaded file is missing or empty"
    }

    # Expand the MSU file
    Write-Log "Expanding MSU file"
    $expandOutput = expand -F:*.cab ".\$msuFileName" "." 2>&1
    Write-Log "Expand output: $expandOutput"

    # Get all CAB files in order (SSU first if present)
    $cabFiles = Get-ChildItem -Filter *.cab | Sort-Object { $_.Name -like "*SSU*" -desc }
    if (-not $cabFiles) {
        throw "No CAB files found after expansion"
    }
    Write-Log "Found CAB files: $($cabFiles.Name -join ', ')"

    # Install each CAB file
    $installSuccess = $true
    foreach ($cab in $cabFiles) {
        Write-Log "Installing $($cab.Name)"
        $process = Start-Process "DISM.exe" -ArgumentList "/Online /Add-Package /PackagePath:`"$($cab.FullName)`" /quiet /norestart" -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-Log "Successfully installed $($cab.Name)"
            if ($process.ExitCode -eq 3010) {
                Write-Log "Restart will be needed but continuing with installations"
            }
        }
        else {
            $installSuccess = $false
            throw "DISM installation failed for $($cab.Name) with exit code $($process.ExitCode)"
        }

        # Get logs
        Write-Log "Checking logs..."
        $dismLog = Get-Content "C:\Windows\Logs\DISM\dism.log" -Tail 50 | Select-String -Pattern "Error|Warning"
        $cbsLog = Get-Content "C:\Windows\Logs\CBS\CBS.log" -Tail 50 | Select-String -Pattern "Error|Warning"
        $setupEvents = Get-WinEvent -LogName Setup -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($dismLog) { Write-Log "DISM Log entries: $($dismLog -join "`n")" }
        if ($cbsLog) { Write-Log "CBS Log entries: $($cbsLog -join "`n")" }
        if ($setupEvents) {
            foreach ($event in $setupEvents) {
                Write-Log "Setup Event: ID=$($event.ID), Message=$($event.Message)"
            }
        }
    }

    if ($installSuccess) {
        Write-Log "All installations completed successfully"
        Set-Content -Path "$TempPath\KB${KBNumber}_success.flag" -Value (Get-Date)
        exit 0
    }
}
catch {
    Write-Log "ERROR: $_"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)"
    
    try {
        $recentDismLog = Get-Content "C:\Windows\Logs\DISM\dism.log" -Tail 20
        $recentCbsLog = Get-Content "C:\Windows\Logs\CBS\CBS.log" -Tail 20
        Write-Log "Recent DISM log entries: $($recentDismLog -join "`n")"
        Write-Log "Recent CBS log entries: $($recentCbsLog -join "`n")"
    }
    catch {
        Write-Log "Unable to retrieve log details: $_"
    }
    
    exit 1
}
finally {
    Write-Log "Script execution completed"
    # Optional cleanup
    # Remove-Item $msuFileName -Force -ErrorAction SilentlyContinue
    # Get-ChildItem -Filter "*.cab" | Remove-Item -Force -ErrorAction SilentlyContinue
}
```

Usage example:
```powershell
.\Install-WindowsUpdate.ps1 -KBNumber "5055175" -DownloadURL "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/updt/2025/03/windows10.0-kb5055175-x64-ndp48_df5de1b5f2a6394b4d40391d6ea8fed4415f806f.msu"
```

Key changes:
1. Added parameters for KB number and download URL
2. Made file naming dynamic based on parameters
3. Made temp path configurable
4. Used Path.GetFileName to extract filename from URL
5. Made log files and success flags include KB number
6. Removed all hardcoded values
7. Made cleanup more dynamic based on actual filenames

The script is now more flexible and can be used for any Windows update MSU file, not just specific KBs.

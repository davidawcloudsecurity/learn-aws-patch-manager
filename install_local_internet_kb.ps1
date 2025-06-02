#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Downloads and installs Windows KB updates with comprehensive error handling and logging.

.DESCRIPTION
    This script downloads a specified Windows KB update from Windows Update catalog
    and installs it using DISM. Includes validation, cleanup, and detailed logging.

.PARAMETER KBNumber
    The KB number to install (without 'KB' prefix)

.PARAMETER DownloadURL
    Direct download URL for the MSU file

.PARAMETER TempPath
    Temporary directory for downloads and extraction

.PARAMETER CleanupAfter
    Whether to clean up temporary files after installation

.PARAMETER MaxRetries
    Maximum number of download retry attempts

.PARAMETER ExcludeWSUSSCAN
    Whether to exclude WSUSSCAN.cab files from installation (recommended: $true)

.PARAMETER UseLocalFiles
    If $true, search for and use existing local CAB files. If $false, always download from internet.
    If "Auto", check local first, then download if not found.

.PARAMETER LocalSearchPaths
    Array of paths to search for local CAB files (when UseLocalFiles is $true or "Auto")

.EXAMPLE
    .\Install-KB.ps1 -KBNumber "5055175" -UseLocalFiles $true
    
.EXAMPLE
    .\Install-KB.ps1 -KBNumber "5055175" -UseLocalFiles $false -CleanupAfter $true
    
.EXAMPLE
    .\Install-KB.ps1 -KBNumber "5055175" -UseLocalFiles "Auto"
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^\d{7}$')]
    [string]$KBNumber = "5055175",
    
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if ($_ -match '^https?://') { $true }
        else { throw "URL must start with http:// or https://" }
    })]
    [string]$DownloadURL = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/updt/2025/03/windows10.0-kb5055175-x64-ndp48_df5de1b5f2a6394b4d40391d6ea8fed4415f806f.msu",
    
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if (Test-Path $_ -IsValid) { $true }
        else { throw "Invalid path format" }
    })]
    [string]$TempPath = "C:\temp",
    
    [Parameter(Mandatory=$false)]
    [bool]$CleanupAfter = $true,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3,
    
    [Parameter(Mandatory=$false)]
    [bool]$ExcludeWSUSSCAN = $true,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet($true, $false, "Auto")]
    [object]$UseLocalFiles = $true,
    
    [Parameter(Mandatory=$false)]
    [string[]]$LocalSearchPaths = @(
        "C:\Windows\SoftwareDistribution\Download",
        "C:\temp",
        "C:\Updates",
        "$env:USERPROFILE\Downloads"
    )
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$script:LogFile = ""

#region Helper Functions

function Find-MatchingCAB {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KBNumber,
        [string[]]$SearchPaths = $LocalSearchPaths
    )

    Write-Log "Searching for KB$KBNumber related CAB files in specified paths" -Level "Info"
    
    $allMatches = @()
    
    foreach ($searchPath in $SearchPaths) {
        if (-not (Test-Path $searchPath)) {
            Write-Log "Search path does not exist: $searchPath" -Level "Warning"
            continue
        }
        
        Write-Log "Searching in: $searchPath" -Level "Info"
        
        try {
            # Get all CAB files in the directory
            $cabFiles = Get-ChildItem -Path $searchPath -Filter "*.cab" -Recurse -ErrorAction SilentlyContinue
            
            if (-not $cabFiles) {
                Write-Log "No CAB files found in: $searchPath" -Level "Info"
                continue
            }
            
            # Filter potential matches using multiple methods
            $matches = $cabFiles | Where-Object {
                # Direct KB number in filename
                $_.Name -match "KB$KBNumber" -or
                $_.Name -match "$KBNumber" -or
                
                # Check if filename contains update patterns
                ($_.Name -match "windows10.*kb.*$KBNumber") -or
                ($_.Name -match "$KBNumber.*\.cab$")
            }
            
            if ($matches) {
                Write-Log "Found $($matches.Count) matching CAB file(s) in $searchPath" -Level "Success"
                foreach ($match in $matches) {
                    Write-Log "- $($match.FullName)" -Level "Info"
                }
                $allMatches += $matches
            }
        }
        catch {
            Write-Log "Error searching in ${searchPath}: $_" -Level "Warning"
        }
    }
    
    if ($allMatches) {
        Write-Log "Total matching CAB files found: $($allMatches.Count)" -Level "Success"
        return $allMatches
    } else {
        Write-Log "No matching CAB files found for KB$KBNumber in any search path" -Level "Warning"
        return $null
    }
}

function Get-PackageSource {
    <#
    .SYNOPSIS
    Determine package source based on UseLocalFiles parameter and availability
    #>
    param([string]$KBNumber)
    
    Write-Log "Package source determination for KB$KBNumber" -Level "Info"
    Write-Log "UseLocalFiles setting: $UseLocalFiles" -Level "Info"
    
    switch ($UseLocalFiles) {
        $true {
            Write-Log "Forced local mode: Searching for local CAB files only" -Level "Info"
            $localCABs = Find-MatchingCAB -KBNumber $KBNumber
            if ($localCABs) {
                return @{
                    Source = "Local"
                    Files = $localCABs
                    Message = "Using local CAB files"
                }
            } else {
                throw "UseLocalFiles is set to true, but no local CAB files found for KB$KBNumber"
            }
        }
        
        $false {
            Write-Log "Forced internet mode: Will download from internet" -Level "Info"
            return @{
                Source = "Internet"
                Files = $null
                Message = "Will download from internet"
            }
        }
        
        "Auto" {
            Write-Log "Auto mode: Checking for local files first" -Level "Info"
            $localCABs = Find-MatchingCAB -KBNumber $KBNumber
            if ($localCABs) {
                return @{
                    Source = "Local"
                    Files = $localCABs
                    Message = "Found local CAB files, using local source"
                }
            } else {
                Write-Log "No local CAB files found, will download from internet" -Level "Info"
                return @{
                    Source = "Internet"
                    Files = $null
                    Message = "No local files found, will download from internet"
                }
            }
        }
    }
}

function Initialize-Environment {
    <#
    .SYNOPSIS
    Initialize the script environment and create necessary directories
    #>
    
    # Validate administrator privileges
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        throw "This script requires administrator privileges. Please run as administrator."
    }
    
    # Create temp directory if it doesn't exist
    if (-not (Test-Path $TempPath)) {
        try {
            New-Item -ItemType Directory -Path $TempPath -Force | Out-Null
            Write-Log "Created temporary directory: $TempPath" -Level "Info"
        }
        catch {
            throw "Failed to create temporary directory '$TempPath': $_"
        }
    }
    
    # Initialize log file
    $script:LogFile = Join-Path $TempPath "KB${KBNumber}_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    # Set working directory
    try {
        Set-Location $TempPath
        Write-Log "Changed working directory to: $TempPath" -Level "Info"
    }
    catch {
        throw "Failed to set working directory to '$TempPath': $_"
    }
}

function Write-Log {
    <#
    .SYNOPSIS
    Enhanced logging function with different log levels
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Color output based on level
    switch ($Level) {
        "Info"    { Write-Host $logMessage -ForegroundColor White }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error"   { Write-Host $logMessage -ForegroundColor Red }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
    }
    
    # Write to log file if available
    if ($script:LogFile) {
        try {
            Add-Content -Path $script:LogFile -Value $logMessage -ErrorAction SilentlyContinue
        }
        catch {
            # Silently continue if log write fails to avoid recursive errors
        }
    }
}

function Test-InternetConnectivity {
    <#
    .SYNOPSIS
    Test internet connectivity and URL accessibility
    #>
    param(
        [string]$TestURL = $DownloadURL,
        [int]$TimeoutSeconds = 15
    )
    
    Write-Log "Testing connectivity to: $TestURL" -Level "Info"
    
    try {
        $response = Invoke-WebRequest -Uri $TestURL -Method Head -UseBasicParsing -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) {
            Write-Log "Successfully verified URL accessibility (Status: $($response.StatusCode))" -Level "Success"
            return $true
        }
        else {
            Write-Log "Unexpected response code: $($response.StatusCode)" -Level "Warning"
            return $false
        }
    }
    catch {
        Write-Log "Failed to connect to URL: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

function Test-KBInstallation {
    <#
    .SYNOPSIS
    Check if a specific KB is already installed
    #>
    param([string]$KBNumber)
    
    try {
        $hotfix = Get-HotFix -Id "KB$KBNumber" -ErrorAction SilentlyContinue
        if ($hotfix) {
            Write-Log "KB$KBNumber is already installed (Installed: $($hotfix.InstalledOn))" -Level "Info"
            return $true
        }
        else {
            Write-Log "KB$KBNumber is not currently installed" -Level "Info"
            return $false
        }
    }
    catch {
        Write-Log "Error checking KB installation status: $_" -Level "Warning"
        return $false
    }
}

function Remove-ExistingKB {
    <#
    .SYNOPSIS
    Remove existing KB installation with multiple methods
    #>
    param([string]$KBNumber)
    
    if (-not (Test-KBInstallation $KBNumber)) {
        return $true
    }
    
    Write-Log "Attempting to remove existing KB$KBNumber..." -Level "Info"
    
    # Try DISM first
    try {
        Write-Log "Attempting removal with DISM..." -Level "Info"
        $dismArgs = @("/Online", "/Remove-Package", "/PackageName:Package_for_KB$KBNumber", "/quiet", "/norestart")
        $dismProcess = Start-Process "DISM.exe" -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
        
        if ($dismProcess.ExitCode -eq 0) {
            Write-Log "Successfully removed KB$KBNumber using DISM" -Level "Success"
            return $true
        }
    }
    catch {
        Write-Log "DISM removal failed: $_" -Level "Warning"
    }
    
    # Try WUSA as fallback
    try {
        Write-Log "Attempting removal with WUSA..." -Level "Info"
        $wusaArgs = @("/uninstall", "/kb:$KBNumber", "/quiet", "/norestart")
        $wusaProcess = Start-Process "wusa.exe" -ArgumentList $wusaArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
        
        if ($wusaProcess.ExitCode -eq 0) {
            Write-Log "Successfully removed KB$KBNumber using WUSA" -Level "Success"
            return $true
        }
    }
    catch {
        Write-Log "WUSA removal failed: $_" -Level "Warning"
    }
    
    Write-Log "Failed to remove KB$KBNumber with all methods" -Level "Error"
    return $false
}

function Invoke-FileDownload {
    <#
    .SYNOPSIS
    Download file with retry logic and progress tracking
    #>
    param(
        [string]$URL,
        [string]$OutputPath,
        [int]$MaxRetries = $script:MaxRetries
    )
    
    $fileName = Split-Path $OutputPath -Leaf
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            Write-Log "Download attempt $attempt of $MaxRetries for $fileName" -Level "Info"
            
            # Clean up partial downloads
            if (Test-Path $OutputPath) {
                Remove-Item $OutputPath -Force
            }
            
            # Download with progress
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "PowerShell KB Installer")
            
            # Add progress tracking for large files
            Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -Action {
                $Global:DownloadProgress = $Event.SourceEventArgs.ProgressPercentage
            } | Out-Null
            
            $webClient.DownloadFile($URL, $OutputPath)
            $webClient.Dispose()
            
            # Verify download
            if ((Test-Path $OutputPath) -and (Get-Item $OutputPath).Length -gt 0) {
                $fileSize = [math]::Round((Get-Item $OutputPath).Length / 1MB, 2)
                Write-Log "Download completed successfully ($fileSize MB)" -Level "Success"
                return $true
            }
            else {
                throw "Downloaded file is missing or empty"
            }
        }
        catch {
            Write-Log "Download attempt $attempt failed: $_" -Level "Warning"
            
            if ($attempt -eq $MaxRetries) {
                throw "All download attempts failed: $_"
            }
            
            # Wait before retry
            Start-Sleep -Seconds (5 * $attempt)
        }
    }
    
    return $false
}

function Expand-MSUFile {
    <#
    .SYNOPSIS
    Extract CAB files from MSU package and validate contents
    #>
    param([string]$MSUPath)
    
    Write-Log "Expanding MSU file: $(Split-Path $MSUPath -Leaf)" -Level "Info"
    
    try {
        # Clean up existing CAB files
        Get-ChildItem -Filter "*.cab" -ErrorAction SilentlyContinue | Remove-Item -Force
        
        # Expand MSU
        $expandArgs = @("-F:*.cab", "`"$MSUPath`"", ".")
        $expandProcess = Start-Process "expand.exe" -ArgumentList $expandArgs -Wait -PassThru -NoNewWindow -RedirectStandardError $true
        
        if ($expandProcess.ExitCode -ne 0) {
            throw "Expand process failed with exit code: $($expandProcess.ExitCode)"
        }
        
        # Get all CAB files
        $allCABFiles = Get-ChildItem -Filter "*.cab"
        if (-not $allCABFiles) {
            throw "No CAB files found after expansion"
        }
        
        # Separate valid CAB files from WSUSSCAN (if excluding)
        $validCABFiles = if ($ExcludeWSUSSCAN) {
            $allCABFiles | Where-Object { 
                $_.Name -notlike "*WSUSSCAN*" -and $_.Name -notlike "*wsusscan*" 
            }
        } else {
            $allCABFiles
        }
        
        $wsusscanFiles = $allCABFiles | Where-Object { 
            $_.Name -like "*WSUSSCAN*" -or $_.Name -like "*wsusscan*" 
        }
        
        # Log findings
        Write-Log "Total CAB files extracted: $($allCABFiles.Count)" -Level "Info"
        
        if ($wsusscanFiles) {
            if ($ExcludeWSUSSCAN) {
                Write-Log "WSUSSCAN files found (will be excluded): $($wsusscanFiles.Name -join ', ')" -Level "Warning"
            } else {
                Write-Log "WSUSSCAN files found (will be included): $($wsusscanFiles.Name -join ', ')" -Level "Info"
            }
        }
        
        if (-not $validCABFiles) {
            throw "No valid CAB files found after excluding WSUSSCAN files"
        }
        
        # Identify SSU files
        $ssuFiles = $validCABFiles | Where-Object { 
            $_.Name.ToLower() -like "*ssu*" -or 
            $_.Name.ToLower() -like "*servicing*stack*" -or 
            $_.Name.ToLower() -like "*service*stack*" 
        }
        
        if ($ssuFiles) {
            Write-Log "Service Stack Update files detected: $($ssuFiles.Name -join ', ')" -Level "Info"
        }
        
        Write-Log "Valid CAB files for installation: $($validCABFiles.Name -join ', ')" -Level "Success"
        return $validCABFiles
    }
    catch {
        throw "Failed to expand MSU file: $_"
    }
}

function Install-CABFiles {
    <#
    .SYNOPSIS
    Install CAB files using DISM with proper ordering (SSU first, excluding WSUSSCAN.cab)
    #>
    param([System.IO.FileInfo[]]$CABFiles)
    
    # Filter out WSUSSCAN.cab if requested and sort remaining files
    $filteredCABs = if ($ExcludeWSUSSCAN) {
        $CABFiles | Where-Object { 
            $_.Name -notlike "*WSUSSCAN*" -and $_.Name -notlike "*wsusscan*" 
        }
    } else {
        $CABFiles
    }
    
    if ($ExcludeWSUSSCAN -and ($filteredCABs.Count -lt $CABFiles.Count)) {
        $excludedFiles = $CABFiles | Where-Object { $_.Name -like "*WSUSSCAN*" -or $_.Name -like "*wsusscan*" }
        Write-Log "Excluded WSUSSCAN files: $($excludedFiles.Name -join ', ')" -Level "Warning"
    }
    
    if (-not $filteredCABs) {
        throw "No valid CAB files to install after filtering"
    }
    
    # Sort CAB files with proper priority:
    # 1. Service Stack Updates (SSU) - highest priority
    # 2. Security updates 
    # 3. Other KB updates
    # 4. Everything else
    $sortedCABs = $filteredCABs | Sort-Object { 
        $name = $_.Name.ToLower()
        if ($name -like "*ssu*" -or $name -like "*servicing*stack*" -or $name -like "*service*stack*") { 
            return 0  # SSU first
        } 
        elseif ($name -like "*security*" -or $name -like "*sec*") { 
            return 1  # Security updates second
        }
        elseif ($name -like "*kb*") { 
            return 2  # Regular KB updates third
        }
        else { 
            return 3  # Everything else last
        }
    }, Name  # Secondary sort by name for consistency
    
    # Separate SSU and non-SSU files for special handling
    $ssuFiles = $sortedCABs | Where-Object { 
        $_.Name.ToLower() -like "*ssu*" -or 
        $_.Name.ToLower() -like "*servicing*stack*" -or 
        $_.Name.ToLower() -like "*service*stack*" 
    }
    
    $nonSSUFiles = $sortedCABs | Where-Object { 
        $_.Name.ToLower() -notlike "*ssu*" -and 
        $_.Name.ToLower() -notlike "*servicing*stack*" -and 
        $_.Name.ToLower() -notlike "*service*stack*" 
    }
    
    if ($ssuFiles) {
        Write-Log "Found $($ssuFiles.Count) Service Stack Update(s): $($ssuFiles.Name -join ', ')" -Level "Info"
        Write-Log "SSU files will be installed first and may require intermediate restart" -Level "Info"
    }
    
    Write-Log "Installation order: $($sortedCABs.Name -join ' -> ')" -Level "Info"
    
    $restartRequired = $false
    $ssuInstalled = $false
    
    # Install SSU files first
    foreach ($cab in $ssuFiles) {
        Write-Log "Installing Service Stack Update: $($cab.Name)" -Level "Info"
        
        try {
            $dismArgs = @("/Online", "/Add-Package", "/PackagePath:`"$($cab.FullName)`"", "/quiet", "/norestart")
            $dismProcess = Start-Process "DISM.exe" -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
            
            switch ($dismProcess.ExitCode) {
                0 { 
                    Write-Log "Successfully installed SSU: $($cab.Name)" -Level "Success"
                    $ssuInstalled = $true
                }
                3010 { 
                    Write-Log "Successfully installed SSU: $($cab.Name) - Restart required" -Level "Success"
                    $restartRequired = $true
                    $ssuInstalled = $true
                }
                default { 
                    throw "DISM failed with exit code: $($dismProcess.ExitCode)"
                }
            }
            
            # Brief pause after SSU installation
            Start-Sleep -Seconds 3
            
        }
        catch {
            throw "Failed to install Service Stack Update $($cab.Name): $_"
        }
    }
    
    # If SSU was installed and requires restart, warn but continue
    if ($ssuInstalled -and $restartRequired) {
        Write-Log "Service Stack Update installed successfully" -Level "Success"
        Write-Log "Continuing with remaining updates (restart will be needed after all installations)" -Level "Info"
    }
    
    # Install remaining updates
    foreach ($cab in $nonSSUFiles) {
        Write-Log "Installing: $($cab.Name)" -Level "Info"
        
        try {
            $dismArgs = @("/Online", "/Add-Package", "/PackagePath:`"$($cab.FullName)`"", "/quiet", "/norestart")
            $dismProcess = Start-Process "DISM.exe" -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
            
            switch ($dismProcess.ExitCode) {
                0 { 
                    Write-Log "Successfully installed $($cab.Name)" -Level "Success"
                }
                3010 { 
                    Write-Log "Successfully installed $($cab.Name) - Restart required" -Level "Success"
                    $restartRequired = $true
                }
                default { 
                    throw "DISM failed with exit code: $($dismProcess.ExitCode)"
                }
            }
        }
        catch {
            throw "Failed to install $($cab.Name): $_"
        }
    }
    
    return $restartRequired
}

function Get-InstallationLogs {
    <#
    .SYNOPSIS
    Collect relevant installation logs for troubleshooting
    #>
    
    Write-Log "Collecting installation logs..." -Level "Info"
    
    try {
        # DISM logs
        $dismLogPath = "C:\Windows\Logs\DISM\dism.log"
        if (Test-Path $dismLogPath) {
            $dismEntries = Get-Content $dismLogPath -Tail 20 | Where-Object { $_ -match "Error|Warning" }
            if ($dismEntries) {
                Write-Log "Recent DISM log entries:" -Level "Info"
                $dismEntries | ForEach-Object { Write-Log "  $_" -Level "Info" }
            }
        }
        
        # CBS logs
        $cbsLogPath = "C:\Windows\Logs\CBS\CBS.log"
        if (Test-Path $cbsLogPath) {
            $cbsEntries = Get-Content $cbsLogPath -Tail 20 | Where-Object { $_ -match "Error|Warning" }
            if ($cbsEntries) {
                Write-Log "Recent CBS log entries:" -Level "Info"
                $cbsEntries | ForEach-Object { Write-Log "  $_" -Level "Info" }
            }
        }
        
        # Setup event logs
        $setupEvents = Get-WinEvent -LogName Setup -MaxEvents 5 -ErrorAction SilentlyContinue | 
                      Where-Object { $_.LevelDisplayName -in @("Error", "Warning") }
        
        if ($setupEvents) {
            Write-Log "Recent Setup events:" -Level "Info"
            $setupEvents | ForEach-Object {
                Write-Log "  Event ID: $($_.Id), Level: $($_.LevelDisplayName), Message: $($_.Message)" -Level "Info"
            }
        }
    }
    catch {
        Write-Log "Error collecting logs: $_" -Level "Warning"
    }
}

function Clear-TemporaryFiles {
    <#
    .SYNOPSIS
    Clean up temporary files created during installation
    #>
    
    if (-not $CleanupAfter) {
        Write-Log "Cleanup skipped (CleanupAfter = false)" -Level "Info"
        return
    }
    
    Write-Log "Cleaning up temporary files..." -Level "Info"
    
    try {
        # Remove MSU file
        Get-ChildItem -Filter "*.msu" | Remove-Item -Force -ErrorAction SilentlyContinue
        
        # Remove valid CAB files (keep WSUSSCAN for reference if needed)
        Get-ChildItem -Filter "*.cab" | Where-Object { 
            $_.Name -notlike "*WSUSSCAN*" -and $_.Name -notlike "*wsusscan*" 
        } | Remove-Item -Force -ErrorAction SilentlyContinue
        
        # Optionally remove WSUSSCAN files too
        $wsusscanFiles = Get-ChildItem -Filter "*WSUSSCAN*.cab" -ErrorAction SilentlyContinue
        if ($wsusscanFiles) {
            Write-Log "WSUSSCAN files preserved for reference: $($wsusscanFiles.Name -join ', ')" -Level "Info"
            # Uncomment the next line if you want to remove WSUSSCAN files too
            $wsusscanFiles | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "Temporary files cleaned up successfully" -Level "Success"
    }
    catch {
        Write-Log "Error during cleanup: $_" -Level "Warning"
    }
}

#endregion

#region Main Script

try {
    Write-Host "Windows KB Installation Script" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "KB Number: $KBNumber" -ForegroundColor Yellow
    Write-Host "Use Local Files: $UseLocalFiles" -ForegroundColor Yellow
    Write-Host "Download URL: $DownloadURL" -ForegroundColor Yellow
    Write-Host "Temp Path: $TempPath" -ForegroundColor Yellow
    Write-Host "Local Search Paths: $($LocalSearchPaths -join ', ')" -ForegroundColor Yellow
    Write-Host ""
    
    # Initialize environment
    Initialize-Environment
    
    Write-Log "Starting KB$KBNumber installation process" -Level "Info"
    
    # Check if already installed
    if (Test-KBInstallation $KBNumber) {
        Write-Log "Installation cancelled - KB already installed" -Level "Info"
        exit 0
    }
    
    # Determine package source
    $packageSource = Get-PackageSource -KBNumber $KBNumber
    Write-Log $packageSource.Message -Level "Success"
    
    # Get CAB files based on source
    if ($packageSource.Source -eq "Local") {
        Write-Log "Using local CAB files" -Level "Info"
        $cabFiles = $packageSource.Files
    } else {
        Write-Log "Downloading from internet" -Level "Info"
        
        # Test internet connectivity only when downloading
        if (-not (Test-InternetConnectivity)) {
            throw "Internet connectivity test failed"
        }
        
        # Download and extract
        $msuFileName = [System.IO.Path]::GetFileName($DownloadURL)
        $msuPath = Join-Path $TempPath $msuFileName
        
        Write-Log "Starting download of $msuFileName" -Level "Info"
        Invoke-FileDownload -URL $DownloadURL -OutputPath $msuPath
        
        # Extract CAB files
        $cabFiles = Expand-MSUFile -MSUPath $msuPath
    }
    
    # Install CAB files
    $restartRequired = Install-CABFiles -CABFiles $cabFiles
    
    # Verify installation
    Start-Sleep -Seconds 5  # Allow time for system to register the installation
    
    if (Test-KBInstallation $KBNumber) {
        Write-Log "KB$KBNumber installation completed successfully!" -Level "Success"
        
        # Create success flag
        $successFlag = Join-Path $TempPath "KB${KBNumber}_success.flag"
        Set-Content -Path $successFlag -Value "Installation completed: $(Get-Date)"
        
        if ($restartRequired) {
            Write-Log "IMPORTANT: A system restart is required to complete the installation" -Level "Warning"
            Write-Log "Initiating system restart in 30 seconds..." -Level "Info"
            shutdown /r /t 30 /c "KB$KBNumber installation requires restart"           
        }
        
        exit 0
    }
    else {
        throw "Installation appeared successful but KB$KBNumber is not detected as installed"
    }
}
catch {
    Write-Log "INSTALLATION FAILED: $_" -Level "Error"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "Error"
    
    # Collect logs for troubleshooting
    Get-InstallationLogs
    
    exit 1
}
finally {
    # Always attempt cleanup
    Clear-TemporaryFiles
    
    Write-Log "Script execution completed" -Level "Info"
    Write-Log "Log file saved to: $script:LogFile" -Level "Info"
}

#endregion

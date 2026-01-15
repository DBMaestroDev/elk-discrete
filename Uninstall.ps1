<#
.SYNOPSIS
    ELK Stack uninstaller - Remove services and clean up installation

.DESCRIPTION
    Stops and removes Windows services for Elasticsearch, Kibana, and Logstash.
    Optionally removes the installation directory and downloaded files.

.PARAMETER Path
    Installation directory (default: C:\DBmaestroELK)

.PARAMETER RemoveInstallation
    If specified, removes the entire installation directory (default: $false)

.PARAMETER RemoveDownloads
    If specified, removes the downloads directory (default: $false)

.PARAMETER Force
    If specified, skips confirmation prompts (default: $false)

.EXAMPLE
    .\3-Uninstall.ps1 -Path "C:\DBmaestroELK"

.EXAMPLE
    .\3-Uninstall.ps1 -Path "C:\DBmaestroELK" -RemoveInstallation -RemoveDownloads -Force

#>

param(
    [string]$Path = "C:\DBmaestroELK",
    [switch]$RemoveInstallation = $false,
    [switch]$RemoveDownloads = $false,
    [switch]$Force = $false
)

$ElasticsearchDir = "$Path\elasticsearch"
$KibanaDir = "$Path\kibana"
$LogstashDir = "$Path\logstash"
$DownloadPath = "$Path\downloads"
$LogFile = Join-Path $PSScriptRoot "ELK-Uninstall-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Write to console and log file
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Write-Host $Message
    
    try {
        Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue
    }
    catch {
        # Silently fail if log file can't be written
    }
}

# Check admin rights
function Test-Administrator {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Confirm action
function Confirm-Action {
    param([string]$Message)
    
    if ($Force) {
        return $true
    }
    
    $response = Read-Host "$Message (Y/N)"
    return $response -eq "Y" -or $response -eq "y"
}

# Stop and remove a service
function Remove-Service {
    param([string]$ServiceName)
    
    Write-Log "Processing service: $ServiceName"
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if ($service) {
        if ($service.Status -eq "Running") {
            Write-Log "  Stopping service..."
            try {
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                Write-Log "  OK: Service stopped"
            }
            catch {
                Write-Log "  WARNING: Failed to stop service: $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-Log "  Removing service..."
        try {
            # Try native removal first (for Elasticsearch)
            if ($ServiceName -eq "DOP_Elasticsearch") {
                $esBatPath = Join-Path $ElasticsearchDir "bin\elasticsearch-service.bat"
                if (Test-Path $esBatPath) {
                    & cmd /c $esBatPath remove "DOP_Elasticsearch"
                    Start-Sleep -Seconds 2
                }
            }
            else {
                # Use NSSM for Kibana and Logstash
                $nssmFile = Get-ChildItem -Path $DownloadPath -Filter "nssm*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                
                if ($nssmFile) {
                    & $nssmFile.FullName remove $ServiceName confirm
                    Start-Sleep -Seconds 2
                }
                else {
                    # Fallback to native Remove-Service
                    sc.exe delete $ServiceName
                    Start-Sleep -Seconds 2
                }
            }
            
            Write-Log "  OK: Service removed"
        }
        catch {
            Write-Log "  WARNING: Failed to remove service: $($_.Exception.Message)" "WARN"
        }
    }
    else {
        Write-Log "  INFO: Service not found"
    }
}

# Main execution
Write-Log "==============================================================="
Write-Log "ELK Stack Uninstaller - Starting"
Write-Log "==============================================================="

# Check administrator rights
if (-not (Test-Administrator)) {
    Write-Log "ERROR: This script requires administrator privileges" "ERROR"
    exit 1
}

Write-Log ""
Write-Log "Configuration:"
Write-Log "  Installation Path: $Path"
Write-Log "  Remove Installation: $RemoveInstallation"
Write-Log "  Remove Downloads: $RemoveDownloads"
Write-Log "  Force Mode: $Force"

Write-Log ""

# Confirm uninstall action
if (-not (Confirm-Action "This will stop and remove ELK services. Continue?")) {
    Write-Log "INFO: Uninstall cancelled by user"
    exit 0
}

Write-Log ""
Write-Log "STEP 1: Stop and Remove Services"
Write-Log "---------------------------------------------------------------"

Remove-Service -ServiceName "DOP_Logstash"
Write-Log ""
Remove-Service -ServiceName "DOP_Kibana"
Write-Log ""
Remove-Service -ServiceName "DOP_Elasticsearch"

Write-Log ""

# Remove installation directory
if ($RemoveInstallation) {
    Write-Log "STEP 2: Remove Installation Directory"
    Write-Log "---------------------------------------------------------------"
    
    if (-not (Confirm-Action "This will delete the entire installation directory at $Path. Continue?")) {
        Write-Log "INFO: Installation directory removal skipped"
    }
    else {
        if (Test-Path $Path) {
            try {
                Write-Log "Removing installation directory: $Path"
                Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                Write-Log "OK: Installation directory removed"
            }
            catch {
                Write-Log "ERROR: Failed to remove installation directory: $($_.Exception.Message)" "ERROR"
            }
        }
        else {
            Write-Log "INFO: Installation directory not found: $Path"
        }
    }
    
    Write-Log ""
}

# Remove downloads directory
if ($RemoveDownloads) {
    Write-Log "STEP 3: Remove Downloads Directory"
    Write-Log "---------------------------------------------------------------"
    
    if (-not (Confirm-Action "This will delete the downloads directory at $DownloadPath. Continue?")) {
        Write-Log "INFO: Downloads directory removal skipped"
    }
    else {
        if (Test-Path $DownloadPath) {
            try {
                Write-Log "Removing downloads directory: $DownloadPath"
                Remove-Item -Path $DownloadPath -Recurse -Force -ErrorAction Stop
                Write-Log "OK: Downloads directory removed"
            }
            catch {
                Write-Log "ERROR: Failed to remove downloads directory: $($_.Exception.Message)" "ERROR"
            }
        }
        else {
            Write-Log "INFO: Downloads directory not found: $DownloadPath"
        }
    }
    
    Write-Log ""
}

Write-Log ""
Write-Log "==============================================================="
Write-Log "ELK Stack Uninstaller - Complete"
Write-Log "==============================================================="
Write-Log ""

if ($RemoveInstallation -or $RemoveDownloads) {
    Write-Log "Removed items:"
    if ($RemoveInstallation) {
        Write-Log "  - Installation directory: $Path"
    }
    if ($RemoveDownloads) {
        Write-Log "  - Downloads directory: $DownloadPath"
    }
}
else {
    Write-Log "Removed items:"
    Write-Log "  - Windows services: DOP_Elasticsearch, DOP_Kibana, DOP_Logstash"
    Write-Log ""
    Write-Log "To also remove installation files, use the following options:"
    Write-Log "  -RemoveInstallation  Remove the entire installation directory"
    Write-Log "  -RemoveDownloads     Remove the downloads directory"
}

Write-Log ""
Write-Log "Log file: $LogFile"
Write-Log "==============================================================="

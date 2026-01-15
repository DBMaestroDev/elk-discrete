<#
.SYNOPSIS
    ELK Stack downloader - Download, verify, and extract components with version tracking

.DESCRIPTION
    Downloads Elasticsearch, Kibana, and Logstash, verifies SHA512 checksums, and extracts them.
    Checks component version files to skip downloads/extractions if already at target version.

.PARAMETER Version
    Version of Elastic Stack to install (default: 9.2.3)

.PARAMETER Path
    Installation directory (default: C:\DBmaestroELK)

.PARAMETER Force
    Force re-download and re-extract even if version matches (default: $false)

.EXAMPLE
    .\1-Download.ps1 -Version 9.2.3 -Path "C:\DBmaestroELK"

.EXAMPLE
    .\1-Download.ps1 -Version 9.2.3 -Path "C:\DBmaestroELK" -Force

#>

param(
    [string]$Version = "9.2.3",
    [string]$Path = "C:\DBmaestroELK",
    [switch]$Force = $false
)

$DownloadDir = "$Path\downloads"
$ElasticsearchDir = "$Path\elasticsearch"
$KibanaDir = "$Path\kibana"
$LogstashDir = "$Path\logstash"
$ESVersionFile = "$ElasticsearchDir\version.txt"
$KBVersionFile = "$KibanaDir\version.txt"
$LSVersionFile = "$LogstashDir\version.txt"
$LogFile = Join-Path $PSScriptRoot "ELK-Download-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

# Get component version
function Get-ComponentVersion {
    param([string]$VersionFilePath)
    
    if (Test-Path $VersionFilePath) {
        return (Get-Content $VersionFilePath -Raw).Trim()
    }
    return ""
}

# Set component version
function Set-ComponentVersion {
    param([string]$VersionFilePath, [string]$Ver)
    
    try {
        $Ver | Set-Content $VersionFilePath -NoNewline
    }
    catch {
        Write-Log "WARN: Failed to update component version file: $_" "WARN"
    }
}

# Download file with retries and SHA verification
function Download-File {
    param([string]$Url, [string]$OutFile)
    
    if (Test-Path $OutFile) {
        Write-Log "OK: Already downloaded: $(Split-Path $OutFile -Leaf)"
        return $true
    }
    
    Write-Log "... Downloading: $(Split-Path $OutFile -Leaf)"
    
    for ($i = 1; $i -le 3; $i++) {
        try {
            $req = [System.Net.HttpWebRequest]::Create($Url)
            $req.Timeout = 30000
            $res = $req.GetResponse()
            $total = $res.ContentLength
            
            $inStream = $res.GetResponseStream()
            $outStream = [System.IO.File]::Create($OutFile)
            $buf = New-Object byte[] 1048576
            $downloaded = 0
            
            while ($true) {
                $read = $inStream.Read($buf, 0, $buf.Length)
                if ($read -eq 0) { break }
                $outStream.Write($buf, 0, $read) | Out-Null
                $downloaded += $read
            }
            
            $outStream.Close()
            $inStream.Close()
            $res.Dispose()
            
            Write-Log "OK: Downloaded"
            return $true
        }
        catch {
            Write-Log "WARN: Attempt $i failed: $($_.Exception.Message)" "WARN"
            if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
            if ($i -lt 3) {
                Write-Log "    Retrying in 10 seconds..."
                Start-Sleep -Seconds 10
            }
        }
    }
    
    Write-Log "ERROR: Download failed" "ERROR"
    return $false
}

# Verify SHA512 checksum
function Verify-Checksum {
    param([string]$FilePath, [string]$Url)
    
    $fileName = Split-Path $FilePath -Leaf
    Write-Log "... Verifying checksum for: $fileName"
    
    try {
        # Download SHA512 file
        $shaUrl = "$Url.sha512"
        $shaFile = "$FilePath.sha512"
        
        $req = [System.Net.HttpWebRequest]::Create($shaUrl)
        $req.Timeout = 30000
        $res = $req.GetResponse()
        $reader = New-Object System.IO.StreamReader($res.GetResponseStream())
        $shaContent = $reader.ReadToEnd()
        $reader.Close()
        $res.Dispose()
        
        # Extract checksum (format: "hash  filename")
        $expectedHash = ($shaContent -split '\s+')[0].ToLower()
        
        # Compute file hash
        $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA512).Hash.ToLower()
        
        if ($fileHash -eq $expectedHash) {
            Write-Log "OK: Checksum verified"
            return $true
        }
        else {
            Write-Log "ERROR: Checksum mismatch!" "ERROR"
            Write-Log "  Expected: $expectedHash"
            Write-Log "  Got:      $fileHash"
            return $false
        }
    }
    catch {
        Write-Log "ERROR: Failed to verify checksum: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Extract and flatten
function Extract-Package {
    param([string]$ZipFile, [string]$DestDir, [string]$Component)
    
    Write-Log "... Extracting: $Component"
    
    if (Test-Path $DestDir) {
        Remove-Item -Path $DestDir -Recurse -Force
    }
    
    New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
    Expand-Archive -Path $ZipFile -DestinationPath $DestDir -Force
    
    # Move files up one level
    $subDir = Get-ChildItem -Path $DestDir -Directory | Select-Object -First 1
    if ($subDir) {
        Get-ChildItem -Path $subDir.FullName | Move-Item -Destination $DestDir -Force
        Remove-Item -Path $subDir.FullName -Force
    }
    
    Write-Log "OK: Extracted to: $DestDir"
}

# Download and extract component
function Download-Component {
    param(
        [string]$Name,
        [string]$Url,
        [string]$ZipFile,
        [string]$DestDir,
        [string]$VersionFilePath
    )
    
    $currentCompVer = Get-ComponentVersion -VersionFilePath $VersionFilePath
    $versionFileExists = Test-Path $VersionFilePath
    
    # Skip only if version.txt exists AND contains the same version as target
    if (-not $Force -and $versionFileExists -and $currentCompVer -eq $Version) {
        Write-Log "OK: $Name already at version $Version"
        return $true
    }
    
    Write-Log "... Processing: $Name"
    
    # Download file if not already downloaded
    if (-not (Test-Path $ZipFile)) {
        if (-not (Download-File -Url $Url -OutFile $ZipFile)) {
            Write-Log "ERROR: Failed to download $Name" "ERROR"
            return $false
        }
    }
    else {
        Write-Log "OK: Already downloaded: $(Split-Path $ZipFile -Leaf)"
    }
    
    # Verify checksum
    if (-not (Verify-Checksum -FilePath $ZipFile -Url $Url)) {
        Write-Log "ERROR: Checksum verification failed for $Name" "ERROR"
        return $false
    }
    
    # Extract
    Extract-Package -ZipFile $ZipFile -DestDir $DestDir -Component $Name
    
    # Update component version
    Set-ComponentVersion -VersionFilePath $VersionFilePath -Ver $Version
    
    return $true
}

# Main
Write-Log ""
Write-Log "==============================================================="
Write-Log "ELK Stack Download and Extract"
Write-Log "==============================================================="
Write-Log "Target Version: $Version"
Write-Log "Install Path: $Path"
Write-Log "Log File: $LogFile"
Write-Log ""

# Create directories
@($Path, $DownloadDir) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

Write-Log "INFO: Target version: $Version"
if ($Force) { Write-Log "INFO: Force re-download enabled" }
Write-Log ""

# Download and extract components
Write-Log "STEP 1: Download and Extract Components"
Write-Log "---------------------------------------------------------------"

$esUrl = "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$Version-windows-x86_64.zip"
$esZip = "$DownloadDir\elasticsearch-$Version.zip"
if (-not (Download-Component -Name "Elasticsearch" -Url $esUrl -ZipFile $esZip -DestDir $ElasticsearchDir -VersionFilePath $ESVersionFile)) {
    exit 1
}

Write-Log ""

$kbUrl = "https://artifacts.elastic.co/downloads/kibana/kibana-$Version-windows-x86_64.zip"
$kbZip = "$DownloadDir\kibana-$Version.zip"
Write-Log "INFO: Kibana extraction can take several minutes due to the large number of files. Please wait..."
if (-not (Download-Component -Name "Kibana" -Url $kbUrl -ZipFile $kbZip -DestDir $KibanaDir -VersionFilePath $KBVersionFile)) {
    exit 1
}

Write-Log ""

$lsUrl = "https://artifacts.elastic.co/downloads/logstash/logstash-$Version-windows-x86_64.zip"
$lsZip = "$DownloadDir\logstash-$Version.zip"
if (-not (Download-Component -Name "Logstash" -Url $lsUrl -ZipFile $lsZip -DestDir $LogstashDir -VersionFilePath $LSVersionFile)) {
    exit 1
}

Write-Log ""

Write-Log "STEP 2: Download and Extract NSSM"
Write-Log "---------------------------------------------------------------"

# Download NSSM (Non-Sucking Service Manager)
$nssmUrl = "https://dbmutilities.blob.core.windows.net/installers/nssm-2.24-101-g897c7ad.zip"
$nssmZip = "$DownloadDir\nssm-2.24.zip"
$nssmDir = "$DownloadDir\nssm"

if (Test-Path $nssmDir) {
    Write-Log "OK: NSSM already downloaded and extracted at $nssmDir"
}
else {
    Write-Log "... Downloading NSSM (Non-Sucking Service Manager)"
    if (-not (Download-File -Url $nssmUrl -OutFile $nssmZip)) {
        Write-Log "ERROR: Failed to download NSSM" "ERROR"
        exit 1
    }
    
    Write-Log "... Verifying NSSM (checksum verification skipped - provider doesn't publish hashes)"
    
    Write-Log "... Extracting NSSM"
    Extract-Package -ZipFile $nssmZip -DestDir $nssmDir -Component "NSSM"
    Write-Log "OK: NSSM extracted to: $nssmDir"
}

Write-Log ""

Write-Log ""
Write-Log "==============================================================="
Write-Log "Download and Extract Complete"
Write-Log "==============================================================="
Write-Log ""
Write-Log "Components extracted to:"
Write-Log "  $ElasticsearchDir"
Write-Log "  $KibanaDir"
Write-Log "  $LogstashDir"
Write-Log ""
Write-Log "Component version files:"
Write-Log "  $ESVersionFile"
Write-Log "  $KBVersionFile"
Write-Log "  $LSVersionFile"
Write-Log ""
Write-Log "Log file: $LogFile"
Write-Log "==============================================================="

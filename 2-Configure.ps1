<#
.SYNOPSIS
    ELK Stack configuration - Create services and configure components

.DESCRIPTION
    Creates Windows services for Elasticsearch, Kibana, and Logstash.
    Configures elasticsearch.yml, kibana.yml, logstash.yml, and pipelines.yml files.
    Sets up Logstash keystore for secure credential storage.

.PARAMETER Path
    Installation directory (default: C:\DBmaestroELK)

.PARAMETER ElasticPassword
    Password for the 'elastic' user (optional, for keystore configuration)

.PARAMETER KibanaPassword
    Password for the 'kibana_system' user (default: changeme)

.PARAMETER LogstashPassword
    Password for the 'logstash_internal' user (default: changeme)

.PARAMETER JdbcConnectionString
    JDBC connection string for database connectivity (e.g., jdbc:postgresql://localhost:5432/dbmaestro_dop_repo)
    Required for Logstash pipeline execution

.PARAMETER JdbcUser
    Database user for JDBC connections (e.g., postgres)

.PARAMETER JdbcPassword
    Database password for JDBC connections
    Will be stored securely in Logstash keystore

.EXAMPLE
    .\2-Configure.ps1 -Path "C:\DBmaestroELK"

.EXAMPLE
    .\2-Configure.ps1 -Path "C:\DBmaestroELK" `
        -JdbcConnectionString "jdbc:postgresql://localhost:5432/dbmaestro_dop_repo" `
        -JdbcUser "postgres" `
        -JdbcPassword "123456"

.EXAMPLE
    .\2-Configure.ps1 -Path "C:\DBmaestroELK" `
        -KibanaPassword "MyPassword" `
        -LogstashPassword "MyPassword" `
        -JdbcConnectionString "jdbc:postgresql://localhost:5432/dbmaestro_dop_repo" `
        -JdbcUser "postgres" `
        -JdbcPassword "123456"

#>

param(
    [string]$Path = "C:\DBmaestroELK",
    [string]$ElasticPassword = "changeme",
    [string]$KibanaPassword = "changeme",
    [string]$LogstashPassword = "changeme",
    [string]$LogstashKeystorePass = "changeme",
    [string]$MetricbeatPassword = "changeme",
    [string]$FilebeatPassword = "changeme",
    [string]$HeartbeatPassword = "changeme",
    [string]$MonitoringPassword = "changeme",
    [string]$BeatsSystemPassword = "changeme",
    [string]$JdbcConnectionString = "jdbc:postgresql://localhost:5432/dbmaestro_dop_repo",
    [string]$JdbcUser = "postgres",
    [string]$JdbcPassword = "123456",
    [string]$JdbcTimezone = "America/New_York"
)

$ElasticsearchDir = "$Path\elasticsearch"
$KibanaDir = "$Path\kibana"
$LogstashDir = "$Path\logstash"
$DownloadPath = "$Path\downloads"
$ESVersionFile = "$ElasticsearchDir\version.txt"
$KBVersionFile = "$KibanaDir\version.txt"
$LSVersionFile = "$LogstashDir\version.txt"
$LogFile = Join-Path $PSScriptRoot "ELK-Configure-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

# Check if Elasticsearch requires authentication
function Test-ElasticsearchAuthRequired {
    param(
        [string]$ComputerName = "localhost",
        [int]$Port = 9200,
        [int]$MaxRetries = 60,
        [int]$RetryDelaySeconds = 5
    )
    
    $url = "http://${ComputerName}:${Port}/"
    
    Write-Log "Checking if Elasticsearch requires authentication..."
    
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            
            if ($response.StatusCode -eq 200) {
                Write-Log "OK: Elasticsearch is responding without auth required"
                return $false
            }
        }
        catch {
            # WebException with 401/403 indicates auth is required
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                if ($statusCode -eq 401 -or $statusCode -eq 403) {
                    Write-Log "OK: Elasticsearch requires authentication (HTTP $statusCode)"
                    return $true
                }
                else {
                    Write-Log "... Retrying auth check $i/$MaxRetries (HTTP $statusCode)"
                }
            }
            else {
                Write-Log "... Retrying auth check $i/$MaxRetries (connection attempt)"
            }
        }
        
        if ($i -lt $MaxRetries) {
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    
    Write-Log "ERROR: Could not determine if Elasticsearch requires authentication" "ERROR"
    return $null
}

# Wait for Kibana to be available
function Wait-ForKibana {
    param(
        [string]$ComputerName = "localhost",
        [int]$Port = 5601,
        [string]$Username = "elastic",
        [string]$Password = "",
        [int]$MaxRetries = 60,
        [int]$RetryDelaySeconds = 5
    )
    
    $url = "http://${ComputerName}:${Port}/api/status"
    
    Write-Log "Waiting for Kibana at http://${ComputerName}:${Port}"
    
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $headers = @{}
            if ($Password) {
                $pair = "${Username}:${Password}"
                $encodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
                $headers["Authorization"] = "Basic $encodedAuth"
            }
            
            $response = Invoke-WebRequest -Uri $url -Headers $headers -TimeoutSec 15 -UseBasicParsing -ErrorAction SilentlyContinue
            
            if ($response.StatusCode -eq 200) {
                Write-Log "OK: Kibana is responding (HTTP 200)"
                return $true
            }
        }
        catch {
            # Continue retrying
        }
        
        if ($i -lt $MaxRetries) {
            Write-Log "... Retry $i/$MaxRetries in $RetryDelaySeconds seconds"
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    
    Write-Log "ERROR: Kibana did not respond after $MaxRetries attempts" "ERROR"
    return $false
}

# Import Kibana dashboards from NDJSON file
function Import-KibanaDashboards {
    param(
        [string]$NdjsonFile,
        [string]$Username = "elastic",
        [string]$Password = ""
    )
    
    if (-not (Test-Path $NdjsonFile)) {
        Write-Log "ERROR: NDJSON file not found: $NdjsonFile" "ERROR"
        return $false
    }
    
    $kibanaUrl = "http://localhost:5601/api/saved_objects/_import?overwrite=true"
    
    try {
        Write-Log "  Importing: $(Split-Path $NdjsonFile -Leaf)"
        
        # Read file as bytes
        $fileBytes = [System.IO.File]::ReadAllBytes($NdjsonFile)
        
        # Create multipart form data with manual encoding
        # This approach is more reliable across PowerShell versions than System.Net.Http classes
        $boundary = [System.Guid]::NewGuid().ToString()
        
        # Build multipart body parts
        $headerText = "--$boundary`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$(Split-Path $NdjsonFile -Leaf)`"`r`nContent-Type: application/x-ndjson`r`n`r`n"
        $footerText = "`r`n--$boundary--"
        
        $headerBytes = [System.Text.Encoding]::UTF8.GetBytes($headerText)
        $footerBytes = [System.Text.Encoding]::UTF8.GetBytes($footerText)
        
        # Combine all parts into final body
        $bodyStream = New-Object System.IO.MemoryStream
        $bodyStream.Write($headerBytes, 0, $headerBytes.Length)
        $bodyStream.Write($fileBytes, 0, $fileBytes.Length)
        $bodyStream.Write($footerBytes, 0, $footerBytes.Length)
        $bodyArray = $bodyStream.ToArray()
        $bodyStream.Dispose()
        
        # Create headers
        $headers = @{
            "kbn-xsrf" = "true"
            "Content-Type" = "multipart/form-data; boundary=`"$boundary`""
        }
        
        if ($Password) {
            $pair = "${Username}:${Password}"
            $encodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
            $headers["Authorization"] = "Basic $encodedAuth"
        }
        
        $response = Invoke-WebRequest -Uri $kibanaUrl `
            -Method POST `
            -Headers $headers `
            -Body $bodyArray `
            -UseBasicParsing `
            -TimeoutSec 30 `
            -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) {
            Write-Log "    OK: Imported successfully"
            return $true
        }
        else {
            Write-Log "    ERROR: Import failed with status code: $($response.StatusCode)" "WARN"
            return $false
        }
    }
    catch {
        Write-Log "    ERROR: Import error: $($_.Exception.Message)" "WARN"
        return $false
    }
}

# Wait for Elasticsearch to be available (HTTP 200)
function Wait-ForElasticsearch {
    param(
        [string]$ComputerName = "localhost",
        [int]$Port = 9200,
        [string]$Username = "elastic",
        [string]$Password = "",
        [int]$MaxRetries = 60,
        [int]$RetryDelaySeconds = 5
    )
    
    $url = "http://${ComputerName}:${Port}/"
    
    Write-Log "Waiting for Elasticsearch at $url"
    
    $consecutive401s = 0
    
    for ($i = 1; $i -le $MaxRetries; $i++) {
        # Try without authentication first
        try {
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            
            if ($response.StatusCode -eq 200) {
                Write-Log "OK: Elasticsearch is responding (no auth)"
                return $true
            }
        }
        catch {
            # Not successful without auth, continue
        }
        
        # If password provided, try with authentication
        if ($Password) {
            try {
                $pair = "${Username}:${Password}"
                $encodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
                $headers = @{ "Authorization" = "Basic $encodedAuth" }
                
                $response = Invoke-WebRequest -Uri $url -Headers $headers -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
                
                if ($response.StatusCode -eq 200) {
                    Write-Log "OK: Elasticsearch is responding (with auth)"
                    $consecutive401s = 0
                    return $true
                }
            }
            catch {
                # Check what error we got
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    if ($statusCode -eq 200) {
                        Write-Log "OK: Elasticsearch is responding (with auth)"
                        return $true
                    }
                    elseif ($statusCode -eq 401) {
                        # Count consecutive 401s - if we get 3+, credentials are wrong
                        $consecutive401s++
                        if ($consecutive401s -ge 3) {
                            Write-Log "ERROR: Received multiple 401 responses (HTTP 401) - credentials appear to be incorrect"
                            return $false
                        }
                        Write-Log "... Retry $i/$MaxRetries (auth response: HTTP 401)"
                    }
                    else {
                        Write-Log "... Retry $i/$MaxRetries (HTTP $statusCode)"
                        $consecutive401s = 0
                    }
                }
                else {
                    Write-Log "... Retry $i/$MaxRetries (connection)"
                    $consecutive401s = 0
                }
            }
        }
        else {
            Write-Log "... Retry $i/$MaxRetries (no password provided)"
        }
        
        if ($i -lt $MaxRetries) {
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    
    Write-Log "ERROR: Elasticsearch did not respond after $MaxRetries attempts" "ERROR"
    return $false
}

# Wait for built-in users to be initialized
function Wait-ForBuiltInUsers {
    param(
        [string]$ComputerName = "localhost",
        [int]$Port = 9200,
        [string]$Username = "elastic",
        [string]$Password = "",
        [int]$MaxRetries = 30,
        [int]$RetryDelaySeconds = 1
    )
    
    $url = "http://${ComputerName}:${Port}/_security/user"
    
    Write-Log "Waiting for built-in users to be initialized..."
    
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $headers = @{}
            if ($Password) {
                $pair = "${Username}:${Password}"
                $encodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
                $headers["Authorization"] = "Basic $encodedAuth"
            }
            
            $response = Invoke-WebRequest -Uri $url -Headers $headers -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
            
            if ($response.StatusCode -eq 200) {
                # Parse the JSON response
                $users = $response.Content | ConvertFrom-Json
                
                # Get user names
                $userNames = $users.PSObject.Properties.Name
                
                # Check if elastic user exists (primary built-in user)
                if ($userNames -contains "elastic") {
                    $userCount = @($userNames).Count
                    Write-Log "OK: Built-in users initialized (found $userCount users: $($userNames -join ', '))"
                    return $true
                }
            }
        }
        catch {
            # Continue retrying silently
        }
        
        if ($i -lt $MaxRetries) {
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    
    Write-Log "ERROR: Built-in users not initialized after $MaxRetries attempts" "ERROR"
    return $false
}

# Test if a user exists
function Test-ElasticsearchUser {
    param(
        [string]$Username,
        [string]$ElasticPassword = ""
    )
    
    $url = "http://localhost:9200/_security/user/$Username"
    
    try {
        $headers = @{}
        if ($ElasticPassword) {
            $pair = "elastic:${ElasticPassword}"
            $encodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
            $headers["Authorization"] = "Basic $encodedAuth"
        }
        
        $response = Invoke-WebRequest -Uri $url -Headers $headers -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
        
        if ($response.StatusCode -eq 200) {
            return $true
        }
    }
    catch {
        # User doesn't exist
    }
    
    return $false
}

# Create or update an Elasticsearch role from JSON definition
function New-ElasticsearchRoleFromFile {
    param(
        [string]$RoleName,
        [string]$RoleJsonPath,
        [string]$ElasticPassword = ""
    )
    
    if (-not (Test-Path $RoleJsonPath)) {
        Write-Log "WARNING: Role file not found: $RoleJsonPath" "WARN"
        return $false
    }
    
    try {
        $roleContent = Get-Content -Path $RoleJsonPath -Raw
        
        $url = "http://localhost:9200/_security/role/$RoleName"
        
        $headers = @{ "Content-Type" = "application/json" }
        if ($ElasticPassword) {
            $pair = "elastic:${ElasticPassword}"
            $encodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
            $headers["Authorization"] = "Basic $encodedAuth"
        }
        
        $response = Invoke-WebRequest -Uri $url -Method PUT -Headers $headers -Body $roleContent -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) {
            Write-Log "OK: Role '$RoleName' created from $RoleJsonPath"
            return $true
        }
    }
    catch {
        Write-Log "ERROR: Failed to create role '$RoleName': $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Create or update an Elasticsearch role
function New-ElasticsearchRole {
    param(
        [string]$RoleName,
        [hashtable]$Permissions,
        [string]$ElasticPassword = ""
    )
    
    $url = "http://localhost:9200/_security/role/$RoleName"
    
    $body = $Permissions | ConvertTo-Json -Depth 10
    
    try {
        $headers = @{ "Content-Type" = "application/json" }
        if ($ElasticPassword) {
            $pair = "elastic:${ElasticPassword}"
            $encodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
            $headers["Authorization"] = "Basic $encodedAuth"
        }
        
        $response = Invoke-WebRequest -Uri $url -Method PUT -Headers $headers -Body $body -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) {
            Write-Log "OK: Role '$RoleName' created"
            return $true
        }
    }
    catch {
        Write-Log "ERROR: Failed to create role '$RoleName': $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Create or update a user
function New-ElasticsearchUser {
    param(
        [string]$Username,
        [string]$Password,
        [string]$Role = "",
        [string]$ElasticPassword = ""
    )
    
    $url = "http://localhost:9200/_security/user/$Username"
    
    $body = @{
        password = $Password
    } | ConvertTo-Json
    
    if ($Role) {
        $body = @{
            password = $Password
            roles    = @($Role)
        } | ConvertTo-Json
    }
    
    try {
        $headers = @{ "Content-Type" = "application/json" }
        if ($ElasticPassword) {
            $pair = "elastic:${ElasticPassword}"
            $encodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
            $headers["Authorization"] = "Basic $encodedAuth"
        }
        
        $response = Invoke-WebRequest -Uri $url -Method PUT -Headers $headers -Body $body -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) {
            Write-Log "OK: User '$Username' created"
            return $true
        }
    }
    catch {
        Write-Log "ERROR: Failed to create user '$Username': $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Set user password
function Set-ElasticsearchUserPassword {
    param(
        [string]$Username,
        [string]$Password,
        [string]$ElasticPassword = ""
    )
    
    $url = "http://localhost:9200/_security/user/$Username/_password"
    
    $body = @{
        password = $Password
    } | ConvertTo-Json
    
    try {
        $headers = @{ "Content-Type" = "application/json" }
        if ($ElasticPassword) {
            $pair = "elastic:${ElasticPassword}"
            $encodedAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
            $headers["Authorization"] = "Basic $encodedAuth"
        }
        
        $response = Invoke-WebRequest -Uri $url -Method POST -Headers $headers -Body $body -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) {
            Write-Log "OK: Password updated for user '$Username'"
            return $true
        }
    }
    catch {
        Write-Log "ERROR: Failed to update password for '$Username': $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Configure Elasticsearch
function Configure-Elasticsearch {
    Write-Log "Configuring Elasticsearch..."
    
    $configPath = Join-Path $ElasticsearchDir "config\elasticsearch.yml"
    $sourceConfigPath = Join-Path $PSScriptRoot "elasticsearch\config\elasticsearch.yml"
    
    if (-not (Test-Path $sourceConfigPath)) {
        Write-Log "ERROR: Source elasticsearch.yml not found at $sourceConfigPath" "ERROR"
        return $false
    }
    
    # Backup existing configuration if it exists
    if (Test-Path $configPath) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backupPath = "$configPath.backup-$timestamp"
        Copy-Item -Path $configPath -Destination $backupPath -Force
        Write-Log "Existing configuration backed up to: $backupPath"
    }
    
    # Copy configuration from source
    Copy-Item -Path $sourceConfigPath -Destination $configPath -Force
    
    # Replace ${PATH} placeholder with actual installation path (with escaped backslashes for YAML)
    $configContent = Get-Content -Path $configPath -Raw
    $escapedPath = $Path -replace '\\', '\\'
    $configContent = $configContent -replace '\$\{PATH\}', $escapedPath
    Set-Content -Path $configPath -Value $configContent
    
    Write-Log "OK: Elasticsearch configuration copied and paths configured"
    
    # Configure JVM options for Windows
    $jvmOptionsPath = Join-Path $ElasticsearchDir "config\jvm.options"
    $sourceJvmOptionsPath = Join-Path $PSScriptRoot "elasticsearch\config\jvm.options"
    
    if (-not (Test-Path $sourceJvmOptionsPath)) {
        Write-Log "ERROR: Source jvm.options not found at $sourceJvmOptionsPath" "ERROR"
        return $false
    }
    
    # Backup existing JVM options if they exist
    if (Test-Path $jvmOptionsPath) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backupPath = "$jvmOptionsPath.backup-$timestamp"
        Copy-Item -Path $jvmOptionsPath -Destination $backupPath -Force
        Write-Log "Existing JVM options backed up to: $backupPath"
    }
    
    # Copy from source
    Copy-Item -Path $sourceJvmOptionsPath -Destination $jvmOptionsPath -Force
    Write-Log "OK: JVM options configured from source"
}

# Configure Kibana
function Configure-Kibana {
    Write-Log "Configuring Kibana..."
    
    $configPath = Join-Path $KibanaDir "config\kibana.yml"
    $nodeOptionsPath = Join-Path $KibanaDir "config\node.options"
    $sourceConfigPath = Join-Path $PSScriptRoot "kibana\config\kibana.yml"
    $sourceNodeOptionsPath = Join-Path $PSScriptRoot "kibana\config\node.options"
    
    if (-not (Test-Path $sourceConfigPath)) {
        Write-Log "ERROR: Source kibana.yml not found at $sourceConfigPath" "ERROR"
        return $false
    }
    
    # Backup existing configuration if it exists
    if (Test-Path $configPath) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backupPath = "$configPath.backup-$timestamp"
        Copy-Item -Path $configPath -Destination $backupPath -Force
        Write-Log "Existing configuration backed up to: $backupPath"
    }
    
    # Copy configuration from source
    Copy-Item -Path $sourceConfigPath -Destination $configPath -Force
    
    # Replace ${KibanaPassword} placeholder with actual password
    $configContent = Get-Content -Path $configPath -Raw
    $configContent = $configContent -replace '\$\{KibanaPassword\}', $KibanaPassword
    Set-Content -Path $configPath -Value $configContent
    
    Write-Log "OK: Kibana configuration copied and passwords configured"
    
    # Copy node.options from elk-discrete source if it exists
    if (Test-Path $sourceNodeOptionsPath) {
        # Backup existing node.options if it exists
        if (Test-Path $nodeOptionsPath) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $backupPath = "$nodeOptionsPath.backup-$timestamp"
            Copy-Item -Path $nodeOptionsPath -Destination $backupPath -Force
            Write-Log "Existing node.options backed up to: $backupPath"
        }
        
        # Copy from source
        Copy-Item -Path $sourceNodeOptionsPath -Destination $nodeOptionsPath -Force
        Write-Log "OK: Kibana node.options configured from source"
    }
    else {
        Write-Log "WARNING: Source node.options not found at $sourceNodeOptionsPath" "WARN"
    }
}

# Configure Logstash
function Configure-Logstash {
    Write-Log "Configuring Logstash..."
    
    $configPath = Join-Path $LogstashDir "config\logstash.yml"
    $pipelinesPath = Join-Path $LogstashDir "config\pipelines.yml"
    $jvmOptionsPath = Join-Path $LogstashDir "config\jvm.options"
    
    # Copy logstash.yml from elk-discrete source
    $sourceLogstashYml = Join-Path $PSScriptRoot "logstash\config\logstash.yml"
    
    if (Test-Path $sourceLogstashYml) {
        # Backup existing configuration if it exists
        if (Test-Path $configPath) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $backupPath = "$configPath.backup-$timestamp"
            Copy-Item -Path $configPath -Destination $backupPath -Force
            Write-Log "Existing configuration backed up to: $backupPath"
        }
        
        Copy-Item -Path $sourceLogstashYml -Destination $configPath -Force
        
        # Replace ${PATH} placeholder with actual installation path (with escaped backslashes for YAML)
        $configContent = Get-Content -Path $configPath -Raw
        $escapedPath = $Path -replace '\\', '\\'
        $configContent = $configContent -replace '\$\{PATH\}', $escapedPath
        Set-Content -Path $configPath -Value $configContent
        
        Write-Log "OK: Logstash configuration copied and paths configured"
    }
    else {
        Write-Log "WARNING: Source logstash.yml not found at $sourceLogstashYml" "WARN"
    }
    
    # Copy pipelines.yml from elk-discrete source
    $sourcePipelinesYml = Join-Path $PSScriptRoot "logstash\config\pipelines.yml"
    
    if (Test-Path $sourcePipelinesYml) {
        # Backup existing pipelines configuration if it exists
        if (Test-Path $pipelinesPath) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $backupPath = "$pipelinesPath.backup-$timestamp"
            Copy-Item -Path $pipelinesPath -Destination $backupPath -Force
            Write-Log "Existing pipelines configuration backed up to: $backupPath"
        }
        
        # Read the source pipelines.yml
        $pipelinesContent = Get-Content -Path $sourcePipelinesYml -Raw
        
        # Replace ${PATH} placeholder with actual installation path (with escaped backslashes for YAML)
        $escapedPath = $Path -replace '\\', '\\'
        $pipelinesContent = $pipelinesContent -replace '\$\{PATH\}', $escapedPath
        
        # Write the updated content
        Set-Content -Path $pipelinesPath -Value $pipelinesContent
        Write-Log "OK: Pipelines configuration copied and paths configured"
    }
    else {
        Write-Log "WARNING: Source pipelines.yml not found at $sourcePipelinesYml" "WARN"
    }
    
    # Copy jvm.options from elk-discrete source
    $sourceJvmOptions = Join-Path $PSScriptRoot "logstash\config\jvm.options"
    
    if (Test-Path $sourceJvmOptions) {
        # Backup existing JVM options if they exist
        if (Test-Path $jvmOptionsPath) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $backupPath = "$jvmOptionsPath.backup-$timestamp"
            Copy-Item -Path $jvmOptionsPath -Destination $backupPath -Force
            Write-Log "Existing JVM options backed up to: $backupPath"
        }
        
        # Copy from source
        Copy-Item -Path $sourceJvmOptions -Destination $jvmOptionsPath -Force
        Write-Log "OK: Logstash JVM options configured from source"
    }
    else {
        Write-Log "WARNING: Source jvm.options not found at $sourceJvmOptions" "WARN"
    }
    
    # Copy PostgreSQL JDBC JAR file
    $sourceJdbcDir = Join-Path $PSScriptRoot "logstash\psql-jdbc-jar"
    $destinationJdbcDir = Join-Path $LogstashDir "psql-jdbc-jar"
    
    if (Test-Path $sourceJdbcDir) {
        # Create destination directory if it doesn't exist
        if (-not (Test-Path $destinationJdbcDir)) {
            New-Item -ItemType Directory -Path $destinationJdbcDir -Force | Out-Null
        }
        
        # Copy all JAR files
        $jarFiles = Get-ChildItem -Path $sourceJdbcDir -Filter "*.jar" -ErrorAction SilentlyContinue
        
        foreach ($file in $jarFiles) {
            Copy-Item -Path $file.FullName -Destination $destinationJdbcDir -Force
            Write-Log "OK: Copied $($file.Name) to $destinationJdbcDir"
        }
    }
    else {
        Write-Log "WARNING: Source JDBC directory not found at $sourceJdbcDir" "WARN"
    }
}

# Verify Logstash keystore contents
function Verify-LogstashKeystore {
    param(
        [string]$LogstashPath
    )
    
    Write-Log "Verifying Logstash keystore contents..."
    
    $keystoreToolPath = Join-Path $LogstashPath "bin\logstash-keystore.bat"
    
    if (-not (Test-Path $keystoreToolPath)) {
        Write-Log "WARNING: Logstash keystore tool not found at $keystoreToolPath" "WARN"
        return $false
    }
    
    try {
        Push-Location $LogstashPath\bin
        
        # List keystore contents (both stdout and stderr)
        $output = @(cmd /c "logstash-keystore.bat list 2>&1")
        
        Pop-Location
        
        # Filter out Java/Logstash startup messages - be more aggressive
        $keystoreLines = @()
        if ($output -and $output.Count -gt 0) {
            foreach ($line in $output) {
                # Skip lines that are Java startup messages or empty
                if ($line -and `
                    $line -notmatch "Using bundled" -and `
                    $line -notmatch "Sending Logstash" -and `
                    $line -notmatch "log4j2" -and `
                    $line -notmatch "^[a-zA-Z]:[\\]" -and `
                    $line -notmatch "^Enter value" -and `
                    $line -notmatch "Added.*to the Logstash" -and `
                    $line.Trim().Length -gt 0) {
                    $keystoreLines += $line.Trim()
                }
            }
        }
        
        Write-Log "Keystore contents:"
        if ($keystoreLines.Count -gt 0) {
            foreach ($line in $keystoreLines) {
                Write-Log "  $line"
            }
        }
        else {
            Write-Log "  (no entries found or unable to parse)"
        }
        
        # Check if both required passwords are in the keystore entries (case-insensitive)
        $foundJdbcPassword = $false
        $foundLogstashPassword = $false
        foreach ($line in $keystoreLines) {
            if ($line -match "^jdbc_password$" -or $line -match "^JDBC_PASSWORD$") {
                $foundJdbcPassword = $true
            }
            if ($line -match "^logstash_internal_password$" -or $line -match "^LOGSTASH_INTERNAL_PASSWORD$") {
                $foundLogstashPassword = $true
            }
        }
        
        # Report what was found
        if ($foundJdbcPassword) {
            Write-Log "OK: JDBC_PASSWORD found in keystore"
        }
        else {
            Write-Log "WARNING: JDBC_PASSWORD not found in keystore" "WARN"
        }
        
        if ($foundLogstashPassword) {
            Write-Log "OK: LOGSTASH_INTERNAL_PASSWORD found in keystore"
        }
        else {
            Write-Log "WARNING: LOGSTASH_INTERNAL_PASSWORD not found in keystore" "WARN"
        }
        
        # Return true if both passwords are found
        if ($foundJdbcPassword -and $foundLogstashPassword) {
            return $true
        }
        else {
            if (-not $foundJdbcPassword) {
                Write-Log "ERROR: JDBC_PASSWORD not found in keystore" "ERROR"
            }
            if (-not $foundLogstashPassword) {
                Write-Log "ERROR: LOGSTASH_INTERNAL_PASSWORD not found in keystore" "ERROR"
            }
            return $false
        }
    }
    catch {
        Write-Log "ERROR: Failed to verify keystore: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Create or manage Logstash keystore
function Initialize-LogstashKeystore {
    param(
        [string]$LogstashPath,
        [string]$JdbcPassword,
        [string]$LogstashPassword = "",
        [string]$LogstashKeystorePass = ""
    )
    
    Write-Log "Initializing Logstash keystore..."
    
    $keystorePath = Join-Path $LogstashPath "config\logstash.keystore"
    $keystoreToolPath = Join-Path $LogstashPath "bin\logstash-keystore.bat"
    
    if (-not (Test-Path $keystoreToolPath)) {
        Write-Log "WARNING: Logstash keystore tool not found at $keystoreToolPath" "WARN"
        return $false
    }
    
    # Create keystore if it doesn't exist
    if (-not (Test-Path $keystorePath)) {
        Write-Log "Creating new Logstash keystore..."
        try {
            Push-Location $LogstashPath\bin
            
            # Create keystore without password (user will be prompted, pass 'y' via stdin)
            Write-Log "Creating keystore without password protection..."
            "y" | & cmd /c "logstash-keystore.bat create 2>&1" | Out-Null
            
            Pop-Location
            Write-Log "OK: Keystore created"
        }
        catch {
            Write-Log "ERROR: Failed to create keystore: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    else {
        Write-Log "OK: Keystore already exists at $keystorePath"
    }
    
    # Add or update JDBC_PASSWORD in keystore
    if ($JdbcPassword) {
        Write-Log "Adding JDBC_PASSWORD to keystore..."
        try {
            Push-Location $LogstashPath\bin
            
            # Remove existing entry if it exists (suppress errors)
            & cmd /c "logstash-keystore.bat remove JDBC_PASSWORD" 2>&1 | Out-Null
            
            # Use a temporary file to pass the password to stdin (more reliable on Windows)
            $tempFile = [System.IO.Path]::GetTempFileName()
            try {
                Set-Content -Path $tempFile -Value $JdbcPassword -Encoding ASCII -NoNewline
                
                # Add the password using file redirection
                Get-Content $tempFile | & cmd /c "logstash-keystore.bat add JDBC_PASSWORD --stdin" 2>&1 | Out-Null
                
                Write-Log "OK: JDBC_PASSWORD added to keystore"
            }
            finally {
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
            }
            
            Pop-Location
        }
        catch {
            Write-Log "ERROR: Failed to add JDBC_PASSWORD to keystore: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    else {
        Write-Log "WARNING: No JDBC_PASSWORD provided, skipping keystore password entry" "WARN"
    }
    
    # Add or update LOGSTASH_INTERNAL_PASSWORD in keystore
    if ($LogstashPassword) {
        Write-Log "Adding LOGSTASH_INTERNAL_PASSWORD to keystore..."
        try {
            Push-Location $LogstashPath\bin
            
            # Remove existing entry if it exists (suppress errors)
            & cmd /c "logstash-keystore.bat remove LOGSTASH_INTERNAL_PASSWORD" 2>&1 | Out-Null
            
            # Use a temporary file to pass the password to stdin
            $tempFile = [System.IO.Path]::GetTempFileName()
            try {
                Set-Content -Path $tempFile -Value $LogstashPassword -Encoding ASCII -NoNewline
                
                # Add the password using file redirection
                Get-Content $tempFile | & cmd /c "logstash-keystore.bat add LOGSTASH_INTERNAL_PASSWORD --stdin" 2>&1 | Out-Null
                
                Write-Log "OK: LOGSTASH_INTERNAL_PASSWORD added to keystore"
            }
            finally {
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
            }
            
            Pop-Location
        }
        catch {
            Write-Log "ERROR: Failed to add LOGSTASH_INTERNAL_PASSWORD to keystore: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    else {
        Write-Log "WARNING: No LOGSTASH_INTERNAL_PASSWORD provided, skipping keystore password entry" "WARN"
    }
    
    return $true
}

# Update pipeline configuration files with environment variables
function Update-LogstashPipelines {
    param(
        [string]$PipelineDir,
        [string]$JdbcConnectionString,
        [string]$JdbcUser,
        [string]$LogstashDir
    )
    
    Write-Log "Updating Logstash pipeline configurations..."
    
    if (-not (Test-Path $PipelineDir)) {
        Write-Log "ERROR: Pipeline directory not found: $PipelineDir" "ERROR"
        return $false
    }
    
    # Build JDBC JAR path
    $jdbcJarPath = Join-Path $LogstashDir "psql-jdbc-jar"
    
    $confFiles = Get-ChildItem -Path $PipelineDir -Filter "*.conf" -ErrorAction SilentlyContinue
    
    foreach ($file in $confFiles) {
        $content = Get-Content $file.FullName -Raw
        $modified = $false
        
        # Replace JDBC_JAR path variable
        if ($content -match '\$\{JDBC_JAR\}') {
            $content = $content -replace '\$\{JDBC_JAR\}', $jdbcJarPath
            $modified = $true
        }
        
        # Replace JDBC connection details (non-sensitive)
        if ($JdbcConnectionString -and $content -match '\$\{JDBC_CONNECTION_STRING\}') {
            $content = $content -replace '\$\{JDBC_CONNECTION_STRING\}', $JdbcConnectionString
            $modified = $true
        }
        
        if ($JdbcUser -and $content -match '\$\{JDBC_USER\}') {
            $content = $content -replace '\$\{JDBC_USER\}', $JdbcUser
            $modified = $true
        }
        
        # NOTE: Do NOT replace ${JDBC_PASSWORD} or ${LOGSTASH_INTERNAL_PASSWORD}
        # These are read from the Logstash keystore at runtime for security
        
        if ($modified) {
            Set-Content -Path $file.FullName -Value $content
            Write-Log "  Updated: $($file.Name)"
        }
    }
    
    Write-Log "OK: Pipeline configurations updated"
    return $true
}

# Copy pipeline configurations
function Copy-Pipelines {
    Write-Log "Copying pipeline configurations..."
    
    $sourcePipelineDir = Join-Path $PSScriptRoot "logstash\pipeline"
    $destinationPipelineDir = Join-Path $LogstashDir "pipeline"
    
    if (-not (Test-Path $sourcePipelineDir)) {
        Write-Log "ERROR: Source pipeline directory not found: $sourcePipelineDir" "ERROR"
        return $false
    }
    
    # Create destination pipeline directory if it doesn't exist
    if (-not (Test-Path $destinationPipelineDir)) {
        New-Item -ItemType Directory -Path $destinationPipelineDir -Force | Out-Null
    }
    
    # Copy all .conf files
    $confFiles = Get-ChildItem -Path $sourcePipelineDir -Filter "*.conf" -ErrorAction SilentlyContinue
    
    if ($confFiles.Count -eq 0) {
        Write-Log "WARNING: No .conf files found in $sourcePipelineDir" "WARN"
        return $false
    }
    
    foreach ($file in $confFiles) {
        Copy-Item -Path $file.FullName -Destination $destinationPipelineDir -Force
    }
    
    Write-Log "OK: Pipeline configurations copied ($($confFiles.Count) .conf files)"    
    return $true
}

# Create Windows services
function Create-WindowsServices {
    Write-Log "Creating Windows services..."
    
    # Get NSSM path
    $nssmFile = Get-ChildItem -Path $DownloadPath -Filter "nssm*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if (-not $nssmFile) {
        Write-Log "ERROR: NSSM executable not found in $DownloadPath" "ERROR"
        return $false
    }
    
    $nssmPath = $nssmFile.FullName
    
    # Create Elasticsearch service (native Windows service)
    Write-Log "Creating DOP_Elasticsearch service (native)..."
    
    $esServiceName = "DOP_Elasticsearch"
    try {
        $esServiceExists = Get-Service -Name $esServiceName -ErrorAction SilentlyContinue
    }
    catch {
        $esServiceExists = $null
    }
    
    if (-not $esServiceExists) {
        # Set environment variables for elasticsearch-service.bat
        $env:SERVICE_DISPLAY_NAME = "DOP_Elasticsearch"
        $env:SERVICE_ID = "DOP_Elasticsearch"
        $env:SERVICE_DESCRIPTION = "DOP Elasticsearch"
        $env:ES_START_TYPE = "auto"
        $esBatPath = Join-Path $ElasticsearchDir "bin\elasticsearch-service.bat"
        if (Test-Path $esBatPath) {
            & cmd /c $esBatPath install
            Start-Sleep -Seconds 2
            Write-Log "OK: $esServiceName service created"
        }
        else {
            Write-Log "ERROR: elasticsearch-service.bat not found" "ERROR"
        }
    }
    else {
        Write-Log "INFO: $esServiceName service already exists"
    }
    
    # Create Kibana service (NSSM)
    Write-Log "Creating DOP_Kibana service..."
    
    $kbServiceName = "DOP_Kibana"
    try {
        $kbServiceExists = Get-Service -Name $kbServiceName -ErrorAction SilentlyContinue
    }
    catch {
        $kbServiceExists = $null
    }
    
    if (-not $kbServiceExists) {
        $kbExePath = Join-Path $KibanaDir "bin\kibana.bat"
        # Install service
        & $nssmPath install $kbServiceName $kbExePath
        & $nssmPath set $kbServiceName Description "DOP Kibana"
        & $nssmPath set $kbServiceName DisplayName "DOP_Kibana"
        # Configure service properties
        & $nssmPath set $kbServiceName AppDirectory $KibanaDir
        & $nssmPath set $kbServiceName AppStdout "$KibanaDir\logs\kibana-stdout.log"
        & $nssmPath set $kbServiceName AppStderr "$KibanaDir\logs\kibana-stderr.log"
        & $nssmPath set $kbServiceName Start SERVICE_AUTO_START
        
        # Configure logging rotation
        & $nssmPath set $kbServiceName AppRotateFiles 1
        & $nssmPath set $kbServiceName AppRotateOnline 1
        & $nssmPath set $kbServiceName AppRotateSeconds 86400
        & $nssmPath set $kbServiceName AppRotateBytes 10485760

        Start-Sleep -Seconds 2
        Write-Log "OK: $kbServiceName service created"
    }
    else {
        Write-Log "INFO: $kbServiceName service already exists"
    }
    
    # Create Logstash service (NSSM)
    Write-Log "Creating DOP_Logstash service..."
    
    $lsServiceName = "DOP_Logstash"
    try {
        $lsServiceExists = Get-Service -Name $lsServiceName -ErrorAction SilentlyContinue
    }
    catch {
        $lsServiceExists = $null
    }
    
    if ($lsServiceExists) {
        # Service exists - remove and recreate to clear old AppParameters
        Write-Log "Removing existing $lsServiceName service to apply new configuration..."
        & $nssmPath remove $lsServiceName confirm
        Start-Sleep -Seconds 2
    }
    
    if (-not $lsServiceExists -or $true) {  # Always recreate to ensure clean config
        $lsExePath = Join-Path $LogstashDir "bin\logstash.bat"
        
        # Install service
        & $nssmPath install $lsServiceName $lsExePath
        & $nssmPath set $lsServiceName DisplayName "DOP_Logstash"
        & $nssmPath set $lsServiceName Description "DOP Logstash"
        
        # Configure service properties
        & $nssmPath set $lsServiceName Start SERVICE_AUTO_START
        & $nssmPath set $lsServiceName AppDirectory $LogstashDir
        & $nssmPath set $lsServiceName AppExit Default Exit
        
        # Configure logging
        & $nssmPath set $lsServiceName AppStdout "$LogstashDir\logs\logstash-stdout.log"
        & $nssmPath set $lsServiceName AppStderr "$LogstashDir\logs\logstash-stderr.log"
        & $nssmPath set $lsServiceName AppRotateFiles 1
        & $nssmPath set $lsServiceName AppRotateOnline 1
        & $nssmPath set $lsServiceName AppRotateSeconds 86400
        & $nssmPath set $lsServiceName AppRotateBytes 10485760
        
        # Do NOT set AppParameters - let logstash.yml handle path configuration
        # Command line options would override pipelines.yml configuration
        
        # Configure JVM and Logstash environment variables
        # Detect Java installation
        $javaHome = $env:JAVA_HOME
        if (-not $javaHome) {
            # Try to find Java in typical locations
            $javaPathCandidates = @(
                "C:\Program Files\Java\jdk-21",
                "C:\Program Files\Java\jdk-21.0.9",
                "C:\Program Files\Java\jre-21",
                "$LogstashDir\..\java",
                "$LogstashDir\..\jdk"
            )
            foreach ($candidate in $javaPathCandidates) {
                if (Test-Path "$candidate\bin\java.exe") {
                    $javaHome = $candidate
                    break
                }
            }
        }
        
        if ($javaHome) {
            & $nssmPath set $lsServiceName AppEnvironmentExtra "JAVA_HOME=$javaHome"
            & $nssmPath set $lsServiceName AppEnvironmentExtra "LS_JAVA_HOME=$javaHome"
        }
        
        # Logstash-specific configuration
        & $nssmPath set $lsServiceName AppEnvironmentExtra "LOGSTASH_HOME=$LogstashDir"
        & $nssmPath set $lsServiceName AppEnvironmentExtra "LS_PATH_CONF=$LogstashDir\config"
        
        # Set timezone for JRuby (required for JDBC scheduler plugin on Windows)
        Write-Log "Using JDBC timezone: $JdbcTimezone"
        & $nssmPath set $lsServiceName AppEnvironmentExtra "TZ=$JdbcTimezone"
        
        Start-Sleep -Seconds 2
        Write-Log "OK: $lsServiceName service created with comprehensive configuration"
    }
    
    # Configure service dependencies
    Write-Log "Configuring service dependencies..."
    
    # Kibana depends on Elasticsearch
    sc.exe config DOP_Kibana depend= DOP_Elasticsearch
    
    # Logstash depends on Elasticsearch
    sc.exe config DOP_Logstash depend= DOP_Elasticsearch
    
    Write-Log "OK: Service dependencies configured"
    
    return $true
}

# Reset Elasticsearch password
function Reset-ElasticPassword {
    param(
        [string]$ElasticsearchPath
    )
    
    $resetToolPath = Join-Path $ElasticsearchPath "bin\elasticsearch-reset-password.bat"
    
    if (-not (Test-Path $resetToolPath)) {
        Write-Log "ERROR: Reset password tool not found at $resetToolPath" "ERROR"
        return $null
    }
    
    # Wait for cluster to be ready
    Write-Log "Waiting 30 seconds for Elasticsearch cluster to initialize..."
    Start-Sleep -Seconds 30
    
    $maxAttempts = 10
    $attempt = 0
    
    while ($attempt -lt $maxAttempts) {
        try {
            $attempt++
            Write-Log "Attempting to reset elastic password (attempt $attempt/$maxAttempts)..."
            
            Push-Location $ElasticsearchPath\bin
            
            # Reset password and capture output
            $output = & cmd.exe /c "$resetToolPath -u elastic -b --url http://localhost:9200/ 2>&1"
            
            Pop-Location
            
            # Parse the generated password from output
            $passwordLine = $output | Select-String "New value:"
            if ($passwordLine) {
                $password = $passwordLine -replace '.*New value:\s*', ''
                Write-Log "OK: Elastic user password generated on attempt $attempt"
                return $password.Trim()
            }
        }
        catch {
            Write-Log "Reset password attempt $attempt failed: $($_.Exception.Message)" "WARN"
        }
        
        if ($attempt -lt $maxAttempts) {
            Write-Log "Waiting 5 seconds before retry..."
            Start-Sleep -Seconds 5
        }
    }
    
    Write-Log "ERROR: Failed to reset elastic password after $maxAttempts attempts" "ERROR"
    return $null
}

# Main execution
Write-Log "==============================================================="
Write-Log "ELK Stack Configuration - Starting"
Write-Log "==============================================================="

# Check administrator rights
if (-not (Test-Administrator)) {
    Write-Log "ERROR: This script requires administrator privileges" "ERROR"
    exit 1
}

# Validate directories exist
if (-not (Test-Path $ElasticsearchDir)) {
    Write-Log "ERROR: Elasticsearch directory not found: $ElasticsearchDir" "ERROR"
    exit 1
}

if (-not (Test-Path $KibanaDir)) {
    Write-Log "ERROR: Kibana directory not found: $KibanaDir" "ERROR"
    exit 1
}

if (-not (Test-Path $LogstashDir)) {
    Write-Log "ERROR: Logstash directory not found: $LogstashDir" "ERROR"
    exit 1
}

Write-Log ""
Write-Log "STEP 1: Configure Elasticsearch, Kibana, and Logstash"
Write-Log "---------------------------------------------------------------"

Configure-Elasticsearch
Configure-Kibana
Configure-Logstash

Write-Log ""
Write-Log "STEP 2: Copy and Configure Pipeline Files"
Write-Log "---------------------------------------------------------------"

Copy-Pipelines

# Configure Logstash keystore and update pipelines with database credentials
if ($JdbcPassword) {
    Write-Log ""
    Write-Log "STEP 2b: Configure Logstash Keystore and Database Credentials"
    Write-Log "---------------------------------------------------------------"
    
    if (Initialize-LogstashKeystore -LogstashPath $LogstashDir -JdbcPassword $JdbcPassword -LogstashPassword $LogstashPassword -LogstashKeystorePass $LogstashKeystorePass) {
        Write-Log "OK: Logstash keystore configured"
        
        # Verify keystore contents
        if (Verify-LogstashKeystore -LogstashPath $LogstashDir) {
            Write-Log "OK: Keystore verification successful"
        }
        else {
            Write-Log "ERROR: Keystore verification failed" "ERROR"
        }
    }
    else {
        Write-Log "WARNING: Failed to configure keystore, pipelines may not start" "WARN"
    }
    
    # Update pipeline configurations with database connection details
    $pipelineDir = Join-Path $LogstashDir "pipeline"
    if (Update-LogstashPipelines -PipelineDir $pipelineDir `
        -JdbcConnectionString $JdbcConnectionString `
        -JdbcUser $JdbcUser `
        -LogstashDir $LogstashDir) {
        Write-Log "OK: Pipeline configurations updated with non-sensitive credentials"
    }
}
else {
    Write-Log "INFO: No JDBC credentials provided, pipelines will need manual configuration"
}

Write-Log ""
Write-Log "STEP 3: Create Windows Services"
Write-Log "---------------------------------------------------------------"

Create-WindowsServices

Write-Log ""
Write-Log "STEP 4: Configure Elasticsearch Users"
Write-Log "---------------------------------------------------------------"

# Start Elasticsearch service if not running
Write-Log "Starting Elasticsearch service..."
$esService = Get-Service -Name "DOP_Elasticsearch" -ErrorAction SilentlyContinue
if ($esService -and $esService.Status -ne "Running") {
    Start-Service "DOP_Elasticsearch" -ErrorAction SilentlyContinue
    Write-Log "Waiting for Elasticsearch to initialize..."
    Start-Sleep -Seconds 15
}
else {
    # Wait a bit for services to start
    Start-Sleep -Seconds 5
}

# Check if Elasticsearch requires authentication
$authRequired = Test-ElasticsearchAuthRequired

Write-Log ""

if ($authRequired) {
    Write-Log "INFO: Elasticsearch requires authentication"
    
    # Try to connect with provided password first
    Write-Log "Attempting to authenticate with provided ElasticPassword..."
    if (Wait-ForElasticsearch -Username "elastic" -Password $ElasticPassword) {
        Write-Log "OK: Successfully authenticated with provided ElasticPassword"
    }
    else {
        Write-Log "WARN: Could not authenticate with provided password, attempting reset..."
        
        # Reset the password
        $generatedPassword = Reset-ElasticPassword -ElasticsearchPath $ElasticsearchDir
        
        if ($generatedPassword) {
            Write-Log "Password reset generated: $generatedPassword"
            
            # Change it to the parameter value
            Write-Log "Waiting for Elasticsearch to stabilize..."
            Start-Sleep -Seconds 10
            
            if (Wait-ForElasticsearch -Username "elastic" -Password $generatedPassword) {
                Write-Log "Setting elastic password to parameter value..."
                if (Set-ElasticsearchUserPassword -Username "elastic" -Password $ElasticPassword -ElasticPassword $generatedPassword) {
                    Write-Log "OK: Password changed and verified"
                }
            }
        }
    }
    
    # Wait for built-in users
    if (Wait-ForBuiltInUsers -Username "elastic" -Password $ElasticPassword) {
        Write-Log "Creating/updating Elasticsearch roles and users..."
        
        # Create all roles from role files
        $rolesDir = Join-Path $PSScriptRoot "setup\roles"
        if (Test-Path $rolesDir) {
            Write-Log "Loading roles from: $rolesDir"
            $roleFiles = Get-ChildItem -Path $rolesDir -Filter "*.json" -ErrorAction SilentlyContinue
            
            foreach ($roleFile in $roleFiles) {
                $roleName = $roleFile.BaseName
                Write-Log "Processing role: $roleName"
                if (New-ElasticsearchRoleFromFile -RoleName $roleName -RoleJsonPath $roleFile.FullName -ElasticPassword $ElasticPassword) {
                    Write-Log "  Role $roleName created/updated"
                }
            }
        }
        else {
            Write-Log "WARNING: Roles directory not found: $rolesDir" "WARN"
        }
        
        # Kibana user
        Write-Log "Processing user: kibana_system"
        $kibanaUserExists = Test-ElasticsearchUser -Username "kibana_system" -ElasticPassword $ElasticPassword
        if ($kibanaUserExists) {
            Write-Log "  User exists, updating password"
            Set-ElasticsearchUserPassword -Username "kibana_system" -Password $KibanaPassword -ElasticPassword $ElasticPassword
        }
        else {
            Write-Log "  User does not exist, creating"
            New-ElasticsearchUser -Username "kibana_system" -Password $KibanaPassword -ElasticPassword $ElasticPassword
        }
        
        # Logstash user
        Write-Log "Processing user: logstash_internal"
        $logstashUserExists = Test-ElasticsearchUser -Username "logstash_internal" -ElasticPassword $ElasticPassword
        if ($logstashUserExists) {
            Write-Log "  User exists, updating password and role"
            Set-ElasticsearchUserPassword -Username "logstash_internal" -Password $LogstashPassword -ElasticPassword $ElasticPassword
            # Ensure logstash_writer role is assigned
            New-ElasticsearchUser -Username "logstash_internal" -Password $LogstashPassword -Role "logstash_writer" -ElasticPassword $ElasticPassword
        }
        else {
            Write-Log "  User does not exist, creating"
            New-ElasticsearchUser -Username "logstash_internal" -Password $LogstashPassword -Role "logstash_writer" -ElasticPassword $ElasticPassword
        }
        
        # Metricbeat user
        Write-Log "Processing user: metricbeat_internal"
        $metricbeatUserExists = Test-ElasticsearchUser -Username "metricbeat_internal" -ElasticPassword $ElasticPassword
        if ($metricbeatUserExists) {
            Write-Log "  User exists, updating password and role"
            Set-ElasticsearchUserPassword -Username "metricbeat_internal" -Password $MetricbeatPassword -ElasticPassword $ElasticPassword
            # Ensure metricbeat_writer role is assigned
            New-ElasticsearchUser -Username "metricbeat_internal" -Password $MetricbeatPassword -Role "metricbeat_writer" -ElasticPassword $ElasticPassword
        }
        else {
            Write-Log "  User does not exist, creating"
            New-ElasticsearchUser -Username "metricbeat_internal" -Password $MetricbeatPassword -Role "metricbeat_writer" -ElasticPassword $ElasticPassword
        }
        
        # Filebeat user
        Write-Log "Processing user: filebeat_internal"
        $filebeatUserExists = Test-ElasticsearchUser -Username "filebeat_internal" -ElasticPassword $ElasticPassword
        if ($filebeatUserExists) {
            Write-Log "  User exists, updating password and role"
            Set-ElasticsearchUserPassword -Username "filebeat_internal" -Password $FilebeatPassword -ElasticPassword $ElasticPassword
            # Ensure filebeat_writer role is assigned
            New-ElasticsearchUser -Username "filebeat_internal" -Password $FilebeatPassword -Role "filebeat_writer" -ElasticPassword $ElasticPassword
        }
        else {
            Write-Log "  User does not exist, creating"
            New-ElasticsearchUser -Username "filebeat_internal" -Password $FilebeatPassword -Role "filebeat_writer" -ElasticPassword $ElasticPassword
        }
        
        # Heartbeat user
        Write-Log "Processing user: heartbeat_internal"
        $heartbeatUserExists = Test-ElasticsearchUser -Username "heartbeat_internal" -ElasticPassword $ElasticPassword
        if ($heartbeatUserExists) {
            Write-Log "  User exists, updating password and role"
            Set-ElasticsearchUserPassword -Username "heartbeat_internal" -Password $HeartbeatPassword -ElasticPassword $ElasticPassword
            # Ensure heartbeat_writer role is assigned
            New-ElasticsearchUser -Username "heartbeat_internal" -Password $HeartbeatPassword -Role "heartbeat_writer" -ElasticPassword $ElasticPassword
        }
        else {
            Write-Log "  User does not exist, creating"
            New-ElasticsearchUser -Username "heartbeat_internal" -Password $HeartbeatPassword -Role "heartbeat_writer" -ElasticPassword $ElasticPassword
        }
        
        # Monitoring user
        Write-Log "Processing user: monitoring_internal"
        $monitoringUserExists = Test-ElasticsearchUser -Username "monitoring_internal" -ElasticPassword $ElasticPassword
        if ($monitoringUserExists) {
            Write-Log "  User exists, updating password and role"
            Set-ElasticsearchUserPassword -Username "monitoring_internal" -Password $MonitoringPassword -ElasticPassword $ElasticPassword
            # Ensure remote_monitoring_collector role is assigned
            New-ElasticsearchUser -Username "monitoring_internal" -Password $MonitoringPassword -Role "remote_monitoring_collector" -ElasticPassword $ElasticPassword
        }
        else {
            Write-Log "  User does not exist, creating"
            New-ElasticsearchUser -Username "monitoring_internal" -Password $MonitoringPassword -Role "remote_monitoring_collector" -ElasticPassword $ElasticPassword
        }
    }
    else {
        Write-Log "ERROR: Built-in users not initialized" "ERROR"
    }
}
else {
    Write-Log "INFO: Elasticsearch does not require authentication"
    
    # Wait for Elasticsearch without auth
    if (Wait-ForElasticsearch) {
        # Wait for built-in users
        if (Wait-ForBuiltInUsers) {
            Write-Log "Creating/updating Elasticsearch roles and users..."
            
            # Create all roles from role files
            $rolesDir = Join-Path $PSScriptRoot "setup\roles"
            if (Test-Path $rolesDir) {
                Write-Log "Loading roles from: $rolesDir"
                $roleFiles = Get-ChildItem -Path $rolesDir -Filter "*.json" -ErrorAction SilentlyContinue
                
                foreach ($roleFile in $roleFiles) {
                    $roleName = $roleFile.BaseName
                    Write-Log "Processing role: $roleName"
                    if (New-ElasticsearchRoleFromFile -RoleName $roleName -RoleJsonPath $roleFile.FullName) {
                        Write-Log "  Role $roleName created/updated"
                    }
                }
            }
            else {
                Write-Log "WARNING: Roles directory not found: $rolesDir" "WARN"
            }
            
            # Kibana user
            Write-Log "Processing user: kibana_system"
            $kibanaUserExists = Test-ElasticsearchUser -Username "kibana_system"
            if ($kibanaUserExists) {
                Write-Log "  User exists, updating password"
                Set-ElasticsearchUserPassword -Username "kibana_system" -Password $KibanaPassword
            }
            else {
                Write-Log "  User does not exist, creating"
                New-ElasticsearchUser -Username "kibana_system" -Password $KibanaPassword
            }
            
            # Logstash user
            Write-Log "Processing user: logstash_internal"
            $logstashUserExists = Test-ElasticsearchUser -Username "logstash_internal"
            if ($logstashUserExists) {
                Write-Log "  User exists, updating password and role"
                Set-ElasticsearchUserPassword -Username "logstash_internal" -Password $LogstashPassword
                # Ensure logstash_writer role is assigned
                New-ElasticsearchUser -Username "logstash_internal" -Password $LogstashPassword -Role "logstash_writer"
            }
            else {
                Write-Log "  User does not exist, creating"
                New-ElasticsearchUser -Username "logstash_internal" -Password $LogstashPassword -Role "logstash_writer"
            }
            
            # Metricbeat user
            Write-Log "Processing user: metricbeat_internal"
            $metricbeatUserExists = Test-ElasticsearchUser -Username "metricbeat_internal"
            if ($metricbeatUserExists) {
                Write-Log "  User exists, updating password and role"
                Set-ElasticsearchUserPassword -Username "metricbeat_internal" -Password $MetricbeatPassword
                # Ensure metricbeat_writer role is assigned
                New-ElasticsearchUser -Username "metricbeat_internal" -Password $MetricbeatPassword -Role "metricbeat_writer"
            }
            else {
                Write-Log "  User does not exist, creating"
                New-ElasticsearchUser -Username "metricbeat_internal" -Password $MetricbeatPassword -Role "metricbeat_writer"
            }
            
            # Filebeat user
            Write-Log "Processing user: filebeat_internal"
            $filebeatUserExists = Test-ElasticsearchUser -Username "filebeat_internal"
            if ($filebeatUserExists) {
                Write-Log "  User exists, updating password and role"
                Set-ElasticsearchUserPassword -Username "filebeat_internal" -Password $FilebeatPassword
                # Ensure filebeat_writer role is assigned
                New-ElasticsearchUser -Username "filebeat_internal" -Password $FilebeatPassword -Role "filebeat_writer"
            }
            else {
                Write-Log "  User does not exist, creating"
                New-ElasticsearchUser -Username "filebeat_internal" -Password $FilebeatPassword -Role "filebeat_writer"
            }
            
            # Heartbeat user
            Write-Log "Processing user: heartbeat_internal"
            $heartbeatUserExists = Test-ElasticsearchUser -Username "heartbeat_internal"
            if ($heartbeatUserExists) {
                Write-Log "  User exists, updating password and role"
                Set-ElasticsearchUserPassword -Username "heartbeat_internal" -Password $HeartbeatPassword
                # Ensure heartbeat_writer role is assigned
                New-ElasticsearchUser -Username "heartbeat_internal" -Password $HeartbeatPassword -Role "heartbeat_writer"
            }
            else {
                Write-Log "  User does not exist, creating"
                New-ElasticsearchUser -Username "heartbeat_internal" -Password $HeartbeatPassword -Role "heartbeat_writer"
            }
            
            # Monitoring user
            Write-Log "Processing user: monitoring_internal"
            $monitoringUserExists = Test-ElasticsearchUser -Username "monitoring_internal"
            if ($monitoringUserExists) {
                Write-Log "  User exists, updating password and role"
                Set-ElasticsearchUserPassword -Username "monitoring_internal" -Password $MonitoringPassword
                # Ensure remote_monitoring_collector role is assigned
                New-ElasticsearchUser -Username "monitoring_internal" -Password $MonitoringPassword -Role "remote_monitoring_collector"
            }
            else {
                Write-Log "  User does not exist, creating"
                New-ElasticsearchUser -Username "monitoring_internal" -Password $MonitoringPassword -Role "remote_monitoring_collector"
            }
        }
        else {
            Write-Log "ERROR: Built-in users not initialized" "ERROR"
        }
    }
    else {
        Write-Log "ERROR: Elasticsearch not available" "ERROR"
    }
}

Write-Log ""

# Step 5: Wait for Kibana
Write-Log "STEP 5: Wait for Kibana to be Available"
Write-Log "---------------------------------------------------------------"

# Start Kibana service if not running
$kibanaService = Get-Service -Name "DOP_Kibana" -ErrorAction SilentlyContinue
if ($kibanaService -and $kibanaService.Status -ne "Running") {
    Write-Log "Starting Kibana service..."
    Start-Service "DOP_Kibana" -ErrorAction SilentlyContinue
    Write-Log "Waiting for Kibana to initialize..."
    Start-Sleep -Seconds 10
}

# Wait for Kibana with kibana_system credentials
if ($authRequired) {
    Write-Log "Waiting for Kibana with kibana_system credentials..."
    if (Wait-ForKibana -Username "kibana_system" -Password $KibanaPassword) {
        Write-Log "OK: Kibana is ready"
    }
    else {
        Write-Log "WARN: Kibana did not respond, continuing anyway..." "WARN"
    }
}
else {
    Write-Log "Waiting for Kibana without authentication..."
    if (Wait-ForKibana) {
        Write-Log "OK: Kibana is ready"
    }
    else {
        Write-Log "WARN: Kibana did not respond, continuing anyway..." "WARN"
    }
}

# Step 6: Import Kibana dashboards
Write-Log ""
Write-Log "STEP 6: Import Kibana Dashboards"
Write-Log "---------------------------------------------------------------"

$kibanaObjectsPath = Join-Path $PSScriptRoot "setup\kibana_saved_objects"
if (Test-Path $kibanaObjectsPath) {
    $ndjsonFiles = Get-ChildItem -Path $kibanaObjectsPath -Filter "*.ndjson" -ErrorAction SilentlyContinue
    
    if ($ndjsonFiles.Count -gt 0) {
        Write-Log "Found $($ndjsonFiles.Count) NDJSON file(s) to import"
        
        foreach ($file in $ndjsonFiles) {
            if ($authRequired) {
                # Dashboard imports require 'elastic' user (kibana_system doesn't have permission)
                Import-KibanaDashboards -NdjsonFile $file.FullName -Username "elastic" -Password $ElasticPassword
            }
            else {
                Import-KibanaDashboards -NdjsonFile $file.FullName
            }
        }
    }
    else {
        Write-Log "No NDJSON files found in $kibanaObjectsPath"
    }
}
else {
    Write-Log "Kibana saved objects directory not found at $kibanaObjectsPath"
}

Write-Log ""
Write-Log "STEP 7: Verify Services Status"
Write-Log "---------------------------------------------------------------"

$services = @("DOP_Elasticsearch", "DOP_Kibana", "DOP_Logstash")
$allRunning = $true

foreach ($serviceName in $services) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    
    if ($service) {
        Write-Log "Service '$serviceName' status: $($service.Status)"
        
        if ($service.Status -ne "Running") {
            Write-Log "  Attempting to start service..."
            try {
                Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
                
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service.Status -eq "Running") {
                    Write-Log "  OK: Service started successfully"
                }
                else {
                    Write-Log "  WARNING: Service is not running. Check logs for details." "WARN"
                    $allRunning = $false
                }
            }
            catch {
                Write-Log "  ERROR: Failed to start service: $($_.Exception.Message)" "ERROR"
                $allRunning = $false
            }
        }
    }
    else {
        Write-Log "ERROR: Service '$serviceName' not found" "ERROR"
        $allRunning = $false
    }
}

if ($allRunning) {
    Write-Log "OK: All services are running"
}
else {
    Write-Log "WARNING: Some services are not running. Please check the logs." "WARN"
}

Write-Log ""
Write-Log ""
Write-Log "Services created:"
Write-Log "  DOP_Elasticsearch (native Windows service)"
Write-Log "  DOP_Kibana (NSSM service)"
Write-Log "  DOP_Logstash (NSSM service)"
Write-Log ""
Write-Log "Service logs:"
Write-Log "  Kibana stdout: $KibanaDir\logs\kibana-stdout.log"
Write-Log "  Kibana stderr: $KibanaDir\logs\kibana-stderr.log"
Write-Log "  Logstash stdout: $LogstashDir\logs\logstash-stdout.log"
Write-Log "  Logstash stderr: $LogstashDir\logs\logstash-stderr.log"
Write-Log ""
Write-Log "Configuration locations:"
Write-Log "  Elasticsearch: $ElasticsearchDir\config\elasticsearch.yml"
Write-Log "  Kibana: $KibanaDir\config\kibana.yml"
Write-Log "  Logstash: $LogstashDir\config\logstash.yml"
Write-Log "  Logstash Pipelines: $LogstashDir\config\pipelines.yml"
Write-Log "  Logstash Keystore: $LogstashDir\config\logstash.keystore"
Write-Log ""
Write-Log "Users configured:"
Write-Log "  elastic (password: $ElasticPassword)"
Write-Log "  kibana_system (password: $KibanaPassword)"
Write-Log "  logstash_internal (password: $LogstashPassword)"
if ($JdbcUser) {
    Write-Log ""
    Write-Log "Database configuration:"
    Write-Log "  JDBC Connection String: $JdbcConnectionString"
    Write-Log "  JDBC User: $JdbcUser"
    Write-Log "  JDBC Password: (stored in Logstash keystore)"
}
Write-Log ""
Write-Log "Next steps:"
Write-Log "  1. Review configuration files:"
Write-Log "     - $ElasticsearchDir\config\elasticsearch.yml"
Write-Log "     - $KibanaDir\config\kibana.yml"
Write-Log "     - $LogstashDir\config\logstash.yml"
Write-Log "     - $LogstashDir\config\pipelines.yml"
Write-Log ""
Write-Log "  2. Verify service status:"
Write-Log "     Get-Service DOP_* | Select Name, Status, StartType"
Write-Log ""
Write-Log "  3. Access Kibana at: http://localhost:5601"
Write-Log "     Username: elastic"
Write-Log "     Password: (your elastic password)"
Write-Log ""
Write-Log "  4. Review Logstash pipeline logs:"
Write-Log "     Get-Content -Path '$LogstashDir\logs\logstash-stdout.log' -Tail 50"
Write-Log ""
Write-Log "  5. View imported dashboards in Kibana"
Write-Log ""
Write-Log "Log file: $LogFile"
Write-Log "==============================================================="

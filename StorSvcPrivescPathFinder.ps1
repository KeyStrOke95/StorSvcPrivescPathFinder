# ------------------------------------------------------------------------------------------------
#                                  [+] Purpose [+]
#           Identify writable directories from the PATH environment variable 
#            to facilitate potential privilege escalation by injecting a DLL 
#          triggered via the StorSvc service's SvcRebootToFlashingMode method.
# ------------------------------------------------------------------------------------------------

Write-Output "`n===================================================================================="
Write-Output " Writable Directories Enumeration for DLL Injection"
Write-Output " Target: StorSvc SvcRebootToFlashingMode Method"
Write-Output "====================================================================================`n"

# Retrieve the Path value from the registry
$regQuery = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -v Path

# Parse the registry output to extract the PATH value
$lines = $regQuery -split "`r?`n"
$pathLine = $lines | Where-Object { $_ -match "Path\s+REG_EXPAND_SZ" }
$pathValue = $pathLine -replace ".*REG_EXPAND_SZ\s+", ""

# Split the PATH into directories
$directories = $pathValue -split ';'

# Display the directories being tested
Write-Output "Directories to be tested:"
$directories | ForEach-Object { Write-Output " - $_" }
Write-Output "`nStarting permission checks...`n"

# Function to check write access for the current user
function Test-WriteAccess ($directory) {
    # Expand environment variables to get the actual path
    $expandedDir = [System.Environment]::ExpandEnvironmentVariables($directory)
    
    if (Test-Path $expandedDir -PathType Container) {
        # Use icacls to retrieve permissions for the directory
        $icaclsOutput = icacls $expandedDir 2>$null
        $currentUser = $env:USERNAME

        # Check if the current user has (F) or (W) permissions
        $userPermissions = $icaclsOutput | Where-Object { $_ -match "$currentUser" }
        $hasWriteAccess = $userPermissions | Select-String -Pattern "(?:\(F\)|\(W\))"

        if ($hasWriteAccess) {
            # Return directory as writable
            return [PSCustomObject]@{
                Directory   = $expandedDir
                IsWritable  = $true
            }
        } else {
            # Return directory as not writable
            return [PSCustomObject]@{
                Directory   = $expandedDir
                IsWritable  = $false
            }
        }
    } else {
        # Directory does not exist
        return [PSCustomObject]@{
            Directory   = $expandedDir
            IsWritable  = $false
            Reason      = "Does not exist"
        }
    }
}

# Test each directory for write access
$results = foreach ($dir in $directories) {
    Test-WriteAccess $dir
}

# Separate writable and non-writable directories
$writableDirs = $results | Where-Object { $_.IsWritable -eq $true }
$nonWritableDirs = $results | Where-Object { $_.IsWritable -eq $false }

# Output Results
Write-Output "`n===================================================================================="
Write-Output " Results: Writable Directories (Potential DLL Injection Targets)"
Write-Output "===================================================================================="
foreach ($dir in $writableDirs) {
    Write-Host " - $($dir.Directory)" -ForegroundColor Green
}

Write-Output "`n===================================================================================="
Write-Output " Results: Non-Writable Directories"
Write-Output "===================================================================================="
foreach ($dir in $nonWritableDirs) {
    if ($dir.Reason -eq "Does not exist") {
        Write-Host " - $($dir.Directory) (Does not exist)" -ForegroundColor Yellow
    } else {
        Write-Host " - $($dir.Directory)" -ForegroundColor Red
    }
}

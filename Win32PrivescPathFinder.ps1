# ------------------------------------------------------------------------------------------------
#                                  [+] Purpose [+]
#           Identify writable directories from the PATH environment variable 
#            to facilitate potential privilege escalation by injecting a DLL 
#          triggered via the StorSvc service's SvcRebootToFlashingMode method.
#   For use in situations where Registry editing has been disabled by your administrator.
# ------------------------------------------------------------------------------------------------

# Output header information for the script's purpose
Write-Output "`n===================================================================================="
Write-Output " Writable Directories Enumeration for DLL Injection"
Write-Output " Target: StorSvc SvcRebootToFlashingMode Method"
Write-Output "====================================================================================`n"

# Define P/Invoke signatures for Win32 API functions from advapi32.dll
# These allow direct access to registry operations in PowerShell to bypass restrictions on reg.exe
Add-Type -MemberDefinition @"
    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern int RegQueryValueEx(IntPtr hKey, string lpValueName, IntPtr lpReserved, out uint lpType, [Out] System.Text.StringBuilder lpData, ref uint lpcbData);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegCloseKey(IntPtr hKey);
"@ -Name "RegApis" -Namespace "Win32" -PassThru

# Define constants for registry access
$hklm = [IntPtr]0x80000002  # HKEY_LOCAL_MACHINE root key
$subKey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"  # Subkey path to environment variables
$valueName = "Path"  # Name of the value to query (system PATH)
$samDesired = 0x20019  # KEY_READ access mask (KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY)

# Open the registry key
$phkResult = [IntPtr]::Zero  # Initialize handle for the opened key
$openError = [Win32.RegApis]::RegOpenKeyEx($hklm, $subKey, 0, $samDesired, [ref]$phkResult)
if ($openError -ne 0) {
    # Handle error if key cannot be opened
    Write-Error "Failed to open registry key. Error code: $openError (Win32 error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    return
}

# First query to determine the size of the value data
$type = [uint32]0  # Variable to store the registry value type (e.g., REG_EXPAND_SZ)
$size = [uint32]0  # Variable to store the size of the data in bytes
[Win32.RegApis]::RegQueryValueEx($phkResult, $valueName, [IntPtr]::Zero, [ref]$type, $null, [ref]$size) | Out-Null

# Allocate a StringBuilder buffer based on the size and query the actual value
$buffer = New-Object System.Text.StringBuilder -ArgumentList ([int]$size / 2)  # Divide size by 2 since it's in bytes and StringBuilder uses chars
$queryError = [Win32.RegApis]::RegQueryValueEx($phkResult, $valueName, [IntPtr]::Zero, [ref]$type, $buffer, [ref]$size)
if ($queryError -ne 0) {
    # Handle error if value cannot be queried
    Write-Error "Failed to query value. Error code: $queryError (Win32 error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    [Win32.RegApis]::RegCloseKey($phkResult) | Out-Null
    return
}

# Retrieve the unexpanded PATH value
$pathValue = $buffer.ToString()

# Close the registry key handle to free resources
[Win32.RegApis]::RegCloseKey($phkResult) | Out-Null

# Split the PATH into individual directories
$directories = $pathValue -split ';'

# Display the directories being tested
Write-Output "Directories to be tested:"
$directories | ForEach-Object { Write-Output " - $_" }
Write-Output "`nStarting permission checks...`n"

# Function to check write access for the current user by attempting to create and delete a temp file
# This is more reliable than parsing icacls output, avoiding issues with user naming or permission formats
function Test-WriteAccess ($directory) {
    # Expand environment variables to get the actual path
    $expandedDir = [System.Environment]::ExpandEnvironmentVariables($directory)
    
    if (-not (Test-Path $expandedDir -PathType Container)) {
        # Directory does not exist
        return [PSCustomObject]@{
            Directory   = $expandedDir
            IsWritable  = $false
            Reason      = "Does not exist"
        }
    }
    
    try {
        # Attempt to create a temporary file
        $tempFile = Join-Path $expandedDir "temp_test_write_$(Get-Random).txt"
        New-Item -Path $tempFile -ItemType File -Force -ErrorAction Stop | Out-Null
        
        # Clean up the temporary file
        Remove-Item $tempFile -Force -ErrorAction Stop
        
        # Return directory as writable
        return [PSCustomObject]@{
            Directory   = $expandedDir
            IsWritable  = $true
        }
    } catch {
        # Return directory as not writable if creation or deletion fails
        return [PSCustomObject]@{
            Directory   = $expandedDir
            IsWritable  = $false
        }
    }
}

# Test each directory for write access and collect results
$results = foreach ($dir in $directories) {
    Test-WriteAccess $dir
}

# Separate writable and non-writable directories
$writableDirs = $results | Where-Object { $_.IsWritable -eq $true }
$nonWritableDirs = $results | Where-Object { $_.IsWritable -eq $false }

# Output Results for writable directories
Write-Output "`n===================================================================================="
Write-Output " Results: Writable Directories (Potential DLL Injection Targets)"
Write-Output "===================================================================================="
foreach ($dir in $writableDirs) {
    Write-Host " - $($dir.Directory)" -ForegroundColor Green
}

# Output Results for non-writable directories
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

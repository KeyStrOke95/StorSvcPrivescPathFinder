# This script identifies writable directories in the PATH environment variable,
# which could facilitate privilege escalation by allowing DLL injection or executable placement.
# Registry access is performed using Win32 API to bypass potential restrictions on tools like reg.exe.

#Requires -Version 2

# Check if the script is running with administrative privileges
# If running as admin, the script warns and exits, as file write checks may not reflect normal user permissions
If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "WARNING: This script will not function accurately with administrative privileges." -ForegroundColor Yellow
    Write-Host "Please run as a normal user." -ForegroundColor Yellow
    Break
}

# Define P/Invoke signatures for Win32 API functions from advapi32.dll
# These allow direct registry operations in PowerShell without using reg.exe or Get-ItemProperty
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

# Output script header with colors for better visibility
Write-Host "`n====================================================================================" -ForegroundColor Cyan
Write-Host " Writable PATH Directories Checker" -ForegroundColor Cyan
Write-Host " Purpose: Identify writable directories in system PATH for potential privilege escalation" -ForegroundColor Cyan
Write-Host "====================================================================================`n" -ForegroundColor Cyan

# Open the registry key
$phkResult = [IntPtr]::Zero  # Initialize handle for the opened key
$openError = [Win32.RegApis]::RegOpenKeyEx($hklm, $subKey, 0, $samDesired, [ref]$phkResult)
if ($openError -ne 0) {
    # Handle error if key cannot be opened
    Write-Host "ERROR: Failed to open registry key." -ForegroundColor Red
    Write-Host "Error code: $openError (Win32 error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))" -ForegroundColor Red
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
    Write-Host "ERROR: Failed to query PATH value." -ForegroundColor Red
    Write-Host "Error code: $queryError (Win32 error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))" -ForegroundColor Red
    [Win32.RegApis]::RegCloseKey($phkResult) | Out-Null
    return
}

# Retrieve the unexpanded PATH value
$pathValue = $buffer.ToString()

# Close the registry key handle to free resources
[Win32.RegApis]::RegCloseKey($phkResult) | Out-Null

# Split the PATH into individual directories
$paths = $pathValue.Split(";")

# Display the directories being tested with highlighting
Write-Host "Directories in PATH to be tested:" -ForegroundColor Magenta
foreach ($p in $paths) {
    Write-Host " - $p" -ForegroundColor White
}
Write-Host "`nStarting write access checks...`n" -ForegroundColor Magenta

# Define the test file name for write access checks
$outfile = "acltestfile"

# Initialize a flag to track if any insecure (writable) paths are found
$insecure = 0

# Collect writable paths for summary
$writablePaths = @()

# Iterate through each directory in the PATH
Foreach ($path in $paths) {
    # Easier to get effective access of current user by just trying to create a file
    Try {
        $fullPath = "$path\$outfile"
        # Attempt to open the file for writing (creates if not exists)
        [io.file]::OpenWrite($fullPath).close()
        # If successful, collect and highlight as writable
        Write-Host "Writable: $path" -ForegroundColor Yellow
        $insecure = 1
        $writablePaths += $path
        # Delete the test file to clean up
        Remove-Item -Path $fullPath -Force -ErrorAction SilentlyContinue
    }
    Catch {
        # If fails, highlight as not writable
        Write-Host "Not Writable: $path" -ForegroundColor Green
    }
}

# Output the final result with enhanced formatting and colors
Write-Host "`n====================================================================================" -ForegroundColor Cyan
Write-Host " Summary of Checks" -ForegroundColor Cyan
Write-Host "====================================================================================" -ForegroundColor Cyan

If ($insecure -eq 1) {
    Write-Host "WARNING: Writable directories found in system PATH!" -ForegroundColor Yellow
    Write-Host "These can allow privilege escalation by placing malicious DLLs or executables." -ForegroundColor Yellow
    Write-Host "Affected Paths:" -ForegroundColor Yellow
    foreach ($wp in $writablePaths) {
        Write-Host " - $wp" -ForegroundColor Red
    }
    Write-Host "Recommendation: Review and secure these directories." -ForegroundColor Yellow
} Else {
    Write-Host "SUCCESS: No writable directories found in system PATH." -ForegroundColor Green
    Write-Host "Your system appears secure against this type of PATH-based escalation." -ForegroundColor Green
}

Write-Host "`nChecks Complete.`n" -ForegroundColor Cyan

# StorSvcPrivescPathFinder

This PowerShell script enumerates writable directories from the PATH environment variable, specifically designed to identify paths that may be exploited for DLL injection to achieve privilege escalation, particularly by targeting the SvcRebootToFlashingMode method of the StorSvc service.

The StorSvc service operates as `NT AUTHORITY\SYSTEM`, and when the `SvcRebootToFlashingMode` RPC method is executed locally, it attempts to load the missing `SprintCSP.dll`. By placing a malicious DLL in a writable directory included in the service’s search path, privilege escalation can be achieved.

# Credits
All credit for the discovery of this technique goes to [@blackarrowsec](https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc) and their research into the StorSvc service.
This script is built on their findings to automate the enumeration of writable paths.

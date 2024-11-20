# StorSvcPrivescPathFinder
This PowerShell script enumerates writable directories from the PATH environment variable for the current user. It is specifically designed to identify paths that may be exploited for DLL injection to achieve privilege escalation, particularly by targeting the SvcRebootToFlashingMode method of the StorSvc service.

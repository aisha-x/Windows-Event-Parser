# Windows Event Parser

A PowerShell module for extracting specific fields from Windows Event Logs. Currently supports Security and Sysmon logs with focused field selection for common event types.

## Currently Supported Logs

- **Security Log Events**
- **Sysmon Log Events** 

## Features

- **Focused Field Selection**: Returns only relevant fields for each event type
- **Built-in Filtering**: Message-based filtering capabilities
- **Consistent Interface**: Easy-to-remember function names
- **Customizable**: Easy to extend with new event types

## Available Functions

**Security Log Functions**
```powershell

sec-NewProcess           # 4688: A new process has been created
sec-GroupMembershipEnum  # 4798: A user's local group membership was enumerated.
sec-FileAccess           # 4663: An attempt was made to access an object
sec-UserCreated          # 4720: User Account Created
sec-UserEnabled          # 4722: A user account was enabled 
sec-ResetPasswd          # 4724: An attempt was made to reset an account's password
sec-UserAccountChanged   # 4738: A user account was changed.
ConvertAccessMask        # Helper Function to convert access mask value to human readable format
```
**Sysmon Log Functions**
```powershell
sys-processCreation     # Event ID 1 - Process creation
sys-fileCreated         # Event ID 11 - File creation
sys-registryValueSet    # Event ID 13 - Registry events
sys-network             # Event ID 3 - Network connections
```

## Installation

Clone the repo, then copy the module to the current user's module path

```powershell
# Copy to PowerShell modules directory
Copy-Item -Path .\sec-field-filter.psm1 -Destination "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\sec-field-filter\"
Copy-Item -Path .\sec-field-filter.psd1 -Destination "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\sec-field-filter\"

# Import Module
import-module sec-field-filter -Force
import-module sys-field-filter -Force

# Remove Module
Remove-Module sec-field-filter
Remove-Module sys-field-filter

```

## Usage example:

```powershell

 # Sort-Object (order result)
 sys-process | Sort-Object UtcTime -Descending
 sys-file | Sort-Object Image -Unique |fl
 
 
 # Select-String pattern
 sys-process | Select-String -Pattern "-e powershell" -InputObject {$_.CommandLine}
 sys-file | Select-String -Pattern "Temp" -InputObject {$_.TargetFilename}
 
 # Export to csv
 sys-process |Export-Csv -Path .\Desktop\processes.csv -NoTypeInformation
 
 # ForEach-Object (Custom processing)
 sys-process |ForEach-Object { "$($_.Image) -> $($_.CommandLine)"}
 
 # Comparison 
 sys-process |Where-Object {$_.CommandLine.Length -gt 100}
 sys-network | Where-Object {$_.DestinationPort -in @(80, 443, 8080)}
 
 # Result Limiting
  sys-process |Select-Object -First 2
  sys-network | Select-Object -Skip 20 -First 10

```

```powershell

sec-NewProcess           # 4688: A new process has been created
sec-GroupMembershipEnum  # 4798: A user's local group membership was enumerated.
sec-FileAccess           # 4663: An attempt was made to access an object
sec-UserCreated          # 4720: User Account Created
sec-UserEnabled          # 4722: A user account was enabled 
sec-ResetPasswd          # 4724: An attempt was made to reset an account's password
sec-UserAccountChanged   # 4738: A user account was changed.
ConvertAccessMask        # Helper Function to convert access mask value to human readable format
```

```powershell
sys-processCreation     # Event ID 1 - Process creation
sys-fileCreated         # Event ID 11 - File creation
sys-registryValueSet    # Event ID 13 - Registry events
sys-network             # Event ID 3 - Network connections
```

## Sample Output

**Sysmon: RegistryValueSet**

```powershell
PS C:\Users\Administrator> sys-registryValueSet
=== Sysmon Event ID 13: RegistryEvent (Value Set) ===

UtcTime      : 2025-08-26 09:13:02.172
RuleNumber   : -
EventType    : SetValue
ProcessId    : 3368
Image        : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetObject : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText
Detials      : THM{THM_Offline_Index_Emulation}
```

**Sysmon: ProcessCreation**

```powershell
PS C:\Users\Administrator> sys-processCreation -FilterMessage "new-service"

=== Sysmon Event ID 1: Process creation ===

UtcTime           : 2025-08-26 09:09:29.456
Image             : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
ProcessId         : 3808
CommandLine       : "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths
                    @"C:\Users\Administrator\AppData\Local\Temp\2\lxzevmgi\lxzevmgi.cmdline"
ParentProcessId   : 4520
ParentCommandLine : "powershell.exe" & {C:\AtomicRedTeam\atomics\T0003\new-service.ps1}
```

**Security: UserCreated**

```powershell
PS C:\Users\Administrator> sec-UserCreated
=== Security Event ID 4720: User Account Created ===

TimeCreated      : 8/26/2025 1:55:36 PM
CreatorAccount   : Administrator
CreatorDomain    : ATOMICBIRD
NewAccountName   : Adminstrator
NewAccountDomain : ATOMICBIRD
NewAccountSID    : S-1-5-21-1966530601-3185510712-10604624-1030
SAMAccountName   : Adminstrator

```

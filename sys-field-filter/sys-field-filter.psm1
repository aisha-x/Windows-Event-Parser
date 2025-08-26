function sys-processCreation {

    [CmdletBinding()]
    param([string]$FilterMessage)
    
    Write-Host "=== Sysmon Event ID 1: Process creation ===" -ForegroundColor Yellow

    $events = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1}

    if (-not $events) {
        Write-Warning "No Sysmon event found with ID 1"
        return
    }
    
    # Apply filters while we still have the full Message property
    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }
    
    
    
    $result = $events | Select-Object @(
        @{Name='UtcTime'; Expression={$_.Properties[1].Value}}
        @{Name='Image'; Expression={$_.Properties[4].Value}}
        @{Name='ProcessId'; Expression={$_.Properties[3].Value}}
        @{Name='CommandLine'; Expression={$_.Properties[10].Value}}
        @{Name='ParentProcessId'; Expression={$_.Properties[19].Value}}
        @{Name='ParentCommandLine'; Expression={$_.Properties[21].Value}}
    ) 

    return $result
}




function sys-fileCreated {

    [CmdletBinding()]
    param([string]$FilterMessage)

    Write-Host "=== Sysmon Event ID 11: File Created ===" -ForegroundColor Yellow

    $events = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=11} 

    
    if (-not $events) {
        Write-Warning "No Sysmon event found with ID 11"
        return
    }
    
    
    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }
    
    $result = $events | Select-Object @(
    
        @{Name='UtcTime'; Expression={$_.Properties[1].Value}}
        @{Name='Image'; Expression={$_.Properties[4].Value}}
        @{Name='ProcessId'; Expression={$_.Properties[3].Value}}
        @{Name='TargetFilename'; Expression={$_.Properties[5].Value}}
) 
    return $result
}



function sys-registryValueSet {

[CmdletBinding()]
    param([string]$FilterMessage)

    Write-Host "=== Sysmon Event ID 13: RegistryEvent (Value Set) ===" -ForegroundColor Yellow

    # Regisrty event id 13 -> value set
    $events = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=13}

    if (-not $events){
    Write-Warning "No Sysmon event found with ID 13"
    }
    # apply filter
    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }

    $result = $events | Select-Object @(
        @{Name='UtcTime'; Expression={$_.Properties[2].Value}}
        @{Name='RuleNumber'; Expression={$_.Properties[0].Value}}
        @{Name='EventType'; Expression={$_.Properties[1].Value}}
        @{Name='ProcessId'; Expression={$_.Properties[4].Value}}
        @{Name='Image'; Expression={$_.Properties[5].Value}}
        @{Name='TargetObject'; Expression={$_.Properties[6].Value}}
        @{Name='Detials'; Expression={$_.Properties[7].Value}}
    ) 
    return $result

}



function sys-network {


    [CmdletBinding()]
    param([string]$FilterMessage)

    Write-Host "=== Sysmon Event ID 3: Network connection detected  ===" -ForegroundColor Yellow

    $events= Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=3}
    
    if (-not $events){
    Write-Warning "No Sysmon event found with ID 3"
    }

    # apply filter
    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }

    $result = $events | Select-Object @(
        @{Name='UtcTime'; Expression={$_.Properties[1].Value}}
        @{Name='RuleName'; Expression={$_.Properties[0].Value}}
        @{Name='ProcessId'; Expression={$_.Properties[3].Value}}
        @{Name='Image'; Expression={$_.Properties[4].Value}}
        @{Name='SourceIP'; Expression={$_.Properties[9].Value}}
        @{Name='SourcePort'; Expression={$_.Properties[11].Value}}
        @{Name='DestinationIp'; Expression={$_.Properties[14].Value}}
        @{Name='DestinationPort'; Expression={$_.Properties[16].Value}}
    ) 
    return $result
}



Export-ModuleMember -Function 'sys-network', 'sys-registryValueSet', 'sys-fileCreated', 'sys-processCreation'


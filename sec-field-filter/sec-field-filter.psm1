
function sec-NewProcess {
    # 4688: A new process has been created

    [CmdletBinding()]
    param([string]$FilterMessage)

    Write-Host "=== Security Event ID 4688: A new process has been created. ===" -ForegroundColor Cyan

    $events = Get-WinEvent -FilterHashtable @{LogName="Security";ID=4688}  
    
    if (-not $events){
    Write-Warning "No Security event found with ID 4688"
    return
    }

    # apply filter
    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }

    $result = $events | Select-Object @(
        'TimeCreated'
        @{Name='AccountName'; Expression={$_.Properties[1].Value}}
        @{Name='Domain'; Expression={$_.Properties[2].Value}}
        @{Name='LogonID'; Expression={$_.Properties[3].Value}}
        @{Name='NewProcessID'; Expression={$_.Properties[4].Value}}
        @{Name='NewProcessName'; Expression={$_.Properties[5].Value}}
        @{Name='TokenElevationType'; Expression={$_.Properties[6].Value}}
        @{Name='ProcessID'; Expression={$_.Properties[7].Value}}
        @{Name='CommandLine'; Expression={$_.Properties[8].Value}}
    ) 
    return $result
}

function sec-GroupMembershipEnum {

    # 4798: A user's local group membership was enumerated.

    [CmdletBinding()]
    param([string]$FilterMessage)

    Write-Host "=== Security Event ID 4798: A user's local group membership was enumerated. ===" -ForegroundColor Cyan

    $events = Get-WinEvent -FilterHashtable @{LogName="Security";ID=4798}  
    
    if (-not $events){
    Write-Warning "No Security event found with ID 4798"
    return
    }

    # apply filter
    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }

    $result = $events | Select-Object @(
        'TimeCreated'
        @{Name='SubjectAccount'; Expression={$_.Properties[4].Value}}
        @{Name='SubjectDomain'; Expression={$_.Properties[5].Value}}
        @{Name='TargetUser'; Expression={$_.Properties[0].Value}}
        @{Name='TargetDomain'; Expression={$_.Properties[1].Value}}
        @{Name='ProcessID'; Expression={$_.Properties[7].Value}}
        @{Name='ProcessName'; Expression={$_.Properties[8].Value}} 
        )
    return $result


}

# Helper Function to convert access mask to human readable format
function ConvertAccessMask {
    param([string]$accessMaskString)
    
    # Convert hex string to integer
    if ($accessMaskString -match "^0x") {
        $accessMask = [Convert]::ToInt32($accessMaskString.Substring(2), 16)
    } else {
        $accessMask = [int]$accessMaskString
    }
    
    $accessRights = @{
        0x1 = "FILE_READ_DATA"
        0x2 = "FILE_WRITE_DATA"
        0x4 = "FILE_APPEND_DATA"
        0x20 = "FILE_EXECUTE"
        0x80 = "FILE_READ_ATTRIBUTES"
        0x100 = "FILE_WRITE_ATTRIBUTES"
        0x10000 = "DELETE"
        0x20000 = "READ_CONTROL"
        0x40000 = "WRITE_DAC"
        0x80000 = "WRITE_OWNER"
        0x100000 = "SYNCHRONIZE"
        0x10000000 = "GENERIC_ALL"
        0x20000000 = "GENERIC_EXECUTE"
        0x40000000 = "GENERIC_WRITE"
        0x80000000 = "GENERIC_READ"
    }
    
    $result = @()
    foreach ($right in $accessRights.GetEnumerator()) {
        if ($accessMask -band $right.Key) {
            $result += $right.Value
        }
    }
    
    # Fixed return statement - use proper conditional logic
    if ($result.Count -eq 0) {
        return "UNKNOWN_ACCESS"
    } else {
        return ($result -join " | ")
    }
}

function sec-FileAccess {
    # 4663: An attempt was made to access an object

    [CmdletBinding()]
    param([string]$FilterMessage)

    Write-Host "=== Security Event ID 4663: An attempt was made to access an object ===" -ForegroundColor Cyan

    $events = Get-WinEvent -FilterHashtable @{LogName="Security";ID=4663}  
    
    if (-not $events){
    Write-Warning "No Security event found with ID 4663"
    }

    # apply filter
    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }
    $result = $events | Select-Object @(
        'TimeCreated'
        @{Name='SubjectAccount'; Expression={$_.Properties[1].Value}}
        @{Name='SubjectDomain'; Expression={$_.Properties[2].Value}}
        @{Name='ObjectType'; Expression={$_.Properties[5].Value}}
        @{Name='ObjectName'; Expression={$_.Properties[6].Value}}
        @{Name='ProcessID'; Expression={$_.Properties[9].Value}}
        @{Name='ProcessName'; Expression={$_.Properties[11].Value}}
        @{Name='AccessesMask'; Expression={$_.Properties[10].Value}}
        @{Name='AccessRights'; Expression={ConvertAccessMask $_.Properties[10].Value}}
) 
    return $result

}

function sec-UserCreated {
    [CmdletBinding()]
    param([string]$FilterMessage)

    Write-Host "=== Security Event ID 4720: User Account Created ===" -ForegroundColor Cyan
    
    $events = Get-WinEvent -FilterHashtable @{LogName="Security";ID=4720}  
    
    if (-not $events) {
        Write-Warning "No Security event found with ID 4720"
        return
    }

    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }
    
    $result = $events | Select-Object @(
        'TimeCreated'
        @{Name='CreatorAccount'; Expression={$_.Properties[4].Value}}
        @{Name='CreatorDomain'; Expression={$_.Properties[5].Value}}
        @{Name='NewAccountName'; Expression={$_.Properties[0].Value}}
        @{Name='NewAccountDomain'; Expression={$_.Properties[1].Value}}
        @{Name='NewAccountSID'; Expression={$_.Properties[2].Value}}
        @{Name='SAMAccountName'; Expression={$_.Properties[8].Value}}
        
    )
    
    return $result
}

function sec-UserAccountChanged {
    [CmdletBinding()]
    param([string]$FilterMessage)

    Write-Host "=== Security Event ID 4738: A user account was changed. ===" -ForegroundColor Cyan
    
    $events = Get-WinEvent -FilterHashtable @{LogName="Security";ID=4738}  
    
    if (-not $events) {
        Write-Warning "No Security event found with ID 4738"
        return
    }

    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }
    
    $result = $events | Select-Object @(
        'TimeCreated'
        @{Name='SubjectAccount'; Expression={$_.Properties[1].Value}}
        @{Name='SubjectDomain'; Expression={$_.Properties[2].Value}}
        @{Name='TargetAccount'; Expression={$_.Properties[5].Value}}
        @{Name='TargetDomain'; Expression={$_.Properties[6].Value}}
        @{Name='TargetAccountSID'; Expression={$_.Properties[4].Value}}
        @{Name='SAMAccountName'; Expression={$_.Properties[8].Value}}
        
    )
    
    return $result
}

function sec-UserEnabled{

    [CmdletBinding()]
    param([string]$FilterMessage)

    Write-Host "=== Security Event ID 4722: A user account was enabled ===" -ForegroundColor Cyan
    
    $events = Get-WinEvent -FilterHashtable @{LogName="Security";ID=4722}  
    
    if (-not $events) {
        Write-Warning "No Security event found with ID 4722"
        return
    }

    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }
    $result = $events | Select-Object @(
        'TimeCreated'
        @{Name='SubjectAccount'; Expression={$_.Properties[0].Value}}
        @{Name='SubjectDomain'; Expression={$_.Properties[1].Value}}
        @{Name='TargetAccount'; Expression={$_.Properties[4].Value}}
        @{Name='TargetDomain'; Expression={$_.Properties[5].Value}})

    return $result
}

function sec-ResetPasswd{

    [CmdletBinding()]
    param([string]$FilterMessage)

    Write-Host "=== Security Event ID 4724: An attempt was made to reset an account's password ===" -ForegroundColor Cyan
    
    $events = Get-WinEvent -FilterHashtable @{LogName="Security";ID=4724}  
    
    if (-not $events) {
        Write-Warning "No Security event found with ID 4724"
        return
    }

    if ($FilterMessage) {
        $events = $events | Where-Object {$_.Message -Like "*$FilterMessage*"}
    }
    $result = $events | Select-Object @(
        'TimeCreated'
        @{Name='SubjectAccount'; Expression={$_.Properties[0].Value}}
        @{Name='SubjectDomain'; Expression={$_.Properties[1].Value}}
        @{Name='TargetAccount'; Expression={$_.Properties[4].Value}}
        @{Name='TargetDomain'; Expression={$_.Properties[5].Value}})

    return $result
}


Export-ModuleMember -Function 'sec-NewProcess', 'sec-GroupMembershipEnum', 'sec-FileAccess', 'sec-UserCreated', 'sec-UserEnabled','sec-ResetPasswd' ,'ConvertAccessMask', 'sec-UserAccountChanged'

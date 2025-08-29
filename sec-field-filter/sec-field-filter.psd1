@{
    ModuleVersion = '1.0'
    GUID = '64582248-97e8-4d49-9e27-54aa35a3b267'
    Author = 'Aisha-x'
    Description = 'Simple module that selects specific fields from security log'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('sec-NewProcess', 'sec-GroupMembershipEnum', 'sec-FileAccess', 'sec-UserCreated', 'sec-UserEnabled','sec-ResetPasswd' ,'ConvertAccessMask', 'sec-UserAccountChanged')
    AliasesToExport = '*'
    CmdletsToExport = '*'
    VariablesToExport = '*'
    RootModule = 'sec-field-filter.psm1'
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'LogAnalysis', 'Windows')
            LicenseUri = ''
            ProjectUri = 'https://github.com/aisha-x/Windows-Event-Parser'
            ReleaseNotes = 'Initial release'
        }
    }
}

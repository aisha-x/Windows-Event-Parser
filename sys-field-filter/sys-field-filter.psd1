@{
    ModuleVersion = '1.0'
    GUID = '879b3e52-e94d-4f7d-8201-59fa2143be13'
    Author = 'Aisha-x'
    Description = 'Simple module that selects specific fields from Sysmon log'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('sys-network', 'sys-registryValueSet', 'sys-fileCreated', 'sys-processCreation')
    AliasesToExport = '*'
    CmdletsToExport = '*'
    VariablesToExport = '*'
    RootModule = 'sys-field-filter.psm1'
    PrivateData = @{
        PSData = @{
            Tags = @('Sysmon', 'LogAnalysis', 'Windows')
            LicenseUri = ''
            ProjectUri = 'https://github.com/aisha-x/Windows-Event-Parser'
            ReleaseNotes = 'Initial release'
        }
    }
}

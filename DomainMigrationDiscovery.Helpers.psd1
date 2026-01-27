@{
    RootModule        = 'DomainMigrationDiscovery.Helpers.psm1'
    ModuleVersion     = '1.0.0'
    FunctionsToExport = @(
        'Get-CredentialManagerDomainReferences',
        'Get-CertificatesWithDomainReferences',
        'Get-FirewallRulesWithDomainReferences',
        'Get-IISDomainReferences',
        'Get-SqlDomainReferences',
        'Get-EventLogDomainReferences',
        'Get-ApplicationConfigDomainReferences'
    )
}

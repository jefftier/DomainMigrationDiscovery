@{
    RootModule        = 'DomainMigrationDiscovery.Helpers.psm1'
    ModuleVersion     = '1.0.0'
    FunctionsToExport = @(
        'Hide-SensitiveText',
        'Get-SqlServerPresence',
        'Get-CredentialManagerDomainReferences',
        'Get-CertificatesWithDomainReferences',
        'Get-FirewallRulesWithDomainReferences',
        'Get-IISDomainReferences',
        'Get-SqlDomainReferences',
        'Get-EventLogDomainReferences',
        'Get-ApplicationConfigDomainReferences',
        'Get-OracleDiscovery',
        'Get-RDSLicensingDiscovery'
    )
}

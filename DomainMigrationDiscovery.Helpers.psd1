@{
    RootModule        = 'DomainMigrationDiscovery.Helpers.psm1'
    ModuleVersion     = '1.0.0'
    FunctionsToExport = @(
        'Redact-SensitiveText',
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

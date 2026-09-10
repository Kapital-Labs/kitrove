# Shared, pinned tooling for ephemeral Windows signing jobs. No authentication here.
function Get-KitroveWindowsPublisher {
    return 'CN=Kapital Labs LLC, O=Kapital Labs LLC, L=Austin, S=Texas, C=US'
}

function Get-Digest([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-PinnedZip([string]$Name, [string]$Uri, [string]$Digest) {
    $zip = Join-Path $toolDir "$Name.zip"
    Invoke-WebRequest -Uri $Uri -OutFile $zip
    if ((Get-Digest $zip) -cne $Digest) { throw "$Name package digest mismatch" }
    $destination = Join-Path $toolDir $Name
    Expand-Archive -LiteralPath $zip -DestinationPath $destination
    return $destination
}

function Initialize-KitroveSigningTools([string]$AzureDirectory) {
    $publisher = Get-KitroveWindowsPublisher
    New-Item -ItemType Directory -Path $toolDir | Out-Null
    $runtimes = dotnet --list-runtimes
    if (-not ($runtimes -match '^Microsoft.NETCore.App (8|9|[1-9][0-9])\.')) {
        throw 'Microsoft signing provider requires .NET 8 or later on the runner'
    }
    $sdk = Get-PinnedZip 'sdk' 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/10.0.26100.8249/microsoft.windows.sdk.buildtools.10.0.26100.8249.nupkg' '1628c77d21ed187c4db998b37b18e267a7f092ae755589e21110c14260b14960'
    $client = Get-PinnedZip 'client' 'https://api.nuget.org/v3-flatcontainer/microsoft.trusted.signing.client/1.0.95/microsoft.trusted.signing.client.1.0.95.nupkg' '3bfcf1e0a3cb42af1692f0a8ed45c15de070c2de86f28a59b2795d904d8a920f'
    $signTool = Join-Path $sdk 'bin/10.0.26100.0/x64/signtool.exe'
    $dlib = Join-Path $client 'bin/x64/Azure.CodeSigning.Dlib.dll'
    foreach ($file in @($signTool, $dlib)) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') {
            throw 'Pinned signing tool does not have a valid Microsoft signature'
        }
    }
    $metadata = Join-Path $toolDir 'metadata.json'
    @{
        Endpoint = 'https://eus.codesigning.azure.net/'
        CodeSigningAccountName = 'kapitallabs-kitrove'
        CertificateProfileName = 'kitrove-public'
        ExcludeCredentials = @('EnvironmentCredential', 'ManagedIdentityCredential',
            'WorkloadIdentityCredential', 'SharedTokenCacheCredential', 'VisualStudioCredential',
            'VisualStudioCodeCredential', 'AzurePowerShellCredential', 'AzureDeveloperCliCredential',
            'InteractiveBrowserCredential')
    } | ConvertTo-Json | Set-Content -LiteralPath $metadata -Encoding utf8NoBOM
    @("KITROVE_SIGNTOOL=$signTool", "KITROVE_AZURE_SIGNING_DLIB=$dlib",
        "KITROVE_AZURE_SIGNING_METADATA=$metadata", "KITROVE_WINDOWS_PUBLISHER=$publisher",
        "AZURE_CONFIG_DIR=$AzureDirectory") |
        Add-Content -LiteralPath $env:GITHUB_ENV
}

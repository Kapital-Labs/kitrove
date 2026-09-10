param([ValidateSet('Prepare', 'Sign', 'Cleanup')][string]$Stage)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

function Invoke-HostedWindowsSigning([string]$Operation) {
    if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        $env:GITHUB_REPOSITORY -cne 'Kapital-Labs/kitrove' -or
        $env:GITHUB_REF -cnotmatch '^refs/tags/v' -or
        $env:DIST_TARGET -cne 'x86_64-pc-windows-msvc') {
        throw 'Hosted signing requires the protected Windows release context'
    }
    if (-not [IO.Path]::IsPathFullyQualified($env:RUNNER_TEMP)) {
        throw 'Hosted signing requires an absolute runner temporary directory'
    }
    $temporary = Get-Item -LiteralPath $env:RUNNER_TEMP
    if (-not $temporary.PSIsContainer -or ($temporary.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Runner temporary directory must not be redirected'
    }
    $azureDirectory = Join-Path $temporary.FullName 'kitrove-release-azure'
    $toolDir = Join-Path $temporary.FullName 'kitrove-signing-tools'
    $xtask = Join-Path $temporary.FullName 'kitrove-release-xtask.exe'
    . "$PSScriptRoot/windows-signing-tools.ps1"

    switch ($Operation) {
        'Prepare' {
            if (Test-Path -LiteralPath $azureDirectory) { throw 'Azure cache must start absent' }
            cargo build --locked -p xtask
            if ($LASTEXITCODE -ne 0) { throw 'Release tool compilation failed' }
            Copy-Item -LiteralPath 'target/debug/xtask.exe' -Destination $xtask
            Initialize-KitroveSigningTools $azureDirectory
        }
        'Sign' {
            if ($env:AZURE_CONFIG_DIR -cne $azureDirectory -or
                [string]::IsNullOrWhiteSpace($env:RELEASE_TAG)) {
                throw 'Signing requires the isolated Azure cache and release tag'
            }
            $tool = Get-Item -LiteralPath $xtask
            if ($tool.PSIsContainer -or ($tool.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'Prebuilt release tool must be a regular file'
            }
            $priorModulePath = $env:PSModulePath
            try {
                Remove-Item Env:PSModulePath -ErrorAction SilentlyContinue
                foreach ($product in @('kitrove-cli', 'kitrove-installer')) {
                    & $xtask prepare-platform-release "target/distrib/$product-$env:DIST_TARGET.zip" `
                        $env:DIST_TARGET $env:RELEASE_TAG release/application-compatibility.json dist-manifest.json
                    if ($LASTEXITCODE -ne 0) { throw 'Signed archive preparation failed' }
                }
            } finally {
                $env:PSModulePath = $priorModulePath
            }
        }
        'Cleanup' {
            if ($env:AZURE_CONFIG_DIR -cne $azureDirectory) { throw 'Refusing unrelated Azure cache cleanup' }
            $clearFailed = $false
            try {
                az account clear --only-show-errors
                if ($LASTEXITCODE -ne 0) { $clearFailed = $true }
            } catch {
                $clearFailed = $true
            } finally {
                if (Test-Path -LiteralPath $azureDirectory) {
                    $cache = Get-Item -LiteralPath $azureDirectory
                    if (-not $cache.PSIsContainer -or ($cache.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        throw 'Refusing redirected Azure cache cleanup'
                    }
                    Remove-Item -LiteralPath $azureDirectory -Recurse -Force
                }
            }
            if ($clearFailed) { throw 'Azure account cleanup failed' }
        }
        default { throw 'Unknown hosted signing operation' }
    }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-HostedWindowsSigning $Stage }

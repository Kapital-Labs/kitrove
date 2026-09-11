param([Parameter(Mandatory)][string]$FixtureRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Match Prepare's Get-Item path authority, including Windows short-name expansion.
$FixtureRoot = (Get-Item -LiteralPath $FixtureRoot).FullName

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-Fails([scriptblock]$Action, [string]$Message) {
    $failed = $false
    try { & $Action } catch { $failed = $true }
    Assert-True $failed $Message
}

foreach ($name in @('hosted-windows-signing.ps1', 'windows-signing-tools.ps1', 'windows-signing-rehearsal.ps1')) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name), [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "PowerShell parser rejected $name"
}

. "$PSScriptRoot/hosted-windows-signing.ps1"
$env:GITHUB_ACTIONS = 'true'
$env:GITHUB_REPOSITORY = 'Kapital-Labs/kitrove'
$env:GITHUB_REF = 'refs/tags/v0.0.0'
$env:DIST_TARGET = 'x86_64-pc-windows-msvc'
$env:RUNNER_TEMP = $FixtureRoot
$env:RUNNER_ENVIRONMENT = 'self-hosted'
Assert-Fails { Invoke-HostedWindowsSigning 'Prepare' } 'Self-hosted runner was accepted'
$env:RUNNER_ENVIRONMENT = 'github-hosted'
$env:GITHUB_REF = 'refs/heads/main'
Assert-Fails { Invoke-HostedWindowsSigning 'Prepare' } 'Untagged context was accepted'
$env:GITHUB_REF = 'refs/tags/v0.0.0'

# Substitute Azure itself. No authentication, provider access or signing occurs.
$script:clearCode = 0
$script:clearCalls = 0
function az {
    $script:clearCalls++
    Assert-True (($args -join ' ') -ceq 'account clear --only-show-errors') 'Unexpected Azure operation'
    $global:LASTEXITCODE = $script:clearCode
}
$env:AZURE_CONFIG_DIR = Join-Path $FixtureRoot 'kitrove-release-azure'
foreach ($code in @(0, 1)) {
    $script:clearCode = $code
    New-Item -ItemType Directory -Path $env:AZURE_CONFIG_DIR | Out-Null
    Set-Content -LiteralPath (Join-Path $env:AZURE_CONFIG_DIR 'synthetic-token') -Value 'fixture'
    if ($code -eq 0) {
        Invoke-HostedWindowsSigning 'Cleanup'
    } else {
        Assert-Fails { Invoke-HostedWindowsSigning 'Cleanup' } 'Failed Azure clear was ignored'
    }
    Assert-True (-not (Test-Path -LiteralPath $env:AZURE_CONFIG_DIR)) 'Azure cache was retained'
}
Assert-True ($script:clearCalls -eq 2) 'Cleanup did not call Azure exactly twice'
$env:AZURE_CONFIG_DIR = $FixtureRoot
Assert-Fails { Invoke-HostedWindowsSigning 'Cleanup' } 'Unrelated cache path was accepted'
Assert-True (Test-Path -LiteralPath $FixtureRoot) 'Unrelated directory was removed'
Assert-True ($script:clearCalls -eq 2) 'Unrelated cache reached Azure'

# A branch is accepted only for the exact manually approved rehearsal workflow.
$env:GITHUB_REF = 'refs/heads/main'
$env:GITHUB_EVENT_NAME = 'workflow_dispatch'
$env:GITHUB_WORKFLOW_REF = 'Kapital-Labs/kitrove/.github/workflows/signing-rehearsal.yml@refs/heads/main'
$env:GITHUB_SHA = 'a' * 40
$env:KITROVE_SIGNING_REHEARSAL_SHA = $env:GITHUB_SHA
$env:RELEASE_TAG = 'v0.0.0'
$env:AZURE_CONFIG_DIR = Join-Path $FixtureRoot 'kitrove-release-azure'
$script:clearCode = 0
Invoke-HostedWindowsSigning 'Cleanup'
Assert-True ($script:clearCalls -eq 3) 'Approved rehearsal was rejected'
foreach ($name in @('GITHUB_EVENT_NAME', 'GITHUB_WORKFLOW_REF', 'GITHUB_SHA', 'KITROVE_SIGNING_REHEARSAL_SHA', 'RELEASE_TAG')) {
    $prior = [Environment]::GetEnvironmentVariable($name)
    [Environment]::SetEnvironmentVariable($name, 'wrong')
    Assert-Fails { Invoke-HostedWindowsSigning 'Cleanup' } "Rehearsal accepted incorrect $name"
    [Environment]::SetEnvironmentVariable($name, $prior)
}
Assert-True ($script:clearCalls -eq 3) 'Invalid rehearsal reached Azure'

. "$PSScriptRoot/windows-signing-tools.ps1"
$toolDir = $FixtureRoot
$script:expanded = 0
function Invoke-WebRequest { param($Uri, $OutFile) Set-Content -LiteralPath $OutFile -Value 'synthetic package' }
function Expand-Archive { param($LiteralPath, $DestinationPath) $script:expanded++ }
Assert-Fails { Get-PinnedZip 'mismatch' 'https://invalid.example/' ('0' * 64) } 'Checksum mismatch was accepted'
Assert-True ($script:expanded -eq 0) 'Unverified package was expanded'
'Hosted Windows synthetic checks passed'

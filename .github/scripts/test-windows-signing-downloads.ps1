param([Parameter(Mandatory)][string]$FixtureRoot, [string]$LoopbackUri)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/windows-signing-tools.ps1"

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Invoke-Scenario([string]$Scenario) {
    $toolDir = Join-Path $FixtureRoot $Scenario
    New-Item -ItemType Directory -Path $toolDir | Out-Null
    $script:calls = 0
    $script:expansions = 0
    $script:boundedRequests = 0
    $script:waits = @()
    $expected = Join-Path $toolDir 'fixture'
    [IO.File]::WriteAllText($expected, 'complete')
    $digest = Get-Digest $expected
    if ($Scenario -eq 'preexisting') {
        [IO.File]::WriteAllText((Join-Path $toolDir 'sdk-1.zip'), 'preserve')
    }
    function Invoke-WebRequest {
        param($Uri, $OutFile, $ConnectionTimeoutSeconds, $OperationTimeoutSeconds, $ErrorAction)
        $script:calls++
        Assert-True ($Uri -ceq 'https://invalid.example/fixed') 'Download URI changed'
        if ($ConnectionTimeoutSeconds -eq 30 -and $OperationTimeoutSeconds -eq 120) { $script:boundedRequests++ }
        Assert-True (-not (Test-Path -LiteralPath $OutFile)) 'Attempt reused existing bytes'
        if ($Scenario -eq 'unknown') { throw 'SECRET_PROVIDER /SECRET_PATH' }
        if ($Scenario -eq 'http') {
            throw [System.Net.Http.HttpRequestException]::new(
                [System.Net.Http.HttpRequestError]::HttpProtocolError, 'SECRET_HTTP', $null,
                [System.Net.HttpStatusCode]::NotFound)
        }
        if ($Scenario -in @('timeout', 'connection', 'dns')) {
            if ($Scenario -eq 'timeout') { throw [System.TimeoutException]::new('SECRET_TIMEOUT') }
            $kind = if ($Scenario -eq 'connection') { [System.Net.Http.HttpRequestError]::ConnectionError } else { [System.Net.Http.HttpRequestError]::NameResolutionError }
            throw [System.Net.Http.HttpRequestException]::new($kind, 'SECRET_NETWORK')
        }
        if ($Scenario -eq 'interrupt' -and $script:calls -lt 3 -or $Scenario -eq 'exhaust') {
            [IO.File]::WriteAllText($OutFile, 'partial')
            $error = [System.Net.Http.HttpIOException]::new(
                [System.Net.Http.HttpRequestError]::ResponseEnded, 'SECRET_PROVIDER /SECRET_PATH')
            throw [System.Net.Http.HttpRequestException]::new('SECRET_WRAPPER', $error)
        }
        [IO.File]::WriteAllText($OutFile, $(if ($Scenario -eq 'digest') { 'wrong' } else { 'complete' }))
    }
    function Start-Sleep { param($Seconds) $script:waits += $Seconds }
    function Expand-Archive {
        param($LiteralPath, $DestinationPath)
        $script:expansions++
        Assert-True ((Get-Digest $LiteralPath) -ceq $digest) 'Unverified bytes expanded'
        if ($Scenario -eq 'extract') { throw 'SECRET_EXTRACT' }
    }
    $failure = $null
    $result = $null
    try { $result = Get-PinnedZip 'sdk' 'https://invalid.example/fixed' $digest } catch { $failure = $_ }
    if ($Scenario -in @('interrupt', 'success')) {
        Assert-True ($null -eq $failure) "Valid download refused: $Scenario"
        Assert-True ($result -ceq (Join-Path $toolDir 'sdk')) 'Diagnostic text polluted returned path'
        Assert-True ($script:expansions -eq 1) 'Verified archive not expanded exactly once'
    } else {
        Assert-True ($null -ne $failure) "Invalid download accepted: $Scenario"
        Assert-True (-not ($failure.ToString().Contains('SECRET'))) 'Raw error escaped'
        Assert-True ($script:expansions -eq $(if ($Scenario -eq 'extract') { 1 } else { 0 })) 'Invalid bytes expanded'
    }
    $expectedCalls = if ($Scenario -in @('interrupt', 'exhaust', 'timeout', 'connection', 'dns')) { 3 } elseif ($Scenario -eq 'preexisting') { 0 } else { 1 }
    Assert-True ($script:calls -eq $expectedCalls) "Incorrect retry bound: $Scenario"
    Assert-True ($script:boundedRequests -eq $script:calls) 'Download is unbounded'
    Assert-True (($script:waits -join ',') -ceq $(if ($expectedCalls -eq 3) { '2,4' } else { '' })) 'Unexpected retry waits'
    if ($Scenario -eq 'preexisting') {
        Assert-True ([IO.File]::ReadAllText((Join-Path $toolDir 'sdk-1.zip')) -ceq 'preserve') 'Preexisting file changed'
    }
    Assert-True (@(Get-ChildItem -LiteralPath $toolDir -Filter '*.zip').Count -eq $(if ($Scenario -eq 'preexisting') { 1 } else { 0 })) 'Partial attempt retained'
}
foreach ($scenario in @('interrupt', 'success', 'exhaust', 'timeout', 'connection', 'dns', 'http', 'unknown', 'digest', 'extract', 'preexisting')) {
    Invoke-Scenario $scenario
}
if ($LoopbackUri) {
    # Python owns this loopback-only HTTP fixture. Use the real HTTP client, never a provider.
    if (-not $LoopbackUri.StartsWith('http://127.0.0.1:')) { throw 'Fixture URI is not loopback' }
    $toolDir = Join-Path $FixtureRoot 'real-http'
    New-Item -ItemType Directory -Path $toolDir | Out-Null
    $fixture = Join-Path $toolDir 'expected'
    [IO.File]::WriteAllText($fixture, 'complete')
    $script:realExpansions = 0
    function Expand-Archive {
        param($LiteralPath, $DestinationPath, $ErrorAction)
        Assert-True ((Get-Digest $LiteralPath) -ceq (Get-Digest $fixture)) 'Real client accepted partial bytes'
        $script:realExpansions++
    }
    $result = Get-PinnedZip 'client' $LoopbackUri (Get-Digest $fixture)
    Assert-True ($result -ceq (Join-Path $toolDir 'client')) 'Real download path changed'
    Assert-True ($script:realExpansions -eq 1) 'Real client did not expand verified bytes once'
}
'Pinned download scenarios passed; only optional loopback traffic, no authentication/signing.'

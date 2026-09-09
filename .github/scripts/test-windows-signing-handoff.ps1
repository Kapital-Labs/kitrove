Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'windows-signing-rehearsal.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Rehearsal script has syntax errors' }
$helper = $ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-ReleaseTool'
}, $true)
if ($helper.Count -ne 1) { throw 'Expected exactly one shared release-tool invocation helper' }
. ([scriptblock]::Create($helper[0].Extent.Text))
$xtask = 'Test-ReleaseTool'
function Test-ReleaseTool {
    param([string]$Mode)
    if ($env:PSModulePath) { throw 'PowerShell module path leaked into release tool' }
    if ($Mode -eq 'fail') { throw 'synthetic release-tool failure' }
    if ($Mode -ne 'pass') { throw 'release-tool argument was not forwarded' }
}
$testModulePath = $env:PSModulePath
Invoke-ReleaseTool @('pass')
if ($env:PSModulePath -cne $testModulePath) { throw 'Successful invocation changed caller modules' }
$failed = $false
try { Invoke-ReleaseTool @('fail') } catch {
    if ($_.Exception.Message -ne 'synthetic release-tool failure') { throw }
    $failed = $true
}
if (-not $failed -or $env:PSModulePath -cne $testModulePath) {
    throw 'Failed invocation suppressed its error or changed caller modules'
}
Write-Output 'Release-tool environment isolation and restoration passed.'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('kitrove-handoff-test-' + [guid]::NewGuid())
$priorSha = $env:GITHUB_SHA
$priorSourceSha = $env:EXPECTED_SOURCE_SHA
$priorDigest = $env:EXPECTED_INVENTORY_DIGEST
$priorTemp = $env:RUNNER_TEMP
New-Item -ItemType Directory -Path (Join-Path $testRoot 'signing-input') | Out-Null
Push-Location $testRoot
try {
    $env:GITHUB_SHA = 'a' * 40
    $env:EXPECTED_SOURCE_SHA = ''
    $env:RUNNER_TEMP = $testRoot
    $names = @('xtask.exe', 'dist-manifest.json', 'application-compatibility.json',
        'kitrove-cli-x86_64-pc-windows-msvc.zip', 'kitrove-cli-x86_64-pc-windows-msvc.zip.sha256',
        'kitrove-installer-x86_64-pc-windows-msvc.zip', 'kitrove-installer-x86_64-pc-windows-msvc.zip.sha256')
    $files = [ordered]@{}
    foreach ($name in $names) {
        Set-Content -LiteralPath "signing-input/$name" -Value 'synthetic fixture'
        $files[$name] = (Get-FileHash "signing-input/$name" -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $inventory = @{ commit = $env:GITHUB_SHA; files = $files } | ConvertTo-Json -Depth 4
    Set-Content 'signing-input/inventory.json' $inventory
    $env:EXPECTED_INVENTORY_DIGEST = (Get-FileHash 'signing-input/inventory.json' -Algorithm SHA256).Hash.ToLowerInvariant()
    & $scriptPath -Stage ValidateHandoff

    function Assert-Rejected([string]$Label) {
        $rejected = $false
        try { & $scriptPath -Stage ValidateHandoff } catch { $rejected = $true }
        if (-not $rejected) { throw "Handoff unexpectedly accepted: $Label" }
        Write-Output "Rejected $Label"
    }
    $env:GITHUB_SHA = 'b' * 40
    Assert-Rejected 'another source commit'
    $env:EXPECTED_SOURCE_SHA = 'a' * 40
    & $scriptPath -Stage ValidateHandoff
    $env:EXPECTED_SOURCE_SHA = 'c' * 40
    Assert-Rejected 'another explicitly pinned build commit'
    $env:EXPECTED_SOURCE_SHA = 'not-a-commit'
    Assert-Rejected 'a malformed pinned build commit'
    $env:EXPECTED_SOURCE_SHA = ''
    $env:GITHUB_SHA = 'a' * 40
    Set-Content 'signing-input/extra.txt' 'unexpected'
    Assert-Rejected 'an extra file'
    Remove-Item -LiteralPath 'signing-input/extra.txt'
    Set-Content 'signing-input/xtask.exe' 'changed'
    Assert-Rejected 'a substituted build tool'
    Set-Content 'signing-input/xtask.exe' 'synthetic fixture'
    $env:EXPECTED_INVENTORY_DIGEST = '0' * 64
    Assert-Rejected 'a substituted inventory'
    $env:EXPECTED_INVENTORY_DIGEST = (Get-FileHash 'signing-input/inventory.json' -Algorithm SHA256).Hash.ToLowerInvariant()
    Remove-Item -LiteralPath 'signing-input/xtask.exe'
    Assert-Rejected 'a missing build tool'
    Write-Output 'Handoff validation: two positive cases and seven refusal cases passed.'
} finally {
    Pop-Location
    $env:GITHUB_SHA = $priorSha
    $env:EXPECTED_SOURCE_SHA = $priorSourceSha
    $env:EXPECTED_INVENTORY_DIGEST = $priorDigest
    $env:RUNNER_TEMP = $priorTemp
    # This invocation created this exact unpredictable synthetic-fixture directory.
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}

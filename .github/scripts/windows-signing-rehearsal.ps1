param([Parameter(Mandatory)][ValidateSet('Build', 'Provision', 'Sign', 'ValidateHandoff')][string]$Stage)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
if ($Stage -ne 'ValidateHandoff' -and (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true')) {
    throw 'The signing rehearsal requires an ephemeral Windows GitHub runner'
}
$target = 'x86_64-pc-windows-msvc'
$tag = 'v0.0.0'
$products = @('kitrove-cli', 'kitrove-installer')
$inputDir = Join-Path $PWD 'signing-input'
$toolDir = Join-Path $env:RUNNER_TEMP 'kitrove-signing-tools'
$sourceSha = if ($env:EXPECTED_SOURCE_SHA) { $env:EXPECTED_SOURCE_SHA } else { $env:GITHUB_SHA }

. "$PSScriptRoot/windows-signing-tools.ps1"
$publisher = Get-KitroveWindowsPublisher

function Invoke-ReleaseTool([string[]]$Arguments) {
    # Also isolates the reviewed prebuilt tool, which predates child-env isolation.
    $priorModulePath = $env:PSModulePath
    try {
        if (Test-Path Env:PSModulePath) { Remove-Item Env:PSModulePath }
        & $xtask @Arguments
    } finally {
        $env:PSModulePath = $priorModulePath
    }
}
function Assert-Handoff {
    $inventoryPath = Join-Path $inputDir 'inventory.json'
    if ($env:EXPECTED_INVENTORY_DIGEST -cnotmatch '^[a-f0-9]{64}$' -or
        (Get-Digest $inventoryPath) -cne $env:EXPECTED_INVENTORY_DIGEST) {
        throw 'Build inventory does not match the reviewed expected digest'
    }
    $inventory = Get-Content -Raw -LiteralPath $inventoryPath | ConvertFrom-Json
    if ($sourceSha -cnotmatch '^[a-f0-9]{40}$' -or $inventory.commit -cne $sourceSha) {
        throw 'Build source commit mismatch'
    }
    $expected = @('xtask.exe', 'dist-manifest.json', 'application-compatibility.json')
    foreach ($product in $products) {
        $expected += "$product-$target.zip", "$product-$target.zip.sha256"
    }
    $names = @($inventory.files.PSObject.Properties.Name)
    if (@(Compare-Object ($expected | Sort-Object) ($names | Sort-Object) -CaseSensitive).Count -ne 0) {
        throw 'Unexpected handoff inventory'
    }
    $actual = @(Get-ChildItem -LiteralPath $inputDir -Force | Select-Object -ExpandProperty Name)
    if (@(Compare-Object (($expected + 'inventory.json') | Sort-Object) ($actual | Sort-Object) -CaseSensitive).Count -ne 0) {
        throw 'Unexpected handoff files'
    }
    foreach ($name in $expected) {
        $file = Get-Item -LiteralPath (Join-Path $inputDir $name)
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            (Get-Digest $file.FullName) -cne $inventory.files.$name) {
            throw 'Handoff file is redirected or has changed'
        }
    }
}

if ($Stage -eq 'Build') {
    if ($env:ACTIONS_ID_TOKEN_REQUEST_URL) { throw 'Build job must not have OIDC access' }
    & "$PSScriptRoot/test-windows-signing-handoff.ps1"
    # Fail fast on host-specific integrity regressions before compiling products.
    cargo test --locked -p kitrove-release-policy -p xtask
    cargo build --locked -p xtask
    New-Item -ItemType Directory -Path $inputDir, $toolDir | Out-Null
    $distDir = Get-PinnedZip 'dist' 'https://github.com/axodotdev/cargo-dist/releases/download/v0.32.0/cargo-dist-x86_64-pc-windows-msvc.zip' '26e845cabff12a92911ce960af73a86c8f9b2b2d9072b01dfe5b662acf044fa3'
    $dist = Join-Path $distDir 'dist.exe'
    & $dist build --tag=$tag --artifacts=local --target=$target --output-format=json |
        Set-Content -LiteralPath (Join-Path $inputDir 'dist-manifest.json') -Encoding utf8NoBOM
    Copy-Item -LiteralPath 'target/debug/xtask.exe' -Destination $inputDir
    Copy-Item -LiteralPath 'release/application-compatibility.json' -Destination $inputDir
    foreach ($product in $products) {
        $archive = "target/distrib/$product-$target.zip"
        Copy-Item -LiteralPath $archive, "$archive.sha256" -Destination $inputDir
    }
    $files = [ordered]@{}
    Get-ChildItem -LiteralPath $inputDir -File | Sort-Object Name | ForEach-Object {
        $files[$_.Name] = Get-Digest $_.FullName
    }
    $inventoryPath = Join-Path $inputDir 'inventory.json'
    @{ commit = $env:GITHUB_SHA; files = $files } | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath $inventoryPath -Encoding utf8NoBOM
    "inventory-digest=$(Get-Digest $inventoryPath)" | Add-Content -LiteralPath $env:GITHUB_OUTPUT
    exit 0
}

Assert-Handoff
if ($Stage -eq 'ValidateHandoff') { exit 0 }
if ($Stage -eq 'Provision') {
    Initialize-KitroveSigningTools (Join-Path $env:RUNNER_TEMP 'kitrove-rehearsal-azure')
    exit 0
}

# Only the reviewed build tool runs with credentials, never either product binary.
$xtask = Join-Path $inputDir 'xtask.exe'
$manifest = Join-Path $inputDir 'dist-manifest.json'
$compatibility = Join-Path $inputDir 'application-compatibility.json'
$evidenceDir = Join-Path $PWD 'signing-evidence'
New-Item -ItemType Directory -Path $evidenceDir | Out-Null
foreach ($product in $products) {
    $archive = Join-Path $inputDir "$product-$target.zip"
    Invoke-ReleaseTool @('prepare-platform-release', $archive, $target, $tag, $compatibility, $manifest)
    Invoke-ReleaseTool @('verify-application-release-bundle', $archive, $target, $tag, $manifest)
}
# Recheck both bundles after the shared cargo-dist manifest has its final digests.
$results = @()
foreach ($product in $products) {
    $archive = Join-Path $inputDir "$product-$target.zip"
    Invoke-ReleaseTool @('verify-application-release-bundle', $archive, $target, $tag, $manifest)
    $expanded = Join-Path $toolDir $product
    Expand-Archive -LiteralPath $archive -DestinationPath $expanded
    $name = if ($product -eq 'kitrove-cli') { 'kitrove.exe' } else { 'kitrove-installer.exe' }
    $executable = Join-Path $expanded $name
    $signature = Get-AuthenticodeSignature -LiteralPath $executable
    if ($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Authenticode' -or
        $null -eq $signature.TimeStamperCertificate -or
        $signature.SignerCertificate.Subject -cne $publisher) {
        throw 'Final archive lost its timestamped publisher signature'
    }
    $results += @{
        product = $product; archive_sha256 = Get-Digest $archive
        executable_sha256 = Get-Digest $executable; publisher = $signature.SignerCertificate.Subject
        timestamp_subject = $signature.TimeStamperCertificate.Subject; signature_status = 'Valid'
    }
    Copy-Item -LiteralPath $archive, "$archive.sha256" -Destination $evidenceDir
}
Copy-Item -LiteralPath $manifest -Destination $evidenceDir
@{ commit = $sourceSha; workflow_commit = $env:GITHUB_SHA; run_id = $env:GITHUB_RUN_ID; tag = $tag; results = $results } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidenceDir 'evidence.json') -Encoding utf8NoBOM
'Both Windows archives passed native signing, timestamp, publisher and digest verification.' |
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY

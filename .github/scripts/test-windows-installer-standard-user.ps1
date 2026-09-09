param(
    [ValidateSet("All", "Replacement")]
    [string] $Suite = "All"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$user = "KitRoveCi"
$securePassword = ConvertTo-SecureString ([guid]::NewGuid().ToString("N") + "aA1!") -AsPlainText -Force
$createdUser = $false

try {
    $account = New-LocalUser -Name $user -Password $securePassword -AccountNeverExpires -UserMayNotChangePassword
    $createdUser = $true
    Add-LocalGroupMember -SID "S-1-5-32-545" -Member $account

    $buildOutput = cargo test --locked -p kitrove-installer --lib --test public_staging --no-run --message-format=json
    if ($LASTEXITCODE -ne 0) { throw "installer test build failed" }
    $artifacts = @($buildOutput | ConvertFrom-Json | Where-Object { $_.reason -eq "compiler-artifact" })
    $probeBuild = cargo build --locked -p kitrove-version-probe --features windows-test-fixture --bin kitrove-version-probe-fixture --message-format=json
    if ($LASTEXITCODE -ne 0) { throw "application probe fixture build failed" }
    $probeArtifacts = @($probeBuild | ConvertFrom-Json | Where-Object { $_.reason -eq "compiler-artifact" -and $_.target.name -eq "kitrove-version-probe-fixture" -and $_.executable })
    if ($probeArtifacts.Count -ne 1) { throw "expected exactly one application probe fixture" }
    $cases = @(
        @{ Target = "public_staging"; Name = "authenticated_windows_executable_crosses_the_public_staging_boundary"; Ignored = $false },
        @{ Target = "kitrove_installer"; Name = "upgrade_transaction::windows_tests::standard_user_preparation_and_recovery"; Ignored = $true },
        @{ Target = "kitrove_installer"; Name = "release_intake::windows_tests::standard_user_local_release_intake"; Ignored = $true },
        @{ Target = "kitrove_installer"; Name = "installation_state::windows_tests::standard_user_first_install_state_preparation"; Ignored = $true },
        @{ Target = "kitrove_installer"; Name = "installation_state::execution::tests::standard_user_state_guarded_installation"; Ignored = $true },
        @{ Target = "kitrove_installer"; Name = "installation_state::execution::tests::recovery_tests::standard_user_read_only_first_install_recovery"; Ignored = $true },
        @{ Target = "kitrove_installer"; Name = "installation_state::execution::tests::recovery_tests::execution_tests::standard_user_first_install_recovery_execution"; Ignored = $true }
        @{ Target = "kitrove_installer"; Name = "installation_state::execution::tests::recovery_tests::retirement_tests::standard_user_terminal_history_retention"; Ignored = $true }
        @{ Target = "kitrove_installer"; Name = "command::tests::windows_workflow::standard_user_command_workflow"; Ignored = $true }
    )

    if ($Suite -eq "Replacement") {
        $requiredCases = @(
            "upgrade_transaction::windows_tests::standard_user_preparation_and_recovery",
            "command::tests::windows_workflow::standard_user_command_workflow"
        )
        $cases = @($cases | Where-Object { $_.Name -in $requiredCases })
        if ($cases.Count -ne $requiredCases.Count) { throw "replacement suite selection is incomplete" }
        foreach ($required in $requiredCases) {
            if (@($cases | Where-Object { $_.Name -eq $required }).Count -ne 1) {
                throw "replacement suite must contain each required case exactly once"
            }
        }
    }

    $credential = [pscredential]::new("$env:COMPUTERNAME\$user", $securePassword)
    $bootstrap = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
        -ArgumentList '/d /c exit 0' `
        -WorkingDirectory $env:SystemRoot -Credential $credential -LoadUserProfile -Wait -PassThru
    if ($bootstrap.ExitCode -ne 0) { throw "failed to load standard-user profile" }

    $sid = ([System.Security.Principal.NTAccount]::new($env:COMPUTERNAME, $user)).Translate(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
    $profile = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }
    if (-not $profile.LocalPath) { throw "standard-user profile was not created" }
    $prepare = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
        -ArgumentList '/d /c mkdir KitRoveTest' `
        -WorkingDirectory $profile.LocalPath -Credential $credential -LoadUserProfile -Wait -PassThru
    if ($prepare.ExitCode -ne 0) { throw "failed to create standard-user test directory" }
    $runDirectory = Join-Path $profile.LocalPath "KitRoveTest"
    Copy-Item $probeArtifacts[0].executable (Join-Path $runDirectory "application-probe-fixture.exe")
    $caseIndex = 0
    foreach ($case in $cases) {
        $testArtifacts = @($artifacts | Where-Object { $_.target.name -eq $case.Target -and $_.profile.test -and $_.executable })
        if ($testArtifacts.Count -ne 1) { throw "expected exactly one installer test executable for $($case.Target)" }
        $artifact = $testArtifacts[0]
        $arguments = @("--exact", $case.Name, "--nocapture")
        if ($case.Ignored) { $arguments += "--ignored" }
        $listed = & $artifact.executable @arguments --list
        if ($LASTEXITCODE -ne 0 -or "$($case.Name): test" -notin $listed) {
            throw "required standard-user test is missing: $($case.Name)"
        }
        $testExecutable = Join-Path $runDirectory "$($case.Target).exe"
        Copy-Item $artifact.executable $testExecutable
        $stdout = Join-Path $runDirectory "case-$caseIndex.stdout.log"
        $stderr = Join-Path $runDirectory "case-$caseIndex.stderr.log"
        $process = Start-Process -FilePath $testExecutable `
            -ArgumentList $arguments `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
            -WorkingDirectory $runDirectory -Credential $credential -LoadUserProfile -Wait -PassThru
        Write-Output "Standard-user test: $($case.Name)"
        Get-Content $stdout
        Get-Content $stderr
        if ($process.ExitCode -ne 0) { throw "standard-user installer test failed: $($case.Name)" }
        $caseIndex++
    }
} finally {
    if ($createdUser) {
        Remove-LocalUser -Name $user
    }
}

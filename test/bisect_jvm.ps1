# Bisect which Catfuscator config makes the obfuscated jvm.dll usable in the
# launcher. Tries a sequence of progressively more aggressive configurations,
# runs the launcher test on each, records pass/fail.
#
# Assumes jvm.dll is already built in the kotopushkavm output tree (run a
# `make hotspot` first if you changed markers). This script only re-runs
# Catfuscator with different flags and tests via the launcher.

param(
    [int]$LauncherTimeout = 180,
    [int]$IterationsPerConfig = 2  # run each config N times to filter RNG flakes
)

$catfuscator = "c:\protection\catfuscator\Catfuscator\x64\Release\Catfuscator-con.exe"
$srcDll      = "c:\AntiAutistLeak\kotopushkavm\build\windows-x86_64-server-release\jdk\bin\server\jvm.dll"
$obfDll      = "c:\AntiAutistLeak\kotopushkavm\build\windows-x86_64-server-release\jdk\bin\server\jvm.obf.dll"
$dstDll      = "C:\YumeSoft\Nuclear\default\jvm\bin\server\jvm.dll"

if (-not (Test-Path $srcDll)) {
    Write-Error "jvm.dll not built at $srcDll -- run 'make hotspot' first"
    exit 9
}

# Each config: a string -> ' '-separated Catfuscator flags.
# Order from MOST disabled (safer) to LEAST disabled (more obfuscation).
$configs = [ordered]@{
    "all_off"              = "--markers --no-mov --no-add --no-lea --no-antidisasm"
    "antidisasm_only"      = "--markers --no-mov --no-add --no-lea"
    "junk_only"            = "--markers --no-mov --no-add --no-lea --no-deadcode --no-ff-obf"
    "deadcode_only"        = "--markers --no-mov --no-add --no-lea --no-junk --no-ff-obf"
    "ff_only"              = "--markers --no-mov --no-add --no-lea --no-junk --no-deadcode"
    "lea_only"             = "--markers --no-mov --no-add --no-antidisasm"
    "add_only"             = "--markers --no-mov --no-lea --no-antidisasm"
    "mov_only"             = "--markers --no-add --no-lea --no-antidisasm"
    "all_on"               = "--markers"
}

$results = [ordered]@{}

foreach ($name in $configs.Keys) {
    $flags = $configs[$name]
    Write-Host "`n========== CONFIG: $name [$flags] ==========" -ForegroundColor Cyan

    # Obfuscate fresh -- binary path MUST be argv[1], flags follow
    $obfArgs = @($srcDll) + $flags.Split(' ')
    Remove-Item -Path $obfDll -ErrorAction SilentlyContinue
    & $catfuscator @obfArgs 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Host "  $_" }

    if (-not (Test-Path $obfDll)) {
        Write-Host "  FAIL: obfuscation produced no output" -ForegroundColor Red
        $results[$name] = @{ pass=0; fail=$IterationsPerConfig; verdicts=@(99) }
        continue
    }

    # Run launcher N times
    $verdicts = @()
    for ($i = 1; $i -le $IterationsPerConfig; $i++) {
        # Re-deploy (launcher may rewrap to .Themida-wrap, so always restore)
        Copy-Item -Force $obfDll $dstDll
        Write-Host ("  iter ${i}: deployed obf ({0:N0} bytes), running launcher..." -f (Get-Item $dstDll).Length)

        $verdictLine = & "c:\protection\catfuscator\test\run_launcher_test.ps1" -TimeoutSec $LauncherTimeout 2>&1 | Select-Object -Last 1
        $verdict = if ($verdictLine -match "VERDICT=(\d+)") { [int]$matches[1] } else { 9 }
        $verdicts += $verdict

        $color = if ($verdict -eq 0) { "Green" } else { "Yellow" }
        Write-Host "  iter $i verdict: $verdict" -ForegroundColor $color
        Start-Sleep -Seconds 3
    }

    $pass = ($verdicts | Where-Object { $_ -eq 0 }).Count
    $fail = $IterationsPerConfig - $pass
    $results[$name] = @{ pass=$pass; fail=$fail; verdicts=$verdicts }

    $sumColor = if ($pass -eq $IterationsPerConfig) { "Green" } else { "Yellow" }
    Write-Host ("  config $name : {0}/{1} pass" -f $pass, $IterationsPerConfig) -ForegroundColor $sumColor
}

Write-Host "`n`n=========================================" -ForegroundColor Cyan
Write-Host "FINAL TABLE" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
foreach ($name in $results.Keys) {
    $r = $results[$name]
    $color = if ($r.pass -eq $IterationsPerConfig) { "Green" } elseif ($r.pass -gt 0) { "Yellow" } else { "Red" }
    Write-Host ("{0,-20} {1}/{2} pass  verdicts=[{3}]" -f $name, $r.pass, $IterationsPerConfig, ($r.verdicts -join ",")) -ForegroundColor $color
}

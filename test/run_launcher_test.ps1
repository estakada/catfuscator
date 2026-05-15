# Automated JVM-via-launcher regression test.
# Spawns launcher with stdout redirected to a file, polls the file for outcome
# signals, kills the whole tree on conclusion.
#
# Exit codes:
#   0 = JVM init succeeded AND class loading reached app launch
#       ("Launching Minecraft" seen, no error/crash within $PostInitWaitSec)
#   1 = TAKOPI / classfile cipher produced wrong output
#       ("Error occurred during initialization of VM")
#   2 = launcher exited silently after "Loading JVM..." (LoadLibrary failed)
#   3 = JVM created then crashed (fatal error / new hs_err)
#   4 = timeout without a clear signal
#   9 = harness error

param(
    [string]$LauncherExe    = "C:\Users\miked\Downloads\AyuGram Desktop\LauncherCLI.exe",
    [int]$TimeoutSec        = 150,
    [int]$PostInitWaitSec   = 45,  # after "Launching Minecraft" wait this long, no crash = PASS
    [string]$LogPath        = "c:\protection\catfuscator\test\diag\launcher_run.log"
)

if (-not (Test-Path $LauncherExe)) {
    Write-Output "VERDICT=9 REASON=launcher not found at $LauncherExe"
    exit 9
}

$gameDir = "C:\YumeSoft\Nuclear\default"
$existingErrs = @{}
if (Test-Path $gameDir) {
    foreach ($f in (Get-ChildItem $gameDir -Filter "hs_err_pid*.log" -ErrorAction SilentlyContinue)) {
        $existingErrs[$f.FullName] = $f.LastWriteTime
    }
}

function Kill-LauncherTree {
    # Kill by exact process names (case-insensitive); be aggressive.
    $names = @('LauncherCLI','launcher','java','javaw')
    foreach ($n in $names) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}

Kill-LauncherTree
Start-Sleep -Milliseconds 800
Kill-LauncherTree

New-Item -ItemType Directory -Path (Split-Path $LogPath -Parent) -Force | Out-Null

$tmpOut = [IO.Path]::GetTempFileName()
$tmpErr = [IO.Path]::GetTempFileName()

# Launch with stdout/stderr redirected to files. Start-Process with -PassThru +
# -RedirectStandard* lets us tail the files while the process runs.
$proc = Start-Process -FilePath $LauncherExe `
                       -WorkingDirectory (Split-Path $LauncherExe -Parent) `
                       -RedirectStandardOutput $tmpOut `
                       -RedirectStandardError  $tmpErr `
                       -PassThru -WindowStyle Hidden

$deadline      = (Get-Date).AddSeconds($TimeoutSec)
$verdict       = 4
$verdictReason = "timeout reached"
$sawLaunchMC   = $false
$launchMCAt    = $null

while ((Get-Date) -lt $deadline) {
    $out = ""
    if (Test-Path $tmpOut) { $out += (Get-Content $tmpOut -Raw -ErrorAction SilentlyContinue) }
    if (Test-Path $tmpErr) { $out += "`n" + (Get-Content $tmpErr -Raw -ErrorAction SilentlyContinue) }

    # Order matters: error signals take precedence over launch signal.
    if ($out -match "fatal error has been detected by the Java Runtime") {
        $verdict = 3
        $verdictReason = "JVM crash (fatal error in JRE)"
        break
    }
    if ($out -match "Error occurred during initialization of VM") {
        $verdict = 1
        $verdictReason = "JVM init error -- classfile cipher output garbled"
        break
    }

    if (-not $sawLaunchMC -and $out -match "Launching Minecraft") {
        $sawLaunchMC = $true
        $launchMCAt = Get-Date
    }

    if ($sawLaunchMC) {
        $elapsed = ((Get-Date) - $launchMCAt).TotalSeconds
        if ($elapsed -ge $PostInitWaitSec) {
            $verdict = 0
            $verdictReason = "JVM created and 'Launching Minecraft' stable for $PostInitWaitSec sec"
            break
        }
    }

    if ($proc.HasExited) {
        if (-not $sawLaunchMC) {
            $verdict = 2
            $verdictReason = "launcher exited silently before 'Launching Minecraft' (LoadLibrary or DllMain failure?)"
        } else {
            $verdict = 0
            $verdictReason = "launcher exited after 'Launching Minecraft' (success)"
        }
        break
    }

    Start-Sleep -Milliseconds 400
}

# Final capture
$finalOut = ""
if (Test-Path $tmpOut) { $finalOut += (Get-Content $tmpOut -Raw -ErrorAction SilentlyContinue) }
if (Test-Path $tmpErr) { $finalOut += "`n[stderr] " + (Get-Content $tmpErr -Raw -ErrorAction SilentlyContinue) }

Kill-LauncherTree
Start-Sleep -Milliseconds 400
Kill-LauncherTree

# Check for new hs_err
if (Test-Path $gameDir) {
    foreach ($f in (Get-ChildItem $gameDir -Filter "hs_err_pid*.log" -ErrorAction SilentlyContinue)) {
        if (-not $existingErrs.ContainsKey($f.FullName) -or $f.LastWriteTime -gt $existingErrs[$f.FullName]) {
            if ($verdict -eq 0) {
                $verdict = 3
                $verdictReason = "JVM crashed after init (new hs_err: $($f.Name))"
            }
        }
    }
}

$logBody = ("=== verdict: {0} ({1}) ===`n" -f $verdict, $verdictReason) + $finalOut
Set-Content -Path $LogPath -Value $logBody -Encoding UTF8

Remove-Item $tmpOut -ErrorAction SilentlyContinue
Remove-Item $tmpErr -ErrorAction SilentlyContinue

Write-Output "VERDICT=$verdict REASON=$verdictReason"
exit $verdict

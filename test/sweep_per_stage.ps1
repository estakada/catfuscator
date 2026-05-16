# Run the per-stage TAKOPI cipher test through N obfuscation seeds.
# Reports per-stage PASS/FAIL counts and, on the first failure of each stage,
# saves both a passing and the failing .obf.exe pair for later disasm-diff.

param(
    [int]$Seeds = 30
)

Set-Location $PSScriptRoot

$catfuscator = "c:\protection\catfuscator\Catfuscator\x64\Release\Catfuscator-con.exe"
$exe         = ".\test_takopi_cipher.exe"
$obfExe      = ".\test_takopi_cipher.obf.exe"

if (-not (Test-Path $exe)) {
    Write-Error "Compile test_takopi_cipher.exe first"
    exit 9
}

# Per-stage stats
$stats   = @{}
$saved   = @{}    # stage -> @{ pass=$path; fail=$path } (first occurrences)
for ($s = 1; $s -le 12; $s++) {
    $stats[$s] = @{ Pass = 0; Fail = 0; Crash = 0; ExpectMismatch = 0 }
    $saved[$s] = @{ Pass = $null; Fail = $null }
}

Write-Output "Sweeping $Seeds seeds across stages 1..12..."

for ($seed = 1; $seed -le $Seeds; $seed++) {
    & $catfuscator $exe --markers 2>&1 | Out-Null
    if (-not (Test-Path $obfExe)) { continue }
    $obfHash = (Get-FileHash $obfExe).Hash.Substring(0, 12)

    for ($stage = 1; $stage -le 12; $stage++) {
        $proc = Start-Process -FilePath $obfExe -ArgumentList "$stage" -PassThru -NoNewWindow -Wait `
                              -RedirectStandardOutput "out.tmp" -RedirectStandardError "err.tmp"
        $ec = $proc.ExitCode

        if ($ec -eq 0) {
            $stats[$stage].Pass++
            if (-not $saved[$stage].Pass) {
                $savePath = ".\diag\stage${stage}_PASS_seed${seed}_${obfHash}.obf.exe"
                New-Item -ItemType Directory -Path .\diag -Force | Out-Null
                Copy-Item $obfExe $savePath -Force
                $saved[$stage].Pass = $savePath
            }
        } elseif ($ec -eq $stage) {
            $stats[$stage].ExpectMismatch++
            if (-not $saved[$stage].Fail) {
                $savePath = ".\diag\stage${stage}_MISMATCH_seed${seed}_${obfHash}.obf.exe"
                New-Item -ItemType Directory -Path .\diag -Force | Out-Null
                Copy-Item $obfExe $savePath -Force
                $saved[$stage].Fail = $savePath
            }
        } else {
            # Crash (0xC0000005, 0xC000001D, ...) or other failure
            $stats[$stage].Crash++
            $stats[$stage].Fail++
            if (-not $saved[$stage].Fail) {
                $savePath = ".\diag\stage${stage}_CRASH_seed${seed}_ec$($ec.ToString('X8'))_${obfHash}.obf.exe"
                New-Item -ItemType Directory -Path .\diag -Force | Out-Null
                Copy-Item $obfExe $savePath -Force
                $saved[$stage].Fail = $savePath
            }
        }
    }

    # Tiny sleep so Catfuscator's srand(time(NULL)) actually picks a new seed.
    Start-Sleep -Milliseconds 1100
}

Write-Output ""
Write-Output "=== Per-stage results ==="
for ($s = 1; $s -le 12; $s++) {
    $st = $stats[$s]
    $total = $st.Pass + $st.Fail + $st.ExpectMismatch
    $rate  = if ($total -gt 0) { ($st.Pass / $total) * 100 } else { 0 }
    Write-Output ("stage{0}:  PASS={1,3}  CRASH={2,3}  WRONG_RESULT={3,3}    pass_rate={4,5:F1}%" -f $s, $st.Pass, $st.Crash, $st.ExpectMismatch, $rate)
}

Write-Output ""
Write-Output "=== Saved diagnostic pairs ==="
for ($s = 1; $s -le 12; $s++) {
    if ($saved[$s].Pass)  { Write-Output ("stage{0} PASS sample: {1}" -f $s, $saved[$s].Pass) }
    if ($saved[$s].Fail)  { Write-Output ("stage{0} FAIL sample: {1}" -f $s, $saved[$s].Fail) }
}

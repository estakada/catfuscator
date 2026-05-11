$ErrorActionPreference = "Continue"

$vcredist = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
$Catfuscator = "C:\protection\Catfuscator\Catfuscator\x64\Release\Catfuscator-con.exe"
$workdir = "C:\protection\Catfuscator"
$objdir = "C:\protection\Catfuscator\test"

$tests = @(
    'test_vm_basic','test_vm_branch','test_vm_loop','test_vm_nested_branch',
    'test_vm_bitops','test_vm_memory','test_vm_switch','test_vm_call',
    'test_vm_mul_div','test_vm_stack','test_vm_movzx_lea','test_vm_float',
    'test_vm_string','test_vm_mixed64','test_vm_stress','test_vm_setcc_cmov',
    'test_vm_ptr_arith','test_vm_mixed_sizes','test_vm_no_branch',
    'test_vm_empty_region','test_vm_big_switch','test_vm_big_func',
    'test_vm_deep_recursion','test_vm_extreme_values','test_vm_multi_region',
    'test_vm_cff2','test_vm_cff','test_vm_ultra_stress','test_vm_ultra_big'
)

$PASS = 0
$FAIL = 0
$TOTAL = 0

foreach ($t in $tests) {
    $TOTAL++
    Write-Host ""
    Write-Host "=== $t ==="

    $src = "$objdir\$t.cpp"
    $exe = "$objdir\$t.exe"
    $obf = "$objdir\$t.obf.exe"

    if (-not (Test-Path $src)) {
        Write-Host "[SKIP ] $t - no source"
        continue
    }

    # Remove stale objs/exes
    $base = "$objdir\$t"
    Remove-Item "$base.obj" -ErrorAction SilentlyContinue
    Remove-Item "$exe" -ErrorAction SilentlyContinue

    $batch = @"
call "$vcredist" >nul 2>&1
cd /d $workdir
cl /O2 /Zi /EHsc $src $objdir\Catfuscator_markers.obj /Fo:$base.obj /Fe:$exe /link /DEBUG
echo COMPILE_RET:%ERRORLEVEL%
"@

    $batfile = "$workdir\_runtest_compile.bat"
    Set-Content -Path $batfile -Value $batch -Encoding ASCII

    $null = & cmd /c $batfile 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[COMPILE FAIL] $t"
        $FAIL++
        continue
    }

    $run_orig = & cmd /c "cd /d $workdir && $exe" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[UNOBF FAIL] $t"
        $FAIL++
        continue
    }

    $obf_out = & cmd /c "cd /d $workdir && `"$Catfuscator`" `"$workdir\test\$t.exe`" `"$workdir\test\$t.obf.exe`"" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[OBFUSCATE FAIL] $t"
        Write-Host "    $obf_out"
        $FAIL++
        continue
    }

    $run_obf = & cmd /c "cd /d $workdir && $obf" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[RUN FAIL] $t"
        Write-Host "    $run_obf"
        $FAIL++
        continue
    }

    Write-Host "[PASS] $t"
    $PASS++
}

Write-Host ""
Write-Host "========================================"
Write-Host "Results: $PASS/$TOTAL passed, $FAIL failed"
Write-Host "========================================"

if ($FAIL -ne 0) {
    exit 1
}
exit 0
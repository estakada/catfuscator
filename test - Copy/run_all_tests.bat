@echo off
setlocal enabledelayedexpansion

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

set Catfuscator=Catfuscator\x64\Release\Catfuscator-con.exe
set MARKERS=test\Catfuscator_markers.obj
set PASS=0
set FAIL=0
set TOTAL=0

for %%T in (
    test_vm_basic
    test_vm_branch
    test_vm_loop
    test_vm_nested_branch
    test_vm_bitops
    test_vm_memory
    test_vm_switch
    test_vm_call
    test_vm_mul_div
    test_vm_stack
    test_vm_movzx_lea
    test_vm_float
    test_vm_string
    test_vm_mixed64
    test_vm_stress
    test_vm_setcc_cmov
    test_vm_ptr_arith
    test_vm_mixed_sizes
    test_vm_no_branch
    test_vm_empty_region
    test_vm_big_switch
    test_vm_big_func
    test_vm_deep_recursion
    test_vm_extreme_values
    test_vm_multi_region
    test_vm_cff2
    test_vm_cff
    test_vm_ultra_stress
    test_vm_ultra_big
) do (
    set /a TOTAL+=1
    echo.
    echo === %%T ===

    REM Compile
    cl /O2 /Zi /EHsc test\%%T.cpp %MARKERS% /Fe:test\%%T.exe /link /DEBUG >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (
        echo [COMPILE FAIL] %%T
        set /a FAIL+=1
    ) else (
        REM Run unobfuscated first
        test\%%T.exe >nul 2>&1
        if !ERRORLEVEL! NEQ 0 (
            echo [UNOBF FAIL] %%T
            set /a FAIL+=1
        ) else (
            REM Obfuscate
            %Catfuscator% test\%%T.exe test\%%T.obf.exe >nul 2>&1
            if !ERRORLEVEL! NEQ 0 (
                echo [OBFUSCATE FAIL] %%T
                set /a FAIL+=1
            ) else (
                REM Run obfuscated
                test\%%T.obf.exe >nul 2>&1
                if !ERRORLEVEL! NEQ 0 (
                    echo [RUN FAIL] %%T
                    set /a FAIL+=1
                ) else (
                    echo [PASS] %%T
                    set /a PASS+=1
                )
            )
        )
    )
)

echo.
echo ========================================
echo Results: !PASS!/!TOTAL! passed, !FAIL! failed
echo ========================================

if !FAIL! NEQ 0 exit /b 1
exit /b 0

@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d C:\protection\Catfuscator

set MARKERS=test\Catfuscator_markers.obj

if not exist %MARKERS% (
    echo Building markers...
    ml64 /c /nologo sdk\Catfuscator_markers.asm /Fo%MARKERS%
)

echo.
echo === Building and obfuscating all tests ===
echo.

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
    echo [%%T]
    echo   Compile...
    cl /O2 /Zi /EHsc test\%%T.cpp %MARKERS% /Fe:test\%%T.exe /link /DEBUG >nul 2>&1

    echo   Run original...
    test\%%T.exe >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (
        echo   ERROR: Original failed
    ) else (
        echo   Obfuscate...
        Catfuscator\build_tmp\Catfuscator-con.exe test\%%T.exe >nul 2>&1
        if !ERRORLEVEL! NEQ 0 (
            echo   ERROR: Obfuscate failed
        ) else (
            echo   Run obfuscated...
            test\%%T.obf.exe >nul 2>&1
            if !ERRORLEVEL! NEQ 0 (
                echo   ERROR: Obfuscated failed
            ) else (
                echo   OK
            )
        )
    )
    echo.
)

echo Done
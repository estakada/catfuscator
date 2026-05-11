@echo off
setlocal enabledelayedexpansion

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

set Catfuscator=Catfuscator\x64\Release\Catfuscator-con.exe
set MARKERS=test\Catfuscator_markers.obj
set PASS=0
set FAIL=0

echo === Repeat obfuscation stability test (VM stress) ===
echo.

REM Compile once
cl /O2 /Zi /EHsc test\test_vm_stress.cpp %MARKERS% /Fe:test\test_vm_stress.exe /link /DEBUG >nul 2>&1

REM Output is always test\test_vm_stress.obf.exe
for /L %%I in (1,1,10) do (
    del test\test_vm_stress.obf.exe >nul 2>&1
    %Catfuscator% test\test_vm_stress.exe >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (
        echo [OBFUSCATE FAIL] run %%I
        set /a FAIL+=1
    ) else (
        test\test_vm_stress.obf.exe >nul 2>&1
        if !ERRORLEVEL! NEQ 0 (
            echo [RUN FAIL] run %%I
            set /a FAIL+=1
        ) else (
            echo [PASS] run %%I
            set /a PASS+=1
        )
    )
)

echo.
echo VM stress repeat: !PASS!/10 passed, !FAIL! failed

REM Ultra repeat test
echo.
echo === Repeat obfuscation stability test (Ultra stress) ===
cl /O2 /Zi /EHsc test\test_vm_ultra_stress.cpp %MARKERS% /Fe:test\test_vm_ultra_stress.exe /link /DEBUG >nul 2>&1

set PASS2=0
set FAIL2=0
for /L %%I in (1,1,10) do (
    del test\test_vm_ultra_stress.obf.exe >nul 2>&1
    %Catfuscator% test\test_vm_ultra_stress.exe >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (
        echo [OBFUSCATE FAIL] ultra run %%I
        set /a FAIL2+=1
    ) else (
        test\test_vm_ultra_stress.obf.exe >nul 2>&1
        if !ERRORLEVEL! NEQ 0 (
            echo [RUN FAIL] ultra run %%I
            set /a FAIL2+=1
        ) else (
            echo [PASS] ultra run %%I
            set /a PASS2+=1
        )
    )
)

echo.
echo Ultra stress repeat: !PASS2!/10 passed, !FAIL2! failed

REM Real crackme repeat
echo.
echo === Repeat obfuscation stability test (Real crackme) ===

set PASS3=0
set FAIL3=0
for /L %%I in (1,1,5) do (
    del test\test_real_crackme.obf.exe >nul 2>&1
    %Catfuscator% test\test_real_crackme.exe >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (
        echo [OBFUSCATE FAIL] crackme run %%I
        set /a FAIL3+=1
    ) else (
        test\test_real_crackme.obf.exe >nul 2>&1
        if !ERRORLEVEL! NEQ 0 (
            echo [RUN FAIL] crackme run %%I
            set /a FAIL3+=1
        ) else (
            echo [PASS] crackme run %%I
            set /a PASS3+=1
        )
    )
)

echo.
echo Real crackme repeat: !PASS3!/5 passed, !FAIL3! failed

echo.
echo ========================================
set /a TOTAL_PASS=!PASS!+!PASS2!+!PASS3!
set /a TOTAL_FAIL=!FAIL!+!FAIL2!+!FAIL3!
set /a TOTAL=!TOTAL_PASS!+!TOTAL_FAIL!
echo Total: !TOTAL_PASS!/!TOTAL! passed, !TOTAL_FAIL! failed
echo ========================================

if !TOTAL_FAIL! NEQ 0 exit /b 1
exit /b 0

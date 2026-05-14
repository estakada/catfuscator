@echo off
setlocal

REM ---------------------------------------------------------------------------
REM Regression tester for Catfuscator MUTATE on TAKOPI-like cipher.
REM
REM Workflow:
REM   1. Compile test_takopi_cipher.exe (unobfuscated)
REM   2. Run it with --print to discover expected outputs
REM   3. Patch those outputs into the source
REM   4. Recompile
REM   5. Run Catfuscator with --markers
REM   6. Execute the obfuscated binary and check exit code
REM
REM Usage:
REM   run_takopi_test.bat             - full regression
REM   run_takopi_test.bat 8           - run 8 randomized obfuscation seeds
REM ---------------------------------------------------------------------------

set N_SEEDS=%1
if "%N_SEEDS%"=="" set N_SEEDS=1

cd /d "%~dp0"

call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul

REM Step 1 + 2: build unobf and capture expected outputs
echo [1/4] Compiling unobf...
cl /nologo /O2 /MT /EHsc /std:c++17 ^
    /Fe:test_takopi_cipher.exe ^
    test_takopi_cipher.cpp Catfuscator_markers.obj ^
    /link /DEBUG:FULL >nul
if errorlevel 1 (
    echo cl FAILED
    exit /b 9
)

echo [2/4] Capturing expected outputs...
test_takopi_cipher.exe --print > expected.txt
if errorlevel 1 (
    echo Unobf binary returned non-zero on --print; bug in test source
    type expected.txt
    exit /b 9
)
echo expected outputs:
type expected.txt

REM Parse out hex values, sed expected[] table in the source.
REM Lines look like: "stage1: 0x..."
powershell -NoProfile -Command ^
    "$lines = Get-Content expected.txt;" ^
    "$hex = $lines | %% { ($_ -split ' ')[1] };" ^
    "$src = Get-Content test_takopi_cipher.cpp -Raw;" ^
    "$replacement = \"    const uint64_t expected[5] = {`n        $($hex[0]),`n        $($hex[1]),`n        $($hex[2]),`n        $($hex[3]),`n        $($hex[4]),`n    };\";" ^
    "$pattern = '(?s)    const uint64_t expected\[5\] = \{.*?\};';" ^
    "$src2 = [regex]::Replace($src, $pattern, $replacement);" ^
    "Set-Content -Path test_takopi_cipher.cpp -Value $src2 -NoNewline"

echo [3/4] Recompiling with expected values baked in...
cl /nologo /O2 /MT /EHsc /std:c++17 ^
    /Fe:test_takopi_cipher.exe ^
    test_takopi_cipher.cpp Catfuscator_markers.obj ^
    /link /DEBUG:FULL >nul
if errorlevel 1 (
    echo cl FAILED (after expected update)
    exit /b 9
)

REM Sanity: unobf should PASS now.
test_takopi_cipher.exe
if errorlevel 1 (
    echo ASSERT FAILED: unobf binary doesn't pass its own expected values
    exit /b 9
)
echo unobf: PASS

REM Step 4: obfuscate + run, N times
echo [4/4] Running %N_SEEDS% obfuscation seed(s)...
set PASS=0
set FAIL=0
for /l %%i in (1,1,%N_SEEDS%) do (
    Catfuscator-con.exe test_takopi_cipher.exe --markers >nul 2>&1
    test_takopi_cipher.obf.exe
    if errorlevel 1 (
        set /a FAIL=FAIL+1
        echo   seed %%i: FAIL (exit !errorlevel!^)
    ) else (
        set /a PASS=PASS+1
        echo   seed %%i: PASS
    )
)

echo.
echo === Summary ===
echo Passed: %PASS%
echo Failed: %FAIL%
if "%FAIL%"=="0" (
    echo OVERALL: ALL OBFUSCATION SEEDS PASS
    exit /b 0
) else (
    exit /b 1
)

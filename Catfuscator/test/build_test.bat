@echo off
REM Build test binary with markers
REM Run from VS Developer Command Prompt or after calling vcvarsall.bat

call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

echo [1/2] Assembling markers...
ml64 /c /nologo "%~dp0..\sdk\Catfuscator_markers.asm" /Fo"%~dp0Catfuscator_markers.obj"
if errorlevel 1 (echo FAILED: ml64 & exit /b 1)

echo [2/2] Compiling test binary...
cl /nologo /O2 /MT /EHsc /Fe:"%~dp0test_markers.exe" "%~dp0test_markers.cpp" "%~dp0Catfuscator_markers.obj" /link /DEBUG:NONE
if errorlevel 1 (echo FAILED: cl & exit /b 1)

echo.
echo Build successful: test_markers.exe
echo.
echo Run:  Catfuscator-con.exe test_markers.exe --markers

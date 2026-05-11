@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d C:\protection\Catfuscator

echo Building Catfuscator...
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe" Catfuscator.sln /p:Configuration=Release /p:Platform=x64 /t:Catfuscator-con:Rebuild /v:minimal

echo.
echo Done. Binary in Catfuscator\build_tmp\
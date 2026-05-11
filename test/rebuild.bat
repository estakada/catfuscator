@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d C:\protection\Catfuscator\test

echo Building test_vm_branch...
cl /O2 /Zi /EHsc test_vm_branch.cpp Catfuscator_markers.obj /Fe:test_vm_branch.exe /link /DEBUG

echo Building test_vm_loop...
cl /O2 /Zi /EHsc test_vm_loop.cpp Catfuscator_markers.obj /Fe:test_vm_loop.exe /link /DEBUG

echo Building test_vm_bitops...
cl /O2 /Zi /EHsc test_vm_bitops.cpp Catfuscator_markers.obj /Fe:test_vm_bitops.exe /link /DEBUG

echo Done
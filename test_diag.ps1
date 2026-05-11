$ErrorActionPreference = "Continue"
$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1"
& $vsPath -Arch amd64 -SkipActivate | Out-Null

$src = "C:\protection\catfuscator\test\test_vm_basic.cpp"
$objdir = "C:\protection\catfuscator\test\objs"
$base = "$objdir\test_vm_basic"
$markerobj = "$objdir\Catfuscator_markers.obj"
$exe_orig = "$objdir\test_vm_basic_base.exe"
$exe_obf = "$objdir\test_vm_basic_obf.exe"

if (!(Test-Path $objdir)) {
    New-Item -ItemType Directory -Path $objdir | Out-Null
}

# Remove stale objs
Remove-Item "$base*.obj" -Force -EA SilentlyContinue

# Compile original
Write-Host "=== Compiling original ==="
$cl_exe = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.34131\bin\HostX64\x64\cl.exe"
$batfile = "$env:TEMP\cl_compile_$PID.bat"
$bat_content = @"
@echo off
call "$vsPath" -Arch amd64 -SkipActivate > nul 2>&1
"$cl_exe" /O2 /Zi /EHsc "$src" "$markerobj" /Fo"$objdir\test_vm_basic_base.obj" /Fe"$exe_orig" /link /DEBUG
"@
[System.IO.File]::WriteAllText($batfile, $bat_content)
cmd /c $batfile
Remove-Item $batfile -Force

Write-Host "=== Running original ==="
& $exe_orig
Write-Host "Original exit: $LASTEXITCODE"

# Run obfuscator
Write-Host "=== Running Catfuscator ==="
$cat_exe = "C:\protection\catfuscator\Catfuscator\build_tmp\Catfuscator-con.exe"
& $cat_exe $exe_orig 2>&1
Write-Host "Catfuscator exit: $LASTEXITCODE"

# Find the .obf output
$obf_files = Get-ChildItem "$objdir\*.obf.exe" -EA SilentlyContinue
if ($obf_files) {
    $obf_exe = $obf_files[0].FullName
    Write-Host "=== Running obfuscated ==="
    Write-Host "Running: $obf_exe"
    & $obf_exe
    Write-Host "Obfuscated exit: $LASTEXITCODE"
} else {
    Write-Host "No .obf.exe found!"
    Get-ChildItem "$objdir\*" | Format-Table Name, Length
}

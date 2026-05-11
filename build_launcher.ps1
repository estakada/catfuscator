$vcredist = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
$workdir = "C:\aal\new\min-launcher\launcher-cli"
$builddir = "C:\aal\new\min-launcher\launcher-cli\build"

Write-Host "Setting up vcvars..."
& $vcredist > $null 2>&1

Write-Host "Configuring CMake (clean build dir)..."
Set-Location $workdir

if (Test-Path $builddir) {
    Write-Host "Removing old build dir..."
    Remove-Item $builddir -Recurse -Force
}
New-Item -ItemType Directory -Path $builddir | Out-Null

Write-Host "Running cmake configure..."
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=RelWithDebInfo 2>&1

Write-Host ""
Write-Host "Building launcher-cli..."
$build_result = cmake --build build --config RelWithDebInfo 2>&1
Write-Host $build_result

Write-Host ""
$exit = $LASTEXITCODE
Write-Host "Exit code: $exit"

$exe = "$builddir\RelWithDebInfo\LauncherCLI.exe"
if (Test-Path $exe) {
    Write-Host "Success! Output: $exe"
} else {
    Write-Host "Build failed - no exe found"
    exit 1
}

if ($exit -ne 0) {
    exit $exit
}
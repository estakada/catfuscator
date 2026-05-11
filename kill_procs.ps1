$procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.MainModule.FileName -like "*test_vm_branch*" }
if ($procs) { $procs | Stop-Process -Force }
$procs2 = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.MainModule.FileName -like "*catfuscator*" }
if ($procs2) { $procs2 | Stop-Process -Force }
Write-Host "Done. Processes killed: test=$($procs.Count), catfuscator=$($procs2.Count)"
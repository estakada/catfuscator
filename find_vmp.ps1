Get-ChildItem "C:\aal\new\min-launcher" -Include "*.cpp","*.h" -Recurse |
    Where-Object { $_.Name -notlike "cli_compat.h" } |
    Select-String -Pattern "VMProtect" |
    ForEach-Object {
        Write-Host "$($_.Filename):$($_.LineNumber): $($_.Line.Trim())"
    }
Get-ChildItem "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC" -Directory | ForEach-Object {
    Get-ChildItem $_.FullName -Filter "ml64.exe" -Recurse -ErrorAction SilentlyContinue
} | Select-Object -First 1 -ExpandProperty FullName
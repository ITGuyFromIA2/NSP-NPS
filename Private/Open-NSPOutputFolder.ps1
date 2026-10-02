function Open-NSPOutputFolder {
    # Opens Explorer on the folder a hand-back file was written to, so the tech can copy it off the
    # server. The folder is Administrators-only, so Explorer (not elevated) may ask for access - the
    # tech accepts that prompt. Skipped without explorer.exe (Server Core), when nothing was written
    # (dry run), and with NSP_NO_EXPLORER=1 (the test runners set it).
    param([string]$Path)
    if (-not $Path -or $env:NSP_NO_EXPLORER -eq '1') { return }
    $folder = if (Test-Path -LiteralPath $Path -PathType Leaf) { Split-Path -Parent $Path } else { $Path }
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) { return }
    if (-not (Get-Command explorer.exe -ErrorAction SilentlyContinue)) { return }
    Start-Process -FilePath explorer.exe -ArgumentList "`"$folder`""
}

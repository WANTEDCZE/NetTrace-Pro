$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
Write-Host '=== NetTrace Pro 0.8.0 - Windows build ===' -ForegroundColor Cyan
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'Python 3.10+ was not found. Install Python and enable Add Python to PATH.' }
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if (-not (Test-Path '.\speedtest.exe')) { Write-Warning 'speedtest.exe is missing. The application will build, but Ookla Speedtest will be unavailable.' }
$pyArgs = @('-m','PyInstaller','--noconfirm','--clean','--onefile','--windowed','--name','NetTracePro')
if (Test-Path '.\speedtest.exe') { $pyArgs += @('--add-binary','speedtest.exe;.') }
$pyArgs += 'main.py'
python @pyArgs
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
Write-Host "Build complete: $PSScriptRoot\dist\NetTracePro.exe" -ForegroundColor Green

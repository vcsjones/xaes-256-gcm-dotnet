# PowerShell < 7 does not handle ZIP files correctly.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script requires PowerShell 7 or higher."
}

$tmpDir = $env:TEMP
$scratchDir = Join-Path -Path $tmpDir -ChildPath ([System.Guid]::NewGuid().ToString('N'))
$pkgPath = $args[0]

if (!$pkgPath) {
    throw 'Please specify a package path.'
}

$winKitDir = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' 'KitsRoot10'

if (!$winKitDir -or !(Test-Path -Path $winKitDir)) {
    throw 'Windows SDK path is not found.'
}

$sdkVersion = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' | Sort-Object Name -Descending | Select-Object -ExpandProperty PSChildName -First 1
$sdkPath = Join-Path -Path $winKitDir -ChildPath 'bin'
$sdkPath = Join-Path -Path $sdkPath -ChildPath $sdkVersion

$architecture = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
$archDirName = switch ($architecture) {
    'ARM64' { 'arm64' }
    'x86' { 'x86' }
    'AMD64' { 'x64' }
    Default { throw 'Unknown architecture' }
}

$sdkBinPath = Join-Path -Path $sdkPath -ChildPath $archDirName
Expand-Archive -Path $pkgPath -DestinationPath $scratchDir


& "$sdkBinPath\signtool.exe" sign /d "Xaes256Gcm" /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/xaes-256-gcm-dotnet" "$scratchDir\lib\net8.0\Xaes256Gcm.dll"
& "$sdkBinPath\signtool.exe" sign /d "Xaes256Gcm" /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/xaes-256-gcm-dotnet" "$scratchDir\lib\net10.0\Xaes256Gcm.dll"
& "$sdkBinPath\signtool.exe" sign /d "Xaes256Gcm" /sha1 73f0844a95e35441a676cd6be1e79a3cd51d00b4 /fd SHA384 /td SHA384 /tr "http://timestamp.digicert.com" /du "https://github.com/vcsjones/xaes-256-gcm-dotnet" "$scratchDir\lib\net462\Xaes256Gcm.dll"

$pkgPathDir = Split-Path -Parent $pkgPath
$pkgPathFile = Split-Path -Leaf $pkgPath
$pkgPathFileSigned = $pkgPathFile -Replace '_unsigned(?=\.[^\\.]+$)', ''
$outputPath = Join-Path $pkgPathDir $pkgPathFileSigned

Remove-Item -Path $outputPath -ErrorAction SilentlyContinue
Compress-Archive -Path "$scratchDir\*" -DestinationPath $outputPath

dotnet nuget sign --certificate-fingerprint 68821304869e065c24e0684eb43bf974e124642f3437f2ff494a93bb371d029a --hash-algorithm SHA384 --timestamper "http://timestamp.digicert.com" --overwrite "$outputPath"

Remove-Item -Path $scratchDir -Recurse -Force -ErrorAction SilentlyContinue
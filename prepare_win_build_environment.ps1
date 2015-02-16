#powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1 [openssl] [libxml]
param(
	[string]$target = "C:\build",
	[string]$msbuild = "C:\Program Files (x86)\MSBuild\12.0\Bin\MSBuild.exe",
	[string]$7zip = "C:\Program Files\7-Zip\7z.exe",
	[string]$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat", #$env:VCINSTALLDIR
	[string]$opensslver = "openssl-1.0.1m",
	[string]$libxml2ver = "libxml2-2.9.2",
	[switch]$openssl = $false,
	[switch]$libxml2 = $false
)

$libdigidoc = split-path -parent $MyInvocation.MyCommand.Definition
if(!(Test-Path -Path $target )){
    New-Item -ItemType directory -Path $target
}
$shell = new-object -com shell.application
$client = new-object System.Net.WebClient

function openssl() {
	$client.DownloadFile("https://www.openssl.org/source/$opensslver.tar.gz", "$libdigidoc\$opensslver.tar.gz")
	& $7zip "x" "$opensslver.tar.gz"
	& $7zip "x" "$opensslver.tar"
	Push-Location -Path $opensslver
	& "perl" "Configure" "VC-WIN32" "no-asm"
	& "ms\do_ms"
	& $vcvars "x86" "&&" "nmake" "-f" "ms\ntdll.mak" "install" "INSTALLTOP=\OpenSSL-Win32" "OPENSSLDIR=\OpenSSL-Win32\bin"
	Pop-Location
	Remove-Item $opensslver -Force -Recurse

	& $7zip "x" "$opensslver.tar"
	Push-Location -Path $opensslver
	& $vcvars "x86_amd64" "&&" perl Configure VC-WIN64A no-asm
	& $vcvars "x86_amd64" "&&" ms\do_win64a
	& $vcvars "x86_amd64" "&&" "nmake" "-f" "ms\ntdll.mak" "install" "INSTALLTOP=\OpenSSL-Win64" "OPENSSLDIR=\OpenSSL-Win64\bin"
	Pop-Location
	Remove-Item $opensslver -Force -Recurse
	Remove-Item "$opensslver.tar"
}

function libxml2() {
	$client.DownloadFile("ftp://xmlsoft.org/libxml2/$libxml2ver.tar.gz", "$libdigidoc\$libxml2ver.tar.gz")
	& $7zip "x" "$libxml2ver.tar.gz"
	& $7zip "x" "$libxml2ver.tar"
	foreach($item in $shell.NameSpace("$libdigidoc\$libxml2ver-patches.zip").items()) {
		$shell.Namespace($libdigidoc).CopyHere($item,0x14)
	}

	Push-Location -Path "$libxml2ver\win32"
	& "cscript" "configure.js" "iconv=no" "iso8859x=yes" "prefix=$target\libxml\x86"
	& $vcvars "x86" "&&" "nmake" "-f" "Makefile.msvc" "install"
	Pop-Location
	Remove-Item $libxml2ver -Force -Recurse
	& $7zip "x" "$libxml2ver.tar"
	foreach($item in $shell.NameSpace("$libdigidoc\$libxml2ver-patches.zip").items()) {
		$shell.Namespace($libdigidoc).CopyHere($item,0x14)
	}

	Push-Location -Path "$libxml2ver\win32"
	& "cscript" "configure.js" "iconv=no" "iso8859x=yes" "prefix=$target\libxml\x64"
	& $vcvars "x86_amd64" "&&" "nmake" "-f" "Makefile.msvc" "install"
	Pop-Location
	Remove-Item $libxml2ver -Force -Recurse
	Remove-Item "$libxml2ver.tar" -Force -Recurse
}

if($openssl) {
	openssl
}
if($libxml2) {
	libxml2
}
if(!$openssl -and !$libxml2) {
	openssl
	libxml2
}

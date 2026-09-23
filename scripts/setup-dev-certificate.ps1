param(
	[Parameter(Mandatory = $true)]
	[string]$Password
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$certificateDirectory = Join-Path $repositoryRoot '.https'
$certificatePath = Join-Path $certificateDirectory 'jwtauth-dev.pfx'

New-Item -ItemType Directory -Path $certificateDirectory -Force | Out-Null
dotnet dev-certs https --export-path $certificatePath --password $Password --trust

if ($LASTEXITCODE -ne 0) {
	throw 'Failed to create and trust the ASP.NET Core development certificate.'
}

Write-Host "Trusted certificate exported to $certificatePath"
Write-Host 'Use the same password as HTTPS_CERT_PASSWORD in .env.'

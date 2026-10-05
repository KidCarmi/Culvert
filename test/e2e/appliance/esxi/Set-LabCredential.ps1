[CmdletBinding()]
param([string]$EndpointHost = '192.168.1.78')
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT' -or $EndpointHost -notmatch '^[A-Za-z0-9.-]+$') {
    throw 'A Windows account and a plain endpoint hostname are required.'
}
$credentialDirectory = Join-Path $env:LOCALAPPDATA 'CulvertEsxiLab'
$null = New-Item -ItemType Directory -Path $credentialDirectory -Force
$accountSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $credentialDirectory /inheritance:r /grant:r "*${accountSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the credential directory.' }
$credentialPath = Join-Path $credentialDirectory "$EndpointHost.credential.xml"
$esxiCredential = Get-Credential -Message "ESXi lab credential for $EndpointHost (stored with Windows user encryption)"
if (-not $esxiCredential) { throw 'Credential entry cancelled.' }
try {
    $esxiCredential | Export-Clixml -LiteralPath $credentialPath
} finally {
    Remove-Variable esxiCredential -ErrorAction SilentlyContinue
}
Write-Host 'Credential saved for this Windows user. No password was printed.'

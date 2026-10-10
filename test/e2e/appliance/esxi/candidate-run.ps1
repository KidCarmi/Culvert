param(
    [Parameter(Mandatory=$true)][string]$Scope,
    [Parameter(Mandatory=$true)][string]$Bind,
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)][string]$ConsoleFont,
    [switch]$ResumePostOS,
    [switch]$ContinueUndispatched
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../../..')).Path
$scopePath = (Resolve-Path -LiteralPath $Scope).Path
$configuration = Get-Content -LiteralPath $scopePath -Raw | ConvertFrom-Json
if (-not $configuration.controller_manifest) { throw 'Controller freeze manifest required' }
& $Python (Join-Path $PSScriptRoot 'controller-freeze.py') verify --manifest $configuration.controller_manifest
if ($LASTEXITCODE -ne 0) { throw 'Controller freeze verification failed' }
$freeze = Get-Content -LiteralPath $configuration.controller_manifest -Raw | ConvertFrom-Json
$owned = Get-Content -LiteralPath (Join-Path $configuration.run_dir 'owned.json') -Raw | ConvertFrom-Json
$enrollment = Get-Content -LiteralPath (Join-Path $configuration.run_dir 'secrets/operator-enrollment-attempt.json') -Raw | ConvertFrom-Json
if ($enrollment.status -ne 'pass' -or $enrollment.uuid -ne $owned.uuid) { throw 'Operator enrollment evidence missing' }
$adapterPath = (Join-Path $PSScriptRoot 'esxi-lab.py').Replace('\','/')
$guestAddress = & $Python -c 'import importlib.util,pathlib,sys; s=importlib.util.spec_from_file_location("lab",sys.argv[1]); m=importlib.util.module_from_spec(s);s.loader.exec_module(m); print(m.Lab(pathlib.Path(sys.argv[2])).guest_ip())' $adapterPath $scopePath
if ($LASTEXITCODE -ne 0 -or $guestAddress -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw 'Owned guest address unavailable' }
$env:ESXI_SHARED_LAB = (Join-Path $repoRoot 'test/e2e/appliance/lab/appliance-lab.sh').Replace('\','/')
$env:ESXI_SHARED_SHA256 = $freeze.files.'test/e2e/appliance/lab/appliance-lab.sh'
$env:ESXI_PYTHON = $Python.Replace('\','/')
$env:ESXI_ADAPTER = $adapterPath
$env:ESXI_SCOPE = $scopePath.Replace('\','/')
$env:ESXI_HOST_KEY_ALIAS = $owned.name
$env:ESXI_OPERATOR_ENROLLED = '1'
$env:ESXI_HOST_KEY_PINNED = '1'
$env:ESXI_EXTENDED_CAMPAIGN = '1'
$env:ESXI_ENGINE_SURFACE = if ($configuration.source_sha -in @('7c7b29ee3be40af6a0809c73ad04d4337303263d','91e05872dfe5f96c94ec725b8b2dc2b1002116ab','72c827b7f59f4e43ff2a813241be9029f58f23a9','bad788e54ffef2a2f8490ba27ebfe027a2a6eb11')) { '1' } else { '0' }
$env:ESXI_ENGINE_SOURCE = $configuration.source_sha
$env:ESXI_BIND = $Bind
if ($ContinueUndispatched) {
    if (-not $ResumePostOS) { throw 'Continuation requires the explicit post-OS resume' }
    $env:ESXI_CONTINUE_UNDISPATCHED = '1'
}
$env:LAB_DIR = $configuration.run_dir.Replace('\','/')
$env:LAB_HOST = $guestAddress
$env:LAB_SSH_PORT = '22'
$env:LAB_PROXY_PORT = '8080'
$env:LAB_UI_PORT = '9090'
$env:LAB_SSH_KEY = "$($env:LAB_DIR)/secrets/id_ed25519"
$privPath = (Join-Path $PSScriptRoot 'console-priv.py').Replace('\','/')
# The shared shell transport uses a word-list contract, so reject ambiguous paths.
foreach ($word in @($env:ESXI_PYTHON,$env:ESXI_SCOPE,$privPath,$Bind)) {
    if ($word -notmatch '^[A-Za-z0-9_./:\\-]+$') { throw 'Transport argument is not a safe word' }
}
$env:LAB_PRIV_CMD = "$($env:ESXI_PYTHON) $privPath --scope $($env:ESXI_SCOPE) --bind $Bind"
$env:LAB_UPDATE_DIR = "$($env:LAB_DIR)/secrets/signed-update"
$env:LAB_EXPECT_IMAGE_ID = $configuration.image_id
$fontPaths = @($ConsoleFont.Split([IO.Path]::PathSeparator))
if ($fontPaths.Count -lt 1 -or $fontPaths.Count -gt 2 -or @($fontPaths | Where-Object { -not $_ }).Count) {
    throw 'Provide one or two approved console font paths separated by the platform path separator'
}
$resolvedFonts = @($fontPaths | ForEach-Object { (Resolve-Path -LiteralPath $_).Path.Replace('\','/') })
# Validate both hashes before any console use. The decoder chooses one globally
# consistent exact font per capture and never repairs uncertain credentials.
& $Python -B -c 'import importlib.util,sys; s=importlib.util.spec_from_file_location("fonts",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); [m.font_table(p) for p in sys.argv[2:]]' (Join-Path $PSScriptRoot 'pixel-console.py') @resolvedFonts
if ($LASTEXITCODE -ne 0) { throw 'Approved console font verification failed' }
$env:CULVERT_ESXI_CONSOLE_FONT = $resolvedFonts -join [IO.Path]::PathSeparator
Set-Location -LiteralPath $repoRoot
$entrypoint = if ($ResumePostOS) { 'post-os-resume.sh' } else { 'access-aware-qualify.sh' }
& $configuration.bash (Join-Path $PSScriptRoot $entrypoint)
exit $LASTEXITCODE

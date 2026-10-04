# Run with Windows PowerShell 5.1 (powershell.exe), not PowerShell Core.
# Local-only OCR: no network, console capture, credential parsing, or stdout text.
# The caller must protect the source screenshot separately. Output is UTF-8 in a
# new file whose ACL grants access only to the current Windows user and SYSTEM.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ImagePath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [ValidateRange(1, 60)][int]$TimeoutSeconds = 20,
    [ValidateSet(1, 2)][int]$Scale = 1
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-RegularPath {
    param([string]$Path)
    $cursor = $Path
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'OCR paths must not contain reparse points.'
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}

function Wait-WinRT {
    param($Operation, [Type]$ResultType)
    $task = $script:AsTask.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
    $remaining = [int]($TimeoutSeconds * 1000 - $script:Timer.ElapsedMilliseconds)
    if ($remaining -le 0 -or -not $task.Wait($remaining)) {
        try { $Operation.Cancel() } catch { }
        throw 'Local OCR exceeded its time budget.'
    }
    return $task.Result
}

function Save-PrivateText {
    param([string]$Path, [string]$Text)
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    if ($bytes.Length -gt 65536) { throw 'OCR output exceeds 64 KiB.' }
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($Path)) ('.ocr-' + [guid]::NewGuid().ToString('N'))
    $file = $null
    try {
        $file = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $file.Dispose()
        $file = $null
        # Set the private ACL while the file is still empty, before any OCR text.
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner($user)
        foreach ($principal in @($user, $system)) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', 'Allow')
            [void]$acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $temporary -AclObject $acl
        $file = [IO.File]::Open($temporary, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $file.Write($bytes, 0, $bytes.Length)
        $file.Flush($true)
        $file.Dispose()
        $file = $null
        # File.Move refuses an existing destination; never overwrite prior evidence.
        [IO.File]::Move($temporary, $Path)
    } finally {
        if ($null -ne $file) { $file.Dispose() }
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

$stream = $null
$bitmap = $null
try {
    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'Use Windows PowerShell 5.1 (powershell.exe) for WinRT OCR.'
    }
    $source = [IO.Path]::GetFullPath($ImagePath)
    $destination = [IO.Path]::GetFullPath($OutputPath)
    Assert-RegularPath $source
    Assert-RegularPath ([IO.Path]::GetDirectoryName($destination))
    if (Test-Path -LiteralPath $destination) { throw 'OCR destination already exists.' }
    $inputFile = Get-Item -LiteralPath $source
    if ($inputFile.PSIsContainer -or $inputFile.Length -le 0 -or $inputFile.Length -gt 10MB) {
        throw 'OCR requires a nonempty image no larger than 10 MiB.'
    }
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    [void][Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
    [void][Windows.Storage.FileAccessMode, Windows.Storage, ContentType = WindowsRuntime]
    [void][Windows.Storage.Streams.IRandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.SoftwareBitmap, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.BitmapPixelFormat, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.BitmapAlphaMode, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.BitmapTransform, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.ExifOrientationMode, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.ColorManagementMode, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    [void][Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
    [void][Windows.Media.Ocr.OcrResult, Windows.Foundation, ContentType = WindowsRuntime]
    [void][Windows.Globalization.Language, Windows.Globalization, ContentType = WindowsRuntime]
    $script:AsTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetGenericArguments().Length -eq 1 -and
        $_.GetParameters().Length -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1
    if ($null -eq $script:AsTask) { throw 'WinRT task adapter is unavailable.' }
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage([Windows.Globalization.Language]::new('en-US'))
    if ($null -eq $engine) { throw 'The Windows English OCR language pack is unavailable.' }
    $script:Timer = [Diagnostics.Stopwatch]::StartNew()
    $storage = Wait-WinRT ([Windows.Storage.StorageFile]::GetFileFromPathAsync($source)) ([Windows.Storage.StorageFile])
    $stream = Wait-WinRT ($storage.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    $decoder = Wait-WinRT ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $dimensionLimit = [Math]::Min(4096, [Windows.Media.Ocr.OcrEngine]::MaxImageDimension)
    if ($decoder.PixelWidth -lt 1 -or $decoder.PixelHeight -lt 1 -or
        $decoder.PixelWidth -gt $dimensionLimit -or $decoder.PixelHeight -gt $dimensionLimit -or
        ([long]$decoder.PixelWidth * [long]$decoder.PixelHeight) -gt 16777216) {
        throw 'OCR image dimensions exceed the bounded decoder limit.'
    }
    $scaledWidth = [long]$decoder.PixelWidth * $Scale
    $scaledHeight = [long]$decoder.PixelHeight * $Scale
    if ($scaledWidth -gt $dimensionLimit -or $scaledHeight -gt $dimensionLimit -or
        ($scaledWidth * $scaledHeight) -gt 16777216) {
        throw 'OCR scaled image dimensions exceed the bounded decoder limit.'
    }
    if ($Scale -eq 1) {
        $bitmap = Wait-WinRT ($decoder.GetSoftwareBitmapAsync([Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,
            [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied)) ([Windows.Graphics.Imaging.SoftwareBitmap])
    } else {
        $transform = [Windows.Graphics.Imaging.BitmapTransform]::new()
        $transform.ScaledWidth = [uint32]$scaledWidth
        $transform.ScaledHeight = [uint32]$scaledHeight
        $bitmap = Wait-WinRT ($decoder.GetSoftwareBitmapAsync([Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,
            [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied, $transform,
            [Windows.Graphics.Imaging.ExifOrientationMode]::IgnoreExifOrientation,
            [Windows.Graphics.Imaging.ColorManagementMode]::DoNotColorManage)) ([Windows.Graphics.Imaging.SoftwareBitmap])
    }
    $result = Wait-WinRT ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
    if ([string]::IsNullOrWhiteSpace($result.Text)) { throw 'OCR did not recognize any text.' }
    Save-PrivateText $destination $result.Text
} catch {
    # Do not forward WinRT payloads or OCR text through exception formatting.
    [Console]::Error.WriteLine('Local OCR failed; verify image bounds, Windows OCR availability, paths and permissions.')
    exit 1
} finally {
    if ($null -ne $bitmap) { $bitmap.Dispose() }
    if ($null -ne $stream) { $stream.Dispose() }
}

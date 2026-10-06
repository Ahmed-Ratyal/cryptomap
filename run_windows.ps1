param(
    [switch]$InventoryOnly,
    [string]$AsOf = "",
    [string]$PythonPath = ""
)
$ErrorActionPreference = "Stop"
$candidates = @()
if ($PythonPath) {
    $candidates += @{Path=$PythonPath; Prefix=@()}
} else {
    foreach ($name in @("py", "python", "python3")) {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if ($found) {
            $prefix = @()
            if ($name -eq "py") { $prefix = @("-3") }
            $candidates += @{Path=$found.Source; Prefix=$prefix}
        }
    }
    $bundled = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
    if (Test-Path -LiteralPath $bundled) { $candidates += @{Path=$bundled; Prefix=@()} }
}
$chosen = $null
foreach ($candidate in $candidates) {
    try {
        $prefix = $candidate.Prefix
        & $candidate.Path @prefix -c "import sys; assert sys.version_info >= (3,10)" 2>$null
        if ($LASTEXITCODE -eq 0) { $chosen = $candidate; break }
    } catch { }
}
if (-not $chosen) { Write-Error "Python 3.10+ was not found. Install Python or supply -PythonPath with your interpreter path."; exit 1 }
if ($AsOf -and -not $InventoryOnly) { Write-Error "-AsOf applies to -InventoryOnly. The live local demo uses today's actual date."; exit 1 }
$prefix = $chosen.Prefix
if ($InventoryOnly) {
    $arguments = @((Join-Path $PSScriptRoot "crypto_inventory.py"), (Join-Path $PSScriptRoot "data\sample_inventory.csv"), "--out", (Join-Path $PSScriptRoot "results\inventory"))
    if ($AsOf) { $arguments += @("--as-of", $AsOf) }
} else {
    & $chosen.Path @prefix -c "import cryptography" 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Error "Install the project requirements using this Python interpreter before running the demo; see README.md."; exit 1 }
    $arguments = @((Join-Path $PSScriptRoot "demo_run.py"))
}
& $chosen.Path @prefix @arguments
exit $LASTEXITCODE

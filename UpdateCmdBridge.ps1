# Cmd Bridge updater.
# Downloads the latest tools/cmd-bridge files from GitHub (main branch)
# and replaces the local copies. Old files are saved to a backup_ folder.
#
# The repository is PRIVATE, so one of these is required:
#   * GITHUB_TOKEN environment variable (fine-grained PAT, Contents: Read)
#   * GH_TOKEN environment variable
#   * GitHub CLI installed and logged in (gh auth login)

param(
    [Parameter(Mandatory = $true)][string]$Target
)

$ErrorActionPreference = "Stop"
$Target = $Target.TrimEnd("\", "/")
$Owner = "i-dislike-lanschool"
$Repo = "Free-Model-Radar"
$Branch = "main"
$SubPath = "tools/cmd-bridge"
$Files = @("cmd_bridge.py", "README.md", "UpdateCmdBridge.ps1", "UpdateCmdBridge.cmd")

try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

function Get-GitHubToken {
    if ($env:GITHUB_TOKEN) { return $env:GITHUB_TOKEN.Trim() }
    if ($env:GH_TOKEN) { return $env:GH_TOKEN.Trim() }
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if ($gh) {
        try {
            $t = & gh auth token 2>$null
            if ($LASTEXITCODE -eq 0 -and $t) { return ($t | Out-String).Trim() }
        } catch { }
    }
    return $null
}

$token = Get-GitHubToken
$headers = @{}
if ($token) {
    $headers["Authorization"] = "token $token"
    Write-Host "Using a GitHub token for authentication."
} else {
    Write-Host "Note: no GitHub token found (GITHUB_TOKEN / GH_TOKEN / gh CLI)."
    Write-Host "This works only if the repository is public."
}

$stamp = [DateTime]::Now.ToString("yyyyMMdd_HHmmss")
$work = Join-Path $env:TEMP ("CmdBridgeUpdate_" + $stamp)
New-Item -ItemType Directory -Path $work | Out-Null

Write-Host "Downloading latest Cmd Bridge from $Owner/$Repo @ $Branch ..."
$failed = @()
foreach ($name in $Files) {
    $url = "https://raw.githubusercontent.com/$Owner/$Repo/$Branch/$SubPath/$name"
    $dest = Join-Path $work $name
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dest `
            -Headers $headers -TimeoutSec 60
        if (-not (Test-Path $dest) -or (Get-Item $dest).Length -eq 0) {
            throw "downloaded file is empty"
        }
        Write-Host "  ok: $name"
    } catch {
        Write-Host ("  FAILED: {0} ({1})" -f $name, $_.Exception.Message)
        $failed += $name
    }
}

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "Update aborted, no files were changed."
    Write-Host "The repository is private, so one of these is required:"
    Write-Host "  1. set GITHUB_TOKEN=<personal access token with Contents: Read>"
    Write-Host "     (GitHub -> Settings -> Developer settings -> Personal access tokens)"
    Write-Host "  2. or install GitHub CLI and run: gh auth login"
    exit 1
}

# Sanity check before touching local files.
$py = Get-Content (Join-Path $work "cmd_bridge.py") -Raw
if ($py -notmatch "Cmd Bridge") {
    Write-Host "Update aborted: downloaded cmd_bridge.py looks wrong."
    exit 1
}

# Backup current files.
$backup = Join-Path $Target ("backup_" + $stamp)
New-Item -ItemType Directory -Path $backup | Out-Null
foreach ($name in $Files) {
    $current = Join-Path $Target $name
    if (Test-Path $current) {
        Copy-Item $current $backup -Force
    }
}

foreach ($name in $Files) {
    Copy-Item (Join-Path $work $name) (Join-Path $Target $name) -Force
    Write-Host "Updated: $name"
}

Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "Cmd Bridge is up to date. Previous files saved to:"
Write-Host $backup
exit 0

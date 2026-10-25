# Cmd Bridge updater (ASCII version)
# Downloads files from the root of the repository and replaces local copies
# next to this script. Old versions are kept in backup_<date>_<time>.
#
#   .\UpdateCmdBridge.ps1                          update from the default repo
#   .\UpdateCmdBridge.ps1 -DryRun                  only list files
#   .\UpdateCmdBridge.ps1 -Ref v1.1.0              update from a tag
#   .\UpdateCmdBridge.ps1 -Subdir tools/cmd-bridge if files live in a subfolder
#
# Token lookup: GITHUB_TOKEN, then GH_TOKEN (optional for public repos).

param(
    [string]$Repo   = $env:CMD_BRIDGE_REPO,
    [string]$Ref    = 'main',
    [string]$Subdir = '',
    [switch]$DryRun,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
if ([string]::IsNullOrWhiteSpace($Repo)) { $Repo = 'i-dislike-lanschool/cmd-br' }

function Fail([string]$msg) {
    Write-Host ''
    Write-Host ('ERROR: ' + $msg) -ForegroundColor Red
    Write-Host 'No file was changed.' -ForegroundColor Yellow
    exit 1
}

$Subdir  = $Subdir.Trim('/')
$selfDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$token = $env:GITHUB_TOKEN
if ([string]::IsNullOrWhiteSpace($token)) { $token = $env:GH_TOKEN }
$headers = @{ 'User-Agent' = 'cmd-bridge-updater'; 'Accept' = 'application/vnd.github+json' }
if (-not [string]::IsNullOrWhiteSpace($token)) { $headers['Authorization'] = "Bearer $token" }

$apiPath = "https://api.github.com/repos/$Repo/contents"
if ($Subdir) { $apiPath = "$apiPath/$Subdir" }
$apiPath = "$apiPath" + "?ref=$Ref"

Write-Host ('repo  : ' + $Repo + '  (ref: ' + $Ref + ')')
Write-Host ('token : ' + $(if ($token) { 'found' } else { 'not set (fine for public repos)' }))
Write-Host ''

try {
    $items = Invoke-RestMethod -Uri $apiPath -Headers $headers -Method Get
} catch {
    $code = $null
    try { $code = $_.Exception.Response.StatusCode.value__ } catch { }
    if ($code -eq 404) { Fail 'repository, branch or folder not found (404).' }
    if ($code -eq 401 -or $code -eq 403) { Fail ('access denied (' + $code + ').') }
    Fail ('could not read the file list: ' + $_.Exception.Message)
}

$files = @($items | Where-Object { $_.type -eq 'file' })
if ($files.Count -eq 0) { Fail 'no files found.' }

Write-Host ('files: ' + $files.Count)
foreach ($f in $files) { Write-Host ('  ' + $f.name.PadRight(30) + $f.size.ToString().PadLeft(8) + ' B') }
Write-Host ''

if ($DryRun) { Write-Host 'DryRun: nothing downloaded, nothing changed.' -ForegroundColor Yellow; exit 0 }
if (-not $Yes) {
    $answer = Read-Host 'Download and replace local files? (y/n)'
    if ($answer -notmatch '^[yY]') { Write-Host 'Cancelled.'; exit 0 }
}

$backupDir = Join-Path $selfDir ('backup_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

$updated = 0; $added = 0; $failed = @()
foreach ($f in $files) {
    $target = Join-Path $selfDir $f.name
    $tmp = Join-Path $env:TEMP ('cb_' + [guid]::NewGuid().ToString('N') + '_' + $f.name)
    try {
        $dl = $headers.Clone()
        $dl['Accept'] = 'application/octet-stream'
        Invoke-WebRequest -Uri $f.download_url -Headers $dl -OutFile $tmp -UseBasicParsing
        if (Test-Path $target) {
            Copy-Item $target (Join-Path $backupDir $f.name) -Force
            Move-Item $tmp $target -Force
            $updated++
            Write-Host ('  updated: ' + $f.name)
        } else {
            Move-Item $tmp $target -Force
            $added++
            Write-Host ('  added  : ' + $f.name)
        }
    } catch {
        $failed += $f.name
        Write-Host ('  ERROR: ' + $f.name + ' - ' + $_.Exception.Message) -ForegroundColor Red
        if (Test-Path $tmp) { Remove-Item $tmp -Force }
    }
}

Write-Host ''
Write-Host ('Done. Updated: ' + $updated + ', added: ' + $added + ', errors: ' + $failed.Count)
Write-Host ('Backup: ' + $backupDir)
Write-Host 'Restart CmdBridge.cmd to run the new version.'

param(
    [string]$WXWorkExe = "D:\Cursor_env\企业微信\WXWork\WXWork.exe",
    [string]$WXWorkWebExe = "C:\Users\LENOVO\AppData\Roaming\Tencent\WXWork\cef\5.0.80.5496\cef\WXWorkWeb.exe",
    [int]$Port = 9222,
    [switch]$TryLauncherPassThrough
)

$ErrorActionPreference = "SilentlyContinue"

function Resolve-WXWorkExe([string]$Candidate) {
    if ($Candidate -and (Test-Path $Candidate)) {
        return $Candidate
    }
    $live = Get-CimInstance Win32_Process |
        Where-Object { $_.Name -eq "WXWork.exe" -and $_.ExecutablePath } |
        Select-Object -First 1 -ExpandProperty ExecutablePath
    if ($live) {
        return $live
    }
    return $Candidate
}

function Write-Section([string]$title) {
    Write-Host ""
    Write-Host "=== $title ==="
}

function Test-CdpEndpoint([int]$TargetPort) {
    try {
        $resp = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$TargetPort/json/version" -TimeoutSec 2
        return $resp.Content
    } catch {
        return $null
    }
}

Write-Section "Baseline Process"
Get-CimInstance Win32_Process |
    Where-Object { $_.Name -in @("WXWork.exe", "WXWorkWeb.exe") } |
    Select-Object Name, ProcessId, ParentProcessId, CommandLine |
    Format-List

Write-Section "Baseline Port"
netstat -ano | Select-String ":$Port"

Write-Section "Baseline CDP Endpoint"
$baseline = Test-CdpEndpoint -TargetPort $Port
if ($baseline) {
    Write-Host $baseline
} else {
    Write-Host "CDP endpoint unavailable"
}

if (-not (Test-Path $WXWorkWebExe)) {
    Write-Host "WXWorkWeb path not found: $WXWorkWebExe"
    exit 1
}

Write-Section "Standalone WXWorkWeb Flag Trial"
$args = @(
    "--remote-debugging-port=$Port",
    "--user-data-dir=`"C:\Users\LENOVO\AppData\Local\wxworkweb-cdp-test`"",
    "--lang=zh-CN",
    "--noerrdialogs",
    "--disable-gpu"
)
$trial = Start-Process -FilePath $WXWorkWebExe -ArgumentList $args -PassThru
Start-Sleep -Seconds 3

Write-Host "Trial PID: $($trial.Id)"
netstat -ano | Select-String ":$Port"

$trialResp = Test-CdpEndpoint -TargetPort $Port
if ($trialResp) {
    Write-Host $trialResp
} else {
    Write-Host "Standalone trial failed to expose CDP"
}

if (-not $trial.HasExited) {
    Stop-Process -Id $trial.Id -Force
    Write-Host "Stopped trial PID: $($trial.Id)"
}

if ($TryLauncherPassThrough) {
    $WXWorkExe = Resolve-WXWorkExe -Candidate $WXWorkExe
    if (-not (Test-Path $WXWorkExe)) {
        Write-Host "WXWork path not found: $WXWorkExe"
        exit 1
    }
    Write-Section "Launcher Pass-through Trial"
    Start-Process -FilePath $WXWorkExe -ArgumentList "--remote-debugging-port=$Port" | Out-Null
    Start-Sleep -Seconds 4

    netstat -ano | Select-String ":$Port"
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -in @("WXWork.exe", "WXWorkWeb.exe") -and $_.CommandLine -match "remote-debugging-port"
        } |
        Select-Object Name, ProcessId, ParentProcessId, CommandLine |
        Format-List

    $passResp = Test-CdpEndpoint -TargetPort $Port
    if ($passResp) {
        Write-Host $passResp
    } else {
        Write-Host "Launcher pass-through did not expose CDP"
    }
}

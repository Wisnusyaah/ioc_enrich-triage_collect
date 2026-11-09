<#
.SYNOPSIS
    Triage collector untuk host tersangka (Bagian D).

.DESCRIPTION
    Mengumpulkan:
      1. Proses berjalan + command line + parent      -> processes.csv
      2. Koneksi jaringan aktif (TCP + UDP) + PID      -> network_tcp.csv, network_udp.csv
      3. Autorun registry Run / RunOnce (HKLM + semua user) -> autoruns.csv
      4. User yang sedang login                        -> logged_on_users.csv, quser.txt
    Semua file disimpan di satu folder ber-timestamp, lalu SHA256 tiap file
    ditulis ke hashes_sha256.csv. Hanya membaca, tidak mengubah apa pun di host.

    Jalankan sebagai Administrator (atau SYSTEM lewat EDR) supaya command line
    proses milik user lain ikut terbaca. Kompatibel Windows PowerShell 5.1.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\triage_collect.ps1
    powershell -ExecutionPolicy Bypass -File .\triage_collect.ps1 -OutputRoot D:\IR -Zip
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$Zip
)

$ErrorActionPreference = 'Stop'

# Default: folder tempat script berada. $PSScriptRoot bisa kosong di param
# block Windows PowerShell 5.1, jadi ditentukan di sini dengan beberapa fallback.
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    if ($PSScriptRoot) {
        $OutputRoot = $PSScriptRoot
    } elseif ($MyInvocation.MyCommand.Path) {
        $OutputRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        $OutputRoot = (Get-Location).Path
    }
}
$startUtc = (Get-Date).ToUniversalTime()
$stamp    = $startUtc.ToString('yyyyMMdd_HHmmss') + 'Z'
$outDir   = Join-Path $OutputRoot ("triage_{0}_{1}" -f $env:COMPUTERNAME, $stamp)
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$logFile  = Join-Path $outDir 'collection.log'

function Write-Log([string]$Message) {
    $line = '{0}  {1}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Message
    Add-Content -Path $logFile -Value $line
    Write-Host $line
}

# Setiap modul dibungkus try/catch: kalau satu gagal, modul lain tetap jalan.
function Invoke-Step([string]$Name, [scriptblock]$Action) {
    try {
        & $Action
        Write-Log "OK    $Name"
    } catch {
        Write-Log "GAGAL $Name : $($_.Exception.Message)"
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Log ("Mulai triage di {0} sebagai {1} (admin: {2})" -f $env:COMPUTERNAME, [Security.Principal.WindowsIdentity]::GetCurrent().Name, $isAdmin)
if (-not $isAdmin) { Write-Log 'PERINGATAN: bukan admin, command line proses lain bisa kosong.' }

# Peta PID -> nama proses, dipakai juga oleh modul jaringan.
$procs = @(Get-CimInstance Win32_Process)
$pidName = @{}
foreach ($p in $procs) { $pidName[[int]$p.ProcessId] = $p.Name }

# 1. Proses + command line ----------------------------------------------------
Invoke-Step 'processes' {
    $procs | ForEach-Object {
        $owner = ''
        try {
            $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
            if ($o.User) { $owner = "$($o.Domain)\$($o.User)" }
        } catch { }
        [pscustomobject]@{
            PID            = $_.ProcessId
            PPID           = $_.ParentProcessId
            ParentName     = $pidName[[int]$_.ParentProcessId]
            Name           = $_.Name
            CommandLine    = $_.CommandLine
            ExecutablePath = $_.ExecutablePath
            Owner          = $owner
            CreationDate   = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { '' }
        }
    } | Sort-Object PID | Export-Csv -Path (Join-Path $outDir 'processes.csv') -NoTypeInformation -Encoding UTF8
}

# 2. Koneksi jaringan -----------------------------------------------------------
Invoke-Step 'network' {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        Get-NetTCPConnection | ForEach-Object {
            [pscustomobject]@{
                LocalAddress  = $_.LocalAddress;  LocalPort  = $_.LocalPort
                RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort
                State         = $_.State
                PID           = $_.OwningProcess
                ProcessName   = $pidName[[int]$_.OwningProcess]
            }
        } | Export-Csv -Path (Join-Path $outDir 'network_tcp.csv') -NoTypeInformation -Encoding UTF8

        Get-NetUDPEndpoint | ForEach-Object {
            [pscustomobject]@{
                LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort
                PID          = $_.OwningProcess
                ProcessName  = $pidName[[int]$_.OwningProcess]
            }
        } | Export-Csv -Path (Join-Path $outDir 'network_udp.csv') -NoTypeInformation -Encoding UTF8
    } else {
        # Fallback untuk Windows lama tanpa modul NetTCPIP.
        netstat -ano | Out-File -FilePath (Join-Path $outDir 'netstat.txt') -Encoding UTF8
    }
}

# 3. Autorun registry Run / RunOnce ---------------------------------------------
Invoke-Step 'autoruns' {
    $subKeys = @(
        'Software\Microsoft\Windows\CurrentVersion\Run',
        'Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    # HKLM + hive setiap user yang sedang dimuat (HKU\<SID>). Saat dijalankan
    # sebagai SYSTEM, HKCU adalah milik SYSTEM, jadi HKU yang perlu dibaca.
    $hives = @('HKLM')
    $hives += Get-ChildItem 'Registry::HKEY_USERS' |
              Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
              ForEach-Object { "HKU\$($_.PSChildName)" }

    $rows = foreach ($hive in $hives) {
        foreach ($sub in $subKeys) {
            $path = "Registry::$($hive -replace '^HKLM','HKEY_LOCAL_MACHINE' -replace '^HKU','HKEY_USERS')\$sub"
            if (-not (Test-Path $path)) { continue }
            $key = Get-Item -Path $path
            foreach ($valueName in $key.GetValueNames()) {
                [pscustomobject]@{
                    Hive  = $hive
                    Key   = $sub
                    Name  = $valueName
                    Value = $key.GetValue($valueName)
                }
            }
        }
    }
    $rows | Export-Csv -Path (Join-Path $outDir 'autoruns.csv') -NoTypeInformation -Encoding UTF8
}

# 4. User yang login ------------------------------------------------------------
Invoke-Step 'logged_on_users' {
    # Sesi interaktif (2), RDP (10), cached (11) beserta akunnya.
    $interactive = @(2, 10, 11)
    $sessions = Get-CimInstance Win32_LogonSession | Where-Object { $interactive -contains $_.LogonType }
    $rows = foreach ($s in $sessions) {
        $accounts = Get-CimAssociatedInstance -InputObject $s -ResultClassName Win32_Account -ErrorAction SilentlyContinue
        foreach ($a in $accounts) {
            [pscustomobject]@{
                User      = "$($a.Domain)\$($a.Name)"
                LogonType = $s.LogonType
                LogonId   = $s.LogonId
                StartTime = if ($s.StartTime) { $s.StartTime.ToUniversalTime().ToString('o') } else { '' }
                AuthPkg   = $s.AuthenticationPackage
            }
        }
    }
    $rows | Export-Csv -Path (Join-Path $outDir 'logged_on_users.csv') -NoTypeInformation -Encoding UTF8

    # quser menampilkan status sesi (Active/Disc). Tidak ada di Windows Home.
    if (Get-Command quser.exe -ErrorAction SilentlyContinue) {
        quser.exe 2>&1 | Out-File -FilePath (Join-Path $outDir 'quser.txt') -Encoding UTF8
    }
}

# Hash SHA256 setiap file output --------------------------------------------
Write-Log 'Selesai koleksi, menghitung SHA256'
$hashFile = Join-Path $outDir 'hashes_sha256.csv'
Get-ChildItem -Path $outDir -File |
    Where-Object { $_.FullName -ne $hashFile } |
    Get-FileHash -Algorithm SHA256 |
    Select-Object @{n='File';e={Split-Path $_.Path -Leaf}}, Hash |
    Export-Csv -Path $hashFile -NoTypeInformation -Encoding UTF8
# collection.log ikut di-hash di atas, jadi log terakhir hanya ke layar.

if ($Zip) {
    $zipPath = "$outDir.zip"
    Compress-Archive -Path $outDir -DestinationPath $zipPath -Force
    $zh = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
    Write-Host "ZIP: $zipPath  SHA256: $zh"
}
Write-Host "Output: $outDir"

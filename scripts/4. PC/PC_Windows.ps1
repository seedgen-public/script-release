#================================================================
# PC_Windows 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : PC_Windows
# 항목  : PC-01 ~ PC-18 (18개)
# 제작  : Seedgen
#================================================================
$META_STD = "KISA"

#================================================================
# 관리자 권한 자동 승격
#================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    try {
        Start-Process PowerShell -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`"" -Verb RunAs -Wait
    } catch {
        Write-Host "[X] 관리자 권한 상승 실패: $_" -ForegroundColor Red
        Read-Host "Press Enter to exit"
    }
    exit
}

#================================================================
# INIT
#================================================================
chcp 65001 | Out-Null
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# 콘솔 창 크기 조정
try {
    $host.UI.RawUI.WindowTitle = "Windows PC 보안 진단"
    $width = 70
    $height = 32
    $bufferSize = $host.UI.RawUI.BufferSize
    if ($bufferSize.Width -lt $width) { $bufferSize.Width = $width }
    if ($bufferSize.Height -lt 3000) { $bufferSize.Height = 3000 }
    $host.UI.RawUI.BufferSize = $bufferSize
    $host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size($width, $height)
} catch { }

$META_VER = "1.0"
$META_PLAT = "Windows"
$META_TYPE = "PC"

$script:xmlBuilder = New-Object System.Text.StringBuilder

# 결과 출력 함수
function Output-Checkpoint {
    param(
        [string]$CODE, [string]$CAT, [string]$NAME, [string]$IMP,
        [string]$STD, [string]$RES, [string]$DESC, [string]$DT
    )

    switch ($RES) {
        "Y"   { Write-Host "    [$([char]0x1b)[32mY$([char]0x1b)[0m] $CODE $NAME" }
        "N"   { Write-Host "    [$([char]0x1b)[31mN$([char]0x1b)[0m] $CODE $NAME" }
        "M"   { Write-Host "    [$([char]0x1b)[33mM$([char]0x1b)[0m] $CODE $NAME" }
        "N/A" { Write-Host "    [$([char]0x1b)[90m-$([char]0x1b)[0m] $CODE $NAME" }
        default { Write-Host "    [-] $CODE $NAME" }
    }

    $E_NAME = $NAME -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
    $E_DESC = $DESC -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'

    [void]$script:xmlBuilder.Append(@"
        <cp>
            <code>$CODE</code>
            <cat>$CAT</cat>
            <n>$E_NAME</n>
            <imp>$IMP</imp>
            <std>$STD</std>
            <res>$RES</res>
            <desc>$E_DESC</desc>
            <dt><![CDATA[$DT]]></dt>
        </cp>

"@)
}

#================================================================
# UI — 사용자 정보 입력
#================================================================
Clear-Host
Write-Host ""
Write-Host "  $META_PLAT PC Security Assessment v$META_VER [$META_STD]" -ForegroundColor Cyan
Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  [사용자 정보 입력]" -ForegroundColor Yellow
Write-Host ""
$USER_DEPT = Read-Host "    부서명"
$USER_NAME = Read-Host "    사용자명"
Write-Host ""

# 입력값 검증 (빈값이면 기본값 사용)
if ([string]::IsNullOrWhiteSpace($USER_DEPT)) { $USER_DEPT = "Unknown" }
if ([string]::IsNullOrWhiteSpace($USER_NAME)) { $USER_NAME = $env:USERNAME }

# 파일명에서 사용 불가 문자 제거
$USER_DEPT = $USER_DEPT -replace '[\\/:*?"<>|]', '_'
$USER_NAME = $USER_NAME -replace '[\\/:*?"<>|]', '_'

Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  부서: $USER_DEPT" -ForegroundColor White
Write-Host "  │  사용자: $USER_NAME" -ForegroundColor White
Write-Host "  │  호스트: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  │  기준: $META_STD" -ForegroundColor White
Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

#================================================================
# COLLECT
#================================================================
$META_DATE = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$SYS_HOST = $env:COMPUTERNAME
$SYS_DOM = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain
if (-not $SYS_DOM) { $SYS_DOM = "WORKGROUP" }

$SYS_OS_NAME = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
$SYS_OS_FN = $SYS_OS_NAME -replace "Microsoft ", ""
$osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$SYS_KN = $osInfo.Version
$SYS_ARCH = $osInfo.OSArchitecture

$SYS_IP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress
if (-not $SYS_IP) { $SYS_IP = "N/A" }
$SYS_NET_ALL = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)" }) -join "`n"

$OUTPUT_FILE = Join-Path $PSScriptRoot "${USER_DEPT}_${USER_NAME}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

function Check01 {
    $CODE = "PC-01"
    $CAT = "계정관리"
    $NAME = "비밀번호의 주기적 변경"
    $IMP = "상"
    $STD = "최대 암호 사용 기간이 `"90일`" 이하로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# 최대 암호 사용 기간 조회
$maxPasswordAge = $null
$netAccounts = net accounts 2>$null
$maxAgeLine = $netAccounts | Select-String -Pattern "Maximum password age"

if ($maxAgeLine) {
    $maxAgeValue = ($maxAgeLine.ToString() -split ":")[1].Trim()
    if ($maxAgeValue -match "^\d+$") {
        $maxPasswordAge = [int]$maxAgeValue
    } elseif ($maxAgeValue -match "Unlimited|무제한") {
        $maxPasswordAge = 999
    }
}

# 판단
if ($null -eq $maxPasswordAge -or $maxPasswordAge -gt 90) {
    $RES = "N"
    $DESC = "최대 암호 사용 기간이 90일을 초과하여 취약"
} else {
    $RES = "Y"
    $DESC = "최대 암호 사용 기간이 90일 이하로 설정되어 양호"
}

$DT = "Maximum password age: $maxAgeValue"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check02 {
    $CODE = "PC-02"
    $CAT = "계정관리"
    $NAME = "비밀번호 관리정책 설정"
    $IMP = "상"
    $STD = "복잡성을 만족하는 비밀번호 정책이 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# 최소 암호 길이 조회
$minPasswordLength = $null
$netAccounts = net accounts 2>$null
$minLenLine = $netAccounts | Select-String -Pattern "Minimum password length"

if ($minLenLine) {
    $minLenValue = ($minLenLine.ToString() -split ":")[1].Trim()
    if ($minLenValue -match "^\d+$") {
        $minPasswordLength = [int]$minLenValue
    }
}

# 복잡성 설정 확인 (secedit)
$secpolPath = "$env:TEMP\secpol_$([guid]::NewGuid().ToString('N')).cfg"
$passwordComplexity = $null

try {
    secedit /export /cfg $secpolPath 2>$null | Out-Null
    if (Test-Path $secpolPath) {
        $secpolContent = Get-Content $secpolPath -ErrorAction SilentlyContinue
        $complexityLine = $secpolContent | Where-Object { $_ -match "PasswordComplexity" }
        if ($complexityLine) {
            $passwordComplexity = [int](($complexityLine -split "=")[1].Trim())
        }
        Remove-Item $secpolPath -Force -ErrorAction SilentlyContinue
    }
} catch {
    # secedit 실패 시 무시
}

# 판단
$isMinLenOK = ($minPasswordLength -ge 8)
$isComplexityOK = ($passwordComplexity -eq 1)

if ($isMinLenOK -and $isComplexityOK) {
    $RES = "Y"
    $DESC = "비밀번호 정책이 적절히 설정되어 양호"
} else {
    $RES = "N"
    $issues = @()
    if (-not $isMinLenOK) { $issues += "최소 길이 미달" }
    if (-not $isComplexityOK) { $issues += "복잡성 미설정" }
    $DESC = "비밀번호 정책 미흡 ($($issues -join ', '))"
}

$DT = "Minimum password length: $minPasswordLength`nPasswordComplexity: $(if($passwordComplexity -eq 1){'사용'}else{'사용 안 함'})"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check03 {
    $CODE = "PC-03"
    $CAT = "계정관리"
    $NAME = "복구 콘솔에서 자동 로그온을 금지하도록 설정"
    $IMP = "중"
    $STD = "복구 콘솔 자동 로그온 허용이 `"사용 안 함`"으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
$securityLevel = $null

try {
    $regValue = Get-ItemProperty -Path $regPath -Name "SecurityLevel" -ErrorAction SilentlyContinue
    if ($regValue) {
        $securityLevel = $regValue.SecurityLevel
    }
} catch {
    # 레지스트리 없음
}

# 판단: SecurityLevel이 없거나 0이면 양호, 1이면 취약
if ($null -eq $securityLevel -or $securityLevel -eq 0) {
    $RES = "Y"
    $DESC = "복구 콘솔 자동 로그온이 금지되어 양호"
} else {
    $RES = "N"
    $DESC = "복구 콘솔 자동 로그온이 허용되어 취약"
}

$DT = "SecurityLevel: $(if($null -eq $securityLevel){'Not Set'}else{$securityLevel})"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check04 {
    $CODE = "PC-04"
    $CAT = "서비스관리"
    $NAME = "공유 폴더 제거"
    $IMP = "상"
    $STD = "불필요한 공유 폴더가 존재하지 않거나 공유 폴더에 접근 권한 및 비밀번호가 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# 공유 폴더 조회 (IPC$ 제외)
$shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "IPC$" }
$adminShares = $shares | Where-Object { $_.Name -match '^[A-Z]\$|^ADMIN\$' }
$userShares = $shares | Where-Object { $_.Name -notmatch '^[A-Z]\$|^ADMIN\$' }

$shareList = ($shares | ForEach-Object { "$($_.Name) -> $($_.Path)" }) -join "`n"

# [FIX] 기본 관리 공유만 먼저 판정, 사용자 공유는 접근 권한 확인 후 판정
if ($adminShares) {
    $RES = "N"
    $DESC = "기본 관리 공유(C$/D$/ADMIN$)가 존재하여 취약"
} elseif ($userShares) {
    # [FIX] 사용자 공유 폴더의 Everyone 권한 확인
    $everyoneFound = $false
    $accessDetails = @()
    foreach ($s in $userShares) {
        $acl = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
        $everyoneAcl = $acl | Where-Object { $_.AccountName -match 'Everyone' }
        if ($everyoneAcl) {
            $everyoneFound = $true
            $accessDetails += "$($s.Name): Everyone 권한 있음"
        } else {
            $accessDetails += "$($s.Name): Everyone 권한 없음"
        }
    }
    if ($everyoneFound) {
        # [FIX] Everyone 권한 존재 시 취약
        $RES = "N"
        $DESC = "사용자 공유 폴더에 Everyone 접근 권한이 존재하여 취약"
    } else {
        # [FIX] Everyone 권한 없으면 수동 확인
        $RES = "M"
        $DESC = "사용자 공유 폴더 존재, 접근 권한 수동 확인 필요"
    }
    $shareList += "`n`n접근 권한 확인:`n$($accessDetails -join "`n")"
} else {
    $RES = "Y"
    $DESC = "불필요한 공유 폴더가 존재하지 않아 양호"
}

$DT = "공유 폴더 목록:`n$shareList"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check05 {
    $CODE = "PC-05"
    $CAT = "서비스관리"
    $NAME = "항목의 불필요한 서비스 제거"
    $IMP = "상"
    $STD = "일반적으로 불필요한 서비스(아래 목록 참조)가 중지된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# [FIX] Win10/11 필수 서비스 제외: wuauserv, CryptSvc, DHCP, Dnscache, WlanSvc
$unnecessaryServices = @(
    "Alerter",
    # "wuauserv",        # [FIX] 제외 — Windows Update, 보안 패치 적용에 필수
    "ClipSrv",           # Clipbook
    "Browser",           # Computer Browser
    # "CryptSvc",        # [FIX] 제외 — Cryptographic Services, 인증서 검증에 필수
    # "DHCP",            # [FIX] 제외 — DHCP Client, 네트워크 IP 할당에 필수
    "TrkWks",            # Distributed Link Tracking Client
    "TrkSvr",            # Distributed Link Tracking Server
    # "Dnscache",        # [FIX] 제외 — DNS Client, DNS 확인에 필수
    "ERSvc",             # Error Reporting Service
    "HidServ",           # Human Interface Device Access
    "IMAPI",             # IMAPI CD-Burning COM Service
    "Irmon",             # Infrared Monitor
    "Messenger",
    "mnmsrvc",           # NetMeeting Remote Desktop Sharing
    "WmdmPmSN",          # Portable Media Serial Number
    "Spooler",           # Print Spooler
    "RemoteRegistry",
    "simptcp",           # Simple TCP/IP Services
    "upnphost",          # Universal Plug and Play Device Host
    "WZCSVC",            # Wireless Zero Configuration
    # "WlanSvc",         # [FIX] 제외 — WLAN AutoConfig, Wi-Fi 연결에 필수
    "SSDPSRV"            # SSDP Discovery
)

$runningServices = @()
foreach ($svcName in $unnecessaryServices) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        $runningServices += "$($svc.Name) ($($svc.DisplayName))"
    }
}

# 판단
if ($runningServices.Count -gt 0) {
    $RES = "N"
    $DESC = "불필요한 서비스가 실행 중이어서 취약"
} else {
    $RES = "Y"
    $DESC = "불필요한 서비스가 실행되지 않아 양호"
}

$DT = "실행 중인 불필요 서비스:`n$($runningServices -join "`n")"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check06 {
    $CODE = "PC-06"
    $CAT = "서비스관리"
    $NAME = "비인가 상용 메신저 사용 금지"
    $IMP = "상"
    $STD = "Windows Messenger가 실행 중지된 상태이거나 상용 메신저가 설치되지 않은 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# 메신저 목록 (정확한 매칭을 위해 단어 경계 사용)
$messengerPatterns = @(
    "카카오톡", "KakaoTalk",
    "네이트온", "NateOn",
    "^Skype",
    "^LINE$|^LINE ",        # LINE 앱만 매칭 (Command Line 등 제외)
    "^Discord",
    "^Telegram",
    "^WeChat",
    "^WhatsApp",
    "Facebook Messenger"
)

$installedMessengers = @()

# 레지스트리에서 설치된 프로그램 확인
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($path in $uninstallPaths) {
    $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue
    foreach ($app in $apps) {
        foreach ($pattern in $messengerPatterns) {
            if ($app.DisplayName -match $pattern) {
                $installedMessengers += $app.DisplayName
            }
        }
    }
}

$installedMessengers = $installedMessengers | Select-Object -Unique

# Windows Messenger 정책 확인 (가이드라인 요구사항)
$wmPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
$preventRun = $null
try {
    $wmPolicy = Get-ItemProperty -Path $wmPolicyPath -Name "PreventRun" -ErrorAction SilentlyContinue
    if ($wmPolicy) {
        $preventRun = $wmPolicy.PreventRun
    }
} catch {}

# 판단: 메신저 설치 여부 + Windows Messenger 정책
$vulnerabilities = @()

if ($installedMessengers.Count -gt 0) {
    $vulnerabilities += "상용 메신저 설치됨"
}

if ($preventRun -ne 1) {
    $vulnerabilities += "Windows Messenger 실행 허용 안 함 미설정"
}

if ($vulnerabilities.Count -gt 0) {
    $RES = "N"
    $DESC = $vulnerabilities -join ", "
} else {
    $RES = "Y"
    $DESC = "상용 메신저 미설치 및 Windows Messenger 정책 설정됨"
}

$dtList = @()
$dtList += "[설치된 메신저]"
if ($installedMessengers.Count -gt 0) {
    $dtList += $installedMessengers -join "`n"
} else {
    $dtList += "(없음)"
}
$dtList += ""
$dtList += "[Windows Messenger 정책]"
$dtList += "PreventRun: $(if($null -eq $preventRun){'미설정'}else{$preventRun}) (1=사용안함)"

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check07 {
    $CODE = "PC-07"
    $CAT = "서비스관리"
    $NAME = "파일 시스템이 NTFS 포맷으로 설정"
    $IMP = "중"
    $STD = "모든 디스크 볼륨의 파일 시스템이 NTFS인 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# 고정 디스크만 확인 (DriveType=3)
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
$nonNtfsDisks = @()
$diskInfo = @()

foreach ($disk in $disks) {
    $diskInfo += "$($disk.DeviceID) - $($disk.FileSystem)"
    if ($disk.FileSystem -ne "NTFS") {
        $nonNtfsDisks += "$($disk.DeviceID) ($($disk.FileSystem))"
    }
}

# 판단
if ($nonNtfsDisks.Count -gt 0) {
    $RES = "N"
    $DESC = "NTFS가 아닌 파일 시스템이 존재하여 취약"
} else {
    $RES = "Y"
    $DESC = "모든 드라이브가 NTFS로 설정되어 양호"
}

$DT = "드라이브 파일시스템:`n$($diskInfo -join "`n")"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check08 {
    $CODE = "PC-08"
    $CAT = "서비스관리"
    $NAME = "대상 시스템이 Windows 서버를 제외한 다른 OS로 멀티 부팅이 가능하지 않도록 설정"
    $IMP = "중"
    $STD = "PC 내에 하나의 OS만 설치된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# bcdedit로 부팅 항목 확인
$bcdOutput = bcdedit /enum 2>$null | Out-String

# Windows Boot Loader 항목 개수 확인
$osCount = ([regex]::Matches($bcdOutput, "identifier")).Count - 1  # bootmgr 제외

# 판단
if ($osCount -gt 1) {
    $RES = "N"
    $DESC = "멀티 부팅이 설정되어 취약"
} else {
    $RES = "Y"
    $DESC = "단일 OS로 설정되어 양호"
}

$DT = "부팅 항목 수: $osCount"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check09 {
    $CODE = "PC-09"
    $CAT = "서비스관리"
    $NAME = "브라우저 종료 시 임시 인터넷 파일 폴더의 내용을 삭제하도록 설정"
    $IMP = "하"
    $STD = "`"브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기`" 설정이 `"사용`"으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# 여러 레지스트리 경로 확인 (GPO 정책이 우선)
$persistent = $null
$clearOnExit = $null
$persistentSource = "미설정"
$clearOnExitSource = "미설정"

# 1. HKLM Group Policy 경로 (최우선 - gpedit 설정 시 사용되는 경로)
$gpoPathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache"
try {
    $regValue = Get-ItemProperty -Path $gpoPathHKLM -Name "Persistent" -ErrorAction SilentlyContinue
    if ($null -ne $regValue -and $null -ne $regValue.Persistent) {
        $persistent = $regValue.Persistent
        $persistentSource = "HKLM GPO"
    }
} catch {}

# 2. HKCU Group Policy 경로 (GPO 우선)
$gpPath = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Privacy"
try {
    $regValue = Get-ItemProperty -Path $gpPath -Name "ClearBrowsingHistoryOnExit" -ErrorAction SilentlyContinue
    if ($null -ne $regValue -and $null -ne $regValue.ClearBrowsingHistoryOnExit) {
        $clearOnExit = $regValue.ClearBrowsingHistoryOnExit
        $clearOnExitSource = "HKCU GPO"
    }
} catch {}

# 3. Internet Settings Cache - Persistent (사용자 설정)
if ($null -eq $persistent) {
    $cachePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache"
    try {
        $regValue = Get-ItemProperty -Path $cachePath -Name "Persistent" -ErrorAction SilentlyContinue
        if ($null -ne $regValue -and $null -ne $regValue.Persistent) {
            $persistent = $regValue.Persistent
            $persistentSource = "HKCU"
        }
    } catch {}
}

# 4. IE Privacy - ClearBrowsingHistoryOnExit (IE 인터넷 옵션에서 설정)
if ($null -eq $clearOnExit) {
    $privacyPath = "HKCU:\Software\Microsoft\Internet Explorer\Privacy"
    try {
        $regValue = Get-ItemProperty -Path $privacyPath -Name "ClearBrowsingHistoryOnExit" -ErrorAction SilentlyContinue
        if ($null -ne $regValue -and $null -ne $regValue.ClearBrowsingHistoryOnExit) {
            $clearOnExit = $regValue.ClearBrowsingHistoryOnExit
            $clearOnExitSource = "HKCU IE Privacy"
        }
    } catch {}
}

# 5. 5.0 Cache (이전 버전 호환성)
if ($null -eq $persistent) {
    $cache50Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache"
    try {
        $regValue = Get-ItemProperty -Path $cache50Path -Name "Persistent" -ErrorAction SilentlyContinue
        if ($null -ne $regValue -and $null -ne $regValue.Persistent) {
            $persistent = $regValue.Persistent
            $persistentSource = "HKCU 5.0 Cache"
        }
    } catch {}
}

# 판단: Persistent=0 또는 ClearBrowsingHistoryOnExit=1 이면 양호
$isSecure = ($persistent -eq 0) -or ($clearOnExit -eq 1)

if ($isSecure) {
    $RES = "Y"
    $DESC = "임시 인터넷 파일 삭제가 설정되어 양호"
} else {
    $RES = "N"
    $DESC = "임시 인터넷 파일 삭제가 미설정되어 취약"
}

$dtList = @()
$dtList += "[Cache 설정]"
$dtList += "Persistent: $(if($null -eq $persistent){'미설정'}else{$persistent}) (0=삭제)"
$dtList += "  설정 소스: $persistentSource"
$dtList += ""
$dtList += "[IE Privacy 설정]"
$dtList += "ClearBrowsingHistoryOnExit: $(if($null -eq $clearOnExit){'미설정'}else{$clearOnExit}) (1=삭제)"
$dtList += "  설정 소스: $clearOnExitSource"
$dtList += ""
$dtList += "[참고] GPO 정책 > 사용자 설정 순으로 우선 적용됨"
$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check10 {
    $CODE = "PC-10"
    $CAT = "패치관리"
    $NAME = "주기적 보안 패치 및 벤더 권고사항 적용"
    $IMP = "상"
    $STD = "HOT FIX 설치 및 자동 업데이트 설정이 되어 있고 내부적으로 관리 절차를 수립하여 이행한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# [FIX] 최근 90일 이내 패치 확인 (30일 → 90일)
$ninetyDaysAgo = (Get-Date).AddDays(-90)
$recentPatches = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn -gt $ninetyDaysAgo }
$allPatches = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 5

$patchList = ($allPatches | ForEach-Object { "$($_.HotFixID) - $($_.InstalledOn)" }) -join "`n"

# [FIX] 자동 업데이트 설정 확인
$auRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
$wuPolPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$auOptions = $null
$wuServer = $null
$isCentralManaged = $false
$updateInfo = @()

try {
    $auReg = Get-ItemProperty -Path $auRegPath -ErrorAction SilentlyContinue
    if ($auReg -and $null -ne $auReg.AUOptions) {
        $auOptions = [int]$auReg.AUOptions
    }
} catch {}

try {
    $wuPol = Get-ItemProperty -Path $wuPolPath -ErrorAction SilentlyContinue
    if ($wuPol -and $null -ne $wuPol.WUServer) {
        $wuServer = $wuPol.WUServer
        $isCentralManaged = $true  # [FIX] WSUS/SCCM 중앙관리 환경
    }
} catch {}

$auDesc = switch ($auOptions) {
    1 { "비활성화" }
    2 { "다운로드 전 알림" }
    3 { "자동 다운로드, 설치 전 알림" }
    4 { "자동 다운로드 및 설치" }
    default { "미설정" }
}
$updateInfo += "AUOptions: $auOptions ($auDesc)"
if ($wuServer) { $updateInfo += "WUServer: $wuServer (중앙관리)" }

# [FIX] 종합 판정: 패치 + 업데이트 설정
$hasPatch = $recentPatches.Count -gt 0

if ($hasPatch -and ($auOptions -eq 4)) {
    # [FIX] 90일 내 패치 있고, 자동 업데이트 설정 → 양호
    $RES = "Y"
    $DESC = "최근 90일 이내 보안 패치 적용, 자동 업데이트 설정되어 양호"
} elseif ($hasPatch -and $isCentralManaged) {
    # [FIX] 패치 있고, WSUS/SCCM 환경 → 수동 확인
    $RES = "M"
    $DESC = "최근 90일 이내 패치 적용, 중앙관리(WSUS/SCCM) 환경 확인 필요"
} elseif ($hasPatch) {
    # [FIX] 패치 있으나 자동 업데이트 미설정
    $RES = "M"
    $DESC = "최근 90일 이내 패치 적용, 자동 업데이트 설정 수동 확인 필요"
} elseif ($isCentralManaged) {
    # [FIX] 패치 없으나 중앙관리 환경 → 수동 확인
    $RES = "M"
    $DESC = "최근 90일 이내 패치 없음, 중앙관리(WSUS/SCCM) 환경 수동 확인 필요"
} else {
    # [FIX] 패치 없고 자동 업데이트도 미설정 → 취약
    $RES = "N"
    $DESC = "최근 90일 이내 패치 없음, 자동 업데이트 미설정으로 취약"
}

$DT = "최근 패치 목록:`n$patchList`n`n업데이트 설정:`n$($updateInfo -join "`n")"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check11 {
    $CODE = "PC-11"
    $CAT = "패치관리"
    $NAME = "지원이 종료되지 않은 Windows OS Build 적용"
    $IMP = "상"
    $STD = "최신 빌드가 적용되어 있고 내부적으로 관리 절차를 수립하여 이행한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$osInfo = Get-CimInstance Win32_OperatingSystem
$osVersion = $osInfo.Version
$osCaption = $osInfo.Caption
$osBuildNumber = $osInfo.BuildNumber

# [FIX] Windows 10은 취약, Windows 11은 수동 확인
if ($osCaption -match "Windows 10") {
    $RES = "N"
    $DESC = "Windows 10은 지원 종료 예정으로 취약"
} elseif ($osCaption -match "Windows 11") {
    $RES = "M"
    $DESC = "Windows 11 빌드 버전 수동 확인 필요"
} else {
    $RES = "M"
    $DESC = "OS 버전 정보 확인 필요 (수동 확인)"
}

$DT = "OS: $osCaption`nVersion: $osVersion`nBuild: $osBuildNumber"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check12 {
    $CODE = "PC-12"
    $CAT = "보안관리"
    $NAME = "Windows 자동 로그인 점검"
    $IMP = "중"
    $STD = "Windows 자동 로그인이 비활성화된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

$autoAdminLogon = $null
$defaultPassword = $null
$defaultUserName = $null

try {
    $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    $autoAdminLogon = $regValues.AutoAdminLogon
    $defaultPassword = $regValues.DefaultPassword
    $defaultUserName = $regValues.DefaultUserName
} catch {
    # 레지스트리 없음
}

# 판단: AutoAdminLogon=1 또는 DefaultPassword 존재 시 취약
if ($autoAdminLogon -eq "1" -or $defaultPassword) {
    $RES = "N"
    $DESC = "Windows 자동 로그인이 설정되어 취약"
} else {
    $RES = "Y"
    $DESC = "Windows 자동 로그인이 비활성화되어 양호"
}

$DT = "AutoAdminLogon: $(if($autoAdminLogon){$autoAdminLogon}else{'Not Set'})`nDefaultUserName: $(if($defaultUserName){$defaultUserName}else{'Not Set'})`nDefaultPassword: $(if($defaultPassword){'Set'}else{'Not Set'})"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check13 {
    $CODE = "PC-13"
    $CAT = "보안관리"
    $NAME = "바이러스 백신 프로그램 설치 및 주기적 업데이트"
    $IMP = "상"
    $STD = "백신이 설치되어 있고, 최신 업데이트가 적용된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$antivirusProducts = @()

try {
    $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    foreach ($av in $avProducts) {
        $antivirusProducts += $av.displayName
    }
} catch {
    # SecurityCenter2 접근 불가
}

# Windows Defender 상태 확인
$defenderStatus = $null
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
} catch {
    # Defender 없음
}

# [FIX] Defender 외 백신 분리
$otherAV = $antivirusProducts | Where-Object { $_ -notmatch 'Windows Defender|Microsoft Defender' }

# [FIX] 판정: Defender/기타 백신 유무에 따라 M 또는 N
if ($defenderStatus) {
    # [FIX] Defender 감지 시: 모든 정보 표기, M 처리
    $RES = "M"
    $DESC = "Windows Defender 감지, 수동 확인 필요"
    $dtList = @()
    $dtList += "백신: Windows Defender"
    $dtList += "실시간 보호: $(if($defenderStatus.RealTimeProtectionEnabled){'사용'}else{'사용 안 함'})"
    $dtList += "서명 버전: $($defenderStatus.AntivirusSignatureVersion)"
    $dtList += "서명 업데이트: $($defenderStatus.AntivirusSignatureLastUpdated)"
    $dtList += "엔진 버전: $($defenderStatus.AMEngineVersion)"
    $dtList += "제품 버전: $($defenderStatus.AMProductVersion)"
    if ($otherAV) {
        $dtList += "`n기타 백신: $($otherAV -join ', ')"
    }
    $DT = $dtList -join "`n"
} elseif ($otherAV.Count -gt 0) {
    # [FIX] 기타 백신만 감지: 이름만 기록, M 처리
    $RES = "M"
    $DESC = "백신 프로그램 감지, 수동 확인 필요"
    $DT = "설치된 백신: $($otherAV -join ', ')"
} else {
    $RES = "N"
    $DESC = "백신 프로그램이 설치되지 않아 취약"
    $DT = "설치된 백신: 없음"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check14 {
    $CODE = "PC-14"
    $CAT = "보안관리"
    $NAME = "바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화"
    $IMP = "상"
    $STD = "설치된 백신의 실시간 감시기능이 활성화된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$avStatusList = @()
$anyRealTimeEnabled = $false

# SecurityCenter2에서 모든 백신 확인 (productState 비트마스킹)
try {
    $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    foreach ($av in $avProducts) {
        $productState = $av.productState
        # productState 비트 분석: bit 12-15가 0x1이면 실시간 보호 활성화
        $realTimeOn = (($productState -shr 12) -band 0xF) -eq 0x1
        $avStatusList += "$($av.displayName): $(if($realTimeOn){'ON'}else{'OFF'}) (0x$($productState.ToString('X')))"
        if ($realTimeOn) { $anyRealTimeEnabled = $true }
    }
} catch {
    # SecurityCenter2 접근 불가
}

# Defender 상태도 추가 확인 (더 정확함)
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
        $anyRealTimeEnabled = $true
        # 이미 목록에 있으면 상태 업데이트
        $avStatusList = $avStatusList | ForEach-Object {
            if ($_ -match "Windows Defender") {
                "Windows Defender: ON (Get-MpComputerStatus)"
            } else { $_ }
        }
    }
} catch {
    # Defender 없음
}

# 판단
if ($anyRealTimeEnabled) {
    $RES = "Y"
    $DESC = "실시간 보호 기능이 활성화되어 양호"
} elseif ($avStatusList.Count -eq 0) {
    $RES = "N"
    $DESC = "백신이 설치되지 않아 취약"
} else {
    $RES = "N"
    $DESC = "실시간 보호 기능이 비활성화되어 취약"
}

$DT = "백신 실시간 감시 상태:`n$($avStatusList -join "`n")"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check15 {
    $CODE = "PC-15"
    $CAT = "보안관리"
    $NAME = "OS에서 제공하는 침입차단 기능 활성화"
    $IMP = "상"
    $STD = "Windows 방화벽 `"사용`"으로 설정된 경우 또는 유·무료 기타 방화벽을 사용한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# netsh로 방화벽 상태 확인
$firewallOutput = netsh advfirewall show currentprofile state 2>$null
$firewallEnabled = $firewallOutput -match "ON|설정"

# 프로필별 상태 확인
$profiles = @("Domain", "Private", "Public")
$profileStatus = @()

foreach ($profile in $profiles) {
    $status = netsh advfirewall show $profile.ToLower() state 2>$null
    if ($status -match "ON|설정") {
        $profileStatus += "$profile : ON"
    } else {
        $profileStatus += "$profile : OFF"
    }
}

# 판단
if ($firewallEnabled) {
    $RES = "Y"
    $DESC = "Windows 방화벽이 활성화되어 양호"
} else {
    $RES = "N"
    $DESC = "Windows 방화벽이 비활성화되어 취약"
}

$DT = ($profileStatus -join "`n")

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check16 {
    $CODE = "PC-16"
    $CAT = "보안관리"
    $NAME = "화면보호기 대기 시간 설정 및 재시작 시 암호 보호 설정"
    $IMP = "상"
    $STD = "화면보호기 설정(대기 시간 10분 이하) 및 비밀번호로 보호가 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$regPath = "HKCU:\Control Panel\Desktop"

$screenSaveActive = $null
$screenSaverIsSecure = $null
$screenSaveTimeOut = $null

try {
    $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    $screenSaveActive = $regValues.ScreenSaveActive
    $screenSaverIsSecure = $regValues.ScreenSaverIsSecure
    $screenSaveTimeOut = $regValues.ScreenSaveTimeOut
} catch {
    # 레지스트리 없음
}

# 판단: 화면보호기 활성 + 10분(600초) 이하 + 암호 보호
$isActive = ($screenSaveActive -eq "1")
$isSecure = ($screenSaverIsSecure -eq "1")
$isTimeoutOK = ($screenSaveTimeOut -and [int]$screenSaveTimeOut -le 600)

if ($isActive -and $isSecure -and $isTimeoutOK) {
    $RES = "Y"
    $DESC = "화면보호기가 적절히 설정되어 양호"
} else {
    $RES = "N"
    $issues = @()
    if (-not $isActive) { $issues += "화면보호기 비활성" }
    if (-not $isSecure) { $issues += "암호 보호 미설정" }
    if (-not $isTimeoutOK) { $issues += "대기 시간 10분 초과" }
    $DESC = "화면보호기 설정 미흡 ($($issues -join ', '))"
}

$timeoutMin = if ($screenSaveTimeOut) { [math]::Round([int]$screenSaveTimeOut / 60, 1) } else { "N/A" }
$DT = "ScreenSaveActive: $screenSaveActive`nScreenSaverIsSecure: $screenSaverIsSecure`nScreenSaveTimeOut: $screenSaveTimeOut 초 ($timeoutMin 분)"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check17 {
    $CODE = "PC-17"
    $CAT = "보안관리"
    $NAME = "CD, DVD, USB 메모리 등과 같은 미디어의 자동 실행 방지 등 이동식 미디어에 대한 보안대책 수립"
    $IMP = "상"
    $STD = "미디어 사용 시 자동 실행되지 않고 내부적으로 관리 절차를 수립하여 이행된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$noDriveTypeAutoRun = $null

try {
    $regValue = Get-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    if ($regValue) {
        $noDriveTypeAutoRun = $regValue.NoDriveTypeAutoRun
    }
} catch {
    # 레지스트리 없음
}

# 판단: NoDriveTypeAutoRun이 255이면 모든 드라이브 자동 실행 방지
if ($noDriveTypeAutoRun -eq 255) {
    $RES = "Y"
    $DESC = "이동식 미디어 자동 실행이 방지되어 양호"
} else {
    $RES = "N"
    $DESC = "이동식 미디어 자동 실행이 방지되지 않아 취약"
}

if ($null -eq $noDriveTypeAutoRun) {
    $DT = "NoDriveTypeAutoRun: 미설정 (기본값: 자동실행 허용)"
} else {
    $DT = "NoDriveTypeAutoRun: $noDriveTypeAutoRun (255=모두 차단)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check18 {
    $CODE = "PC-18"
    $CAT = "보안관리"
    $NAME = "원격 지원을 금지하도록 정책이 설정"
    $IMP = "중"
    $STD = "원격 지원이 `"사용 안 함`"으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$fAllowToGetHelp = $null
$fAllowUnsolicited = $null
$fAllowUnsolicitedFullControl = $null

try {
    $regItem = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if ($regItem) {
        if ($null -ne $regItem.fAllowToGetHelp) {
            $fAllowToGetHelp = $regItem.fAllowToGetHelp
        }
        if ($null -ne $regItem.fAllowUnsolicited) {
            $fAllowUnsolicited = $regItem.fAllowUnsolicited
        }
        if ($null -ne $regItem.fAllowUnsolicitedFullControl) {
            $fAllowUnsolicitedFullControl = $regItem.fAllowUnsolicitedFullControl
        }
    }
} catch {
    # 레지스트리 없음
}

# 판단: GPO 값이 있으면 GPO 기준으로 판정
$gpoConfigured = ($null -ne $fAllowToGetHelp) -or ($null -ne $fAllowUnsolicited) -or ($null -ne $fAllowUnsolicitedFullControl)

if ($gpoConfigured) {
    # 1순위: GPO 경로에 값 존재 → GPO 기준 판정
    $isVulnerable = ($fAllowToGetHelp -eq 1) -or ($fAllowUnsolicited -eq 1) -or ($fAllowUnsolicitedFullControl -eq 1)
    if ($isVulnerable) {
        $RES = "N"
        $DESC = "GPO에서 원격 지원이 허용되어 취약"
    } else {
        $RES = "Y"
        $DESC = "GPO에서 원격 지원이 금지되어 양호"
    }
} else {
    # [FIX] 2순위: GPO 미설정 시 시스템 레지스트리 확인
    $sysRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    $sysFAllowToGetHelp = $null
    try {
        $sysRegItem = Get-ItemProperty -Path $sysRegPath -ErrorAction SilentlyContinue
        if ($sysRegItem -and $null -ne $sysRegItem.fAllowToGetHelp) {
            $sysFAllowToGetHelp = $sysRegItem.fAllowToGetHelp
        }
    } catch {}

    if ($sysFAllowToGetHelp -eq 1) {
        # [FIX] 시스템 설정에서 원격 지원 활성화 → 취약
        $RES = "N"
        $DESC = "시스템 설정에서 원격 지원이 허용되어 취약"
    } else {
        $RES = "Y"
        $DESC = "원격 지원이 금지되어 양호"
    }
}

$dtList = @()
$dtList += "[GPO] fAllowToGetHelp: $(if($null -eq $fAllowToGetHelp){'미설정'}else{$fAllowToGetHelp})"
$dtList += "[GPO] fAllowUnsolicited: $(if($null -eq $fAllowUnsolicited){'미설정'}else{$fAllowUnsolicited})"
$dtList += "[GPO] fAllowUnsolicitedFullControl: $(if($null -eq $fAllowUnsolicitedFullControl){'미설정'}else{$fAllowUnsolicitedFullControl})"
# [FIX] 시스템 레지스트리 정보도 DT에 기록
if (-not $gpoConfigured) {
    $dtList += "[시스템] fAllowToGetHelp: $(if($null -eq $sysFAllowToGetHelp){'미설정'}else{$sysFAllowToGetHelp})"
}
$dtList += ""
$dtList += "※ GPO 설정 우선 적용. GPO 미설정 시 시스템 레지스트리 참조"
$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}


#================================================================
# EXECUTE
#================================================================
Write-Host "[*] 진단 시작..."

[void]$script:xmlBuilder.Append(@"
<?xml version="1.0" encoding="UTF-8"?>
<seedgen>
    <meta>
        <date>$META_DATE</date>
        <ver>$META_VER</ver>
        <plat>$META_PLAT</plat>
        <type>$META_TYPE</type>
        <std>$META_STD</std>
        <user>
            <dept>$USER_DEPT</dept>
            <name>$USER_NAME</name>
        </user>
    </meta>
    <sys>
        <host>$SYS_HOST</host>
        <dom>$SYS_DOM</dom>
        <os>
            <n>$SYS_OS_NAME</n>
            <fn>$SYS_OS_FN</fn>
        </os>
        <kn>$SYS_KN</kn>
        <arch>$SYS_ARCH</arch>
        <net>
            <ip>$SYS_IP</ip>
            <all><![CDATA[$SYS_NET_ALL]]></all>
        </net>
    </sys>
    <results>

"@)

# 진단 실행
    Check01
    Check02
    Check03
    Check04
    Check05
    Check06
    Check07
    Check08
    Check09
    Check10
    Check11
    Check12
    Check13
    Check14
    Check15
    Check16
    Check17
    Check18

# XML 종료
[void]$script:xmlBuilder.Append(@"
    </results>
</seedgen>
"@)

#================================================================
# CLEANUP
#================================================================
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OUTPUT_FILE, $script:xmlBuilder.ToString(), $utf8NoBom)

Write-Host ""
Write-Host "[완료] 결과 파일: $OUTPUT_FILE"
Write-Host ""
Read-Host "아무 키나 누르면 종료됩니다"

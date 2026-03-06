#================================================================
# Windows Server 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Windows Server 2016, 2019, 2022
# 항목  : W-01 ~ W-64 (64개)
# 제작  : Seedgen
#================================================================
$META_STD = "KISA"

#================================================================
# 관리자 권한 자동 승격
#================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process PowerShell -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`"" -Verb RunAs -Wait
    exit
}

#================================================================
# INIT
#================================================================
chcp 65001 | Out-Null
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$META_VER = "1.0"
$META_PLAT = "Windows"
$META_TYPE = "Server"

# secedit 정책 내보내기
$SECPOL_PATH = "$env:TEMP\secpol_$([guid]::NewGuid().ToString('N')).cfg"
secedit /export /cfg $SECPOL_PATH /quiet 2>$null
$SECPOL_CONTENT = if (Test-Path $SECPOL_PATH) { Get-Content $SECPOL_PATH -ErrorAction SilentlyContinue } else { @() }

# XML StringBuilder
$script:xmlBuilder = New-Object System.Text.StringBuilder

# 결과 출력 함수
function Output-Checkpoint {
    param(
        [string]$CODE, [string]$CAT, [string]$NAME, [string]$IMP,
        [string]$STD, [string]$RES, [string]$DESC, [string]$DT
    )

    # 콘솔 출력
    switch ($RES) {
        "Y"   { Write-Host "    [$([char]0x1b)[32mY$([char]0x1b)[0m] $CODE $NAME" }
        "N"   { Write-Host "    [$([char]0x1b)[31mN$([char]0x1b)[0m] $CODE $NAME" }
        "M"   { Write-Host "    [$([char]0x1b)[33mM$([char]0x1b)[0m] $CODE $NAME" }
        "N/A" { Write-Host "    [$([char]0x1b)[90m-$([char]0x1b)[0m] $CODE $NAME" }
        default { Write-Host "    [-] $CODE $NAME" }
    }

    # XML 이스케이프
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

# 헬퍼 함수
function Get-SecpolValue {
    param([string]$Pattern)
    $line = $SECPOL_CONTENT | Select-String -Pattern "^\s*$Pattern\s*=" | Select-Object -First 1
    if ($line) { return ($line -split "=")[1].Trim() }
    return $null
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $item -and $null -ne $item.$Name) { return $item.$Name.ToString() }
    } catch {}
    return $null
}

#================================================================
# COLLECT
#================================================================
Write-Host "[*] 시스템 정보 수집 중..."

$META_DATE = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$SYS_HOST = $env:COMPUTERNAME
$SYS_DOM = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain
if (-not $SYS_DOM) { $SYS_DOM = "WORKGROUP" }

$SYS_OS_NAME = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
$SYS_OS_FN = $SYS_OS_NAME -replace "Microsoft ", "" -replace " Datacenter| Standard| Enterprise| Essentials", ""

$osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$SYS_KN = $osInfo.Version
$SYS_ARCH = $osInfo.OSArchitecture

# 대표 IP (가상 인터페이스 제외)
$virtualPatterns = @("WSL","Hyper-V","vEthernet","VPN","Bluetooth","Loopback","VMware","VirtualBox","Docker")
$allIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
    $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*"
}
$realIPs = $allIPs | Where-Object {
    $alias = $_.InterfaceAlias
    -not ($virtualPatterns | Where-Object { $alias -like "*$_*" })
}
$SYS_IP = if ($realIPs) { ($realIPs | Select-Object -First 1).IPAddress } else { ($allIPs | Select-Object -First 1).IPAddress }
if (-not $SYS_IP) { $SYS_IP = "N/A" }
$SYS_NET_ALL = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)" }) -join "`n"

$OUTPUT_FILE = Join-Path $PSScriptRoot "${META_PLAT}_${SYS_HOST}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"

Write-Host "[*] 호스트: $SYS_HOST"
Write-Host "[*] OS: $SYS_OS_FN"
Write-Host "[*] IP: $SYS_IP"

#================================================================
# CHECK FUNCTIONS
#================================================================

function Check01 {
    $CODE = "W-01"
    $CAT = "계정관리"
    $NAME = "Administrator 계정 이름 변경 등 보안성 강화"
    $IMP = "상"
    $STD = "Administrator 기본 계정 이름을 변경하거나 강화된 비밀번호를 적용한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$adminName = Get-SecpolValue "NewAdministratorName"
$adminName = $adminName -replace '"', ''

if ([string]::IsNullOrEmpty($adminName) -or $adminName -ieq "Administrator") {
    $RES = "N"
    $DESC = "Administrator 기본 계정 이름이 변경되지 않음"
    $DT = "Administrator 계정명: Administrator (기본값)"
} else {
    $RES = "Y"
    $DESC = "Administrator 계정 이름이 변경됨"
    $DT = "Administrator 계정명: $adminName"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check02 {
    $CODE = "W-02"
    $CAT = "계정관리"
    $NAME = "Guest 계정 비활성화"
    $IMP = "상"
    $STD = "Guest 계정이 비활성화되어 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$guestEnabled = Get-SecpolValue "EnableGuestAccount"

if ($guestEnabled -eq "0") {
    $RES = "Y"
    $DESC = "Guest 계정이 비활성화되어 있음"
    $DT = "EnableGuestAccount: 0 (비활성화)"
} else {
    $RES = "N"
    $DESC = "Guest 계정이 활성화되어 있음"
    $DT = "EnableGuestAccount: $guestEnabled (활성화)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check03 {
    $CODE = "W-03"
    $CAT = "계정관리"
    $NAME = "불필요한 계정 제거"
    $IMP = "상"
    $STD = "불필요한 계정이 존재하지 않는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    $users = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, Description
    $userList = ($users | ForEach-Object { "$($_.Name) (Enabled: $($_.Enabled))" }) -join "`n"

    $RES = "M"
    $DESC = "계정 목록 수동 확인 필요"
    $DT = "로컬 사용자 계정 목록:`n$userList"
} catch {
    $RES = "M"
    $DESC = "계정 목록 조회 실패"
    $DT = "오류: $($_.Exception.Message)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check04 {
    $CODE = "W-04"
    $CAT = "계정관리"
    $NAME = "계정 잠금 임계값 설정"
    $IMP = "상"
    $STD = "계정 잠금 임계값이 5 이하의 값으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$lockoutBadCount = Get-SecpolValue "LockoutBadCount"

if ([string]::IsNullOrEmpty($lockoutBadCount)) {
    $RES = "N"
    $DESC = "계정 잠금 임계값이 설정되지 않음"
    $DT = "LockoutBadCount: Not Set"
} elseif ($lockoutBadCount -match "^\d+$") {
    $value = [int]$lockoutBadCount
    if ($value -gt 0 -and $value -le 5) {
        $RES = "Y"
        $DESC = "계정 잠금 임계값이 적절히 설정됨"
        $DT = "계정 잠금 임계값: ${value}회 (기준: 5회 이하)"
    } else {
        $RES = "N"
        $DESC = "계정 잠금 임계값이 미흡함"
        $DT = "계정 잠금 임계값: ${value}회 (기준: 5회 이하)"
    }
} else {
    $RES = "N"
    $DESC = "계정 잠금 임계값 설정 확인 필요"
    $DT = "LockoutBadCount: $lockoutBadCount"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check05 {
    $CODE = "W-05"
    $CAT = "계정관리"
    $NAME = "해독 가능한 암호화를 사용하여 암호 저장 해제"
    $IMP = "상"
    $STD = "`"해독 가능한 암호화를 사용하여 암호 저장`" 정책이 `"사용 안 함`"으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$clearTextPwd = Get-SecpolValue "ClearTextPassword"

if ($clearTextPwd -eq "0") {
    $RES = "Y"
    $DESC = "해독 가능한 암호화 사용 안 함"
    $DT = "ClearTextPassword: 0 (사용 안 함)"
} else {
    $RES = "N"
    $DESC = "해독 가능한 암호화가 사용됨"
    $DT = "ClearTextPassword: $clearTextPwd (사용)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check06 {
    $CODE = "W-06"
    $CAT = "계정관리"
    $NAME = "관리자 그룹에 최소한의 사용자 포함"
    $IMP = "상"
    $STD = "Administrators 그룹의 구성원을 1명 이하로 유지하거나, 불필요한 관리자 계정이 존재하지 않 는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $adminList = ($admins | ForEach-Object { $_.Name }) -join "`n"
    $adminCount = $admins.Count

    $RES = "M"
    $DESC = "Administrators 그룹 구성원 ${adminCount}명 - 수동 확인 필요"
    $DT = "Administrators 그룹 구성원 (${adminCount}명):`n$adminList"
} catch {
    $RES = "M"
    $DESC = "관리자 그룹 조회 실패"
    $DT = "오류: $($_.Exception.Message)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check07 {
    $CODE = "W-07"
    $CAT = "계정관리"
    $NAME = "Everyone 사용 권한을 익명 사용자에 적용"
    $IMP = "중"
    $STD = "`"Everyone 사용 권한을 익명 사용자에게 적용`" 정책이 `"사용 안 함`"으로 되어 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 및 레지스트리에서 값 확인
$everyoneAnon = Get-SecpolValue "EveryoneIncludesAnonymous"
if ([string]::IsNullOrEmpty($everyoneAnon)) {
    $everyoneAnon = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous"
}

if ($everyoneAnon -eq "1") {
    $RES = "N"
    $DESC = "Everyone 사용 권한이 익명 사용자에 적용됨"
    $DT = "EveryoneIncludesAnonymous: 1 (사용)"
} elseif ($everyoneAnon -eq "0") {
    $RES = "Y"
    $DESC = "Everyone 사용 권한을 익명 사용자에 적용하지 않음"
    $DT = "EveryoneIncludesAnonymous: 0 (사용 안 함)"
} else {
    $RES = "Y"
    $DESC = "Everyone 사용 권한을 익명 사용자에 적용하지 않음 (기본값)"
    $DT = "EveryoneIncludesAnonymous: Not Set (기본값 0)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check08 {
    $CODE = "W-08"
    $CAT = "계정관리"
    $NAME = "계정 잠금 기간 설정"
    $IMP = "중"
    $STD = "`"계정 잠금 기간`" 및 `"계정 잠금 기간 원래대로 설정 기간`"이 60분 이상으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$lockoutDuration = Get-SecpolValue "LockoutDuration"
$resetLockout = Get-SecpolValue "ResetLockoutCount"

$dtList = @()
$isVulnerable = $false

if ([string]::IsNullOrEmpty($lockoutDuration)) {
    $dtList += "LockoutDuration: Not Set"
    $isVulnerable = $true
} elseif ([int]$lockoutDuration -ge 60) {
    $dtList += "계정 잠금 기간: ${lockoutDuration}분 (양호)"
} else {
    $dtList += "계정 잠금 기간: ${lockoutDuration}분 (기준: 60분 이상)"
    $isVulnerable = $true
}

if ([string]::IsNullOrEmpty($resetLockout)) {
    $dtList += "ResetLockoutCount: Not Set"
    $isVulnerable = $true
} elseif ([int]$resetLockout -ge 60) {
    $dtList += "잠금 카운터 원래대로 설정: ${resetLockout}분 (양호)"
} else {
    $dtList += "잠금 카운터 원래대로 설정: ${resetLockout}분 (기준: 60분 이상)"
    $isVulnerable = $true
}

if ($isVulnerable) {
    $RES = "N"
    $DESC = "계정 잠금 기간 설정이 미흡함"
} else {
    $RES = "Y"
    $DESC = "계정 잠금 기간이 적절히 설정됨"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check09 {
    $CODE = "W-09"
    $CAT = "계정관리"
    $NAME = "비밀번호 관리 정책 설정"
    $IMP = "상"
    $STD = "계정 비밀번호 관리 정책이 모두 적용된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$complexity = Get-SecpolValue "PasswordComplexity"
$minLength = Get-SecpolValue "MinimumPasswordLength"
$maxAge = Get-SecpolValue "MaximumPasswordAge"
$minAge = Get-SecpolValue "MinimumPasswordAge"
$history = Get-SecpolValue "PasswordHistorySize"

$dtList = @()
$vulnerableCount = 0

# 복잡성
if ($complexity -eq "1") {
    $dtList += "암호 복잡성: 사용 (양호)"
} else {
    $dtList += "암호 복잡성: 사용 안 함 (취약)"
    $vulnerableCount++
}

# 최소 길이
if ([string]::IsNullOrEmpty($minLength) -or [int]$minLength -lt 8) {
    $dtList += "최소 암호 길이: ${minLength}자 (기준: 8자 이상)"
    $vulnerableCount++
} else {
    $dtList += "최소 암호 길이: ${minLength}자 (양호)"
}

# 최대 사용 기간
if ([string]::IsNullOrEmpty($maxAge) -or [int]$maxAge -gt 90 -or [int]$maxAge -eq 0) {
    $dtList += "최대 암호 사용 기간: ${maxAge}일 (기준: 90일 이하)"
    $vulnerableCount++
} else {
    $dtList += "최대 암호 사용 기간: ${maxAge}일 (양호)"
}

# 최소 사용 기간
if ([string]::IsNullOrEmpty($minAge) -or [int]$minAge -lt 1) {
    $dtList += "최소 암호 사용 기간: ${minAge}일 (기준: 1일 이상)"
    $vulnerableCount++
} else {
    $dtList += "최소 암호 사용 기간: ${minAge}일 (양호)"
}

# 암호 기억
if ([string]::IsNullOrEmpty($history) -or [int]$history -lt 4) {
    $dtList += "최근 암호 기억: ${history}개 (기준: 4개 이상)"
    $vulnerableCount++
} else {
    $dtList += "최근 암호 기억: ${history}개 (양호)"
}

if ($vulnerableCount -eq 0) {
    $RES = "Y"
    $DESC = "비밀번호 관리 정책이 모두 적절히 설정됨"
} else {
    $RES = "N"
    $DESC = "비밀번호 관리 정책 ${vulnerableCount}개 항목 미흡"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check10 {
    $CODE = "W-10"
    $CAT = "계정관리"
    $NAME = "마지막 사용자 이름 표시 안 함"
    $IMP = "중"
    $STD = "`"마지막 사용자 이름 표시 안 함`"이 `"사용`"으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 및 레지스트리에서 값 확인
$dontDisplay = Get-SecpolValue "DontDisplayLastUserName"
if ([string]::IsNullOrEmpty($dontDisplay)) {
    $dontDisplay = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
}

if ($dontDisplay -eq "1") {
    $RES = "Y"
    $DESC = "마지막 사용자 이름 표시 안 함이 설정됨"
    $DT = "DontDisplayLastUserName: 1 (사용)"
} elseif ($dontDisplay -eq "0") {
    $RES = "N"
    $DESC = "마지막 사용자 이름이 표시됨"
    $DT = "DontDisplayLastUserName: 0 (사용 안 함)"
} else {
    $RES = "N"
    $DESC = "마지막 사용자 이름이 표시됨 (기본값)"
    $DT = "DontDisplayLastUserName: Not Set (기본값 0)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check11 {
    $CODE = "W-11"
    $CAT = "계정관리"
    $NAME = "로컬 로그온 허용"
    $IMP = "중"
    $STD = "로컬 로그온 허용 정책에 Administrators, IUSR_ 만 존재하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$logonRight = Get-SecpolValue "SeInteractiveLogonRight"

if ([string]::IsNullOrEmpty($logonRight)) {
    $RES = "M"
    $DESC = "로컬 로그온 허용 정책 확인 필요"
    $DT = "SeInteractiveLogonRight: Not Set"
} else {
    $RES = "M"
    $DESC = "로컬 로그온 허용 사용자 수동 확인 필요"
    $DT = "SeInteractiveLogonRight: $logonRight`n(권장: Administrators, IUSR_ 만 허용)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check12 {
    $CODE = "W-12"
    $CAT = "계정관리"
    $NAME = "익명 SID/이름 변환 허용 해제"
    $IMP = "중"
    $STD = "`"익명 SID/이름 변환 허용`" 정책이 `"사용 안 함`"으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$lsaAnon = Get-SecpolValue "LSAAnonymousNameLookup"

if ($lsaAnon -eq "0" -or [string]::IsNullOrEmpty($lsaAnon)) {
    $RES = "Y"
    $DESC = "익명 SID/이름 변환이 허용되지 않음"
    $DT = "LSAAnonymousNameLookup: 0 (사용 안 함)"
} else {
    $RES = "N"
    $DESC = "익명 SID/이름 변환이 허용됨"
    $DT = "LSAAnonymousNameLookup: $lsaAnon (사용)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check13 {
    $CODE = "W-13"
    $CAT = "계정관리"
    $NAME = "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한"
    $IMP = "중"
    $STD = "`"콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한`" 정책이 `"사용`"인 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 및 레지스트리에서 값 확인
$limitBlank = Get-SecpolValue "LimitBlankPasswordUse"
if ([string]::IsNullOrEmpty($limitBlank)) {
    $limitBlank = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
}

if ($limitBlank -eq "0") {
    $RES = "N"
    $DESC = "빈 암호 사용이 허용됨"
    $DT = "LimitBlankPasswordUse: 0 (사용 안 함)"
} elseif ($limitBlank -eq "1") {
    $RES = "Y"
    $DESC = "빈 암호 사용이 제한됨"
    $DT = "LimitBlankPasswordUse: 1 (사용)"
} else {
    $RES = "Y"
    $DESC = "빈 암호 사용이 제한됨 (기본값)"
    $DT = "LimitBlankPasswordUse: Not Set (기본값 1)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check14 {
    $CODE = "W-14"
    $CAT = "계정관리"
    $NAME = "원격터미널 접속 가능한 사용자 그룹 제한"
    $IMP = "중"
    $STD = "(관리자 계정을 제외한) 원격 접속이 가능한 계정을 생성하여 타 사용자의 원격 접속을 제한하고, 원격 접속 사용자 그룹에 불필요한 계정이 등록되어 있지 않은 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction Stop
    if ($rdpUsers.Count -eq 0) {
        $RES = "M"
        $DESC = "Remote Desktop Users 그룹에 구성원 없음 - 수동 확인 필요"
        $DT = "Remote Desktop Users: 구성원 없음`n(관리자 외 별도 계정 생성 권장)"
    } else {
        $userList = ($rdpUsers | ForEach-Object { $_.Name }) -join "`n"
        $RES = "M"
        $DESC = "Remote Desktop Users 그룹 구성원 수동 확인 필요"
        $DT = "Remote Desktop Users 그룹 구성원:`n$userList"
    }
} catch {
    $RES = "M"
    $DESC = "Remote Desktop Users 그룹 조회 실패"
    $DT = "오류: $($_.Exception.Message)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check15 {
    $CODE = "W-15"
    $CAT = "서비스관리"
    $NAME = "사용자 개인키 사용 시 암호 입력"
    $IMP = "상"
    $STD = "사용자 개인 키를 사용할 때마다 암호 입력을 받는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 및 레지스트리에서 값 확인
$forceKeyProtection = Get-SecpolValue "ForceKeyProtection"
if ([string]::IsNullOrEmpty($forceKeyProtection)) {
    # Group Policy 경로 확인
    $forceKeyProtection = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" "ForceKeyProtection"
}
if ([string]::IsNullOrEmpty($forceKeyProtection)) {
    # 직접 설정 경로 확인
    $forceKeyProtection = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Cryptography\Protect\Providers\df9d8cd0-1501-11d1-8c7a-00c04fc297eb" "ForceKeyProtection"
}

if ($forceKeyProtection -eq "2") {
    $RES = "Y"
    $DESC = "키를 사용할 때마다 암호 입력이 설정됨"
    $DT = "ForceKeyProtection: 2 (키를 사용할 때마다 암호 입력)"
} elseif ($forceKeyProtection -eq "1") {
    $RES = "N"
    $DESC = "키 보호 수준이 낮음"
    $DT = "ForceKeyProtection: 1 (새 키를 저장할 때 알림)"
} elseif ($forceKeyProtection -eq "0") {
    $RES = "N"
    $DESC = "키 보호가 설정되지 않음"
    $DT = "ForceKeyProtection: 0 (사용자 입력 필요 없음)"
} else {
    $RES = "N"
    $DESC = "키 보호가 설정되지 않음"
    $DT = "ForceKeyProtection: Not Set (권장: 2)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check16 {
    $CODE = "W-16"
    $CAT = "서비스관리"
    $NAME = "공유 권한 및 사용자 그룹 설정"
    $IMP = "상"
    $STD = "일반 공유 디렉터리가 없거나 공유 디렉터리 접근 권한에 Everyone 권한이 없는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    $shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notlike "*$" }
    if ($shares.Count -eq 0) {
        $RES = "Y"
        $DESC = "일반 공유 디렉터리가 존재하지 않음"
        $DT = "일반 공유 폴더: 없음"
    } else {
        $everyoneShares = @()
        foreach ($share in $shares) {
            $access = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            $everyoneAccess = $access | Where-Object { $_.AccountName -eq "Everyone" }
            if ($everyoneAccess) { $everyoneShares += "$($share.Name)" }
        }
        if ($everyoneShares.Count -eq 0) {
            $RES = "Y"
            $DESC = "공유 디렉터리에 Everyone 권한이 없음"
            $DT = "일반 공유 폴더: $($shares.Name -join ', ')"
        } else {
            $RES = "N"
            $DESC = "공유 디렉터리에 Everyone 권한이 존재함"
            $DT = "Everyone 권한 공유: $($everyoneShares -join ', ')"
        }
    }
} catch {
    $RES = "M"
    $DESC = "공유 디렉터리 확인 필요"
    $DT = "오류: $($_.Exception.Message)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check17 {
    $CODE = "W-17"
    $CAT = "서비스관리"
    $NAME = "하드디스크 기본 공유 제거"
    $IMP = "상"
    $STD = "레지스트리의 AutoShareServer (WinNT: AutoShareWks)가 0이며 기본 공유가 존재하지 않 는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
$autoShare = Get-ItemProperty -Path $regPath -Name "AutoShareServer" -ErrorAction SilentlyContinue
$defaultShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$" -and $_.Name -notlike "IPC$" }

if ($autoShare.AutoShareServer -eq 0 -and $defaultShares.Count -eq 0) {
    $RES = "Y"
    $DESC = "기본 공유가 제거됨"
    $DT = "AutoShareServer: 0, 기본 공유: 없음"
} else {
    $RES = "N"
    $DESC = "기본 공유가 존재함"
    $shareList = ($defaultShares | ForEach-Object { $_.Name }) -join ", "
    $DT = "AutoShareServer: $($autoShare.AutoShareServer)`n기본 공유: $shareList"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check18 {
    $CODE = "W-18"
    $CAT = "서비스관리"
    $NAME = "불필요한 서비스 제거"
    $IMP = "상"
    $STD = "일반적으로 불필요한 서비스(아래 목록 참조)가 중지된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$unnecessaryServices = @("Alerter", "ClipSrv", "Messenger", "RemoteRegistry", "simptcp", "TlntSvr")
$runningUnnecessary = @()

foreach ($svcName in $unnecessaryServices) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") { $runningUnnecessary += $svcName }
}

if ($runningUnnecessary.Count -eq 0) {
    $RES = "Y"
    $DESC = "불필요한 서비스가 실행되지 않음"
    $DT = "점검 대상: $($unnecessaryServices -join ', ')"
} else {
    $RES = "N"
    $DESC = "불필요한 서비스가 실행 중"
    $DT = "실행 중인 불필요 서비스: $($runningUnnecessary -join ', ')"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check19 {
    $CODE = "W-19"
    $CAT = "서비스관리"
    $NAME = "불필요한 IIS 서비스 구동 점검"
    $IMP = "상"
    $STD = "IIS 서비스를 사용하지 않는 경우 또는 필요에 의해 IIS 서비스를 사용하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$iisSvc = Get-Service -Name "W3SVC", "IISADMIN" -ErrorAction SilentlyContinue
$runningIIS = $iisSvc | Where-Object { $_.Status -eq "Running" }

if (-not $iisSvc) {
    $RES = "Y"
    $DESC = "IIS 서비스가 설치되어 있지 않음"
    $DT = "W3SVC, IISADMIN: 미설치"
} elseif ($runningIIS) {
    $RES = "M"
    $DESC = "IIS 서비스 실행 중 - 필요 여부 확인 필요"
    $DT = "IIS 상태: 실행 중"
} else {
    $RES = "Y"
    $DESC = "IIS 서비스가 중지됨"
    $DT = "IIS 상태: 중지"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check20 {
    $CODE = "W-20"
    $CAT = "서비스관리"
    $NAME = "NetBIOS 바인딩 서비스 구동 점검"
    $IMP = "상"
    $STD = "TCP/IP와 NetBIOS 간의 바인딩이 제거되어 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    # 활성 네트워크 어댑터의 GUID 목록 가져오기
    $activeAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty SettingID

    # 레지스트리에서 인터페이스 목록 가져오기
    $interfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
    $interfaces = Get-ChildItem -Path $interfacesPath -ErrorAction SilentlyContinue

    $dtList = @()
    $enabledCount = 0
    $activeCount = 0

    foreach ($iface in $interfaces) {
        $ifaceGuid = $iface.PSChildName -replace "Tcpip_", ""
        $isActive = $activeAdapters -contains $ifaceGuid

        $nbOption = Get-ItemProperty -Path $iface.PSPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue
        # NetbiosOptions: 0=DHCP, 1=Enable, 2=Disable
        $nbValue = if ($null -eq $nbOption) { 0 } else { $nbOption.NetbiosOptions }
        $nbStatus = switch ($nbValue) {
            0 { "DHCP" }
            1 { "Enable" }
            2 { "Disable" }
            default { "Unknown($nbValue)" }
        }

        if ($isActive) {
            $activeCount++
            $dtList += "[활성] $ifaceGuid : NetbiosOptions=$nbStatus"
            if ($nbValue -ne 2) { $enabledCount++ }
        } else {
            $dtList += "[비활성] $ifaceGuid : NetbiosOptions=$nbStatus"
        }
    }

    if ($activeCount -eq 0) {
        $RES = "M"
        $DESC = "활성 네트워크 어댑터 확인 필요"
        $DT = "활성 어댑터를 찾을 수 없음`n" + ($dtList -join "`n")
    } elseif ($enabledCount -eq 0) {
        $RES = "Y"
        $DESC = "활성 어댑터에서 NetBIOS 비활성화됨"
        $DT = "활성 어댑터: ${activeCount}개, NetBIOS 사용: 0개`n" + ($dtList -join "`n")
    } else {
        $RES = "N"
        $DESC = "활성 어댑터에서 NetBIOS 활성화됨"
        $DT = "활성 어댑터: ${activeCount}개, NetBIOS 사용: ${enabledCount}개`n" + ($dtList -join "`n")
    }
} catch {
    $RES = "M"
    $DESC = "NetBIOS 설정 확인 필요"
    $DT = "조회 실패: $($_.Exception.Message)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check21 {
    $CODE = "W-21"
    $CAT = "서비스관리"
    $NAME = "암호화되지 않는 FTP 서비스 비활성화"
    $IMP = "상"
    $STD = "FTP 서비스를 사용하지 않는 경우 또는 Secure FTP 서비스를 사용하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$ftpSvc = Get-Service -Name "FTPSVC", "MSFTPSVC" -ErrorAction SilentlyContinue
$runningFTP = $ftpSvc | Where-Object { $_.Status -eq "Running" }

if (-not $ftpSvc) {
    $RES = "Y"
    $DESC = "FTP 서비스가 설치되어 있지 않음"
    $DT = "FTP 서비스: 미설치"
} elseif ($runningFTP) {
    $RES = "N"
    $DESC = "FTP 서비스가 실행 중 (SFTP/FTPS 권장)"
    $DT = "FTP 서비스: 실행 중"
} else {
    $RES = "Y"
    $DESC = "FTP 서비스가 중지됨"
    $DT = "FTP 서비스: 중지"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check22 {
    $CODE = "W-22"
    $CAT = "서비스관리"
    $NAME = "FTP 디렉토리 접근권한 설정"
    $IMP = "상"
    $STD = "FTP 홈 디렉터리에 Everyone 권한이 없는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$ftpSvc = Get-Service -Name "FTPSVC", "MSFTPSVC" -ErrorAction SilentlyContinue

if (-not $ftpSvc) {
    $RES = "N/A"
    $DESC = "FTP 서비스 미설치"
    $DT = "FTP 서비스: 미설치"
} else {
    $ftpPath = "C:\inetpub\ftproot"
    if (Test-Path $ftpPath) {
        $acl = Get-Acl $ftpPath -ErrorAction SilentlyContinue
        $everyone = $acl.Access | Where-Object { $_.IdentityReference -like "*Everyone*" }
        if ($everyone) {
            $RES = "N"
            $DESC = "FTP 홈 디렉터리에 Everyone 권한 존재"
            $DT = "FTP 경로: $ftpPath`nEveryone 권한: 존재"
        } else {
            $RES = "Y"
            $DESC = "FTP 홈 디렉터리에 Everyone 권한 없음"
            $DT = "FTP 경로: $ftpPath`nEveryone 권한: 없음"
        }
    } else {
        $RES = "M"
        $DESC = "FTP 홈 디렉터리 확인 필요"
        $DT = "기본 경로 존재하지 않음"
    }
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check23 {
    $CODE = "W-23"
    $CAT = "서비스관리"
    $NAME = "공유 서비스에 대한 익명 접근 제한 설정"
    $IMP = "상"
    $STD = "공유 서비스를 사용하지 않거나, 익명 인증 사용 안 함으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$ftpSvc = Get-Service -Name "FTPSVC", "MSFTPSVC" -ErrorAction SilentlyContinue

if (-not $ftpSvc -or $ftpSvc.Status -ne "Running") {
    $RES = "N/A"
    $DESC = "FTP 서비스 미실행"
    $DT = "FTP 서비스: 미실행 또는 미설치"
} else {
    $RES = "M"
    $DESC = "FTP 익명 인증 설정 수동 확인 필요"
    $DT = "IIS 관리자에서 FTP 인증 설정 확인 필요"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check24 {
    $CODE = "W-24"
    $CAT = "서비스관리"
    $NAME = "FTP 접근 제어 설정"
    $IMP = "상"
    $STD = "특정 IP주소에서만 FTP 서버에 접속하도록 접근 제어 설정을 적용한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$ftpSvc = Get-Service -Name "FTPSVC", "MSFTPSVC" -ErrorAction SilentlyContinue

if (-not $ftpSvc -or $ftpSvc.Status -ne "Running") {
    $RES = "N/A"
    $DESC = "FTP 서비스 미실행"
    $DT = "FTP 서비스: 미실행 또는 미설치"
} else {
    $RES = "M"
    $DESC = "FTP IP 접근 제어 설정 수동 확인 필요"
    $DT = "IIS 관리자에서 IP 제한 설정 확인 필요"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check25 {
    $CODE = "W-25"
    $CAT = "서비스관리"
    $NAME = "DNS Zone Transfer 설정"
    $IMP = "상"
    $STD = "아래 기준에 해당하는 경우 1. DNS 서비스가 비활성화인 경우 2. 영역 전송 허용을 하지 않는 경우 3. 특정 서버로만 설정이 되어있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dnsSvc = Get-Service -Name "DNS" -ErrorAction SilentlyContinue

if (-not $dnsSvc) {
    $RES = "Y"
    $DESC = "DNS 서비스 미설치"
    $DT = "DNS 서비스: 미설치"
} elseif ($dnsSvc.Status -ne "Running") {
    $RES = "Y"
    $DESC = "DNS 서비스 중지됨"
    $DT = "DNS 서비스: 중지"
} else {
    $RES = "M"
    $DESC = "DNS Zone Transfer 설정 수동 확인 필요"
    $DT = "DNS 관리자에서 영역 전송 설정 확인 필요"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check26 {
    $CODE = "W-26"
    $CAT = "서비스관리"
    $NAME = "RDS(Remote Data Services)제거"
    $IMP = "상"
    $STD = "다음 중 한 가지라도 해당하는 경우 1. IIS를 사용하지 않는 경우 2. Windows 2008 이상 버전을 사용하는 경우 3. Windows 2000 서비스팩 4, Windows 2003 서비스팩 2 이상 설치된 경우 4. 기본 웹 사이트에 MSADC 가상 디렉터리가 존재하지 않는 경우 5. 해당 레지스트리 값이 존재하지 않는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$osVer = [System.Environment]::OSVersion.Version

if ($osVer.Major -ge 6) {
    $RES = "Y"
    $DESC = "Windows 2008 이상으로 해당 없음"
    $DT = "OS 버전: $($osVer.ToString())"
} else {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch"
    if (Test-Path $regPath) {
        $RES = "N"
        $DESC = "RDS 관련 레지스트리 존재"
        $DT = "ADCLaunch: 존재"
    } else {
        $RES = "Y"
        $DESC = "RDS 관련 레지스트리 없음"
        $DT = "ADCLaunch: 없음"
    }
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check27 {
    $CODE = "W-27"
    $CAT = "서비스관리"
    $NAME = "최신 Windows OS Build 버전 적용"
    $IMP = "상"
    $STD = "최신 Build가 설치되어 있으며 적용 절차 및 방법이 수립된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$osInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
$build = $osInfo.CurrentBuild
$ubr = $osInfo.UBR
$displayVer = $osInfo.DisplayVersion
$releaseId = $osInfo.ReleaseId
$productName = $osInfo.ProductName

# DisplayVersion이 없으면 ReleaseId로 대체 (Windows Server 2019 이하)
$versionInfo = if (-not [string]::IsNullOrEmpty($displayVer)) {
    $displayVer
} elseif (-not [string]::IsNullOrEmpty($releaseId)) {
    $releaseId
} else {
    "N/A"
}

$fullBuild = if ($ubr) { "$build.$ubr" } else { $build }

$RES = "M"
$DESC = "최신 Build 버전 수동 확인 필요"
$DT = "[OS 정보]`nProductName: $productName`nBuild: $fullBuild`nDisplayVersion: $(if ($displayVer) { $displayVer } else { '(없음)' })`nReleaseId: $(if ($releaseId) { $releaseId } else { '(없음)' })`n버전 식별: $versionInfo"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check28 {
    $CODE = "W-28"
    $CAT = "서비스관리"
    $NAME = "터미널 서비스 암호화 수준 설정"
    $IMP = "중"
    $STD = "원격 데스크톱 서비스를 사용하지 않거나 사용 시 암호화 수준을 `"클라이언트와 호환 가능(중간)`" 이상으로 설정한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$rdpSvc = Get-Service -Name "TermService" -ErrorAction SilentlyContinue

# GPO 경로 우선 확인, 없으면 로컬 설정 확인
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$localPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

$policyEnc = Get-ItemProperty -Path $policyPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
$localEnc = Get-ItemProperty -Path $localPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue

# GPO 설정이 우선 적용됨
$minEncLevel = $null
$source = ""
if ($null -ne $policyEnc.MinEncryptionLevel) {
    $minEncLevel = $policyEnc.MinEncryptionLevel
    $source = "GPO"
} elseif ($null -ne $localEnc.MinEncryptionLevel) {
    $minEncLevel = $localEnc.MinEncryptionLevel
    $source = "Local"
}

if (-not $rdpSvc -or $rdpSvc.Status -ne "Running") {
    $RES = "N/A"
    $DESC = "원격 데스크톱 서비스 미실행"
    $DT = "TermService: 미실행"
} elseif ($null -eq $minEncLevel) {
    $RES = "M"
    $DESC = "암호화 수준 설정 확인 필요"
    $DT = "MinEncryptionLevel: 미설정`nGPO: $policyPath`nLocal: $localPath"
} elseif ($minEncLevel -ge 2) {
    $RES = "Y"
    $DESC = "암호화 수준 적절"
    $DT = "MinEncryptionLevel: $minEncLevel (Source: $source)"
} else {
    $RES = "N"
    $DESC = "암호화 수준 낮음"
    $DT = "MinEncryptionLevel: $minEncLevel (권장: 2 이상, Source: $source)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check29 {
    $CODE = "W-29"
    $CAT = "서비스관리"
    $NAME = "불필요한 SNMP 서비스 구동 점검"
    $IMP = "중"
    $STD = "SNMP 서비스를 사용하지 않는 경우 또는 Community String을 설정하여 SNMP 서비스를 사용하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$snmpSvc = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue

if (-not $snmpSvc) {
    $RES = "Y"
    $DESC = "SNMP 서비스 미설치"
    $DT = "SNMP 서비스: 미설치"
} elseif ($snmpSvc.Status -ne "Running") {
    $RES = "Y"
    $DESC = "SNMP 서비스 중지됨"
    $DT = "SNMP 서비스: 중지"
} else {
    $RES = "M"
    $DESC = "SNMP 서비스 실행 중 - 필요 여부 확인"
    $DT = "SNMP 서비스: 실행 중"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check30 {
    $CODE = "W-30"
    $CAT = "서비스관리"
    $NAME = "SNMP Community String 복잡성 설정"
    $IMP = "중"
    $STD = "SNMP 서비스를 사용하지 않거나 Community String이 public, private 이 아닌 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$snmpSvc = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue

if (-not $snmpSvc -or $snmpSvc.Status -ne "Running") {
    $RES = "N/A"
    $DESC = "SNMP 서비스 미실행"
    $DT = "SNMP 서비스: 미실행"
} else {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
    $comm = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if ($comm) {
        $names = $comm.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object { $_.Name }
        $weak = $names | Where-Object { $_ -ieq "public" -or $_ -ieq "private" }
        if ($weak) {
            $RES = "N"
            $DESC = "기본 Community String 사용"
            $DT = "Community: $($names -join ', ')"
        } else {
            $RES = "Y"
            $DESC = "Community String 적절"
            $DT = "Community: $($names -join ', ')"
        }
    } else {
        $RES = "M"
        $DESC = "Community String 확인 필요"
        $DT = "레지스트리 조회 실패"
    }
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check31 {
    $CODE = "W-31"
    $CAT = "서비스관리"
    $NAME = "SNMP Access Control 설정"
    $IMP = "중"
    $STD = "SNMP 서비스를 사용하지 않거나 특정 호스트로부터 SNMP 패킷 받아들이기가 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$snmpSvc = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue

if (-not $snmpSvc -or $snmpSvc.Status -ne "Running") {
    $RES = "N/A"
    $DESC = "SNMP 서비스 미실행"
    $DT = "SNMP 서비스: 미실행"
} else {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
    $mgrs = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if ($mgrs) {
        $count = ($mgrs.PSObject.Properties | Where-Object { $_.Name -match "^\d+$" }).Count
        if ($count -gt 0) {
            $RES = "Y"
            $DESC = "특정 호스트만 허용"
            $DT = "허용 호스트 수: $count"
        } else {
            $RES = "N"
            $DESC = "SNMP 접근 제어 미설정"
            $DT = "모든 호스트 허용"
        }
    } else {
        $RES = "N"
        $DESC = "SNMP 접근 제어 미설정"
        $DT = "PermittedManagers 없음"
    }
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check32 {
    $CODE = "W-32"
    $CAT = "서비스관리"
    $NAME = "DNS 서비스 구동 점검"
    $IMP = "중"
    $STD = "DNS 서비스를 사용하지 않거나 동적 업데이트 `"없음(아니오)`"으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dnsSvc = Get-Service -Name "DNS" -ErrorAction SilentlyContinue

if (-not $dnsSvc) {
    $RES = "Y"
    $DESC = "DNS 서비스 미설치"
    $DT = "DNS 서비스: 미설치"
} elseif ($dnsSvc.Status -ne "Running") {
    $RES = "Y"
    $DESC = "DNS 서비스 중지됨"
    $DT = "DNS 서비스: 중지"
} else {
    $RES = "M"
    $DESC = "DNS 동적 업데이트 설정 수동 확인 필요"
    $DT = "DNS 서비스: 실행 중"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check33 {
    $CODE = "W-33"
    $CAT = "서비스관리"
    $NAME = "HTTP/FTP/SMTP 배너 차단"
    $IMP = "하"
    $STD = "HTTP, FTP, SMTP 접속 시 배너 정보가 보이지 않는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$RES = "M"
$DESC = "HTTP/FTP/SMTP 배너 차단 수동 확인 필요"
$DT = "IIS Server 헤더, FTP 배너, SMTP 배너 확인 필요"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check34 {
    $CODE = "W-34"
    $CAT = "서비스관리"
    $NAME = "Telnet 서비스 비활성화"
    $IMP = "중"
    $STD = "Telnet 서비스가 구동되어 있지 않거나 인증 방법이 NTLM인 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$telnetSvc = Get-Service -Name "TlntSvr" -ErrorAction SilentlyContinue

if (-not $telnetSvc) {
    $RES = "Y"
    $DESC = "Telnet 서비스 미설치"
    $DT = "Telnet 서비스: 미설치"
} elseif ($telnetSvc.Status -ne "Running") {
    $RES = "Y"
    $DESC = "Telnet 서비스 중지됨"
    $DT = "Telnet 서비스: 중지"
} else {
    $RES = "N"
    $DESC = "Telnet 서비스 실행 중"
    $DT = "Telnet 서비스: 실행 중"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check35 {
    $CODE = "W-35"
    $CAT = "서비스관리"
    $NAME = "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거"
    $IMP = "중"
    $STD = "시스템 DSN 부분의 데이터 소스를 현재 사용하고 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    $dsns = Get-OdbcDsn -DsnType System -ErrorAction SilentlyContinue
    if ($dsns.Count -eq 0) {
        $RES = "Y"
        $DESC = "시스템 DSN 없음"
        $DT = "시스템 DSN: 없음"
    } else {
        $RES = "M"
        $DESC = "시스템 DSN 사용 여부 확인 필요"
        $list = ($dsns | ForEach-Object { $_.Name }) -join ", "
        $DT = "시스템 DSN: $list"
    }
} catch {
    $RES = "M"
    $DESC = "ODBC 데이터 소스 확인 필요"
    $DT = "Get-OdbcDsn 실행 실패"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check36 {
    $CODE = "W-36"
    $CAT = "서비스관리"
    $NAME = "원격터미널 접속 타임아웃 설정"
    $IMP = "중"
    $STD = "원격 제어 시 Timeout 제어 설정을 30분 이하로 설정한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$rdpSvc = Get-Service -Name "TermService" -ErrorAction SilentlyContinue

if (-not $rdpSvc -or $rdpSvc.Status -ne "Running") {
    $RES = "N/A"
    $DESC = "원격 데스크톱 서비스 미실행"
    $DT = "TermService: 미실행"
} else {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $maxIdle = Get-ItemProperty -Path $regPath -Name "MaxIdleTime" -ErrorAction SilentlyContinue
    if ($maxIdle.MaxIdleTime) {
        $minutes = $maxIdle.MaxIdleTime / 60000
        if ($minutes -le 30 -and $minutes -gt 0) {
            $RES = "Y"
            $DESC = "타임아웃 적절"
            $DT = "유휴 세션 제한: ${minutes}분"
        } else {
            $RES = "N"
            $DESC = "타임아웃 부적절"
            $DT = "유휴 세션 제한: ${minutes}분 (권장: 30분 이하)"
        }
    } else {
        $RES = "N"
        $DESC = "타임아웃 미설정"
        $DT = "MaxIdleTime: 미설정"
    }
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check37 {
    $CODE = "W-37"
    $CAT = "서비스관리"
    $NAME = "예약된 작업에 의심스러운 명령이 등록되어 있는지 점검"
    $IMP = "중"
    $STD = "불필요한 명령어나 파일 등 주기적인 예약 작업의 존재 여부를 주기적으로 점검하고 제거한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne "Disabled" }
    $count = $tasks.Count

    $RES = "M"
    $DESC = "예약된 작업 ${count}개 수동 확인 필요"

    # 전체 활성 작업 목록 출력 (State 포함)
    $taskList = @()
    foreach ($task in $tasks) {
        $taskList += "$($task.State.ToString().PadRight(8)) $($task.TaskPath)$($task.TaskName)"
    }
    $DT = "[활성 예약 작업 목록 (총 ${count}개)]`n$($taskList -join "`n")"
} catch {
    $RES = "M"
    $DESC = "예약된 작업 확인 필요"
    $DT = "Get-ScheduledTask 실행 실패"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check38 {
    $CODE = "W-38"
    $CAT = "패치관리"
    $NAME = "주기적 보안 패치 및 벤더 권고사항 적용"
    $IMP = "상"
    $STD = "패치 절차를 수립하여 주기적으로 패치를 확인 및 설치하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 5
    $lastPatch = $hotfixes | Select-Object -First 1

    $daysSince = if ($lastPatch.InstalledOn) { (New-TimeSpan -Start $lastPatch.InstalledOn -End (Get-Date)).Days } else { -1 }
    $patchList = ($hotfixes | ForEach-Object { "$($_.HotFixID) ($($_.InstalledOn))" }) -join "`n"

    if ($daysSince -ge 0 -and $daysSince -le 90) {
        $RES = "Y"
        $DESC = "최근 90일 이내 패치 적용됨"
        $DT = "최근 패치 (${daysSince}일 전):`n$patchList"
    } else {
        $RES = "M"
        $DESC = "패치 적용 현황 수동 확인 필요"
        $DT = "최근 패치:`n$patchList"
    }
} catch {
    $RES = "M"
    $DESC = "패치 현황 확인 필요"
    $DT = "Get-HotFix 실행 실패"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check39 {
    $CODE = "W-39"
    $CAT = "패치관리"
    $NAME = "백신 프로그램 업데이트"
    $IMP = "상"
    $STD = "바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    $lastUpdate = $mpStatus.AntivirusSignatureLastUpdated
    $daysSince = if ($lastUpdate) { (New-TimeSpan -Start $lastUpdate -End (Get-Date)).Days } else { -1 }

    if ($daysSince -ge 0 -and $daysSince -le 7) {
        $RES = "Y"
        $DESC = "백신 최신 업데이트됨 (${daysSince}일 전)"
        $DT = "마지막 업데이트: $lastUpdate"
    } else {
        $RES = "N"
        $DESC = "백신 업데이트 필요"
        $DT = "마지막 업데이트: $lastUpdate (${daysSince}일 전)"
    }
} catch {
    $RES = "M"
    $DESC = "백신 업데이트 상태 수동 확인 필요"
    $DT = "Windows Defender 상태 확인 실패"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check40 {
    $CODE = "W-40"
    $CAT = "로그관리"
    $NAME = "정책에 따른 시스템 로깅 설정"
    $IMP = "중"
    $STD = "감사 정책 권고 기준에 따라 감사 설정이 되어 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    # CSV 형식으로 감사 정책 조회 (/r 옵션)
    $auditpolCsv = auditpol /get /category:* /r 2>&1
    $auditLines = $auditpolCsv | Where-Object { $_ -match "," -and $_ -notmatch "^Machine Name" }

    $policyList = @()
    foreach ($line in $auditLines) {
        $cols = $line -split ","
        if ($cols.Count -ge 4) {
            $subcategory = $cols[2].Trim()
            $setting = $cols[4].Trim()
            # 설정값 한글화
            $settingKor = switch ($setting) {
                "No Auditing" { "감사 안 함" }
                "Success" { "성공" }
                "Failure" { "실패" }
                "Success and Failure" { "성공 및 실패" }
                default { $setting }
            }
            if ($subcategory) {
                $policyList += "$($subcategory.PadRight(40)) : $settingKor"
            }
        }
    }

    $RES = "M"
    $DESC = "감사 정책 설정 확인 필요"
    $DT = "[현재 감사 정책 설정]`n$($policyList -join "`n")"
} catch {
    $RES = "M"
    $DESC = "감사 정책 확인 필요"
    $DT = "auditpol 실행 실패: $($_.Exception.Message)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check41 {
    $CODE = "W-41"
    $CAT = "로그관리"
    $NAME = "NTP 및 시각 동기화 설정"
    $IMP = "중"
    $STD = "NTP 및 시각 동기화를 설정한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    # 레지스트리에서 직접 NTP 설정 확인 (인코딩 문제 회피)
    $w32timePath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
    $ntpServer = Get-ItemProperty -Path $w32timePath -Name "NtpServer" -ErrorAction SilentlyContinue
    $syncType = Get-ItemProperty -Path $w32timePath -Name "Type" -ErrorAction SilentlyContinue

    $typeValue = if ($syncType) { $syncType.Type } else { "Unknown" }
    $serverValue = if ($ntpServer) { $ntpServer.NtpServer } else { "Not Set" }

    $dtList = @()
    $dtList += "Type: $typeValue"
    $dtList += "NtpServer: $serverValue"

    # W32Time 서비스 상태 확인
    $w32Svc = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
    $dtList += "W32Time Service: $(if ($w32Svc) { $w32Svc.Status } else { 'Not Found' })"

    # Type이 NTP 또는 NT5DS이고, 서버가 설정된 경우 양호
    if ($typeValue -in @("NTP", "NT5DS", "AllSync") -and $serverValue -ne "Not Set" -and $serverValue -notmatch "^,") {
        $RES = "Y"
        $DESC = "NTP 시각 동기화 설정됨"
    } elseif ($typeValue -eq "NoSync") {
        $RES = "N"
        $DESC = "시각 동기화 비활성화됨"
    } else {
        $RES = "M"
        $DESC = "NTP 설정 수동 확인 필요"
    }
    $DT = $dtList -join "`n"
} catch {
    $RES = "M"
    $DESC = "NTP 설정 확인 필요"
    $DT = "레지스트리 조회 실패: $($_.Exception.Message)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check42 {
    $CODE = "W-42"
    $CAT = "로그관리"
    $NAME = "이벤트 로그 관리 설정"
    $IMP = "하"
    $STD = "최대 로그 크기 `"10,240KB 이상`"으로 설정, `"90일 이후 이벤트 덮어씀`"을 설정한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    $secLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    $sizeKB = $secLog.MaximumSizeInBytes / 1024

    if ($sizeKB -ge 10240) {
        $RES = "Y"
        $DESC = "보안 로그 크기 적절"
        $DT = "Security 로그 크기: ${sizeKB}KB (기준: 10240KB 이상)"
    } else {
        $RES = "N"
        $DESC = "보안 로그 크기 부족"
        $DT = "Security 로그 크기: ${sizeKB}KB (기준: 10240KB 이상)"
    }
} catch {
    $RES = "M"
    $DESC = "이벤트 로그 설정 확인 필요"
    $DT = "Get-WinEvent 실행 실패"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check43 {
    $CODE = "W-43"
    $CAT = "로그관리"
    $NAME = "이벤트 로그 파일 접근 통제 설정"
    $IMP = "중"
    $STD = "로그 디렉터리의 접근 권한에 Everyone 권한이 없는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$logDir = "$env:SystemRoot\system32\config"

if (Test-Path $logDir) {
    $acl = Get-Acl $logDir -ErrorAction SilentlyContinue
    $everyone = $acl.Access | Where-Object { $_.IdentityReference -like "*Everyone*" }

    if ($everyone) {
        $RES = "N"
        $DESC = "로그 디렉터리에 Everyone 권한 존재"
        $DT = "경로: $logDir`nEveryone 권한: 존재"
    } else {
        $RES = "Y"
        $DESC = "로그 디렉터리에 Everyone 권한 없음"
        $DT = "경로: $logDir`nEveryone 권한: 없음"
    }
} else {
    $RES = "M"
    $DESC = "로그 디렉터리 확인 필요"
    $DT = "경로: $logDir 존재하지 않음"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check44 {
    $CODE = "W-44"
    $CAT = "보안관리"
    $NAME = "원격으로 액세스할 수 있는 레지스트리 경로"
    $IMP = "상"
    $STD = "Remote Registry Service가 중지된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$rrSvc = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue

if (-not $rrSvc) {
    $RES = "Y"
    $DESC = "Remote Registry 서비스 미설치"
    $DT = "RemoteRegistry: 미설치"
} elseif ($rrSvc.Status -ne "Running") {
    $RES = "Y"
    $DESC = "Remote Registry 서비스 중지됨"
    $DT = "RemoteRegistry: 중지"
} else {
    $RES = "N"
    $DESC = "Remote Registry 서비스 실행 중"
    $DT = "RemoteRegistry: 실행 중"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check45 {
    $CODE = "W-45"
    $CAT = "보안관리"
    $NAME = "백신 프로그램 설치"
    $IMP = "상"
    $STD = "바이러스 백신 프로그램이 설치된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    if ($mpStatus.AntivirusEnabled) {
        $RES = "Y"
        $DESC = "Windows Defender 활성화됨"
        $DT = "AntivirusEnabled: True`nRealTimeProtection: $($mpStatus.RealTimeProtectionEnabled)"
    } else {
        $RES = "N"
        $DESC = "Windows Defender 비활성화됨"
        $DT = "AntivirusEnabled: False"
    }
} catch {
    $RES = "M"
    $DESC = "백신 프로그램 설치 확인 필요"
    $DT = "Windows Defender 상태 확인 실패 - 다른 백신 설치 여부 확인 필요"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check46 {
    $CODE = "W-46"
    $CAT = "보안관리"
    $NAME = "SAM 파일 접근 통제 설정"
    $IMP = "상"
    $STD = "SAM 파일 접근 권한에 Administrator, System 그룹만 모든 권한으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$samPath = "$env:SystemRoot\system32\config\SAM"

if (Test-Path $samPath) {
    $acl = Get-Acl $samPath -ErrorAction SilentlyContinue
    $accessList = $acl.Access | Where-Object { $_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller" }

    if ($accessList.Count -eq 0) {
        $RES = "Y"
        $DESC = "SAM 파일 접근 권한 적절"
        $DT = "SAM 파일: Administrator, System만 접근 가능"
    } else {
        $RES = "N"
        $DESC = "SAM 파일에 불필요한 권한 존재"
        $others = ($accessList | ForEach-Object { $_.IdentityReference }) -join ", "
        $DT = "추가 권한: $others"
    }
} else {
    $RES = "M"
    $DESC = "SAM 파일 확인 필요"
    $DT = "SAM 파일 경로: $samPath"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check47 {
    $CODE = "W-47"
    $CAT = "보안관리"
    $NAME = "화면 보호기 설정"
    $IMP = "하"
    $STD = "화면 보호기를 설정하고 대기 시간이 10분 이하의 값으로 설정되어 있으며, 화면 보호기 해제를 위한 암호를 사용하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$regPath = "HKCU:\Control Panel\Desktop"
$ssActive = Get-ItemProperty -Path $regPath -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
$ssSecure = Get-ItemProperty -Path $regPath -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue
$ssTimeout = Get-ItemProperty -Path $regPath -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue

$dtList = @()
$isSecure = $true

if ($ssActive.ScreenSaveActive -eq "1") {
    $dtList += "화면 보호기: 사용"
} else {
    $dtList += "화면 보호기: 사용 안 함"
    $isSecure = $false
}

if ($ssSecure.ScreenSaverIsSecure -eq "1") {
    $dtList += "암호 사용: 예"
} else {
    $dtList += "암호 사용: 아니오"
    $isSecure = $false
}

$timeout = [int]$ssTimeout.ScreenSaveTimeOut
if ($timeout -gt 0 -and $timeout -le 600) {
    $dtList += "대기 시간: $($timeout)초 ($([math]::Round($timeout/60,1))분)"
} else {
    $dtList += "대기 시간: $($timeout)초 (10분 초과 또는 미설정)"
    $isSecure = $false
}

if ($isSecure) {
    $RES = "Y"
    $DESC = "화면 보호기 적절히 설정됨"
} else {
    $RES = "N"
    $DESC = "화면 보호기 설정 미흡"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check48 {
    $CODE = "W-48"
    $CAT = "보안관리"
    $NAME = "로그온하지 않고 시스템 종료 허용"
    $IMP = "상"
    $STD = "`"로그온하지 않고 시스템 종료 허용`"이 `"사용 안 함`"으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 및 레지스트리에서 값 확인
$shutdownNoLogon = Get-SecpolValue "ShutdownWithoutLogon"
if ([string]::IsNullOrEmpty($shutdownNoLogon)) {
    $shutdownNoLogon = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon"
}

if ($shutdownNoLogon -eq "0") {
    $RES = "Y"
    $DESC = "로그온 없이 시스템 종료 허용 안 함"
    $DT = "ShutdownWithoutLogon: 0 (사용 안 함)"
} elseif ($shutdownNoLogon -eq "1") {
    $RES = "N"
    $DESC = "로그온 없이 시스템 종료 허용됨"
    $DT = "ShutdownWithoutLogon: 1 (사용)"
} else {
    # 기본값은 1 (허용)
    $RES = "N"
    $DESC = "로그온 없이 시스템 종료 허용됨 (기본값)"
    $DT = "ShutdownWithoutLogon: Not Set (기본값 1)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check49 {
    $CODE = "W-49"
    $CAT = "보안관리"
    $NAME = "원격 시스템에서 강제로 시스템 종료"
    $IMP = "상"
    $STD = "`"원격 시스템에서 강제로 시스템 종료`" 정책에 `"Administrators`"만 존재하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$remoteShutdown = Get-SecpolValue "SeRemoteShutdownPrivilege"

if ([string]::IsNullOrEmpty($remoteShutdown)) {
    $RES = "M"
    $DESC = "원격 시스템 종료 정책 확인 필요"
    $DT = "SeRemoteShutdownPrivilege: Not Set"
} elseif ($remoteShutdown -match "S-1-5-32-544" -and $remoteShutdown -notmatch ",") {
    $RES = "Y"
    $DESC = "Administrators만 원격 종료 허용"
    $DT = "SeRemoteShutdownPrivilege: Administrators"
} else {
    $RES = "N"
    $DESC = "Administrators 외 계정이 원격 종료 가능"
    $DT = "SeRemoteShutdownPrivilege: $remoteShutdown"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check50 {
    $CODE = "W-50"
    $CAT = "보안관리"
    $NAME = "보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료"
    $IMP = "상"
    $STD = "`"보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료`" 정책이 `"사용 안 함`"으로 되어있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 및 레지스트리에서 값 확인
$crashOnAudit = Get-SecpolValue "CrashOnAuditFail"
if ([string]::IsNullOrEmpty($crashOnAudit)) {
    $crashOnAudit = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail"
}

if ($crashOnAudit -eq "1" -or $crashOnAudit -eq "2") {
    $RES = "N"
    $DESC = "감사 실패 시 시스템 종료됨"
    $DT = "CrashOnAuditFail: $crashOnAudit (사용)"
} elseif ($crashOnAudit -eq "0") {
    $RES = "Y"
    $DESC = "감사 실패 시 시스템 종료 안 함"
    $DT = "CrashOnAuditFail: 0 (사용 안 함)"
} else {
    $RES = "Y"
    $DESC = "감사 실패 시 시스템 종료 안 함 (기본값)"
    $DT = "CrashOnAuditFail: Not Set (기본값 0)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check51 {
    $CODE = "W-51"
    $CAT = "보안관리"
    $NAME = "SAM 계정과 공유의 익명 열거 허용 안 함"
    $IMP = "상"
    $STD = "`"SAM 계정과 공유의 익명 열거 허용 안 함`"이 `"사용`"으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 및 레지스트리에서 값 확인
$restrictAnon = Get-SecpolValue "RestrictAnonymous"
if ([string]::IsNullOrEmpty($restrictAnon)) {
    $restrictAnon = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
}

$restrictAnonSam = Get-SecpolValue "RestrictAnonymousSAM"
if ([string]::IsNullOrEmpty($restrictAnonSam)) {
    $restrictAnonSam = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
}

$dtList = @()
$isSecure = $true

if ($restrictAnon -eq "1") {
    $dtList += "RestrictAnonymous: 1 (양호)"
} elseif ([string]::IsNullOrEmpty($restrictAnon)) {
    $dtList += "RestrictAnonymous: Not Set (취약)"
    $isSecure = $false
} else {
    $dtList += "RestrictAnonymous: $restrictAnon (취약)"
    $isSecure = $false
}

if ($restrictAnonSam -eq "1") {
    $dtList += "RestrictAnonymousSAM: 1 (양호)"
} elseif ([string]::IsNullOrEmpty($restrictAnonSam)) {
    $dtList += "RestrictAnonymousSAM: Not Set (취약)"
    $isSecure = $false
} else {
    $dtList += "RestrictAnonymousSAM: $restrictAnonSam (취약)"
    $isSecure = $false
}

if ($isSecure) {
    $RES = "Y"
    $DESC = "SAM 계정 익명 열거 허용 안 함"
} else {
    $RES = "N"
    $DESC = "SAM 계정 익명 열거 설정 미흡"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check52 {
    $CODE = "W-52"
    $CAT = "보안관리"
    $NAME = "Autologon 기능 제어"
    $IMP = "상"
    $STD = "AutoAdminLogon 값이 없거나 0으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$autoLogon = Get-ItemProperty -Path $regPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue

if ([string]::IsNullOrEmpty($autoLogon.AutoAdminLogon) -or $autoLogon.AutoAdminLogon -eq "0") {
    $RES = "Y"
    $DESC = "Autologon 비활성화됨"
    $DT = "AutoAdminLogon: 0 또는 미설정"
} else {
    $RES = "N"
    $DESC = "Autologon 활성화됨"
    $DT = "AutoAdminLogon: $($autoLogon.AutoAdminLogon)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check53 {
    $CODE = "W-53"
    $CAT = "보안관리"
    $NAME = "이동식 미디어 포맷 및 꺼내기 허용"
    $IMP = "상"
    $STD = "`"이동식 미디어 포맷 및 꺼내기 허용`" 정책이 `"Administrators`"로 되어있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 및 레지스트리에서 값 확인
$allocateDASD = Get-SecpolValue "AllocateDASD"
if ([string]::IsNullOrEmpty($allocateDASD)) {
    $allocateDASD = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateDASD"
}

if ($allocateDASD -eq "0") {
    $RES = "Y"
    $DESC = "Administrators만 이동식 미디어 허용"
    $DT = "AllocateDASD: 0 (Administrators)"
} elseif ($allocateDASD -eq "1") {
    $RES = "N"
    $DESC = "Administrators와 Power Users 허용됨"
    $DT = "AllocateDASD: 1 (Administrators + Power Users)"
} elseif ($allocateDASD -eq "2") {
    $RES = "N"
    $DESC = "Administrators와 대화형 사용자 허용됨"
    $DT = "AllocateDASD: 2 (Administrators + Interactive Users)"
} elseif ([string]::IsNullOrEmpty($allocateDASD)) {
    $RES = "Y"
    $DESC = "Administrators만 이동식 미디어 허용 (기본값)"
    $DT = "AllocateDASD: Not Set (기본값 0)"
} else {
    $RES = "N"
    $DESC = "Administrators 외 사용자도 허용됨"
    $DT = "AllocateDASD: $allocateDASD"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check54 {
    $CODE = "W-54"
    $CAT = "보안관리"
    $NAME = "Dos 공격 방어 레지스트리 설정"
    $IMP = "중"
    $STD = "아래 4가지 DoS 방어 레지스트리를 설정한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$synAttack = Get-ItemProperty -Path $regPath -Name "SynAttackProtect" -ErrorAction SilentlyContinue
$deadGW = Get-ItemProperty -Path $regPath -Name "EnableDeadGWDetect" -ErrorAction SilentlyContinue
$keepAlive = Get-ItemProperty -Path $regPath -Name "KeepAliveTime" -ErrorAction SilentlyContinue
$noNameRelease = Get-ItemProperty -Path $regPath -Name "NoNameReleaseOnDemand" -ErrorAction SilentlyContinue

$dtList = @()
$vulnCount = 0

if ($synAttack.SynAttackProtect -ge 1) { $dtList += "SynAttackProtect: $($synAttack.SynAttackProtect) (양호)" }
else { $dtList += "SynAttackProtect: 미설정 또는 0 (취약)"; $vulnCount++ }

if ($deadGW.EnableDeadGWDetect -eq 0) { $dtList += "EnableDeadGWDetect: 0 (양호)" }
else { $dtList += "EnableDeadGWDetect: $($deadGW.EnableDeadGWDetect) (취약)"; $vulnCount++ }

if ($keepAlive.KeepAliveTime -le 300000) { $dtList += "KeepAliveTime: $($keepAlive.KeepAliveTime) (양호)" }
else { $dtList += "KeepAliveTime: 미설정 또는 기준 초과 (취약)"; $vulnCount++ }

if ($noNameRelease.NoNameReleaseOnDemand -eq 1) { $dtList += "NoNameReleaseOnDemand: 1 (양호)" }
else { $dtList += "NoNameReleaseOnDemand: 미설정 또는 0 (취약)"; $vulnCount++ }

if ($vulnCount -eq 0) {
    $RES = "Y"
    $DESC = "DoS 방어 레지스트리 적절"
} else {
    $RES = "N"
    $DESC = "DoS 방어 레지스트리 ${vulnCount}개 항목 미흡"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check55 {
    $CODE = "W-55"
    $CAT = "보안관리"
    $NAME = "사용자가 프린터 드라이버를 설치할 수 없게 함"
    $IMP = "중"
    $STD = "`"사용자가 프린터 드라이버를 설치할 수 없게 함`" 정책이 `"사용`"인 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 및 레지스트리에서 값 확인
$addPrinterDrivers = Get-SecpolValue "AddPrinterDrivers"
if ([string]::IsNullOrEmpty($addPrinterDrivers)) {
    $addPrinterDrivers = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers"
}

if ($addPrinterDrivers -eq "1") {
    $RES = "Y"
    $DESC = "사용자 프린터 드라이버 설치 제한됨"
    $DT = "AddPrinterDrivers: 1 (사용)"
} elseif ($addPrinterDrivers -eq "0") {
    $RES = "N"
    $DESC = "사용자 프린터 드라이버 설치 허용됨"
    $DT = "AddPrinterDrivers: 0 (사용 안 함)"
} else {
    # 기본값은 0 (허용)
    $RES = "N"
    $DESC = "사용자 프린터 드라이버 설치 허용됨 (기본값)"
    $DT = "AddPrinterDrivers: Not Set (기본값 0)"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check56 {
    $CODE = "W-56"
    $CAT = "보안관리"
    $NAME = "SMB 세션 중단 관리 설정"
    $IMP = "중"
    $STD = "`"로그온 시간이 만료되면 클라이언트 연결 끊기`" 정책을 `"사용`"으로, `"세션 연결을 중단하기 전에 필요한 유휴 시간`" 정책을 `"15분`" 이하로 설정한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 및 레지스트리에서 값 확인
$autoDisconnect = Get-SecpolValue "AutoDisconnect"
if ([string]::IsNullOrEmpty($autoDisconnect)) {
    $autoDisconnect = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "AutoDisconnect"
}

# EnableForcedLogOff를 우선 확인 (GPO 설정 시 이 키로 저장됨)
$forceLogoff = Get-SecpolValue "EnableForcedLogOff"
if ([string]::IsNullOrEmpty($forceLogoff)) {
    $forceLogoff = Get-SecpolValue "ForceLogoffWhenHourExpire"
}
if ([string]::IsNullOrEmpty($forceLogoff)) {
    $forceLogoff = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "EnableForcedLogOff"
}

$dtList = @()
$isSecure = $true

if ($forceLogoff -eq "1") {
    $dtList += "로그온 시간 만료 시 연결 끊기: 사용"
} elseif ([string]::IsNullOrEmpty($forceLogoff)) {
    $dtList += "로그온 시간 만료 시 연결 끊기: Not Set (기본값 사용)"
} else {
    $dtList += "로그온 시간 만료 시 연결 끊기: 사용 안 함"
    $isSecure = $false
}

# 안전한 정수 변환
$autoDisconnectInt = -1
if (-not [string]::IsNullOrEmpty($autoDisconnect)) {
    try { $autoDisconnectInt = [int]$autoDisconnect } catch { $autoDisconnectInt = -1 }
}

if ($autoDisconnectInt -ge 0 -and $autoDisconnectInt -le 15) {
    $dtList += "세션 유휴 시간: ${autoDisconnect}분"
} elseif ($autoDisconnectInt -gt 15) {
    $dtList += "세션 유휴 시간: ${autoDisconnect}분 (15분 초과)"
    $isSecure = $false
} else {
    $dtList += "세션 유휴 시간: 미설정"
    $isSecure = $false
}

if ($isSecure) {
    $RES = "Y"
    $DESC = "SMB 세션 관리 적절"
} else {
    $RES = "N"
    $DESC = "SMB 세션 관리 미흡"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check57 {
    $CODE = "W-57"
    $CAT = "보안관리"
    $NAME = "로그온 시 경고 메시지 설정"
    $IMP = "하"
    $STD = "로그인 경고 메시지 제목 및 내용이 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# 그룹 정책 설정 경로 (우선 확인)
$policyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# 직접 레지스트리 설정 경로 (폴백)
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

$captionValue = $null
$textValue = $null
$sourcePath = ""

# 1. 그룹 정책 경로 먼저 확인 (secpol.msc, gpedit.msc로 설정한 경우)
try {
    $policyItem = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
    if ($null -ne $policyItem) {
        if ($null -ne $policyItem.LegalNoticeCaption -and $policyItem.LegalNoticeCaption -ne "") {
            $captionValue = $policyItem.LegalNoticeCaption
            $sourcePath = "Policies\System"
        }
        if ($null -ne $policyItem.LegalNoticeText -and $policyItem.LegalNoticeText -ne "") {
            $textValue = $policyItem.LegalNoticeText
        }
    }
} catch {}

# 2. Winlogon 경로 확인 (직접 레지스트리 수정한 경우)
if ([string]::IsNullOrEmpty($captionValue) -or [string]::IsNullOrEmpty($textValue)) {
    try {
        $winlogonItem = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue
        if ($null -ne $winlogonItem) {
            if ([string]::IsNullOrEmpty($captionValue) -and $null -ne $winlogonItem.LegalNoticeCaption) {
                $captionValue = $winlogonItem.LegalNoticeCaption
                $sourcePath = "Winlogon"
            }
            if ([string]::IsNullOrEmpty($textValue) -and $null -ne $winlogonItem.LegalNoticeText) {
                $textValue = $winlogonItem.LegalNoticeText
            }
        }
    } catch {}
}

# NULL 문자 및 XML 호환성을 위한 문자열 정리 함수
function Sanitize-XmlString {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    # NULL 문자 및 제어 문자 제거 (탭, 개행 제외)
    return $Value -replace "`0", "" -replace "[\x00-\x08\x0B\x0C\x0E-\x1F]", ""
}

# 레지스트리 값에서 NULL 문자 제거
if ($captionValue) { $captionValue = Sanitize-XmlString $captionValue }
if ($textValue) { $textValue = Sanitize-XmlString $textValue }

$hasCaption = -not [string]::IsNullOrEmpty($captionValue)
$hasText = -not [string]::IsNullOrEmpty($textValue)

if ($hasCaption -and $hasText) {
    $RES = "Y"
    $DESC = "로그온 경고 메시지 설정됨"
    # 안전한 Substring 처리
    $textPreview = if ($textValue.Length -gt 50) { $textValue.Substring(0, 50) + "..." } else { $textValue }
    $DT = "경로: $sourcePath`n제목: $captionValue`n내용: $textPreview"
} else {
    $RES = "N"
    $DESC = "로그온 경고 메시지 미설정"
    $dtList = @()
    $dtList += "확인 경로: Policies\System, Winlogon"
    if ($hasCaption) { $dtList += "LegalNoticeCaption: $captionValue" } else { $dtList += "LegalNoticeCaption: 미설정" }
    if ($hasText) { $dtList += "LegalNoticeText: (설정됨)" } else { $dtList += "LegalNoticeText: 미설정" }
    $DT = $dtList -join "`n"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check58 {
    $CODE = "W-58"
    $CAT = "보안관리"
    $NAME = "사용자별 홈 디렉터리 권한 설정"
    $IMP = "중"
    $STD = "홈 디렉터리에 Everyone 권한이 없는 경우 (All Users, Default User 디렉터리 제외)"
    $RES = ""
    $DESC = ""
    $DT = ""

$usersPath = "$env:SystemDrive\Users"
$excludeDirs = @("All Users", "Default", "Default User", "Public")

if (Test-Path $usersPath) {
    $userDirs = Get-ChildItem $usersPath -Directory | Where-Object { $_.Name -notin $excludeDirs }
    $everyoneDirs = @()
    $resultList = @()

    foreach ($dir in $userDirs) {
        $acl = Get-Acl $dir.FullName -ErrorAction SilentlyContinue
        $everyone = $acl.Access | Where-Object { $_.IdentityReference -like "*Everyone*" }
        if ($everyone) {
            $everyoneDirs += $dir.Name
            $everyonePerms = ($everyone | ForEach-Object { $_.FileSystemRights }) -join ", "
            $resultList += "[취약] $($dir.FullName) - Everyone 권한: $everyonePerms"
        } else {
            $resultList += "[양호] $($dir.FullName)"
        }
    }

    if ($everyoneDirs.Count -eq 0) {
        $RES = "Y"
        $DESC = "홈 디렉터리에 Everyone 권한 없음"
    } else {
        $RES = "N"
        $DESC = "홈 디렉터리 $($everyoneDirs.Count)개에 Everyone 권한 존재"
    }
    $DT = "[사용자 홈 디렉터리 권한 점검 결과 (총 $($userDirs.Count)개)]`n$($resultList -join "`n")"
} else {
    $RES = "M"
    $DESC = "사용자 디렉터리 확인 필요"
    $DT = "Users 디렉터리: $usersPath"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check59 {
    $CODE = "W-59"
    $CAT = "보안관리"
    $NAME = "LAN Manager 인증 수준"
    $IMP = "중"
    $STD = "`"LAN Manager 인증 수준`" 정책에 `"NTLMv2 응답만 보냄`"이 설정되어 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# secedit 정책에서 먼저 확인
$lmLevel = Get-SecpolValue "LmCompatibilityLevel"
$source = "Secpol"

# 정책 파일에서 못 찾으면 레지스트리에서 확인
if ([string]::IsNullOrEmpty($lmLevel)) {
    $lmLevel = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
    $source = "Registry"
}

if (-not [string]::IsNullOrEmpty($lmLevel) -and [int]$lmLevel -ge 3) {
    $RES = "Y"
    $DESC = "NTLMv2 응답만 보내기 설정됨"
    $DT = "LmCompatibilityLevel: $lmLevel (3 이상: NTLMv2)`nSource: $source"
} elseif ([string]::IsNullOrEmpty($lmLevel)) {
    $RES = "M"
    $DESC = "LAN Manager 인증 수준 확인 필요"
    $DT = "LmCompatibilityLevel: 미설정`nSecpol 및 Registry에서 값을 찾을 수 없음"
} else {
    $RES = "N"
    $DESC = "LAN Manager 인증 수준 낮음"
    $DT = "LmCompatibilityLevel: $lmLevel (권장: 3 이상)`nSource: $source"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check60 {
    $CODE = "W-60"
    $CAT = "보안관리"
    $NAME = "보안 채널 데이터 디지털 암호화 또는 서명"
    $IMP = "중"
    $STD = "아래 3가지 정책 모두 `"사용`"으로 되어있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

# secedit 및 레지스트리에서 값 확인
$requireSign = Get-SecpolValue "RequireSignOrSeal"
if ([string]::IsNullOrEmpty($requireSign)) {
    $requireSign = Get-RegValue $regPath "RequireSignOrSeal"
}

$sealChannel = Get-SecpolValue "SealSecureChannel"
if ([string]::IsNullOrEmpty($sealChannel)) {
    $sealChannel = Get-RegValue $regPath "SealSecureChannel"
}

$signChannel = Get-SecpolValue "SignSecureChannel"
if ([string]::IsNullOrEmpty($signChannel)) {
    $signChannel = Get-RegValue $regPath "SignSecureChannel"
}

$dtList = @()
$vulnCount = 0

if ($requireSign -eq "1") {
    $dtList += "RequireSignOrSeal: 1 (양호)"
} elseif ([string]::IsNullOrEmpty($requireSign)) {
    $dtList += "RequireSignOrSeal: Not Set (취약)"
    $vulnCount++
} else {
    $dtList += "RequireSignOrSeal: $requireSign (취약)"
    $vulnCount++
}

if ($sealChannel -eq "1") {
    $dtList += "SealSecureChannel: 1 (양호)"
} elseif ([string]::IsNullOrEmpty($sealChannel)) {
    $dtList += "SealSecureChannel: Not Set (취약)"
    $vulnCount++
} else {
    $dtList += "SealSecureChannel: $sealChannel (취약)"
    $vulnCount++
}

if ($signChannel -eq "1") {
    $dtList += "SignSecureChannel: 1 (양호)"
} elseif ([string]::IsNullOrEmpty($signChannel)) {
    $dtList += "SignSecureChannel: Not Set (취약)"
    $vulnCount++
} else {
    $dtList += "SignSecureChannel: $signChannel (취약)"
    $vulnCount++
}

if ($vulnCount -eq 0) {
    $RES = "Y"
    $DESC = "보안 채널 암호화/서명 적절"
} else {
    $RES = "N"
    $DESC = "보안 채널 설정 ${vulnCount}개 항목 미흡"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check61 {
    $CODE = "W-61"
    $CAT = "보안관리"
    $NAME = "파일 및 디렉토리 보호"
    $IMP = "중"
    $STD = "NTFS 파일 시스템을 사용하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$volumes = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.DriveType -eq "Fixed" }
$dtList = @()
$fatFound = $false

foreach ($vol in $volumes) {
    $fs = $vol.FileSystemType
    $drive = $vol.DriveLetter
    $dtList += "${drive}: $fs"
    if ($fs -like "FAT*") {
        $fatFound = $true
    }
}

if (-not $fatFound) {
    $RES = "Y"
    $DESC = "모든 드라이브가 NTFS 파일 시스템 사용"
} else {
    $RES = "N"
    $DESC = "FAT 파일 시스템 사용 드라이브 존재"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check62 {
    $CODE = "W-62"
    $CAT = "보안관리"
    $NAME = "시작 프로그램 목록 분석"
    $IMP = "중"
    $STD = "시작 프로그램 목록을 정기적으로 검사하고 불필요한 서비스를 비활성화한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$startupItems = @()

# HKCU Run
$hkcuRun = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
if ($hkcuRun) {
    $hkcuRun.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
        $startupItems += "[HKCU\Run] $($_.Name): $($_.Value)"
    }
}

# HKLM Run
$hklmRun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
if ($hklmRun) {
    $hklmRun.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
        $startupItems += "[HKLM\Run] $($_.Name): $($_.Value)"
    }
}

if ($startupItems.Count -eq 0) {
    $RES = "Y"
    $DESC = "시작 프로그램 없음"
    $DT = "등록된 시작 프로그램 없음"
} else {
    $RES = "M"
    $DESC = "시작 프로그램 $($startupItems.Count)개 수동 확인 필요"
    $DT = $startupItems -join "`n"
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check63 {
    $CODE = "W-63"
    $CAT = "보안관리"
    $NAME = "도메인 컨트롤러-사용자의 시간 동기화"
    $IMP = "중"
    $STD = "컴퓨터 시계 동기화 최대 허용 오차값이 5분 이하인 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# Kerberos MaxClockSkew 확인 (secedit)
$maxSkew = Get-SecpolValue "MaxClockSkew"

if ($maxSkew -and $maxSkew -match "^\d+$") {
    $skewValue = [int]$maxSkew
    $DT = "MaxClockSkew: ${skewValue}분"

    if ($skewValue -le 5) {
        $RES = "Y"
        $DESC = "시간 동기화 허용 오차 적절 (${skewValue}분)"
    } else {
        $RES = "N"
        $DESC = "시간 동기화 허용 오차 초과 (${skewValue}분 > 5분)"
    }
} else {
    # 도메인 미가입 시 N/A
    $domain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    if (-not $domain) {
        $RES = "N/A"
        $DESC = "도메인 미가입 시스템"
        $DT = "Kerberos 정책 해당 없음"
    } else {
        $RES = "M"
        $DESC = "MaxClockSkew 설정 확인 필요"
        $DT = "MaxClockSkew: 미설정 또는 확인 불가"
    }
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check64 {
    $CODE = "W-64"
    $CAT = "보안관리"
    $NAME = "윈도우 방화벽 설정"
    $IMP = "중"
    $STD = "Windows 방화벽 `"사용`"으로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
$dtList = @()
$disabledCount = 0

foreach ($profile in $profiles) {
    $status = if ($profile.Enabled) { "사용" } else { "사용 안 함" }
    $dtList += "$($profile.Name): $status"
    if (-not $profile.Enabled) {
        $disabledCount++
    }
}

if ($disabledCount -eq 0) {
    $RES = "Y"
    $DESC = "모든 프로필 방화벽 활성화됨"
} else {
    $RES = "N"
    $DESC = "방화벽 비활성화된 프로필 ${disabledCount}개"
}

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
    Check19
    Check20
    Check21
    Check22
    Check23
    Check24
    Check25
    Check26
    Check27
    Check28
    Check29
    Check30
    Check31
    Check32
    Check33
    Check34
    Check35
    Check36
    Check37
    Check38
    Check39
    Check40
    Check41
    Check42
    Check43
    Check44
    Check45
    Check46
    Check47
    Check48
    Check49
    Check50
    Check51
    Check52
    Check53
    Check54
    Check55
    Check56
    Check57
    Check58
    Check59
    Check60
    Check61
    Check62
    Check63
    Check64

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

if (Test-Path $SECPOL_PATH) {
    Remove-Item $SECPOL_PATH -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "[완료] 결과 파일: $OUTPUT_FILE"
Write-Host ""

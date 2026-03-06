#================================================================
# MSSQL_Windows 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : MSSQL_Windows
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
$META_STD = "KISA"

#================================================================
# INIT
#================================================================
chcp 65001 | Out-Null
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$META_VER = "1.0"
$META_PLAT = "MSSQL"
$META_TYPE = "DBMS"

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

# SQL 실행 헬퍼
function Invoke-SqlQuery {
    param([string]$Query)
    try {
        if ($script:UseWindowsAuth) {
            $result = Invoke-Sqlcmd -ServerInstance $script:ServerInstance -Database $script:Database -Query $Query -ErrorAction Stop
        } else {
            $result = Invoke-Sqlcmd -ServerInstance $script:ServerInstance -Database $script:Database -Username $script:Username -Password $script:Password -Query $Query -ErrorAction Stop
        }
        return $result
    } catch { return $null }
}

#================================================================
# CONNECT — 플랫폼별 커스터마이즈 영역
# (SqlServer 모듈 확인, 연결정보 입력, 연결 테스트)
#================================================================
Write-Host ""
Write-Host "============================================================"
Write-Host " MSSQL 보안 진단 스크립트"
Write-Host "============================================================"
Write-Host ""
Write-Host "[연결 정보 입력]"
Write-Host ""

# SqlServer 모듈 확인
$sqlModule = Get-Module -ListAvailable -Name SqlServer
if (-not $sqlModule) {
    $sqlModule = Get-Module -ListAvailable -Name SQLPS
}

if (-not $sqlModule) {
    Write-Host "[!] SqlServer 또는 SQLPS 모듈을 찾을 수 없습니다."
    Write-Host "[!] Install-Module SqlServer 명령으로 설치해주세요."
    exit 1
}

Import-Module SqlServer -ErrorAction SilentlyContinue
if (-not (Get-Module SqlServer)) {
    Import-Module SQLPS -DisableNameChecking -ErrorAction SilentlyContinue
}

# 연결 정보 입력
$serverInput = Read-Host "Server Instance (default: localhost)"
$script:ServerInstance = if ($serverInput) { $serverInput } else { "localhost" }

$dbInput = Read-Host "Database (default: master)"
$script:Database = if ($dbInput) { $dbInput } else { "master" }

$authInput = Read-Host "Use Windows Authentication? (y/n, default: y)"
$script:UseWindowsAuth = ($authInput -ne "n")

if (-not $script:UseWindowsAuth) {
    $script:Username = Read-Host "Username (default: sa)"
    if (-not $script:Username) { $script:Username = "sa" }

    $securePassword = Read-Host "Password" -AsSecureString
    $script:Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    )

    if (-not $script:Password) {
        Write-Host "[!] 비밀번호를 입력해주세요."
        exit 1
    }
}

# 연결 테스트
Write-Host ""
Write-Host "[연결 테스트 중...]"

$testQuery = "SELECT @@VERSION AS Version"
$versionResult = Invoke-SqlQuery -Query $testQuery

if (-not $versionResult) {
    Write-Host "[!] MSSQL 연결 실패"
    exit 1
}

$script:DBVersion = $versionResult.Version
Write-Host "[OK] MSSQL 연결 성공"
Write-Host ""

# SQL Server 버전 정보
$versionQuery = "SELECT SERVERPROPERTY('ProductVersion') AS Version, SERVERPROPERTY('ProductLevel') AS Level, SERVERPROPERTY('Edition') AS Edition"
$sqlVersion = Invoke-SqlQuery -Query $versionQuery
$SQL_VERSION = "$($sqlVersion.Version) $($sqlVersion.Level)"

#================================================================
# COLLECT
#================================================================
$META_DATE = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$SYS_HOST = $env:COMPUTERNAME
$OUTPUT_FILE = Join-Path $PSScriptRoot "${META_PLAT}_${SYS_HOST}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

function Check01 {
    $CODE = "D-01"
    $CAT = "계정관리"
    $NAME = "기본 계정의 비밀번호, 정책 등을 변경하여 사용"
    $IMP = "상"
    $STD = "기본 계정의 초기 비밀번호를 변경하거나 잠금설정한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    $saQuery = @"
SELECT name, is_disabled, is_policy_enforced, is_expiration_checked
FROM sys.sql_logins WHERE name = 'sa';
"@
    $saStatus = Invoke-SqlQuery -Query $saQuery

    if ($null -eq $saStatus) {
        $Res = "N/A"
        $Desc = "sa 계정 정보를 조회할 수 없음"
        $Dt = "[sa 계정 상태]`nsa 계정이 존재하지 않거나 조회 권한이 없습니다."
        return
    }

    # Boolean 값 변환 (문자열/정수/불리언 모두 처리)
    $isDisabled = [System.Convert]::ToBoolean($saStatus.is_disabled)
    $isPolicyEnforced = [System.Convert]::ToBoolean($saStatus.is_policy_enforced)
    $isExpirationChecked = [System.Convert]::ToBoolean($saStatus.is_expiration_checked)

    $Dt = "[sa 계정 상태]`nname: $($saStatus.name)`nis_disabled: $isDisabled`nis_policy_enforced: $isPolicyEnforced`nis_expiration_checked: $isExpirationChecked"

    if ($isDisabled) {
        $Res = "Y"
        $Desc = "sa 계정이 비활성화되어 있음"
    } elseif ($isPolicyEnforced) {
        $Res = "Y"
        $Desc = "sa 계정이 활성화되어 있으나 비밀번호 정책이 적용됨"
    } else {
        $Res = "N"
        $Desc = "sa 계정이 활성화되어 있고 비밀번호 정책이 미적용"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check02 {
    $CODE = "D-02"
    $CAT = "계정관리"
    $NAME = "데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
    $IMP = "상"
    $STD = "계정 정보를 확인하여 불필요한 계정이 없는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    $Res = "M"
    $Desc = "계정 목록 수동 확인 필요"

    $loginQuery = @"
SELECT name, type_desc, is_disabled, create_date, modify_date
FROM sys.server_principals
WHERE type IN ('S', 'U', 'G')
ORDER BY name;
"@
    $logins = Invoke-SqlQuery -Query $loginQuery

    $Dt = "[로그인 목록 - 불필요 계정 여부 확인 필요]`n"
    foreach ($login in $logins) {
        $Dt += "$($login.name) | $($login.type_desc) | disabled:$($login.is_disabled)`n"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check03 {
    $CODE = "D-03"
    $CAT = "계정관리"
    $NAME = "비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"
    $IMP = "상"
    $STD = "기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    $policyQuery = @"
SELECT name, is_policy_enforced, is_expiration_checked
FROM sys.sql_logins
WHERE type_desc = 'SQL_LOGIN';
"@
    $policies = Invoke-SqlQuery -Query $policyQuery

    $Dt = "[SQL 로그인 비밀번호 정책]`n"
    $noPolicyCount = 0
    $noExpirationCount = 0
    foreach ($p in $policies) {
        $policyEnforced = [System.Convert]::ToBoolean($p.is_policy_enforced)
        $expirationChecked = [System.Convert]::ToBoolean($p.is_expiration_checked)
        $Dt += "$($p.name) | policy:$policyEnforced | expiration:$expirationChecked`n"
        if (-not $policyEnforced) {
            $noPolicyCount++
        }
        if (-not $expirationChecked) {
            $noExpirationCount++
        }
    }

    # Windows 계정 정책 확인 (secedit 사용)
    $Dt += "`n[Windows 비밀번호 정책]`n"
    try {
        $seceditPath = "$env:TEMP\secpol_d03.cfg"
        secedit /export /cfg $seceditPath /quiet 2>$null
        if (Test-Path $seceditPath) {
            $content = Get-Content $seceditPath -ErrorAction SilentlyContinue
            $complexity = $content | Select-String "PasswordComplexity" | ForEach-Object { $_.Line }
            $minLength = $content | Select-String "MinimumPasswordLength" | ForEach-Object { $_.Line }
            $maxAge = $content | Select-String "MaximumPasswordAge" | ForEach-Object { $_.Line }
            $minAge = $content | Select-String "MinimumPasswordAge" | ForEach-Object { $_.Line }
            $Dt += "  $complexity`n"
            $Dt += "  $minLength`n"
            $Dt += "  $maxAge`n"
            $Dt += "  $minAge`n"
            Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue
        }
    } catch {
        $Dt += "  Windows 정책 조회 실패"
    }

    $Dt += "`n[참고]`n"
    $Dt += "※ is_policy_enforced=True: Windows 비밀번호 복잡도 정책 적용`n"
    $Dt += "※ is_expiration_checked=True: Windows 비밀번호 만료 정책 적용`n"
    $Dt += "※ 양호 기준: 모든 계정에 복잡도(policy)와 만료(expiration) 모두 적용"

    if ($noPolicyCount -eq 0 -and $noExpirationCount -eq 0) {
        $Res = "Y"
        $Desc = "모든 SQL 로그인에 비밀번호 정책과 만료 정책이 적용됨"
    } elseif ($noPolicyCount -gt 0 -and $noExpirationCount -gt 0) {
        $Res = "N"
        $Desc = "복잡도 미적용 ${noPolicyCount}개, 만료 미적용 ${noExpirationCount}개 계정 존재"
    } elseif ($noPolicyCount -gt 0) {
        $Res = "N"
        $Desc = "비밀번호 복잡도 정책이 미적용된 계정 ${noPolicyCount}개 존재"
    } else {
        $Res = "N"
        $Desc = "비밀번호 만료 정책이 미적용된 계정 ${noExpirationCount}개 존재"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check04 {
    $CODE = "D-04"
    $CAT = "계정관리"
    $NAME = "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
    $IMP = "상"
    $STD = "관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    $Res = "M"
    $Desc = "sysadmin 권한 보유 계정 수동 확인 필요"

    $sysadminQuery = @"
SELECT m.name AS member_name, r.name AS role_name
FROM sys.server_role_members rm
JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin';
"@
    $sysadmins = Invoke-SqlQuery -Query $sysadminQuery

    $Dt = "[sysadmin 역할 멤버]`n"
    foreach ($sa in $sysadmins) {
        $Dt += "$($sa.member_name)`n"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check05 {
    $CODE = "D-05"
    $CAT = "계정관리"
    $NAME = "비밀번호 재사용에 대한 제약 설정"
    $IMP = "중"
    $STD = "비밀번호 재사용 제한 설정을 적용한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "M"
$Desc = "Windows 암호 정책과 연동하여 수동 확인 필요"

$Dt = "MSSQL은 Windows 암호 정책과 연동하여 비밀번호 재사용을 제한합니다.`nWindows 로컬 보안 정책의 '암호 정책 > 최근 암호 기억' 설정을 확인하세요."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check06 {
    $CODE = "D-06"
    $CAT = "계정관리"
    $NAME = "DB 사용자 계정을 개별적으로 부여하여 사용"
    $IMP = "중"
    $STD = "사용자별 계정을 사용하고 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    $Res = "M"
    $Desc = "사용자별 개별 계정 사용 여부 수동 확인 필요"

    $userQuery = @"
SELECT name, type_desc, is_disabled, create_date
FROM sys.server_principals
WHERE type IN ('S', 'U')
AND name NOT LIKE '##%'
AND name NOT LIKE 'NT %'
ORDER BY name;
"@
    $users = Invoke-SqlQuery -Query $userQuery

    $Dt = "[사용자 계정 목록 - 개별 계정 사용 여부 확인 필요]`n"
    foreach ($u in $users) {
        # Boolean 값 변환 (문자열/정수/불리언 모두 처리)
        $isDisabled = [System.Convert]::ToBoolean($u.is_disabled)
        $Dt += "$($u.name) | $($u.type_desc) | disabled:$isDisabled`n"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check07 {
    $CODE = "D-07"
    $CAT = "계정관리"
    $NAME = "root 권한으로 서비스 구동 제한"
    $IMP = "중"
    $STD = "DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "N/A"
$Desc = "N/A (Windows 환경에서는 해당 항목 점검 대상 아님)"
$Dt = "해당 항목은 Unix/Linux 환경에서 DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되는지 점검하는 항목입니다.`nWindows 환경의 MSSQL은 서비스 계정으로 구동되며 root 개념이 다르므로 본 항목은 점검 대상에서 제외됩니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check08 {
    $CODE = "D-08"
    $CAT = "계정관리"
    $NAME = "안전한 암호화 알고리즘 사용"
    $IMP = "상"
    $STD = "해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$versionQuery = "SELECT SERVERPROPERTY('ProductVersion') AS Version, SERVERPROPERTY('ProductMajorVersion') AS MajorVersion"
$ver = Invoke-SqlQuery -Query $versionQuery

$majorVersion = 0
try {
    # ProductMajorVersion이 없는 경우 ProductVersion에서 추출
    if ($null -ne $ver.MajorVersion) {
        $majorVersion = [int]$ver.MajorVersion
    } else {
        $majorVersion = [int]($ver.Version -split '\.')[0]
    }
} catch {
    $majorVersion = 0
}

$Dt = "[SQL Server 버전]`n$($ver.Version)`n"

# SQL Server 버전별 암호화 알고리즘
# 11.x = SQL Server 2012, 10.x = SQL Server 2008, 9.x = SQL Server 2005
if ($majorVersion -ge 11) {
    $Res = "Y"
    $Desc = "SHA-512 해시 알고리즘 사용 (SQL Server 2012 이상)"
    $Dt += "`n[암호화 알고리즘]`n"
    $Dt += "SHA-512 (32bit Salt 적용)`n"
    $Dt += "`n※ SQL Server 2012 이상에서 사용자 계정의 비밀번호는 32bit Salt를 적용한 SHA-512 해시 알고리즘을 사용합니다."
} elseif ($majorVersion -ge 10) {
    $Res = "M"
    $Desc = "SHA-1 해시 알고리즘 사용 (SQL Server 2008) - 수동 확인 필요"
    $Dt += "`n[암호화 알고리즘]`n"
    $Dt += "SHA-1 (SQL Server 2008 이하)`n"
    $Dt += "`n[경고] SQL Server 2008은 SHA-1 해시 알고리즘을 사용합니다.`n"
    $Dt += "SHA-1은 KISA 권고 보안 강도(112비트 이상)에 미달할 수 있으므로, 가능한 경우 상위 버전 업그레이드를 권장합니다."
} else {
    $Res = "N"
    $Desc = "취약한 해시 알고리즘 사용 (SQL Server 2005 이하)"
    $Dt += "`n[암호화 알고리즘]`n"
    $Dt += "SHA-1 또는 그 이하 (SQL Server 2005 이하)`n"
    $Dt += "`n[취약] SQL Server 2005 이하 버전은 보안 강도가 낮은 해시 알고리즘을 사용합니다.`n"
    $Dt += "상위 버전으로의 업그레이드를 강력히 권장합니다."
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check09 {
    $CODE = "D-09"
    $CAT = "계정관리"
    $NAME = "일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정"
    $IMP = "중"
    $STD = "로그인 시도 횟수를 제한하는 값을 설정한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    $lockQuery = @"
SELECT name, is_policy_enforced
FROM sys.sql_logins
WHERE type_desc = 'SQL_LOGIN';
"@
    $locks = Invoke-SqlQuery -Query $lockQuery

    $Dt = "[SQL 로그인 정책 적용 상태]`n"
    $noPolicyCount = 0
    foreach ($l in $locks) {
        # Boolean 값 변환 (문자열/정수/불리언 모두 처리)
        $isPolicyEnforced = [System.Convert]::ToBoolean($l.is_policy_enforced)
        $Dt += "$($l.name) | policy_enforced:$isPolicyEnforced`n"
        if (-not $isPolicyEnforced) {
            $noPolicyCount++
        }
    }

    # Windows 계정 잠금 정책 확인
    $Dt += "`n[Windows 계정 잠금 정책]`n"
    try {
        $seceditPath = "$env:TEMP\secpol_d09.cfg"
        secedit /export /cfg $seceditPath /quiet 2>$null
        if (Test-Path $seceditPath) {
            $content = Get-Content $seceditPath -ErrorAction SilentlyContinue
            $lockoutBadCount = $content | Select-String "LockoutBadCount" | ForEach-Object { $_.Line }
            $lockoutDuration = $content | Select-String "LockoutDuration" | ForEach-Object { $_.Line }
            $resetCount = $content | Select-String "ResetLockoutCount" | ForEach-Object { $_.Line }
            $Dt += "  $lockoutBadCount`n"
            $Dt += "  $lockoutDuration`n"
            $Dt += "  $resetCount`n"
            Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue
        }
    } catch {
        $Dt += "  Windows 정책 조회 실패"
    }

    $Dt += "`n[참고]`n"
    $Dt += "※ is_policy_enforced=True: SQL 로그인이 Windows 계정 잠금 정책과 연동됨`n"
    $Dt += "※ Windows 정책을 따르더라도 LockoutBadCount=0이면 잠금 미적용`n"
    $Dt += "※ 권장: LockoutBadCount >= 5, LockoutDuration >= 30"

    if ($noPolicyCount -eq 0) {
        # 정책 연동은 되어있으나 Windows 정책 자체의 적절성은 수동 확인 필요
        $Res = "M"
        $Desc = "모든 SQL 로그인에 Windows 정책 연동됨 - Windows 잠금 정책 수동 확인 필요"
    } else {
        $Res = "N"
        $Desc = "정책이 미적용된 계정 ${noPolicyCount}개 존재"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check10 {
    $CODE = "D-10"
    $CAT = "접근관리"
    $NAME = "원격에서 DB 서버로의 접속 제한"
    $IMP = "상"
    $STD = "DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    $Res = "M"
    $Desc = "방화벽 및 네트워크 설정 수동 확인 필요"

    $remoteQuery = @"
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name IN ('remote access', 'remote admin connections', 'remote login timeout (s)', 'remote query timeout (s)');
"@
    $remote = Invoke-SqlQuery -Query $remoteQuery

    $Dt = "[원격 접속 관련 설정]`n"
    foreach ($r in $remote) {
        $Dt += "$($r.name): $($r.value_in_use)`n"
    }
    $Dt += "`n※ Windows 방화벽에서 SQL Server 포트(1433) 접근 제한 여부를 확인하세요."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check11 {
    $CODE = "D-11"
    $CAT = "접근관리"
    $NAME = "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
    $IMP = "상"
    $STD = "시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    # 시스템 뷰/테이블에 대한 비인가 사용자 권한 확인
    $sysGrantQuery = @"
SELECT dp.name AS principal_name,
       dp.type_desc,
       p.permission_name,
       p.state_desc,
       SCHEMA_NAME(o.schema_id) AS schema_name,
       o.name AS object_name
FROM sys.database_permissions p
JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
LEFT JOIN sys.objects o ON p.major_id = o.object_id
WHERE p.class = 1
AND dp.name NOT IN ('dbo', 'db_owner', 'public', 'guest')
AND dp.name NOT LIKE '##%'
AND dp.name NOT LIKE 'db_%'
AND (SCHEMA_NAME(o.schema_id) = 'sys' OR o.is_ms_shipped = 1);
"@
    $sysGrants = Invoke-SqlQuery -Query $sysGrantQuery

    # PUBLIC에 명시적으로 부여된 시스템 객체 권한 (기본 권한 제외)
    $publicGrantQuery = @"
SELECT SCHEMA_NAME(o.schema_id) AS schema_name,
       o.name AS object_name,
       p.permission_name,
       p.state_desc
FROM sys.database_permissions p
JOIN sys.objects o ON p.major_id = o.object_id
WHERE p.grantee_principal_id = DATABASE_PRINCIPAL_ID('public')
AND p.state_desc = 'GRANT'
AND (o.name LIKE 'sys%' OR o.name LIKE 'sp_%' OR o.name LIKE 'xp_%' OR o.is_ms_shipped = 1)
AND p.permission_name IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'EXECUTE', 'ALTER', 'CONTROL');
"@
    $publicGrants = Invoke-SqlQuery -Query $publicGrantQuery

    # GUEST 계정의 시스템 객체 접근 권한 (시스템 관련 권한만)
    $guestQuery = @"
SELECT p.permission_name, p.state_desc,
       CASE WHEN o.object_id IS NOT NULL THEN SCHEMA_NAME(o.schema_id) + '.' + o.name ELSE 'DB-level' END AS target
FROM sys.database_permissions p
LEFT JOIN sys.objects o ON p.major_id = o.object_id
WHERE p.grantee_principal_id = DATABASE_PRINCIPAL_ID('guest')
AND p.state_desc = 'GRANT'
AND (o.is_ms_shipped = 1 OR o.name LIKE 'sys%' OR p.major_id = 0);
"@
    $guestGrants = Invoke-SqlQuery -Query $guestQuery

    # guest 계정 활성화 상태 확인
    $guestStatusQuery = @"
SELECT dp.name, dp.type_desc,
       CASE WHEN dp.hasdbaccess = 1 THEN 'ENABLED' ELSE 'DISABLED' END AS access_status
FROM sys.database_principals dp
WHERE dp.name = 'guest';
"@
    $guestStatus = Invoke-SqlQuery -Query $guestStatusQuery

    $Dt = "[sys 스키마 비인가 접근 권한]`n"
    $vulnerableCount = 0

    if ($sysGrants) {
        foreach ($g in $sysGrants) {
            $Dt += "$($g.principal_name) | $($g.schema_name).$($g.object_name) | $($g.permission_name) | $($g.state_desc)`n"
            $vulnerableCount++
        }
    } else {
        $Dt += "비인가 사용자 권한 없음`n"
    }

    $Dt += "`n[PUBLIC 시스템 객체 권한]`n"
    if ($publicGrants) {
        foreach ($p in $publicGrants) {
            $Dt += "$($p.schema_name).$($p.object_name) | $($p.permission_name) | $($p.state_desc)`n"
            $vulnerableCount++
        }
    } else {
        $Dt += "PUBLIC에 명시적으로 부여된 시스템 객체 권한 없음`n"
    }

    $Dt += "`n[GUEST 계정 상태]`n"
    if ($guestStatus) {
        $Dt += "상태: $($guestStatus.access_status)`n"
    }
    $Dt += "`n[GUEST 시스템 객체 권한]`n"
    if ($guestGrants) {
        foreach ($g in $guestGrants) {
            $Dt += "$($g.target) | $($g.permission_name) | $($g.state_desc)`n"
            $vulnerableCount++
        }
    } else {
        $Dt += "GUEST 계정 없음"
    }

    if ($vulnerableCount -eq 0) {
        $Res = "Y"
        $Desc = "시스템 테이블에 DBA만 접근 가능"
    } else {
        $Res = "N"
        $Desc = "비인가 사용자에게 시스템 테이블 접근 권한 존재 ($vulnerableCount 건)"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check12 {
    $CODE = "D-12"
    $CAT = "접근관리"
    $NAME = "안전한 리스너 비밀번호 설정 및 사용"
    $IMP = "상"
    $STD = "Listener의 비밀번호가 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "N/A"
$Desc = "N/A (MSSQL은 리스너 개념이 없음)"
$Dt = "해당 항목은 Oracle의 TNS Listener 비밀번호 설정 여부를 점검하는 항목입니다.`nMSSQL은 Oracle과 달리 별도의 리스너(Listener) 프로세스가 없으며,`nSQL Server Browser 서비스가 유사한 역할을 하지만 비밀번호 설정 개념이 없습니다.`n따라서 본 항목은 MSSQL 환경에서 점검 대상에서 제외됩니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check13 {
    $CODE = "D-13"
    $CAT = "접근관리"
    $NAME = "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"
    $IMP = "중"
    $STD = "불필요한 ODBC/OLE-DB가 설치되지 않은 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "N/A"
$Desc = "N/A (Windows OS 레벨 점검 항목)"
$Dt = "해당 항목은 Windows OS에서 불필요한 ODBC/OLE-DB 데이터 소스가 설치되어 있는지 점검하는 항목입니다.`nODBC 데이터 소스 관리자 도구(시작 > 설정 > 제어판 > 관리 도구 > ODBC 데이터 원본 관리자)를 통해 수동 점검이 필요합니다.`n불필요한 데이터 소스 및 드라이버를 제거하여 비인가자의 데이터베이스 접속을 차단해야 합니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check14 {
    $CODE = "D-14"
    $CAT = "접근관리"
    $NAME = "데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"
    $IMP = "중"
    $STD = "주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "M"
$Desc = "SQL Server 설치 폴더 권한 수동 확인 필요"

$pathQuery = "SELECT SERVERPROPERTY('InstanceDefaultDataPath') AS DataPath, SERVERPROPERTY('InstanceDefaultLogPath') AS LogPath"
$paths = Invoke-SqlQuery -Query $pathQuery

$Dt = "[SQL Server 데이터 경로]`nData: $($paths.DataPath)`nLog: $($paths.LogPath)`n`n※ 위 경로의 파일 시스템 권한을 확인하세요.`n※ SQL Server 서비스 계정과 관리자만 접근 가능해야 합니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check15 {
    $CODE = "D-15"
    $CAT = "접근관리"
    $NAME = "관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한"
    $IMP = "하"
    $STD = "Listener 관련 설정 파일에 대한 권한이 관리자로 설정되어 있으며, Listener로 파라미터를 변경할 수 없게 옵션이 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "N/A"
$Desc = "N/A (MSSQL은 Oracle의 trace 파일 개념과 다름)"
$Dt = "해당 항목은 Oracle의 trace 파일(*.trc) 권한을 점검하는 항목입니다.`nMSSQL은 Oracle과 달리 trace 파일 대신 SQL Server Profiler 또는 Extended Events를 사용합니다.`n이러한 트레이스 데이터는 파일 시스템이 아닌 SQL Server 내부에서 관리되며,`n권한 체계가 다르므로 본 항목은 MSSQL 환경에서 점검 대상에서 제외됩니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check16 {
    $CODE = "D-16"
    $CAT = "접근관리"
    $NAME = "Windows 인증 모드 사용"
    $IMP = "하"
    $STD = "Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우 sa 계정 활성화 시 강력한 암호 정책을 설정한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$authQuery = "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS IsWindowsAuth"
$auth = Invoke-SqlQuery -Query $authQuery

$Dt = "[인증 모드]`nIsIntegratedSecurityOnly: $($auth.IsWindowsAuth)`n"

if ($auth.IsWindowsAuth -eq 1) {
    $Dt += "현재 설정: Windows 인증 모드"
    $Res = "Y"
    $Desc = "Windows 인증 모드 사용 중"
} else {
    $Dt += "현재 설정: 혼합 인증 모드 (SQL Server + Windows)"

    $saQuery = "SELECT name, is_disabled, is_policy_enforced FROM sys.sql_logins WHERE name = 'sa'"
    $sa = Invoke-SqlQuery -Query $saQuery

    $Dt += "`n`n[sa 계정 상태]`nis_disabled: $($sa.is_disabled)`nis_policy_enforced: $($sa.is_policy_enforced)"

    if ($sa.is_disabled -eq $true) {
        $Res = "Y"
        $Desc = "혼합 인증 모드이나 sa 계정이 비활성화됨"
    } elseif ($sa.is_policy_enforced -eq $true) {
        $Res = "Y"
        $Desc = "혼합 인증 모드이나 sa 계정에 강력한 암호 정책 적용"
    } else {
        $Res = "N"
        $Desc = "혼합 인증 모드에서 sa 계정에 암호 정책 미적용"
    }
}

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check17 {
    $CODE = "D-17"
    $CAT = "옵션관리"
    $NAME = "Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한"
    $IMP = "하"
    $STD = "Audit Table 접근 권한이 관리자 계정으로 설정한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "N/A"
$Desc = "N/A (MSSQL에 해당 기능 없음)"
$Dt = "해당 항목은 Oracle, Altibase, Tibero 등에서 Audit Table 접근 권한이 관리자 계정으로 제한되어 있는지 점검하는 항목입니다.`nMSSQL은 감사 기록을 SQL Server Audit 기능으로 관리하며, Oracle의 AUD$ 테이블과 같은 구조가 없습니다.`n따라서 본 항목은 MSSQL 환경에서 점검 대상에서 제외됩니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check18 {
    $CODE = "D-18"
    $CAT = "옵션관리"
    $NAME = "응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"
    $IMP = "상"
    $STD = "DBA 계정의 Role이 Public으로 설정되지 않은 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "N/A"
$Desc = "N/A (MSSQL에 해당 기능 없음)"
$Dt = "해당 항목은 Oracle, Altibase, Tibero 등에서 DBA 계정의 Role이 Public으로 설정되어 있는지 점검하는 항목입니다.`nMSSQL은 Oracle과 Role 관리 체계가 다르며, PUBLIC 데이터베이스 역할의 권한 관리 방식이 다릅니다.`nMSSQL의 PUBLIC 권한 점검은 D-11(시스템 테이블 접근 제한)에서 수행됩니다.`n따라서 본 항목은 MSSQL 환경에서 점검 대상에서 제외됩니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check19 {
    $CODE = "D-19"
    $CAT = "옵션관리"
    $NAME = "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"
    $IMP = "상"
    $STD = "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 FALSE로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "N/A"
$Desc = "N/A (MSSQL에 해당 기능 없음)"
$Dt = "해당 항목은 Oracle에서 OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 파라미터가 FALSE로 설정되어 있는지 점검하는 항목입니다.`n이 파라미터들은 원격 클라이언트의 OS 인증 및 Role 사용을 제어합니다.`nMSSQL은 Windows 인증 또는 SQL Server 인증을 사용하며,`nOracle의 해당 파라미터들과 같은 기능이 없습니다.`n따라서 본 항목은 MSSQL 환경에서 점검 대상에서 제외됩니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check20 {
    $CODE = "D-20"
    $CAT = "옵션관리"
    $NAME = "인가되지 않은 Object Owner의 제한"
    $IMP = "하"
    $STD = "Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "N/A"
$Desc = "N/A (MSSQL에 해당 기능 없음)"
$Dt = "해당 항목은 Oracle, Altibase, Tibero, PostgreSQL 등에서 Object Owner가 인가된 계정에게만 존재하는지 점검하는 항목입니다.`nObject Owner는 SYS, SYSTEM과 같은 데이터베이스 관리자 계정과 응용 프로그램의 관리자 계정에만 존재해야 합니다.`nMSSQL은 스키마 기반의 객체 소유권 관리 방식이 다르므로 본 항목은 점검 대상에서 제외됩니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check21 {
    $CODE = "D-21"
    $CAT = "옵션관리"
    $NAME = "인가되지 않은 GRANT OPTION 사용 제한"
    $IMP = "중"
    $STD = "WITH_GRANT_OPTION이 ROLE에 의하여 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "N/A"
$Desc = "N/A (MSSQL에 해당 기능 없음)"
$Dt = "해당 항목은 Oracle, MySQL, Altibase, Tibero 등에서 일반 사용자에게 GRANT OPTION이 ROLE에 의하여 부여되어 있는지 점검하는 항목입니다.`n일반 사용자에게 GRANT OPTION이 부여된 경우 다른 일반 사용자에게 권한을 부여할 수 있어 권한의 무분별한 확산 위험이 있습니다.`nMSSQL은 권한 부여 체계가 다르며, 본 항목은 점검 대상에서 제외됩니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check22 {
    $CODE = "D-22"
    $CAT = "옵션관리"
    $NAME = "데이터베이스의 자원 제한 기능을 TRUE로 설정"
    $IMP = "하"
    $STD = "RESOURCE_LIMIT 설정이 TRUE로 되어있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "N/A"
$Desc = "N/A (MSSQL에 해당 기능 없음)"
$Dt = "해당 항목은 Oracle에서 RESOURCE_LIMIT 값이 TRUE로 설정되어 있는지 점검하는 항목입니다.`nRESOURCE_LIMIT을 TRUE로 설정하면 프로파일에 정의된 자원 제한이 적용됩니다.`nMSSQL은 Resource Governor라는 별도의 리소스 관리 기능을 제공하며,`nOracle의 RESOURCE_LIMIT과 동작 방식이 다르므로 본 항목은 점검 대상에서 제외됩니다."

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check23 {
    $CODE = "D-23"
    $CAT = "옵션관리"
    $NAME = "xp_cmdshell 사용 제한"
    $IMP = "상"
    $STD = "xp_cmdshell이 비활성화 되어 있거나, 활성화 되어 있으면 다음의 조건을 모두 만족하는 경우 1. public의 실행(Execute) 권한이 부여되어 있지 않은 경우 2. 서비스 계정(애플리케이션 연동)에 sysadmin 권한이 부여되어 있지 않은 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    # xp_cmdshell 설정 확인
    $xpQuery = "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
    $xp = Invoke-SqlQuery -Query $xpQuery

    $Dt = "[xp_cmdshell 설정]`n"
    $Dt += "value_in_use: $($xp.value_in_use) (0=비활성화, 1=활성화)`n"

    # sysadmin 역할 멤버 확인
    $sysadminQuery = @"
SELECT sp.name AS login_name, sp.type_desc
FROM sys.server_principals sp
INNER JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id
INNER JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin'
ORDER BY sp.name;
"@
    $sysadmins = Invoke-SqlQuery -Query $sysadminQuery

    $Dt += "`n[sysadmin 역할 멤버]`n"
    if ($sysadmins) {
        foreach ($sa in $sysadmins) {
            $Dt += "  $($sa.login_name) | $($sa.type_desc)`n"
        }
    } else {
        $Dt += "  조회 결과 없음`n"
    }

    # master DB에서 xp_cmdshell 권한 확인 (xp_cmdshell은 master DB의 확장 저장 프로시저)
    $permQuery = @"
USE master;
SELECT
    pr.name AS grantee,
    pr.type_desc AS grantee_type,
    dp.permission_name,
    dp.state_desc
FROM sys.database_permissions dp
INNER JOIN sys.database_principals pr ON dp.grantee_principal_id = pr.principal_id
INNER JOIN sys.objects o ON dp.major_id = o.object_id
WHERE o.name = 'xp_cmdshell'
ORDER BY pr.name;
"@
    $perms = Invoke-SqlQuery -Query $permQuery

    $Dt += "`n[xp_cmdshell 실행 권한 (master DB)]`n"
    $hasPublicGrant = $false
    $hasGuestGrant = $false

    if ($perms) {
        foreach ($p in $perms) {
            $Dt += "  $($p.grantee) | $($p.grantee_type) | $($p.permission_name) | $($p.state_desc)`n"
            if ($p.grantee -eq "public" -and $p.state_desc -eq "GRANT") {
                $hasPublicGrant = $true
            }
            if ($p.grantee -eq "guest" -and $p.state_desc -eq "GRANT") {
                $hasGuestGrant = $true
            }
        }
    } else {
        $Dt += "  명시적으로 부여된 권한 없음`n"
    }

    # 판정
    if ($xp.value_in_use -eq 0) {
        $Res = "Y"
        $Desc = "xp_cmdshell이 비활성화됨"
    } elseif ($hasPublicGrant -or $hasGuestGrant) {
        $Res = "N"
        $Desc = "xp_cmdshell이 활성화되고 public/guest에 권한 존재"
    } else {
        $Res = "M"
        $Desc = "xp_cmdshell이 활성화됨 (sysadmin 멤버 수동 확인 필요)"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check24 {
    $CODE = "D-24"
    $CAT = "옵션관리"
    $NAME = "Registry Procedure 권한 제한"
    $IMP = "상"
    $STD = "제한이 필요한 시스템 확장 저장 프로시저들이 DBA 외 guest/public에게 부여되지 않은 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    # master DB에서 xp_reg* 프로시저 목록 조회 (xp_reg*는 master DB 객체)
    $procListQuery = @"
USE master;
SELECT name AS proc_name
FROM sys.extended_procedures
WHERE name LIKE 'xp_reg%'
ORDER BY name;
"@
    $procList = Invoke-SqlQuery -Query $procListQuery

    $Dt = "[Registry 관련 확장 저장 프로시저 목록 (master DB)]`n"
    if ($procList) {
        foreach ($proc in $procList) {
            $Dt += "  $($proc.proc_name)`n"
        }
    } else {
        $Dt += "  xp_reg* 프로시저 없음`n"
    }

    # master DB에서 xp_reg* 권한 조회 (모든 사용자)
    $regQuery = @"
USE master;
SELECT
    p.name AS proc_name,
    pr.name AS grantee,
    pr.type_desc AS grantee_type,
    dp.permission_name,
    dp.state_desc
FROM sys.extended_procedures p
INNER JOIN sys.database_permissions dp ON p.object_id = dp.major_id
INNER JOIN sys.database_principals pr ON dp.grantee_principal_id = pr.principal_id
WHERE p.name LIKE 'xp_reg%'
ORDER BY p.name, pr.name;
"@
    $regs = Invoke-SqlQuery -Query $regQuery

    $Dt += "`n[xp_reg* 프로시저 권한 (master DB)]`n"
    $publicGrant = $false
    $guestGrant = $false
    $otherGrant = $false
    $granteeList = @()

    if ($regs) {
        foreach ($r in $regs) {
            $Dt += "  $($r.proc_name) | $($r.grantee) | $($r.grantee_type) | $($r.permission_name) | $($r.state_desc)`n"
            if ($r.state_desc -eq "GRANT") {
                if ($r.grantee -eq "public") {
                    $publicGrant = $true
                } elseif ($r.grantee -eq "guest") {
                    $guestGrant = $true
                } else {
                    $otherGrant = $true
                    if ($r.grantee -notin $granteeList) {
                        $granteeList += $r.grantee
                    }
                }
            }
        }
    } else {
        $Dt += "  명시적으로 부여된 권한 없음`n"
    }

    # 판정 (public/guest 권한 있으면 취약, 그 외 권한 있으면 수동 확인)
    if ($publicGrant -or $guestGrant) {
        $Res = "N"
        $vulnUsers = @()
        if ($publicGrant) { $vulnUsers += "public" }
        if ($guestGrant) { $vulnUsers += "guest" }
        $Desc = "Registry Procedure에 $($vulnUsers -join '/') 실행 권한 존재"
    } elseif ($otherGrant) {
        $Res = "M"
        $Desc = "Registry Procedure 권한 존재 (대상: $($granteeList -join ', ')) - 수동 확인 필요"
    } else {
        $Res = "Y"
        $Desc = "Registry Procedure에 비인가 사용자 실행 권한 없음"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check25 {
    $CODE = "D-25"
    $CAT = "패치관리"
    $NAME = "주기적 보안 패치 및 벤더 권고 사항 적용"
    $IMP = "상"
    $STD = "보안 패치가 적용된 버전을 사용하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$Res = "M"
$Desc = "현재 버전 확인 후 최신 패치 적용 여부 수동 확인 필요"

$Dt = "[현재 버전]`n$SQL_VERSION`n`n[전체 버전 정보]`n$DB_VERSION`n`n※ 최신 버전은 Microsoft 공식 사이트에서 확인`nhttps://docs.microsoft.com/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check26 {
    $CODE = "D-26"
    $CAT = "패치관리"
    $NAME = "데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정"
    $IMP = "상"
    $STD = "DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

    $auditQuery = @"
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name LIKE '%audit%';
"@
    $audit = Invoke-SqlQuery -Query $auditQuery

    $loginAuditQuery = @"
EXEC xp_loginconfig 'audit level';
"@
    $loginAudit = Invoke-SqlQuery -Query $loginAuditQuery

    $Dt = "[감사 관련 설정]`n"
    if ($audit) {
        foreach ($a in $audit) {
            $Dt += "$($a.name): $($a.value_in_use)`n"
        }
    }

    $Dt += "`n[로그인 감사 수준]`n"
    if ($loginAudit) {
        $Dt += "$($loginAudit.name): $($loginAudit.config_value)"

        if ($loginAudit.config_value -eq "all") {
            $Res = "Y"
            $Desc = "로그인 감사가 '모두'로 설정됨"
        } elseif ($loginAudit.config_value -eq "failure") {
            $Res = "M"
            $Desc = "로그인 감사가 '실패'로만 설정됨"
        } else {
            $Res = "N"
            $Desc = "로그인 감사가 설정되지 않음"
        }
    } else {
        $Res = "M"
        $Desc = "감사 설정 수동 확인 필요"
    }

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
        <dom>N/A</dom>
        <os>
            <n>$META_PLAT $script:DBVersion</n>
            <fn>$META_PLAT</fn>
        </os>
        <kn>$script:DBVersion</kn>
        <arch>$(if ([System.Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' })</arch>
        <net>
            <ip>$script:ServerInstance</ip>
            <all><![CDATA[Instance: $script:ServerInstance]]></all>
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

#================================================================
# Apache_Windows 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Apache_Windows
# 항목  : WEB-01 ~ WEB-26 (26개)
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
$META_PLAT = "Apache"
$META_TYPE = "WEB"

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
# COLLECT
#================================================================
$META_DATE = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$SYS_HOST = $env:COMPUTERNAME
$SYS_OS_NAME = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
$SYS_OS_FN = $SYS_OS_NAME -replace "Microsoft ", ""
$SYS_KN = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Version
$SYS_ARCH = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).OSArchitecture
$SYS_IP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress
if (-not $SYS_IP) { $SYS_IP = "N/A" }

#================================================================
# DETECT — 플랫폼별 커스터마이즈 영역
# (서비스 탐지, 설정파일 경로, 버전 정보)
# 세팅 변수: $SVC_VERSION, $SVC_CONF
#================================================================
function Find-ApacheInstallation {
    # Apache 설치 경로 자동 탐지
    $apachePaths = @(
        "C:\Apache24",
        "C:\Apache2",
        "C:\Program Files\Apache Software Foundation\Apache2.4",
        "C:\Program Files\Apache Software Foundation\Apache2.2",
        "C:\Program Files (x86)\Apache Software Foundation\Apache2.4",
        "C:\xampp\apache",
        "C:\laragon\bin\apache\httpd-2.4.54-win64-VS16",
        "C:\laragon\bin\apache"
    )

    # Laragon의 경우 하위 폴더 탐색
    $laragonBase = "C:\laragon\bin\apache"
    if (Test-Path $laragonBase) {
        $laragonApache = Get-ChildItem -Path $laragonBase -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($laragonApache) {
            $apachePaths += $laragonApache.FullName
        }
    }

    foreach ($path in $apachePaths) {
        $httpdConf = Join-Path $path "conf\httpd.conf"
        if (Test-Path $httpdConf) {
            return @{
                Home = $path
                Conf = $httpdConf
                ConfDir = Join-Path $path "conf"
            }
        }
    }

    # 서비스에서 Apache 경로 찾기
    $apacheServices = @("Apache2.4", "Apache24", "Apache2", "httpd")
    foreach ($svcName in $apacheServices) {
        try {
            $svc = Get-WmiObject Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
            if ($svc -and $svc.PathName) {
                $exePath = $svc.PathName -replace '"', '' -replace '\s+-\w.*$', ''
                $apacheHome = Split-Path (Split-Path $exePath -Parent) -Parent
                $httpdConf = Join-Path $apacheHome "conf\httpd.conf"
                if (Test-Path $httpdConf) {
                    return @{
                        Home = $apacheHome
                        Conf = $httpdConf
                        ConfDir = Join-Path $apacheHome "conf"
                    }
                }
            }
        } catch { }
    }

    return $null
}

# Apache 설치 확인
$APACHE = Find-ApacheInstallation

if (-not $APACHE) {
    Write-Host "[X] Apache가 설치되어 있지 않습니다." -ForegroundColor Red
    Write-Host "    이 스크립트는 Apache가 설치된 시스템에서만 실행 가능합니다." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    확인 경로:" -ForegroundColor Gray
    Write-Host "    - C:\Apache24" -ForegroundColor Gray
    Write-Host "    - C:\Program Files\Apache Software Foundation\Apache2.4" -ForegroundColor Gray
    Write-Host "    - C:\xampp\apache" -ForegroundColor Gray
    Write-Host "    - C:\laragon\bin\apache" -ForegroundColor Gray
    Read-Host "Press Enter to exit"
    exit 1
}

$APACHE_HOME = $APACHE.Home
$APACHE_CONF = $APACHE.Conf
$APACHE_CONF_DIR = $APACHE.ConfDir

# Apache 버전 확인
$APACHE_VERSION = ""
$httpdExe = Join-Path $APACHE_HOME "bin\httpd.exe"
if (Test-Path $httpdExe) {
    try {
        $versionOutput = & $httpdExe -v 2>&1
        $APACHE_VERSION = ($versionOutput | Select-String "Server version") -replace "Server version:\s*", ""
    } catch { }
}

$SVC_VERSION = $APACHE_VERSION
$SVC_CONF = $APACHE_CONF

$OUTPUT_FILE = Join-Path $PSScriptRoot "${META_PLAT}_${SYS_HOST}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

function Check01 {
    $CODE = "WEB-01"
    $CAT = "계정관리"
    $NAME = "Default 관리자 계정명 변경"
    $IMP = "상"
    $STD = "관리자 페이지를 사용하지 않거나, 계정명이 기본 계정명으로 설정되어 있지 않은 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

# 유틸리티 함수

# httpd.conf 및 Include된 설정 파일에서 지시자 검색
function Get-ApacheDirective {
    param(
        [string]$Pattern,
        [switch]$IncludeCommented
    )

    $results = @()
    $confFiles = @($APACHE_CONF)

    # conf 디렉터리의 모든 .conf 파일
    $extraConfDir = Join-Path $APACHE_CONF_DIR "extra"
    if (Test-Path $extraConfDir) {
        $confFiles += Get-ChildItem -Path $extraConfDir -Filter "*.conf" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    }

    foreach ($file in $confFiles) {
        if (Test-Path $file) {
            $content = Get-Content $file -ErrorAction SilentlyContinue
            $lineNum = 0
            foreach ($line in $content) {
                $lineNum++
                if ($IncludeCommented) {
                    if ($line -match $Pattern) {
                        $results += [PSCustomObject]@{
                            File = $file
                            Line = $lineNum
                            Content = $line.Trim()
                        }
                    }
                } else {
                    # 주석 제외
                    if ($line -match "^\s*$Pattern" -and $line -notmatch "^\s*#") {
                        $results += [PSCustomObject]@{
                            File = $file
                            Line = $lineNum
                            Content = $line.Trim()
                        }
                    }
                }
            }
        }
    }

    return $results
}

# NTFS ACL에서 취약한 권한 확인
function Test-VulnerablePermission {
    param(
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        return $null
    }

    $vulnerable = $false
    $permissions = @()

    try {
        $acl = Get-Acl $Path -ErrorAction SilentlyContinue
        foreach ($access in $acl.Access) {
            $identity = $access.IdentityReference.Value
            $rights = $access.FileSystemRights.ToString()

            $permissions += "$identity : $rights"

            # Everyone 또는 Users 그룹에 쓰기/수정 권한이 있으면 취약
            if ($identity -match "Everyone|BUILTIN\\Users") {
                if ($rights -match "Write|FullControl|Modify|Delete") {
                    $vulnerable = $true
                }
            }
        }
    } catch {
        return @{
            Vulnerable = $null
            Permissions = @("권한 확인 실패: $_")
        }
    }

    return @{
        Vulnerable = $vulnerable
        Permissions = $permissions
    }
}

# COLLECT - 시스템 정보 수집

$META_DATE = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$SYS_HOST = $env:COMPUTERNAME
$SYS_DOM = (Get-CimInstance Win32_ComputerSystem).Domain
$SYS_OS_NAME = (Get-CimInstance Win32_OperatingSystem).Caption
$SYS_OS_FN = $SYS_OS_NAME -replace "Microsoft ", ""
$os = Get-CimInstance Win32_OperatingSystem
$SYS_KN = $os.Version
$SYS_ARCH = $os.OSArchitecture

# 대표 IP 수집
$virtualPatterns = @("WSL", "Hyper-V", "vEthernet", "VPN", "Bluetooth", "Loopback", "VMware", "VirtualBox", "Docker")
$allIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
    $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*"
}
$realIPs = $allIPs | Where-Object {
    $alias = $_.InterfaceAlias
    -not ($virtualPatterns | Where-Object { $alias -like "*$_*" })
}
$SYS_IP = if ($realIPs) { ($realIPs | Select-Object -First 1).IPAddress } else { ($allIPs | Select-Object -First 1).IPAddress }
$SYS_NET_ALL = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)" }) -join "`n"

# 출력 파일 경로
$OUTPUT_FILE = "$PSScriptRoot\${META_PLAT}_${SYS_HOST}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"


Write-Host "  [진단 시작]" -ForegroundColor Yellow
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

    $RES = "N/A"
    $DESC = "Apache는 별도의 관리자 계정이 없음 (설정 파일 기반 운영)"

    $dtList = @()
    $dtList += "Apache HTTP Server는 IIS나 Tomcat과 달리 별도의 관리 콘솔 및 관리자 계정이 없습니다."
    $dtList += "서버 관리는 설정 파일(httpd.conf) 편집을 통해 이루어지며, 파일 시스템 권한으로 접근을 제어합니다."

    $DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check02 {
    $CODE = "WEB-02"
    $CAT = "계정관리"
    $NAME = "취약한 비밀번호 사용 제한"
    $IMP = "상"
    $STD = "관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$RES = "N/A"
$DESC = "Apache는 별도의 내장 인증 계정이 없음"

$dtList = @()
$dtList += "Apache HTTP Server는 내장된 인증 계정 시스템이 없습니다."
$dtList += "기본 인증(Basic Auth)을 사용할 경우 .htpasswd 파일을 별도로 구성하며, 이는 WEB-03 항목에서 선택적으로 점검합니다."

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check03 {
    $CODE = "WEB-03"
    $CAT = "계정관리"
    $NAME = "비밀번호 파일 권한 관리"
    $IMP = "상"
    $STD = "비밀번호 파일에 권한이 600 이하로 설정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$RES = "N/A"
$DESC = "Apache는 별도의 비밀번호 파일이 없음 (.htpasswd는 선택적 사용)"

$dtList = @()
$dtList += "Apache HTTP Server는 기본적으로 비밀번호 파일을 사용하지 않습니다."
$dtList += ".htpasswd 파일은 Basic 인증 사용 시 선택적으로 구성되며, 대부분의 환경에서는 애플리케이션 레벨에서 인증을 처리합니다."

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check04 {
    $CODE = "WEB-04"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 디렉터리 리스팅 방지 설정"
    $IMP = "상"
    $STD = "디렉터리 리스팅이 설정되지 않은 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()
$vulnerable = $false

# Options Indexes 설정 확인
$indexesOn = Get-ApacheDirective -Pattern "Options.*Indexes" | Where-Object { $_.Content -notmatch "-Indexes" }

$dtList += "[디렉터리 리스팅 설정 확인]"
$dtList += "설정 파일: $APACHE_CONF"
$dtList += ""

if ($indexesOn) {
    $vulnerable = $true
    $dtList += "[발견된 Indexes 설정]"
    foreach ($item in $indexesOn) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
} else {
    $dtList += "Options Indexes: 미설정 또는 -Indexes 설정됨 (양호)"
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "디렉터리 리스팅이 활성화되어 취약"
} else {
    $RES = "Y"
    $DESC = "디렉터리 리스팅이 비활성화되어 양호"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check05 {
    $CODE = "WEB-05"
    $CAT = "서비스관리"
    $NAME = "지정하지 않은 CGI/ISAPI 실행 제한"
    $IMP = "상"
    $STD = "CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()

# CGI 모듈 로드 확인
$cgiModule = Get-ApacheDirective -Pattern "LoadModule.*(cgi_module|cgid_module)"

# ExecCGI 옵션 확인
$execCgi = Get-ApacheDirective -Pattern "Options.*ExecCGI" | Where-Object { $_.Content -notmatch "-ExecCGI" }

# ScriptAlias 확인
$scriptAlias = Get-ApacheDirective -Pattern "ScriptAlias"

$dtList += "[CGI 실행 설정 확인]"
$dtList += ""

if ($cgiModule) {
    $dtList += "[CGI 모듈]"
    foreach ($item in $cgiModule) {
        $dtList += "  - $($item.Content)"
    }
    $dtList += ""
} else {
    $dtList += "[CGI 모듈] 비활성화"
    $dtList += ""
}

if ($execCgi) {
    $dtList += "[ExecCGI 옵션]"
    foreach ($item in $execCgi) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
    $dtList += ""
}

if ($scriptAlias) {
    $dtList += "[ScriptAlias 설정]"
    foreach ($item in $scriptAlias) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
}

if (-not $cgiModule -and -not $execCgi) {
    $RES = "Y"
    $DESC = "CGI 실행이 제한되어 양호"
} elseif ($cgiModule -or $execCgi) {
    $RES = "M"
    $DESC = "CGI 설정 존재, 필요성 수동 확인 필요"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check06 {
    $CODE = "WEB-06"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 상위 디렉터리 접근 제한 설정"
    $IMP = "상"
    $STD = "상위 디렉터리 접근 기능을 제거한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()

# AllowOverride 설정 확인
$allowOverride = Get-ApacheDirective -Pattern "AllowOverride"

$dtList += "[AllowOverride 설정 확인]"
$dtList += ""

if ($allowOverride) {
    $hasAll = $allowOverride | Where-Object { $_.Content -match "\bAll\b" }
    $hasNone = $allowOverride | Where-Object { $_.Content -match "\bNone\b" -and $_.Content -notmatch "\bAll\b" }
    $hasAuthConfig = $allowOverride | Where-Object { $_.Content -match "AuthConfig" -and $_.Content -notmatch "\bAll\b" }

    foreach ($item in $allowOverride) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }

    # AllowOverride All이 있으면 취약 (모든 지시자 오버라이드 허용)
    if ($hasAll) {
        $RES = "N"
        $DESC = "AllowOverride All 설정으로 .htaccess 오버라이드 전체 허용 (취약)"
    }
    # AllowOverride None만 있으면 양호 (.htaccess 오버라이드 차단)
    elseif ($hasNone -and -not $hasAuthConfig) {
        $RES = "Y"
        $DESC = "AllowOverride None으로 .htaccess 오버라이드 제한됨"
    }
    # AuthConfig만 있으면 수동 확인 필요
    elseif ($hasAuthConfig) {
        $RES = "M"
        $DESC = "AllowOverride AuthConfig 설정, 필요성 수동 확인 필요"
    }
    else {
        $RES = "M"
        $DESC = "AllowOverride 설정 확인 필요"
    }
} else {
    $RES = "M"
    $DESC = "AllowOverride 설정이 없음, 수동 확인 필요"
    $dtList += "AllowOverride: 미설정"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check07 {
    $CODE = "WEB-07"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 경로 내 불필요한 파일 제거"
    $IMP = "중"
    $STD = "기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()
$vulnerable = $false

# 매뉴얼 디렉터리 확인
$manualDir = Join-Path $APACHE_HOME "htdocs\manual"
$docsDir = Join-Path $APACHE_HOME "manual"

$dtList += "[불필요한 디렉터리 확인]"
$dtList += ""

if (Test-Path $manualDir) {
    $dtList += "매뉴얼 디렉터리 존재: $manualDir (취약)"
    $vulnerable = $true
}
if (Test-Path $docsDir) {
    $dtList += "매뉴얼 디렉터리 존재: $docsDir (취약)"
    $vulnerable = $true
}

# DocumentRoot에서 불필요한 파일 확인
$docRootDirective = Get-ApacheDirective -Pattern "DocumentRoot"
$docRoot = if ($docRootDirective) {
    ($docRootDirective[0].Content -replace 'DocumentRoot\s*"?', '') -replace '"$', ''
} else {
    Join-Path $APACHE_HOME "htdocs"
}

if (Test-Path $docRoot) {
    $dtList += ""
    $dtList += "[DocumentRoot 불필요 파일 확인]"
    $dtList += "DocumentRoot: $docRoot"

    $unnecessaryFiles = Get-ChildItem $docRoot -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -match "\.(bak|old|tmp|backup|log)$" -or
        $_.Name -match "^(test|sample|example|readme|install)"
    } | Select-Object -First 5

    if ($unnecessaryFiles) {
        $vulnerable = $true
        $dtList += "불필요 파일:"
        foreach ($file in $unnecessaryFiles) {
            $dtList += "  - $($file.Name)"
        }
    } else {
        $dtList += "불필요 파일 없음 (양호)"
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "불필요한 파일 또는 디렉터리가 존재하여 취약"
} else {
    $RES = "Y"
    $DESC = "불필요한 파일이 존재하지 않아 양호"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check08 {
    $CODE = "WEB-08"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 파일 업로드 및 다운로드 용량 제한"
    $IMP = "하"
    $STD = "파일 업로드 및 다운로드 용량을 제한한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()

# LimitRequestBody 설정 확인
$limitBody = Get-ApacheDirective -Pattern "LimitRequestBody"

$dtList += "[파일 업로드 용량 제한 설정]"
$dtList += ""

if ($limitBody) {
    # LimitRequestBody 값 확인 (0 = 제한 없음)
    $hasNoLimit = $false
    foreach ($item in $limitBody) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
        if ($item.Content -match "LimitRequestBody\s+0\s*$") {
            $hasNoLimit = $true
        }
    }

    if ($hasNoLimit) {
        $RES = "N"
        $DESC = "LimitRequestBody가 0으로 설정되어 용량 제한이 없음 (취약)"
        $dtList += ""
        $dtList += "[경고] LimitRequestBody 0은 용량 제한 없음을 의미합니다."
        $dtList += "[권장 설정] LimitRequestBody 5242880  # 5MB"
    } else {
        $RES = "M"
        $DESC = "파일 업로드 용량 제한이 설정됨 - 적절성 수동 확인 필요"
    }
} else {
    $RES = "N"
    $DESC = "파일 업로드 용량 제한이 설정되지 않음"
    $dtList += "LimitRequestBody: 미설정 (기본값: 제한 없음)"
    $dtList += ""
    $dtList += "[권장 설정]"
    $dtList += "LimitRequestBody 5242880  # 5MB"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check09 {
    $CODE = "WEB-09"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 프로세스 권한 제한"
    $IMP = "상"
    $STD = "웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진 별도의 계정으로 구동되고 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()
$vulnerable = $false

# Apache 서비스 실행 계정 확인
$apacheServices = @("Apache2.4", "Apache24", "Apache2", "httpd")
$foundService = $null

foreach ($svcName in $apacheServices) {
    $svc = Get-WmiObject Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
    if ($svc) {
        $foundService = $svc
        break
    }
}

$dtList += "[Apache 서비스 실행 계정 확인]"
$dtList += ""

if ($foundService) {
    $serviceName = $foundService.Name
    $startName = $foundService.StartName
    $state = $foundService.State

    $dtList += "서비스명: $serviceName"
    $dtList += "실행 계정: $startName"
    $dtList += "상태: $state"

    # LocalSystem으로 실행되면 취약
    if ($startName -match "LocalSystem|NT AUTHORITY\\SYSTEM") {
        $vulnerable = $true
        $dtList += ""
        if ($state -eq "Running") {
            $dtList += "-> 경고: LocalSystem 권한으로 실행 중 (취약)"
        } else {
            $dtList += "-> 경고: Apache 실행 시 LocalSystem 권한으로 실행됨 (취약)"
        }
        $dtList += "   Network Service 또는 별도 서비스 계정 사용 권장"
    }
} else {
    $dtList += "Apache 서비스를 찾을 수 없음"
    $dtList += ""

    # 프로세스에서 확인
    $httpdProc = Get-Process -Name "httpd" -ErrorAction SilentlyContinue
    if ($httpdProc) {
        $dtList += "[실행 중인 httpd 프로세스]"
        foreach ($proc in $httpdProc) {
            try {
                $owner = (Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.Id)").GetOwner()
                $dtList += "  PID: $($proc.Id) - 실행 계정: $($owner.Domain)\$($owner.User)"

                if ("$($owner.Domain)\$($owner.User)" -match "NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators") {
                    $vulnerable = $true
                }
            } catch {
                $dtList += "  PID: $($proc.Id) - 실행 계정 확인 실패"
            }
        }
    } else {
        $dtList += "실행 중인 Apache 프로세스 없음"
        $RES = "M"
        $DESC = "Apache 프로세스 실행 계정 수동 확인 필요"
    }
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "Apache가 관리자 권한으로 실행되어 취약"
    } else {
        $RES = "Y"
        $DESC = "Apache가 제한된 권한으로 실행되어 양호"
    }
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check10 {
    $CODE = "WEB-10"
    $CAT = "서비스관리"
    $NAME = "불필요한 프록시 설정 제한"
    $IMP = "상"
    $STD = "불필요한 Proxy 설정을 제한한 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()
$vulnerable = $false

# Proxy 모듈 확인
$proxyModule = Get-ApacheDirective -Pattern "LoadModule.*proxy_module"

# ProxyPass 설정 확인
$proxyPass = Get-ApacheDirective -Pattern "ProxyPass"

# ProxyRequests 확인 (Forward Proxy)
$proxyRequestsOn = Get-ApacheDirective -Pattern "ProxyRequests\s+On"
$proxyRequestsOff = Get-ApacheDirective -Pattern "ProxyRequests\s+Off"

$dtList += "[프록시 설정 확인]"
$dtList += ""

# Proxy 모듈 상태
if ($proxyModule) {
    $dtList += "[Proxy 모듈] 활성화"
    foreach ($item in $proxyModule) {
        $dtList += "  - $($item.Content)"
    }
} else {
    $dtList += "[Proxy 모듈] 비활성화 (미로드)"
}
$dtList += ""

# ProxyPass 설정
if ($proxyPass) {
    $dtList += "[ProxyPass 설정]"
    foreach ($item in $proxyPass) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
} else {
    $dtList += "[ProxyPass 설정] 없음"
}
$dtList += ""

# ProxyRequests 상태 출력 (항상 표시)
if ($proxyRequestsOn) {
    $vulnerable = $true
    $dtList += "[ProxyRequests] On - Forward Proxy 활성화 (취약)"
    foreach ($item in $proxyRequestsOn) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
} elseif ($proxyRequestsOff) {
    $dtList += "[ProxyRequests] Off - Forward Proxy 비활성화 (양호)"
    foreach ($item in $proxyRequestsOff) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
} else {
    $dtList += "[ProxyRequests] 미설정 (기본값: Off)"
}

# 판정: ProxyRequests On이 있으면 무조건 취약
if ($vulnerable) {
    $RES = "N"
    $DESC = "Forward Proxy가 활성화되어 취약 (ProxyRequests On)"
} elseif (-not $proxyModule -and -not $proxyPass) {
    $RES = "Y"
    $DESC = "프록시 설정이 비활성화되어 양호"
} elseif ($proxyRequestsOff) {
    $RES = "Y"
    $DESC = "Forward Proxy가 비활성화됨 (ProxyRequests Off)"
} else {
    $RES = "M"
    $DESC = "프록시 설정 존재, 필요성 수동 확인 필요"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check11 {
    $CODE = "WEB-11"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 경로 설정"
    $IMP = "중"
    $STD = "웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()

# 활성화된 Include 파일 목록 확인
$activeIncludes = @()
if (Test-Path $APACHE_CONF) {
    $confContent = Get-Content $APACHE_CONF -ErrorAction SilentlyContinue
    foreach ($line in $confContent) {
        if ($line -match "^\s*Include\s+" -and $line -notmatch "^\s*#") {
            $includePath = ($line -replace '^\s*Include\s+', '') -replace '"', ''
            $activeIncludes += $includePath
        }
    }
}

# DocumentRoot 확인 (활성화된 설정 파일에서만)
$docRootDirective = @()

# httpd.conf에서 DocumentRoot
if (Test-Path $APACHE_CONF) {
    $content = Get-Content $APACHE_CONF -ErrorAction SilentlyContinue
    $lineNum = 0
    foreach ($line in $content) {
        $lineNum++
        if ($line -match "^\s*DocumentRoot" -and $line -notmatch "^\s*#") {
            $docRootDirective += [PSCustomObject]@{
                File = $APACHE_CONF
                Line = $lineNum
                Content = $line.Trim()
                Active = $true
            }
        }
    }
}

# extra/*.conf 파일에서 DocumentRoot (Include 여부 확인)
$extraConfDir = Join-Path $APACHE_CONF_DIR "extra"
if (Test-Path $extraConfDir) {
    $extraFiles = Get-ChildItem -Path $extraConfDir -Filter "*.conf" -ErrorAction SilentlyContinue
    foreach ($file in $extraFiles) {
        $isActive = $activeIncludes | Where-Object { $file.Name -match ($_ -replace '.*[/\\]', '' -replace '\*', '.*') }
        $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
        $lineNum = 0
        foreach ($line in $content) {
            $lineNum++
            if ($line -match "^\s*DocumentRoot" -and $line -notmatch "^\s*#") {
                $docRootDirective += [PSCustomObject]@{
                    File = $file.FullName
                    Line = $lineNum
                    Content = $line.Trim()
                    Active = [bool]$isActive
                }
            }
        }
    }
}

$dtList += "[DocumentRoot 설정 확인]"
$dtList += ""

if ($docRootDirective) {
    $activeRoots = $docRootDirective | Where-Object { $_.Active }
    $inactiveRoots = $docRootDirective | Where-Object { -not $_.Active }

    if ($activeRoots) {
        $dtList += "[활성 DocumentRoot]"
        foreach ($item in $activeRoots) {
            $docRoot = ($item.Content -replace 'DocumentRoot\s*"?', '') -replace '"$', ''
            $dtList += "  DocumentRoot: $docRoot"
            $dtList += "    파일: $($item.File):$($item.Line)"

            # 시스템 경로와 분리 여부 확인
            if ($docRoot -match "^C:\\Windows|^C:\\Program Files\\Apache") {
                $dtList += "    -> 경고: 시스템 경로와 분리 필요"
                $RES = "N"
                $DESC = "DocumentRoot가 시스템 경로 내에 있어 취약"
            }
        }
        $dtList += ""
    }

    if ($inactiveRoots) {
        $dtList += "[비활성 DocumentRoot (Include 미설정)]"
        foreach ($item in $inactiveRoots) {
            $docRoot = ($item.Content -replace 'DocumentRoot\s*"?', '') -replace '"$', ''
            $dtList += "  DocumentRoot: $docRoot (미적용)"
            $dtList += "    파일: $($item.File):$($item.Line)"
        }
    }

    if ([string]::IsNullOrEmpty($RES)) {
        $RES = "Y"
        $DESC = "DocumentRoot가 적절히 설정되어 양호"
    }
} else {
    $RES = "M"
    $DESC = "DocumentRoot 설정을 찾을 수 없음, 수동 확인 필요"
    $dtList += "DocumentRoot: 미설정"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check12 {
    $CODE = "WEB-12"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 링크 사용 금지"
    $IMP = "중"
    $STD = "심볼릭 링크, aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()
$vulnerable = $false

# FollowSymLinks 설정 확인 (활성화된 것과 비활성화된 것 모두)
$followLinksOn = Get-ApacheDirective -Pattern "Options.*FollowSymLinks" | Where-Object { $_.Content -notmatch "-FollowSymLinks" }
$followLinksOff = Get-ApacheDirective -Pattern "Options.*-FollowSymLinks"

$dtList += "[심볼릭 링크 설정 확인]"
$dtList += ""

if ($followLinksOn) {
    $vulnerable = $true
    $dtList += "[FollowSymLinks 활성화 (취약)]"
    foreach ($item in $followLinksOn) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
    $dtList += ""
}

if ($followLinksOff) {
    $dtList += "[-FollowSymLinks 설정 (양호)]"
    foreach ($item in $followLinksOff) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
    $dtList += ""
}

if (-not $followLinksOn -and -not $followLinksOff) {
    $dtList += "FollowSymLinks: 미설정 (기본값에 따름)"
}

# DocumentRoot에서 바로가기 파일 확인
$docRootDirective = Get-ApacheDirective -Pattern "DocumentRoot"
if ($docRootDirective) {
    $docRoot = ($docRootDirective[0].Content -replace 'DocumentRoot\s*"?', '') -replace '"$', ''
    if (Test-Path $docRoot) {
        $shortcuts = Get-ChildItem $docRoot -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
        if ($shortcuts) {
            $vulnerable = $true
            $dtList += ""
            $dtList += "[바로가기 파일 존재 (취약)]"
            foreach ($shortcut in $shortcuts) {
                $dtList += "  - $($shortcut.FullName)"
            }
        }
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "심볼릭 링크 또는 바로가기가 허용되어 취약"
} else {
    $RES = "Y"
    $DESC = "심볼릭 링크 사용이 제한되어 양호"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check13 {
    $CODE = "WEB-13"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 설정 파일 노출 제한"
    $IMP = "상"
    $STD = "일반 사용자의 DB 연결 파일에 대한 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$RES = "N/A"
$DESC = "WEB-14에서 설정 파일 권한 점검으로 통합"

$dtList = @()
$dtList += "Apache HTTP Server의 설정 파일 노출 제한은 WEB-14(웹 서비스 경로 내 파일의 접근 통제) 항목에서 설정 파일 권한 점검으로 통합하여 진단합니다."
$dtList += "중복 점검을 방지하고 효율적인 진단을 위해 해당 항목에서 설정 파일(httpd.conf 등)의 권한을 확인합니다."

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check14 {
    $CODE = "WEB-14"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 경로 내 파일의 접근 통제"
    $IMP = "상"
    $STD = "주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()
$vulnerable = $false

# httpd.conf 권한 확인
$dtList += "[설정 파일 권한 확인]"
$dtList += ""

$confPermission = Test-VulnerablePermission -Path $APACHE_CONF
if ($confPermission) {
    $dtList += "파일: $APACHE_CONF"
    foreach ($perm in $confPermission.Permissions) {
        $dtList += "  - $perm"
    }

    if ($confPermission.Vulnerable) {
        $vulnerable = $true
        $dtList += "  -> 취약: Everyone 또는 Users 그룹에 쓰기 권한 존재"
    }
}

# conf 디렉터리 권한 확인
$dtList += ""
$dtList += "[conf 디렉터리 권한 확인]"

$confDirPermission = Test-VulnerablePermission -Path $APACHE_CONF_DIR
if ($confDirPermission) {
    $dtList += "디렉터리: $APACHE_CONF_DIR"
    foreach ($perm in $confDirPermission.Permissions | Select-Object -First 5) {
        $dtList += "  - $perm"
    }

    if ($confDirPermission.Vulnerable) {
        $vulnerable = $true
        $dtList += "  -> 취약: Everyone 또는 Users 그룹에 쓰기 권한 존재"
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "설정 파일에 불필요한 권한이 존재하여 취약"
} else {
    $RES = "Y"
    $DESC = "설정 파일 권한이 적절히 설정되어 양호"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check15 {
    $CODE = "WEB-15"
    $CAT = "서비스관리"
    $NAME = "웹 서비스의 불필요한 스크립트 매핑 제거"
    $IMP = "상"
    $STD = "불필요한 스크립트 매핑이 존재하지 않는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$RES = "N/A"
$DESC = "Apache는 모듈 기반으로 WEB-05에서 CGI 점검"

$dtList = @()
$dtList += "Apache HTTP Server는 IIS의 스크립트 매핑(.asp, .asa 등)과 달리 모듈 기반으로 스크립트를 처리합니다."
$dtList += "CGI, PHP 등의 스크립트 실행은 WEB-05(지정하지 않은 CGI/ISAPI 실행 제한) 항목에서 CGI 모듈 및 ExecCGI 옵션을 점검하여 통합 진단합니다."

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check16 {
    $CODE = "WEB-16"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 헤더 정보 노출 제한"
    $IMP = "중"
    $STD = "HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()
$vulnerable = $false

# ServerTokens 설정 확인
$serverTokens = Get-ApacheDirective -Pattern "ServerTokens"

# ServerSignature 설정 확인
$serverSig = Get-ApacheDirective -Pattern "ServerSignature"

$dtList += "[HTTP 응답 헤더 설정 확인]"
$dtList += ""

if ($serverTokens) {
    foreach ($item in $serverTokens) {
        $dtList += "ServerTokens: $($item.Content)"
        $dtList += "  파일: $($item.File):$($item.Line)"
        if ($item.Content -notmatch "Prod|ProductOnly") {
            $vulnerable = $true
            $dtList += "  -> 취약: Prod 또는 ProductOnly 권장"
        }
    }
} else {
    $vulnerable = $true
    $dtList += "ServerTokens: 미설정 (기본값 Full - 취약)"
}

$dtList += ""

if ($serverSig) {
    foreach ($item in $serverSig) {
        $dtList += "ServerSignature: $($item.Content)"
        $dtList += "  파일: $($item.File):$($item.Line)"
        if ($item.Content -notmatch "Off") {
            $vulnerable = $true
            $dtList += "  -> 취약: Off 권장"
        }
    }
} else {
    $vulnerable = $true
    $dtList += "ServerSignature: 미설정 (기본값 On - 취약)"
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "서버 헤더 정보가 노출될 수 있어 취약"
    $dtList += ""
    $dtList += "[권장 설정]"
    $dtList += "ServerTokens Prod"
    $dtList += "ServerSignature Off"
} else {
    $RES = "Y"
    $DESC = "서버 헤더 정보 노출이 제한되어 양호"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check17 {
    $CODE = "WEB-17"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 가상 디렉로리 삭제"
    $IMP = "중"
    $STD = "불필요한 가상 디렉터리가 존재하지 않는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()

# Alias 설정 확인
$aliases = Get-ApacheDirective -Pattern "^\s*Alias\s+"

$dtList += "[Alias 설정 확인]"
$dtList += ""

if ($aliases) {
    $dtList += "[발견된 Alias 설정]"
    foreach ($item in $aliases) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
    $RES = "M"
    $DESC = "Alias 설정 존재, 필요성 수동 확인 필요"
} else {
    $dtList += "Alias 설정 없음 (양호)"
    $RES = "Y"
    $DESC = "불필요한 Alias 설정이 없어 양호"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check18 {
    $CODE = "WEB-18"
    $CAT = "서비스관리"
    $NAME = "웹 서비스 WebDAV 비활성화"
    $IMP = "상"
    $STD = "WebDAV 서비스를 비활성화하고 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()
$vulnerable = $false

# WebDAV 모듈 확인
$davModule = Get-ApacheDirective -Pattern "LoadModule.*(dav_module|dav_fs_module)"

# Dav On 설정 확인
$davOn = Get-ApacheDirective -Pattern "Dav\s+On"

$dtList += "[WebDAV 설정 확인]"
$dtList += ""

if ($davModule) {
    $vulnerable = $true
    $dtList += "[WebDAV 모듈]"
    foreach ($item in $davModule) {
        $dtList += "  - $($item.Content)"
    }
    $dtList += ""
}

if ($davOn) {
    $vulnerable = $true
    $dtList += "[Dav On 설정]"
    foreach ($item in $davOn) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "WebDAV가 활성화되어 취약"
} else {
    $RES = "Y"
    $DESC = "WebDAV가 비활성화되어 양호"
    $dtList += "WebDAV 모듈 및 설정 없음 (양호)"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check19 {
    $CODE = "WEB-19"
    $CAT = "보안설정"
    $NAME = "웹 서비스 SSI(Server Side Includes) 사용 제한"
    $IMP = "중"
    $STD = "웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()
$vulnerable = $false

# SSI 모듈 확인
$ssiModule = Get-ApacheDirective -Pattern "LoadModule.*include_module"

# Options Includes 설정 확인
$includes = Get-ApacheDirective -Pattern "Options.*Includes" | Where-Object { $_.Content -notmatch "-Includes" }

$dtList += "[SSI 설정 확인]"
$dtList += ""

if ($ssiModule) {
    $dtList += "[SSI 모듈]"
    foreach ($item in $ssiModule) {
        $dtList += "  - $($item.Content)"
    }
    $dtList += ""
}

if ($includes) {
    $vulnerable = $true
    $dtList += "[Options Includes 설정]"
    foreach ($item in $includes) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
}

if ($vulnerable -or $ssiModule) {
    $RES = "N"
    $DESC = "SSI가 활성화되어 취약"
} else {
    $RES = "Y"
    $DESC = "SSI가 비활성화되어 양호"
    $dtList += "SSI 모듈 및 설정 없음 (양호)"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check20 {
    $CODE = "WEB-20"
    $CAT = "보안설정"
    $NAME = "SSL/TLS 활성화"
    $IMP = "상"
    $STD = "SSL/TLS 설정이 활성화되어 있는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()

# SSL 모듈 확인 (httpd.conf에서만, 주석 제외)
$sslModule = Get-ApacheDirective -Pattern "LoadModule.*ssl_module"

# httpd-ssl.conf Include 확인 (httpd.conf에서)
$sslInclude = $null
if (Test-Path $APACHE_CONF) {
    $confContent = Get-Content $APACHE_CONF -ErrorAction SilentlyContinue
    $lineNum = 0
    foreach ($line in $confContent) {
        $lineNum++
        if ($line -match "^\s*Include.*httpd-ssl\.conf" -and $line -notmatch "^\s*#") {
            $sslInclude = [PSCustomObject]@{
                File = $APACHE_CONF
                Line = $lineNum
                Content = $line.Trim()
            }
            break
        }
    }
}

# SSLEngine On 확인 (Include된 설정 파일에서만)
$sslEngine = $null
$listen443 = $null
if ($sslInclude) {
    $sslEngine = Get-ApacheDirective -Pattern "SSLEngine\s+On"
    $listen443 = Get-ApacheDirective -Pattern "Listen.*443"
}

# SSL 설정 파일 존재 확인
$sslConf = Join-Path $APACHE_CONF_DIR "extra\httpd-ssl.conf"

$dtList += "[SSL/TLS 설정 확인]"
$dtList += ""

if ($sslModule) {
    $dtList += "[SSL 모듈] 활성화"
    foreach ($item in $sslModule) {
        $dtList += "  - $($item.Content)"
    }
    $dtList += ""
} else {
    $dtList += "[SSL 모듈] 비활성화 (LoadModule ssl_module 주석 처리됨)"
    $dtList += ""
}

if ($sslInclude) {
    $dtList += "[SSL 설정 Include] 활성화"
    $dtList += "  - $($sslInclude.File):$($sslInclude.Line) - $($sslInclude.Content)"
    $dtList += ""
} else {
    $dtList += "[SSL 설정 Include] 비활성화 (httpd-ssl.conf Include 주석 처리됨)"
    $dtList += ""
}

if ($sslEngine) {
    $dtList += "[SSLEngine On]"
    foreach ($item in $sslEngine) {
        $dtList += "  - $($item.File):$($item.Line)"
    }
    $dtList += ""
}

if ($listen443) {
    $dtList += "[Listen 443]"
    foreach ($item in $listen443) {
        $dtList += "  - $($item.Content)"
    }
    $dtList += ""
}

if (Test-Path $sslConf) {
    $dtList += "SSL 설정 파일: $sslConf (존재)"
}

# 판정 로직: SSL 모듈 로드 + Include 활성화 + 실제 설정 필요
if ($sslModule -and $sslInclude -and ($sslEngine -or $listen443)) {
    $RES = "Y"
    $DESC = "SSL/TLS가 활성화되어 양호"
} elseif ($sslModule -and -not $sslInclude) {
    $RES = "N"
    $DESC = "SSL 모듈 로드됨, httpd-ssl.conf Include 미활성화 (취약)"
    $dtList += ""
    $dtList += "[권장 조치]"
    $dtList += "httpd.conf에서 httpd-ssl.conf Include 주석 해제"
} elseif (-not $sslModule -and ($sslEngine -or $listen443)) {
    # SSL 모듈 비활성화 + SSLEngine On 또는 Listen 443 설정이 있는 경우
    $RES = "M"
    $DESC = "SSL 설정은 있으나 SSL 모듈이 로드되지 않음"
    $dtList += ""
    $dtList += "[주의] SSL 모듈(ssl_module)을 로드해야 SSL/TLS가 작동합니다."
    $dtList += ""
    $dtList += "[권장 조치]"
    $dtList += "1. httpd.conf에서 ssl_module 주석 해제"
    $dtList += "2. httpd-ssl.conf Include 주석 해제"
} elseif (-not $sslModule) {
    $RES = "N"
    $DESC = "SSL/TLS가 비활성화되어 취약"
    $dtList += ""
    $dtList += "[권장 조치]"
    $dtList += "1. httpd.conf에서 ssl_module 주석 해제"
    $dtList += "2. httpd-ssl.conf Include 주석 해제"
    $dtList += "3. SSL 인증서 설정"
} else {
    $RES = "M"
    $DESC = "SSL 설정 확인 필요"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check21 {
    $CODE = "WEB-21"
    $CAT = "보안설정"
    $NAME = "HTTP 리디렉션"
    $IMP = "중"
    $STD = "HTTP 접근 시 HTTPS Redirection이 활성화된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()

# Redirect 설정 확인
$redirect = Get-ApacheDirective -Pattern "Redirect.*https"

# RewriteEngine On/Off 확인
$rewriteEngineOn = Get-ApacheDirective -Pattern "RewriteEngine\s+On"
$rewriteEngineOff = Get-ApacheDirective -Pattern "RewriteEngine\s+Off"

# RewriteRule 확인
$rewriteRule = Get-ApacheDirective -Pattern "RewriteRule.*https"

# RewriteCond HTTPS off 확인
$rewriteCond = Get-ApacheDirective -Pattern "RewriteCond.*HTTPS.*off"

$dtList += "[HTTP to HTTPS 리디렉션 설정 확인]"
$dtList += ""

if ($redirect) {
    $dtList += "[Redirect 설정]"
    foreach ($item in $redirect) {
        $dtList += "  - $($item.Content)"
    }
    $dtList += ""
}

# RewriteEngine 상태 출력
if ($rewriteEngineOn) {
    $dtList += "[RewriteEngine] On"
    foreach ($item in $rewriteEngineOn) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
    $dtList += ""
} elseif ($rewriteEngineOff) {
    $dtList += "[RewriteEngine] Off (비활성화)"
    foreach ($item in $rewriteEngineOff) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
    $dtList += ""
} else {
    $dtList += "[RewriteEngine] 미설정"
    $dtList += ""
}

if ($rewriteRule) {
    $dtList += "[RewriteRule 설정]"
    foreach ($item in $rewriteRule) {
        $dtList += "  - $($item.Content)"
    }
    $dtList += ""
}

if ($rewriteCond) {
    $dtList += "[RewriteCond 설정]"
    foreach ($item in $rewriteCond) {
        $dtList += "  - $($item.Content)"
    }
}

# 판정 로직
if ($redirect) {
    # Redirect 지시자는 RewriteEngine 없이도 동작
    $RES = "Y"
    $DESC = "HTTP to HTTPS 리디렉션이 설정되어 양호"
} elseif (($rewriteRule -or $rewriteCond) -and $rewriteEngineOn -and -not $rewriteEngineOff) {
    # RewriteRule/Cond + RewriteEngine On + Off 없음 = 양호
    $RES = "Y"
    $DESC = "RewriteEngine을 통한 HTTPS 리디렉션이 활성화됨"
} elseif (($rewriteRule -or $rewriteCond) -and $rewriteEngineOff) {
    # RewriteRule은 있지만 RewriteEngine Off가 있음
    $RES = "N"
    $DESC = "RewriteRule 존재하나 RewriteEngine Off로 비활성화 (취약)"
    $dtList += ""
    $dtList += "[경고] RewriteEngine Off가 설정되어 RewriteRule이 동작하지 않습니다."
} elseif ($rewriteRule -or $rewriteCond) {
    # RewriteRule은 있지만 RewriteEngine On이 없음
    $RES = "N"
    $DESC = "RewriteRule 존재하나 RewriteEngine 미활성화 (취약)"
    $dtList += ""
    $dtList += "[경고] RewriteEngine On이 설정되지 않아 RewriteRule이 동작하지 않습니다."
} else {
    $RES = "N"
    $DESC = "HTTP to HTTPS 리디렉션이 설정되지 않아 취약"
    $dtList += "리디렉션 설정 없음"
    $dtList += ""
    $dtList += "[권장 설정]"
    $dtList += "RewriteEngine On"
    $dtList += "RewriteCond %{HTTPS} off"
    $dtList += "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check22 {
    $CODE = "WEB-22"
    $CAT = "보안설정"
    $NAME = "에러 페이지 관리"
    $IMP = "하"
    $STD = "웹 서비스 에러 페이지가 별도로 지정된 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()

# ErrorDocument 설정 확인
$errorDoc = Get-ApacheDirective -Pattern "ErrorDocument"

$dtList += "[에러 페이지 설정 확인]"
$dtList += ""

if ($errorDoc) {
    $dtList += "[ErrorDocument 설정]"
    foreach ($item in $errorDoc) {
        $dtList += "  - $($item.File):$($item.Line) - $($item.Content)"
    }
    $dtList += ""

    # 주요 오류 코드 필수 설정 확인 (400, 401, 403, 404, 500)
    $requiredCodes = @("400", "401", "403", "404", "500")
    $missingCodes = @()
    foreach ($code in $requiredCodes) {
        $found = $errorDoc | Where-Object { $_.Content -match "ErrorDocument\s+$code\b" }
        if (-not $found) {
            $missingCodes += $code
        }
    }

    # .var 파일 사용 여부 확인 (Apache 기본 에러 페이지 - 버전 정보 노출)
    $usesVarFile = $errorDoc | Where-Object { $_.Content -match "\.var" }

    if ($missingCodes.Count -gt 0) {
        $RES = "N"
        $DESC = "주요 에러 코드 중 일부에 대한 에러 페이지가 미설정됨"
        $dtList += "[취약] 미설정 에러 코드: $($missingCodes -join ', ')"
        $dtList += "필수 에러 코드(400,401,403,404,500)에 대한 ErrorDocument 설정이 필요합니다."
    } elseif ($usesVarFile) {
        $RES = "N"
        $DESC = "기본 에러 페이지(.var) 사용으로 버전 정보 노출 가능 (취약)"
        $dtList += "[경고] .var 파일은 Apache 기본 에러 페이지로 버전 정보가 노출됩니다."
        $dtList += ""
        $dtList += "[권장 조치]"
        $dtList += "커스텀 에러 페이지로 변경하세요."
    } else {
        $RES = "Y"
        $DESC = "주요 에러 코드(400,401,403,404,500)에 대한 커스텀 에러 페이지가 설정되어 양호"
    }
} else {
    $RES = "N"
    $DESC = "에러 페이지가 설정되지 않아 취약"
    $dtList += "ErrorDocument: 미설정 (기본 에러 페이지 사용)"
    $dtList += ""
    $dtList += "[권장 설정]"
    $dtList += "ErrorDocument 400 /error.html"
    $dtList += "ErrorDocument 401 /error.html"
    $dtList += "ErrorDocument 403 /error.html"
    $dtList += "ErrorDocument 404 /error.html"
    $dtList += "ErrorDocument 500 /error.html"
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check23 {
    $CODE = "WEB-23"
    $CAT = "보안설정"
    $NAME = "LDAP 알고리즘 적절하게 구성"
    $IMP = "중"
    $STD = "LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$RES = "N/A"
$DESC = "Apache 자체는 LDAP 인증 서버가 아님 (mod_ldap은 별도 모듈)"

$dtList = @()
$dtList += "Apache HTTP Server는 LDAP 인증 서버가 아니며, LDAP 연동 시 mod_ldap/mod_authnz_ldap 모듈을 사용합니다."
$dtList += "LDAP 인증 알고리즘 및 보안 설정은 연동된 LDAP 서버(OpenLDAP, Active Directory 등)에서 관리하며, Apache는 클라이언트 역할만 수행합니다."

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check24 {
    $CODE = "WEB-24"
    $CAT = "보안설정"
    $NAME = "별도의 업로드 경로 사용 및 권한 설정"
    $IMP = "중"
    $STD = "별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$RES = "M"
$DESC = "업로드 경로 및 권한 수동 확인 필요"

$dtList = @()

# DocumentRoot 확인
$docRootDirective = Get-ApacheDirective -Pattern "DocumentRoot"
$docRoot = if ($docRootDirective) {
    ($docRootDirective[0].Content -replace 'DocumentRoot\s*"?', '') -replace '"$', ''
} else {
    Join-Path $APACHE_HOME "htdocs"
}

$dtList += "[웹 서비스 경로 정보]"
$dtList += "DocumentRoot: $docRoot"
$dtList += ""

$foundUploadDirs = @()
if (Test-Path $docRoot) {
    # 일반적인 업로드 디렉터리 확인
    $uploadDirs = @("uploads", "upload", "files", "attachments", "media")

    foreach ($dir in $uploadDirs) {
        $uploadPath = Join-Path $docRoot $dir
        if (Test-Path $uploadPath) {
            $foundUploadDirs += $uploadPath
        }
    }
}

if ($foundUploadDirs.Count -gt 0) {
    $dtList += "[DocumentRoot 내 업로드 디렉터리 발견]"
    foreach ($uploadPath in $foundUploadDirs) {
        $dtList += "경로: $uploadPath"
        $permission = Test-VulnerablePermission -Path $uploadPath
        if ($permission) {
            foreach ($perm in $permission.Permissions | Select-Object -First 3) {
                $dtList += "  - $perm"
            }
        }
        $dtList += ""
    }
    $dtList += "[경고] 업로드 디렉터리가 DocumentRoot 내부에 위치함"
    $dtList += "  -> DocumentRoot 외부로 분리 권장"
    $dtList += ""
} else {
    $dtList += "[업로드 디렉터리]"
    $dtList += "DocumentRoot 내 업로드 디렉터리 없음"
    $dtList += ""
}

$dtList += "[수동 확인 필요]"
$dtList += "- 업로드 디렉터리가 DocumentRoot 외부에 위치하는지 확인"
$dtList += "- 업로드 디렉터리에 스크립트 실행 권한이 없는지 확인"
$dtList += "- Everyone/Users 그룹의 불필요한 권한 제거"

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check25 {
    $CODE = "WEB-25"
    $CAT = "패치및로그관리"
    $NAME = "주기적 보안 패치 및 벤더 권고사항 적용"
    $IMP = "상"
    $STD = "최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$RES = "M"
$DESC = "Apache 버전 및 패치 수준 수동 확인 필요"

$dtList = @()

$dtList += "[Apache 버전 정보]"
$dtList += ""

if ($APACHE_VERSION) {
    $dtList += "버전: $APACHE_VERSION"
} else {
    $dtList += "버전: 확인 불가"
}

$dtList += "설치 경로: $APACHE_HOME"
$dtList += ""

# httpd.exe 파일 정보
$httpdExe = Join-Path $APACHE_HOME "bin\httpd.exe"
if (Test-Path $httpdExe) {
    $fileInfo = Get-Item $httpdExe
    $dtList += "[httpd.exe 파일 정보]"
    $dtList += "수정일: $($fileInfo.LastWriteTime)"
    $dtList += "크기: $([math]::Round($fileInfo.Length / 1KB, 2)) KB"
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- 최신 버전: https://httpd.apache.org/download.cgi"
$dtList += "- 보안 권고: https://httpd.apache.org/security/"
$dtList += "- 정기적인 패치 적용 정책 수립 및 관리"

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}

function Check26 {
    $CODE = "WEB-26"
    $CAT = "패치및로그관리"
    $NAME = "로그 디렉터리 및 파일 권한 설정"
    $IMP = "중"
    $STD = "로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우"
    $RES = ""
    $DESC = ""
    $DT = ""

$dtList = @()
$vulnerable = $false

# 로그 디렉터리 확인
$logDir = Join-Path $APACHE_HOME "logs"

$dtList += "[로그 디렉터리 권한 확인]"
$dtList += ""

if (Test-Path $logDir) {
    $dtList += "로그 디렉터리: $logDir"
    $dtList += ""

    $permission = Test-VulnerablePermission -Path $logDir
    if ($permission) {
        $dtList += "[디렉터리 권한]"
        foreach ($perm in $permission.Permissions | Select-Object -First 5) {
            $dtList += "  - $perm"
        }

        if ($permission.Vulnerable) {
            $vulnerable = $true
            $dtList += "  -> 취약: Everyone 또는 Users 그룹에 쓰기 권한 존재"
        }
    }

    # 로그 파일 권한 확인
    $logFiles = Get-ChildItem $logDir -Filter "*.log" -ErrorAction SilentlyContinue | Select-Object -First 3
    if ($logFiles) {
        $dtList += ""
        $dtList += "[로그 파일 권한]"
        foreach ($file in $logFiles) {
            $filePermission = Test-VulnerablePermission -Path $file.FullName
            $dtList += "$($file.Name):"
            if ($filePermission -and $filePermission.Vulnerable) {
                $vulnerable = $true
                $dtList += "  -> 취약: 일반 사용자 접근 가능"
            }
        }
    }
} else {
    $dtList += "로그 디렉터리를 찾을 수 없음: $logDir"
    $RES = "M"
    $DESC = "로그 디렉터리 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "로그 디렉터리에 불필요한 권한이 존재하여 취약"
    } else {
        $RES = "Y"
        $DESC = "로그 디렉터리 권한이 적절히 설정되어 양호"
    }
}

$DT = $dtList -join "`n"

    Output-Checkpoint $CODE $CAT $NAME $IMP $STD $RES $DESC $DT
}


#================================================================
# EXECUTE
#================================================================
Write-Host "[*] 진단 시작..."
Write-Host "[*] 호스트: $SYS_HOST"
Write-Host "[*] 서비스: $(if ($SVC_VERSION) { $SVC_VERSION } else { 'Not found' })"

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
            <n>$SYS_OS_NAME</n>
            <fn>$SYS_OS_FN</fn>
        </os>
        <kn>$SYS_KN</kn>
        <arch>$SYS_ARCH</arch>
        <net>
            <ip>$SYS_IP</ip>
            <all><![CDATA[N/A]]></all>
        </net>
        <svc>
            <ver><![CDATA[$SVC_VERSION]]></ver>
            <conf>$SVC_CONF</conf>
        </svc>
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

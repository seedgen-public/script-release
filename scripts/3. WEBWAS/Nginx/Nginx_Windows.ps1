#================================================================
# Nginx_Windows 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Nginx_Windows
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
$META_PLAT = "Nginx"
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
function Find-NginxInstallPath {
    $nginxPaths = @()

    # 방법 1: 일반적인 설치 경로 확인
    $commonPaths = @(
        "C:\nginx",
        "C:\Program Files\nginx",
        "C:\Program Files (x86)\nginx",
        "D:\nginx",
        "E:\nginx"
    )

    foreach ($path in $commonPaths) {
        if (Test-Path "$path\nginx.exe") {
            $nginxPaths += $path
        }
    }

    # 방법 2: NGINX_HOME 환경변수 확인
    $nginxHome = [Environment]::GetEnvironmentVariable("NGINX_HOME", "Machine")
    if ($nginxHome -and (Test-Path "$nginxHome\nginx.exe")) {
        if ($nginxPaths -notcontains $nginxHome) {
            $nginxPaths += $nginxHome
        }
    }
    $nginxHome = [Environment]::GetEnvironmentVariable("NGINX_HOME", "User")
    if ($nginxHome -and (Test-Path "$nginxHome\nginx.exe")) {
        if ($nginxPaths -notcontains $nginxHome) {
            $nginxPaths += $nginxHome
        }
    }

    # 방법 3: 실행 중인 nginx.exe 프로세스에서 경로 추출
    try {
        $nginxProcesses = Get-Process -Name "nginx" -ErrorAction SilentlyContinue
        foreach ($proc in $nginxProcesses) {
            $procPath = Split-Path -Parent $proc.Path
            if ($procPath -and ($nginxPaths -notcontains $procPath)) {
                $nginxPaths += $procPath
            }
        }
    } catch { }

    # 방법 4: where 명령으로 PATH에서 검색
    try {
        $whereResult = & where.exe nginx.exe 2>$null
        if ($whereResult) {
            $procPath = Split-Path -Parent $whereResult
            if ($procPath -and ($nginxPaths -notcontains $procPath)) {
                $nginxPaths += $procPath
            }
        }
    } catch { }

    return $nginxPaths
}

# Nginx 경로 탐지
$script:NGINX_PATHS = Find-NginxInstallPath

if ($script:NGINX_PATHS.Count -eq 0) {
    Write-Host "[X] Nginx가 설치되어 있지 않습니다." -ForegroundColor Red
    Write-Host "    이 스크립트는 Nginx가 설치된 시스템에서만 실행 가능합니다." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    탐색한 경로:" -ForegroundColor Yellow
    Write-Host "    - C:\nginx" -ForegroundColor Gray
    Write-Host "    - C:\Program Files\nginx" -ForegroundColor Gray
    Write-Host "    - NGINX_HOME 환경변수" -ForegroundColor Gray
    Write-Host "    - nginx.exe 프로세스" -ForegroundColor Gray
    Read-Host "Press Enter to exit"
    exit 1
}

# 첫 번째 경로를 기본 경로로 사용
$script:NGINX_HOME = $script:NGINX_PATHS[0]
$script:NGINX_CONF = "$script:NGINX_HOME\conf\nginx.conf"

# Nginx 설정 파일 파싱 함수
function Get-NginxConfig {
    param(
        [string]$ConfigPath = $script:NGINX_CONF
    )

    if (-not (Test-Path $ConfigPath)) {
        return $null
    }

    try {
        $content = Get-Content $ConfigPath -Raw -ErrorAction SilentlyContinue
        return $content
    } catch {
        return $null
    }
}

function Get-NginxConfigValue {
    param(
        [string]$Content,
        [string]$Directive,
        [string]$Default = ""
    )

    if (-not $Content) { return $Default }

    # 지시자 값 추출 (예: server_tokens off;)
    $pattern = "(?m)^\s*$Directive\s+([^;]+);"
    if ($Content -match $pattern) {
        return $matches[1].Trim()
    }
    return $Default
}

function Test-NginxDirectiveExists {
    param(
        [string]$Content,
        [string]$Directive
    )

    if (-not $Content) { return $false }

    $pattern = "(?m)^\s*$Directive\s+"
    return $Content -match $pattern
}

# Nginx 버전 정보
$NGINX_VERSION = ""
$nginxExe = Join-Path $script:NGINX_HOME "nginx.exe"
if (Test-Path $nginxExe) {
    try {
        $versionOutput = & $nginxExe -v 2>&1
        $NGINX_VERSION = "$versionOutput"
    } catch { }
}

$SVC_VERSION = $NGINX_VERSION
$SVC_CONF = $script:NGINX_CONF

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

# Nginx 버전 수집
$NGINX_VERSION = ""
try {
    $nginxExe = "$script:NGINX_HOME\nginx.exe"
    if (Test-Path $nginxExe) {
        $versionOutput = & $nginxExe -v 2>&1
        if ($versionOutput -match "nginx/([0-9\.]+)") {
            $NGINX_VERSION = $matches[1]
        }
    }
} catch { }

# 설정 파일 내용 로드
$script:NGINX_CONFIG_CONTENT = Get-NginxConfig

# 출력 파일 경로
$OUTPUT_FILE = "$PSScriptRoot\${META_PLAT}_${SYS_HOST}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"


Write-Host "  [진단 시작]" -ForegroundColor Yellow
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

    $RES = "N/A"
    $DESC = "Nginx는 별도의 관리자 계정이 없음 (설정 파일 기반 운영)"
    $DT = @"
Nginx는 별도의 관리 콘솔이나 관리자 계정을 사용하지 않습니다.
설정 파일(nginx.conf)을 직접 편집하여 운영하므로 해당 점검 항목은 N/A 처리됩니다.
"@

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
    $DESC = "Nginx는 별도의 내장 인증 계정이 없음"
    $DT = @"
Nginx는 자체적인 사용자 인증 계정 시스템을 제공하지 않습니다.
Basic 인증 사용 시 htpasswd 파일로 관리하며, 이는 WEB-03에서 점검합니다.
해당 점검 항목은 N/A 처리됩니다.
"@

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
    $DESC = "Nginx는 별도의 비밀번호 파일이 없음"
    $DT = @"
Nginx는 자체적인 비밀번호 파일을 사용하지 않습니다.
Basic 인증 사용 시 htpasswd 파일은 별도 관리가 필요하며,
해당 점검 항목은 N/A 처리됩니다.
"@

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

$dtList += "[Nginx 디렉터리 리스팅 설정 확인]"
$dtList += "설정 파일: $script:NGINX_CONF"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # autoindex 설정 확인
    $autoindexPattern = "(?m)^\s*autoindex\s+(\w+)\s*;"
    $matches_found = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $autoindexPattern)

    if ($matches_found.Count -gt 0) {
        foreach ($match in $matches_found) {
            $value = $match.Groups[1].Value.ToLower()
            $dtList += "autoindex: $value"

            if ($value -eq "on") {
                $vulnerable = $true
                $dtList += "  -> 취약: 디렉터리 리스팅이 활성화됨"
            } else {
                $dtList += "  -> 양호: 디렉터리 리스팅이 비활성화됨"
            }
        }
    } else {
        $dtList += "autoindex 설정 없음 (기본값: off)"
        $dtList += "  -> 양호: 디렉터리 리스팅이 비활성화됨"
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "autoindex on 설정이 존재하여 취약"
    } else {
        $RES = "Y"
        $DESC = "디렉터리 리스팅이 비활성화되어 양호"
    }
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
$hasRestriction = $true

$dtList += "[Nginx FastCGI/CGI 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # fastcgi_pass 설정 확인
    $fastcgiPattern = "(?m)^\s*fastcgi_pass\s+([^;]+);"
    $fastcgiMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $fastcgiPattern)

    if ($fastcgiMatches.Count -gt 0) {
        $dtList += "[FastCGI 설정]"
        foreach ($match in $fastcgiMatches) {
            $dtList += "fastcgi_pass: $($match.Groups[1].Value)"
        }
        $dtList += ""
    } else {
        $dtList += "FastCGI 설정 없음"
    }

    # location 블록에서 .cgi, .pl 등 스크립트 매핑 확인
    $scriptPattern = "(?m)location\s+~\s+\\\.(cgi|pl|py|sh)"
    if ($script:NGINX_CONFIG_CONTENT -match $scriptPattern) {
        $dtList += ""
        $dtList += "[경고] CGI/스크립트 매핑 발견"
        $dtList += "  -> 스크립트 실행 디렉터리 제한 확인 필요"
    }

    # 디렉터리별 스크립트 실행 제한 확인
    $denyPattern = "(?m)location\s+[^{]+\{\s*[^}]*deny\s+all"
    if ($script:NGINX_CONFIG_CONTENT -match $denyPattern) {
        $dtList += ""
        $dtList += "접근 제한 설정 존재 (양호)"
    }

    $dtList += ""
    $dtList += "[수동 확인 필요]"
    $dtList += "- 업로드 디렉터리에서 스크립트 실행 차단 여부 확인"
    $dtList += "- fastcgi_pass 설정이 필요한 경로에만 적용되었는지 확인"

    $RES = "M"
    $DESC = "CGI/스크립트 설정 수동 확인 필요"
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
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
$vulnerable = $false

$dtList += "[상위 디렉터리 접근 제한 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # .. 경로 차단 설정 확인
    # location 블록에서 상위 경로 접근 차단 패턴 확인
    $blockPattern = "(?m)location\s+~\s+\.\."
    $rewritePattern = "(?m)if\s+\(\s*\`$uri\s+~\s+\.\.\s*\)"

    if ($script:NGINX_CONFIG_CONTENT -match $blockPattern -or $script:NGINX_CONFIG_CONTENT -match $rewritePattern) {
        $dtList += "상위 디렉터리(..) 접근 차단 설정 존재"
        $dtList += "  -> 양호"
    } else {
        $dtList += "명시적인 상위 디렉터리 접근 차단 설정 없음"
        $dtList += ""
        $dtList += "[권장 설정]"
        $dtList += "location ~ \\.\\. {"
        $dtList += "    deny all;"
        $dtList += "}"
    }

    # auth_basic 설정 확인 (디렉터리 접근 제한)
    $authPattern = "(?m)^\s*auth_basic\s+"
    if ($script:NGINX_CONFIG_CONTENT -match $authPattern) {
        $dtList += ""
        $dtList += "[인증 설정]"
        $dtList += "auth_basic 설정 존재 - 디렉터리 접근 인증 적용됨"
    }

    $dtList += ""
    $dtList += "[수동 확인 필요]"
    $dtList += "- URL에 '..' 문자열을 포함한 요청이 차단되는지 확인"
    $dtList += "- 민감한 디렉터리에 인증이 적용되었는지 확인"

    $RES = "M"
    $DESC = "상위 디렉터리 접근 차단 설정 수동 확인 필요"
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
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

$dtList += "[불필요한 파일 확인]"
$dtList += ""

# Nginx html 디렉터리 확인
$htmlDir = "$script:NGINX_HOME\html"
if (Test-Path $htmlDir) {
    $dtList += "HTML 디렉터리: $htmlDir"
    $dtList += ""

    # 기본 설치 파일 확인
    $defaultFiles = @("index.html", "50x.html")
    foreach ($file in $defaultFiles) {
        $filePath = Join-Path $htmlDir $file
        if (Test-Path $filePath) {
            $content = Get-Content $filePath -Raw -ErrorAction SilentlyContinue
            if ($content -match "Welcome to nginx" -or $content -match "nginx error page") {
                $dtList += "기본 파일 존재: $file (취약)"
                $vulnerable = $true
            }
        }
    }

    # 불필요한 파일 패턴 확인
    $unnecessaryFiles = Get-ChildItem $htmlDir -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -match "\.(bak|old|tmp|temp|backup|log|txt)$" -or
        $_.Name -match "^(test|sample|example|readme|install)"
    }

    if ($unnecessaryFiles) {
        $dtList += ""
        $dtList += "[불필요한 파일 발견]"
        foreach ($file in $unnecessaryFiles | Select-Object -First 10) {
            $dtList += "  - $($file.Name)"
            $vulnerable = $true
        }
    }
} else {
    $dtList += "HTML 디렉터리 없음: $htmlDir"
}

# conf 디렉터리 내 백업 파일 확인
$confDir = "$script:NGINX_HOME\conf"
if (Test-Path $confDir) {
    $backupConfigs = Get-ChildItem $confDir -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -match "\.(bak|old|backup|orig)$"
    }

    if ($backupConfigs) {
        $dtList += ""
        $dtList += "[설정 파일 백업 발견]"
        foreach ($file in $backupConfigs | Select-Object -First 5) {
            $dtList += "  - $($file.Name)"
            $vulnerable = $true
        }
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "불필요한 파일이 존재하여 취약"
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

$dtList += "[파일 업로드 용량 제한 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # client_max_body_size 설정 확인
    $bodySize = Get-NginxConfigValue -Content $script:NGINX_CONFIG_CONTENT -Directive "client_max_body_size" -Default "1m (기본값)"

    $dtList += "client_max_body_size: $bodySize"

    if ($bodySize -eq "1m (기본값)") {
        $dtList += "  -> 기본값(1MB) 사용 중"
        $dtList += "  -> 업무 환경에 따라 조정 필요"
    } elseif ($bodySize -match "^(\d+)([kmgKMG])?$") {
        $dtList += "  -> 명시적 용량 제한 설정됨"
    }

    # client_body_buffer_size 설정 확인
    $bufferSize = Get-NginxConfigValue -Content $script:NGINX_CONFIG_CONTENT -Directive "client_body_buffer_size" -Default "설정 없음"
    if ($bufferSize -ne "설정 없음") {
        $dtList += "client_body_buffer_size: $bufferSize"
    }

    $dtList += ""
    $dtList += "[권장 사항]"
    $dtList += "- 업무 요구사항에 맞는 적절한 용량 제한 설정"
    $dtList += "- 권장: client_max_body_size 5M;"

    $RES = "Y"
    $DESC = "파일 업로드 용량 제한이 설정되어 양호"
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
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

$dtList += "[Nginx 프로세스 권한 확인]"
$dtList += ""

# 실행 중인 nginx 프로세스 확인
try {
    $nginxProcesses = Get-Process -Name "nginx" -ErrorAction SilentlyContinue

    if ($nginxProcesses) {
        $dtList += "[실행 중인 프로세스]"

        foreach ($proc in $nginxProcesses) {
            $owner = (Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue).GetOwner()
            if ($owner) {
                $userName = "$($owner.Domain)\$($owner.User)"
                $dtList += "PID: $($proc.Id) - User: $userName"

                # 관리자 권한 확인
                if ($userName -match "SYSTEM|Administrator|Administrators") {
                    $dtList += "  -> 경고: 관리자 권한으로 실행 중"
                    $vulnerable = $true
                }
            }
        }
    } else {
        $dtList += "실행 중인 nginx 프로세스 없음"
        $dtList += ""
        $dtList += "[수동 확인 필요]"
        $dtList += "- Nginx 서비스 실행 계정 확인"
    }
} catch {
    $dtList += "프로세스 정보 확인 실패: $_"
}

# Windows 서비스로 등록된 경우 확인
$dtList += ""
$dtList += "[서비스 설정]"

try {
    $nginxService = Get-Service -Name "*nginx*" -ErrorAction SilentlyContinue
    if ($nginxService) {
        $serviceInfo = Get-WmiObject Win32_Service -Filter "Name='$($nginxService.Name)'" -ErrorAction SilentlyContinue
        if ($serviceInfo) {
            $dtList += "서비스명: $($serviceInfo.Name)"
            $dtList += "실행 계정: $($serviceInfo.StartName)"

            if ($serviceInfo.StartName -match "LocalSystem|SYSTEM") {
                $dtList += "  -> 경고: LocalSystem 계정으로 실행됨"
                $vulnerable = $true
            }
        }
    } else {
        $dtList += "Nginx가 Windows 서비스로 등록되지 않음"
    }
} catch {
    $dtList += "서비스 정보 확인 실패"
}

$dtList += ""
$dtList += "[권장 사항]"
$dtList += "- 전용 서비스 계정 생성 (예: nginx)"
$dtList += "- 해당 계정으로 Nginx 서비스 실행"
$dtList += "- 관리자 그룹에서 제외"

if ($vulnerable) {
    $RES = "N"
    $DESC = "관리자 권한으로 실행되어 취약"
} else {
    $RES = "M"
    $DESC = "프로세스 권한 수동 확인 필요"
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

$RES = "M"
$DESC = "프록시 설정 수동 확인 필요"

$dtList = @()

$dtList += "[Nginx 프록시 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # proxy_pass 설정 확인
    $proxyPattern = "(?m)^\s*proxy_pass\s+([^;]+);"
    $proxyMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $proxyPattern)

    if ($proxyMatches.Count -gt 0) {
        $dtList += "[발견된 프록시 설정]"
        foreach ($match in $proxyMatches) {
            $dtList += "proxy_pass: $($match.Groups[1].Value)"
        }
        $dtList += ""
        $dtList += "[수동 확인 필요]"
        $dtList += "- 각 프록시 설정이 필요한 것인지 확인"
        $dtList += "- 불필요한 프록시 설정 제거"
    } else {
        $dtList += "프록시 설정 없음"
        $RES = "Y"
        $DESC = "불필요한 프록시 설정이 없어 양호"
    }

    # upstream 설정 확인
    $upstreamPattern = "(?m)upstream\s+(\w+)\s*\{"
    $upstreamMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $upstreamPattern)

    if ($upstreamMatches.Count -gt 0) {
        $dtList += ""
        $dtList += "[Upstream 설정]"
        foreach ($match in $upstreamMatches) {
            $dtList += "upstream: $($match.Groups[1].Value)"
        }
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
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
$vulnerable = $false

$dtList += "[웹 서비스 경로 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # root 설정 확인
    $rootPattern = "(?m)^\s*root\s+([^;]+);"
    $rootMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $rootPattern)

    if ($rootMatches.Count -gt 0) {
        $dtList += "[DocumentRoot 설정]"
        foreach ($match in $rootMatches) {
            $rootPath = $match.Groups[1].Value.Trim()
            $dtList += "root: $rootPath"

            # 시스템 경로와 분리 여부 확인
            $systemPaths = @("C:\Windows", "C:\Program Files", "C:\Users")
            foreach ($sysPath in $systemPaths) {
                if ($rootPath -like "$sysPath*") {
                    $dtList += "  -> 경고: 시스템 경로와 분리 필요"
                    $vulnerable = $true
                }
            }
        }
    } else {
        $dtList += "root 설정 없음 (기본값 사용)"
    }

    # Nginx 설치 경로 내 html 디렉터리 사용 확인
    $defaultHtml = "$script:NGINX_HOME\html"
    if (Test-Path $defaultHtml) {
        $dtList += ""
        $dtList += "[기본 HTML 디렉터리]"
        $dtList += "경로: $defaultHtml"
        $dtList += "  -> 업무 환경에 맞는 별도 경로 사용 권장"
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "웹 서비스 경로가 시스템 경로와 분리되지 않아 취약"
    } else {
        $RES = "Y"
        $DESC = "웹 서비스 경로가 적절히 설정되어 양호"
    }
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

$dtList += "[심볼릭 링크 사용 제한 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # disable_symlinks 설정 확인
    $symlinkValue = Get-NginxConfigValue -Content $script:NGINX_CONFIG_CONTENT -Directive "disable_symlinks" -Default "설정 없음"

    if ($symlinkValue -eq "설정 없음") {
        $dtList += "disable_symlinks 설정 없음"
        $dtList += "  -> 기본값: 심볼릭 링크 허용"
        $dtList += ""
        $dtList += "[권장 설정]"
        $dtList += "disable_symlinks on;"
        $vulnerable = $true
    } else {
        $dtList += "disable_symlinks: $symlinkValue"
        if ($symlinkValue -match "^on") {
            $dtList += "  -> 양호: 심볼릭 링크 사용 제한됨"
        } else {
            $dtList += "  -> 취약: 심볼릭 링크 허용됨"
            $vulnerable = $true
        }
    }

    # alias 설정 확인
    $aliasPattern = "(?m)^\s*alias\s+([^;]+);"
    $aliasMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $aliasPattern)

    if ($aliasMatches.Count -gt 0) {
        $dtList += ""
        $dtList += "[Alias 설정]"
        foreach ($match in $aliasMatches) {
            $dtList += "alias: $($match.Groups[1].Value)"
        }
        $dtList += "  -> 불필요한 alias 설정 확인 필요"
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

# 웹 루트에 바로가기 파일 확인 (Windows)
$htmlDir = "$script:NGINX_HOME\html"
if (Test-Path $htmlDir) {
    $shortcuts = Get-ChildItem $htmlDir -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
    if ($shortcuts) {
        $dtList += ""
        $dtList += "[바로가기 파일 발견]"
        foreach ($shortcut in $shortcuts) {
            $dtList += "  - $($shortcut.FullName)"
            $vulnerable = $true
        }
    }
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "심볼릭 링크 사용이 제한되지 않아 취약"
    } else {
        $RES = "Y"
        $DESC = "심볼릭 링크 사용이 제한되어 양호"
    }
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
    $DT = @"
Nginx 설정 파일 노출 제한은 WEB-14(웹 서비스 경로 내 파일의 접근 통제) 항목에서
설정 파일 권한 점검으로 통합하여 진단합니다.
해당 점검 항목은 N/A 처리됩니다.
"@

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

$dtList += "[설정 파일 및 디렉터리 권한 확인]"
$dtList += ""

# nginx.conf 권한 확인
if (Test-Path $script:NGINX_CONF) {
    $dtList += "[nginx.conf 권한]"
    $dtList += "경로: $script:NGINX_CONF"

    try {
        $acl = Get-Acl $script:NGINX_CONF -ErrorAction SilentlyContinue
        foreach ($access in $acl.Access) {
            $identity = $access.IdentityReference.Value
            $rights = $access.FileSystemRights

            $dtList += "  $identity : $rights"

            # Everyone에 쓰기 권한이 있으면 취약
            if ($identity -match "Everyone" -and $rights -match "Write|FullControl|Modify") {
                $vulnerable = $true
                $dtList += "    -> 취약: Everyone 쓰기 권한"
            }
        }
    } catch {
        $dtList += "  권한 확인 실패: $_"
    }
}

# conf 디렉터리 권한 확인
$confDir = "$script:NGINX_HOME\conf"
if (Test-Path $confDir) {
    $dtList += ""
    $dtList += "[conf 디렉터리 권한]"
    $dtList += "경로: $confDir"

    try {
        $acl = Get-Acl $confDir -ErrorAction SilentlyContinue
        foreach ($access in $acl.Access | Select-Object -First 5) {
            $identity = $access.IdentityReference.Value
            $rights = $access.FileSystemRights
            $dtList += "  $identity : $rights"

            if ($identity -match "Everyone" -and $rights -match "Write|FullControl|Modify") {
                $vulnerable = $true
            }
        }
    } catch {
        $dtList += "  권한 확인 실패"
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
    $DESC = "Nginx는 location 기반으로 WEB-05에서 점검"
    $DT = @"
Nginx는 IIS와 같은 스크립트 매핑 방식이 아닌 location 블록 기반으로 스크립트를 처리합니다.
스크립트 실행 제한은 WEB-05(지정하지 않은 CGI/ISAPI 실행 제한) 항목에서 점검합니다.
해당 점검 항목은 N/A 처리됩니다.
"@

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

$dtList += "[HTTP 응답 헤더 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # server_tokens 설정 확인
    $serverTokens = Get-NginxConfigValue -Content $script:NGINX_CONFIG_CONTENT -Directive "server_tokens" -Default "on (기본값)"

    $dtList += "server_tokens: $serverTokens"

    if ($serverTokens -eq "on (기본값)" -or $serverTokens -eq "on") {
        $dtList += "  -> 취약: 서버 버전 정보가 노출됨"
        $dtList += ""
        $dtList += "[권장 설정]"
        $dtList += "server_tokens off;"
        $vulnerable = $true
    } else {
        $dtList += "  -> 양호: 서버 버전 정보가 숨겨짐"
    }

    # more_clear_headers 또는 proxy_hide_header 확인
    $hideHeaderPattern = "(?m)^\s*(more_clear_headers|proxy_hide_header)\s+"
    if ($script:NGINX_CONFIG_CONTENT -match $hideHeaderPattern) {
        $dtList += ""
        $dtList += "추가 헤더 숨김 설정 존재"
    }

    # add_header로 보안 헤더 추가 확인
    $addHeaderPattern = "(?m)^\s*add_header\s+([^\s]+)"
    $addHeaderMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $addHeaderPattern)

    if ($addHeaderMatches.Count -gt 0) {
        $dtList += ""
        $dtList += "[추가된 보안 헤더]"
        foreach ($match in $addHeaderMatches | Select-Object -First 10) {
            $dtList += "  - $($match.Groups[1].Value)"
        }
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "server_tokens off 미설정으로 서버 정보 노출"
    } else {
        $RES = "Y"
        $DESC = "서버 정보 노출이 제한되어 양호"
    }
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

$RES = "M"
$DESC = "가상 디렉터리(alias) 설정 수동 확인 필요"

$dtList = @()

$dtList += "[가상 디렉터리 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # alias 설정 확인
    $aliasPattern = "(?m)^\s*alias\s+([^;]+);"
    $aliasMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $aliasPattern)

    if ($aliasMatches.Count -gt 0) {
        $dtList += "[발견된 Alias 설정]"
        foreach ($match in $aliasMatches) {
            $dtList += "alias: $($match.Groups[1].Value)"
        }
        $dtList += ""
        $dtList += "[수동 확인 필요]"
        $dtList += "- 각 alias 설정이 필요한 것인지 확인"
        $dtList += "- 불필요한 alias 설정 제거"
    } else {
        $dtList += "alias 설정 없음"
        $RES = "Y"
        $DESC = "불필요한 가상 디렉터리가 없어 양호"
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
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

$dtList += "[WebDAV 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # dav_methods 설정 확인
    $davPattern = "(?m)^\s*dav_methods\s+([^;]+);"
    $davMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $davPattern)

    if ($davMatches.Count -gt 0) {
        $dtList += "[WebDAV 설정 발견]"
        foreach ($match in $davMatches) {
            $dtList += "dav_methods: $($match.Groups[1].Value)"
            $vulnerable = $true
        }
    } else {
        $dtList += "dav_methods 설정 없음 (양호)"
    }

    # dav_access 설정 확인
    $davAccessPattern = "(?m)^\s*dav_access\s+([^;]+);"
    if ($script:NGINX_CONFIG_CONTENT -match $davAccessPattern) {
        $dtList += ""
        $dtList += "dav_access 설정 발견"
        $vulnerable = $true
    }

    # create_full_put_path 설정 확인
    if ($script:NGINX_CONFIG_CONTENT -match "create_full_put_path\s+on") {
        $dtList += "create_full_put_path on 설정 발견"
        $vulnerable = $true
    }

    if ($vulnerable) {
        $dtList += ""
        $dtList += "[경고] WebDAV가 활성화되어 있습니다."
        $dtList += "불필요한 경우 관련 설정을 제거하세요."
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "WebDAV가 활성화되어 취약"
    } else {
        $RES = "Y"
        $DESC = "WebDAV가 비활성화되어 양호"
    }
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

$dtList += "[SSI 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # ssi 설정 확인
    $ssiValue = Get-NginxConfigValue -Content $script:NGINX_CONFIG_CONTENT -Directive "ssi" -Default "off (기본값)"

    $dtList += "ssi: $ssiValue"

    if ($ssiValue -eq "on") {
        $dtList += "  -> 취약: SSI가 활성화됨"
        $vulnerable = $true
    } else {
        $dtList += "  -> 양호: SSI가 비활성화됨"
    }

    # ssi_types 설정 확인
    $ssiTypesValue = Get-NginxConfigValue -Content $script:NGINX_CONFIG_CONTENT -Directive "ssi_types" -Default ""
    if ($ssiTypesValue) {
        $dtList += "ssi_types: $ssiTypesValue"
    }

    if ($vulnerable) {
        $dtList += ""
        $dtList += "[권장 설정]"
        $dtList += "ssi off;"
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "SSI가 활성화되어 취약"
    } else {
        $RES = "Y"
        $DESC = "SSI가 비활성화되어 양호"
    }
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
$hasHttps = $false

$dtList += "[SSL/TLS 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # listen 443 ssl 설정 확인
    $httpsPattern = "(?m)^\s*listen\s+(\d+\s+)?ssl"
    if ($script:NGINX_CONFIG_CONTENT -match $httpsPattern) {
        $dtList += "HTTPS 리스닝 설정 존재"
        $hasHttps = $true
    }

    # ssl_certificate 설정 확인
    $sslCertPattern = "(?m)^\s*ssl_certificate\s+([^;]+);"
    $sslCertMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $sslCertPattern)

    if ($sslCertMatches.Count -gt 0) {
        $dtList += ""
        $dtList += "[SSL 인증서 설정]"
        foreach ($match in $sslCertMatches) {
            $dtList += "ssl_certificate: $($match.Groups[1].Value)"
            $hasHttps = $true
        }
    }

    # ssl_certificate_key 확인
    $sslKeyPattern = "(?m)^\s*ssl_certificate_key\s+([^;]+);"
    if ($script:NGINX_CONFIG_CONTENT -match $sslKeyPattern) {
        $dtList += "ssl_certificate_key 설정 존재"
    }

    # ssl_protocols 확인
    $sslProtocols = Get-NginxConfigValue -Content $script:NGINX_CONFIG_CONTENT -Directive "ssl_protocols" -Default ""
    if ($sslProtocols) {
        $dtList += ""
        $dtList += "[SSL 프로토콜]"
        $dtList += "ssl_protocols: $sslProtocols"

        # 취약한 프로토콜 확인
        if ($sslProtocols -match "SSLv2|SSLv3|TLSv1\.0|TLSv1\.1") {
            $dtList += "  -> 경고: 취약한 프로토콜 사용"
        }
    }

    # ssl_ciphers 확인
    $sslCiphers = Get-NginxConfigValue -Content $script:NGINX_CONFIG_CONTENT -Directive "ssl_ciphers" -Default ""
    if ($sslCiphers) {
        $dtList += "ssl_ciphers 설정 존재"
    }

    if (-not $hasHttps) {
        $dtList += ""
        $dtList += "[경고] HTTPS 설정이 발견되지 않음"
        $dtList += ""
        $dtList += "[권장 설정]"
        $dtList += "listen 443 ssl;"
        $dtList += "ssl_certificate /path/to/cert.pem;"
        $dtList += "ssl_certificate_key /path/to/key.pem;"
        $dtList += "ssl_protocols TLSv1.2 TLSv1.3;"
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($hasHttps) {
        $RES = "Y"
        $DESC = "SSL/TLS가 활성화되어 양호"
    } else {
        $RES = "N"
        $DESC = "SSL/TLS가 활성화되지 않아 취약"
    }
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

$RES = "M"
$DESC = "HTTP->HTTPS 리디렉션 수동 확인 필요"

$dtList = @()

$dtList += "[HTTP 리디렉션 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # return 301 https 패턴 확인
    $redirectPattern = "(?m)return\s+301\s+https"
    if ($script:NGINX_CONFIG_CONTENT -match $redirectPattern) {
        $dtList += "HTTPS 리디렉션 설정 존재 (return 301)"
        $RES = "Y"
        $DESC = "HTTP->HTTPS 리디렉션이 설정되어 양호"
    }

    # rewrite https 패턴 확인
    $rewritePattern = "(?m)rewrite\s+.*\s+https"
    if ($script:NGINX_CONFIG_CONTENT -match $rewritePattern) {
        $dtList += "HTTPS 리디렉션 설정 존재 (rewrite)"
        $RES = "Y"
        $DESC = "HTTP->HTTPS 리디렉션이 설정되어 양호"
    }

    if ($RES -eq "M") {
        $dtList += "명시적인 HTTPS 리디렉션 설정 없음"
        $dtList += ""
        $dtList += "[권장 설정]"
        $dtList += "server {"
        $dtList += "    listen 80;"
        $dtList += "    server_name example.com;"
        $dtList += "    return 301 https://\$host\$request_uri;"
        $dtList += "}"
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
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
$hasCustomError = $false

$dtList += "[에러 페이지 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # error_page 설정 확인
    $errorPagePattern = "(?m)^\s*error_page\s+([^;]+);"
    $errorPageMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $errorPagePattern)

    if ($errorPageMatches.Count -gt 0) {
        $dtList += "[커스텀 에러 페이지 설정]"
        foreach ($match in $errorPageMatches) {
            $dtList += "error_page $($match.Groups[1].Value)"
            $hasCustomError = $true
        }
    } else {
        $dtList += "커스텀 에러 페이지 설정 없음"
        $dtList += "  -> 기본 에러 페이지 사용 (서버 정보 노출 가능)"
    }

    if (-not $hasCustomError) {
        $dtList += ""
        $dtList += "[권장 설정]"
        $dtList += "error_page 404 /404.html;"
        $dtList += "error_page 500 502 503 504 /50x.html;"
    }
} else {
    $dtList += "설정 파일을 읽을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($hasCustomError) {
        $RES = "Y"
        $DESC = "커스텀 에러 페이지가 설정되어 양호"
    } else {
        $RES = "N"
        $DESC = "커스텀 에러 페이지가 미설정되어 취약"
    }
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
    $DESC = "Nginx 자체는 LDAP 인증을 지원하지 않음"
    $DT = @"
Nginx는 자체적으로 LDAP 인증 기능을 지원하지 않습니다.
LDAP 인증이 필요한 경우 nginx-auth-ldap 모듈을 별도로 설치해야 합니다.
해당 점검 항목은 N/A 처리됩니다.
"@

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

$dtList += "[업로드 경로 설정 확인]"
$dtList += ""

if ($script:NGINX_CONFIG_CONTENT) {
    # client_body_temp_path 설정 확인
    $bodyTempPath = Get-NginxConfigValue -Content $script:NGINX_CONFIG_CONTENT -Directive "client_body_temp_path" -Default ""

    if ($bodyTempPath) {
        $dtList += "client_body_temp_path: $bodyTempPath"
    }

    # upload 관련 location 확인
    $uploadPattern = "(?m)location\s+.*upload"
    if ($script:NGINX_CONFIG_CONTENT -match $uploadPattern) {
        $dtList += "upload 관련 location 블록 존재"
    }

    $dtList += ""
    $dtList += "[수동 확인 필요]"
    $dtList += "- 업로드 디렉터리가 웹 루트 외부에 위치하는지 확인"
    $dtList += "- 업로드 디렉터리에서 스크립트 실행이 차단되는지 확인"
    $dtList += "- 업로드 디렉터리 권한이 적절히 설정되었는지 확인"
    $dtList += ""
    $dtList += "[권장 설정 예시]"
    $dtList += "location /uploads/ {"
    $dtList += "    alias /var/www/uploads/;"
    $dtList += "    location ~ \\.(php|cgi|pl)$ {"
    $dtList += "        deny all;"
    $dtList += "    }"
    $dtList += "}"
} else {
    $dtList += "설정 파일을 읽을 수 없음"
}

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
$DESC = "Nginx 버전 및 패치 수준 수동 확인 필요"

$dtList = @()

$dtList += "[Nginx 버전 정보]"
$dtList += ""

if ($NGINX_VERSION) {
    $dtList += "설치된 버전: nginx/$NGINX_VERSION"
} else {
    $dtList += "버전 정보를 확인할 수 없음"
}

$dtList += "설치 경로: $script:NGINX_HOME"

# nginx.exe 파일 정보
$nginxExe = "$script:NGINX_HOME\nginx.exe"
if (Test-Path $nginxExe) {
    try {
        $fileInfo = Get-Item $nginxExe
        $dtList += ""
        $dtList += "[nginx.exe 파일 정보]"
        $dtList += "수정일: $($fileInfo.LastWriteTime)"
        $dtList += "크기: $([math]::Round($fileInfo.Length / 1KB, 2)) KB"
    } catch { }
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- 최신 안정 버전과 비교 확인"
$dtList += "- 보안 취약점 패치 적용 여부 확인"
$dtList += ""
$dtList += "[참고 사이트]"
$dtList += "- https://nginx.org/en/download.html"
$dtList += "- https://nginx.org/en/security_advisories.html"

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

$dtList += "[로그 디렉터리 권한 확인]"
$dtList += ""

# logs 디렉터리 확인
$logsDir = "$script:NGINX_HOME\logs"
if (Test-Path $logsDir) {
    $dtList += "[logs 디렉터리]"
    $dtList += "경로: $logsDir"

    try {
        $acl = Get-Acl $logsDir -ErrorAction SilentlyContinue
        foreach ($access in $acl.Access | Select-Object -First 5) {
            $identity = $access.IdentityReference.Value
            $rights = $access.FileSystemRights
            $dtList += "  $identity : $rights"

            # Everyone에 쓰기 권한이 있으면 취약
            if ($identity -match "Everyone" -and $rights -match "Write|FullControl|Modify") {
                $vulnerable = $true
                $dtList += "    -> 취약: Everyone 권한 존재"
            }
        }
    } catch {
        $dtList += "  권한 확인 실패"
    }

    # 로그 파일 확인
    $logFiles = Get-ChildItem $logsDir -Filter "*.log" -ErrorAction SilentlyContinue | Select-Object -First 5
    if ($logFiles) {
        $dtList += ""
        $dtList += "[로그 파일]"
        foreach ($logFile in $logFiles) {
            $dtList += "  - $($logFile.Name) ($([math]::Round($logFile.Length / 1KB, 2)) KB)"
        }
    }
} else {
    $dtList += "logs 디렉터리 없음: $logsDir"
}

# 설정 파일에서 로그 경로 확인
if ($script:NGINX_CONFIG_CONTENT) {
    $accessLogPattern = "(?m)^\s*access_log\s+([^;]+);"
    $accessLogMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $accessLogPattern)

    if ($accessLogMatches.Count -gt 0) {
        $dtList += ""
        $dtList += "[설정된 로그 경로]"
        foreach ($match in $accessLogMatches) {
            $dtList += "access_log: $($match.Groups[1].Value)"
        }
    }

    $errorLogPattern = "(?m)^\s*error_log\s+([^;]+);"
    $errorLogMatches = [regex]::Matches($script:NGINX_CONFIG_CONTENT, $errorLogPattern)

    if ($errorLogMatches.Count -gt 0) {
        foreach ($match in $errorLogMatches) {
            $dtList += "error_log: $($match.Groups[1].Value)"
        }
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "로그 디렉터리에 불필요한 권한이 존재하여 취약"
} else {
    $RES = "Y"
    $DESC = "로그 디렉터리 권한이 적절히 설정되어 양호"
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

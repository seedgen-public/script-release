#================================================================
# WebtoB_Windows 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : WebtoB_Windows
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
$META_PLAT = "WebtoB"
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
function Find-WebtoBInstallation {
    $webtobPaths = @()

    # 방법 1: WEBTOBDIR 환경변수 확인
    $webtobDir = [System.Environment]::GetEnvironmentVariable("WEBTOBDIR", "Machine")
    if (-not $webtobDir) {
        $webtobDir = [System.Environment]::GetEnvironmentVariable("WEBTOBDIR", "User")
    }
    if (-not $webtobDir) {
        $webtobDir = $env:WEBTOBDIR
    }
    if ($webtobDir -and (Test-Path $webtobDir)) {
        $webtobPaths += $webtobDir
    }

    # 방법 2: 일반적인 설치 경로 확인
    $commonPaths = @(
        "C:\TmaxSoft\WebtoB",
        "C:\webtob",
        "C:\TmaxSoft\WebtoB5",
        "D:\TmaxSoft\WebtoB",
        "D:\webtob",
        "E:\TmaxSoft\WebtoB",
        "E:\webtob"
    )

    foreach ($path in $commonPaths) {
        if ((Test-Path $path) -and ($webtobPaths -notcontains $path)) {
            $webtobPaths += $path
        }
    }

    # 방법 3: 프로세스 확인 (wsm.exe, htl.exe)
    $webtobProcesses = @("wsm", "htl", "hth", "wsboot")
    foreach ($procName in $webtobProcesses) {
        try {
            $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($proc) {
                $procPath = $proc.Path
                if ($procPath) {
                    $binDir = Split-Path $procPath -Parent
                    $webtobRoot = Split-Path $binDir -Parent
                    if ((Test-Path $webtobRoot) -and ($webtobPaths -notcontains $webtobRoot)) {
                        $webtobPaths += $webtobRoot
                    }
                }
            }
        } catch { }
    }

    # 방법 4: 서비스 확인
    try {
        $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*WebtoB*" -or $_.Name -like "*webtob*" }
        foreach ($svc in $services) {
            try {
                $svcPath = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue).PathName
                if ($svcPath) {
                    $svcPath = $svcPath -replace '"', ''
                    $binDir = Split-Path $svcPath -Parent
                    $webtobRoot = Split-Path $binDir -Parent
                    if ((Test-Path $webtobRoot) -and ($webtobPaths -notcontains $webtobRoot)) {
                        $webtobPaths += $webtobRoot
                    }
                }
            } catch { }
        }
    } catch { }

    return $webtobPaths
}

# WebtoB 설치 경로 탐지
$script:webtobInstallPaths = Find-WebtoBInstallation

if ($script:webtobInstallPaths.Count -eq 0) {
    Write-Host "[X] WebtoB가 설치되어 있지 않습니다." -ForegroundColor Red
    Write-Host "    이 스크립트는 WebtoB가 설치된 시스템에서만 실행 가능합니다." -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Yellow
    Write-Host "    탐지 방법:" -ForegroundColor Yellow
    Write-Host "    - WEBTOBDIR 환경변수" -ForegroundColor Gray
    Write-Host "    - C:\TmaxSoft\WebtoB, C:\webtob 등 일반 경로" -ForegroundColor Gray
    Write-Host "    - wsm.exe, htl.exe 프로세스" -ForegroundColor Gray
    Read-Host "Press Enter to exit"
    exit 1
}

# 첫 번째 발견된 경로를 기본 경로로 사용
$script:WEBTOB_HOME = $script:webtobInstallPaths[0]

# WebtoB 설정 파일 파싱 함수
function Get-WebtoBConfig {
    param([string]$ConfigFile)

    $config = @{
        Content = ""
        Sections = @{}
        Raw = @()
    }

    if (Test-Path $ConfigFile) {
        try {
            $content = Get-Content $ConfigFile -Raw -ErrorAction SilentlyContinue
            $config.Content = $content
            $config.Raw = Get-Content $ConfigFile -ErrorAction SilentlyContinue

            # 섹션별 파싱 (*NODE, *VHOST, *ALIAS, *SSL 등)
            $currentSection = ""
            foreach ($line in $config.Raw) {
                $trimmedLine = $line.Trim()
                if ($trimmedLine -match '^\*(\w+)') {
                    $currentSection = $Matches[1]
                    if (-not $config.Sections.ContainsKey($currentSection)) {
                        $config.Sections[$currentSection] = @()
                    }
                }
                elseif ($currentSection -and $trimmedLine -and -not $trimmedLine.StartsWith("#")) {
                    $config.Sections[$currentSection] += $trimmedLine
                }
            }
        } catch { }
    }

    return $config
}

function Get-WebtoBConfigValue {
    param(
        [string]$Content,
        [string]$Key
    )

    $pattern = "$Key\s*=\s*[`"']?([^`"',\r\n]+)[`"']?"
    if ($Content -match $pattern) {
        return $Matches[1].Trim()
    }
    return $null
}

# WebtoB 설정 파일 경로
$WEBTOB_CONF = ""
if (Test-Path "$script:WEBTOB_HOME\config\http.m") {
    $WEBTOB_CONF = "$script:WEBTOB_HOME\config\http.m"
} elseif (Test-Path "$script:WEBTOB_HOME\conf\http.m") {
    $WEBTOB_CONF = "$script:WEBTOB_HOME\conf\http.m"
}

$SVC_VERSION = "WebtoB (Home: $script:WEBTOB_HOME)"
$SVC_CONF = $WEBTOB_CONF

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

# WebtoB 버전 수집
$WEBTOB_VERSION = ""
try {
    $wscflPath = Join-Path $script:WEBTOB_HOME "bin\wscfl.exe"
    if (Test-Path $wscflPath) {
        $versionOutput = & $wscflPath -version 2>&1
        if ($versionOutput) {
            $WEBTOB_VERSION = ($versionOutput | Select-String -Pattern "WebtoB" | Select-Object -First 1).ToString().Trim()
            if (-not $WEBTOB_VERSION) {
                $WEBTOB_VERSION = $versionOutput[0]
            }
        }
    }
} catch { }

if (-not $WEBTOB_VERSION) {
    $WEBTOB_VERSION = "Unknown (Path: $($script:WEBTOB_HOME))"
}

# 설정 파일 로드
$httpMPath = Join-Path $script:WEBTOB_HOME "config\http.m"
$wsconfigPath = Join-Path $script:WEBTOB_HOME "config\wsconfig.m"
$script:httpMConfig = Get-WebtoBConfig -ConfigFile $httpMPath
$script:wsconfigConfig = Get-WebtoBConfig -ConfigFile $wsconfigPath

# 출력 파일 경로
$OUTPUT_FILE = "$PSScriptRoot\${META_PLAT}_${SYS_HOST}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"


Write-Host "  [진단 시작]" -ForegroundColor Yellow
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

    $RES = "N/A"
    $DESC = "WebtoB는 별도의 관리자 계정이 없음 (설정 파일 기반 운영)"
    $DT = "WebtoB는 Apache, IIS와 달리 별도의 관리 콘솔이나 관리자 계정을 사용하지 않습니다.`n설정 파일(http.m)을 직접 편집하여 운영하므로 해당 항목은 적용 대상이 아닙니다."

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
$DESC = "WebtoB는 별도의 내장 인증 계정이 없음"
$DT = "WebtoB는 웹 서버 자체에 내장된 인증 계정 시스템이 없습니다.`n인증이 필요한 경우 OS 계정 또는 별도의 인증 모듈을 사용하므로 해당 항목은 적용 대상이 아닙니다."

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
$DESC = "WebtoB는 별도의 비밀번호 파일이 없음"
$DT = "WebtoB는 Apache의 .htpasswd와 같은 별도의 비밀번호 파일을 사용하지 않습니다.`n인증이 필요한 경우 외부 인증 모듈이나 WAS 연동을 통해 처리하므로 해당 항목은 적용 대상이 아닙니다."

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

$dtList += "[WebtoB 디렉터리 리스팅 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # Options 설정에서 Indexes 확인
    # 양호: Options = "-Indexes" 또는 Options 미설정
    # 취약: Options에 Indexes가 포함된 경우

    $optionsMatch = [regex]::Matches($script:httpMConfig.Content, "Options\s*=\s*[`"']?([^`"',\r\n]+)[`"']?")

    if ($optionsMatch.Count -gt 0) {
        foreach ($match in $optionsMatch) {
            $optionValue = $match.Groups[1].Value.Trim()
            $dtList += "Options 설정: $optionValue"

            # -Indexes가 있으면 양호, Indexes만 있으면 취약
            if ($optionValue -match "^-Indexes" -or $optionValue -match "\s-Indexes") {
                $dtList += "  -> 디렉터리 리스팅 비활성화됨 (양호)"
            }
            elseif ($optionValue -match "Indexes" -and $optionValue -notmatch "-Indexes") {
                $dtList += "  -> 디렉터리 리스팅 활성화됨 (취약)"
                $vulnerable = $true
            }
        }
    } else {
        $dtList += "Options 설정: 미설정 (기본값 사용)"
        $dtList += "  -> 기본적으로 디렉터리 리스팅 비활성화 (양호)"
    }

    # *NODE 섹션의 Options 확인
    if ($script:httpMConfig.Sections.ContainsKey("NODE")) {
        $dtList += ""
        $dtList += "[*NODE 섹션 설정]"
        foreach ($line in $script:httpMConfig.Sections["NODE"]) {
            if ($line -match "Options") {
                $dtList += $line
            }
        }
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음: $httpMPath"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "디렉터리 리스팅이 활성화되어 취약"
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
$vulnerable = $false

$dtList += "[WebtoB CGI 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # *SVRGROUP에서 CGI 타입 확인
    if ($script:httpMConfig.Sections.ContainsKey("SVRGROUP")) {
        $dtList += "[*SVRGROUP 섹션]"
        $cgiFound = $false
        foreach ($line in $script:httpMConfig.Sections["SVRGROUP"]) {
            if ($line -match "SVRTYPE\s*=\s*CGI") {
                $dtList += $line
                $cgiFound = $true
            }
        }
        if (-not $cgiFound) {
            $dtList += "CGI 서버 그룹 미설정 (양호)"
        }
    }

    # *SERVER에서 CGI 서버 확인
    if ($script:httpMConfig.Sections.ContainsKey("SERVER")) {
        $dtList += ""
        $dtList += "[*SERVER 섹션]"
        $cgiServerFound = $false
        foreach ($line in $script:httpMConfig.Sections["SERVER"]) {
            if ($line -match "cgig|SVGNAME.*cgig") {
                $dtList += $line
                $cgiServerFound = $true
                $vulnerable = $true
            }
        }
        if (-not $cgiServerFound) {
            $dtList += "CGI 서버 미설정 (양호)"
        }
    }

    # *URI에서 CGI 매핑 확인
    if ($script:httpMConfig.Sections.ContainsKey("URI")) {
        $dtList += ""
        $dtList += "[*URI 섹션]"
        $cgiUriFound = $false
        foreach ($line in $script:httpMConfig.Sections["URI"]) {
            if ($line -match "Svrtype\s*=\s*CGI|/cgi-bin/") {
                $dtList += $line
                $cgiUriFound = $true
                $vulnerable = $true
            }
        }
        if (-not $cgiUriFound) {
            $dtList += "CGI URI 매핑 미설정 (양호)"
        }
    }

    if (-not $vulnerable) {
        $dtList += ""
        $dtList += "CGI 스크립트 실행 설정이 적절히 제한됨"
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "CGI 스크립트 실행이 제한되지 않아 취약"
    } else {
        $RES = "Y"
        $DESC = "CGI 스크립트 실행이 적절히 제한되어 양호"
    }
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

$dtList += "[WebtoB 상위 디렉터리 접근 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # UpperDirRestrict 설정 확인
    # 양호: UpperDirRestrict = Y 또는 미설정(기본값)
    # 취약: UpperDirRestrict = N

    $upperDirMatch = [regex]::Match($script:httpMConfig.Content, "UpperDirRestrict\s*=\s*(\w+)")

    if ($upperDirMatch.Success) {
        $value = $upperDirMatch.Groups[1].Value.Trim()
        $dtList += "UpperDirRestrict = $value"

        if ($value -eq "N" -or $value -eq "n" -or $value -eq "No" -or $value -eq "no") {
            $dtList += "  -> 상위 디렉터리 접근 허용됨 (취약)"
            $vulnerable = $true
        } else {
            $dtList += "  -> 상위 디렉터리 접근 제한됨 (양호)"
        }
    } else {
        $dtList += "UpperDirRestrict: 미설정 (기본값: 제한)"
        $dtList += "  -> 상위 디렉터리 접근 제한됨 (양호)"
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "상위 디렉터리 접근이 허용되어 취약"
    } else {
        $RES = "Y"
        $DESC = "상위 디렉터리 접근이 제한되어 양호"
    }
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

$dtList += "[WebtoB 불필요한 파일/디렉터리 확인]"
$dtList += ""

# 불필요한 디렉터리 확인
$unnecessaryDirs = @(
    "docs\manuals",
    "samples",
    "docs\samples",
    "demo"
)

$dtList += "[불필요한 디렉터리 확인]"
foreach ($dir in $unnecessaryDirs) {
    $fullPath = Join-Path $script:WEBTOB_HOME $dir
    if (Test-Path $fullPath) {
        $dtList += "존재: $fullPath (취약)"
        $vulnerable = $true
    }
}

if (-not $vulnerable) {
    $dtList += "불필요한 샘플/매뉴얼 디렉터리 없음 (양호)"
}

# DOCROOT 경로에서 불필요한 파일 확인
$docRoot = Get-WebtoBConfigValue -Content $script:httpMConfig.Content -Key "DOCROOT"
if ($docRoot) {
    $docRoot = $docRoot -replace '"', '' -replace "'", ''
    $dtList += ""
    $dtList += "[DOCROOT 불필요 파일 확인]"
    $dtList += "DOCROOT: $docRoot"

    if (Test-Path $docRoot) {
        $unnecessaryFiles = Get-ChildItem $docRoot -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Extension -match "\.(bak|old|tmp|temp|backup|log|txt)$" -or
            $_.Name -match "^(test|sample|example|readme|install)"
        } | Select-Object -First 5

        if ($unnecessaryFiles) {
            foreach ($file in $unnecessaryFiles) {
                $dtList += "불필요 파일: $($file.Name)"
                $vulnerable = $true
            }
        } else {
            $dtList += "불필요한 파일 없음 (양호)"
        }
    } else {
        $dtList += "DOCROOT 경로 접근 불가"
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
$hasLimit = $false

$dtList += "[WebtoB 파일 용량 제한 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # LimitRequestBody 설정 확인
    $limitMatch = [regex]::Match($script:httpMConfig.Content, "LimitRequestBody\s*=\s*(\d+)")

    if ($limitMatch.Success) {
        $value = $limitMatch.Groups[1].Value
        $valueMB = [math]::Round([int]$value / 1MB, 2)
        $dtList += "LimitRequestBody = $value bytes ($valueMB MB)"
        $hasLimit = $true
    } else {
        $dtList += "LimitRequestBody: 미설정"
    }

    # MaxRequestBodySize 확인 (WebtoB 5.x)
    $maxBodyMatch = [regex]::Match($script:httpMConfig.Content, "MaxRequestBodySize\s*=\s*(\d+)")
    if ($maxBodyMatch.Success) {
        $value = $maxBodyMatch.Groups[1].Value
        $dtList += "MaxRequestBodySize = $value"
        $hasLimit = $true
    }

    if (-not $hasLimit) {
        $dtList += ""
        $dtList += "[권장 설정]"
        $dtList += "LimitRequestBody = 5242880 (5MB 권장)"
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($hasLimit) {
        $RES = "Y"
        $DESC = "파일 업로드 용량 제한이 설정되어 양호"
    } else {
        $RES = "N"
        $DESC = "파일 업로드 용량 제한이 미설정되어 취약"
    }
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

$dtList += "[WebtoB 서비스 실행 계정 확인]"
$dtList += ""

# WebtoB 관련 서비스 확인
try {
    $webtobServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -like "*WebtoB*" -or $_.Name -like "*webtob*" -or $_.Name -like "*wsm*"
    }

    if ($webtobServices) {
        $dtList += "[WebtoB 서비스]"
        foreach ($svc in $webtobServices) {
            $startName = $svc.StartName
            $dtList += "서비스: $($svc.Name)"
            $dtList += "  실행 계정: $startName"

            # LocalSystem 또는 Administrator로 실행되면 취약
            if ($startName -match "LocalSystem|NT AUTHORITY\\SYSTEM|Administrator") {
                $dtList += "  -> 경고: 관리자 권한으로 실행됨 (취약)"
                $vulnerable = $true
            } else {
                $dtList += "  -> 제한된 권한으로 실행됨 (양호)"
            }
        }
    } else {
        $dtList += "WebtoB 서비스가 등록되어 있지 않음"
    }
} catch {
    $dtList += "서비스 정보 확인 실패: $_"
}

# 프로세스 확인
$dtList += ""
$dtList += "[WebtoB 프로세스]"
$webtobProcesses = @("wsm", "htl", "hth", "wsboot")
$procFound = $false

foreach ($procName in $webtobProcesses) {
    try {
        $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            $procFound = $true
            try {
                $owner = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).GetOwner()
                $ownerName = "$($owner.Domain)\$($owner.User)"
                $dtList += "프로세스: $procName (PID: $($proc.Id))"
                $dtList += "  실행 계정: $ownerName"

                if ($ownerName -match "SYSTEM|Administrator") {
                    $dtList += "  -> 경고: 관리자 권한으로 실행됨"
                    $vulnerable = $true
                }
            } catch {
                $dtList += "프로세스: $procName (PID: $($proc.Id)) - 소유자 확인 불가"
            }
        }
    } catch { }
}

if (-not $procFound) {
    $dtList += "실행 중인 WebtoB 프로세스 없음"
    $RES = "M"
    $DESC = "WebtoB 프로세스가 실행 중이지 않음, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "WebtoB가 관리자 권한으로 실행되어 취약"
    } else {
        $RES = "Y"
        $DESC = "WebtoB 프로세스 권한이 적절히 설정되어 양호"
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

$RES = "M"
$DESC = "프록시 설정 수동 확인 필요"

$dtList = @()

$dtList += "[WebtoB 프록시 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # REVERSE_PROXY 설정 확인
    $proxyMatch = [regex]::Matches($script:httpMConfig.Content, "REVERSE_PROXY\s*\([^)]*\)[^,]*,[^,]*ServerAddress\s*=\s*[`"']?([^`"',\r\n]+)[`"']?")

    if ($proxyMatch.Count -gt 0) {
        $dtList += "[리버스 프록시 설정]"
        foreach ($match in $proxyMatch) {
            $dtList += $match.Value
        }
        $dtList += ""
        $dtList += "리버스 프록시 설정이 존재합니다."
        $dtList += "불필요한 프록시 설정 여부를 수동으로 확인하세요."
    } else {
        $dtList += "리버스 프록시 설정 없음"
        $RES = "Y"
        $DESC = "불필요한 프록시 설정이 없어 양호"
    }

    # ProxyPass 설정 확인
    if ($script:httpMConfig.Content -match "ProxyPass") {
        $dtList += ""
        $dtList += "ProxyPass 설정이 존재합니다. 수동 확인 필요"
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- http.m 파일의 REVERSE_PROXY 설정 검토"
$dtList += "- 불필요한 프록시 설정 제거"

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

$dtList += "[WebtoB 서비스 경로 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # WEBTOBDIR 확인
    $webtobDir = Get-WebtoBConfigValue -Content $script:httpMConfig.Content -Key "WEBTOBDIR"
    if ($webtobDir) {
        $webtobDir = $webtobDir -replace '"', '' -replace "'", ''
        $dtList += "WEBTOBDIR = $webtobDir"
    }

    # DOCROOT 확인
    $docRoot = Get-WebtoBConfigValue -Content $script:httpMConfig.Content -Key "DOCROOT"
    if ($docRoot) {
        $docRoot = $docRoot -replace '"', '' -replace "'", ''
        $dtList += "DOCROOT = $docRoot"

        # 시스템 경로와 분리되어 있는지 확인
        $systemPaths = @("C:\Windows", "C:\Program Files", "C:\Users")
        foreach ($sysPath in $systemPaths) {
            if ($docRoot -like "$sysPath*") {
                $dtList += "  -> 경고: 시스템 경로와 분리 필요"
                $vulnerable = $true
            }
        }

        if (-not $vulnerable) {
            $dtList += "  -> 웹 서비스 경로가 시스템 경로와 분리됨 (양호)"
        }
    } else {
        $dtList += "DOCROOT: 미설정"
        $RES = "M"
        $DESC = "DOCROOT 설정 확인 필요"
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
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

$dtList += "[WebtoB ALIAS 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # *ALIAS 섹션 확인
    if ($script:httpMConfig.Sections.ContainsKey("ALIAS")) {
        $dtList += "[*ALIAS 섹션]"
        $aliasCount = 0
        foreach ($line in $script:httpMConfig.Sections["ALIAS"]) {
            if ($line.Trim()) {
                $dtList += $line
                $aliasCount++
            }
        }

        if ($aliasCount -gt 0) {
            $dtList += ""
            $dtList += "ALIAS 설정이 $aliasCount 개 존재합니다."
            $dtList += "불필요한 ALIAS 설정 여부를 확인하세요."
            # ALIAS가 존재하더라도 필요한 설정일 수 있으므로 M으로 처리
            $RES = "M"
            $DESC = "ALIAS 설정 존재, 필요성 수동 확인 필요"
        } else {
            $dtList += "ALIAS 설정 없음 (양호)"
        }
    } else {
        $dtList += "*ALIAS 섹션 없음 (양호)"
    }

    # DOCROOT에서 바로가기 파일 확인
    $docRoot = Get-WebtoBConfigValue -Content $script:httpMConfig.Content -Key "DOCROOT"
    if ($docRoot) {
        $docRoot = $docRoot -replace '"', '' -replace "'", ''
        if (Test-Path $docRoot) {
            $dtList += ""
            $dtList += "[바로가기 파일 확인]"
            $shortcuts = Get-ChildItem $docRoot -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
            if ($shortcuts) {
                foreach ($shortcut in $shortcuts) {
                    $dtList += "바로가기: $($shortcut.FullName)"
                    $vulnerable = $true
                }
            } else {
                $dtList += "바로가기 파일 없음 (양호)"
            }
        }
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "웹 서비스 경로에 바로가기 파일이 존재하여 취약"
    } else {
        $RES = "Y"
        $DESC = "불필요한 링크 설정이 없어 양호"
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
$DT = "WebtoB의 설정 파일 노출 제한은 WEB-14 항목에서 설정 파일 권한 점검으로 통합하여 진단합니다.`n설정 파일(http.m) 권한이 적절히 설정되어 있으면 외부 노출이 방지됩니다."

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

$dtList += "[WebtoB 설정 파일 권한 확인]"
$dtList += ""

# http.m 파일 권한 확인
if (Test-Path $httpMPath) {
    $dtList += "[http.m 파일 권한]"
    $dtList += "경로: $httpMPath"

    try {
        $acl = Get-Acl $httpMPath -ErrorAction SilentlyContinue
        foreach ($access in $acl.Access) {
            $identity = $access.IdentityReference.Value
            $rights = $access.FileSystemRights
            $dtList += "  $identity : $rights"

            # Everyone 또는 Users에 쓰기 권한이 있으면 취약
            if ($identity -match "Everyone|BUILTIN\\Users" -and $rights -match "Write|FullControl|Modify") {
                $vulnerable = $true
                $dtList += "    -> 취약: 불필요한 쓰기 권한"
            }
        }
    } catch {
        $dtList += "  권한 확인 실패: $_"
    }
} else {
    $dtList += "http.m 파일을 찾을 수 없음: $httpMPath"
}

# config 디렉터리 권한 확인
$configDir = Join-Path $script:WEBTOB_HOME "config"
if (Test-Path $configDir) {
    $dtList += ""
    $dtList += "[config 디렉터리 권한]"
    $dtList += "경로: $configDir"

    try {
        $acl = Get-Acl $configDir -ErrorAction SilentlyContinue
        foreach ($access in $acl.Access) {
            $identity = $access.IdentityReference.Value
            $rights = $access.FileSystemRights

            if ($identity -match "Everyone" -and $rights -match "Write|FullControl|Modify|Delete") {
                $dtList += "  $identity : $rights"
                $dtList += "    -> 취약: Everyone 쓰기 권한"
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
$DESC = "WebtoB는 핸들러 기반으로 WEB-05에서 점검"
$DT = "WebtoB는 IIS의 스크립트 매핑과 달리 핸들러(SVRGROUP, SERVER) 기반으로 동작합니다.`n불필요한 스크립트 실행 제한은 WEB-05 항목에서 CGI 실행 제한으로 통합하여 진단합니다."

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

$dtList += "[WebtoB 헤더 정보 노출 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # ServerTokens 설정 확인
    # 양호: ServerTokens = ProductOnly(Prod) 또는 off
    # 취약: ServerTokens = Full, OS, Min 등
    $serverTokensMatch = [regex]::Match($script:httpMConfig.Content, "ServerTokens\s*=?\s*[`"']?(\w+)[`"']?", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($serverTokensMatch.Success) {
        $value = $serverTokensMatch.Groups[1].Value.Trim()
        $dtList += "ServerTokens = $value"

        if ($value -match "Prod|ProductOnly|off") {
            $dtList += "  -> 최소 정보만 노출 (양호)"
        } else {
            $dtList += "  -> 서버 정보 노출됨 (취약)"
            $vulnerable = $true
        }
    } else {
        $dtList += "ServerTokens: 미설정 (기본값: off)"
        $dtList += "  -> 헤더 정보 노출 제한됨 (양호)"
    }

    # ServerSignature 설정 확인
    $serverSigMatch = [regex]::Match($script:httpMConfig.Content, "ServerSignature\s*=?\s*[`"']?(\w+)[`"']?", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($serverSigMatch.Success) {
        $value = $serverSigMatch.Groups[1].Value.Trim()
        $dtList += "ServerSignature = $value"

        if ($value -match "off|Off|OFF") {
            $dtList += "  -> 서명 정보 미노출 (양호)"
        } else {
            $dtList += "  -> 서명 정보 노출됨 (취약)"
            $vulnerable = $true
        }
    } else {
        $dtList += "ServerSignature: 미설정 (기본값: off)"
    }

    $dtList += ""
    $dtList += "[권장 설정]"
    $dtList += "ServerTokens ProductOnly(Prod)"
    $dtList += "ServerSignature off"
} else {
    $dtList += "설정 파일을 찾을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "HTTP 응답 헤더에 서버 정보가 노출되어 취약"
    } else {
        $RES = "Y"
        $DESC = "HTTP 응답 헤더 정보가 제한되어 양호"
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
$DESC = "가상 디렉터리 설정 수동 확인 필요"

$dtList = @()

$dtList += "[WebtoB 가상 디렉터리 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # *ALIAS 섹션 확인
    if ($script:httpMConfig.Sections.ContainsKey("ALIAS")) {
        $dtList += "[*ALIAS 섹션 (가상 디렉터리)]"
        $aliasCount = 0
        foreach ($line in $script:httpMConfig.Sections["ALIAS"]) {
            if ($line.Trim()) {
                $dtList += $line
                $aliasCount++
            }
        }

        if ($aliasCount -gt 0) {
            $dtList += ""
            $dtList += "가상 디렉터리(ALIAS) 설정이 $aliasCount 개 존재합니다."
            $dtList += "불필요한 가상 디렉터리 존재 여부를 확인하세요."
        } else {
            $dtList += "가상 디렉터리 설정 없음"
            $RES = "Y"
            $DESC = "불필요한 가상 디렉터리가 없어 양호"
        }
    } else {
        $dtList += "*ALIAS 섹션 없음"
        $RES = "Y"
        $DESC = "가상 디렉터리 설정이 없어 양호"
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- NODE절의 불필요한 Alias 설정 확인 및 제거"

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

$dtList += "[WebtoB WebDAV 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # *VHOST 섹션에서 Method 설정 확인
    # WebDAV 메소드: PROPFIND, PUT, DELETE, MKCOL, COPY, MOVE
    $webdavMethods = @("PROPFIND", "PUT", "DELETE", "MKCOL", "COPY", "MOVE")

    if ($script:httpMConfig.Sections.ContainsKey("VHOST")) {
        $dtList += "[*VHOST 섹션 Method 설정]"
        foreach ($line in $script:httpMConfig.Sections["VHOST"]) {
            if ($line -match "Method\s*=") {
                $dtList += $line

                foreach ($method in $webdavMethods) {
                    if ($line -match $method) {
                        $dtList += "  -> 경고: WebDAV 메소드 '$method' 활성화됨 (취약)"
                        $vulnerable = $true
                    }
                }
            }
        }
    }

    if (-not $vulnerable) {
        $dtList += "WebDAV 관련 메소드 미설정 (양호)"
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
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

$dtList += "[WebtoB SSI 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # *SVRGROUP에서 SSI 타입 확인
    if ($script:httpMConfig.Sections.ContainsKey("SVRGROUP")) {
        $dtList += "[*SVRGROUP 섹션]"
        $ssiFound = $false
        foreach ($line in $script:httpMConfig.Sections["SVRGROUP"]) {
            if ($line -match "SvrType\s*=\s*SSI") {
                $dtList += $line
                $ssiFound = $true
                $vulnerable = $true
            }
        }
        if (-not $ssiFound) {
            $dtList += "SSI 서버 그룹 미설정 (양호)"
        }
    }

    # *SERVER에서 SSI 서버 확인
    if ($script:httpMConfig.Sections.ContainsKey("SERVER")) {
        $dtList += ""
        $dtList += "[*SERVER 섹션]"
        $ssiServerFound = $false
        foreach ($line in $script:httpMConfig.Sections["SERVER"]) {
            if ($line -match "ssig|SVGNAME.*ssig|ssi\s+") {
                $dtList += $line
                $ssiServerFound = $true
                $vulnerable = $true
            }
        }
        if (-not $ssiServerFound) {
            $dtList += "SSI 서버 미설정 (양호)"
        }
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
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
$hasSSL = $false

$dtList += "[WebtoB SSL/TLS 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # *VHOST에서 SSLFLAG 확인
    if ($script:httpMConfig.Sections.ContainsKey("VHOST")) {
        $dtList += "[*VHOST 섹션 SSL 설정]"
        foreach ($line in $script:httpMConfig.Sections["VHOST"]) {
            if ($line -match "SSLFLAG\s*=\s*Y") {
                $dtList += $line
                $hasSSL = $true
            }
            if ($line -match "SSLNAME\s*=") {
                $dtList += $line
            }
        }
    }

    # *SSL 섹션 확인
    if ($script:httpMConfig.Sections.ContainsKey("SSL")) {
        $dtList += ""
        $dtList += "[*SSL 섹션]"
        foreach ($line in $script:httpMConfig.Sections["SSL"]) {
            if ($line -match "CertificateFile|CertificateKeyFile|Protocols") {
                $dtList += $line
                $hasSSL = $true
            }
        }
    }

    # Protocols 설정에서 취약한 프로토콜 확인
    $protocolsMatch = [regex]::Match($script:httpMConfig.Content, "Protocols\s*=\s*[`"']?([^`"'\r\n]+)[`"']?")
    if ($protocolsMatch.Success) {
        $protocols = $protocolsMatch.Groups[1].Value
        $dtList += ""
        $dtList += "[프로토콜 설정]"
        $dtList += "Protocols = $protocols"

        if ($protocols -match "-SSLv2.*-SSLv3.*-TLSv1\.0|TLSv1\.2|TLSv1\.3") {
            $dtList += "  -> 안전한 프로토콜만 허용 (양호)"
        } elseif ($protocols -match "SSLv2|SSLv3|TLSv1\.0" -and $protocols -notmatch "-SSLv2|-SSLv3|-TLSv1\.0") {
            $dtList += "  -> 경고: 취약한 프로토콜이 허용될 수 있음"
        }
    }

    if (-not $hasSSL) {
        $dtList += ""
        $dtList += "SSL/TLS 설정이 없습니다."
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($hasSSL) {
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

$dtList += "[WebtoB HTTP 리디렉션 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # URLRewrite 설정 확인
    $urlRewriteMatch = [regex]::Match($script:httpMConfig.Content, "URLRewrite\s*=\s*Y", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($urlRewriteMatch.Success) {
        $dtList += "URLRewrite = Y (활성화됨)"

        # URLRewriteConfig 확인
        $rewriteConfigMatch = [regex]::Match($script:httpMConfig.Content, "URLRewriteConfig\s*=\s*[`"']?([^`"',\r\n]+)[`"']?")
        if ($rewriteConfigMatch.Success) {
            $rewriteConfigFile = $rewriteConfigMatch.Groups[1].Value.Trim()
            $dtList += "URLRewriteConfig = $rewriteConfigFile"

            # rewrite 설정 파일 내용 확인
            $rewriteFullPath = Join-Path $script:WEBTOB_HOME $rewriteConfigFile
            if (Test-Path $rewriteFullPath) {
                $rewriteContent = Get-Content $rewriteFullPath -Raw -ErrorAction SilentlyContinue
                if ($rewriteContent -match "https://" -or $rewriteContent -match "RewriteRule.*https") {
                    $dtList += ""
                    $dtList += "HTTPS 리디렉션 설정이 존재합니다."
                    $RES = "Y"
                    $DESC = "HTTP->HTTPS 리디렉션이 설정되어 양호"
                }
            } else {
                $dtList += "  -> rewrite 설정 파일을 찾을 수 없음"
            }
        }
    } else {
        $dtList += "URLRewrite: 미설정"
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- http.m 파일의 URLRewrite, URLRewriteConfig 설정 확인"
$dtList += "- rewrite 설정 파일에서 HTTPS 리디렉션 규칙 확인"
$dtList += "예시:"
$dtList += "  RewriteCond %{HTTPS} off"
$dtList += "  RewriteRule .* https://%{SERVER_NAME}%{REQUEST_URI} [R=307,L]"

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
$hasErrorPage = $false

$dtList += "[WebtoB 에러 페이지 설정 확인]"
$dtList += "설정 파일: $httpMPath"
$dtList += ""

if ($script:httpMConfig.Content) {
    # *ERRORDOCUMENT 섹션 확인
    if ($script:httpMConfig.Sections.ContainsKey("ERRORDOCUMENT")) {
        $dtList += "[*ERRORDOCUMENT 섹션]"
        foreach ($line in $script:httpMConfig.Sections["ERRORDOCUMENT"]) {
            if ($line.Trim()) {
                $dtList += $line
                $hasErrorPage = $true
            }
        }
    }

    # VHOST에서 ERRORDOCUMENT 설정 확인
    if ($script:httpMConfig.Sections.ContainsKey("VHOST")) {
        $dtList += ""
        $dtList += "[*VHOST 섹션 ERRORDOCUMENT 설정]"
        foreach ($line in $script:httpMConfig.Sections["VHOST"]) {
            if ($line -match "ERRORDOCUMENT") {
                $dtList += $line
                $hasErrorPage = $true
            }
        }
    }

    # NODE에서 ERRORDOCUMENT 설정 확인
    if ($script:httpMConfig.Sections.ContainsKey("NODE")) {
        foreach ($line in $script:httpMConfig.Sections["NODE"]) {
            if ($line -match "ERRORDOCUMENT") {
                $dtList += ""
                $dtList += "[*NODE 섹션 ERRORDOCUMENT 설정]"
                $dtList += $line
                $hasErrorPage = $true
            }
        }
    }

    if (-not $hasErrorPage) {
        $dtList += "커스텀 에러 페이지 미설정"
    }
} else {
    $dtList += "설정 파일을 찾을 수 없음"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($hasErrorPage) {
        $RES = "Y"
        $DESC = "에러 페이지가 설정되어 양호"
    } else {
        $RES = "N"
        $DESC = "커스텀 에러 페이지가 미설정되어 취약"
    }
}

$dtList += ""
$dtList += "[권장 설정]"
$dtList += "*ERRORDOCUMENT"
$dtList += '400 status = 400, url = `/error.html`'
$dtList += '404 status = 404, url = `/error.html`'
$dtList += '500 status = 500, url = `/error.html`'
$dtList += '503 status = 503, url = `/error.html`'

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
$DESC = "WebtoB는 웹서버로서 LDAP 인증을 지원하지 않음"
$DT = "WebtoB는 웹 서버로서 LDAP 인증 기능을 내장하고 있지 않습니다.`nLDAP 인증이 필요한 경우 WAS(JEUS 등)와 연동하거나 별도의 인증 모듈을 사용하므로 해당 항목은 적용 대상이 아닙니다."

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

$dtList += "[WebtoB 업로드 디렉터리 확인]"
$dtList += ""

if ($script:httpMConfig.Content) {
    # DOCROOT 확인
    $docRoot = Get-WebtoBConfigValue -Content $script:httpMConfig.Content -Key "DOCROOT"
    if ($docRoot) {
        $docRoot = $docRoot -replace '"', '' -replace "'", ''
        $dtList += "DOCROOT: $docRoot"

        # 일반적인 업로드 디렉터리 확인
        $uploadDirs = @("uploads", "upload", "files", "attachments", "media")

        foreach ($dir in $uploadDirs) {
            $uploadPath = Join-Path $docRoot $dir
            if (Test-Path $uploadPath) {
                $dtList += ""
                $dtList += "업로드 디렉터리: $uploadPath"

                # 권한 확인
                try {
                    $acl = Get-Acl $uploadPath -ErrorAction SilentlyContinue
                    foreach ($access in $acl.Access | Where-Object { $_.IdentityReference -match "Everyone|Users" }) {
                        $dtList += "  $($access.IdentityReference): $($access.FileSystemRights)"
                    }
                } catch { }
            }
        }
    }

    # ALIAS에서 upload 관련 설정 확인
    if ($script:httpMConfig.Sections.ContainsKey("ALIAS")) {
        $dtList += ""
        $dtList += "[ALIAS에서 업로드 경로 확인]"
        foreach ($line in $script:httpMConfig.Sections["ALIAS"]) {
            if ($line -match "upload|Upload|UPLOAD") {
                $dtList += $line
            }
        }
    }
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- 업로드 디렉터리가 웹 루트 외부에 위치하는지 확인"
$dtList += "- 업로드 디렉터리에 스크립트 실행 권한이 없는지 확인"
$dtList += "- 일반 사용자의 불필요한 접근 권한 제거 (권장: 750)"

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
$DESC = "WebtoB 버전 및 패치 수준 수동 확인 필요"

$dtList = @()

$dtList += "[WebtoB 버전 정보]"
$dtList += ""

# wscfl -version 실행
$wscflPath = Join-Path $script:WEBTOB_HOME "bin\wscfl.exe"
if (Test-Path $wscflPath) {
    try {
        $versionOutput = & $wscflPath -version 2>&1
        if ($versionOutput) {
            foreach ($line in $versionOutput) {
                $dtList += $line
            }
        }
    } catch {
        $dtList += "버전 정보 확인 실패: $_"
    }
} else {
    $dtList += "wscfl.exe를 찾을 수 없음"
}

$dtList += ""
$dtList += "[설치 경로]"
$dtList += "WEBTOB_HOME: $($script:WEBTOB_HOME)"

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- TmaxSoft 기술 지원 사이트에서 최신 버전 확인"
$dtList += "- 보안 패치 적용 여부 확인"
$dtList += "- 참고: https://technet.tmaxsoft.com/ko/front/download/findDownloadList.do?cmProductCode=0102"

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

$dtList += "[WebtoB 로그 디렉터리 권한 확인]"
$dtList += ""

# 로그 디렉터리 경로
$logDirs = @(
    (Join-Path $script:WEBTOB_HOME "log"),
    (Join-Path $script:WEBTOB_HOME "logs")
)

foreach ($logDir in $logDirs) {
    if (Test-Path $logDir) {
        $dtList += "로그 디렉터리: $logDir"

        try {
            $acl = Get-Acl $logDir -ErrorAction SilentlyContinue

            foreach ($access in $acl.Access) {
                $identity = $access.IdentityReference.Value
                $rights = $access.FileSystemRights

                # Everyone에 읽기/쓰기 권한이 있으면 취약
                if ($identity -match "Everyone" -and $rights -match "Read|Write|FullControl") {
                    $dtList += "  $identity : $rights"
                    $dtList += "    -> 취약: Everyone 권한 존재"
                    $vulnerable = $true
                }
            }
        } catch {
            $dtList += "  권한 확인 실패: $_"
        }

        # 로그 파일 권한 확인
        $dtList += ""
        $dtList += "[로그 파일 샘플]"
        $logFiles = Get-ChildItem $logDir -File -ErrorAction SilentlyContinue | Select-Object -First 3
        foreach ($file in $logFiles) {
            $dtList += "  $($file.Name)"
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

$dtList += ""
$dtList += "[권장 설정]"
$dtList += "- 로그 디렉터리 권한: 750"
$dtList += "- 로그 파일 권한: 640"
$dtList += "- Everyone 권한 제거"

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

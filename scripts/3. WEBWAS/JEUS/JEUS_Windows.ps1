#================================================================
# JEUS_Windows 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : JEUS_Windows
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
$META_PLAT = "JEUS"
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
function Find-JEUSInstallation {
    $jeusPaths = @()

    # 방법 1: JEUS_HOME 환경변수
    $jeusHome = [Environment]::GetEnvironmentVariable("JEUS_HOME", "Machine")
    if (-not $jeusHome) {
        $jeusHome = [Environment]::GetEnvironmentVariable("JEUS_HOME", "User")
    }
    if ($jeusHome -and (Test-Path $jeusHome)) {
        $jeusPaths += $jeusHome
    }

    # 방법 2: 일반적인 설치 경로 확인
    $commonPaths = @(
        "C:\TmaxSoft\JEUS",
        "C:\jeus",
        "C:\Program Files\TmaxSoft\JEUS",
        "C:\TmaxSoft\JEUS8",
        "C:\TmaxSoft\JEUS7",
        "D:\TmaxSoft\JEUS",
        "D:\jeus"
    )

    foreach ($path in $commonPaths) {
        if ((Test-Path $path) -and ($path -notin $jeusPaths)) {
            $jeusPaths += $path
        }
    }

    # 방법 3: java.exe 프로세스에서 JEUS 관련 인자 확인
    try {
        $javaProcesses = Get-CimInstance Win32_Process -Filter "Name='java.exe'" -ErrorAction SilentlyContinue
        foreach ($proc in $javaProcesses) {
            $cmdLine = $proc.CommandLine
            if ($cmdLine -match "jeus" -or $cmdLine -match "JEUS") {
                # jeus.home 또는 JEUS_HOME 추출
                if ($cmdLine -match "-Djeus\.home=([^\s]+)") {
                    $extractedPath = $Matches[1].Trim('"')
                    if ((Test-Path $extractedPath) -and ($extractedPath -notin $jeusPaths)) {
                        $jeusPaths += $extractedPath
                    }
                }
            }
        }
    } catch { }

    return $jeusPaths
}

# JEUS 설치 경로 탐지
$JEUS_PATHS = Find-JEUSInstallation

if ($JEUS_PATHS.Count -eq 0) {
    Write-Host "[X] JEUS가 설치되어 있지 않습니다." -ForegroundColor Red
    Write-Host "    이 스크립트는 JEUS가 설치된 시스템에서만 실행 가능합니다." -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Yellow
    Write-Host "    확인된 경로:" -ForegroundColor Yellow
    Write-Host "    - JEUS_HOME 환경변수: 미설정" -ForegroundColor Gray
    Write-Host "    - C:\TmaxSoft\JEUS: 없음" -ForegroundColor Gray
    Write-Host "    - C:\jeus: 없음" -ForegroundColor Gray
    Read-Host "Press Enter to exit"
    exit 1
}

$JEUS_HOME = $JEUS_PATHS[0]

# JEUS 설정 파일 경로 수집
function Get-JEUSConfigFiles {
    param([string]$JeusHome)

    $configFiles = @{
        DomainXml = @()
        JEUSMainXml = @()
        AccountsXml = @()
        PoliciesXml = @()
        WebXml = @()
        JeusWebDd = @()
    }

    # domains/*/config/domain.xml (JEUS 7+)
    $domainXmlFiles = Get-ChildItem -Path "$JeusHome\domains\*\config\domain.xml" -ErrorAction SilentlyContinue
    foreach ($file in $domainXmlFiles) {
        $configFiles.DomainXml += $file.FullName
    }

    # domains/*/config/JEUSMain.xml (구버전)
    $jeusMainFiles = Get-ChildItem -Path "$JeusHome\domains\*\config\JEUSMain.xml" -ErrorAction SilentlyContinue
    foreach ($file in $jeusMainFiles) {
        $configFiles.JEUSMainXml += $file.FullName
    }

    # 구버전 경로도 확인
    if (Test-Path "$JeusHome\config\JEUSMain.xml") {
        $configFiles.JEUSMainXml += "$JeusHome\config\JEUSMain.xml"
    }

    # domains/*/config/security/accounts.xml
    $accountsFiles = Get-ChildItem -Path "$JeusHome\domains\*\config\security\*\accounts.xml" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $accountsFiles) {
        $configFiles.AccountsXml += $file.FullName
    }

    # policies.xml
    $policiesFiles = Get-ChildItem -Path "$JeusHome\domains\*\config\security\*\policies.xml" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $policiesFiles) {
        $configFiles.PoliciesXml += $file.FullName
    }

    # WEB-INF/web.xml 파일들
    $webXmlFiles = Get-ChildItem -Path "$JeusHome" -Filter "web.xml" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $webXmlFiles) {
        $configFiles.WebXml += $file.FullName
    }

    # jeus-web-dd.xml 파일들
    $jeusWebDdFiles = Get-ChildItem -Path "$JeusHome" -Filter "jeus-web-dd.xml" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $jeusWebDdFiles) {
        $configFiles.JeusWebDd += $file.FullName
    }

    return $configFiles
}

$JEUS_CONFIG = Get-JEUSConfigFiles -JeusHome $JEUS_HOME

$SVC_VERSION = "JEUS (Home: $JEUS_HOME)"
$SVC_CONF = $JEUS_HOME

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

# JEUS 버전 수집
$JEUS_VERSION = ""
try {
    # jeusadmin -version 실행
    $jeusAdmin = Join-Path $JEUS_HOME "bin\jeusadmin.cmd"
    if (Test-Path $jeusAdmin) {
        $versionOutput = & cmd /c "`"$jeusAdmin`" -version" 2>&1
        if ($versionOutput) {
            $JEUS_VERSION = ($versionOutput | Select-String -Pattern "JEUS|version" | Select-Object -First 1).ToString().Trim()
        }
    }

    # 버전 파일에서 읽기
    if (-not $JEUS_VERSION) {
        $versionFile = Join-Path $JEUS_HOME "lib\system\jeus.jar"
        if (Test-Path $versionFile) {
            $JEUS_VERSION = "JEUS (jeus.jar exists)"
        }
    }
} catch {
    $JEUS_VERSION = "Unknown"
}

# 출력 파일 경로
$OUTPUT_FILE = "$PSScriptRoot\${META_PLAT}_${SYS_HOST}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"


Write-Host "  [진단 시작]" -ForegroundColor Yellow
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  JEUS_HOME: $JEUS_HOME" -ForegroundColor Gray
Write-Host ""


    $dtList = @()
    $vulnerable = $false
    $defaultAccounts = @("administrator", "admin", "jeus", "root")

    $dtList += "[JEUS 기본 관리자 계정 확인]"
    $dtList += "JEUS_HOME: $JEUS_HOME"
    $dtList += ""

    # accounts.xml 파일 확인
    if ($JEUS_CONFIG.AccountsXml.Count -gt 0) {
        foreach ($accountFile in $JEUS_CONFIG.AccountsXml) {
            $dtList += "accounts.xml: $accountFile"

            try {
                $content = Get-Content $accountFile -Raw -ErrorAction SilentlyContinue

                foreach ($defaultAccount in $defaultAccounts) {
                    if ($content -match "<name>\s*$defaultAccount\s*</name>" -or
                        $content -match "name\s*=\s*[`"']$defaultAccount[`"']") {
                        $dtList += "  -> 기본 계정 발견: $defaultAccount (취약)"
                        $vulnerable = $true
                    }
                }

                # 사용자 목록 추출 시도
                $userMatches = [regex]::Matches($content, "<name>([^<]+)</name>")
                if ($userMatches.Count -gt 0) {
                    $dtList += "  등록된 사용자:"
                    foreach ($match in $userMatches) {
                        $userName = $match.Groups[1].Value.Trim()
                        $dtList += "    - $userName"
                    }
                }
            } catch {
                $dtList += "  -> 파일 읽기 실패: $_"
            }
        }
    } else {
        $dtList += "accounts.xml 파일을 찾을 수 없습니다."
        $dtList += "  확인 경로: $JEUS_HOME\domains\*\config\security\*\accounts.xml"
        $RES = "M"
        $DESC = "accounts.xml 파일을 찾을 수 없어 수동 확인 필요"
    }

    if ([string]::IsNullOrEmpty($RES)) {
        if ($vulnerable) {
            $RES = "N"
            $DESC = "기본 관리자 계정명이 변경되지 않아 취약"
        } else {
            $RES = "Y"
            $DESC = "기본 관리자 계정명이 변경되어 양호"
        }
    }

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

$RES = "M"
$DESC = "관리자 비밀번호 복잡도 수동 확인 필요"

$dtList = @()

$dtList += "[JEUS 비밀번호 설정 확인]"
$dtList += ""

# accounts.xml에서 비밀번호 암호화 여부 확인
if ($JEUS_CONFIG.AccountsXml.Count -gt 0) {
    foreach ($accountFile in $JEUS_CONFIG.AccountsXml) {
        $dtList += "accounts.xml: $accountFile"

        try {
            $content = Get-Content $accountFile -Raw -ErrorAction SilentlyContinue

            # 비밀번호 암호화 여부 확인
            if ($content -match "<password>([^<]+)</password>") {
                $password = $Matches[1]
                if ($password -match "^\{SHA" -or $password -match "^\{SSHA" -or $password.Length -gt 30) {
                    $dtList += "  -> 비밀번호 암호화: 적용됨 (양호)"
                } else {
                    $dtList += "  -> 비밀번호 암호화: 미적용 (취약)"
                }
            }
        } catch {
            $dtList += "  -> 파일 읽기 실패"
        }
    }
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- JEUS 관리 콘솔에서 비밀번호 복잡도 확인"
$dtList += "- SHA-256 이상 암호화 방식 사용 권장"
$dtList += ""
$dtList += "[비밀번호 설정 기준]"
$dtList += "- 영문/숫자/특수문자 조합 8자 이상"
$dtList += "- 계정명과 동일하지 않은 비밀번호"
$dtList += "- 연속적인 문자/숫자 사용 금지"

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

$dtList = @()
$vulnerable = $false

$dtList += "[JEUS 비밀번호/설정 파일 권한 확인]"
$dtList += ""

# accounts.xml 권한 확인
$filesToCheck = @()
$filesToCheck += $JEUS_CONFIG.AccountsXml
$filesToCheck += $JEUS_CONFIG.PoliciesXml

if ($filesToCheck.Count -gt 0) {
    foreach ($file in $filesToCheck) {
        if (Test-Path $file) {
            $dtList += "파일: $file"

            try {
                $acl = Get-Acl $file -ErrorAction SilentlyContinue

                foreach ($access in $acl.Access) {
                    $identity = $access.IdentityReference.Value
                    $rights = $access.FileSystemRights
                    $accessType = $access.AccessControlType

                    $dtList += "  - $identity : $rights ($accessType)"

                    # Everyone, Users에 읽기/쓰기 권한이 있으면 취약
                    if ($accessType -eq "Allow" -and
                        $identity -match "Everyone|BUILTIN\\Users" -and
                        $rights -match "Read|Write|FullControl|Modify") {
                        $vulnerable = $true
                        $dtList += "    -> 취약: 불필요한 권한 존재"
                    }
                }
            } catch {
                $dtList += "  -> 권한 확인 실패: $_"
            }
            $dtList += ""
        }
    }
} else {
    $dtList += "accounts.xml, policies.xml 파일을 찾을 수 없습니다."
    $RES = "M"
    $DESC = "비밀번호 파일을 찾을 수 없어 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "비밀번호 파일에 불필요한 권한이 존재하여 취약"
    } else {
        $RES = "Y"
        $DESC = "비밀번호 파일 권한이 적절히 설정되어 양호"
    }
}

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
$checked = $false

$dtList += "[JEUS 디렉터리 리스팅 설정 확인]"
$dtList += ""

# jeus-web-dd.xml에서 allow-indexing 확인
if ($JEUS_CONFIG.JeusWebDd.Count -gt 0) {
    $dtList += "[jeus-web-dd.xml 확인]"

    foreach ($file in $JEUS_CONFIG.JeusWebDd) {
        $dtList += "파일: $file"
        $checked = $true

        try {
            $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

            if ($content -match "<allow-indexing>\s*true\s*</allow-indexing>") {
                $dtList += "  -> allow-indexing: true (취약)"
                $vulnerable = $true
            } elseif ($content -match "<allow-indexing>\s*false\s*</allow-indexing>") {
                $dtList += "  -> allow-indexing: false (양호)"
            } else {
                $dtList += "  -> allow-indexing: 설정 없음 (기본값 확인 필요)"
            }
        } catch {
            $dtList += "  -> 파일 읽기 실패"
        }
    }
}

# domain.xml 또는 JEUSMain.xml 확인
$configFiles = $JEUS_CONFIG.DomainXml + $JEUS_CONFIG.JEUSMainXml
if ($configFiles.Count -gt 0) {
    $dtList += ""
    $dtList += "[도메인 설정 파일 확인]"

    foreach ($file in $configFiles) {
        $dtList += "파일: $file"
        $checked = $true

        try {
            $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

            if ($content -match "allow-indexing|directory-listing|listings") {
                if ($content -match "(allow-indexing|directory-listing|listings)\s*[=:>]\s*(true|on)") {
                    $dtList += "  -> 디렉터리 리스팅 활성화됨 (취약)"
                    $vulnerable = $true
                } else {
                    $dtList += "  -> 디렉터리 리스팅 비활성화됨 (양호)"
                }
            } else {
                $dtList += "  -> 디렉터리 리스팅 설정 없음"
            }
        } catch {
            $dtList += "  -> 파일 읽기 실패"
        }
    }
}

if (-not $checked) {
    $dtList += "설정 파일을 찾을 수 없습니다."
    $RES = "M"
    $DESC = "설정 파일을 찾을 수 없어 수동 확인 필요"
} elseif ([string]::IsNullOrEmpty($RES)) {
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

    $RES = "N/A"
    $DESC = "JEUS는 WAS로서 CGI/ISAPI를 지원하지 않음 (서블릿 기반)"
    $DT = @"
JEUS는 Java EE 기반 WAS로서 CGI/ISAPI 방식을 지원하지 않습니다.
서블릿/JSP 기반으로 동작하므로 해당 항목은 적용 대상이 아닙니다.
"@

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

    $RES = "N/A"
    $DESC = "JEUS는 WAS로서 상위 디렉터리 접근이 웹 컨텍스트로 제한됨"
    $DT = @"
JEUS는 Java EE 기반 WAS로서 웹 애플리케이션 컨텍스트 내에서만 리소스 접근이 가능합니다.
상위 디렉터리(../) 접근은 서블릿 컨테이너에 의해 기본적으로 제한됩니다.
"@

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

$dtList += "[JEUS 불필요한 파일/디렉터리 확인]"
$dtList += ""

# 불필요한 샘플/문서 디렉터리 확인
$samplePaths = @(
    "$JEUS_HOME\docs\manuals",
    "$JEUS_HOME\samples",
    "$JEUS_HOME\docs\examples",
    "$JEUS_HOME\webapps\docs",
    "$JEUS_HOME\webapps\examples"
)

$dtList += "[샘플/문서 디렉터리 확인]"

foreach ($path in $samplePaths) {
    if (Test-Path $path) {
        $dtList += "존재: $path (취약)"
        $vulnerable = $true
    }
}

if (-not $vulnerable) {
    $dtList += "불필요한 샘플 디렉터리 없음 (양호)"
}

# 백업 파일 확인
$dtList += ""
$dtList += "[백업/임시 파일 확인]"

try {
    $unnecessaryFiles = Get-ChildItem -Path $JEUS_HOME -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -match "\.(bak|old|tmp|temp|backup|orig)$" -or
        $_.Name -match "^(test|sample|example|readme|BUILDING|RELEASE-NOTES)"
    } | Select-Object -First 10

    if ($unnecessaryFiles) {
        foreach ($file in $unnecessaryFiles) {
            $dtList += "발견: $($file.FullName)"
            $vulnerable = $true
        }
    } else {
        $dtList += "불필요한 백업/임시 파일 없음"
    }
} catch {
    $dtList += "파일 검색 실패"
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

$RES = "M"
$DESC = "파일 업로드 용량 제한 수동 확인 필요"

$dtList = @()

$dtList += "[JEUS 파일 업로드 용량 제한 확인]"
$dtList += ""

# web.xml에서 multipart-config 확인
if ($JEUS_CONFIG.WebXml.Count -gt 0) {
    $dtList += "[web.xml 파일 확인]"

    foreach ($file in $JEUS_CONFIG.WebXml | Select-Object -First 5) {
        $dtList += "파일: $file"

        try {
            $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

            if ($content -match "<max-file-size>([^<]+)</max-file-size>") {
                $maxSize = $Matches[1]
                $dtList += "  -> max-file-size: $maxSize bytes"
            }

            if ($content -match "<max-request-size>([^<]+)</max-request-size>") {
                $maxRequest = $Matches[1]
                $dtList += "  -> max-request-size: $maxRequest bytes"
            }

            if ($content -notmatch "multipart-config") {
                $dtList += "  -> multipart-config 설정 없음"
            }
        } catch {
            $dtList += "  -> 파일 읽기 실패"
        }
    }
}

$dtList += ""
$dtList += "[권장 설정]"
$dtList += "- max-file-size: 5242880 (5MB)"
$dtList += "- 업로드 파일 5MB 이하 권장"

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

$dtList += "[JEUS 프로세스 실행 계정 확인]"
$dtList += ""

try {
    # JEUS 관련 java 프로세스 확인
    $jeusProcesses = Get-CimInstance Win32_Process -Filter "Name='java.exe'" -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match "jeus" -or $_.CommandLine -match "JEUS"
    }

    if ($jeusProcesses) {
        foreach ($proc in $jeusProcesses) {
            $owner = (Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue)
            $userName = if ($owner) { "$($owner.Domain)\$($owner.User)" } else { "Unknown" }

            $dtList += "PID: $($proc.ProcessId)"
            $dtList += "  실행 계정: $userName"

            # 관리자 계정 확인
            if ($userName -match "SYSTEM|Administrator|admin") {
                $dtList += "  -> 경고: 관리자 권한으로 실행 중 (취약)"
                $vulnerable = $true
            } else {
                $dtList += "  -> 별도 계정으로 실행 (양호)"
            }
        }
    } else {
        $dtList += "실행 중인 JEUS 프로세스 없음"
        $dtList += ""
        $dtList += "[JEUS 서비스 확인]"

        # Windows 서비스 확인
        $jeusService = Get-Service -Name "*jeus*" -ErrorAction SilentlyContinue
        if ($jeusService) {
            foreach ($svc in $jeusService) {
                $dtList += "서비스: $($svc.Name) - 상태: $($svc.Status)"

                # 서비스 계정 확인
                $svcInfo = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
                if ($svcInfo) {
                    $dtList += "  실행 계정: $($svcInfo.StartName)"
                    if ($svcInfo.StartName -match "LocalSystem|SYSTEM") {
                        $dtList += "  -> 경고: LocalSystem으로 실행 (취약)"
                        $vulnerable = $true
                    }
                }
            }
        } else {
            $dtList += "JEUS 서비스가 등록되어 있지 않음"
            $RES = "M"
            $DESC = "JEUS 프로세스/서비스 확인 불가, 수동 확인 필요"
        }
    }
} catch {
    $dtList += "프로세스 정보 확인 실패: $_"
    $RES = "M"
    $DESC = "프로세스 정보 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "JEUS가 관리자 권한으로 실행되어 취약"
    } else {
        $RES = "Y"
        $DESC = "JEUS가 적절한 권한으로 실행되어 양호"
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

$dtList += "[JEUS 프록시 설정 확인]"
$dtList += ""

# ReverseProxy 설정 확인
$configFiles = $JEUS_CONFIG.DomainXml + $JEUS_CONFIG.JEUSMainXml + $JEUS_CONFIG.WebXml

if ($configFiles.Count -gt 0) {
    foreach ($file in $configFiles | Select-Object -First 5) {
        if (Test-Path $file) {
            $dtList += "파일: $file"

            try {
                $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

                if ($content -match "proxy|Proxy|PROXY") {
                    $dtList += "  -> 프록시 관련 설정 발견"

                    # 상세 내용 추출
                    $proxyLines = ($content -split "`n") | Where-Object { $_ -match "proxy" } | Select-Object -First 5
                    foreach ($line in $proxyLines) {
                        $dtList += "    $($line.Trim())"
                    }
                } else {
                    $dtList += "  -> 프록시 설정 없음"
                }
            } catch {
                $dtList += "  -> 파일 읽기 실패"
            }
        }
    }
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- JEUS 관리 콘솔에서 ReverseProxy 설정 확인"
$dtList += "- web.xml 내 불필요한 프록시 설정 제거"

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

$dtList += "[JEUS DocRoot 경로 설정 확인]"
$dtList += ""

# 시스템 경로와 분리 여부 확인
$systemPaths = @("C:\Windows", "C:\Program Files", "C:\Users")

# domain.xml 또는 JEUSMain.xml에서 docroot 확인
$configFiles = $JEUS_CONFIG.DomainXml + $JEUS_CONFIG.JEUSMainXml

if ($configFiles.Count -gt 0) {
    foreach ($file in $configFiles) {
        if (Test-Path $file) {
            $dtList += "파일: $file"

            try {
                $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

                # docroot 또는 document-root 추출
                if ($content -match "<doc-root>([^<]+)</doc-root>") {
                    $docRoot = $Matches[1]
                    $dtList += "  -> doc-root: $docRoot"

                    # 시스템 경로 사용 여부 확인
                    foreach ($sysPath in $systemPaths) {
                        if ($docRoot -like "$sysPath*") {
                            $dtList += "    -> 경고: 시스템 경로 사용 (취약)"
                            $vulnerable = $true
                        }
                    }
                }

                # context-path 확인
                if ($content -match "<context-path>([^<]+)</context-path>") {
                    $contextPath = $Matches[1]
                    $dtList += "  -> context-path: $contextPath"
                }
            } catch {
                $dtList += "  -> 파일 읽기 실패"
            }
        }
    }
}

# JEUS_HOME 경로 확인
$dtList += ""
$dtList += "JEUS_HOME: $JEUS_HOME"

foreach ($sysPath in $systemPaths) {
    if ($JEUS_HOME -like "$sysPath*") {
        $dtList += "  -> 경고: JEUS가 시스템 경로에 설치됨"
        $vulnerable = $true
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "웹 서비스 경로가 시스템 경로와 분리되지 않아 취약"
} else {
    $RES = "Y"
    $DESC = "웹 서비스 경로가 적절히 설정되어 양호"
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

$dtList += "[JEUS Alias/바로가기 설정 확인]"
$dtList += ""

# jeus-web-dd.xml에서 aliasing 확인
if ($JEUS_CONFIG.JeusWebDd.Count -gt 0) {
    $dtList += "[jeus-web-dd.xml alias 설정]"

    foreach ($file in $JEUS_CONFIG.JeusWebDd) {
        $dtList += "파일: $file"

        try {
            $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

            if ($content -match "<aliasing>") {
                $dtList += "  -> aliasing 설정 발견 (취약)"
                $vulnerable = $true

                # alias 상세 내용 추출
                if ($content -match "<alias-name>([^<]+)</alias-name>") {
                    $dtList += "    alias-name: $($Matches[1])"
                }
                if ($content -match "<real-path>([^<]+)</real-path>") {
                    $dtList += "    real-path: $($Matches[1])"
                }
            } else {
                $dtList += "  -> aliasing 설정 없음 (양호)"
            }
        } catch {
            $dtList += "  -> 파일 읽기 실패"
        }
    }
}

# 바로가기 파일(.lnk) 확인
$dtList += ""
$dtList += "[바로가기 파일 확인]"

try {
    $shortcuts = Get-ChildItem -Path $JEUS_HOME -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5

    if ($shortcuts) {
        foreach ($shortcut in $shortcuts) {
            $dtList += "발견: $($shortcut.FullName)"
            $vulnerable = $true
        }
    } else {
        $dtList += "바로가기 파일 없음 (양호)"
    }
} catch {
    $dtList += "파일 검색 실패"
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "Alias 또는 바로가기가 존재하여 취약"
} else {
    $RES = "Y"
    $DESC = "불필요한 링크가 존재하지 않아 양호"
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

$dtList = @()
$vulnerable = $false

$dtList += "[JEUS 설정 파일 권한 확인]"
$dtList += ""

# 주요 설정 파일 권한 확인
$configFilesToCheck = @()
$configFilesToCheck += $JEUS_CONFIG.DomainXml
$configFilesToCheck += $JEUS_CONFIG.JEUSMainXml
$configFilesToCheck += $JEUS_CONFIG.AccountsXml

foreach ($file in $configFilesToCheck) {
    if (Test-Path $file) {
        $dtList += "파일: $file"

        try {
            $acl = Get-Acl $file -ErrorAction SilentlyContinue

            foreach ($access in $acl.Access) {
                $identity = $access.IdentityReference.Value
                $rights = $access.FileSystemRights
                $accessType = $access.AccessControlType

                # Everyone, Users에 권한이 있으면 취약
                if ($accessType -eq "Allow" -and
                    $identity -match "Everyone|BUILTIN\\Users" -and
                    $rights -match "Read|Write|FullControl|Modify") {
                    $dtList += "  -> 취약: $identity 에 $rights 권한"
                    $vulnerable = $true
                }
            }
        } catch {
            $dtList += "  -> 권한 확인 실패"
        }
    }
}

# DB 연결 정보 노출 확인
$dtList += ""
$dtList += "[DB 연결 정보 노출 확인]"

foreach ($file in $JEUS_CONFIG.DomainXml) {
    if (Test-Path $file) {
        try {
            $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

            if ($content -match "<datasource>") {
                $dtList += "domain.xml에 datasource 설정 존재"

                if ($content -match "<password>([^<]+)</password>") {
                    $password = $Matches[1]
                    if ($password -notmatch "^\{" -and $password.Length -lt 20) {
                        $dtList += "  -> 경고: 평문 비밀번호 가능성"
                        $vulnerable = $true
                    }
                }
            }
        } catch { }
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "설정 파일에 불필요한 권한 또는 노출 위험이 존재하여 취약"
} else {
    $RES = "Y"
    $DESC = "설정 파일 권한이 적절히 설정되어 양호"
}

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

$dtList += "[JEUS 주요 디렉터리 권한 확인]"
$dtList += ""

# 주요 디렉터리 권한 확인
$dirsToCheck = @(
    "$JEUS_HOME\domains",
    "$JEUS_HOME\config",
    "$JEUS_HOME\bin"
)

foreach ($dir in $dirsToCheck) {
    if (Test-Path $dir) {
        $dtList += "디렉터리: $dir"

        try {
            $acl = Get-Acl $dir -ErrorAction SilentlyContinue

            foreach ($access in $acl.Access) {
                $identity = $access.IdentityReference.Value
                $rights = $access.FileSystemRights
                $accessType = $access.AccessControlType

                $dtList += "  - $identity : $rights"

                # Everyone에 쓰기/수정/삭제 권한이 있으면 취약
                if ($accessType -eq "Allow" -and
                    $identity -match "Everyone" -and
                    $rights -match "Write|FullControl|Modify|Delete") {
                    $dtList += "    -> 취약: Everyone에 쓰기 권한"
                    $vulnerable = $true
                }
            }
        } catch {
            $dtList += "  -> 권한 확인 실패"
        }
        $dtList += ""
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "주요 디렉터리에 불필요한 권한이 존재하여 취약"
} else {
    $RES = "Y"
    $DESC = "주요 디렉터리 권한이 적절히 설정되어 양호"
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

$RES = "M"
$DESC = "스크립트 매핑 수동 확인 필요"

$dtList = @()

$dtList += "[JEUS 서블릿 매핑 확인]"
$dtList += ""

# web.xml에서 servlet-mapping 확인
if ($JEUS_CONFIG.WebXml.Count -gt 0) {
    foreach ($file in $JEUS_CONFIG.WebXml | Select-Object -First 5) {
        $dtList += "파일: $file"

        try {
            $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

            if ($content -match "<servlet-mapping>") {
                $dtList += "  -> servlet-mapping 설정 존재"

                # 매핑 패턴 추출
                $patterns = [regex]::Matches($content, "<url-pattern>([^<]+)</url-pattern>")
                foreach ($pattern in $patterns | Select-Object -First 5) {
                    $dtList += "    pattern: $($pattern.Groups[1].Value)"
                }
            } else {
                $dtList += "  -> servlet-mapping 설정 없음"
            }
        } catch {
            $dtList += "  -> 파일 읽기 실패"
        }
    }
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- 불필요한 서블릿 매핑 제거"
$dtList += "- 사용하지 않는 URL 패턴 확인"

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
$checked = $false

$dtList += "[JEUS 서버 정보 노출 설정 확인]"
$dtList += ""

# domain.xml 또는 JEUSMain.xml에서 serverInfo 설정 확인
$configFiles = $JEUS_CONFIG.DomainXml + $JEUS_CONFIG.JEUSMainXml

foreach ($file in $configFiles) {
    if (Test-Path $file) {
        $dtList += "파일: $file"
        $checked = $true

        try {
            $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

            # serverInfo=false 설정 확인
            if ($content -match "serverInfo\s*=\s*false" -or
                $content -match "<server-info>false</server-info>") {
                $dtList += "  -> serverInfo: false (양호)"
            } elseif ($content -match "serverInfo\s*=\s*true" -or
                     $content -match "<server-info>true</server-info>") {
                $dtList += "  -> serverInfo: true (취약)"
                $vulnerable = $true
            } else {
                $dtList += "  -> serverInfo 설정 없음 (기본값 확인 필요)"
            }

            # response-header 설정 확인
            if ($content -match "<response-header>") {
                $dtList += "  -> response-header 커스텀 설정 존재"
            }
        } catch {
            $dtList += "  -> 파일 읽기 실패"
        }
    }
}

# JEUS 7 이전 버전 command-option 확인
foreach ($file in $JEUS_CONFIG.JEUSMainXml) {
    if (Test-Path $file) {
        try {
            $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

            if ($content -match "jeus\.servlet\.response\.header\.serverInfo=false") {
                $dtList += "  -> JVM 옵션에서 serverInfo=false 설정됨 (양호)"
            }
        } catch { }
    }
}

if (-not $checked) {
    $RES = "M"
    $DESC = "설정 파일을 찾을 수 없어 수동 확인 필요"
} elseif ($vulnerable) {
    $RES = "N"
    $DESC = "HTTP 응답 헤더에 서버 정보가 노출되어 취약"
} else {
    $RES = "Y"
    $DESC = "HTTP 응답 헤더 정보가 제한되어 양호"
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

    $RES = "N/A"
    $DESC = "JEUS는 WAS로서 가상 디렉터리 개념이 없음 (웹 애플리케이션 배포 방식)"
    $DT = @"
JEUS는 웹 서버가 아닌 WAS로서 가상 디렉터리 개념을 사용하지 않습니다.
웹 애플리케이션은 WAR/EAR 형태로 배포되며 컨텍스트 경로로 접근합니다.
"@

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

    $RES = "N/A"
    $DESC = "JEUS는 기본적으로 WebDAV를 지원하지 않음"
    $DT = @"
JEUS는 기본 설치 시 WebDAV 기능을 제공하지 않습니다.
별도의 WebDAV 서블릿을 배포하지 않는 한 해당 기능은 사용되지 않습니다.
"@

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

    $RES = "N/A"
    $DESC = "JEUS는 WAS로서 SSI를 지원하지 않음 (JSP/서블릿 기반)"
    $DT = @"
JEUS는 Java EE 기반 WAS로서 Server Side Includes(SSI)를 지원하지 않습니다.
동적 콘텐츠 처리는 JSP, 서블릿을 통해 수행됩니다.
"@

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

    $RES = "N/A"
    $DESC = "JEUS 앞단에 웹서버를 두고 SSL 처리 권장"
    $DT = @"
JEUS WAS 단독으로 SSL/TLS를 처리하는 것보다 앞단 웹서버(Apache, WebtoB 등)에서
SSL Offloading을 수행하는 아키텍처를 권장합니다.
앞단 웹서버의 SSL/TLS 설정을 점검하시기 바랍니다.
"@

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

    $RES = "N/A"
    $DESC = "JEUS 앞단 웹서버에서 HTTPS 리디렉션 처리 권장"
    $DT = @"
HTTP에서 HTTPS로의 리디렉션은 앞단 웹서버(Apache, WebtoB 등)에서
처리하는 것이 권장됩니다.
앞단 웹서버의 리디렉션 설정을 점검하시기 바랍니다.
"@

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

$dtList += "[JEUS 에러 페이지 설정 확인]"
$dtList += ""

# web.xml에서 error-page 설정 확인
if ($JEUS_CONFIG.WebXml.Count -gt 0) {
    foreach ($file in $JEUS_CONFIG.WebXml | Select-Object -First 5) {
        $dtList += "파일: $file"

        try {
            $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

            if ($content -match "<error-page>") {
                $hasErrorPage = $true
                $dtList += "  -> error-page 설정 존재 (양호)"

                # 에러 코드별 설정 확인
                $errorCodes = [regex]::Matches($content, "<error-code>([^<]+)</error-code>")
                foreach ($code in $errorCodes | Select-Object -First 5) {
                    $dtList += "    error-code: $($code.Groups[1].Value)"
                }

                $locations = [regex]::Matches($content, "<location>([^<]+)</location>")
                foreach ($loc in $locations | Select-Object -First 5) {
                    $dtList += "    location: $($loc.Groups[1].Value)"
                }
            } else {
                $dtList += "  -> error-page 설정 없음"
            }
        } catch {
            $dtList += "  -> 파일 읽기 실패"
        }
    }
}

$dtList += ""
$dtList += "[권장 설정]"
$dtList += "- 400, 401, 403, 404, 500 에러 코드에 대해 일원화된 에러 페이지 설정"
$dtList += "- 에러 페이지에 서버 정보 노출 금지"

if ($hasErrorPage) {
    $RES = "Y"
    $DESC = "에러 페이지가 설정되어 양호"
} else {
    $RES = "N"
    $DESC = "에러 페이지가 설정되지 않아 취약"
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
    $DESC = "JEUS LDAP 연동은 별도 보안 모듈 설정으로 관리"
    $DT = @"
JEUS에서 LDAP 연동 시 보안 설정은 별도의 Security Domain 설정을 통해 관리됩니다.
LDAP 연동을 사용하는 경우 domain.xml 또는 security 설정의 LDAP 관련 항목을 점검하시기 바랍니다.
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

$dtList += "[JEUS 업로드 경로 확인]"
$dtList += ""

# web.xml에서 uploadDir 설정 확인
if ($JEUS_CONFIG.WebXml.Count -gt 0) {
    foreach ($file in $JEUS_CONFIG.WebXml | Select-Object -First 5) {
        $dtList += "파일: $file"

        try {
            $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

            if ($content -match "<param-name>uploadDir</param-name>") {
                if ($content -match "<param-value>([^<]+)</param-value>") {
                    $uploadDir = $Matches[1]
                    $dtList += "  -> uploadDir: $uploadDir"

                    if (Test-Path $uploadDir) {
                        $acl = Get-Acl $uploadDir -ErrorAction SilentlyContinue
                        $dtList += "  -> 권한:"
                        foreach ($access in $acl.Access | Select-Object -First 3) {
                            $dtList += "    $($access.IdentityReference): $($access.FileSystemRights)"
                        }
                    }
                }
            } else {
                $dtList += "  -> uploadDir 설정 없음"
            }
        } catch {
            $dtList += "  -> 파일 읽기 실패"
        }
    }
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- 업로드 디렉터리가 웹 루트 외부에 위치하는지 확인"
$dtList += "- 업로드 디렉터리에 스크립트 실행 권한이 없는지 확인"
$dtList += "- 권한 설정: 750 이하 권장"

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
$DESC = "JEUS 버전 및 패치 수준 수동 확인 필요"

$dtList = @()

$dtList += "[JEUS 버전 정보]"
$dtList += ""

# JEUS 버전 확인
$dtList += "JEUS_HOME: $JEUS_HOME"

try {
    # jeusadmin -version 실행
    $jeusAdmin = Join-Path $JEUS_HOME "bin\jeusadmin.cmd"
    if (Test-Path $jeusAdmin) {
        $dtList += "jeusadmin 경로: $jeusAdmin"

        try {
            $versionOutput = & cmd /c "`"$jeusAdmin`" -version" 2>&1
            if ($versionOutput) {
                foreach ($line in $versionOutput) {
                    $dtList += "  $line"
                }
            }
        } catch {
            $dtList += "  -> 버전 명령 실행 실패"
        }
    }

    # jeusadmin -fullversion
    if (Test-Path $jeusAdmin) {
        try {
            $fullVersionOutput = & cmd /c "`"$jeusAdmin`" -fullversion" 2>&1
            if ($fullVersionOutput) {
                $dtList += ""
                $dtList += "[상세 버전]"
                foreach ($line in $fullVersionOutput | Select-Object -First 5) {
                    $dtList += "  $line"
                }
            }
        } catch { }
    }
} catch {
    $dtList += "버전 정보 확인 실패: $_"
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- TmaxSoft 기술넷에서 최신 버전 확인"
$dtList += "- 참고: https://technet.tmaxsoft.com/ko/front/download/findDownloadList.do"
$dtList += "- 보안 패치 적용 여부 확인"

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

$dtList += "[JEUS 로그 디렉터리 권한 확인]"
$dtList += ""

# 로그 디렉터리 경로
$logPaths = @()

# domains/*/servers/*/logs
$domainLogs = Get-ChildItem -Path "$JEUS_HOME\domains\*\servers\*\logs" -Directory -ErrorAction SilentlyContinue
foreach ($log in $domainLogs) {
    $logPaths += $log.FullName
}

# 기본 logs 디렉터리
if (Test-Path "$JEUS_HOME\logs") {
    $logPaths += "$JEUS_HOME\logs"
}

foreach ($logPath in $logPaths) {
    if (Test-Path $logPath) {
        $dtList += "디렉터리: $logPath"

        try {
            $acl = Get-Acl $logPath -ErrorAction SilentlyContinue

            foreach ($access in $acl.Access) {
                $identity = $access.IdentityReference.Value
                $rights = $access.FileSystemRights
                $accessType = $access.AccessControlType

                $dtList += "  - $identity : $rights"

                # Everyone에 읽기/쓰기 권한이 있으면 취약
                if ($accessType -eq "Allow" -and
                    $identity -match "Everyone" -and
                    $rights -match "Read|Write|FullControl") {
                    $vulnerable = $true
                    $dtList += "    -> 취약: Everyone 권한 존재"
                }
            }
        } catch {
            $dtList += "  -> 권한 확인 실패"
        }
        $dtList += ""
    }
}

if ($logPaths.Count -eq 0) {
    $dtList += "로그 디렉터리를 찾을 수 없습니다."
    $dtList += "  확인 경로: $JEUS_HOME\domains\*\servers\*\logs"
    $RES = "M"
    $DESC = "로그 디렉터리를 찾을 수 없어 수동 확인 필요"
} elseif ($vulnerable) {
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

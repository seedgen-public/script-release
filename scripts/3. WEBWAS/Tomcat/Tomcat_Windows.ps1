#================================================================
# Tomcat_Windows 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Tomcat_Windows
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
$META_PLAT = "Tomcat"
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
function Find-TomcatInstallation {
    $tomcatPaths = @()

    # 1. CATALINA_HOME 환경변수 확인
    $envCatalinaHome = [Environment]::GetEnvironmentVariable("CATALINA_HOME", "Machine")
    if (-not $envCatalinaHome) {
        $envCatalinaHome = [Environment]::GetEnvironmentVariable("CATALINA_HOME", "User")
    }
    if (-not $envCatalinaHome) {
        $envCatalinaHome = $env:CATALINA_HOME
    }
    if ($envCatalinaHome -and (Test-Path "$envCatalinaHome\conf\server.xml")) {
        $tomcatPaths += $envCatalinaHome
    }

    # 2. 일반적인 설치 경로 확인
    $commonPaths = @(
        "C:\Program Files\Apache Software Foundation\Tomcat*",
        "C:\Program Files (x86)\Apache Software Foundation\Tomcat*",
        "C:\tomcat*",
        "C:\Apache\tomcat*",
        "C:\Program Files\tomcat*",
        "D:\tomcat*",
        "D:\Apache\tomcat*"
    )

    foreach ($pattern in $commonPaths) {
        $found = Get-Item $pattern -ErrorAction SilentlyContinue
        foreach ($path in $found) {
            if (Test-Path "$($path.FullName)\conf\server.xml") {
                if ($tomcatPaths -notcontains $path.FullName) {
                    $tomcatPaths += $path.FullName
                }
            }
        }
    }

    # 3. Windows 서비스에서 Tomcat 찾기
    $tomcatServices = @("Tomcat9", "Tomcat10", "Tomcat8", "Tomcat7", "Apache Tomcat*", "*tomcat*")
    foreach ($svcPattern in $tomcatServices) {
        $services = Get-Service -Name $svcPattern -ErrorAction SilentlyContinue
        foreach ($svc in $services) {
            try {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
                $imagePath = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).ImagePath
                if ($imagePath) {
                    # 경로에서 bin\tomcat*.exe 부분 제거하여 CATALINA_HOME 추출
                    # 공백이 포함된 경로를 위해 따옴표 있는 경로 우선 처리
                    $catalinaHome = $null
                    if ($imagePath -match '"([^"]+)\\bin\\') {
                        # 따옴표로 감싸진 경로 (예: "C:\Program Files\Apache Tomcat\bin\tomcat9.exe")
                        $catalinaHome = $matches[1]
                    } elseif ($imagePath -match '([A-Za-z]:\\[^\\]+(?:\\[^\\]+)+)\\bin\\') {
                        # 따옴표 없는 경로 (예: C:\tomcat\bin\tomcat9.exe)
                        $catalinaHome = $matches[1]
                    }

                    if ($catalinaHome -and $catalinaHome.Length -gt 3 -and (Test-Path "$catalinaHome\conf\server.xml") -and ($tomcatPaths -notcontains $catalinaHome)) {
                        $tomcatPaths += $catalinaHome
                    }
                }
            } catch { }
        }
    }

    # 4. 레지스트리에서 Tomcat 찾기
    $regPaths = @(
        "HKLM:\SOFTWARE\Apache Software Foundation\Tomcat*",
        "HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Tomcat*"
    )
    foreach ($regPattern in $regPaths) {
        try {
            $regKeys = Get-Item $regPattern -ErrorAction SilentlyContinue
            foreach ($key in $regKeys) {
                $installPath = (Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue).InstallPath
                if ($installPath -and (Test-Path "$installPath\conf\server.xml") -and ($tomcatPaths -notcontains $installPath)) {
                    $tomcatPaths += $installPath
                }
            }
        } catch { }
    }

    return $tomcatPaths
}

# Tomcat 탐지 실행
$TOMCAT_PATHS = Find-TomcatInstallation

if ($TOMCAT_PATHS.Count -eq 0) {
    Write-Host "[X] Tomcat이 설치되어 있지 않거나 찾을 수 없습니다." -ForegroundColor Red
    Write-Host "    환경변수 CATALINA_HOME이 설정되어 있는지 확인하세요." -ForegroundColor Yellow
    Write-Host "    일반적인 설치 경로: C:\Program Files\Apache Software Foundation\Tomcat X.X" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# 첫 번째로 발견된 Tomcat 사용
$CATALINA_HOME = $TOMCAT_PATHS[0]
$TOMCAT_CONF = "$CATALINA_HOME\conf"
$SERVER_XML = "$TOMCAT_CONF\server.xml"
$WEB_XML = "$TOMCAT_CONF\web.xml"
$TOMCAT_USERS_XML = "$TOMCAT_CONF\tomcat-users.xml"
$CONTEXT_XML = "$TOMCAT_CONF\context.xml"

# Tomcat 버전 확인
$TOMCAT_VERSION = ""
try {
    $catalinaJar = "$CATALINA_HOME\lib\catalina.jar"
    if (Test-Path $catalinaJar) {
        # MANIFEST.MF에서 버전 확인
        $manifestPath = "$env:TEMP\tomcat_manifest_$([guid]::NewGuid().ToString('N'))"
        & jar xf "$catalinaJar" META-INF/MANIFEST.MF 2>$null
        if (Test-Path "META-INF\MANIFEST.MF") {
            $manifest = Get-Content "META-INF\MANIFEST.MF" -ErrorAction SilentlyContinue
            $versionLine = $manifest | Where-Object { $_ -match "Implementation-Version:" }
            if ($versionLine) {
                $TOMCAT_VERSION = ($versionLine -split ":")[1].Trim()
            }
            Remove-Item "META-INF" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # 대안: RELEASE-NOTES 파일에서 확인
    if (-not $TOMCAT_VERSION -and (Test-Path "$CATALINA_HOME\RELEASE-NOTES")) {
        $releaseNotes = Get-Content "$CATALINA_HOME\RELEASE-NOTES" -TotalCount 10 -ErrorAction SilentlyContinue
        $versionLine = $releaseNotes | Where-Object { $_ -match "Apache Tomcat Version" }
        if ($versionLine) {
            $TOMCAT_VERSION = ($versionLine -split "Version")[1].Trim()
        }
    }

    # 대안: 폴더명에서 추출
    if (-not $TOMCAT_VERSION) {
        $folderName = Split-Path $CATALINA_HOME -Leaf
        if ($folderName -match "Tomcat\s*(\d+\.?\d*\.?\d*)") {
            $TOMCAT_VERSION = $matches[1]
        }
    }
} catch { }

$SVC_VERSION = $TOMCAT_VERSION
$SVC_CONF = $TOMCAT_CONF

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

# 출력 파일 경로
$OUTPUT_FILE = "$PSScriptRoot\${META_PLAT}_${SYS_HOST}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"


Write-Host "  [진단 시작]" -ForegroundColor Yellow
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""


    if (-not (Test-Path $TOMCAT_USERS_XML)) {
        $RES = "N/A"
        $DESC = "tomcat-users.xml 파일을 찾을 수 없음"
        $DT = "TOMCAT_USERS_XML: $TOMCAT_USERS_XML (not found)"
    } else {
        try {
            $content = Get-Content $TOMCAT_USERS_XML -Raw -ErrorAction SilentlyContinue

            # 주석 제거 (단순화된 방식)
            $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

            # 기본 계정명(admin, tomcat, manager, root) 확인
            $defaultAccounts = [regex]::Matches($contentWithoutComments, 'username\s*=\s*"(admin|tomcat|manager|root)"')

            # manager-gui 등 관리자 역할 확인
            $adminRoles = [regex]::Matches($contentWithoutComments, 'roles\s*=\s*"[^"]*manager-gui[^"]*"')

            if ($adminRoles.Count -eq 0) {
                $RES = "Y"
                $DESC = "관리자 페이지가 비활성화되어 있거나 관리자 계정이 없음"
                $DT = "manager-gui 역할: 미설정"
            } elseif ($defaultAccounts.Count -eq 0) {
                $RES = "Y"
                $DESC = "기본 관리자 계정명이 변경되어 있음"
                $DT = "관리자 역할 설정 존재, 기본 계정명(admin, tomcat, manager, root) 미사용"
            } else {
                $RES = "N"
                $DESC = "기본 관리자 계정명이 사용되고 있음"
                $foundAccounts = ($defaultAccounts | ForEach-Object { $_.Value }) -join ", "
                $DT = "발견된 기본 계정: $foundAccounts"
            }
        } catch {
            $RES = "M"
            $DESC = "tomcat-users.xml 파일 분석 실패"
            $DT = "오류: $_"
        }
    }

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

if (-not (Test-Path $TOMCAT_USERS_XML)) {
    $RES = "N/A"
    $DESC = "tomcat-users.xml 파일을 찾을 수 없음"
    $DT = "TOMCAT_USERS_XML: not found"
} else {
    try {
        $content = Get-Content $TOMCAT_USERS_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        # 비밀번호 추출
        $passwords = [regex]::Matches($contentWithoutComments, 'password\s*=\s*"([^"]*)"')

        if ($passwords.Count -eq 0) {
            $RES = "Y"
            $DESC = "설정된 비밀번호가 없거나 관리자 계정이 없음"
            $DT = "비밀번호: 미설정"
        } else {
            $weakPasswords = @()
            $totalPass = $passwords.Count

            foreach ($match in $passwords) {
                $pass = $match.Groups[1].Value
                $isWeak = $false

                # 길이 체크 (8자 미만)
                if ($pass.Length -lt 8) {
                    $isWeak = $true
                }

                # 단순 비밀번호 체크
                if ($pass -match "^(password|admin|tomcat|123456|qwerty|1234|root|test)") {
                    $isWeak = $true
                }

                # 숫자만으로 구성
                if ($pass -match "^[0-9]+$") {
                    $isWeak = $true
                }

                # 영문만으로 구성
                if ($pass -match "^[a-zA-Z]+$") {
                    $isWeak = $true
                }

                # 암호화된 비밀번호 확인 (해시)
                if ($pass -match "^\{(SHA|MD5|SSHA|SHA-256|SHA-512)\}") {
                    $isWeak = $false
                }

                if ($isWeak) {
                    $weakPasswords += "취약한 비밀번호 발견 (길이: $($pass.Length))"
                }
            }

            if ($weakPasswords.Count -eq 0) {
                $RES = "Y"
                $DESC = "비밀번호가 복잡도 기준을 충족함"
                $DT = "총 ${totalPass}개 계정 확인, 취약한 비밀번호 없음"
            } else {
                $RES = "N"
                $DESC = "취약한 비밀번호가 발견됨"
                $DT = "총 ${totalPass}개 계정 중 $($weakPasswords.Count)개 취약`n" + ($weakPasswords -join "`n")
            }
        }
    } catch {
        $RES = "M"
        $DESC = "비밀번호 분석 실패"
        $DT = "오류: $_"
    }
}

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

if (-not (Test-Path $TOMCAT_USERS_XML)) {
    $RES = "N/A"
    $DESC = "tomcat-users.xml 파일을 찾을 수 없음"
    $DT = "TOMCAT_USERS_XML: not found"
} else {
    try {
        $acl = Get-Acl $TOMCAT_USERS_XML -ErrorAction SilentlyContinue
        $dtList = @()
        $dtList += "파일: $TOMCAT_USERS_XML"
        $dtList += "소유자: $($acl.Owner)"
        $dtList += ""
        $dtList += "[권한 목록]"

        $vulnerable = $false
        foreach ($access in $acl.Access) {
            $identity = $access.IdentityReference.Value
            $rights = $access.FileSystemRights
            $dtList += "$identity : $rights"

            # Everyone 또는 Users에 읽기/쓰기 권한이 있으면 취약
            if ($identity -match "Everyone|BUILTIN\\Users" -and $rights -match "Read|Write|FullControl|Modify") {
                $vulnerable = $true
            }
        }

        if ($vulnerable) {
            $RES = "N"
            $DESC = "tomcat-users.xml 파일에 불필요한 권한이 존재"
        } else {
            $RES = "Y"
            $DESC = "tomcat-users.xml 파일 권한이 적절히 설정됨"
        }
        $DT = $dtList -join "`n"
    } catch {
        $RES = "M"
        $DESC = "파일 권한 확인 실패"
        $DT = "오류: $_"
    }
}

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

if (-not (Test-Path $WEB_XML)) {
    $RES = "N/A"
    $DESC = "web.xml 파일을 찾을 수 없음"
    $DT = "WEB_XML: not found"
} else {
    try {
        $content = Get-Content $WEB_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        # listings 파라미터 확인
        # <param-name>listings</param-name> 다음의 <param-value> 확인
        if ($contentWithoutComments -match '<param-name>\s*listings\s*</param-name>\s*<param-value>\s*true\s*</param-value>') {
            $RES = "N"
            $DESC = "디렉터리 리스팅이 활성화되어 있음"
            $DT = "listings = true"
        } elseif ($contentWithoutComments -match '<param-name>\s*listings\s*</param-name>\s*<param-value>\s*false\s*</param-value>') {
            $RES = "Y"
            $DESC = "디렉터리 리스팅이 비활성화되어 있음"
            $DT = "listings = false"
        } else {
            # 기본값은 false
            $RES = "Y"
            $DESC = "디렉터리 리스팅 설정이 없음 (기본값: false)"
            $DT = "listings: 미설정 (기본값 false 적용)"
        }
    } catch {
        $RES = "M"
        $DESC = "web.xml 파일 분석 실패"
        $DT = "오류: $_"
    }
}

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

if (-not (Test-Path $WEB_XML)) {
    $RES = "N/A"
    $DESC = "web.xml 파일을 찾을 수 없음"
    $DT = "WEB_XML: not found"
} else {
    try {
        $content = Get-Content $WEB_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        # CGI 서블릿 매핑 확인
        $hasCgiServlet = $contentWithoutComments -match '<servlet-name>\s*cgi\s*</servlet-name>'
        $hasCgiMapping = $contentWithoutComments -match '<url-pattern>\s*/cgi-bin/\*\s*</url-pattern>'

        if (-not $hasCgiServlet -and -not $hasCgiMapping) {
            $RES = "Y"
            $DESC = "CGI 실행이 제한되어 있음"
            $DT = "CGI 서블릿: 비활성화`nCGI 매핑: 미설정"
        } else {
            $RES = "M"
            $DESC = "CGI 설정 확인 필요"
            $dtList = @()
            if ($hasCgiServlet) { $dtList += "CGI 서블릿: 설정됨" }
            if ($hasCgiMapping) { $dtList += "CGI 매핑: 설정됨" }
            $DT = $dtList -join "`n"
        }
    } catch {
        $RES = "M"
        $DESC = "web.xml 파일 분석 실패"
        $DT = "오류: $_"
    }
}

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

# server.xml 확인
if (Test-Path $SERVER_XML) {
    $content = Get-Content $SERVER_XML -Raw -ErrorAction SilentlyContinue
    $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

    if ($contentWithoutComments -match 'allowLinking\s*=\s*"true"') {
        $vulnerable = $true
        $dtList += "server.xml: allowLinking=true (취약)"
    } else {
        $dtList += "server.xml: allowLinking 미설정 또는 false (양호)"
    }
} else {
    $dtList += "server.xml: 파일 없음"
}

# context.xml 확인
if (Test-Path $CONTEXT_XML) {
    $content = Get-Content $CONTEXT_XML -Raw -ErrorAction SilentlyContinue
    $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

    if ($contentWithoutComments -match 'allowLinking\s*=\s*"true"') {
        $vulnerable = $true
        $dtList += "context.xml: allowLinking=true (취약)"
    } else {
        $dtList += "context.xml: allowLinking 미설정 또는 false (양호)"
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "상위 디렉터리 접근이 허용되어 있음"
} else {
    $RES = "Y"
    $DESC = "상위 디렉터리 접근이 제한되어 있음"
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

$webappsPath = "$CATALINA_HOME\webapps"
$dtList = @()
$vulnerable = $false

if (-not (Test-Path $webappsPath)) {
    $RES = "N/A"
    $DESC = "webapps 디렉터리를 찾을 수 없음"
    $DT = "webapps: not found"
} else {
    # 불필요한 기본 애플리케이션 확인
    $unnecessaryApps = @("docs", "examples", "host-manager", "manager")
    $foundApps = @()

    foreach ($app in $unnecessaryApps) {
        $appPath = "$webappsPath\$app"
        if (Test-Path $appPath) {
            $foundApps += $app
            $vulnerable = $true
        }
    }

    if ($foundApps.Count -gt 0) {
        $dtList += "[불필요한 기본 애플리케이션]"
        foreach ($app in $foundApps) {
            $dtList += "- $webappsPath\$app"
        }
    } else {
        $dtList += "기본 애플리케이션(docs, examples): 제거됨"
    }

    # 불필요한 파일 확인
    $unnecessaryFiles = Get-ChildItem $webappsPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -match "\.(bak|backup|old|tmp)$" -or
        $_.Name -match "^(BUILDING|RELEASE-NOTES|README)\.txt$"
    } | Select-Object -First 10

    if ($unnecessaryFiles) {
        $dtList += ""
        $dtList += "[불필요한 파일]"
        foreach ($file in $unnecessaryFiles) {
            $dtList += "- $($file.FullName)"
            $vulnerable = $true
        }
    }

    if ($vulnerable) {
        $RES = "N"
        $DESC = "불필요한 파일 또는 디렉터리가 존재함"
    } else {
        $RES = "Y"
        $DESC = "불필요한 파일 및 디렉터리가 없음"
    }
    $DT = $dtList -join "`n"
}

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

# server.xml에서 maxPostSize 확인
if (Test-Path $SERVER_XML) {
    $content = Get-Content $SERVER_XML -Raw -ErrorAction SilentlyContinue
    $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

    $maxPostSizeMatch = [regex]::Match($contentWithoutComments, 'maxPostSize\s*=\s*"([^"]+)"')
    if ($maxPostSizeMatch.Success) {
        $maxPostSize = $maxPostSizeMatch.Groups[1].Value
        $dtList += "maxPostSize: $maxPostSize bytes"
        $hasLimit = $true
    } else {
        $dtList += "maxPostSize: 미설정 (기본값: 2MB)"
    }
}

# web.xml에서 multipart-config 확인
if (Test-Path $WEB_XML) {
    $content = Get-Content $WEB_XML -Raw -ErrorAction SilentlyContinue
    $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

    if ($contentWithoutComments -match '<multipart-config>') {
        $dtList += "multipart-config: 설정됨"
        $hasLimit = $true

        $maxFileSizeMatch = [regex]::Match($contentWithoutComments, '<max-file-size>([^<]+)</max-file-size>')
        if ($maxFileSizeMatch.Success) {
            $dtList += "  max-file-size: $($maxFileSizeMatch.Groups[1].Value)"
        }

        $maxRequestSizeMatch = [regex]::Match($contentWithoutComments, '<max-request-size>([^<]+)</max-request-size>')
        if ($maxRequestSizeMatch.Success) {
            $dtList += "  max-request-size: $($maxRequestSizeMatch.Groups[1].Value)"
        }
    } else {
        $dtList += "multipart-config: 미설정"
    }
}

if ($hasLimit) {
    $RES = "Y"
    $DESC = "파일 업로드 용량 제한이 설정됨"
} else {
    $RES = "N"
    $DESC = "파일 업로드 용량 제한이 설정되지 않음"
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

# Tomcat 서비스 확인
$tomcatServices = Get-Service -Name "Tomcat*" -ErrorAction SilentlyContinue

if ($tomcatServices) {
    $dtList += "[Tomcat 서비스]"
    foreach ($svc in $tomcatServices) {
        $svcName = $svc.Name

        # 서비스 실행 계정 확인
        try {
            $svcConfig = Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
            $startName = $svcConfig.StartName

            $dtList += "서비스: $svcName"
            $dtList += "  실행 계정: $startName"

            # LocalSystem으로 실행되면 취약
            if ($startName -eq "LocalSystem" -or $startName -eq "NT AUTHORITY\SYSTEM") {
                $vulnerable = $true
                $dtList += "  -> 경고: SYSTEM 권한으로 실행 중"
            }
        } catch {
            $dtList += "서비스: $svcName - 정보 확인 실패"
        }
    }
} else {
    # 프로세스로 확인
    $tomcatProcess = Get-Process -Name "java" -ErrorAction SilentlyContinue | Where-Object {
        $_.MainWindowTitle -match "Tomcat" -or $_.Path -match "tomcat"
    }

    if ($tomcatProcess) {
        $dtList += "[Tomcat 프로세스]"
        foreach ($proc in $tomcatProcess) {
            try {
                $owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue).GetOwner()
                $ownerName = "$($owner.Domain)\$($owner.User)"
                $dtList += "PID: $($proc.Id) - 계정: $ownerName"

                if ($ownerName -match "SYSTEM|Administrator") {
                    $vulnerable = $true
                }
            } catch { }
        }
    } else {
        $dtList += "실행 중인 Tomcat 프로세스/서비스를 찾을 수 없음"
        $RES = "M"
        $DESC = "Tomcat 프로세스 확인 불가, 수동 확인 필요"
    }
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "Tomcat이 관리자/SYSTEM 권한으로 실행 중"
    } else {
        $RES = "Y"
        $DESC = "Tomcat이 제한된 권한으로 실행 중"
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

if (-not (Test-Path $SERVER_XML)) {
    $RES = "N/A"
    $DESC = "server.xml 파일을 찾을 수 없음"
    $DT = "SERVER_XML: not found"
} else {
    try {
        $content = Get-Content $SERVER_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        $dtList = @()
        $hasProxy = $false

        # proxyName, proxyPort 설정 확인
        $proxyNameMatch = [regex]::Match($contentWithoutComments, 'proxyName\s*=\s*"([^"]+)"')
        $proxyPortMatch = [regex]::Match($contentWithoutComments, 'proxyPort\s*=\s*"([^"]+)"')

        if ($proxyNameMatch.Success) {
            $dtList += "proxyName: $($proxyNameMatch.Groups[1].Value)"
            $hasProxy = $true
        } else {
            $dtList += "proxyName: 미설정"
        }

        if ($proxyPortMatch.Success) {
            $dtList += "proxyPort: $($proxyPortMatch.Groups[1].Value)"
            $hasProxy = $true
        } else {
            $dtList += "proxyPort: 미설정"
        }

        if ($hasProxy) {
            $RES = "M"
            $DESC = "프록시 설정 확인 필요 (리버스 프록시 사용 시 양호)"
        } else {
            $RES = "Y"
            $DESC = "프록시 설정이 없음"
        }
        $DT = $dtList -join "`n"
    } catch {
        $RES = "M"
        $DESC = "server.xml 파일 분석 실패"
        $DT = "오류: $_"
    }
}

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

if (-not (Test-Path $SERVER_XML)) {
    $RES = "N/A"
    $DESC = "server.xml 파일을 찾을 수 없음"
    $DT = "SERVER_XML: not found"
} else {
    try {
        $content = Get-Content $SERVER_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        $dtList = @()

        # docBase, appBase 설정 확인
        $docBaseMatch = [regex]::Match($contentWithoutComments, 'docBase\s*=\s*"([^"]+)"')
        $appBaseMatch = [regex]::Match($contentWithoutComments, 'appBase\s*=\s*"([^"]+)"')

        $docBase = if ($docBaseMatch.Success) { $docBaseMatch.Groups[1].Value } else { "미설정" }
        $appBase = if ($appBaseMatch.Success) { $appBaseMatch.Groups[1].Value } else { "webapps" }

        $dtList += "docBase: $docBase"
        $dtList += "appBase: $appBase"

        # 기본 경로 사용 여부 확인
        if ($appBase -eq "webapps" -and $docBase -eq "미설정") {
            $RES = "M"
            $DESC = "기본 appBase 경로 사용 중 (수동 확인 필요)"
        } else {
            $RES = "Y"
            $DESC = "웹 서비스 경로가 설정됨"
        }
        $DT = $dtList -join "`n"
    } catch {
        $RES = "M"
        $DESC = "server.xml 파일 분석 실패"
        $DT = "오류: $_"
    }
}

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

# server.xml에서 allowLinking 확인
if (Test-Path $SERVER_XML) {
    $content = Get-Content $SERVER_XML -Raw -ErrorAction SilentlyContinue
    $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

    if ($contentWithoutComments -match 'allowLinking\s*=\s*"true"') {
        $vulnerable = $true
        $dtList += "server.xml: allowLinking=true (취약)"
    } else {
        $dtList += "server.xml: allowLinking 미설정 또는 false (양호)"
    }
}

# context.xml에서 allowLinking 확인
if (Test-Path $CONTEXT_XML) {
    $content = Get-Content $CONTEXT_XML -Raw -ErrorAction SilentlyContinue
    $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

    if ($contentWithoutComments -match 'allowLinking\s*=\s*"true"') {
        $vulnerable = $true
        $dtList += "context.xml: allowLinking=true (취약)"
    } else {
        $dtList += "context.xml: allowLinking 미설정 또는 false (양호)"
    }
}

# webapps 디렉터리에서 심볼릭 링크 확인
$webappsPath = "$CATALINA_HOME\webapps"
if (Test-Path $webappsPath) {
    $symlinks = Get-ChildItem $webappsPath -ErrorAction SilentlyContinue | Where-Object {
        $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint
    }
    if ($symlinks) {
        $vulnerable = $true
        $dtList += ""
        $dtList += "[심볼릭 링크 발견]"
        foreach ($link in $symlinks) {
            $dtList += "- $($link.FullName)"
        }
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "심볼릭 링크 사용이 허용되어 있음"
} else {
    $RES = "Y"
    $DESC = "심볼릭 링크 사용이 제한되어 있음"
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

# 설정 파일들의 권한 확인
$configFiles = @($SERVER_XML, $WEB_XML, $TOMCAT_USERS_XML, $CONTEXT_XML)

foreach ($configFile in $configFiles) {
    if (Test-Path $configFile) {
        try {
            $acl = Get-Acl $configFile -ErrorAction SilentlyContinue
            $fileName = Split-Path $configFile -Leaf

            $hasIssue = $false
            foreach ($access in $acl.Access) {
                $identity = $access.IdentityReference.Value
                if ($identity -match "Everyone|BUILTIN\\Users" -and $access.FileSystemRights -match "Read|Write|FullControl") {
                    $hasIssue = $true
                    $vulnerable = $true
                }
            }

            if ($hasIssue) {
                $dtList += "$fileName : 일반 사용자 접근 가능 (취약)"
            } else {
                $dtList += "$fileName : 권한 적절 (양호)"
            }
        } catch {
            $dtList += "$(Split-Path $configFile -Leaf): 권한 확인 실패"
        }
    }
}

if ($vulnerable) {
    $RES = "N"
    $DESC = "설정 파일에 불필요한 권한이 존재"
} else {
    $RES = "Y"
    $DESC = "설정 파일 접근 권한이 적절히 설정됨"
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

$webappsPath = "$CATALINA_HOME\webapps"
$dtList = @()
$vulnerable = $false

if (-not (Test-Path $webappsPath)) {
    $RES = "N/A"
    $DESC = "webapps 디렉터리를 찾을 수 없음"
    $DT = "webapps: not found"
} else {
    try {
        $acl = Get-Acl $webappsPath -ErrorAction SilentlyContinue
        $dtList += "경로: $webappsPath"
        $dtList += "소유자: $($acl.Owner)"
        $dtList += ""
        $dtList += "[권한 목록]"

        foreach ($access in $acl.Access) {
            $identity = $access.IdentityReference.Value
            $rights = $access.FileSystemRights
            $dtList += "$identity : $rights"

            # Everyone에 쓰기/수정/삭제 권한이 있으면 취약
            if ($identity -match "Everyone" -and $rights -match "Write|FullControl|Modify|Delete") {
                $vulnerable = $true
            }
        }

        if ($vulnerable) {
            $RES = "N"
            $DESC = "webapps 디렉터리에 불필요한 권한이 존재"
        } else {
            $RES = "Y"
            $DESC = "webapps 디렉터리 권한이 적절히 설정됨"
        }
    } catch {
        $RES = "M"
        $DESC = "디렉터리 권한 확인 실패"
        $DT = "오류: $_"
    }
    $DT = $dtList -join "`n"
}

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

if (-not (Test-Path $WEB_XML)) {
    $RES = "N/A"
    $DESC = "web.xml 파일을 찾을 수 없음"
    $DT = "WEB_XML: not found"
} else {
    try {
        $content = Get-Content $WEB_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        $dtList = @()
        $vulnerable = $false

        # invoker 서블릿 확인 (보안 취약)
        if ($contentWithoutComments -match 'invoker') {
            $dtList += "invoker 서블릿: 발견 (취약)"
            $vulnerable = $true
        } else {
            $dtList += "invoker 서블릿: 없음 (양호)"
        }

        # SSI 서블릿 확인
        if ($contentWithoutComments -match 'SSIServlet|SSIFilter') {
            $dtList += "SSI 서블릿/필터: 발견 (취약)"
            $vulnerable = $true
        } else {
            $dtList += "SSI 서블릿/필터: 없음 (양호)"
        }

        # CGI 서블릿 확인
        if ($contentWithoutComments -match 'CGIServlet') {
            $dtList += "CGI 서블릿: 발견"
            $vulnerable = $true
        } else {
            $dtList += "CGI 서블릿: 없음 (양호)"
        }

        if ($vulnerable) {
            $RES = "N"
            $DESC = "불필요한 스크립트 매핑이 존재함"
        } else {
            $RES = "Y"
            $DESC = "불필요한 스크립트 매핑이 없음"
        }
        $DT = $dtList -join "`n"
    } catch {
        $RES = "M"
        $DESC = "web.xml 파일 분석 실패"
        $DT = "오류: $_"
    }
}

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

if (-not (Test-Path $SERVER_XML)) {
    $RES = "N/A"
    $DESC = "server.xml 파일을 찾을 수 없음"
    $DT = "SERVER_XML: not found"
} else {
    try {
        $content = Get-Content $SERVER_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        $dtList = @()
        $isSecure = $true

        # Connector의 server 속성 확인
        $serverAttrMatch = [regex]::Match($contentWithoutComments, '<Connector[^>]*server\s*=\s*"([^"]+)"')
        if ($serverAttrMatch.Success) {
            $dtList += "Connector server 속성: $($serverAttrMatch.Groups[1].Value)"
        } else {
            $dtList += "Connector server 속성: 미설정 (기본 정보 노출)"
            $isSecure = $false
        }

        # ErrorReportValve의 showServerInfo 확인
        if ($contentWithoutComments -match 'showServerInfo\s*=\s*"false"') {
            $dtList += "showServerInfo: false (양호)"
        } else {
            $dtList += "showServerInfo: 미설정 또는 true (기본 정보 노출)"
            $isSecure = $false
        }

        # showReport 확인
        if ($contentWithoutComments -match 'showReport\s*=\s*"false"') {
            $dtList += "showReport: false (양호)"
        } else {
            $dtList += "showReport: 미설정 또는 true"
        }

        if ($isSecure) {
            $RES = "Y"
            $DESC = "서버 헤더 정보 노출이 제한됨"
        } else {
            $RES = "N"
            $DESC = "서버 헤더 정보가 노출될 수 있음"
        }
        $DT = $dtList -join "`n"
    } catch {
        $RES = "M"
        $DESC = "server.xml 파일 분석 실패"
        $DT = "오류: $_"
    }
}

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

if (-not (Test-Path $SERVER_XML)) {
    $RES = "N/A"
    $DESC = "server.xml 파일을 찾을 수 없음"
    $DT = "SERVER_XML: not found"
} else {
    try {
        $content = Get-Content $SERVER_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        # Context path 설정 확인
        $contexts = [regex]::Matches($contentWithoutComments, '<Context[^>]*path\s*=\s*"([^"]*)"[^>]*>')

        if ($contexts.Count -eq 0) {
            $RES = "Y"
            $DESC = "추가 가상 디렉터리 설정이 없음"
            $DT = "Context path: 미설정"
        } else {
            $RES = "M"
            $DESC = "가상 디렉터리 설정 확인 필요"
            $dtList = @("Context 설정:")
            foreach ($ctx in $contexts) {
                $dtList += "- path: $($ctx.Groups[1].Value)"
            }
            $DT = $dtList -join "`n"
        }
    } catch {
        $RES = "M"
        $DESC = "server.xml 파일 분석 실패"
        $DT = "오류: $_"
    }
}

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
    $DESC = "Tomcat은 기본적으로 WebDAV를 지원하지 않음 (별도 설정 필요)"
    $DT = @"
Tomcat은 Apache HTTP Server와 달리 WebDAV 모듈이 기본 내장되어 있지 않습니다.
별도의 WebDAV 서블릿 구성이 필요하므로 해당 항목은 N/A 처리합니다.
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

if (-not (Test-Path $WEB_XML)) {
    $RES = "N/A"
    $DESC = "web.xml 파일을 찾을 수 없음"
    $DT = "WEB_XML: not found"
} else {
    try {
        $content = Get-Content $WEB_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        $dtList = @()
        $vulnerable = $false

        # SSI 서블릿 확인
        if ($contentWithoutComments -match 'SSIServlet') {
            $dtList += "SSIServlet: 발견 (취약)"
            $vulnerable = $true
        } else {
            $dtList += "SSIServlet: 없음 (양호)"
        }

        # SSI 필터 확인
        if ($contentWithoutComments -match 'SSIFilter') {
            $dtList += "SSIFilter: 발견 (취약)"
            $vulnerable = $true
        } else {
            $dtList += "SSIFilter: 없음 (양호)"
        }

        # .shtml 매핑 확인
        if ($contentWithoutComments -match '\.shtml') {
            $dtList += ".shtml 매핑: 발견 (취약)"
            $vulnerable = $true
        } else {
            $dtList += ".shtml 매핑: 없음 (양호)"
        }

        if ($vulnerable) {
            $RES = "N"
            $DESC = "SSI가 활성화되어 있음"
        } else {
            $RES = "Y"
            $DESC = "SSI가 비활성화되어 있음"
        }
        $DT = $dtList -join "`n"
    } catch {
        $RES = "M"
        $DESC = "web.xml 파일 분석 실패"
        $DT = "오류: $_"
    }
}

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
    $DESC = "Tomcat 앞단에 웹서버(Apache/Nginx)를 두고 SSL 처리 권장"
    $DT = @"
일반적으로 Tomcat 앞단에 Apache HTTP Server 또는 Nginx를 리버스 프록시로 배치하여
SSL/TLS 처리를 위임하는 구성을 권장합니다.

직접 Tomcat에서 SSL을 처리할 경우 server.xml의 Connector에서 설정하며,
이 경우 별도 점검이 필요합니다.
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
    $DESC = "Tomcat 앞단 웹서버에서 HTTPS 리디렉션 처리 권장"
    $DT = @"
HTTP에서 HTTPS로의 리디렉션은 일반적으로 앞단 웹서버(Apache/Nginx)에서 처리합니다.

Tomcat 단독 구성 시 web.xml의 security-constraint를 통해 HTTPS 강제 가능하나,
앞단 웹서버 사용 환경에서는 해당 웹서버 설정을 점검해야 합니다.
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

if (-not (Test-Path $WEB_XML)) {
    $RES = "N/A"
    $DESC = "web.xml 파일을 찾을 수 없음"
    $DT = "WEB_XML: not found"
} else {
    try {
        $content = Get-Content $WEB_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        # error-page 설정 확인
        $errorPages = [regex]::Matches($contentWithoutComments, '<error-page>[\s\S]*?</error-page>')

        if ($errorPages.Count -gt 0) {
            $RES = "Y"
            $DESC = "에러 페이지가 설정되어 있음"
            $dtList = @("error-page 설정:")

            foreach ($ep in $errorPages) {
                $errorCodeMatch = [regex]::Match($ep.Value, '<error-code>([^<]+)</error-code>')
                $exceptionMatch = [regex]::Match($ep.Value, '<exception-type>([^<]+)</exception-type>')
                $locationMatch = [regex]::Match($ep.Value, '<location>([^<]+)</location>')

                if ($errorCodeMatch.Success) {
                    $dtList += "- 오류코드 $($errorCodeMatch.Groups[1].Value) -> $($locationMatch.Groups[1].Value)"
                } elseif ($exceptionMatch.Success) {
                    $dtList += "- 예외타입 $($exceptionMatch.Groups[1].Value)"
                }
            }
            $DT = $dtList -join "`n"
        } else {
            $RES = "N"
            $DESC = "에러 페이지가 설정되지 않음"
            $DT = "error-page: 미설정 (기본 에러 페이지 사용)"
        }
    } catch {
        $RES = "M"
        $DESC = "web.xml 파일 분석 실패"
        $DT = "오류: $_"
    }
}

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

if (-not (Test-Path $SERVER_XML)) {
    $RES = "N/A"
    $DESC = "server.xml 파일을 찾을 수 없음"
    $DT = "SERVER_XML: not found"
} else {
    try {
        $content = Get-Content $SERVER_XML -Raw -ErrorAction SilentlyContinue
        $contentWithoutComments = $content -replace '<!--[\s\S]*?-->', ''

        # LDAP Realm 확인
        if ($contentWithoutComments -match 'JNDIRealm|LDAPRealm') {
            $dtList = @("LDAP Realm: 사용 중")

            # digest 속성 확인
            $digestMatch = [regex]::Match($contentWithoutComments, 'digest\s*=\s*"([^"]+)"')

            if ($digestMatch.Success) {
                $digest = $digestMatch.Groups[1].Value
                $dtList += "digest: $digest"

                if ($digest -match "^(SHA-256|SHA-384|SHA-512|SHA256|SHA384|SHA512)$") {
                    $RES = "Y"
                    $DESC = "안전한 다이제스트 알고리즘 사용 중"
                } elseif ($digest -match "^(MD5|SHA-1|SHA1|SSHA)$") {
                    $RES = "N"
                    $DESC = "취약한 다이제스트 알고리즘 사용 중"
                    $dtList += "-> SHA-256 이상 권장"
                } else {
                    $RES = "M"
                    $DESC = "다이제스트 알고리즘 수동 확인 필요"
                }
            } else {
                $RES = "N"
                $DESC = "LDAP 비밀번호 다이제스트 알고리즘이 설정되지 않음"
                $dtList += "digest: 미설정 (평문 전송 가능)"
            }
            $DT = $dtList -join "`n"
        } else {
            $RES = "N/A"
            $DESC = "LDAP Realm이 설정되지 않음"
            $DT = "LDAP Realm: 미사용"
        }
    } catch {
        $RES = "M"
        $DESC = "server.xml 파일 분석 실패"
        $DT = "오류: $_"
    }
}

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

$webappsPath = "$CATALINA_HOME\webapps"
$dtList = @()
$foundUpload = $false

# 일반적인 업로드 디렉터리 확인
$uploadDirs = @("uploads", "upload", "files", "attachments", "media")

foreach ($dir in $uploadDirs) {
    $uploadPath = "$webappsPath\ROOT\$dir"
    if (Test-Path $uploadPath) {
        $foundUpload = $true
        $dtList += "업로드 디렉터리: $uploadPath"

        try {
            $acl = Get-Acl $uploadPath -ErrorAction SilentlyContinue
            foreach ($access in $acl.Access | Where-Object { $_.IdentityReference -match "Everyone|Users" }) {
                $dtList += "  - $($access.IdentityReference): $($access.FileSystemRights)"
            }
        } catch { }
    }
}

if (-not $foundUpload) {
    $RES = "M"
    $DESC = "업로드 디렉터리를 찾을 수 없음 (수동 확인 필요)"
    $dtList += "일반적인 경로에 업로드 디렉터리 없음"
    $dtList += ""
    $dtList += "[수동 확인 필요]"
    $dtList += "- 업로드 디렉터리가 웹 루트 외부에 위치하는지 확인"
    $dtList += "- 업로드 디렉터리에 스크립트 실행 권한이 없는지 확인"
} else {
    $RES = "M"
    $DESC = "업로드 디렉터리 발견, 권한 수동 확인 필요"
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
$DESC = "Tomcat 버전 및 패치 수준 수동 확인 필요"

$dtList = @()
$dtList += "[Tomcat 버전 정보]"
$dtList += "CATALINA_HOME: $CATALINA_HOME"

if ($TOMCAT_VERSION) {
    $dtList += "버전: $TOMCAT_VERSION"
} else {
    $dtList += "버전: 확인 불가"
}

$dtList += ""
$dtList += "[수동 확인 필요]"
$dtList += "- Apache Tomcat 최신 보안 패치 확인"
$dtList += "- 참고: https://tomcat.apache.org/"
$dtList += "- CVE 취약점 확인: https://tomcat.apache.org/security.html"

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

$logsPath = "$CATALINA_HOME\logs"
$dtList = @()
$vulnerable = $false

if (-not (Test-Path $logsPath)) {
    $RES = "M"
    $DESC = "로그 디렉터리를 찾을 수 없음"
    $DT = "logs: not found"
} else {
    try {
        $acl = Get-Acl $logsPath -ErrorAction SilentlyContinue
        $dtList += "경로: $logsPath"
        $dtList += "소유자: $($acl.Owner)"
        $dtList += ""
        $dtList += "[권한 목록]"

        foreach ($access in $acl.Access) {
            $identity = $access.IdentityReference.Value
            $rights = $access.FileSystemRights
            $dtList += "$identity : $rights"

            # Everyone에 읽기/쓰기 권한이 있으면 취약
            if ($identity -match "Everyone" -and $rights -match "Read|Write|FullControl") {
                $vulnerable = $true
            }
        }

        # 로그 파일 목록
        $logFiles = Get-ChildItem $logsPath -Filter "*.log" -ErrorAction SilentlyContinue | Select-Object -First 5
        if ($logFiles) {
            $dtList += ""
            $dtList += "[로그 파일]"
            foreach ($file in $logFiles) {
                $dtList += "- $($file.Name) ($([math]::Round($file.Length/1KB, 2)) KB)"
            }
        }

        if ($vulnerable) {
            $RES = "N"
            $DESC = "로그 디렉터리에 불필요한 권한이 존재"
        } else {
            $RES = "Y"
            $DESC = "로그 디렉터리 권한이 적절히 설정됨"
        }
    } catch {
        $RES = "M"
        $DESC = "로그 디렉터리 권한 확인 실패"
        $dtList += "오류: $_"
    }
    $DT = $dtList -join "`n"
}

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

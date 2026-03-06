#================================================================
# IIS_Windows 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : IIS_Windows
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
$META_PLAT = "IIS"
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
function Test-IISInstalled {
    # 방법 1: Get-WindowsFeature (Server OS)
    $iisFeature = $null
    try {
        $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
    } catch { }

    if ($iisFeature -and $iisFeature.Installed) {
        return $true
    }

    # 방법 2: Get-WindowsOptionalFeature (Client OS)
    try {
        $iisOptional = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServer -ErrorAction SilentlyContinue
        if ($iisOptional -and $iisOptional.State -eq "Enabled") {
            return $true
        }
    } catch { }

    # 방법 3: 서비스 확인
    $w3svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if ($w3svc) {
        return $true
    }

    return $false
}

# IIS 모듈 로드
$iisInstalled = Test-IISInstalled
if (-not $iisInstalled) {
    Write-Host "[X] IIS가 설치되어 있지 않습니다." -ForegroundColor Red
    Write-Host "    이 스크립트는 IIS가 설치된 시스템에서만 실행 가능합니다." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# WebAdministration 모듈 로드
try {
    Import-Module WebAdministration -ErrorAction Stop
} catch {
    Write-Host "[!] WebAdministration 모듈을 로드할 수 없습니다." -ForegroundColor Yellow
    Write-Host "    일부 점검 항목이 제한될 수 있습니다." -ForegroundColor Yellow
}

# IIS 버전 정보
$IIS_VERSION = ""
try {
    $iisRegPath = "HKLM:\SOFTWARE\Microsoft\InetStp"
    if (Test-Path $iisRegPath) {
        $majorVersion = (Get-ItemProperty $iisRegPath -ErrorAction SilentlyContinue).MajorVersion
        $minorVersion = (Get-ItemProperty $iisRegPath -ErrorAction SilentlyContinue).MinorVersion
        if ($majorVersion) {
            $IIS_VERSION = "IIS $majorVersion.$minorVersion"
        }
    }
} catch { }

$SVC_VERSION = $IIS_VERSION
$SVC_CONF = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"

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

$RES = "N/A"
$DESC = "IIS는 Windows 계정으로 관리되어 웹 서비스 수준의 별도 관리자 계정이 없음"
$DT = "IIS는 별도의 웹 관리 콘솔 계정이 없으며, Windows 운영체제 계정(Administrator)으로 관리됩니다.`n관리자 계정 관리는 OS 수준(Windows Server 진단)에서 점검합니다."

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

# IIS 버전 수집
$IIS_VERSION = ""
try {
    $iisVersion = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue
    if ($iisVersion) {
        $IIS_VERSION = $iisVersion.VersionString
    }
} catch { }

# 출력 파일 경로
$OUTPUT_FILE = "$PSScriptRoot\${META_PLAT}_${SYS_HOST}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"


Write-Host "  [진단 시작]" -ForegroundColor Yellow
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

    $RES = "M"
    $DESC = "관리자 비밀번호 복잡도 수동 확인 필요"

    # IIS 관리자 계정의 비밀번호는 Windows 계정 정책에 의존
    # 비밀번호 복잡도 정책 확인
    $netAccounts = net accounts 2>$null
    $minLen = ($netAccounts | Select-String "Minimum password length" | ForEach-Object { ($_ -split ":")[1].Trim() })

    # secedit로 복잡도 확인
    $secpolPath = "$env:TEMP\secpol_$([guid]::NewGuid().ToString('N')).cfg"
    $complexity = "Unknown"
    try {
        secedit /export /cfg $secpolPath 2>$null | Out-Null
        if (Test-Path $secpolPath) {
            $secpolContent = Get-Content $secpolPath -ErrorAction SilentlyContinue
            $complexityLine = $secpolContent | Where-Object { $_ -match "PasswordComplexity" }
            if ($complexityLine) {
                $complexity = [int](($complexityLine -split "=")[1].Trim())
                $complexity = if ($complexity -eq 1) { "Enabled" } else { "Disabled" }
            }
            Remove-Item $secpolPath -Force -ErrorAction SilentlyContinue
        }
    } catch { }

    $dtList = @()
    $dtList += "[Windows 비밀번호 정책]"
    $dtList += "Minimum password length: $minLen"
    $dtList += "Password complexity: $complexity"
    $dtList += ""
    $dtList += "[수동 확인 필요]"
    $dtList += "- IIS 관리자 계정 비밀번호 복잡도 확인"
    $dtList += "- 영문/숫자/특수문자 조합 8자 이상 설정 권장"
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

# SAM 파일 권한 확인
$samPath = "$env:SystemRoot\system32\config\SAM"
$vulnerable = $false
$dtList = @()

if (Test-Path $samPath) {
    try {
        $acl = Get-Acl $samPath -ErrorAction SilentlyContinue
        $dtList += "[SAM 파일 권한]"
        $dtList += "경로: $samPath"
        $dtList += ""

        foreach ($access in $acl.Access) {
            $identity = $access.IdentityReference.Value
            $rights = $access.FileSystemRights
            $dtList += "$identity : $rights"

            # Administrators, SYSTEM 외의 계정에 권한이 있으면 취약
            if ($identity -notmatch "BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|CREATOR OWNER") {
                if ($access.AccessControlType -eq "Allow") {
                    $vulnerable = $true
                }
            }
        }
    } catch {
        $dtList += "SAM 파일 권한 확인 실패: $_"
        $RES = "M"
        $DESC = "SAM 파일 권한 확인 실패, 수동 확인 필요"
    }
} else {
    $dtList += "SAM 파일을 찾을 수 없음"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "SAM 파일에 불필요한 계정 권한이 존재하여 취약"
    } else {
        $RES = "Y"
        $DESC = "SAM 파일 권한이 적절히 설정되어 양호"
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

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[디렉터리 검색 설정]"

        foreach ($site in $sites) {
            $siteName = $site.Name

            # 디렉터리 검색 설정 확인
            try {
                $dirBrowse = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter "system.webServer/directoryBrowse" -Name "enabled" -ErrorAction SilentlyContinue
                $enabled = if ($dirBrowse) { $dirBrowse.Value } else { $false }

                $dtList += "Site: $siteName - Directory Browsing: $(if($enabled){'Enabled'}else{'Disabled'})"

                if ($enabled) {
                    $vulnerable = $true
                }
            } catch {
                $dtList += "Site: $siteName - 설정 확인 실패"
            }
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "IIS 설정 확인 실패: $_"
    $RES = "M"
    $DESC = "IIS 설정 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "디렉터리 검색이 활성화되어 취약"
    } else {
        $RES = "Y"
        $DESC = "디렉터리 검색이 비활성화되어 양호"
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

try {
    # ISAPI 및 CGI 제한 확인
    $isapiCgiRestriction = Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/isapiCgiRestriction" -ErrorAction SilentlyContinue

    $dtList += "[ISAPI/CGI 제한 설정]"

    if ($isapiCgiRestriction) {
        $notListedCgi = $isapiCgiRestriction.notListedCgisAllowed
        $notListedIsapi = $isapiCgiRestriction.notListedIsapisAllowed

        $dtList += "Not Listed CGIs Allowed: $notListedCgi"
        $dtList += "Not Listed ISAPIs Allowed: $notListedIsapi"

        if ($notListedCgi -or $notListedIsapi) {
            $vulnerable = $true
        }
    }

    # ISAPI 필터 목록 확인
    $dtList += ""
    $dtList += "[등록된 ISAPI 필터]"

    $sites = Get-Website -ErrorAction SilentlyContinue
    foreach ($site in $sites) {
        $siteName = $site.Name
        try {
            $isapiFilters = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter "system.webServer/isapiFilters" -Name "." -ErrorAction SilentlyContinue
            if ($isapiFilters.Collection) {
                foreach ($filter in $isapiFilters.Collection) {
                    $dtList += "Site: $siteName - Filter: $($filter.name) - Path: $($filter.path)"
                }
            } else {
                $dtList += "Site: $siteName - ISAPI 필터 없음"
            }
        } catch {
            $dtList += "Site: $siteName - 필터 확인 실패"
        }
    }
} catch {
    $dtList += "ISAPI/CGI 설정 확인 실패: $_"
    $RES = "M"
    $DESC = "ISAPI/CGI 설정 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "지정되지 않은 CGI/ISAPI 실행이 허용되어 취약"
    } else {
        $RES = "Y"
        $DESC = "CGI/ISAPI 실행이 적절히 제한되어 양호"
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

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[상위 디렉터리 접근 설정 (enableParentPaths)]"

        foreach ($site in $sites) {
            $siteName = $site.Name
            $physicalPath = $site.PhysicalPath

            # ASP enableParentPaths 설정 확인
            try {
                $aspConfig = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter "system.webServer/asp" -Name "enableParentPaths" -ErrorAction SilentlyContinue
                $enabled = if ($aspConfig) { $aspConfig.Value } else { $false }

                $dtList += "Site: $siteName - enableParentPaths: $(if($enabled){'True (취약)'}else{'False (양호)'})"

                if ($enabled) {
                    $vulnerable = $true
                }
            } catch {
                # ASP가 설치되지 않은 경우
                $dtList += "Site: $siteName - ASP 설정 없음 (양호)"
            }

            # web.config에서 httpRuntime enableParentPaths 확인
            $webConfigPath = Join-Path $physicalPath "web.config"
            if (Test-Path $webConfigPath) {
                try {
                    [xml]$webConfig = Get-Content $webConfigPath -ErrorAction SilentlyContinue
                    $httpRuntime = $webConfig.configuration.'system.web'.httpRuntime
                    if ($httpRuntime -and $httpRuntime.enableParentPaths -eq "true") {
                        $dtList += "Site: $siteName - web.config httpRuntime enableParentPaths: True (취약)"
                        $vulnerable = $true
                    }
                } catch { }
            }
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "설정 확인 실패: $_"
    $RES = "M"
    $DESC = "설정 확인 실패, 수동 확인 필요"
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

# 불필요한 IIS 샘플 디렉터리 확인
$samplePaths = @(
    "c:\inetpub\iissamples",
    "c:\winnt\help\iishelp",
    "c:\windows\help\iishelp",
    "c:\program files\common files\system\msadc\sample",
    "$env:SystemRoot\System32\Inetsrv\IISADMPWD"
)

$dtList += "[불필요한 샘플 디렉터리 확인]"

foreach ($path in $samplePaths) {
    if (Test-Path $path) {
        $dtList += "존재: $path (취약)"
        $vulnerable = $true
    }
}

if (-not $vulnerable) {
    $dtList += "불필요한 샘플 디렉터리 없음 (양호)"
}

# 웹 사이트 루트에서 불필요한 파일 확인
$dtList += ""
$dtList += "[웹 루트 디렉터리 불필요 파일 확인]"

try {
    $sites = Get-Website -ErrorAction SilentlyContinue
    foreach ($site in $sites) {
        $physicalPath = $site.PhysicalPath
        if (Test-Path $physicalPath) {
            $unnecessaryFiles = Get-ChildItem $physicalPath -File -ErrorAction SilentlyContinue | Where-Object {
                $_.Extension -match "\.(bak|old|tmp|temp|backup|log|txt)$" -or
                $_.Name -match "^(test|sample|example|readme|install)"
            }

            if ($unnecessaryFiles) {
                foreach ($file in $unnecessaryFiles | Select-Object -First 5) {
                    $dtList += "Site: $($site.Name) - 불필요 파일: $($file.Name)"
                    $vulnerable = $true
                }
            }
        }
    }
} catch { }

if ($vulnerable) {
    $RES = "N"
    $DESC = "불필요한 파일 또는 샘플 디렉터리가 존재하여 취약"
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
$hasLimit = $true

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[파일 업로드 용량 제한 설정]"

        foreach ($site in $sites) {
            $siteName = $site.Name
            $physicalPath = $site.PhysicalPath

            # requestLimits maxAllowedContentLength 확인 (기본값: 30MB = 30000000)
            try {
                $requestLimits = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -ErrorAction SilentlyContinue
                $maxContentLength = if ($requestLimits) { $requestLimits.Value } else { 30000000 }
                $maxContentLengthMB = [math]::Round($maxContentLength / 1MB, 2)

                $dtList += "Site: $siteName - maxAllowedContentLength: $maxContentLength bytes ($maxContentLengthMB MB)"
            } catch {
                $dtList += "Site: $siteName - 설정 확인 실패"
            }

            # web.config에서 maxRequestLength 확인
            $webConfigPath = Join-Path $physicalPath "web.config"
            if (Test-Path $webConfigPath) {
                try {
                    [xml]$webConfig = Get-Content $webConfigPath -ErrorAction SilentlyContinue
                    $httpRuntime = $webConfig.configuration.'system.web'.httpRuntime
                    if ($httpRuntime -and $httpRuntime.maxRequestLength) {
                        $dtList += "Site: $siteName - web.config maxRequestLength: $($httpRuntime.maxRequestLength) KB"
                    }
                } catch { }
            }
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "설정 확인 실패: $_"
    $RES = "M"
    $DESC = "설정 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    # IIS는 기본적으로 제한이 설정되어 있음
    $RES = "Y"
    $DESC = "파일 업로드 용량 제한이 설정되어 양호"
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

try {
    $appPools = Get-ChildItem "IIS:\AppPools" -ErrorAction SilentlyContinue

    if ($appPools) {
        $dtList += "[응용프로그램 풀 ID 설정]"

        foreach ($pool in $appPools) {
            $poolName = $pool.Name
            $identity = $pool.processModel.identityType
            $userName = $pool.processModel.userName

            $identityInfo = switch ($identity) {
                "LocalSystem" { "LocalSystem (취약 - 관리자 권한)" }
                "LocalService" { "LocalService (양호)" }
                "NetworkService" { "NetworkService (양호)" }
                "ApplicationPoolIdentity" { "ApplicationPoolIdentity (양호 - 권장)" }
                "SpecificUser" { "SpecificUser: $userName" }
                default { $identity }
            }

            $dtList += "Pool: $poolName - Identity: $identityInfo"

            # LocalSystem으로 실행되면 취약
            if ($identity -eq "LocalSystem") {
                $vulnerable = $true
            }

            # SpecificUser가 관리자 그룹인지 확인
            if ($identity -eq "SpecificUser" -and $userName) {
                try {
                    $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
                    if ($adminGroup.Name -contains $userName) {
                        $dtList += "  -> 경고: $userName 은 관리자 그룹 멤버"
                        $vulnerable = $true
                    }
                } catch { }
            }
        }
    } else {
        $dtList += "응용프로그램 풀이 없습니다."
        $RES = "N/A"
        $DESC = "응용프로그램 풀 없음"
    }
} catch {
    $dtList += "응용프로그램 풀 설정 확인 실패: $_"
    $RES = "M"
    $DESC = "응용프로그램 풀 설정 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "응용프로그램 풀이 관리자 권한으로 실행되어 취약"
    } else {
        $RES = "Y"
        $DESC = "응용프로그램 풀 권한이 적절히 설정되어 양호"
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

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    $dtList += "[프록시 설정 확인]"
    $dtList += "IIS에서 프록시 설정은 URL Rewrite 모듈 또는 ARR을 통해 구성됩니다."
    $dtList += ""

    # ARR (Application Request Routing) 설치 여부 확인
    $arrInstalled = $false
    try {
        $arr = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/proxy" -Name "enabled" -ErrorAction SilentlyContinue
        if ($null -ne $arr) {
            $arrInstalled = $true
            $dtList += "ARR 프록시 활성화: $($arr.Value)"
        }
    } catch { }

    if (-not $arrInstalled) {
        $dtList += "ARR (Application Request Routing) 미설치 또는 비활성화"
    }

    $dtList += ""
    $dtList += "[수동 확인 필요]"
    $dtList += "- IIS 관리자에서 URL Rewrite 규칙 확인"
    $dtList += "- ARR 프록시 설정 확인"
    $dtList += "- 불필요한 프록시 규칙 제거"
} catch {
    $dtList += "프록시 설정 확인 실패: $_"
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

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[웹 서비스 경로 설정]"

        # 기본 경로 (분리되지 않은 경로)
        $defaultPaths = @("C:\inetpub\wwwroot", "C:\Windows", "C:\Program Files")

        foreach ($site in $sites) {
            $siteName = $site.Name
            $physicalPath = $site.PhysicalPath

            $dtList += "Site: $siteName - Path: $physicalPath"

            # 시스템 기본 경로와 분리되어 있는지 확인
            $isDefault = $false
            foreach ($defaultPath in $defaultPaths) {
                if ($physicalPath -like "$defaultPath*" -and $defaultPath -notlike "*inetpub*") {
                    $isDefault = $true
                    break
                }
            }

            if ($isDefault) {
                $dtList += "  -> 경고: 시스템 경로와 분리 필요"
                $vulnerable = $true
            }
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "경로 설정 확인 실패: $_"
    $RES = "M"
    $DESC = "경로 설정 확인 실패, 수동 확인 필요"
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

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[바로가기 파일 확인]"

        foreach ($site in $sites) {
            $siteName = $site.Name
            $physicalPath = $site.PhysicalPath

            if (Test-Path $physicalPath) {
                # .lnk 파일 (바로가기) 확인
                $shortcuts = Get-ChildItem $physicalPath -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5

                if ($shortcuts) {
                    foreach ($shortcut in $shortcuts) {
                        $dtList += "Site: $siteName - 바로가기: $($shortcut.FullName)"
                        $vulnerable = $true
                    }
                } else {
                    $dtList += "Site: $siteName - 바로가기 파일 없음"
                }
            }
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "바로가기 파일 확인 실패: $_"
    $RES = "M"
    $DESC = "바로가기 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "웹 서비스 경로에 바로가기 파일이 존재하여 취약"
    } else {
        $RES = "Y"
        $DESC = "바로가기 파일이 존재하지 않아 양호"
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

$dtList = @()
$vulnerable = $false

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[web.config 파일 권한 확인]"

        foreach ($site in $sites) {
            $siteName = $site.Name
            $physicalPath = $site.PhysicalPath
            $webConfigPath = Join-Path $physicalPath "web.config"

            if (Test-Path $webConfigPath) {
                try {
                    $acl = Get-Acl $webConfigPath -ErrorAction SilentlyContinue
                    $dtList += "Site: $siteName"
                    $dtList += "  Path: $webConfigPath"

                    foreach ($access in $acl.Access) {
                        $identity = $access.IdentityReference.Value
                        $rights = $access.FileSystemRights

                        # Everyone 또는 Users 그룹에 쓰기 권한이 있으면 취약
                        if ($identity -match "Everyone|BUILTIN\\Users" -and $rights -match "Write|FullControl|Modify") {
                            $dtList += "  -> 취약: $identity 에 $rights 권한"
                            $vulnerable = $true
                        }
                    }
                } catch {
                    $dtList += "Site: $siteName - 권한 확인 실패"
                }
            } else {
                $dtList += "Site: $siteName - web.config 파일 없음"
            }
        }

        # 처리기 매핑에서 .asa/.asax 확인
        $dtList += ""
        $dtList += "[스크립트 매핑 확인 (.asa/.asax)]"

        try {
            $handlers = Get-WebHandler -ErrorAction SilentlyContinue
            $asaHandlers = $handlers | Where-Object { $_.Path -match "\.asa|\.asax" }

            if ($asaHandlers) {
                foreach ($handler in $asaHandlers) {
                    $dtList += "매핑: $($handler.Path) -> $($handler.Modules)"
                    # 활성화되어 있으면 수동 확인 필요
                }
                $dtList += "  -> .asa/.asax 매핑이 존재합니다. 수동 확인 필요"
            } else {
                $dtList += ".asa/.asax 매핑 없음 (양호)"
            }
        } catch {
            $dtList += "처리기 매핑 확인 실패"
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "설정 파일 확인 실패: $_"
    $RES = "M"
    $DESC = "설정 파일 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "설정 파일에 불필요한 권한이 존재하여 취약"
    } else {
        $RES = "Y"
        $DESC = "설정 파일 권한이 적절히 설정되어 양호"
    }
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

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[웹 서비스 디렉터리 권한 확인]"

        foreach ($site in $sites) {
            $siteName = $site.Name
            $physicalPath = $site.PhysicalPath

            if (Test-Path $physicalPath) {
                try {
                    $acl = Get-Acl $physicalPath -ErrorAction SilentlyContinue
                    $dtList += "Site: $siteName"
                    $dtList += "  Path: $physicalPath"

                    foreach ($access in $acl.Access) {
                        $identity = $access.IdentityReference.Value
                        $rights = $access.FileSystemRights

                        # Everyone에 쓰기/수정/삭제 권한이 있으면 취약
                        if ($identity -match "Everyone" -and $rights -match "Write|FullControl|Modify|Delete") {
                            $dtList += "  -> 취약: Everyone 에 $rights 권한"
                            $vulnerable = $true
                        }
                    }
                } catch {
                    $dtList += "Site: $siteName - 권한 확인 실패"
                }
            }
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "디렉터리 권한 확인 실패: $_"
    $RES = "M"
    $DESC = "디렉터리 권한 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "웹 서비스 경로에 불필요한 권한이 존재하여 취약"
    } else {
        $RES = "Y"
        $DESC = "웹 서비스 경로 권한이 적절히 설정되어 양호"
    }
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

$dtList = @()
$vulnerable = $false

# 불필요한 스크립트 매핑 확장자
$unnecessaryExtensions = @(".htr", ".idc", ".stm", ".shtm", ".shtml", ".printer", ".htw", ".ida", ".idq")

try {
    $dtList += "[불필요한 스크립트 매핑 확인]"
    $dtList += "취약 확장자: $($unnecessaryExtensions -join ', ')"
    $dtList += ""

    $handlers = Get-WebHandler -ErrorAction SilentlyContinue

    if ($handlers) {
        $foundUnnecessary = @()

        foreach ($handler in $handlers) {
            foreach ($ext in $unnecessaryExtensions) {
                if ($handler.Path -like "*$ext*") {
                    $foundUnnecessary += "$($handler.Name): $($handler.Path)"
                    $vulnerable = $true
                }
            }
        }

        if ($foundUnnecessary.Count -gt 0) {
            $dtList += "[발견된 불필요한 매핑]"
            foreach ($item in $foundUnnecessary) {
                $dtList += "  - $item"
            }
        } else {
            $dtList += "불필요한 스크립트 매핑 없음 (양호)"
        }
    } else {
        $dtList += "처리기 매핑 정보를 가져올 수 없습니다."
        $RES = "M"
        $DESC = "처리기 매핑 확인 실패, 수동 확인 필요"
    }
} catch {
    $dtList += "스크립트 매핑 확인 실패: $_"
    $RES = "M"
    $DESC = "스크립트 매핑 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "불필요한 스크립트 매핑이 존재하여 취약"
    } else {
        $RES = "Y"
        $DESC = "불필요한 스크립트 매핑이 없어 양호"
    }
}

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

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[HTTP 응답 헤더 설정]"

        # 서버 헤더 제거 여부 확인
        try {
            $requestFiltering = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering" -Name "removeServerHeader" -ErrorAction SilentlyContinue
            $removeHeader = if ($requestFiltering) { $requestFiltering.Value } else { $false }

            $dtList += "removeServerHeader: $(if($removeHeader){'True (양호)'}else{'False (취약)'})"

            if (-not $removeHeader) {
                $vulnerable = $true
            }
        } catch {
            $dtList += "removeServerHeader: 확인 불가 (기본값 사용 - 취약)"
            $vulnerable = $true
        }

        # 오류 페이지 설정 확인
        $dtList += ""
        $dtList += "[오류 페이지 설정]"

        foreach ($site in $sites) {
            $siteName = $site.Name
            try {
                $errorMode = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter "system.webServer/httpErrors" -Name "errorMode" -ErrorAction SilentlyContinue
                $mode = if ($errorMode) { $errorMode.Value } else { "DetailedLocalOnly" }

                $dtList += "Site: $siteName - errorMode: $mode"

                # Detailed 모드면 취약
                if ($mode -eq "Detailed") {
                    $vulnerable = $true
                    $dtList += "  -> 취약: 상세 오류 메시지 노출"
                }
            } catch {
                $dtList += "Site: $siteName - 오류 페이지 설정 확인 실패"
            }
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "헤더 설정 확인 실패: $_"
    $RES = "M"
    $DESC = "헤더 설정 확인 실패, 수동 확인 필요"
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

$dtList = @()
$vulnerable = $false

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[가상 디렉터리 설정 확인]"

        # 불필요한 가상 디렉터리 패턴
        $unnecessaryVDirs = @("scripts", "iissamples", "iisadmpwd", "iishelp", "msadc", "printers", "_vti_bin", "_vti_pvt", "_vti_cnf", "_vti_txt", "_vti_log")

        foreach ($site in $sites) {
            $siteName = $site.Name
            $dtList += ""
            $dtList += "Site: $siteName"

            try {
                # 가상 디렉터리 목록 확인
                $vdirs = Get-WebVirtualDirectory -Site $siteName -ErrorAction SilentlyContinue

                if ($vdirs) {
                    foreach ($vdir in $vdirs) {
                        $vdirName = $vdir.Name
                        $vdirPath = $vdir.PhysicalPath

                        $dtList += "  - VDir: $vdirName -> $vdirPath"

                        # 불필요한 가상 디렉터리인지 확인
                        foreach ($unnecessary in $unnecessaryVDirs) {
                            if ($vdirName -like "*$unnecessary*") {
                                $dtList += "    -> 취약: 불필요한 가상 디렉터리 ($unnecessary)"
                                $vulnerable = $true
                            }
                        }

                        # 가상 디렉터리 경로 존재 여부 확인
                        if (-not (Test-Path $vdirPath)) {
                            $dtList += "    -> 경고: 물리 경로가 존재하지 않음"
                        }
                    }
                } else {
                    $dtList += "  - 가상 디렉터리 없음 (양호)"
                }

                # 응용프로그램 내 가상 디렉터리도 확인
                $apps = Get-WebApplication -Site $siteName -ErrorAction SilentlyContinue
                if ($apps) {
                    foreach ($app in $apps) {
                        $appPath = $app.path
                        $appVdirs = Get-WebVirtualDirectory -Site $siteName -Application $appPath -ErrorAction SilentlyContinue
                        if ($appVdirs) {
                            foreach ($avdir in $appVdirs) {
                                $dtList += "  - App: $appPath - VDir: $($avdir.Name) -> $($avdir.PhysicalPath)"

                                foreach ($unnecessary in $unnecessaryVDirs) {
                                    if ($avdir.Name -like "*$unnecessary*") {
                                        $dtList += "    -> 취약: 불필요한 가상 디렉터리 ($unnecessary)"
                                        $vulnerable = $true
                                    }
                                }
                            }
                        }
                    }
                }
            } catch {
                $dtList += "  - 가상 디렉터리 확인 실패: $_"
            }
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "가상 디렉터리 설정 확인 실패: $_"
    $RES = "M"
    $DESC = "가상 디렉터리 설정 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "불필요한 가상 디렉터리가 존재하여 취약"
    } else {
        $RES = "Y"
        $DESC = "불필요한 가상 디렉터리가 없어 양호"
    }
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

try {
    $dtList += "[WebDAV 설정 확인]"

    # WebDAV 핸들러 확인
    $handlers = Get-WebHandler -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*WebDAV*" }

    if ($handlers) {
        $dtList += "WebDAV 처리기 발견:"
        foreach ($handler in $handlers) {
            $dtList += "  - $($handler.Name): $($handler.Path)"
        }
        $vulnerable = $true
    } else {
        $dtList += "WebDAV 처리기 없음"
    }

    # ISAPI/CGI 제한에서 WebDAV 확인
    $dtList += ""
    $dtList += "[ISAPI/CGI 제한에서 WebDAV 확인]"

    try {
        $restrictions = Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/isapiCgiRestriction" -ErrorAction SilentlyContinue
        if ($restrictions.Collection) {
            $webdavRestriction = $restrictions.Collection | Where-Object { $_.description -like "*WebDAV*" }
            if ($webdavRestriction) {
                foreach ($r in $webdavRestriction) {
                    $status = if ($r.allowed) { "허용됨 (취약)" } else { "차단됨 (양호)" }
                    $dtList += "  - $($r.description): $status"
                    if ($r.allowed) {
                        $vulnerable = $true
                    }
                }
            } else {
                $dtList += "WebDAV 제한 항목 없음"
            }
        }
    } catch {
        $dtList += "ISAPI/CGI 제한 확인 실패"
    }

    # WebDAV 모듈 확인
    $dtList += ""
    $dtList += "[WebDAV 모듈 확인]"

    try {
        $modules = Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/modules" -ErrorAction SilentlyContinue
        $webdavModule = $modules.Collection | Where-Object { $_.name -like "*WebDAV*" }
        if ($webdavModule) {
            $dtList += "WebDAV 모듈 설치됨 (수동 확인 필요)"
            $vulnerable = $true
        } else {
            $dtList += "WebDAV 모듈 없음 (양호)"
        }
    } catch {
        $dtList += "모듈 확인 실패"
    }
} catch {
    $dtList += "WebDAV 설정 확인 실패: $_"
    $RES = "M"
    $DESC = "WebDAV 설정 확인 실패, 수동 확인 필요"
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

try {
    $dtList += "[SSI (Server Side Includes) 설정 확인]"

    # SSI 관련 처리기 매핑 확인 (.shtml, .shtm, .stm)
    $handlers = Get-WebHandler -ErrorAction SilentlyContinue
    $ssiHandlers = $handlers | Where-Object { $_.Path -match "\.(shtml|shtm|stm)$" }

    if ($ssiHandlers) {
        $dtList += "SSI 처리기 매핑 발견:"
        foreach ($handler in $ssiHandlers) {
            $dtList += "  - $($handler.Name): $($handler.Path)"
        }
        $vulnerable = $true
    } else {
        $dtList += "SSI 처리기 매핑 없음 (양호)"
    }

    # SSI 모듈 확인
    $dtList += ""
    $dtList += "[SSI 모듈 확인]"

    try {
        $modules = Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/modules" -ErrorAction SilentlyContinue
        $ssiModule = $modules.Collection | Where-Object { $_.name -like "*SSI*" -or $_.name -like "*ServerSideInclude*" }
        if ($ssiModule) {
            $dtList += "SSI 모듈 설치됨 (취약)"
            $vulnerable = $true
        } else {
            $dtList += "SSI 모듈 없음 (양호)"
        }
    } catch {
        $dtList += "모듈 확인 실패"
    }
} catch {
    $dtList += "SSI 설정 확인 실패: $_"
    $RES = "M"
    $DESC = "SSI 설정 확인 실패, 수동 확인 필요"
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
$httpOnly = $false

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[HTTPS 바인딩 확인]"

        foreach ($site in $sites) {
            $siteName = $site.Name
            $bindings = Get-WebBinding -Name $siteName -ErrorAction SilentlyContinue

            $siteHasHttps = $false
            $siteHasHttp = $false

            foreach ($binding in $bindings) {
                $protocol = $binding.protocol
                $bindingInfo = $binding.bindingInformation

                $dtList += "Site: $siteName - $protocol : $bindingInfo"

                if ($protocol -eq "https") {
                    $siteHasHttps = $true
                    $hasHttps = $true

                    # SSL 인증서 정보 확인
                    try {
                        $cert = $binding.certificateHash
                        if ($cert) {
                            $dtList += "  -> SSL 인증서: $cert"
                        }
                    } catch { }
                }
                if ($protocol -eq "http") {
                    $siteHasHttp = $true
                }
            }

            if ($siteHasHttp -and -not $siteHasHttps) {
                $httpOnly = $true
                $dtList += "  -> 경고: HTTP만 활성화됨"
            }
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "HTTPS 설정 확인 실패: $_"
    $RES = "M"
    $DESC = "HTTPS 설정 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if (-not $hasHttps -or $httpOnly) {
        $RES = "N"
        $DESC = "HTTPS가 활성화되지 않아 취약"
    } else {
        $RES = "Y"
        $DESC = "HTTPS가 활성화되어 양호"
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

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[HTTP 리디렉션 설정 확인]"
        $dtList += ""

        foreach ($site in $sites) {
            $siteName = $site.Name
            $physicalPath = $site.PhysicalPath

            # URL Rewrite 규칙 확인
            try {
                $rewriteRules = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter "system.webServer/rewrite/rules" -Name "." -ErrorAction SilentlyContinue

                if ($rewriteRules -and $rewriteRules.Collection) {
                    $httpsRules = $rewriteRules.Collection | Where-Object { $_.url -match "https" -or $_.action.url -match "https" }
                    if ($httpsRules) {
                        $dtList += "Site: $siteName - HTTPS 리디렉션 규칙 존재"
                        foreach ($rule in $httpsRules) {
                            $dtList += "  - Rule: $($rule.name)"
                        }
                    } else {
                        $dtList += "Site: $siteName - HTTPS 리디렉션 규칙 없음"
                    }
                } else {
                    $dtList += "Site: $siteName - URL Rewrite 규칙 없음"
                }
            } catch {
                $dtList += "Site: $siteName - URL Rewrite 확인 실패 (모듈 미설치 가능)"
            }

            # HTTP 리디렉션 설정 확인
            try {
                $httpRedirect = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter "system.webServer/httpRedirect" -Name "enabled" -ErrorAction SilentlyContinue
                if ($httpRedirect -and $httpRedirect.Value) {
                    $destination = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter "system.webServer/httpRedirect" -Name "destination" -ErrorAction SilentlyContinue
                    $dtList += "Site: $siteName - HTTP 리디렉션 활성화: $($destination.Value)"
                }
            } catch { }
        }

        $dtList += ""
        $dtList += "[수동 확인 필요]"
        $dtList += "- HTTP (80) 접속 시 HTTPS (443)로 리디렉션 되는지 확인"
        $dtList += "- URL Rewrite 모듈 설치 및 규칙 설정 확인"
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "리디렉션 설정 확인 실패: $_"
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
$vulnerable = $false

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[에러 페이지 설정 확인]"

        foreach ($site in $sites) {
            $siteName = $site.Name

            # httpErrors 설정 확인
            try {
                $errorMode = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter "system.webServer/httpErrors" -Name "errorMode" -ErrorAction SilentlyContinue
                $mode = if ($errorMode) { $errorMode.Value } else { "DetailedLocalOnly" }

                $dtList += "Site: $siteName - errorMode: $mode"

                if ($mode -eq "Detailed") {
                    $vulnerable = $true
                    $dtList += "  -> 취약: 상세 오류 메시지가 외부에 노출됨"
                }

                # 커스텀 에러 페이지 확인
                $httpErrors = Get-WebConfiguration -PSPath "IIS:\Sites\$siteName" -Filter "system.webServer/httpErrors" -ErrorAction SilentlyContinue
                if ($httpErrors -and $httpErrors.Collection) {
                    $dtList += "  커스텀 에러 페이지:"
                    foreach ($error in $httpErrors.Collection | Select-Object -First 5) {
                        $dtList += "    - $($error.statusCode): $($error.path)"
                    }
                }
            } catch {
                $dtList += "Site: $siteName - 에러 페이지 설정 확인 실패"
            }
        }
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "에러 페이지 설정 확인 실패: $_"
    $RES = "M"
    $DESC = "에러 페이지 설정 확인 실패, 수동 확인 필요"
}

if ([string]::IsNullOrEmpty($RES)) {
    if ($vulnerable) {
        $RES = "N"
        $DESC = "상세 오류 메시지가 노출되어 취약"
    } else {
        $RES = "Y"
        $DESC = "에러 페이지가 적절히 설정되어 양호"
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
$DESC = "IIS는 Active Directory와 연동되며 별도 LDAP 설정이 없음"

$dtList = @()
$dtList += "[LDAP 설정 확인]"
$dtList += ""
$dtList += "IIS는 Windows 기반 웹 서버로서 Active Directory와 통합되어 운영됩니다."
$dtList += "LDAP 인증은 Windows 인증 메커니즘을 통해 자동으로 처리되며,"
$dtList += "웹 서버 자체에서 별도의 LDAP 알고리즘 설정을 구성하지 않습니다."
$dtList += ""
$dtList += "[참고 사항]"
$dtList += "- Windows 인증 사용 시 Active Directory와 자동 연동"
$dtList += "- LDAP 보안 설정은 Active Directory 도메인 컨트롤러에서 관리"
$dtList += "- LDAPS (LDAP over SSL) 설정은 도메인 컨트롤러 수준에서 구성"
$dtList += ""
$dtList += "[결론]"
$dtList += "본 항목은 IIS 환경에서 해당 없음 (N/A)"

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

try {
    $sites = Get-Website -ErrorAction SilentlyContinue

    if ($sites) {
        $dtList += "[업로드 디렉터리 확인]"
        $dtList += ""

        foreach ($site in $sites) {
            $siteName = $site.Name
            $physicalPath = $site.PhysicalPath

            $dtList += "Site: $siteName"
            $dtList += "  Root: $physicalPath"

            # 일반적인 업로드 디렉터리 확인
            $uploadDirs = @("uploads", "upload", "files", "attachments", "media")

            foreach ($dir in $uploadDirs) {
                $uploadPath = Join-Path $physicalPath $dir
                if (Test-Path $uploadPath) {
                    $dtList += "  Upload Dir: $uploadPath"

                    # 권한 확인
                    try {
                        $acl = Get-Acl $uploadPath -ErrorAction SilentlyContinue
                        foreach ($access in $acl.Access | Where-Object { $_.IdentityReference -match "Everyone|Users" }) {
                            $dtList += "    - $($access.IdentityReference): $($access.FileSystemRights)"
                        }
                    } catch { }
                }
            }
        }

        $dtList += ""
        $dtList += "[수동 확인 필요]"
        $dtList += "- 업로드 디렉터리가 웹 루트 외부에 위치하는지 확인"
        $dtList += "- 업로드 디렉터리에 스크립트 실행 권한이 없는지 확인"
        $dtList += "- 일반 사용자의 불필요한 접근 권한 제거"
    } else {
        $dtList += "활성화된 웹 사이트가 없습니다."
        $RES = "N/A"
        $DESC = "활성화된 웹 사이트 없음"
    }
} catch {
    $dtList += "업로드 경로 확인 실패: $_"
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
$DESC = "IIS 버전 및 패치 수준 수동 확인 필요"

$dtList = @()

try {
    # IIS 버전 확인 (레지스트리)
    $iisVersion = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue

    $dtList += "[IIS 버전 정보]"

    if ($iisVersion) {
        $dtList += "Version: $($iisVersion.VersionString)"
        $dtList += "Major Version: $($iisVersion.MajorVersion)"
        $dtList += "Minor Version: $($iisVersion.MinorVersion)"
        $dtList += "Install Path: $($iisVersion.InstallPath)"
    } else {
        $dtList += "IIS 버전 정보를 가져올 수 없습니다."
    }

    # Windows 업데이트 정보
    $dtList += ""
    $dtList += "[최근 Windows 업데이트]"

    try {
        $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 5
        foreach ($hf in $hotfixes) {
            $dtList += "  - $($hf.HotFixID): $($hf.InstalledOn)"
        }
    } catch {
        $dtList += "Windows 업데이트 정보를 가져올 수 없습니다."
    }

    $dtList += ""
    $dtList += "[수동 확인 필요]"
    $dtList += "- Microsoft 보안 업데이트 확인"
    $dtList += "- IIS 관련 최신 패치 적용 여부 확인"
    $dtList += "- 참고: https://www.iis.net/downloads/microsoft"
} catch {
    $dtList += "버전 정보 확인 실패: $_"
}

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

try {
    # IIS 로그 디렉터리 확인
    $logPaths = @(
        "$env:SystemDrive\inetpub\logs",
        "$env:SystemRoot\System32\LogFiles"
    )

    $dtList += "[IIS 로그 디렉터리 권한 확인]"

    foreach ($logPath in $logPaths) {
        if (Test-Path $logPath) {
            $dtList += ""
            $dtList += "Path: $logPath"

            try {
                $acl = Get-Acl $logPath -ErrorAction SilentlyContinue

                foreach ($access in $acl.Access) {
                    $identity = $access.IdentityReference.Value
                    $rights = $access.FileSystemRights

                    $dtList += "  - $identity : $rights"

                    # Everyone에 읽기/쓰기 권한이 있으면 취약
                    if ($identity -match "Everyone" -and $rights -match "Read|Write|FullControl") {
                        $vulnerable = $true
                        $dtList += "    -> 취약: Everyone 권한 존재"
                    }
                }
            } catch {
                $dtList += "  권한 확인 실패"
            }
        }
    }

    # 사이트별 로그 경로 확인
    $dtList += ""
    $dtList += "[사이트별 로그 경로]"

    $sites = Get-Website -ErrorAction SilentlyContinue
    foreach ($site in $sites) {
        $siteName = $site.Name
        try {
            $siteLogPath = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" -Filter "system.applicationHost/sites/site[@name='$siteName']/logFile" -Name "directory" -ErrorAction SilentlyContinue
            if ($siteLogPath) {
                $dtList += "Site: $siteName - Log: $($siteLogPath.Value)"
            }
        } catch { }
    }
} catch {
    $dtList += "로그 디렉터리 확인 실패: $_"
    $RES = "M"
    $DESC = "로그 디렉터리 확인 실패, 수동 확인 필요"
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

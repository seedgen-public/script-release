# Windows 스크립트 가이드

> Windows 보안 진단 스크립트 가이드

**상위 문서**: [USG.md](../USG.md)

---

## 1. 개요

Windows 플랫폼용 보안 진단 스크립트 작성 가이드.
- Windows Server: 진단 코드 접두사 `W-XX`
- Windows PC: 진단 코드 접두사 `PC-XX`

---

## 2. 시스템 정보 수집

### 2.1 meta (메타데이터)

| 노드 | 설명 | PowerShell | 예시 |
|------|------|------------|------|
| `date` | 생성일시 | `Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"` | `2025-06-18T15:10:22+09:00` |
| `ver` | 스크립트 버전 | 상수 | `1.0` |
| `plat` | 플랫폼 | 고정값 | `Windows` |
| `std` | 진단 기준 | 상수 | `KISA` |

```powershell
$META_DATE = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$META_VER = "1.0"
$META_PLAT = "Windows"
$META_TYPE = "Server"  # 또는 "PC"
$META_STD = "KISA"
```

### 2.2 sys (시스템 정보)

| 노드 | 설명 | PowerShell | 예시 |
|------|------|------------|------|
| `host` | 호스트명 | `$env:COMPUTERNAME` | `DC-SERVER-01` |
| `dom` | 도메인 | `(Get-CimInstance Win32_ComputerSystem).Domain` | `seedgen.local` |
| `os > n` | OS 원본 | `(Get-CimInstance Win32_OperatingSystem).Caption` | `Microsoft Windows Server 2019 Datacenter` |
| `os > fn` | OS 정제 | 파싱 | `Windows Server 2019` |
| `kn` | 빌드 버전 | `$os.Version` | `10.0.17763` |
| `arch` | 아키텍처 | `$os.OSArchitecture` | `64-bit` |
| `ip` | 대표 IP | `Get-NetIPAddress` | `192.168.10.10` |

```powershell
$SYS_HOST = $env:COMPUTERNAME
$SYS_DOM = (Get-CimInstance Win32_ComputerSystem).Domain
$SYS_OS_NAME = (Get-CimInstance Win32_OperatingSystem).Caption
$SYS_OS_FN = $SYS_OS_NAME -replace "Microsoft ", "" -replace " Datacenter| Standard| Enterprise", ""
$os = Get-CimInstance Win32_OperatingSystem
$SYS_KN = $os.Version
$SYS_ARCH = $os.OSArchitecture
$SYS_IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" } | Select-Object -First 1).IPAddress
$SYS_NET_ALL = (Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)" }) -join "`n"
```

---

## 3. 권한 체크 및 셀프 에스컬레이션

### 3.1 기본 권한 체크

```powershell
#Requires -RunAsAdministrator
```

### 3.2 셀프 에스컬레이션 (권장)

```powershell
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    $arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`""
    Start-Process PowerShell -ArgumentList $arguments -Verb RunAs -Wait
    exit
}
```

---

## 4. 인코딩 설정

```powershell
chcp 65001 | Out-Null
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
```

**주의:**
- 스크립트 파일 (.ps1): UTF-8 **with BOM** (PowerShell 5.x 호환)
- 결과 XML 파일: UTF-8 without BOM

---

## 5. 출력 함수

```powershell
function Output-Checkpoint {
    param($CODE, $CAT, $NAME, $IMP, $RES, $DESC, $DT)

    @"
        <cp>
            <code>$CODE</code>
            <cat>$CAT</cat>
            <n>$NAME</n>
            <imp>$IMP</imp>
            <res>$RES</res>
            <desc>$DESC</desc>
            <dt><![CDATA[$DT]]></dt>
        </cp>
"@
}
```

---

## 6. 진단 함수 예시

```powershell
function Check-W01 {
    $CODE = "W-01"
    $CAT = "계정관리"
    $NAME = "계정 잠금 임계값 설정"
    $IMP = "상"
    $RES = ""
    $DESC = ""
    $DT = ""

    # 진단 로직
    $policy = net accounts | Select-String "Lockout threshold"
    $threshold = if ($policy) { ($policy -split ":")[1].Trim() } else { "N/A" }
    
    if ($threshold -match "^\d+$" -and [int]$threshold -le 5 -and [int]$threshold -gt 0) {
        $RES = "Y"
        $DESC = "계정 잠금 임계값이 적절히 설정됨"
        $DT = "잠금 임계값: ${threshold}회"
    } else {
        $RES = "N"
        $DESC = "계정 잠금 임계값 미설정 또는 미흡"
        $DT = "잠금 임계값: ${threshold}"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $RES $DESC $DT
}
```

---

## 7. SecurityCenter2 활용 (백신/보안 상태)

### 7.1 백신 제품 조회

```powershell
$avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
```

### 7.2 productState 비트마스킹

```powershell
$productState = $av.productState
$scannerStatus = ($productState -shr 12) -band 0xF
# 0x0 = OFF, 0x1 = ON
```

### 7.3 주의사항

> ⚠️ **productState 비트마스킹은 오탐률이 높음**

**권장 접근법:**
1. **Windows Defender**: 전용 cmdlet 사용
   ```powershell
   $mpStatus = Get-MpComputerStatus
   $realTimeOn = $mpStatus.RealTimeProtectionEnabled
   ```
2. **3rd Party 백신**: productState + 수동 확인 병행

---

## 8. 스크립트 템플릿

```powershell
#================================================================
# HEADER
#================================================================
<#
.SYNOPSIS
    Windows 보안 진단 스크립트
.VERSION
    1.0
#>

#================================================================
# [!] 프로젝트 설정
#================================================================
$META_STD = "KISA"

#================================================================
# 관리자 권한 자동 승격
#================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`""
    Start-Process PowerShell -ArgumentList $arguments -Verb RunAs -Wait
    exit
}

#================================================================
# INIT
#================================================================
chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$META_VER = "1.0"
$META_PLAT = "Windows"
$META_TYPE = "Server"

function Output-Checkpoint {
    param($CODE, $CAT, $NAME, $IMP, $RES, $DESC, $DT)
    @"
        <cp>
            <code>$CODE</code>
            <cat>$CAT</cat>
            <n>$NAME</n>
            <imp>$IMP</imp>
            <res>$RES</res>
            <desc>$DESC</desc>
            <dt><![CDATA[$DT]]></dt>
        </cp>
"@
}

#================================================================
# COLLECT
#================================================================
$META_DATE = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$SYS_HOST = $env:COMPUTERNAME
$SYS_DOM = (Get-CimInstance Win32_ComputerSystem).Domain
$SYS_OS_NAME = (Get-CimInstance Win32_OperatingSystem).Caption
$SYS_OS_FN = $SYS_OS_NAME -replace "Microsoft ", "" -replace " Datacenter| Standard| Enterprise", ""
$os = Get-CimInstance Win32_OperatingSystem
$SYS_KN = $os.Version
$SYS_ARCH = $os.OSArchitecture
$SYS_IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" } | Select-Object -First 1).IPAddress
$SYS_NET_ALL = (Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)" }) -join "`n"

$OUTPUT_FILE = "${META_PLAT}_${SYS_HOST}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"

#================================================================
# OUTPUT + CHECK
#================================================================
$xmlContent = @"
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
"@

# CHECK 함수들 호출
# $xmlContent += Check-W01
# $xmlContent += Check-W02

$xmlContent += @"
    </results>
</seedgen>
"@

$xmlContent | Out-File -FilePath $OUTPUT_FILE -Encoding UTF8

#================================================================
# CLEANUP
#================================================================
Write-Host "[완료] $OUTPUT_FILE"
```

---

## 9. 파일명 규칙

```
{PLATFORM}_{HOSTNAME}_{YYYYMMDD_HHMMSS}.xml
```

예시: `WINDOWS_DC-SERVER-01_20250618_151022.xml`

---

## 10. 참고 문서

- [USG](../USG.md) - 최상위 공통 정책
- [Logic](../Logic.md) - 진단 로직 작성 가이드
- [XML-Spec](../XML-Spec.md) - XML 출력 스펙
- [Scripting](../Scripting.md) - 스크립트 개발 가이드

---

*v2.3 | 2026-02-01 | Seedgen*


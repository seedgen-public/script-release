# 진단 로직 작성 가이드

> check 함수 작성을 위한 상세 가이드

**상위 문서**: [USG.md](./USG.md)

---

## 1. check 함수 기본 구조

### 1.1 함수 템플릿

**Linux (Bash):**
```bash
check_U01() {
    #------------------------------------------
    # 1. 상수 정의
    #------------------------------------------
    local CODE="U-01"
    local CAT="계정관리"
    local NAME="root 원격 접속 제한"
    local IMP="상"
    local RES=""
    local DESC=""
    local DT=""

    #------------------------------------------
    # 2. 값 추출
    #------------------------------------------
    local VALUE=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

    #------------------------------------------
    # 3. 조건 판단 → 결과 결정
    #------------------------------------------
    if [ "$VALUE" == "no" ]; then
        RES="Y"
        DESC="root 원격 접속이 제한되어 있음"
        DT="PermitRootLogin: no"
    else
        RES="N"
        DESC="root 원격 접속이 허용되어 있음"
        DT="PermitRootLogin: ${VALUE:-not set}"
    fi

    #------------------------------------------
    # 4. 결과 출력
    #------------------------------------------
    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$RES" "$DESC" "$DT"
}
```

**Windows (PowerShell):**
```powershell
function Check-W01 {
    #------------------------------------------
    # 1. 상수 정의
    #------------------------------------------
    $CODE = "W-01"
    $CAT = "계정관리"
    $NAME = "계정 잠금 임계값 설정"
    $IMP = "상"
    $RES = ""
    $DESC = ""
    $DT = ""

    #------------------------------------------
    # 2. 값 추출
    #------------------------------------------
    $policy = net accounts | Select-String "Lockout threshold"
    $VALUE = if ($policy) { ($policy -split ":")[1].Trim() } else { "N/A" }

    #------------------------------------------
    # 3. 조건 판단 → 결과 결정
    #------------------------------------------
    if ($VALUE -match "^\d+$" -and [int]$VALUE -le 5 -and [int]$VALUE -gt 0) {
        $RES = "Y"
        $DESC = "계정 잠금 임계값이 적절히 설정됨"
        $DT = "잠금 임계값: ${VALUE}회"
    } else {
        $RES = "N"
        $DESC = "계정 잠금 임계값 미설정 또는 미흡"
        $DT = "잠금 임계값: ${VALUE}"
    }

    #------------------------------------------
    # 4. 결과 출력
    #------------------------------------------
    Output-Checkpoint $CODE $CAT $NAME $IMP $RES $DESC $DT
}
```

### 1.2 작성 순서

```
1. 상수 정의   → CODE, CAT, NAME, IMP 고정값 설정
2. 값 추출    → 시스템에서 현재 설정값 가져오기
3. 조건 판단   → 추출한 값을 기준과 비교하여 RES 결정
4. 증적 작성   → DESC(요약), DT(상세) 작성
5. 결과 출력   → output_checkpoint 호출
```

---

## 2. 값 추출 패턴

### 2.1 설정 파일에서 값 읽기

**Linux:**
```bash
# 기본: grep + awk
VALUE=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')

# 주석 제외
VALUE=$(grep -v "^#" /etc/ssh/sshd_config | grep "PermitRootLogin" | awk '{print $2}')

# 대소문자 무시
VALUE=$(grep -i "^permitrootlogin" /etc/ssh/sshd_config | awk '{print $2}')

# 값이 없을 때 기본값
VALUE=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
VALUE=${VALUE:-"not set"}

# 특정 구분자로 분리
VALUE=$(grep "^minlen" /etc/security/pwquality.conf | cut -d'=' -f2 | tr -d ' ')
```

**Windows (PowerShell):**
```powershell
# 텍스트 파일에서 값 읽기
$VALUE = Get-Content "C:\path\to\config.txt" | Select-String "SettingName" | ForEach-Object { ($_ -split "=")[1].Trim() }

# 정책 명령어 출력 파싱
$policy = net accounts | Select-String "Lockout threshold"
$VALUE = ($policy -split ":")[1].Trim()

# secedit 결과 파싱
secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet
$content = Get-Content "$env:TEMP\secpol.cfg"
$VALUE = ($content | Select-String "LockoutBadCount") -replace ".*=\s*", ""
```

### 2.2 명령어 출력 파싱

**Linux:**
```bash
# 서비스 상태 확인
STATUS=$(systemctl is-active sshd)

# 패키지 설치 여부
INSTALLED=$(rpm -qa | grep -c "telnet-server")

# 프로세스 실행 여부
RUNNING=$(ps aux | grep -v grep | grep -c "httpd")

# 방화벽 상태
FW_STATUS=$(firewall-cmd --state 2>/dev/null)
```

**Windows (PowerShell):**
```powershell
# 서비스 상태
$STATUS = (Get-Service -Name "wuauserv").Status

# 방화벽 상태
$FW = Get-NetFirewallProfile -Name Domain | Select-Object -ExpandProperty Enabled

# 설치된 프로그램
$INSTALLED = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Telnet*" }

# 레지스트리 값
$VALUE = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue
```

### 2.3 파일/디렉토리 속성 확인

**Linux:**
```bash
# 파일 존재 여부
[ -f /etc/shadow ] && EXISTS="Y" || EXISTS="N"

# 파일 권한 (8진수)
PERM=$(stat -c "%a" /etc/passwd)

# 파일 소유자
OWNER=$(stat -c "%U" /etc/passwd)

# 파일 그룹
GROUP=$(stat -c "%G" /etc/passwd)

# 권한 + 소유자 한번에
STAT=$(stat -c "%a %U:%G" /etc/passwd)
```

**Windows (PowerShell):**
```powershell
# 파일 존재 여부
$EXISTS = Test-Path "C:\Windows\System32\config\SAM"

# 파일 ACL
$ACL = Get-Acl "C:\path\to\file"
$OWNER = $ACL.Owner

# 특정 사용자 권한 확인
$ACCESS = $ACL.Access | Where-Object { $_.IdentityReference -like "*Everyone*" }
```

---

## 3. 조건 판단 패턴

### 3.1 숫자 비교

**Linux:**
```bash
# 기본 비교
if [ "$VALUE" -le 5 ]; then
    RES="Y"
fi

# 범위 확인
if [ "$VALUE" -ge 8 ] && [ "$VALUE" -le 90 ]; then
    RES="Y"
fi

# 숫자 여부 확인 후 비교
if [[ "$VALUE" =~ ^[0-9]+$ ]] && [ "$VALUE" -le 5 ]; then
    RES="Y"
fi
```

**Windows (PowerShell):**
```powershell
# 기본 비교
if ([int]$VALUE -le 5) {
    $RES = "Y"
}

# 범위 확인
if ([int]$VALUE -ge 8 -and [int]$VALUE -le 90) {
    $RES = "Y"
}

# 숫자 여부 확인 후 비교
if ($VALUE -match "^\d+$" -and [int]$VALUE -le 5) {
    $RES = "Y"
}
```

### 3.2 문자열 매칭

**Linux:**
```bash
# 정확히 일치
if [ "$VALUE" == "no" ]; then
    RES="Y"
fi

# 대소문자 무시
if [[ "${VALUE,,}" == "disabled" ]]; then
    RES="Y"
fi

# 정규식 매칭
if [[ "$VALUE" =~ ^(no|disabled|off)$ ]]; then
    RES="Y"
fi

# 포함 여부
if [[ "$VALUE" == *"deny"* ]]; then
    RES="Y"
fi
```

**Windows (PowerShell):**
```powershell
# 정확히 일치
if ($VALUE -eq "no") {
    $RES = "Y"
}

# 대소문자 무시
if ($VALUE -ieq "disabled") {
    $RES = "Y"
}

# 정규식 매칭
if ($VALUE -match "^(no|disabled|off)$") {
    $RES = "Y"
}

# 포함 여부
if ($VALUE -like "*deny*") {
    $RES = "Y"
}
```

### 3.3 존재 여부 확인

**Linux:**
```bash
# 파일 존재
if [ -f /etc/ssh/sshd_config ]; then
    # 파일 있음
fi

# 디렉토리 존재
if [ -d /var/log/audit ]; then
    # 디렉토리 있음
fi

# 설정값 존재
if [ -n "$VALUE" ]; then
    # 값 있음 (not empty)
fi

# 서비스 존재
if systemctl list-units --type=service | grep -q "sshd"; then
    # 서비스 있음
fi
```

**Windows (PowerShell):**
```powershell
# 파일/디렉토리 존재
if (Test-Path "C:\path\to\file") {
    # 존재함
}

# 서비스 존재
if (Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue) {
    # 서비스 존재
}

# 레지스트리 키 존재
if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft") {
    # 키 존재
}

# 값이 비어있지 않음
if (-not [string]::IsNullOrEmpty($VALUE)) {
    # 값 있음
}
```

### 3.4 복합 조건 (AND/OR)

**Linux:**
```bash
# AND 조건
if [ "$VALUE1" == "no" ] && [ "$VALUE2" -le 5 ]; then
    RES="Y"
fi

# OR 조건
if [ "$VALUE" == "no" ] || [ "$VALUE" == "disabled" ]; then
    RES="Y"
fi

# 복합
if [ -f "$FILE" ] && [ "$PERM" -le 644 ] && [ "$OWNER" == "root" ]; then
    RES="Y"
fi
```

**Windows (PowerShell):**
```powershell
# AND 조건
if ($VALUE1 -eq "no" -and [int]$VALUE2 -le 5) {
    $RES = "Y"
}

# OR 조건
if ($VALUE -eq "no" -or $VALUE -eq "disabled") {
    $RES = "Y"
}

# 복합
if ((Test-Path $FILE) -and $PERM -le 644 -and $OWNER -eq "BUILTIN\Administrators") {
    $RES = "Y"
}
```

---

## 4. 결과 결정 기준

### 4.1 결과값 정의

| 결과 | 의미 | 판정 조건 |
|------|------|-----------|
| `Y` | 양호 | 보안 기준 충족 |
| `N` | 취약 | 보안 기준 미충족 |
| `N/A` | 해당없음 | 점검 대상이 아님 |
| `M` | 수동확인 | 자동 판단 불가 |

### 4.2 판정 흐름

```
┌─────────────────┐
│  점검 대상 존재?  │
└────────┬────────┘
         │
    ┌────┴────┐
    │ NO      │ YES
    ▼         ▼
  N/A    ┌─────────────┐
         │ 값 추출 성공? │
         └──────┬──────┘
                │
           ┌────┴────┐
           │ NO      │ YES
           ▼         ▼
          M     ┌─────────────┐
                │ 기준 충족?    │
                └──────┬──────┘
                       │
                  ┌────┴────┐
                  │ NO      │ YES
                  ▼         ▼
                  N         Y
```

### 4.3 판정 예시

```bash
# 예시: 파일 권한 검사

# 1. 파일 존재 확인 → 없으면 N/A
if [ ! -f "$TARGET_FILE" ]; then
    RES="N/A"
    DESC="점검 대상 파일이 존재하지 않음"
    DT="파일: $TARGET_FILE (없음)"

# 2. 권한 추출 실패 → M
elif [ -z "$PERM" ]; then
    RES="M"
    DESC="파일 권한 확인 불가"
    DT="파일: $TARGET_FILE (권한 조회 실패)"

# 3. 기준 충족 → Y
elif [ "$PERM" -le 644 ]; then
    RES="Y"
    DESC="파일 권한이 적절히 설정됨"
    DT="파일: $TARGET_FILE, 권한: $PERM"

# 4. 기준 미충족 → N
else
    RES="N"
    DESC="파일 권한이 과도하게 설정됨"
    DT="파일: $TARGET_FILE, 권한: $PERM (644 이하 권장)"
fi
```

---

## 5. 증적(dt) 작성법

### 5.1 기본 원칙

| 원칙 | 설명 |
|------|------|
| 현재값 포함 | 실제 시스템의 설정값 기록 |
| 기준값 포함 | 비교 기준이 무엇인지 명시 (취약 시) |
| 재현 가능 | 나중에 같은 방법으로 확인 가능하도록 |
| 간결하게 | 핵심 정보만 포함 |

### 5.2 작성 패턴

**단일 값:**
```
설정명: 값
```
예시: `PermitRootLogin: no`

**비교가 필요한 경우:**
```
현재 설정: 값 (기준: 조건)
```
예시: `현재 설정: 6자 (기준: 8자 이상)`

**다중 값:**
```
항목1: 값1
항목2: 값2
항목3: 값3
```
예시:
```
deny: 5
unlock_time: 1800
root_unlock_time: 1800
```

**파일 정보:**
```
파일: 경로
소유자: 사용자
권한: 퍼미션
```
예시:
```
파일: /etc/shadow
소유자: root
권한: 400
```

### 5.3 주의사항

```bash
# 민감 정보 마스킹
PASSWORD="s3cr3t123"
DT="패스워드: ********"  # 실제 값 X

# 긴 출력 요약
LONG_OUTPUT=$(some_command)
DT=$(echo "$LONG_OUTPUT" | head -5)  # 앞 5줄만
DT="$DT\n... (이하 생략)"

# 줄바꿈은 \n 사용
DT="항목1: 값1\n항목2: 값2"
```

---

## 6. 에러 핸들링

### 6.1 파일 없음 처리

**Linux:**
```bash
TARGET="/etc/ssh/sshd_config"

if [ ! -f "$TARGET" ]; then
    RES="N/A"
    DESC="SSH 설정 파일이 존재하지 않음"
    DT="파일: $TARGET (없음)"
else
    VALUE=$(grep "^PermitRootLogin" "$TARGET" | awk '{print $2}')
    # 정상 로직...
fi
```

**Windows (PowerShell):**
```powershell
$TARGET = "C:\Windows\System32\config\some.cfg"

if (-not (Test-Path $TARGET)) {
    $RES = "N/A"
    $DESC = "설정 파일이 존재하지 않음"
    $DT = "파일: $TARGET (없음)"
} else {
    $VALUE = Get-Content $TARGET | Select-String "Setting"
    # 정상 로직...
}
```

### 6.2 명령어 실패 처리

**Linux:**
```bash
# 명령어 실행 결과 확인
VALUE=$(some_command 2>/dev/null)
if [ $? -ne 0 ]; then
    RES="M"
    DESC="명령어 실행 실패"
    DT="명령어: some_command (실행 오류)"
fi

# 또는 || 사용
VALUE=$(some_command 2>/dev/null) || {
    RES="M"
    DESC="값 추출 실패"
    DT="명령 실행 중 오류 발생"
}
```

**Windows (PowerShell):**
```powershell
try {
    $VALUE = Some-Command -ErrorAction Stop
} catch {
    $RES = "M"
    $DESC = "명령어 실행 실패"
    $DT = "오류: $($_.Exception.Message)"
}
```

### 6.3 서비스/기능 미설치 처리

**Linux:**
```bash
# 서비스 존재 확인
if ! systemctl list-units --type=service --all | grep -q "sshd"; then
    RES="N/A"
    DESC="SSH 서비스가 설치되지 않음"
    DT="sshd.service: 미설치"
fi

# 패키지 확인
if ! rpm -qa | grep -q "openssh-server"; then
    RES="N/A"
    DESC="OpenSSH 서버가 설치되지 않음"
    DT="openssh-server: 미설치"
fi
```

**Windows (PowerShell):**
```powershell
# 서비스 존재 확인
$SVC = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
if (-not $SVC) {
    $RES = "N/A"
    $DESC = "SSH 서비스가 설치되지 않음"
    $DT = "sshd: 미설치"
}

# 기능 확인
$FEATURE = Get-WindowsFeature -Name "Telnet-Server" -ErrorAction SilentlyContinue
if (-not $FEATURE -or -not $FEATURE.Installed) {
    $RES = "N/A"
    $DESC = "Telnet 서버가 설치되지 않음"
    $DT = "Telnet-Server: 미설치"
}
```

---

## 7. 실전 예시

### 7.1 패스워드 정책 (숫자 비교)

**Linux - 패스워드 최소 길이:**
```bash
check_U_PASS_MINLEN() {
    local CODE="U-02"
    local CAT="계정관리"
    local NAME="패스워드 최소 길이"
    local IMP="상"
    local RES=""
    local DESC=""
    local DT=""

    # 값 추출 (pwquality.conf 또는 login.defs)
    local MINLEN=""
    if [ -f /etc/security/pwquality.conf ]; then
        MINLEN=$(grep "^minlen" /etc/security/pwquality.conf | cut -d'=' -f2 | tr -d ' ')
    fi
    if [ -z "$MINLEN" ] && [ -f /etc/login.defs ]; then
        MINLEN=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}')
    fi

    # 조건 판단
    if [ -z "$MINLEN" ]; then
        RES="N"
        DESC="패스워드 최소 길이 미설정"
        DT="minlen: not set"
    elif [ "$MINLEN" -ge 8 ]; then
        RES="Y"
        DESC="패스워드 최소 길이가 적절히 설정됨"
        DT="minlen: ${MINLEN}자"
    else
        RES="N"
        DESC="패스워드 최소 길이 미흡"
        DT="minlen: ${MINLEN}자 (기준: 8자 이상)"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$RES" "$DESC" "$DT"
}
```

### 7.2 파일 권한 (복합 조건)

**Linux - /etc/shadow 권한:**
```bash
check_U_SHADOW_PERM() {
    local CODE="U-05"
    local CAT="파일시스템"
    local NAME="/etc/shadow 파일 권한"
    local IMP="상"
    local RES=""
    local DESC=""
    local DT=""

    local TARGET="/etc/shadow"

    # 파일 존재 확인
    if [ ! -f "$TARGET" ]; then
        RES="N/A"
        DESC="shadow 파일이 존재하지 않음"
        DT="파일: $TARGET (없음)"
        output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$RES" "$DESC" "$DT"
        return
    fi

    # 속성 추출
    local PERM=$(stat -c "%a" "$TARGET")
    local OWNER=$(stat -c "%U" "$TARGET")

    # 조건 판단 (권한 400 이하, 소유자 root)
    if [ "$OWNER" == "root" ] && [ "$PERM" -le 400 ]; then
        RES="Y"
        DESC="파일 권한이 적절히 설정됨"
        DT="파일: $TARGET\n소유자: $OWNER\n권한: $PERM"
    else
        RES="N"
        DESC="파일 권한이 부적절함"
        DT="파일: $TARGET\n소유자: $OWNER (기준: root)\n권한: $PERM (기준: 400 이하)"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$RES" "$DESC" "$DT"
}
```

### 7.3 서비스 상태 (존재 + 상태)

**Windows - 불필요 서비스:**
```powershell
function Check-W_UNNECESSARY_SVC {
    $CODE = "W-04"
    $CAT = "서비스관리"
    $NAME = "불필요한 서비스 비활성화"
    $IMP = "중"
    $RES = ""
    $DESC = ""
    $DT = ""

    # 점검 대상 서비스 목록
    $TARGET_SVCS = @("TlntSvr", "RemoteRegistry", "SNMP")
    $RUNNING = @()

    foreach ($svc in $TARGET_SVCS) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            $RUNNING += "$svc: Running"
        }
    }

    # 조건 판단
    if ($RUNNING.Count -eq 0) {
        $RES = "Y"
        $DESC = "불필요한 서비스가 실행되지 않음"
        $DT = "점검 대상: $($TARGET_SVCS -join ', ')`n상태: 모두 비활성"
    } else {
        $RES = "N"
        $DESC = "불필요한 서비스가 실행 중"
        $DT = $RUNNING -join "`n"
    }

    Output-Checkpoint $CODE $CAT $NAME $IMP $RES $DESC $DT
}
```

### 7.4 수동 확인 필요 (M 판정)

**Linux - 서비스 목록 확인:**
```bash
check_U_SVC_REVIEW() {
    local CODE="U-06"
    local CAT="서비스관리"
    local NAME="서비스 목록 검토"
    local IMP="중"
    local RES="M"
    local DESC="서비스 목록 수동 확인 필요"
    local DT=""

    # 실행 중인 서비스 목록 수집
    local SERVICES=$(systemctl list-units --type=service --state=running --no-pager | grep ".service" | awk '{print $1}' | head -10)

    DT="실행 중인 서비스:\n$SERVICES\n... (전체 목록 확인 필요)"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$RES" "$DESC" "$DT"
}
```

---

## 8. 체크리스트

진단 로직 작성 시 확인사항:

- [ ] CODE, CAT, NAME, IMP 상수 정의 완료
- [ ] 점검 대상 존재 여부 확인 (N/A 처리)
- [ ] 값 추출 실패 시 처리 (M 또는 기본값)
- [ ] 조건 판단 로직 명확
- [ ] Y/N 결과에 따른 DESC 작성
- [ ] DT에 현재값과 기준값 포함
- [ ] 민감 정보 마스킹 확인
- [ ] output_checkpoint 호출 확인

---

## 9. PowerShell 주의사항

### 9.1 정규식에서 특수문자 이스케이프

PowerShell에서 `$` 문자를 정규식에서 사용할 때는 **작은따옴표**를 사용해야 합니다.

```powershell
# ❌ 잘못된 예 - 큰따옴표 사용 시 $ 가 변수로 해석됨
$shares | Where-Object { $_.Name -match "^[A-Z]\$$" }  # 에러 발생

# ✅ 올바른 예 - 작은따옴표 사용
$shares | Where-Object { $_.Name -match '^[A-Z]\$' }   # 정상 작동
```

### 9.2 Not Set (미설정) 판단 기준

레지스트리 값이 없을 때의 판단은 **Windows 기본 동작**에 따라 달라집니다.

| 항목 | 레지스트리 | Windows 기본값 | Not Set 판단 |
|------|-----------|---------------|-------------|
| 원격 지원 | fAllowToGetHelp | 비활성화 | **양호** |
| 자동 실행 | NoDriveTypeAutoRun | 허용 | **취약** |
| 복구 콘솔 | SecurityLevel | 비활성화 | **양호** |
| 자동 로그인 | AutoAdminLogon | 비활성화 | **양호** |

**대사집 작성 시 필수 기재:**
```markdown
## Not Set 판단 기준
- Windows 기본값: (활성화/비활성화)
- Not Set 시 판단: (양호/취약)
```

### 9.3 백신 productState 비트마스킹

SecurityCenter2의 `productState`로 백신 상태를 확인할 때 **벤더별 구현이 달라 오탐 가능성**이 있습니다.

```powershell
# productState 비트 분석
$realTimeOn = (($productState -shr 12) -band 0xF) -eq 0x1

# 주의: 이 방식은 오탐이 발생할 수 있음
# Defender의 경우 Get-MpComputerStatus가 더 정확함
```

**권장 접근법:**
1. Defender → `Get-MpComputerStatus` 사용 (정확함)
2. 타사 백신 → productState 참고 + 수동 확인 병행

---

*v1.1 | 2026-02-01 | Seedgen*


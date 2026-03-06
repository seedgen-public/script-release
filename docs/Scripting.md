# 스크립트 개발 가이드

> USG 하위 문서 - 스크립트 작성 규칙

**상위 문서**: [USG.md](./USG.md)

---

## 1. 전체 항목 포함 규칙 (필수)

### 1.1 원칙

**모든 스크립트는 해당 영역의 전체 진단 항목을 포함해야 한다.**

- WEB/WAS 스크립트: WEB-01 ~ WEB-26 전체 26개
- DBMS 스크립트: D-01 ~ D-26 전체 26개
- PC 스크립트: PC-01 ~ PC-18 전체 18개

### 1.2 N/A 항목 처리

해당 서비스에 적용되지 않는 항목도 **반드시 함수로 구현**하고, N/A 사유를 명시한다.

**잘못된 예 (항목 누락):**
```bash
# Apache 스크립트에서 WEB-01 함수가 아예 없음
check_WEB04()  # WEB-01, 02, 03 건너뜀
```

**올바른 예 (N/A 포함):**
```bash
check_WEB01() {
    local CODE="WEB-01"
    local CAT="계정관리"
    local NAME="Default 관리자 계정명 변경"
    local IMP="상"
    local RES="N/A"
    local DESC="해당없음 - Apache는 별도의 관리자 계정이 없음"
    local DT="Apache는 설정 파일 기반으로 운영되며, WAS처럼 별도의 관리 콘솔 계정이 존재하지 않음"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$RES" "$DESC" "$DT"
}
```

### 1.3 N/A 사유 작성 기준

| 구분 | 사유 예시 |
|------|----------|
| 기능 미지원 | "{서비스}는 {기능}을 지원하지 않음" |
| 다른 항목에서 점검 | "WEB-XX에서 통합 점검" |
| 플랫폼 전용 | "{기능}은 {플랫폼} 전용 기능임" |
| 아키텍처 차이 | "{서비스}는 {개념}이 없음 (다른방식으로 동작)" |

### 1.4 검증

스크립트 작성 완료 후 다음을 확인:

1. 전체 항목 수가 맞는지 확인 (WEB: 26개, D: 26개, PC: 18개)
2. XML 결과에 모든 항목이 출력되는지 확인
3. N/A 항목의 사유가 명확한지 확인

---

## 2. 스크립트 구조

### 2.1 전체 흐름

```
┌──────────────────────────────────────────────────────────┐
│ HEADER    : 스크립트 정보 주석                           │
├──────────────────────────────────────────────────────────┤
│ INIT      : 초기화                                       │
├──────────────────────────────────────────────────────────┤
│ COLLECT   : 시스템 정보 수집                             │
├──────────────────────────────────────────────────────────┤
│ OUTPUT    : XML 출력 시작 (스트림)                       │
│     ↓                                                    │
│ CHECK     : 진단 실행 → output_checkpoint() → 파일       │
│     ↓                                                    │
│ OUTPUT    : XML 출력 종료                                │
├──────────────────────────────────────────────────────────┤
│ CLEANUP   : 정리                                         │
└──────────────────────────────────────────────────────────┘
```

### 2.2 섹션별 상세

#### HEADER
스크립트 최상단 주석 블록

| 항목 | 설명 | 필수 |
|------|------|------|
| 스크립트명 | 파일명 및 용도 | O |
| 버전 | 스크립트 버전 | O |
| 작성자 | 작성자/팀명 | O |
| 수정이력 | 날짜, 내용 | O |

#### INIT
초기화 및 환경 설정

| 항목 | 설명 | 필수 |
|------|------|------|
| 권한 체크 | root/Administrator 확인 | O |
| **프로젝트 설정** | `META_STD` (진단 기준/프로젝트 식별자) | O |
| 상수 정의 | `META_VER`, `META_PLAT`, `META_TYPE` | O |
| 출력 경로 | `OUTPUT_FILE` 경로 설정 | O |
| 함수 정의 | `output_checkpoint()` 정의 | O |

**META_STD 설정:**
스크립트 최상단에 명시적으로 배치하여 배포 전 수정 가능하도록 함.
```
#================================================================
# [!] 프로젝트 설정 - 배포 전 수정 필요
#================================================================
META_STD="KISA"    # 진단 기준/프로젝트 (예: KISA, CIS, 삼성_2025)
```

#### COLLECT
시스템 정보 수집 (SYS_* 변수)

| 변수 | 설명 | 필수 |
|------|------|------|
| `SYS_HOST` | 호스트명 | O |
| `SYS_DOM` | 도메인 | O |
| `SYS_OS_NAME` | OS 원본 | O |
| `SYS_OS_FN` | OS 정제 | O |
| `SYS_KN` | 커널/빌드 버전 | O |
| `SYS_ARCH` | 아키텍처 | O |
| `SYS_IP` | 대표 IP | O |
| `SYS_NET_ALL` | 전체 네트워크 | O |

#### OUTPUT (시작)
XML 스트림 출력 시작

```
1. 출력 파일로 리다이렉트 시작
2. XML 헤더 출력
3. <seedgen> 시작
4. <meta> 출력
5. <sys> 출력
6. <results> 시작
```

#### CHECK
진단 항목 순차 실행

```
1. 진단 로직 실행
2. 결과 판정 (Y/N/N/A/M)
3. output_checkpoint() 호출 → 파일로 직접 출력
4. 다음 항목으로
```

#### OUTPUT (종료)
XML 스트림 출력 종료

```
1. </results> 출력
2. </seedgen> 출력
3. 리다이렉트 종료
```

#### CLEANUP
정리 및 종료

| 항목 | 설명 | 필수 |
|------|------|------|
| 종료 메시지 | 결과 파일 경로 출력 | O |

### 2.3 XML 출력 방식: 스트림

진단 결과를 **즉시 파일로 출력**하는 방식 사용.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   CHECK     │ ──→ │  output_    │ ──→ │  XML 파일   │
│  (진단)     │     │ checkpoint()│     │  (즉시저장) │
└─────────────┘     └─────────────┘     └─────────────┘
```

---

## 3. 네이밍 규칙

### 변수 접두사

| 접두사 | 용도 | 예시 |
|--------|------|------|
| `SYS_` | 시스템 정보 | `SYS_HOSTNAME`, `SYS_IP` |
| `CHECK_` | 진단 정보 | `CHECK_CODE`, `CHECK_NAME` |
| `RESULT_` | 결과값 | `RESULT_STATUS`, `RESULT_DETAIL` |
| `PATH_` | 경로 | `PATH_OUTPUT`, `PATH_TEMP` |

### 함수 접두사

| 접두사 | 용도 | 예시 |
|--------|------|------|
| `system_` | 시스템 정보 수집 | `system_get_hostname()` |
| `check_` | 진단 실행 | `check_U01()` |
| `output_` | 결과 출력 | `output_checkpoint()` |

---

## 4. 파일명 규칙

### 4.1 스크립트 파일명

```
{서비스명}_{플랫폼}.{확장자}
```

| 구성요소 | 설명 | 예시 |
|----------|------|------|
| `서비스명` | 진단 대상 서비스 | `Apache`, `MySQL`, `PC` |
| `플랫폼` | 실행 환경 | `Linux`, `Windows` |
| `확장자` | 스크립트 언어 | `.sh` (Bash), `.ps1` (PowerShell) |

**예시:**
- `Apache_Linux.sh` - Apache Linux 진단 스크립트
- `Apache_Windows.ps1` - Apache Windows 진단 스크립트
- `MySQL_Linux.sh` - MySQL Linux 진단 스크립트
- `MSSQL_Windows.ps1` - MSSQL Windows 진단 스크립트
- `PC_Windows.ps1` - Windows PC 진단 스크립트

### 4.2 결과 XML 파일명

```
{PLATFORM}_{HOSTNAME}_{YYYYMMDD_HHMMSS}.xml
```

| 구성요소 | 설명 | 예시 |
|----------|------|------|
| `PLATFORM` | 플랫폼 (대문자) | `LINUX`, `WINDOWS` |
| `HOSTNAME` | 호스트명 | `web-prod-01`, `DC-SERVER-01` |
| `YYYYMMDD_HHMMSS` | 생성일시 | `20250618_151022` |

**예시:**
- `LINUX_web-prod-01_20250618_143215.xml`
- `WINDOWS_DC-SERVER-01_20250618_151022.xml`

---

## 5. 인코딩 규칙

| 플랫폼 | 줄바꿈 | 스크립트 인코딩 | 결과 XML 인코딩 |
|--------|--------|-----------------|-----------------|
| Windows | CRLF | UTF-8 BOM | UTF-8 (BOM 없음) |
| Linux | LF | UTF-8 (BOM 없음) | UTF-8 (BOM 없음) |

**주의사항:**
- Windows PowerShell 5.x는 BOM 없는 UTF-8 파일을 시스템 기본 인코딩(CP949)으로 인식
- **스크립트 파일**: Windows는 UTF-8 BOM 필수 (PowerShell 5.x 호환성)
- **결과 XML 파일**: UTF-8 BOM 없음 (표준 XML 호환성)

---

## 6. 결과 출력 원칙

### 6.1 양호(Y) 판정 시에도 근거 출력

판정 결과가 양호(Y)라도 해당 판정의 근거가 되는 데이터를 `<dt>` 노드에 출력한다.

**예시:**
```xml
<cp>
    <code>WEB-06</code>
    <res>Y</res>
    <desc>AllowOverride None 설정됨</desc>
    <dt><![CDATA[
[/var/www/html]
AllowOverride None
    ]]></dt>
</cp>
```

### 6.2 수동확인(M) 시 판단 정보 출력

수동 확인이 필요한 경우, 담당자가 판단할 수 있는 모든 관련 정보를 출력한다.

**예시:**
```xml
<cp>
    <code>WEB-08</code>
    <res>M</res>
    <desc>LimitRequestBody 설정 확인 필요</desc>
    <dt><![CDATA[
[설정 현황]
/etc/httpd/conf/httpd.conf: LimitRequestBody 5242880
/etc/httpd/conf.d/vhost.conf: 설정 없음

[업로드 기능 존재 여부 확인 필요]
    ]]></dt>
</cp>
```

---

## 7. XML 안전 출력

### 7.1 제어문자 제거

NULL 문자(0x00) 등 XML에서 허용되지 않는 제어문자는 출력 전 제거한다.

**Bash 예시:**
```bash
# NULL 문자 및 제어문자 제거
clean_output=$(echo "$raw_output" | tr -d '\000-\010\013\014\016-\037')
```

**PowerShell 예시:**
```powershell
# NULL 문자 및 제어문자 제거
$cleanOutput = $rawOutput -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
```

### 7.2 CDATA 내 특수문자 처리

CDATA 섹션 종료 시퀀스(`]]>`)가 데이터에 포함된 경우 이스케이프 처리한다.

**예시:**
```bash
# CDATA 종료 시퀀스 이스케이프
safe_output=$(echo "$output" | sed 's/]]>/]]]]><![CDATA[>/g')
```

---

*v3.1 | 2026-02-01 | Seedgen*


# Script Structure Reference

> 진단 스크립트의 내부 구조 요약. 스크립트 전체를 읽지 않고도 구조를 파악할 수 있도록 작성됨.

---

## 1. 파일 구조 (섹션 순서)

```
HEADER   → 주석 블록 (스크립트명, 버전, 수정이력)
INIT     → 상수 + output_checkpoint() 함수 정의
COLLECT  → 시스템/연결 정보 수집
OUTPUT   → XML 헤더 출력 시작
CHECK    → check_XXX() 함수들 순차 실행
OUTPUT   → XML 푸터 출력 종료
CLEANUP  → 완료 메시지
```

---

## 2. 메타데이터 변수 (INIT 섹션)

스크립트 상단에 다음 상수가 선언됨:

```bash
META_STD="KISA"        # 진단 기준
META_VER="1.0"         # 스크립트 버전
META_PLAT="MySQL"      # 플랫폼명
META_TYPE="DBMS"       # 유형 (Server, DBMS, WEBWAS, PC)
```

---

## 3. 핵심 함수: output_checkpoint()

모든 진단 결과를 XML로 출력하는 단일 함수. 모든 check 함수가 이것을 호출함.

```bash
output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$RES" "$DESC" "$DT"
```

| 인자 | 설명 | 예시 |
|------|------|------|
| CODE | 진단 코드 | `D-01` |
| CAT  | 카테고리 | `계정관리` |
| NAME | 항목명 (전체) | `기본 계정의 비밀번호, 정책 등을 변경하여 사용` |
| IMP  | 중요도 | `상`, `중`, `하` |
| RES  | 결과 | `Y`, `N`, `N/A`, `M` |
| DESC | 설명 (한 줄) | `비밀번호 미설정 계정 존재` |
| DT   | 상세 증적 | 수집된 데이터 (CDATA) |

출력 XML:
```xml
<cp>
    <code>D-01</code>
    <cat>계정관리</cat>
    <n>기본 계정의 비밀번호, 정책 등을 변경하여 사용</n>
    <imp>상</imp>
    <res>Y</res>
    <desc>양호</desc>
    <dt><![CDATA[...]]></dt>
</cp>
```

---

## 4. check 함수 패턴

모든 check 함수는 동일한 구조:

```bash
check_D01() {
    # 1) 메타데이터 선언 (여기가 검증 대상)
    local CODE="D-01"
    local CAT="계정관리"
    local NAME="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
    local IMP="상"
    local RES=""
    local DESC=""
    local DT=""

    # 2) 진단 로직 (데이터 수집 + 판정)
    ...

    # 3) 결과 출력
    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$RES" "$DESC" "$DT"
}
```

**메타데이터 검증 시 확인할 4개 필드:**
- `CODE` — spec의 코드와 일치 여부
- `NAME` — spec의 name과 일치 여부 (가장 빈번한 불일치)
- `CAT`  — spec의 cat과 일치 여부
- `IMP`  — spec의 imp와 일치 여부

---

## 5. 코드 체계

### 진단 코드 → 스크립트 내 함수명 매핑

| KISA 코드 | 스크립트 내 CODE | 함수명 |
|-----------|-----------------|--------|
| D-01      | `D-01`          | `check_D01()` |
| WEB-01    | `WEB-01`        | `check_WEB01()` |
| U-01      | `U-01`          | `check_U01()` |
| W-01      | `W-01`          | `check_W01()` |
| PC-01     | `PC-01`         | `check_PC01()` |

### 제품별 스크립트 코드 접두사 (DBMS/WEBWAS)

DBMS와 WEBWAS는 **KISA 코드를 그대로 사용** (D-XX, WEB-XX).
제품별 접두사 변환 없이 모든 제품 스크립트가 동일한 D-01~D-26, WEB-01~WEB-26을 사용.

---

## 6. N/A 항목 규칙

해당 제품에 적용 불가한 항목도 반드시 함수로 존재해야 함:

```bash
check_D12() {
    local CODE="D-12"
    local CAT="접근관리"
    local NAME="안전한 리스너 비밀번호 설정"
    local IMP="상"
    local RES="N/A"
    local DESC="MySQL은 Oracle 리스너 개념이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]..."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$RES" "$DESC" "$DT"
}
```

---

## 7. 파일명 규칙

```
{서비스명}_{플랫폼}.{확장자}
```

예: `MySQL_Linux.sh`, `Apache_Windows.ps1`, `MSSQL_Windows.ps1`

---

## 8. 결과값 상수

| 값 | 의미 |
|----|------|
| Y | 양호 |
| N | 취약 |
| N/A | 해당없음 |
| M | 수동확인 |

---

## 9. 메타데이터 검증 방법 (grep 패턴)

스크립트에서 메타데이터를 추출할 때 사용할 정규식:

```bash
# CODE 추출
grep -oP 'local CODE="[^"]+"' script.sh

# NAME 추출  
grep -oP 'local NAME="[^"]+"' script.sh

# CAT 추출
grep -oP 'local CAT="[^"]+"' script.sh

# IMP 추출
grep -oP 'local IMP="[^"]+"' script.sh
```

또는 한번에:
```bash
grep -E 'local (CODE|NAME|CAT|IMP)=' script.sh
```

---

*v1.0 | 2026-02-05 | 클코 작업용 구조 레퍼런스*

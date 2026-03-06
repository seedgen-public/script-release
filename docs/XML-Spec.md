# XML 출력 스펙

> USG 하위 문서 - XML 구조 및 노드 정의

**상위 문서**: [USG.md](./USG.md)

---

## 1. XML 전체 구조

```xml
<?xml version="1.0" encoding="UTF-8"?>
<seedgen>
    <meta>
        <date></date>      <!-- 생성일시 (ISO8601) -->
        <ver></ver>        <!-- 스크립트 버전 -->
        <plat></plat>      <!-- 플랫폼 -->
        <type></type>      <!-- 플랫폼 유형 -->
        <std></std>        <!-- 진단 기준 -->
    </meta>
    <sys>
        <host></host>      <!-- 호스트명 -->
        <dom></dom>        <!-- 도메인 -->
        <os>
            <n></n>        <!-- OS 원본 -->
            <fn></fn>      <!-- OS 정제 -->
        </os>
        <kn></kn>          <!-- 커널/빌드 버전 -->
        <arch></arch>      <!-- 아키텍처 -->
        <net>
            <ip></ip>      <!-- 대표 IP -->
            <all><![CDATA[]]></all>  <!-- 전체 네트워크 -->
        </net>
    </sys>
    <results>
        <cp>               <!-- 진단 항목 (반복) -->
            <code></code>  <!-- 진단 코드 -->
            <cat></cat>    <!-- 카테고리 -->
            <n></n>        <!-- 항목명 -->
            <imp></imp>    <!-- 중요도 -->
            <res></res>    <!-- 결과 -->
            <desc></desc>  <!-- 설명 -->
            <dt><![CDATA[]]></dt>  <!-- 상세 증적 -->
        </cp>
    </results>
</seedgen>
```

---

## 2. 노드 정의

### 2.1 meta (메타데이터)

| 노드 | 풀네임 | 설명 | 예시 |
|------|--------|------|------|
| `date` | generatedAt | 생성일시 (ISO8601) | `2025-06-18T14:32:15+09:00` |
| `ver` | version | 스크립트 버전 | `1.0` |
| `plat` | platform | 플랫폼 | `Linux`, `Windows` |
| `type` | type | 플랫폼 유형 | `PC`, `Server`, `DBMS` |
| `std` | standard | 진단 기준 | `KISA`, `CIS`, `내부기준` |

### 2.2 sys (시스템 정보)

| 노드 | 풀네임 | 설명 | 예시 |
|------|--------|------|------|
| `host` | hostname | 호스트명 | `web-prod-01` |
| `dom` | domain | 도메인 | `seedgen.local` |
| `os > n` | name | OS 원본 | `Rocky Linux 8.9 (Green Obsidian)` |
| `os > fn` | friendlyName | OS 정제 | `Rocky Linux 8.9` |
| `kn` | kernel | 커널/빌드 버전 | `4.18.0-513.el8.x86_64` |
| `arch` | architecture | 아키텍처 | `x86_64` |
| `net > ip` | ip | 대표 IP | `192.168.10.51` |
| `net > all` | all | 전체 IP (CDATA) | 인터페이스별 목록 |

### 2.3 results > cp (진단 항목)

| 노드 | 풀네임 | 설명 | 예시 |
|------|--------|------|------|
| `code` | code | 진단 코드 | `U-01`, `W-01` |
| `cat` | category | 카테고리 | `계정관리` |
| `n` | name | 항목명 | `root 원격 접속 제한` |
| `imp` | importance | 중요도 | `상`, `중`, `하` |
| `res` | result | 결과 | `Y`, `N`, `N/A`, `M` |
| `desc` | description | 설명 (한 줄) | `root 원격 접속이 제한되어 있음` |
| `dt` | detail | 상세 증적 (CDATA) | `PermitRootLogin: no` |

---

## 3. 결과값 상수

| 값 | 의미 | 언제 사용 |
|----|------|----------|
| `Y` | 양호 | 기준 충족 |
| `N` | 취약 | 기준 미충족 |
| `N/A` | 해당없음 | 점검 불가/미해당 |
| `M` | 수동확인 | 자동판단 불가 |

---

## 4. 예시

### 4.1 전체 XML 예시

```xml
<?xml version="1.0" encoding="UTF-8"?>
<seedgen>
    <meta>
        <date>2026-01-15T14:32:15+09:00</date>
        <ver>1.0</ver>
        <plat>Linux</plat>
        <type>Server</type>
        <std>KISA</std>
    </meta>
    <sys>
        <host>web-prod-01</host>
        <dom>seedgen.local</dom>
        <os>
            <n>Rocky Linux 8.9 (Green Obsidian)</n>
            <fn>Rocky Linux 8.9</fn>
        </os>
        <kn>4.18.0-513.el8.x86_64</kn>
        <arch>x86_64</arch>
        <net>
            <ip>192.168.10.51</ip>
            <all><![CDATA[eth0: 192.168.10.51
eth1: 10.0.0.100]]></all>
        </net>
    </sys>
    <results>
        <cp>
            <code>U-01</code>
            <cat>계정관리</cat>
            <n>root 원격 접속 제한</n>
            <imp>상</imp>
            <res>Y</res>
            <desc>root 원격 접속이 제한되어 있음</desc>
            <dt><![CDATA[PermitRootLogin: no]]></dt>
        </cp>
        <cp>
            <code>U-02</code>
            <cat>계정관리</cat>
            <n>패스워드 최소 길이</n>
            <imp>상</imp>
            <res>N</res>
            <desc>패스워드 최소 길이 미흡</desc>
            <dt><![CDATA[minlen: 6자 (기준: 8자 이상)]]></dt>
        </cp>
    </results>
</seedgen>
```

---

*v3.1 | 2026-02-01 | Seedgen*


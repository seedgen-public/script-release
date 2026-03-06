# Linux 스크립트 가이드

> Linux/Unix 보안 진단 스크립트 가이드

**상위 문서**: [USG.md](../USG.md)

---

## 1. 개요

Linux/Unix 플랫폼용 보안 진단 스크립트 작성 가이드.
진단 코드 접두사: `U-XX`

---

## 2. 시스템 정보 수집

### 2.1 meta (메타데이터)

| 노드 | 설명 | 수집 방법 | 예시 |
|------|------|-----------|------|
| `date` | 생성일시 (ISO8601) | `date +%Y-%m-%dT%H:%M:%S%:z` | `2025-06-18T14:32:15+09:00` |
| `ver` | 스크립트 버전 | 스크립트 내 상수 | `1.0` |
| `plat` | 플랫폼 | 고정값 | `Linux` |
| `std` | 진단 기준 | 스크립트 내 상수 | `KISA` |

```bash
META_DATE=$(date +%Y-%m-%dT%H:%M:%S%:z)
META_VER="1.0"
META_PLAT="Linux"
META_TYPE="Server"
META_STD="KISA"
```

### 2.2 sys (시스템 정보)

| 노드 | 설명 | 수집 방법 | 예시 |
|------|------|-----------|------|
| `host` | 호스트명 | `hostname` | `web-prod-01` |
| `dom` | 도메인 | `hostname -d` | `seedgen.local` |
| `os > n` | OS 원본 | `/etc/os-release` | `Rocky Linux 8.9 (Green Obsidian)` |
| `os > fn` | OS 정제 | 파싱 | `Rocky Linux 8.9` |
| `kn` | 커널 버전 | `uname -r` | `4.18.0-513.el8.x86_64` |
| `arch` | 아키텍처 | `uname -m` | `x86_64` |
| `ip` | 대표 IP | `hostname -I` | `192.168.10.51` |
| `all` | 전체 IP | `ip addr` | 인터페이스별 목록 |

```bash
SYS_HOST=$(hostname)
SYS_DOM=$(hostname -d 2>/dev/null || echo "N/A")
SYS_OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
SYS_OS_FN=$(echo "$SYS_OS_NAME" | sed 's/ (.*)//g')
SYS_KN=$(uname -r)
SYS_ARCH=$(uname -m)
SYS_IP=$(hostname -I | awk '{print $1}')
SYS_NET_ALL=$(ip -4 addr show | grep inet | awk '{print $NF": "$2}' | cut -d'/' -f1)
```

---

## 3. 권한 체크

```bash
if [ "$EUID" -ne 0 ]; then
    echo "[!] root 권한으로 실행하세요."
    exit 1
fi
```

---

## 4. 출력 함수

```bash
output_checkpoint() {
    local CODE="$1"
    local CAT="$2"
    local NAME="$3"
    local IMP="$4"
    local RES="$5"
    local DESC="$6"
    local DT="$7"

    echo "        <cp>"
    echo "            <code>$CODE</code>"
    echo "            <cat>$CAT</cat>"
    echo "            <n>$NAME</n>"
    echo "            <imp>$IMP</imp>"
    echo "            <res>$RES</res>"
    echo "            <desc>$DESC</desc>"
    echo "            <dt><![CDATA[$DT]]></dt>"
    echo "        </cp>"
}
```

---

## 5. 진단 함수 예시

```bash
check_U01() {
    local CODE="U-01"
    local CAT="계정관리"
    local NAME="root 원격 접속 제한"
    local IMP="상"
    local RES=""
    local DESC=""
    local DT=""

    # 진단 로직
    local PERMIT=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
    
    if [ "$PERMIT" == "no" ]; then
        RES="Y"
        DESC="root 원격 접속이 제한되어 있음"
        DT="PermitRootLogin: no"
    else
        RES="N"
        DESC="root 원격 접속이 허용되어 있음"
        DT="PermitRootLogin: ${PERMIT:-not set}"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$RES" "$DESC" "$DT"
}
```

---

## 6. 스크립트 템플릿

```bash
#!/bin/bash
#================================================================
# HEADER
#================================================================
# 스크립트명 : linux_security_check.sh
# 버전      : 1.0
# 작성자    : Seedgen
#================================================================

#================================================================
# [!] 프로젝트 설정 - 배포 전 수정 필요
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================

# 권한 체크
if [ "$EUID" -ne 0 ]; then
    echo "[!] root 권한으로 실행하세요."
    exit 1
fi

# 상수 정의
META_VER="1.0"
META_PLAT="Linux"
META_TYPE="Server"

# 출력 함수 정의
output_checkpoint() {
    local CODE="$1" CAT="$2" NAME="$3" IMP="$4" RES="$5" DESC="$6" DT="$7"
    echo "        <cp>"
    echo "            <code>$CODE</code>"
    echo "            <cat>$CAT</cat>"
    echo "            <n>$NAME</n>"
    echo "            <imp>$IMP</imp>"
    echo "            <res>$RES</res>"
    echo "            <desc>$DESC</desc>"
    echo "            <dt><![CDATA[$DT]]></dt>"
    echo "        </cp>"
}

#================================================================
# COLLECT
#================================================================

META_DATE=$(date +%Y-%m-%dT%H:%M:%S%:z)
SYS_HOST=$(hostname)
SYS_DOM=$(hostname -d 2>/dev/null || echo "N/A")
SYS_OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
SYS_OS_FN=$(echo "$SYS_OS_NAME" | sed 's/ (.*)//g')
SYS_KN=$(uname -r)
SYS_ARCH=$(uname -m)
SYS_IP=$(hostname -I | awk '{print $1}')
SYS_NET_ALL=$(ip -4 addr show | grep inet | awk '{print $NF": "$2}' | cut -d'/' -f1)

OUTPUT_FILE="${META_PLAT}_${SYS_HOST}_$(date +%Y%m%d_%H%M%S).xml"

#================================================================
# OUTPUT + CHECK
#================================================================

{
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<seedgen>'
    echo '    <meta>'
    echo "        <date>$META_DATE</date>"
    echo "        <ver>$META_VER</ver>"
    echo "        <plat>$META_PLAT</plat>"
    echo "        <type>$META_TYPE</type>"
    echo "        <std>$META_STD</std>"
    echo '    </meta>'
    echo '    <sys>'
    echo "        <host>$SYS_HOST</host>"
    echo "        <dom>$SYS_DOM</dom>"
    echo '        <os>'
    echo "            <n>$SYS_OS_NAME</n>"
    echo "            <fn>$SYS_OS_FN</fn>"
    echo '        </os>'
    echo "        <kn>$SYS_KN</kn>"
    echo "        <arch>$SYS_ARCH</arch>"
    echo '        <net>'
    echo "            <ip>$SYS_IP</ip>"
    echo "            <all><![CDATA[$SYS_NET_ALL]]></all>"
    echo '        </net>'
    echo '    </sys>'
    echo '    <results>'

    # CHECK 함수들 호출
    # check_U01
    # check_U02
    # ...

    echo '    </results>'
    echo '</seedgen>'
} > "$OUTPUT_FILE"

#================================================================
# CLEANUP
#================================================================

echo "[완료] $OUTPUT_FILE"
```

---

## 7. 파일명 규칙

```
{PLATFORM}_{HOSTNAME}_{YYYYMMDD_HHMMSS}.xml
```

예시: `LINUX_web-prod-01_20250618_143215.xml`

---

## 8. 참고 문서

- [USG](../USG.md) - 최상위 공통 정책
- [Logic](../Logic.md) - 진단 로직 작성 가이드
- [XML-Spec](../XML-Spec.md) - XML 출력 스펙
- [Scripting](../Scripting.md) - 스크립트 개발 가이드

---

*v2.2 | 2026-02-01 | Seedgen*


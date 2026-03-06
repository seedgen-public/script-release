#!/bin/bash
#================================================================
# Redis_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Redis_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Redis"
META_TYPE="DBMS"

# XML 특수문자 이스케이프
xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    echo "$s"
}

# 결과 출력 함수
output_checkpoint() {
    local CODE="$1"
    local CAT="$2"
    local NAME="$3"
    local IMP="$4"
    local STD="$5"
    local RES="$6"
    local DESC="$7"
    local DT="$8"

    case "$RES" in
        "Y")   echo -e "    [[32mY[0m] $CODE $NAME" ;;
        "N")   echo -e "    [[31mN[0m] $CODE $NAME" ;;
        "M")   echo -e "    [[33mM[0m] $CODE $NAME" ;;
        "N/A") echo -e "    [[90m-[0m] $CODE $NAME" ;;
        *)     echo -e "    [-] $CODE $NAME" ;;
    esac

    local E_NAME; E_NAME=$(xml_escape "$NAME")
    local E_DESC; E_DESC=$(xml_escape "$DESC")
    local E_STD; E_STD=$(xml_escape "$STD")
    cat >> "$OUTPUT_FILE" << CPEOF
        <cp>
            <code>$CODE</code>
            <cat>$CAT</cat>
            <n>$E_NAME</n>
            <imp>$IMP</imp>
            <std>$E_STD</std>
            <res>$RES</res>
            <desc>$E_DESC</desc>
            <dt><![CDATA[$DT]]></dt>
        </cp>
CPEOF
}

#================================================================
# CONNECT — 플랫폼별 커스터마이즈 영역
# (클라이언트 확인, 연결정보 입력, 연결 테스트, 버전 변수 세팅)
#================================================================
echo ""
echo "============================================================"
echo " Redis 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# redis-cli 확인
REDIS_CLI=$(which redis-cli 2>/dev/null)
if [ -z "$REDIS_CLI" ]; then
    echo -n "Redis CLI Path (redis-cli not found): "
    read REDIS_CLI
    if [ ! -x "$REDIS_CLI" ]; then
        echo "[!] redis-cli를 찾을 수 없습니다."
        exit 1
    fi
fi

# 연결 정보 입력
echo -n "Host (default: localhost): "
read DB_HOST
DB_HOST=${DB_HOST:-localhost}

echo -n "Port (default: 6379): "
read DB_PORT
DB_PORT=${DB_PORT:-6379}

echo -n "Password (Enter if no password): "
read -s DB_PASS
echo ""

# Redis 연결 명령어 (비밀번호 유무에 따라 분기)
if [ -n "$DB_PASS" ]; then
    REDIS_CMD="$REDIS_CLI -h $DB_HOST -p $DB_PORT -a $DB_PASS --no-auth-warning"
else
    REDIS_CMD="$REDIS_CLI -h $DB_HOST -p $DB_PORT"
fi

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
PING_RESULT=$($REDIS_CMD PING 2>&1)
if [ "$PING_RESULT" != "PONG" ]; then
    echo "[!] Redis 연결 실패: $PING_RESULT"
    exit 1
fi

# 버전 확인
DB_VERSION=$($REDIS_CMD INFO server 2>/dev/null | grep "redis_version:" | cut -d':' -f2 | tr -d '
')
echo "[OK] Redis $DB_VERSION 연결 성공"
echo ""

# Redis 버전 체크 (6.0 이상 여부 - ACL 지원)
MAJOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f1)
IS_60_OR_HIGHER=0
if [ "$MAJOR_VERSION" -ge 6 ] 2>/dev/null; then
    IS_60_OR_HIGHER=1
fi

#================================================================
# COLLECT
#================================================================
META_DATE=$(date +%Y-%m-%dT%H:%M:%S%:z)
SYS_HOST=$(hostname)
SYS_DOM=$(hostname -d 2>/dev/null || echo "N/A")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/${META_PLAT}_${SYS_HOST}_$(date +%Y%m%d_%H%M%S).xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

check01() {
    local CODE="D-01"
    local CAT="계정관리"
    local NAME="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
    local IMP="상"
    local STD="기본 계정의 초기 비밀번호를 변경하거나 잠금설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

    # CHECK 함수들


        # requirepass 설정 확인
        local REQUIREPASS=$($REDIS_CMD CONFIG GET requirepass 2>/dev/null | tail -1)

        # ACL 사용자 목록 (Redis 6.0+)
        local ACL_LIST=""
        if [ "$IS_60_OR_HIGHER" -eq 1 ]; then
            ACL_LIST=$($REDIS_CMD ACL LIST 2>/dev/null)
        fi

        DT="[requirepass 설정]\n$REQUIREPASS"
        if [ "$IS_60_OR_HIGHER" -eq 1 ]; then
            DT="${DT}\n\n[ACL 사용자 목록 (Redis 6.0+)]\n$ACL_LIST"
        fi

        if [ -z "$REQUIREPASS" ] || [ "$REQUIREPASS" = '""' ] || [ "$REQUIREPASS" = "''" ]; then
            RES="N"
            DESC="Redis 인증 비밀번호(requirepass)가 설정되지 않음"
        else
            RES="M"
            DESC="비밀번호가 설정됨 - 비밀번호 복잡도 수동 확인 필요"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check02() {
    local CODE="D-02"
    local CAT="계정관리"
    local NAME="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
    local IMP="상"
    local STD="계정 정보를 확인하여 불필요한 계정이 없는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ "$IS_60_OR_HIGHER" -eq 1 ]; then
        # ACL 사용자 목록 확인
        local ACL_LIST=$($REDIS_CMD ACL LIST 2>/dev/null)
        local ACL_COUNT=$(echo "$ACL_LIST" | wc -l)

        # default 사용자 확인
        local DEFAULT_USER=$(echo "$ACL_LIST" | grep "^user default")

        DT="[ACL 사용자 목록]\n$ACL_LIST\n\n[사용자 수]\n$ACL_COUNT"

        # default 사용자가 nopass로 설정되어 있는지 확인
        if echo "$DEFAULT_USER" | grep -q "nopass"; then
            RES="N"
            DESC="default 사용자가 비밀번호 없이 활성화됨"
        else
            RES="M"
            DESC="ACL 사용자 목록 수동 확인 필요"
        fi
    else
        DT="[N/A 사유]\nRedis $DB_VERSION은 ACL 기능을 지원하지 않습니다.\nRedis 6.0 이상에서 ACL 기반 사용자 관리가 가능합니다."
        RES="N/A"
        DESC="Redis 6.0 미만은 ACL 기능 미지원"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check03() {
    local CODE="D-03"
    local CAT="계정관리"
    local NAME="비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"
    local IMP="상"
    local STD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 비밀번호 복잡도/만료 정책 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nRedis는 자체적인 비밀번호 복잡도 정책이나 만료 기간 설정 기능을 제공하지 않습니다.\nACL 사용 시 수동으로 강력한 비밀번호를 설정해야 합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check04() {
    local CODE="D-04"
    local CAT="계정관리"
    local NAME="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
    local IMP="상"
    local STD="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ "$IS_60_OR_HIGHER" -eq 1 ]; then
        # ACL 사용자 목록에서 관리자 권한 확인
        local ACL_LIST=$($REDIS_CMD ACL LIST 2>/dev/null)

        # +@all 또는 +@admin 권한을 가진 사용자 확인
        local ADMIN_USERS=$(echo "$ACL_LIST" | grep -E "\+@all|\+@admin|\+@dangerous")

        DT="[전체 사용자 목록]\n$ACL_LIST\n\n[관리자 권한 사용자 (+@all, +@admin, +@dangerous)]\n${ADMIN_USERS:-없음}"

        local ADMIN_COUNT=$(echo "$ADMIN_USERS" | grep -c "^user" 2>/dev/null || echo "0")

        if [ "$ADMIN_COUNT" -gt 1 ]; then
            RES="M"
            DESC="관리자 권한 사용자 ${ADMIN_COUNT}명 - 필요 여부 확인 필요"
        else
            RES="Y"
            DESC="관리자 권한이 최소 사용자에게만 부여됨"
        fi
    else
        DT="[N/A 사유]\nRedis $DB_VERSION은 ACL 기능을 지원하지 않습니다.\nRedis 6.0 미만에서는 모든 연결이 동일한 권한을 가집니다."
        RES="N/A"
        DESC="Redis 6.0 미만은 ACL 기능 미지원"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check05() {
    local CODE="D-05"
    local CAT="계정관리"
    local NAME="비밀번호 재사용에 대한 제약 설정"
    local IMP="중"
    local STD="비밀번호 재사용 제한 설정을 적용한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 비밀번호 히스토리 관리 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nRedis는 비밀번호 히스토리를 관리하지 않습니다.\n비밀번호 재사용 제약 기능은 RDBMS 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check06() {
    local CODE="D-06"
    local CAT="계정관리"
    local NAME="DB 사용자 계정을 개별적으로 부여하여 사용"
    local IMP="중"
    local STD="사용자별 계정을 사용하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ "$IS_60_OR_HIGHER" -eq 1 ]; then
        # ACL 사용자 목록 확인
        local ACL_LIST=$($REDIS_CMD ACL LIST 2>/dev/null)
        local USER_COUNT=$(echo "$ACL_LIST" | grep -c "^user")

        DT="[ACL 사용자 목록]\n$ACL_LIST\n\n[사용자 수]\n$USER_COUNT"

        if [ "$USER_COUNT" -le 1 ]; then
            RES="M"
            DESC="사용자가 1명만 존재 - 개별 계정 부여 여부 확인 필요"
        else
            RES="Y"
            DESC="다중 사용자 계정이 설정됨 (${USER_COUNT}명)"
        fi
    else
        DT="[N/A 사유]\nRedis $DB_VERSION은 ACL 기능을 지원하지 않습니다.\nRedis 6.0 미만에서는 단일 비밀번호(requirepass)만 사용 가능합니다."
        RES="N/A"
        DESC="Redis 6.0 미만은 ACL 기능 미지원"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check07() {
    local CODE="D-07"
    local CAT="계정관리"
    local NAME="root 권한으로 서비스 구동 제한"
    local IMP="중"
    local STD="DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # redis-server 프로세스 확인
    local REDIS_PROC=$(ps -ef 2>/dev/null | grep "[r]edis-server" | head -5)
    local REDIS_USER=$(echo "$REDIS_PROC" | awk '{print $1}' | head -1)

    DT="[Redis 프로세스 정보]\n$REDIS_PROC\n\n[실행 사용자]\n${REDIS_USER:-확인불가}"

    if [ -z "$REDIS_USER" ]; then
        RES="M"
        DESC="Redis 프로세스를 확인할 수 없음 - 수동 확인 필요"
    elif [ "$REDIS_USER" = "root" ]; then
        RES="N"
        DESC="Redis가 root 권한으로 실행 중"
    else
        RES="Y"
        DESC="Redis가 일반 사용자($REDIS_USER)로 실행 중"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check08() {
    local CODE="D-08"
    local CAT="계정관리"
    local NAME="안전한 암호화 알고리즘 사용"
    local IMP="상"
    local STD="해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # TLS 설정 확인
    local TLS_PORT=$($REDIS_CMD CONFIG GET tls-port 2>/dev/null | tail -1)
    local TLS_CERT=$($REDIS_CMD CONFIG GET tls-cert-file 2>/dev/null | tail -1)
    local TLS_KEY=$($REDIS_CMD CONFIG GET tls-key-file 2>/dev/null | tail -1)
    local TLS_CA=$($REDIS_CMD CONFIG GET tls-ca-cert-file 2>/dev/null | tail -1)

    DT="[TLS 설정]\ntls-port: $TLS_PORT\ntls-cert-file: $TLS_CERT\ntls-key-file: $TLS_KEY\ntls-ca-cert-file: $TLS_CA"

    if [ -n "$TLS_PORT" ] && [ "$TLS_PORT" != "0" ]; then
        RES="Y"
        DESC="TLS가 활성화됨 (포트: $TLS_PORT)"
    else
        RES="N"
        DESC="TLS가 비활성화됨 - 평문 통신 사용"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check09() {
    local CODE="D-09"
    local CAT="계정관리"
    local NAME="일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정"
    local IMP="중"
    local STD="로그인 시도 횟수를 제한하는 값을 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 계정 잠금 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nRedis는 로그인 실패 시 계정 잠금 기능을 제공하지 않습니다.\n로그인 시도 제한은 외부 방화벽이나 fail2ban 등을 활용해야 합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check10() {
    local CODE="D-10"
    local CAT="접근관리"
    local NAME="원격에서 DB 서버로의 접속 제한"
    local IMP="상"
    local STD="DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

    # bind 설정 확인
    local BIND=$($REDIS_CMD CONFIG GET bind 2>/dev/null | tail -1)
    local PROTECTED_MODE=$($REDIS_CMD CONFIG GET protected-mode 2>/dev/null | tail -1)

    DT="[bind 설정]\n$BIND\n\n[protected-mode 설정]\n$PROTECTED_MODE"

    # bind가 비어있거나 0.0.0.0이면 취약
    if [ -z "$BIND" ] || [ "$BIND" = "0.0.0.0" ] || [ "$BIND" = "*" ]; then
        if [ "$PROTECTED_MODE" = "yes" ]; then
            RES="M"
            DESC="모든 IP 바인딩이지만 protected-mode 활성화 - 수동 확인 필요"
        else
            RES="N"
            DESC="모든 IP에서 접속 가능하고 protected-mode 비활성화"
        fi
    else
        RES="Y"
        DESC="특정 IP로 바인딩 제한됨 ($BIND)"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check11() {
    local CODE="D-11"
    local CAT="접근관리"
    local NAME="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
    local IMP="상"
    local STD="시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # D-11 ~ D-24: RDBMS 전용 항목 (N/A)
        local RES="N/A"
        local DESC="Redis는 시스템 테이블 개념이 없어 해당 항목 적용 불가"
        local DT="[N/A 사유]\nRedis는 RDBMS가 아닌 Key-Value 저장소로 시스템 테이블 개념이 없습니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check12() {
    local CODE="D-12"
    local CAT="접근관리"
    local NAME="안전한 리스너 비밀번호 설정 및 사용"
    local IMP="상"
    local STD="Listener의 비밀번호가 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Oracle Listener 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 Oracle의 리스너(Listener) 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check13() {
    local CODE="D-13"
    local CAT="접근관리"
    local NAME="불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"
    local IMP="중"
    local STD="불필요한 ODBC/OLE-DB가 설치되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 ODBC/OLE-DB 드라이버가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 ODBC/OLE-DB 드라이버를 사용하지 않습니다.\n해당 항목은 Windows RDBMS 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check14() {
    local CODE="D-14"
    local CAT="접근관리"
    local NAME="데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"
    local IMP="중"
    local STD="주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우"
    local RES=""
    local DESC=""
    local DT=""

    # Redis 설정 파일 경로 확인
    local CONFIG_FILE=$($REDIS_CMD CONFIG GET dir 2>/dev/null | tail -1)
    local RDB_FILE=$($REDIS_CMD CONFIG GET dbfilename 2>/dev/null | tail -1)
    local LOG_FILE=$($REDIS_CMD CONFIG GET logfile 2>/dev/null | tail -1)

    # 일반적인 설정 파일 경로
    local COMMON_CONFIGS="/etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf"

    DT="[설정 확인]\ndir: $CONFIG_FILE\ndbfilename: $RDB_FILE\nlogfile: $LOG_FILE\n\n[주요 파일 권한]"

    local VULN_FILES=""

    for conf in $COMMON_CONFIGS; do
        if [ -f "$conf" ]; then
            local PERM=$(stat -c "%a" "$conf" 2>/dev/null)
            local OWNER=$(stat -c "%U:%G" "$conf" 2>/dev/null)
            DT="${DT}\n$conf: $PERM ($OWNER)"

            # other에 쓰기 권한이 있으면 취약
            local OTHER_PERM=$((PERM % 10))
            if [ $((OTHER_PERM & 2)) -ne 0 ]; then
                VULN_FILES="${VULN_FILES}$conf "
            fi
        fi
    done

    if [ -n "$VULN_FILES" ]; then
        RES="N"
        DESC="설정 파일에 other 쓰기 권한 존재"
        DT="${DT}\n\n[취약 파일]\n$VULN_FILES"
    else
        RES="M"
        DESC="파일 권한 수동 확인 필요"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check15() {
    local CODE="D-15"
    local CAT="접근관리"
    local NAME="관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한"
    local IMP="하"
    local STD="Listener 관련 설정 파일에 대한 권한이 관리자로 설정되어 있으며, Listener로 파라미터를 변경할 수 없게 옵션이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Oracle Listener가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 Oracle의 리스너(Listener) 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check16() {
    local CODE="D-16"
    local CAT="접근관리"
    local NAME="Windows 인증 모드 사용"
    local IMP="하"
    local STD="Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우 sa 계정 활성화 시 강력한 암호 정책을 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Windows 인증 모드가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 MSSQL의 Windows 인증 모드를 지원하지 않습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check17() {
    local CODE="D-17"
    local CAT="옵션관리"
    local NAME="Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한"
    local IMP="하"
    local STD="Audit Table 접근 권한이 관리자 계정으로 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Audit Table이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 RDBMS의 Audit Table 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check18() {
    local CODE="D-18"
    local CAT="옵션관리"
    local NAME="응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"
    local IMP="상"
    local STD="DBA 계정의 Role이 Public으로 설정되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 PUBLIC Role이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 RDBMS의 PUBLIC Role 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check19() {
    local CODE="D-19"
    local CAT="옵션관리"
    local NAME="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"
    local IMP="상"
    local STD="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 FALSE로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Oracle OS 인증 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 Oracle의 OS 인증 관련 파라미터가 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check20() {
    local CODE="D-20"
    local CAT="옵션관리"
    local NAME="인가되지 않은 Object Owner의 제한"
    local IMP="하"
    local STD="Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Object Owner 개념이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 RDBMS의 스키마/Object Owner 개념이 없습니다.\n해당 항목은 RDBMS 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check21() {
    local CODE="D-21"
    local CAT="옵션관리"
    local NAME="인가되지 않은 GRANT OPTION 사용 제한"
    local IMP="중"
    local STD="WITH_GRANT_OPTION이 ROLE에 의하여 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 GRANT OPTION이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 RDBMS의 GRANT OPTION 개념이 없습니다.\n해당 항목은 RDBMS 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check22() {
    local CODE="D-22"
    local CAT="옵션관리"
    local NAME="데이터베이스의 자원 제한 기능을 TRUE로 설정"
    local IMP="하"
    local STD="RESOURCE_LIMIT 설정이 TRUE로 되어있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Oracle RESOURCE_LIMIT 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 Oracle의 RESOURCE_LIMIT 파라미터가 없습니다.\nRedis는 maxmemory, maxclients 등 별도의 자원 제한 파라미터를 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check23() {
    local CODE="D-23"
    local CAT="옵션관리"
    local NAME="xp_cmdshell 사용 제한"
    local IMP="상"
    local STD="xp_cmdshell이 비활성화 되어 있거나, 활성화 되어 있으면 다음의 조건을 모두 만족하는 경우 1. public의 실행(Execute) 권한이 부여되어 있지 않은 경우 2. 서비스 계정(애플리케이션 연동)에 sysadmin 권한이 부여되어 있지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 MSSQL xp_cmdshell 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 MSSQL의 xp_cmdshell 확장 저장 프로시저가 없습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check24() {
    local CODE="D-24"
    local CAT="옵션관리"
    local NAME="Registry Procedure 권한 제한"
    local IMP="상"
    local STD="제한이 필요한 시스템 확장 저장 프로시저들이 DBA 외 guest/public에게 부여되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 MSSQL Registry Procedure가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 MSSQL의 Registry 접근 확장 저장 프로시저가 없습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check25() {
    local CODE="D-25"
    local CAT="패치관리"
    local NAME="주기적 보안 패치 및 벤더 권고 사항 적용"
    local IMP="상"
    local STD="보안 패치가 적용된 버전을 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="M"
    local DESC="현재 버전 확인 후 최신 패치 적용 여부 수동 확인 필요"

    DT="[현재 버전]\nRedis $DB_VERSION\n\n※ 최신 버전은 Redis 공식 사이트에서 확인\nhttps://redis.io/download"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check26() {
    local CODE="D-26"
    local CAT="패치관리"
    local NAME="데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정"
    local IMP="상"
    local STD="DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 로그 파일 설정 확인
    local LOGFILE=$($REDIS_CMD CONFIG GET logfile 2>/dev/null | tail -1)
    local LOGLEVEL=$($REDIS_CMD CONFIG GET loglevel 2>/dev/null | tail -1)

    # slowlog 설정 확인
    local SLOWLOG_TIME=$($REDIS_CMD CONFIG GET slowlog-log-slower-than 2>/dev/null | tail -1)
    local SLOWLOG_LEN=$($REDIS_CMD CONFIG GET slowlog-max-len 2>/dev/null | tail -1)

    DT="[로그 설정]\nlogfile: $LOGFILE\nloglevel: $LOGLEVEL\n\n[Slowlog 설정]\nslowlog-log-slower-than: $SLOWLOG_TIME (마이크로초)\nslowlog-max-len: $SLOWLOG_LEN"

    if [ -z "$LOGFILE" ] || [ "$LOGFILE" = '""' ] || [ "$LOGFILE" = "''" ]; then
        RES="N"
        DESC="로그 파일(logfile)이 설정되지 않음"
    else
        RES="M"
        DESC="로그 파일이 설정됨 - 백업 정책 확인 필요"
        DT="${DT}\n\n※ logfile이 설정되어 있습니다."
        DT="${DT}\n※ 주기적인 백업 실시 여부는 인터뷰를 통해 확인하세요."
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}


#================================================================
# EXECUTE
#================================================================

echo ""
echo "  $META_PLAT Security Assessment v$META_VER [$META_STD]"
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  호스트: $SYS_HOST"
echo "  DBMS: $META_PLAT $DB_VERSION"
echo ""
echo "  [진단 시작]"
echo "  ─────────────────────────────────────────────────────────"
echo ""

# XML 헤더
cat > "$OUTPUT_FILE" << XMLEOF
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
            <n>$META_PLAT $DB_VERSION</n>
            <fn>$META_PLAT</fn>
        </os>
        <kn>$DB_VERSION</kn>
        <arch>$(uname -m)</arch>
        <net>
            <ip>${DB_HOST:-localhost}</ip>
            <all><![CDATA[Host: ${DB_HOST:-localhost}, Port: ${DB_PORT:-N/A}]]></all>
        </net>
    </sys>
    <results>
XMLEOF

# 진단 실행
    check01
    check02
    check03
    check04
    check05
    check06
    check07
    check08
    check09
    check10
    check11
    check12
    check13
    check14
    check15
    check16
    check17
    check18
    check19
    check20
    check21
    check22
    check23
    check24
    check25
    check26

# XML 종료
cat >> "$OUTPUT_FILE" << XMLEOF
    </results>
</seedgen>
XMLEOF

#================================================================
# CLEANUP
#================================================================
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  점검이 완료되었습니다!"
echo "  호스트: $SYS_HOST"
echo "  결과 파일: $OUTPUT_FILE"
echo ""

#================================================================
# Redis_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : Redis_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="Redis"
META_TYPE="DBMS"

# XML 특수문자 이스케이프
xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    echo "$s"
}

# 결과 출력 함수
output_checkpoint() {
    local CODE="$1"
    local CAT="$2"
    local NAME="$3"
    local IMP="$4"
    local STD="$5"
    local RES="$6"
    local DESC="$7"
    local DT="$8"

    case "$RES" in
        "Y")   echo -e "    [\033[32mY\033[0m] $CODE $NAME" ;;
        "N")   echo -e "    [\033[31mN\033[0m] $CODE $NAME" ;;
        "M")   echo -e "    [\033[33mM\033[0m] $CODE $NAME" ;;
        "N/A") echo -e "    [\033[90m-\033[0m] $CODE $NAME" ;;
        *)     echo -e "    [-] $CODE $NAME" ;;
    esac

    local E_NAME; E_NAME=$(xml_escape "$NAME")
    local E_DESC; E_DESC=$(xml_escape "$DESC")
    local E_STD; E_STD=$(xml_escape "$STD")
    cat >> "$OUTPUT_FILE" << CPEOF
        <cp>
            <code>$CODE</code>
            <cat>$CAT</cat>
            <n>$E_NAME</n>
            <imp>$IMP</imp>
            <std>$E_STD</std>
            <res>$RES</res>
            <desc>$E_DESC</desc>
            <dt><![CDATA[$DT]]></dt>
        </cp>
CPEOF
}

#================================================================
# CONNECT — 플랫폼별 커스터마이즈 영역
# (클라이언트 확인, 연결정보 입력, 연결 테스트, 버전 변수 세팅)
#================================================================
echo ""
echo "============================================================"
echo " Redis 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# redis-cli 확인
REDIS_CLI=$(which redis-cli 2>/dev/null)
if [ -z "$REDIS_CLI" ]; then
    echo -n "Redis CLI Path (redis-cli not found): "
    read REDIS_CLI
    if [ ! -x "$REDIS_CLI" ]; then
        echo "[!] redis-cli를 찾을 수 없습니다."
        exit 1
    fi
fi

# 연결 정보 입력
echo -n "Host (default: localhost): "
read DB_HOST
DB_HOST=${DB_HOST:-localhost}

echo -n "Port (default: 6379): "
read DB_PORT
DB_PORT=${DB_PORT:-6379}

echo -n "Password (Enter if no password): "
read -s DB_PASS
echo ""

# Redis 연결 명령어 (비밀번호 유무에 따라 분기)
if [ -n "$DB_PASS" ]; then
    REDIS_CMD="$REDIS_CLI -h $DB_HOST -p $DB_PORT -a $DB_PASS --no-auth-warning"
else
    REDIS_CMD="$REDIS_CLI -h $DB_HOST -p $DB_PORT"
fi

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
PING_RESULT=$($REDIS_CMD PING 2>&1)
if [ "$PING_RESULT" != "PONG" ]; then
    echo "[!] Redis 연결 실패: $PING_RESULT"
    exit 1
fi

# 버전 확인
DB_VERSION=$($REDIS_CMD INFO server 2>/dev/null | grep "redis_version:" | cut -d':' -f2 | tr -d '\r')
echo "[OK] Redis $DB_VERSION 연결 성공"
echo ""

# Redis 버전 체크 (6.0 이상 여부 - ACL 지원)
MAJOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f1)
IS_60_OR_HIGHER=0
if [ "$MAJOR_VERSION" -ge 6 ] 2>/dev/null; then
    IS_60_OR_HIGHER=1
fi

#================================================================
# COLLECT
#================================================================
META_DATE=$(date +%Y-%m-%dT%H:%M:%S%:z)
SYS_HOST=$(hostname)
SYS_DOM=$(hostname -d 2>/dev/null || echo "N/A")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/${META_PLAT}_${SYS_HOST}_$(date +%Y%m%d_%H%M%S).xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

check01() {
    local CODE="D-01"
    local CAT="계정관리"
    local NAME="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
    local IMP="상"
    local STD="기본 계정의 초기 비밀번호를 변경하거나 잠금설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

    # CHECK 함수들


        # requirepass 설정 확인
        local REQUIREPASS=$($REDIS_CMD CONFIG GET requirepass 2>/dev/null | tail -1)

        # ACL 사용자 목록 (Redis 6.0+)
        local ACL_LIST=""
        if [ "$IS_60_OR_HIGHER" -eq 1 ]; then
            ACL_LIST=$($REDIS_CMD ACL LIST 2>/dev/null)
        fi

        DT="[requirepass 설정]\n$REQUIREPASS"
        if [ "$IS_60_OR_HIGHER" -eq 1 ]; then
            DT="${DT}\n\n[ACL 사용자 목록 (Redis 6.0+)]\n$ACL_LIST"
        fi

        if [ -z "$REQUIREPASS" ] || [ "$REQUIREPASS" = '""' ] || [ "$REQUIREPASS" = "''" ]; then
            RES="N"
            DESC="Redis 인증 비밀번호(requirepass)가 설정되지 않음"
        else
            RES="M"
            DESC="비밀번호가 설정됨 - 비밀번호 복잡도 수동 확인 필요"
        fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check02() {
    local CODE="D-02"
    local CAT="계정관리"
    local NAME="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
    local IMP="상"
    local STD="계정 정보를 확인하여 불필요한 계정이 없는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ "$IS_60_OR_HIGHER" -eq 1 ]; then
        # ACL 사용자 목록 확인
        local ACL_LIST=$($REDIS_CMD ACL LIST 2>/dev/null)
        local ACL_COUNT=$(echo "$ACL_LIST" | wc -l)

        # default 사용자 확인
        local DEFAULT_USER=$(echo "$ACL_LIST" | grep "^user default")

        DT="[ACL 사용자 목록]\n$ACL_LIST\n\n[사용자 수]\n$ACL_COUNT"

        # default 사용자가 nopass로 설정되어 있는지 확인
        if echo "$DEFAULT_USER" | grep -q "nopass"; then
            RES="N"
            DESC="default 사용자가 비밀번호 없이 활성화됨"
        else
            RES="M"
            DESC="ACL 사용자 목록 수동 확인 필요"
        fi
    else
        DT="[N/A 사유]\nRedis $DB_VERSION은 ACL 기능을 지원하지 않습니다.\nRedis 6.0 이상에서 ACL 기반 사용자 관리가 가능합니다."
        RES="N/A"
        DESC="Redis 6.0 미만은 ACL 기능 미지원"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check03() {
    local CODE="D-03"
    local CAT="계정관리"
    local NAME="비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"
    local IMP="상"
    local STD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 비밀번호 복잡도/만료 정책 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nRedis는 자체적인 비밀번호 복잡도 정책이나 만료 기간 설정 기능을 제공하지 않습니다.\nACL 사용 시 수동으로 강력한 비밀번호를 설정해야 합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check04() {
    local CODE="D-04"
    local CAT="계정관리"
    local NAME="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
    local IMP="상"
    local STD="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ "$IS_60_OR_HIGHER" -eq 1 ]; then
        # ACL 사용자 목록에서 관리자 권한 확인
        local ACL_LIST=$($REDIS_CMD ACL LIST 2>/dev/null)

        # +@all 또는 +@admin 권한을 가진 사용자 확인
        local ADMIN_USERS=$(echo "$ACL_LIST" | grep -E "\+@all|\+@admin|\+@dangerous")

        DT="[전체 사용자 목록]\n$ACL_LIST\n\n[관리자 권한 사용자 (+@all, +@admin, +@dangerous)]\n${ADMIN_USERS:-없음}"

        local ADMIN_COUNT=$(echo "$ADMIN_USERS" | grep -c "^user" 2>/dev/null || echo "0")

        if [ "$ADMIN_COUNT" -gt 1 ]; then
            RES="M"
            DESC="관리자 권한 사용자 ${ADMIN_COUNT}명 - 필요 여부 확인 필요"
        else
            RES="Y"
            DESC="관리자 권한이 최소 사용자에게만 부여됨"
        fi
    else
        DT="[N/A 사유]\nRedis $DB_VERSION은 ACL 기능을 지원하지 않습니다.\nRedis 6.0 미만에서는 모든 연결이 동일한 권한을 가집니다."
        RES="N/A"
        DESC="Redis 6.0 미만은 ACL 기능 미지원"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check05() {
    local CODE="D-05"
    local CAT="계정관리"
    local NAME="비밀번호 재사용에 대한 제약 설정"
    local IMP="중"
    local STD="비밀번호 재사용 제한 설정을 적용한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 비밀번호 히스토리 관리 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nRedis는 비밀번호 히스토리를 관리하지 않습니다.\n비밀번호 재사용 제약 기능은 RDBMS 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check06() {
    local CODE="D-06"
    local CAT="계정관리"
    local NAME="DB 사용자 계정을 개별적으로 부여하여 사용"
    local IMP="중"
    local STD="사용자별 계정을 사용하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    if [ "$IS_60_OR_HIGHER" -eq 1 ]; then
        # ACL 사용자 목록 확인
        local ACL_LIST=$($REDIS_CMD ACL LIST 2>/dev/null)
        local USER_COUNT=$(echo "$ACL_LIST" | grep -c "^user")

        DT="[ACL 사용자 목록]\n$ACL_LIST\n\n[사용자 수]\n$USER_COUNT"

        if [ "$USER_COUNT" -le 1 ]; then
            RES="M"
            DESC="사용자가 1명만 존재 - 개별 계정 부여 여부 확인 필요"
        else
            RES="Y"
            DESC="다중 사용자 계정이 설정됨 (${USER_COUNT}명)"
        fi
    else
        DT="[N/A 사유]\nRedis $DB_VERSION은 ACL 기능을 지원하지 않습니다.\nRedis 6.0 미만에서는 단일 비밀번호(requirepass)만 사용 가능합니다."
        RES="N/A"
        DESC="Redis 6.0 미만은 ACL 기능 미지원"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check07() {
    local CODE="D-07"
    local CAT="계정관리"
    local NAME="root 권한으로 서비스 구동 제한"
    local IMP="중"
    local STD="DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # redis-server 프로세스 확인
    local REDIS_PROC=$(ps -ef 2>/dev/null | grep "[r]edis-server" | head -5)
    local REDIS_USER=$(echo "$REDIS_PROC" | awk '{print $1}' | head -1)

    DT="[Redis 프로세스 정보]\n$REDIS_PROC\n\n[실행 사용자]\n${REDIS_USER:-확인불가}"

    if [ -z "$REDIS_USER" ]; then
        RES="M"
        DESC="Redis 프로세스를 확인할 수 없음 - 수동 확인 필요"
    elif [ "$REDIS_USER" = "root" ]; then
        RES="N"
        DESC="Redis가 root 권한으로 실행 중"
    else
        RES="Y"
        DESC="Redis가 일반 사용자($REDIS_USER)로 실행 중"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check08() {
    local CODE="D-08"
    local CAT="계정관리"
    local NAME="안전한 암호화 알고리즘 사용"
    local IMP="상"
    local STD="해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # TLS 설정 확인
    local TLS_PORT=$($REDIS_CMD CONFIG GET tls-port 2>/dev/null | tail -1)
    local TLS_CERT=$($REDIS_CMD CONFIG GET tls-cert-file 2>/dev/null | tail -1)
    local TLS_KEY=$($REDIS_CMD CONFIG GET tls-key-file 2>/dev/null | tail -1)
    local TLS_CA=$($REDIS_CMD CONFIG GET tls-ca-cert-file 2>/dev/null | tail -1)

    DT="[TLS 설정]\ntls-port: $TLS_PORT\ntls-cert-file: $TLS_CERT\ntls-key-file: $TLS_KEY\ntls-ca-cert-file: $TLS_CA"

    if [ -n "$TLS_PORT" ] && [ "$TLS_PORT" != "0" ]; then
        RES="Y"
        DESC="TLS가 활성화됨 (포트: $TLS_PORT)"
    else
        RES="N"
        DESC="TLS가 비활성화됨 - 평문 통신 사용"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check09() {
    local CODE="D-09"
    local CAT="계정관리"
    local NAME="일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정"
    local IMP="중"
    local STD="로그인 시도 횟수를 제한하는 값을 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 계정 잠금 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nRedis는 로그인 실패 시 계정 잠금 기능을 제공하지 않습니다.\n로그인 시도 제한은 외부 방화벽이나 fail2ban 등을 활용해야 합니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check10() {
    local CODE="D-10"
    local CAT="접근관리"
    local NAME="원격에서 DB 서버로의 접속 제한"
    local IMP="상"
    local STD="DB 서버에 지정된 IP주소에서만 접근 가능하도록 제한한 경우"
    local RES=""
    local DESC=""
    local DT=""

    # bind 설정 확인
    local BIND=$($REDIS_CMD CONFIG GET bind 2>/dev/null | tail -1)
    local PROTECTED_MODE=$($REDIS_CMD CONFIG GET protected-mode 2>/dev/null | tail -1)

    DT="[bind 설정]\n$BIND\n\n[protected-mode 설정]\n$PROTECTED_MODE"

    # bind가 비어있거나 0.0.0.0이면 취약
    if [ -z "$BIND" ] || [ "$BIND" = "0.0.0.0" ] || [ "$BIND" = "*" ]; then
        if [ "$PROTECTED_MODE" = "yes" ]; then
            RES="M"
            DESC="모든 IP 바인딩이지만 protected-mode 활성화 - 수동 확인 필요"
        else
            RES="N"
            DESC="모든 IP에서 접속 가능하고 protected-mode 비활성화"
        fi
    else
        RES="Y"
        DESC="특정 IP로 바인딩 제한됨 ($BIND)"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check11() {
    local CODE="D-11"
    local CAT="접근관리"
    local NAME="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
    local IMP="상"
    local STD="시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # D-11 ~ D-24: RDBMS 전용 항목 (N/A)
        local RES="N/A"
        local DESC="Redis는 시스템 테이블 개념이 없어 해당 항목 적용 불가"
        local DT="[N/A 사유]\nRedis는 RDBMS가 아닌 Key-Value 저장소로 시스템 테이블 개념이 없습니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check12() {
    local CODE="D-12"
    local CAT="접근관리"
    local NAME="안전한 리스너 비밀번호 설정 및 사용"
    local IMP="상"
    local STD="Listener의 비밀번호가 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Oracle Listener 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 Oracle의 리스너(Listener) 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check13() {
    local CODE="D-13"
    local CAT="접근관리"
    local NAME="불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"
    local IMP="중"
    local STD="불필요한 ODBC/OLE-DB가 설치되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 ODBC/OLE-DB 드라이버가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 ODBC/OLE-DB 드라이버를 사용하지 않습니다.\n해당 항목은 Windows RDBMS 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check14() {
    local CODE="D-14"
    local CAT="접근관리"
    local NAME="데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"
    local IMP="중"
    local STD="주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우"
    local RES=""
    local DESC=""
    local DT=""

    # Redis 설정 파일 경로 확인
    local CONFIG_FILE=$($REDIS_CMD CONFIG GET dir 2>/dev/null | tail -1)
    local RDB_FILE=$($REDIS_CMD CONFIG GET dbfilename 2>/dev/null | tail -1)
    local LOG_FILE=$($REDIS_CMD CONFIG GET logfile 2>/dev/null | tail -1)

    # 일반적인 설정 파일 경로
    local COMMON_CONFIGS="/etc/redis/redis.conf /etc/redis.conf /etc/redis/6379.conf"

    DT="[설정 확인]\ndir: $CONFIG_FILE\ndbfilename: $RDB_FILE\nlogfile: $LOG_FILE\n\n[주요 파일 권한]"

    local VULN_FILES=""

    for conf in $COMMON_CONFIGS; do
        if [ -f "$conf" ]; then
            local PERM=$(stat -c "%a" "$conf" 2>/dev/null)
            local OWNER=$(stat -c "%U:%G" "$conf" 2>/dev/null)
            DT="${DT}\n$conf: $PERM ($OWNER)"

            # other에 쓰기 권한이 있으면 취약
            local OTHER_PERM=$((PERM % 10))
            if [ $((OTHER_PERM & 2)) -ne 0 ]; then
                VULN_FILES="${VULN_FILES}$conf "
            fi
        fi
    done

    if [ -n "$VULN_FILES" ]; then
        RES="N"
        DESC="설정 파일에 other 쓰기 권한 존재"
        DT="${DT}\n\n[취약 파일]\n$VULN_FILES"
    else
        RES="M"
        DESC="파일 권한 수동 확인 필요"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check15() {
    local CODE="D-15"
    local CAT="접근관리"
    local NAME="관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한"
    local IMP="하"
    local STD="Listener 관련 설정 파일에 대한 권한이 관리자로 설정되어 있으며, Listener로 파라미터를 변경할 수 없게 옵션이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Oracle Listener가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 Oracle의 리스너(Listener) 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check16() {
    local CODE="D-16"
    local CAT="접근관리"
    local NAME="Windows 인증 모드 사용"
    local IMP="하"
    local STD="Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우 sa 계정 활성화 시 강력한 암호 정책을 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Windows 인증 모드가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 MSSQL의 Windows 인증 모드를 지원하지 않습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check17() {
    local CODE="D-17"
    local CAT="옵션관리"
    local NAME="Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한"
    local IMP="하"
    local STD="Audit Table 접근 권한이 관리자 계정으로 설정한 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Audit Table이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 RDBMS의 Audit Table 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check18() {
    local CODE="D-18"
    local CAT="옵션관리"
    local NAME="응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"
    local IMP="상"
    local STD="DBA 계정의 Role이 Public으로 설정되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 PUBLIC Role이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 RDBMS의 PUBLIC Role 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check19() {
    local CODE="D-19"
    local CAT="옵션관리"
    local NAME="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"
    local IMP="상"
    local STD="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 FALSE로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Oracle OS 인증 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 Oracle의 OS 인증 관련 파라미터가 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check20() {
    local CODE="D-20"
    local CAT="옵션관리"
    local NAME="인가되지 않은 Object Owner의 제한"
    local IMP="하"
    local STD="Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Object Owner 개념이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 RDBMS의 스키마/Object Owner 개념이 없습니다.\n해당 항목은 RDBMS 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check21() {
    local CODE="D-21"
    local CAT="옵션관리"
    local NAME="인가되지 않은 GRANT OPTION 사용 제한"
    local IMP="중"
    local STD="WITH_GRANT_OPTION이 ROLE에 의하여 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 GRANT OPTION이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 RDBMS의 GRANT OPTION 개념이 없습니다.\n해당 항목은 RDBMS 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check22() {
    local CODE="D-22"
    local CAT="옵션관리"
    local NAME="데이터베이스의 자원 제한 기능을 TRUE로 설정"
    local IMP="하"
    local STD="RESOURCE_LIMIT 설정이 TRUE로 되어있는 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 Oracle RESOURCE_LIMIT 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 Oracle의 RESOURCE_LIMIT 파라미터가 없습니다.\nRedis는 maxmemory, maxclients 등 별도의 자원 제한 파라미터를 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check23() {
    local CODE="D-23"
    local CAT="옵션관리"
    local NAME="xp_cmdshell 사용 제한"
    local IMP="상"
    local STD="xp_cmdshell이 비활성화 되어 있거나, 활성화 되어 있으면 다음의 조건을 모두 만족하는 경우 1. public의 실행(Execute) 권한이 부여되어 있지 않은 경우 2. 서비스 계정(애플리케이션 연동)에 sysadmin 권한이 부여되어 있지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 MSSQL xp_cmdshell 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 MSSQL의 xp_cmdshell 확장 저장 프로시저가 없습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check24() {
    local CODE="D-24"
    local CAT="옵션관리"
    local NAME="Registry Procedure 권한 제한"
    local IMP="상"
    local STD="제한이 필요한 시스템 확장 저장 프로시저들이 DBA 외 guest/public에게 부여되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="N/A"
    local DESC="Redis는 MSSQL Registry Procedure가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nRedis는 MSSQL의 Registry 접근 확장 저장 프로시저가 없습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check25() {
    local CODE="D-25"
    local CAT="패치관리"
    local NAME="주기적 보안 패치 및 벤더 권고 사항 적용"
    local IMP="상"
    local STD="보안 패치가 적용된 버전을 사용하는 경우"
    local RES=""
    local DESC=""
    local DT=""

    local RES="M"
    local DESC="현재 버전 확인 후 최신 패치 적용 여부 수동 확인 필요"

    DT="[현재 버전]\nRedis $DB_VERSION\n\n※ 최신 버전은 Redis 공식 사이트에서 확인\nhttps://redis.io/download"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check26() {
    local CODE="D-26"
    local CAT="패치관리"
    local NAME="데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정"
    local IMP="상"
    local STD="DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 로그 파일 설정 확인
    local LOGFILE=$($REDIS_CMD CONFIG GET logfile 2>/dev/null | tail -1)
    local LOGLEVEL=$($REDIS_CMD CONFIG GET loglevel 2>/dev/null | tail -1)

    # slowlog 설정 확인
    local SLOWLOG_TIME=$($REDIS_CMD CONFIG GET slowlog-log-slower-than 2>/dev/null | tail -1)
    local SLOWLOG_LEN=$($REDIS_CMD CONFIG GET slowlog-max-len 2>/dev/null | tail -1)

    DT="[로그 설정]\nlogfile: $LOGFILE\nloglevel: $LOGLEVEL\n\n[Slowlog 설정]\nslowlog-log-slower-than: $SLOWLOG_TIME (마이크로초)\nslowlog-max-len: $SLOWLOG_LEN"

    if [ -z "$LOGFILE" ] || [ "$LOGFILE" = '""' ] || [ "$LOGFILE" = "''" ]; then
        RES="N"
        DESC="로그 파일(logfile)이 설정되지 않음"
    else
        RES="M"
        DESC="로그 파일이 설정됨 - 백업 정책 확인 필요"
        DT="${DT}\n\n※ logfile이 설정되어 있습니다."
        DT="${DT}\n※ 주기적인 백업 실시 여부는 인터뷰를 통해 확인하세요."
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}


#================================================================
# EXECUTE
#================================================================

echo ""
echo "  $META_PLAT Security Assessment v$META_VER [$META_STD]"
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  호스트: $SYS_HOST"
echo "  DBMS: $META_PLAT $DB_VERSION"
echo ""
echo "  [진단 시작]"
echo "  ─────────────────────────────────────────────────────────"
echo ""

# XML 헤더
cat > "$OUTPUT_FILE" << XMLEOF
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
            <n>$META_PLAT $DB_VERSION</n>
            <fn>$META_PLAT</fn>
        </os>
        <kn>$DB_VERSION</kn>
        <arch>$(uname -m)</arch>
        <net>
            <ip>${DB_HOST:-localhost}</ip>
            <all><![CDATA[Host: ${DB_HOST:-localhost}, Port: ${DB_PORT:-N/A}]]></all>
        </net>
    </sys>
    <results>
XMLEOF

# 진단 실행
    check01
    check02
    check03
    check04
    check05
    check06
    check07
    check08
    check09
    check10
    check11
    check12
    check13
    check14
    check15
    check16
    check17
    check18
    check19
    check20
    check21
    check22
    check23
    check24
    check25
    check26

# XML 종료
cat >> "$OUTPUT_FILE" << XMLEOF
    </results>
</seedgen>
XMLEOF

#================================================================
# CLEANUP
#================================================================
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  점검이 완료되었습니다!"
echo "  호스트: $SYS_HOST"
echo "  결과 파일: $OUTPUT_FILE"
echo ""

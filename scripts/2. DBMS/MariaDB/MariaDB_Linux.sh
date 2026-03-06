#!/bin/bash
#================================================================
# MariaDB_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : MariaDB_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="MariaDB"
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
echo " MariaDB 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# mariadb 또는 mysql 클라이언트 확인
MARIA_CLIENT=$(which mariadb 2>/dev/null)
if [ -z "$MARIA_CLIENT" ]; then
    MARIA_CLIENT=$(which mysql 2>/dev/null)
fi

if [ -z "$MARIA_CLIENT" ]; then
    echo -n "MariaDB Client Path (not found in PATH): "
    read MARIA_CLIENT
    if [ ! -x "$MARIA_CLIENT" ]; then
        echo "[!] MariaDB 클라이언트를 찾을 수 없습니다."
        exit 1
    fi
fi

# 연결 정보 입력
echo -n "Host (default: localhost): "
read DB_HOST
DB_HOST=${DB_HOST:-localhost}

echo -n "Port (default: 3306): "
read DB_PORT
DB_PORT=${DB_PORT:-3306}

echo -n "User (default: root): "
read DB_USER
DB_USER=${DB_USER:-root}

echo -n "Password (empty for unix_socket auth): "
read -s DB_PASS
echo ""

# MariaDB 연결 명령어
if [ -z "$DB_PASS" ]; then
    MARIA_CMD="$MARIA_CLIENT -h $DB_HOST -P $DB_PORT -u $DB_USER -N -s"
else
    MARIA_CMD="$MARIA_CLIENT -h $DB_HOST -P $DB_PORT -u $DB_USER -p$DB_PASS -N -s"
fi

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
DB_VERSION=$($MARIA_CMD -e "SELECT VERSION();" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "[!] MariaDB 연결 실패"
    exit 1
fi
echo "[OK] MariaDB $DB_VERSION 연결 성공"
echo ""

# MariaDB 버전 체크 (10.3 이상, 10.4 이상 등)
MAJOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f1)
MINOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f2)

# MariaDB 10.3+ 여부 (비밀번호 재사용 기능)
IS_103_OR_HIGHER=0
if [ "$MAJOR_VERSION" -ge 10 ] && [ "$MINOR_VERSION" -ge 3 ] 2>/dev/null; then
    IS_103_OR_HIGHER=1
elif [ "$MAJOR_VERSION" -ge 11 ] 2>/dev/null; then
    IS_103_OR_HIGHER=1
fi

# MariaDB 10.4+ 여부 (unix_socket 기본 인증)
IS_104_OR_HIGHER=0
if [ "$MAJOR_VERSION" -ge 10 ] && [ "$MINOR_VERSION" -ge 4 ] 2>/dev/null; then
    IS_104_OR_HIGHER=1
elif [ "$MAJOR_VERSION" -ge 11 ] 2>/dev/null; then
    IS_104_OR_HIGHER=1
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

    # 기본 계정 확인
    local ROOT_ACCOUNTS=$($MARIA_CMD -e "SELECT user, host, plugin FROM mysql.user WHERE user='root';" 2>/dev/null)

    # 비밀번호 없는 계정 확인 (unix_socket 인증 및 시스템 계정은 제외)
    # mariadb.sys: MariaDB 시스템 계정 (비밀번호 불필요)
    # mysql.sys, mysql.session, mysql.infoschema: MySQL 호환 시스템 계정
    # MariaDB 10.2 미만에서는 password 컬럼도 확인 필요
    local NO_PASS_ACCOUNTS=""
    if [ "$MAJOR_VERSION" -eq 10 ] && [ "$MINOR_VERSION" -lt 2 ] 2>/dev/null; then
        # MariaDB 10.2 미만: password 컬럼과 authentication_string 둘 다 확인
        NO_PASS_ACCOUNTS=$($MARIA_CMD -e "
            SELECT user, host, plugin FROM mysql.user
            WHERE ((authentication_string='' OR authentication_string IS NULL)
                   AND (password='' OR password IS NULL))
            AND plugin NOT IN ('unix_socket', 'auth_socket', 'mysql_no_login')
            AND user NOT IN ('mariadb.sys', 'mysql.sys', 'mysql.session', 'mysql.infoschema')
            AND user != '';" 2>/dev/null)
    else
        # MariaDB 10.2 이상: authentication_string만 확인
        NO_PASS_ACCOUNTS=$($MARIA_CMD -e "
            SELECT user, host, plugin FROM mysql.user
            WHERE (authentication_string='' OR authentication_string IS NULL)
            AND plugin NOT IN ('unix_socket', 'auth_socket', 'mysql_no_login')
            AND user NOT IN ('mariadb.sys', 'mysql.sys', 'mysql.session', 'mysql.infoschema')
            AND user != '';" 2>/dev/null)
    fi

    # invalid 상태 계정 확인 (account_locked)
    local LOCKED_INFO=""
    if [ "$IS_104_OR_HIGHER" == "1" ]; then
        LOCKED_INFO=$($MARIA_CMD -e "SELECT user, host, account_locked FROM mysql.user WHERE account_locked='Y';" 2>/dev/null)
    fi

    DT="[root 계정 현황]\n$ROOT_ACCOUNTS\n\n[비밀번호 미설정 계정 (시스템 계정/unix_socket 제외)]\n$NO_PASS_ACCOUNTS"
    [ -n "$LOCKED_INFO" ] && DT="${DT}\n\n[잠긴 계정]\n$LOCKED_INFO"

    if [ -z "$NO_PASS_ACCOUNTS" ]; then
        RES="Y"
        DESC="모든 계정에 비밀번호 또는 unix_socket 인증 설정됨"
    else
        RES="N"
        DESC="비밀번호가 설정되지 않은 계정 존재"
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

    local RES="M"
    local DESC="계정 목록 수동 확인 필요"

    # 전체 계정 목록 (MariaDB 10.4+는 account_locked 컬럼 있음)
    local ALL_ACCOUNTS=""
    if [ "$IS_104_OR_HIGHER" == "1" ]; then
        ALL_ACCOUNTS=$($MARIA_CMD -e "
            SELECT user, host, plugin, account_locked,
                   IF(authentication_string='' OR authentication_string IS NULL, 'NO_PASS', 'HAS_PASS') as password_status
            FROM mysql.user ORDER BY user;" 2>/dev/null)
    else
        ALL_ACCOUNTS=$($MARIA_CMD -e "
            SELECT user, host, plugin, 'N/A' as locked,
                   IF(authentication_string='' OR authentication_string IS NULL, 'NO_PASS', 'HAS_PASS') as password_status
            FROM mysql.user ORDER BY user;" 2>/dev/null)
    fi

    # 익명 계정 확인
    local ANON_ACCOUNTS=$($MARIA_CMD -e "SELECT user, host FROM mysql.user WHERE user='';" 2>/dev/null)

    # 전체 계정 수
    local TOTAL_COUNT=$($MARIA_CMD -e "SELECT COUNT(*) FROM mysql.user;" 2>/dev/null)

    DT="[전체 계정 목록 (총 ${TOTAL_COUNT}개)]\nuser\thost\tplugin\tlocked\tpassword_status\n$ALL_ACCOUNTS\n\n[익명 계정]\n$ANON_ACCOUNTS\n\n※ 업무상 불필요한 계정 여부를 확인하세요."

    if [ -n "$ANON_ACCOUNTS" ]; then
        RES="N"
        DESC="익명 계정이 존재함"
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

    # MariaDB 비밀번호 검증 플러그인 확인 (simple_password_check, cracklib_password_check)
    local SIMPLE_PW=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'simple_password_check%';" 2>/dev/null)
    local CRACKLIB_PW=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'cracklib_password_check%';" 2>/dev/null)

    # 플러그인 로드 상태 확인 (인증 플러그인이 아닌 비밀번호 검증 플러그인만 확인)
    local PW_PLUGINS=$($MARIA_CMD -e "
        SELECT plugin_name, plugin_status FROM information_schema.plugins
        WHERE plugin_name IN ('simple_password_check', 'cracklib_password_check');" 2>/dev/null)

    # 비밀번호 만료 설정 확인
    local PW_EXPIRE=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'default_password_lifetime';" 2>/dev/null)

    DT="[비밀번호 검증 플러그인]\n$PW_PLUGINS\n\n[simple_password_check 설정]\n$SIMPLE_PW\n\n[cracklib_password_check 설정]\n$CRACKLIB_PW\n\n[비밀번호 만료 설정]\n$PW_EXPIRE"

    # 플러그인 활성화 여부 확인
    local HAS_ACTIVE_PLUGIN=0
    if echo "$PW_PLUGINS" | grep -qi "ACTIVE"; then
        HAS_ACTIVE_PLUGIN=1
    fi

    if [ "$HAS_ACTIVE_PLUGIN" -eq 0 ]; then
        RES="N"
        DESC="비밀번호 검증 플러그인(simple_password_check 또는 cracklib)이 비활성화됨"
        return
    fi

    # 설정값 검증
    local VULN_REASONS=""

    # simple_password_check_minimal_length >= 8
    local MIN_LENGTH=$(echo "$SIMPLE_PW" | grep -i "minimal_length" | awk '{print $2}')
    if [ -n "$MIN_LENGTH" ] && [ "$MIN_LENGTH" -lt 8 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}비밀번호 최소 길이가 8 미만($MIN_LENGTH)\n"
    fi

    # simple_password_check_digits >= 1
    local DIGITS=$(echo "$SIMPLE_PW" | grep -i "digits" | awk '{print $2}')
    if [ -n "$DIGITS" ] && [ "$DIGITS" -lt 1 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}숫자 요구 미설정(digits=$DIGITS)\n"
    fi

    # simple_password_check_letters_same_case >= 1
    local LETTERS=$(echo "$SIMPLE_PW" | grep -i "letters_same_case" | awk '{print $2}')
    if [ -n "$LETTERS" ] && [ "$LETTERS" -lt 1 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}문자 요구 미설정(letters_same_case=$LETTERS)\n"
    fi

    # simple_password_check_other_characters >= 1 (특수문자 요구)
    local OTHER_CHARS=$(echo "$SIMPLE_PW" | grep -i "other_characters" | awk '{print $2}')
    if [ -n "$OTHER_CHARS" ] && [ "$OTHER_CHARS" -lt 1 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}특수문자 요구 미설정(other_characters=$OTHER_CHARS)\n"
    fi

    # default_password_lifetime: 0이면 미설정, 90일 초과이면 취약
    local PW_LIFETIME=$(echo "$PW_EXPIRE" | awk '{print $2}')
    if [ -n "$PW_LIFETIME" ]; then
        if [ "$PW_LIFETIME" -eq 0 ] 2>/dev/null; then
            VULN_REASONS="${VULN_REASONS}비밀번호 만료 기간 미설정(lifetime=0)\n"
        elif [ "$PW_LIFETIME" -gt 90 ] 2>/dev/null; then
            VULN_REASONS="${VULN_REASONS}비밀번호 만료 기간 90일 초과(lifetime=${PW_LIFETIME}일)\n"
        fi
    fi

    if [ -n "$VULN_REASONS" ]; then
        RES="N"
        DESC="비밀번호 정책 설정이 미흡함"
        DT="${DT}\n\n[취약 항목]\n$VULN_REASONS"
    else
        RES="Y"
        DESC="비밀번호 검증 플러그인 및 정책이 적절히 설정됨"
    fi

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

    local RES="M"
    local DESC="관리자 권한 계정 수동 확인 필요"

    # SUPER 권한 보유 계정
    local SUPER_USERS=$($MARIA_CMD -e "SELECT user, host FROM mysql.user WHERE Super_priv='Y';" 2>/dev/null)

    # ALL PRIVILEGES 보유 계정
    local ALL_PRIV_USERS=$($MARIA_CMD -e "SELECT user, host FROM mysql.user WHERE Select_priv='Y' AND Insert_priv='Y' AND Update_priv='Y' AND Delete_priv='Y' AND Create_priv='Y' AND Drop_priv='Y' AND Grant_priv='Y';" 2>/dev/null)

    DT="[SUPER 권한 보유 계정]\n$SUPER_USERS\n\n[ALL PRIVILEGES 보유 계정]\n$ALL_PRIV_USERS"

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

    # password_reuse_check 플러그인은 MariaDB 10.7.0부터 기본 설치됨
    # 그 이전 버전은 별도 설치 필요
    local REUSE_PLUGIN=$($MARIA_CMD -e "SELECT plugin_name, plugin_status FROM information_schema.plugins WHERE plugin_name = 'password_reuse_check';" 2>/dev/null)
    local REUSE_VARS=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'password_reuse_check%';" 2>/dev/null)

    DT="[password_reuse_check 플러그인]\n$REUSE_PLUGIN\n\n[설정값]\n$REUSE_VARS"

    if echo "$REUSE_PLUGIN" | grep -qi "ACTIVE"; then
        # 플러그인 활성화됨 - 설정값 확인
        local INTERVAL=$(echo "$REUSE_VARS" | grep -i "interval" | awk '{print $2}')
        if [ -n "$INTERVAL" ] && [ "$INTERVAL" -gt 0 ] 2>/dev/null; then
            RES="Y"
            DESC="비밀번호 재사용 제한 플러그인이 활성화됨 (interval: $INTERVAL)"
        else
            RES="N"
            DESC="비밀번호 재사용 제한 플러그인 활성화됨, 설정값 확인 필요"
        fi
    elif [ -n "$REUSE_PLUGIN" ]; then
        # 플러그인 존재하지만 비활성화
        RES="N"
        DESC="비밀번호 재사용 제한 플러그인(password_reuse_check)이 비활성화됨"
    else
        # 플러그인 미설치 - 수동 확인 필요
        RES="M"
        DESC="비밀번호 재사용 제한 설정 수동 확인 필요"
        DT="${DT}\n\n[참고]\npassword_reuse_check 플러그인이 설치되지 않았습니다.\nMariaDB 10.7.0 이상에서 기본 제공되며, 이전 버전은 별도 설치가 필요합니다.\n플러그인, 써드파티 솔루션, 내부 정책 등을 통해 비밀번호 재사용 제한 여부를 확인하세요."
    fi

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

    local RES="M"
    local DESC="사용자별 개별 계정 사용 여부 수동 확인 필요"

    local USER_LIST=$($MARIA_CMD -e "SELECT user, host FROM mysql.user WHERE user != '' ORDER BY user;" 2>/dev/null)

    DT="[계정 목록 - 공용 계정 여부 확인 필요]\n$USER_LIST\n\n※ 업무별/사용자별 개별 계정 사용 여부를 확인하세요."

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

    # MariaDB 프로세스 사용자 확인
    local MARIA_PROC=$(ps -ef | grep -E "mariadbd|mysqld" | grep -v grep | head -1)
    local PROC_USER=$(echo "$MARIA_PROC" | awk '{print $1}')

    DT="[MariaDB 프로세스]\n$MARIA_PROC"

    if [ -z "$MARIA_PROC" ]; then
        RES="N/A"
        DESC="MariaDB 프로세스를 찾을 수 없음"
    elif [ "$PROC_USER" == "root" ]; then
        RES="N"
        DESC="MariaDB가 root 권한으로 구동 중"
    else
        RES="Y"
        DESC="MariaDB가 일반 계정($PROC_USER)으로 구동 중"
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

    # 인증 플러그인 확인
    local AUTH_PLUGINS=$($MARIA_CMD -e "SELECT user, host, plugin FROM mysql.user;" 2>/dev/null)

    DT="[계정별 인증 플러그인]\n$AUTH_PLUGINS\n\n※ 권장 플러그인: unix_socket, ed25519, caching_sha2_password\n※ 허용 플러그인: mysql_native_password (SHA-1, 권고 강도 미달)\n※ 취약한 플러그인: mysql_old_password (MD5)"

    # mysql_old_password 사용 계정 확인 (MD5 기반으로 취약)
    local WEAK_AUTH=$(echo "$AUTH_PLUGINS" | grep -i "mysql_old_password")

    # mysql_native_password 사용 계정 확인 (SHA-1 기반, 권고 강도 미달)
    local NATIVE_AUTH=$($MARIA_CMD -e "
        SELECT CONCAT(user, '@', host) as account, plugin FROM mysql.user
        WHERE plugin = 'mysql_native_password'
        AND user NOT IN ('mariadb.sys', 'mysql.sys', 'mysql.session', 'mysql.infoschema')
        AND user != '';" 2>/dev/null)

    if [ -n "$WEAK_AUTH" ]; then
        RES="N"
        DESC="취약한 인증 플러그인(mysql_old_password) 사용 계정 존재"
        DT="${DT}\n\n[취약 계정 - mysql_old_password]\n$WEAK_AUTH"
    elif [ -n "$NATIVE_AUTH" ]; then
        RES="Y"
        DESC="mysql_native_password는 SHA-1 기반으로 KISA 권고 보안 강도(112비트 이상)에 미달하여, ed25519 또는 caching_sha2_password 방식으로의 전환을 권고함"
        DT="${DT}\n\n[mysql_native_password 사용 계정]\n$NATIVE_AUTH\n\n※ ed25519 또는 caching_sha2_password로 전환을 권고합니다."
    else
        RES="Y"
        DESC="안전한 인증 플러그인 사용 중"
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

    # MariaDB 10.4+ 여부 확인
    if [ "$IS_104_OR_HIGHER" == "1" ]; then
        # MariaDB 10.4.2+에서 max_password_errors 도입
        local MAX_ERRORS=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'max_password_errors';" 2>/dev/null)

        if [ -n "$MAX_ERRORS" ]; then
            local ERROR_VAL=$(echo "$MAX_ERRORS" | awk '{print $2}')
            DT="[로그인 실패 잠금 설정]\nmax_password_errors: $ERROR_VAL\n\n※ 기준: 5회 이하로 설정 필요"

            if [ "$ERROR_VAL" == "0" ] || [ "$ERROR_VAL" == "4294967295" ]; then
                RES="N"
                DESC="로그인 실패 잠금 정책이 설정되지 않음 (무제한)"
            elif [ "$ERROR_VAL" -gt 5 ] 2>/dev/null; then
                RES="N"
                DESC="로그인 실패 허용 횟수가 5회 초과 (현재: $ERROR_VAL)"
                DT="${DT}\n\n[취약] max_password_errors 값이 5회 초과로 설정됨"
            else
                RES="Y"
                DESC="로그인 실패 잠금 정책 설정됨 (max_password_errors: $ERROR_VAL)"
            fi
        else
            # max_password_errors 변수가 없는 경우 (10.4.0~10.4.1)
            RES="M"
            DESC="max_password_errors 변수 미확인 - 수동 확인 필요"
            DT="[참고]\nMariaDB 10.4.0~10.4.1 버전에서는 max_password_errors가 없을 수 있습니다.\n별도 플러그인 또는 솔루션을 통해 로그인 실패 잠금 정책을 확인하세요."
        fi
    else
        # MariaDB 10.4 미만: 수동 진단
        # connection_control 플러그인 확인 시도
        local CONN_CONTROL=$($MARIA_CMD -e "SHOW PLUGINS;" 2>/dev/null | grep -i "connection_control")
        local CONN_VARS=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'connection_control%';" 2>/dev/null)

        DT="[MariaDB 버전]\n$DB_VERSION (10.4 미만)\n\n[connection_control 플러그인]\n$CONN_CONTROL\n\n[설정값]\n$CONN_VARS"

        if echo "$CONN_CONTROL" | grep -qi "ACTIVE"; then
            # connection_control_failed_connections_threshold 값 확인
            local THRESHOLD=$(echo "$CONN_VARS" | grep -i "threshold" | awk '{print $2}')
            if [ -n "$THRESHOLD" ] && [ "$THRESHOLD" -le 5 ] 2>/dev/null; then
                RES="Y"
                DESC="connection_control 플러그인 활성화됨 (threshold: $THRESHOLD)"
            else
                RES="N"
                DESC="connection_control threshold 값이 5 초과 또는 미설정"
            fi
        else
            # 10.4 미만 버전에서 플러그인 미설치: 수동 진단 필요
            RES="M"
            DESC="MariaDB 10.4 미만 - 로그인 실패 잠금 정책 수동 확인 필요"
            DT="${DT}\n\n[수동 진단 필요]\nMariaDB 10.4 미만 버전은 자체적으로 로그인 실패 잠금 기능을 지원하지 않습니다.\n다음 사항을 확인하세요:\n1. connection_control 플러그인 설치 여부\n2. 방화벽, IPS 등 네트워크 장비의 brute-force 방어 설정\n3. fail2ban 등 외부 솔루션 사용 여부\n4. 애플리케이션 레벨의 로그인 시도 제한"
        fi
    fi

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

    local RES="M"
    local DESC="원격 접속 제한 설정 수동 확인 필요"

    # bind-address 확인
    local BIND_ADDR=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'bind_address';" 2>/dev/null)

    # 전체 계정 현황
    local ALL_ACCOUNTS=$($MARIA_CMD -e "SELECT user, host FROM mysql.user ORDER BY user, host;" 2>/dev/null)

    # '%' 호스트 허용 계정 확인
    local REMOTE_ACCOUNTS=$($MARIA_CMD -e "SELECT user, host FROM mysql.user WHERE host='%';" 2>/dev/null)

    # skip_networking 확인
    local SKIP_NET=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'skip_networking';" 2>/dev/null)

    DT="[bind_address 설정]\n$BIND_ADDR\n\n[skip_networking 설정]\n$SKIP_NET\n\n[전체 계정 현황]\n$ALL_ACCOUNTS\n\n[모든 호스트 접속 허용 계정 (host='%')]\n$REMOTE_ACCOUNTS\n\n[수동 확인 필요]\n1. 방화벽/네트워크 장비를 통한 접근 제어 설정 여부\n2. 허용된 원격 접속 계정의 업무 필요성\n3. bind_address가 특정 IP로 제한되어 있는지 확인"

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

    # mysql DB 스키마 권한 보유 계정 확인 (스키마 레벨)
    local MYSQL_DB_GRANTS=$($MARIA_CMD -e "
        SELECT DISTINCT GRANTEE
        FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
        WHERE TABLE_SCHEMA IN ('mysql', 'sys', 'information_schema', 'performance_schema')
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mariadb.%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    # mysql DB 테이블 권한 보유 계정 확인 (테이블 레벨)
    local TABLE_GRANTS=$($MARIA_CMD -e "
        SELECT DISTINCT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE
        FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES
        WHERE TABLE_SCHEMA IN ('mysql', 'sys', 'performance_schema')
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mariadb.%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    DT="[mysql DB 스키마 권한 보유 계정 (root 제외)]\n$MYSQL_DB_GRANTS\n\n[mysql DB 테이블 권한 보유 계정 (root 제외)]\n$TABLE_GRANTS"

    local HAS_VULN=0
    if [ -n "$MYSQL_DB_GRANTS" ]; then
        HAS_VULN=1
    fi
    if [ -n "$TABLE_GRANTS" ]; then
        HAS_VULN=1
    fi

    if [ "$HAS_VULN" -eq 0 ]; then
        RES="Y"
        DESC="일반 사용자에게 시스템 DB 접근 권한 없음"
    else
        RES="M"
        DESC="시스템 DB 접근 권한 수동 확인 필요"
        DT="${DT}\n\n※ 위 계정들의 시스템 테이블 접근 권한이 업무상 필요한지 확인하세요."
    fi

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
    local DESC="MariaDB는 리스너 개념이 없음 (Oracle 전용)"
    local DT="[참고]\nMariaDB는 Oracle과 달리 별도의 리스너(Listener) 프로세스가 없습니다.\nMariaDB는 서버 프로세스(mariadbd/mysqld)가 직접 클라이언트 연결을 처리합니다.\n\n이 점검 항목은 Oracle DBMS에만 해당됩니다."

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
    local DESC="MariaDB Linux 환경에서는 ODBC/OLE-DB 점검 대상 없음 (Windows 전용)"

    DT="[N/A 사유]\nODBC/OLE-DB 데이터 소스 및 드라이버 관리는 Windows 클라이언트 OS 영역입니다.\nMariaDB Linux 서버에서는 점검 대상이 없으므로 해당 항목이 적용되지 않습니다.\n\n해당 항목은 Windows MSSQL 전용 보안 항목입니다."

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

    local CHECKED_FILES=""
    local VULNERABLE_FILES=""

    # MariaDB 설정 파일 위치들
    for CNF_PATH in "/etc/my.cnf" "/etc/my.cnf.d/server.cnf" "/etc/mysql/my.cnf" "/etc/mysql/mariadb.conf.d/50-server.cnf" "$HOME/.my.cnf"; do
        if [ -e "$CNF_PATH" ]; then
            local REAL_PATH="$CNF_PATH"
            local SYMLINK_INFO=""

            # 심볼릭 링크인 경우 실제 파일 경로 확인
            if [ -L "$CNF_PATH" ]; then
                REAL_PATH=$(readlink -f "$CNF_PATH" 2>/dev/null)
                SYMLINK_INFO=" -> $REAL_PATH (symlink)"
            fi

            local FILE_PERM=$(stat -c "%a" "$REAL_PATH" 2>/dev/null)
            local FILE_OWNER=$(stat -c "%U:%G" "$REAL_PATH" 2>/dev/null)
            CHECKED_FILES="${CHECKED_FILES}${CNF_PATH}${SYMLINK_INFO}: ${FILE_PERM} (${FILE_OWNER})\n"

            # 권한 기준: 640 또는 600 이하 (other에게 읽기 권한 없어야 함)
            # 8진수 비교: 권한이 640(=416) 초과이면 취약
            # 실제로 other 권한이 있는지 확인 (마지막 자리가 0이 아니면 취약)
            local OTHER_PERM=$((FILE_PERM % 10))
            if [ "$OTHER_PERM" -gt 0 ] 2>/dev/null; then
                VULNERABLE_FILES="${VULNERABLE_FILES}${CNF_PATH}${SYMLINK_INFO}: ${FILE_PERM} (other 권한 존재)\n"
            elif [ "$FILE_PERM" -gt 640 ] 2>/dev/null; then
                VULNERABLE_FILES="${VULNERABLE_FILES}${CNF_PATH}${SYMLINK_INFO}: ${FILE_PERM} (640 초과)\n"
            fi
        fi
    done

    if [ -z "$CHECKED_FILES" ]; then
        RES="N/A"
        DESC="설정 파일을 찾을 수 없음"
        DT="MariaDB 설정 파일을 찾을 수 없습니다."
    elif [ -z "$VULNERABLE_FILES" ]; then
        RES="Y"
        DESC="주요 설정 파일 권한이 적절함 (640/600 이하)"
        DT="[파일 권한 현황]\n$CHECKED_FILES\n\n※ 권한 기준: 640(rw-r-----) 또는 600(rw-------) 이하"
    else
        RES="N"
        DESC="주요 설정 파일에 과도한 권한 존재 (640/600 초과)"
        DT="[취약 파일]\n$VULNERABLE_FILES\n[전체 파일]\n$CHECKED_FILES\n\n※ 권한 기준: 640(rw-r-----) 또는 600(rw-------) 이하 권장\n※ other(기타 사용자)에게 읽기 권한이 없어야 함"
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
    local DESC="MariaDB는 Oracle trace 파일이 없음 (Oracle 전용)"
    local DT="[참고]\nMariaDB는 Oracle의 trace 파일(.trc) 개념이 없습니다.\nMariaDB는 별도의 로그 파일(error log, slow query log, general log 등)을 사용합니다.\n\n이 점검 항목은 Oracle DBMS에만 해당됩니다."

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
    local DESC="MariaDB는 Windows 인증 모드가 없음 (MSSQL 전용)"
    local DT="[참고]\nWindows 인증 모드는 Microsoft SQL Server 전용 기능입니다.\nMariaDB는 자체 인증 플러그인(mysql_native_password, ed25519, unix_socket 등)을 사용합니다.\n\n이 점검 항목은 MSSQL에만 해당됩니다."

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
    local DESC="MariaDB는 Oracle AUD$ 테이블이 없음 (Oracle 전용)"
    local DT="[N/A 사유]\n해당 항목은 Oracle의 AUD$ 감사 테이블에 대한 접근 권한을 점검하는 항목입니다.\nMariaDB는 Oracle과 같은 AUD$ 테이블이 없으므로 본 항목은 적용되지 않습니다.\n\n※ MariaDB의 감사 기능은 server_audit 플러그인 또는 general_log를 사용합니다."

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
    local DESC="MariaDB는 Oracle PUBLIC Role 개념이 없음 (Oracle 전용)"
    local DT="[N/A 사유]\n해당 항목은 Oracle의 PUBLIC Role에 부여된 권한을 점검하는 항목입니다.\nMariaDB는 Oracle의 PUBLIC Role 개념이 없으며, 개별 사용자에게 직접 권한을 부여하는 방식을 사용합니다.\n\n해당 항목은 Oracle DBMS에만 해당됩니다."

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
    local DESC="MariaDB는 Oracle OS_ROLES 파라미터가 없음 (Oracle 전용)"
    local DT="[N/A 사유]\n해당 항목은 Oracle의 OS_ROLES, REMOTE_OS_AUTHENT, REMOTE_OS_ROLES 파라미터를\nFALSE로 설정했는지 점검하는 항목입니다.\nMariaDB는 이러한 파라미터가 없으므로 본 항목은 적용되지 않습니다.\n\n※ MariaDB에서 OS 인증은 unix_socket 플러그인을 통해 제한적으로 지원됩니다."

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
    local DESC="MariaDB는 Oracle Object Owner 개념이 다르게 적용됨 (Oracle 전용)"
    local DT="[N/A 사유]\n해당 항목은 Oracle의 스키마 기반 Object Owner를 점검하는 항목입니다.\nMariaDB는 Oracle과 같은 스키마 기반 Object Owner 개념이 다르며,\n데이터베이스(스키마) 단위로 권한을 관리합니다.\n\n해당 항목은 Oracle DBMS에만 해당됩니다."

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

    # mysql.user의 Grant_priv 확인 (전역 GRANT 권한)
    local GRANT_USERS=$($MARIA_CMD -e "
        SELECT CONCAT(user, '@', host) as account
        FROM mysql.user
        WHERE grant_priv = 'Y'
        AND user NOT IN ('root', 'mariadb.sys', 'mysql.sys', 'mysql.session', 'mysql.infoschema')
        AND user != '';" 2>/dev/null)

    # IS_GRANTABLE 확인 (WITH GRANT OPTION으로 부여된 권한)
    local IS_GRANTABLE=$($MARIA_CMD -e "
        SELECT DISTINCT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE
        FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
        WHERE IS_GRANTABLE = 'YES'
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mariadb.%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    # 테이블 레벨 IS_GRANTABLE 확인
    local TABLE_GRANTABLE=$($MARIA_CMD -e "
        SELECT DISTINCT GRANTEE, TABLE_SCHEMA, TABLE_NAME
        FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES
        WHERE IS_GRANTABLE = 'YES'
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mariadb.%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    DT="[전역 GRANT 권한 보유 계정]\n$GRANT_USERS\n\n[IS_GRANTABLE 설정된 스키마 권한]\n$IS_GRANTABLE\n\n[IS_GRANTABLE 설정된 테이블 권한]\n$TABLE_GRANTABLE"

    local HAS_ISSUE=0
    if [ -n "$GRANT_USERS" ]; then
        HAS_ISSUE=1
    fi
    if [ -n "$IS_GRANTABLE" ]; then
        HAS_ISSUE=1
    fi
    if [ -n "$TABLE_GRANTABLE" ]; then
        HAS_ISSUE=1
    fi

    if [ "$HAS_ISSUE" -eq 0 ]; then
        RES="Y"
        DESC="일반 사용자에게 GRANT 권한 없음"
    else
        RES="M"
        DESC="GRANT 권한 또는 IS_GRANTABLE 설정 수동 확인 필요"
        DT="${DT}\n\n※ 업무상 불필요하게 WITH GRANT OPTION이 설정된 권한이 있는지 확인하세요."
    fi

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
    local DESC="MariaDB는 sa 계정이 없음 (MSSQL 전용)"
    local DT="[참고]\nsa(System Administrator) 계정은 Microsoft SQL Server의 기본 관리자 계정입니다.\nMariaDB는 sa 계정이 없으며, 대신 root 계정을 사용합니다.\n\nMariaDB의 root 계정 보안은 D-01, D-07, D-10 항목에서 점검합니다."

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
    local DESC="MariaDB는 xp_cmdshell이 없음 (MSSQL 전용)"
    local DT="[참고]\nxp_cmdshell은 Microsoft SQL Server에서 운영체제 명령을 실행하는 확장 저장 프로시저입니다.\nMariaDB는 xp_cmdshell 기능을 지원하지 않습니다.\n\n이 점검 항목은 MSSQL에만 해당됩니다."

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
    local DESC="MariaDB는 SQL Server 에이전트가 없음 (MSSQL 전용)"
    local DT="[참고]\nSQL Server 에이전트는 Microsoft SQL Server의 작업 스케줄링 서비스입니다.\nMariaDB는 SQL Server 에이전트 기능이 없습니다.\n\nMariaDB에서 작업 스케줄링은 이벤트 스케줄러(Event Scheduler)를 통해 수행됩니다."

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

    DT="[현재 버전]\nMariaDB $DB_VERSION\n\n※ 최신 버전은 MariaDB 공식 사이트에서 확인\nhttps://mariadb.org/download/"

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

    # general_log 확인
    local GENERAL_LOG=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'general_log';" 2>/dev/null)
    local GENERAL_LOG_FILE=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'general_log_file';" 2>/dev/null)

    # MariaDB Audit Plugin (server_audit) 확인
    local AUDIT_PLUGIN=$($MARIA_CMD -e "SELECT plugin_name, plugin_status FROM information_schema.plugins WHERE plugin_name = 'SERVER_AUDIT';" 2>/dev/null)
    local AUDIT_VARS=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'server_audit%';" 2>/dev/null)

    # log_error 확인
    local ERROR_LOG=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'log_error';" 2>/dev/null)

    DT="[General Log]\n$GENERAL_LOG\n$GENERAL_LOG_FILE\n\n[MariaDB Audit Plugin (server_audit)]\n$AUDIT_PLUGIN\n\n[Audit 설정]\n$AUDIT_VARS\n\n[Error Log]\n$ERROR_LOG"

    local GENERAL_ON=0
    local AUDIT_ON=0

    if echo "$GENERAL_LOG" | grep -qi "ON"; then
        GENERAL_ON=1
    fi

    if echo "$AUDIT_PLUGIN" | grep -qi "ACTIVE"; then
        AUDIT_ON=1
    fi

    if [ "$AUDIT_ON" -eq 1 ]; then
        # server_audit 플러그인 활성화 - 백업 여부 인터뷰 필요
        RES="M"
        DESC="server_audit 플러그인 활성화됨 - 백업 여부 확인 필요"
        DT="${DT}\n\n※ 감사 로그 수집은 확인됨. 주기적인 백업 실시 여부는 인터뷰를 통해 확인하세요."
    else
        RES="N"
        DESC="감사 로그가 비활성화됨 (server_audit 미활성화)"
        DT="${DT}\n\n※ general_log는 감사 로그가 아니므로 판단 기준에서 제외합니다.\n※ 운영 환경에서는 server_audit 플러그인 사용을 권고합니다."
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
# MariaDB_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : MariaDB_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="MariaDB"
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
echo " MariaDB 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# mariadb 또는 mysql 클라이언트 확인
MARIA_CLIENT=$(which mariadb 2>/dev/null)
if [ -z "$MARIA_CLIENT" ]; then
    MARIA_CLIENT=$(which mysql 2>/dev/null)
fi

if [ -z "$MARIA_CLIENT" ]; then
    echo -n "MariaDB Client Path (not found in PATH): "
    read MARIA_CLIENT
    if [ ! -x "$MARIA_CLIENT" ]; then
        echo "[!] MariaDB 클라이언트를 찾을 수 없습니다."
        exit 1
    fi
fi

# 연결 정보 입력
echo -n "Host (default: localhost): "
read DB_HOST
DB_HOST=${DB_HOST:-localhost}

echo -n "Port (default: 3306): "
read DB_PORT
DB_PORT=${DB_PORT:-3306}

echo -n "User (default: root): "
read DB_USER
DB_USER=${DB_USER:-root}

echo -n "Password (empty for unix_socket auth): "
read -s DB_PASS
echo ""

# MariaDB 연결 명령어
if [ -z "$DB_PASS" ]; then
    MARIA_CMD="$MARIA_CLIENT -h $DB_HOST -P $DB_PORT -u $DB_USER -N -s"
else
    MARIA_CMD="$MARIA_CLIENT -h $DB_HOST -P $DB_PORT -u $DB_USER -p$DB_PASS -N -s"
fi

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
DB_VERSION=$($MARIA_CMD -e "SELECT VERSION();" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "[!] MariaDB 연결 실패"
    exit 1
fi
echo "[OK] MariaDB $DB_VERSION 연결 성공"
echo ""

# MariaDB 버전 체크 (10.3 이상, 10.4 이상 등)
MAJOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f1)
MINOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f2)

# MariaDB 10.3+ 여부 (비밀번호 재사용 기능)
IS_103_OR_HIGHER=0
if [ "$MAJOR_VERSION" -ge 10 ] && [ "$MINOR_VERSION" -ge 3 ] 2>/dev/null; then
    IS_103_OR_HIGHER=1
elif [ "$MAJOR_VERSION" -ge 11 ] 2>/dev/null; then
    IS_103_OR_HIGHER=1
fi

# MariaDB 10.4+ 여부 (unix_socket 기본 인증)
IS_104_OR_HIGHER=0
if [ "$MAJOR_VERSION" -ge 10 ] && [ "$MINOR_VERSION" -ge 4 ] 2>/dev/null; then
    IS_104_OR_HIGHER=1
elif [ "$MAJOR_VERSION" -ge 11 ] 2>/dev/null; then
    IS_104_OR_HIGHER=1
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

    # 기본 계정 확인
    local ROOT_ACCOUNTS=$($MARIA_CMD -e "SELECT user, host, plugin FROM mysql.user WHERE user='root';" 2>/dev/null)

    # 비밀번호 없는 계정 확인 (unix_socket 인증 및 시스템 계정은 제외)
    # mariadb.sys: MariaDB 시스템 계정 (비밀번호 불필요)
    # mysql.sys, mysql.session, mysql.infoschema: MySQL 호환 시스템 계정
    # MariaDB 10.2 미만에서는 password 컬럼도 확인 필요
    local NO_PASS_ACCOUNTS=""
    if [ "$MAJOR_VERSION" -eq 10 ] && [ "$MINOR_VERSION" -lt 2 ] 2>/dev/null; then
        # MariaDB 10.2 미만: password 컬럼과 authentication_string 둘 다 확인
        NO_PASS_ACCOUNTS=$($MARIA_CMD -e "
            SELECT user, host, plugin FROM mysql.user
            WHERE ((authentication_string='' OR authentication_string IS NULL)
                   AND (password='' OR password IS NULL))
            AND plugin NOT IN ('unix_socket', 'auth_socket', 'mysql_no_login')
            AND user NOT IN ('mariadb.sys', 'mysql.sys', 'mysql.session', 'mysql.infoschema')
            AND user != '';" 2>/dev/null)
    else
        # MariaDB 10.2 이상: authentication_string만 확인
        NO_PASS_ACCOUNTS=$($MARIA_CMD -e "
            SELECT user, host, plugin FROM mysql.user
            WHERE (authentication_string='' OR authentication_string IS NULL)
            AND plugin NOT IN ('unix_socket', 'auth_socket', 'mysql_no_login')
            AND user NOT IN ('mariadb.sys', 'mysql.sys', 'mysql.session', 'mysql.infoschema')
            AND user != '';" 2>/dev/null)
    fi

    # invalid 상태 계정 확인 (account_locked)
    local LOCKED_INFO=""
    if [ "$IS_104_OR_HIGHER" == "1" ]; then
        LOCKED_INFO=$($MARIA_CMD -e "SELECT user, host, account_locked FROM mysql.user WHERE account_locked='Y';" 2>/dev/null)
    fi

    DT="[root 계정 현황]\n$ROOT_ACCOUNTS\n\n[비밀번호 미설정 계정 (시스템 계정/unix_socket 제외)]\n$NO_PASS_ACCOUNTS"
    [ -n "$LOCKED_INFO" ] && DT="${DT}\n\n[잠긴 계정]\n$LOCKED_INFO"

    if [ -z "$NO_PASS_ACCOUNTS" ]; then
        RES="Y"
        DESC="모든 계정에 비밀번호 또는 unix_socket 인증 설정됨"
    else
        RES="N"
        DESC="비밀번호가 설정되지 않은 계정 존재"
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

    local RES="M"
    local DESC="계정 목록 수동 확인 필요"

    # 전체 계정 목록 (MariaDB 10.4+는 account_locked 컬럼 있음)
    local ALL_ACCOUNTS=""
    if [ "$IS_104_OR_HIGHER" == "1" ]; then
        ALL_ACCOUNTS=$($MARIA_CMD -e "
            SELECT user, host, plugin, account_locked,
                   IF(authentication_string='' OR authentication_string IS NULL, 'NO_PASS', 'HAS_PASS') as password_status
            FROM mysql.user ORDER BY user;" 2>/dev/null)
    else
        ALL_ACCOUNTS=$($MARIA_CMD -e "
            SELECT user, host, plugin, 'N/A' as locked,
                   IF(authentication_string='' OR authentication_string IS NULL, 'NO_PASS', 'HAS_PASS') as password_status
            FROM mysql.user ORDER BY user;" 2>/dev/null)
    fi

    # 익명 계정 확인
    local ANON_ACCOUNTS=$($MARIA_CMD -e "SELECT user, host FROM mysql.user WHERE user='';" 2>/dev/null)

    # 전체 계정 수
    local TOTAL_COUNT=$($MARIA_CMD -e "SELECT COUNT(*) FROM mysql.user;" 2>/dev/null)

    DT="[전체 계정 목록 (총 ${TOTAL_COUNT}개)]\nuser\thost\tplugin\tlocked\tpassword_status\n$ALL_ACCOUNTS\n\n[익명 계정]\n$ANON_ACCOUNTS\n\n※ 업무상 불필요한 계정 여부를 확인하세요."

    if [ -n "$ANON_ACCOUNTS" ]; then
        RES="N"
        DESC="익명 계정이 존재함"
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

    # MariaDB 비밀번호 검증 플러그인 확인 (simple_password_check, cracklib_password_check)
    local SIMPLE_PW=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'simple_password_check%';" 2>/dev/null)
    local CRACKLIB_PW=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'cracklib_password_check%';" 2>/dev/null)

    # 플러그인 로드 상태 확인 (인증 플러그인이 아닌 비밀번호 검증 플러그인만 확인)
    local PW_PLUGINS=$($MARIA_CMD -e "
        SELECT plugin_name, plugin_status FROM information_schema.plugins
        WHERE plugin_name IN ('simple_password_check', 'cracklib_password_check');" 2>/dev/null)

    # 비밀번호 만료 설정 확인
    local PW_EXPIRE=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'default_password_lifetime';" 2>/dev/null)

    DT="[비밀번호 검증 플러그인]\n$PW_PLUGINS\n\n[simple_password_check 설정]\n$SIMPLE_PW\n\n[cracklib_password_check 설정]\n$CRACKLIB_PW\n\n[비밀번호 만료 설정]\n$PW_EXPIRE"

    # 플러그인 활성화 여부 확인
    local HAS_ACTIVE_PLUGIN=0
    if echo "$PW_PLUGINS" | grep -qi "ACTIVE"; then
        HAS_ACTIVE_PLUGIN=1
    fi

    if [ "$HAS_ACTIVE_PLUGIN" -eq 0 ]; then
        RES="N"
        DESC="비밀번호 검증 플러그인(simple_password_check 또는 cracklib)이 비활성화됨"
        return
    fi

    # 설정값 검증
    local VULN_REASONS=""

    # simple_password_check_minimal_length >= 8
    local MIN_LENGTH=$(echo "$SIMPLE_PW" | grep -i "minimal_length" | awk '{print $2}')
    if [ -n "$MIN_LENGTH" ] && [ "$MIN_LENGTH" -lt 8 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}비밀번호 최소 길이가 8 미만($MIN_LENGTH)\n"
    fi

    # simple_password_check_digits >= 1
    local DIGITS=$(echo "$SIMPLE_PW" | grep -i "digits" | awk '{print $2}')
    if [ -n "$DIGITS" ] && [ "$DIGITS" -lt 1 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}숫자 요구 미설정(digits=$DIGITS)\n"
    fi

    # simple_password_check_letters_same_case >= 1
    local LETTERS=$(echo "$SIMPLE_PW" | grep -i "letters_same_case" | awk '{print $2}')
    if [ -n "$LETTERS" ] && [ "$LETTERS" -lt 1 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}문자 요구 미설정(letters_same_case=$LETTERS)\n"
    fi

    # simple_password_check_other_characters >= 1 (특수문자 요구)
    local OTHER_CHARS=$(echo "$SIMPLE_PW" | grep -i "other_characters" | awk '{print $2}')
    if [ -n "$OTHER_CHARS" ] && [ "$OTHER_CHARS" -lt 1 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}특수문자 요구 미설정(other_characters=$OTHER_CHARS)\n"
    fi

    # default_password_lifetime: 0이면 미설정, 90일 초과이면 취약
    local PW_LIFETIME=$(echo "$PW_EXPIRE" | awk '{print $2}')
    if [ -n "$PW_LIFETIME" ]; then
        if [ "$PW_LIFETIME" -eq 0 ] 2>/dev/null; then
            VULN_REASONS="${VULN_REASONS}비밀번호 만료 기간 미설정(lifetime=0)\n"
        elif [ "$PW_LIFETIME" -gt 90 ] 2>/dev/null; then
            VULN_REASONS="${VULN_REASONS}비밀번호 만료 기간 90일 초과(lifetime=${PW_LIFETIME}일)\n"
        fi
    fi

    if [ -n "$VULN_REASONS" ]; then
        RES="N"
        DESC="비밀번호 정책 설정이 미흡함"
        DT="${DT}\n\n[취약 항목]\n$VULN_REASONS"
    else
        RES="Y"
        DESC="비밀번호 검증 플러그인 및 정책이 적절히 설정됨"
    fi

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

    local RES="M"
    local DESC="관리자 권한 계정 수동 확인 필요"

    # SUPER 권한 보유 계정
    local SUPER_USERS=$($MARIA_CMD -e "SELECT user, host FROM mysql.user WHERE Super_priv='Y';" 2>/dev/null)

    # ALL PRIVILEGES 보유 계정
    local ALL_PRIV_USERS=$($MARIA_CMD -e "SELECT user, host FROM mysql.user WHERE Select_priv='Y' AND Insert_priv='Y' AND Update_priv='Y' AND Delete_priv='Y' AND Create_priv='Y' AND Drop_priv='Y' AND Grant_priv='Y';" 2>/dev/null)

    DT="[SUPER 권한 보유 계정]\n$SUPER_USERS\n\n[ALL PRIVILEGES 보유 계정]\n$ALL_PRIV_USERS"

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

    # password_reuse_check 플러그인은 MariaDB 10.7.0부터 기본 설치됨
    # 그 이전 버전은 별도 설치 필요
    local REUSE_PLUGIN=$($MARIA_CMD -e "SELECT plugin_name, plugin_status FROM information_schema.plugins WHERE plugin_name = 'password_reuse_check';" 2>/dev/null)
    local REUSE_VARS=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'password_reuse_check%';" 2>/dev/null)

    DT="[password_reuse_check 플러그인]\n$REUSE_PLUGIN\n\n[설정값]\n$REUSE_VARS"

    if echo "$REUSE_PLUGIN" | grep -qi "ACTIVE"; then
        # 플러그인 활성화됨 - 설정값 확인
        local INTERVAL=$(echo "$REUSE_VARS" | grep -i "interval" | awk '{print $2}')
        if [ -n "$INTERVAL" ] && [ "$INTERVAL" -gt 0 ] 2>/dev/null; then
            RES="Y"
            DESC="비밀번호 재사용 제한 플러그인이 활성화됨 (interval: $INTERVAL)"
        else
            RES="N"
            DESC="비밀번호 재사용 제한 플러그인 활성화됨, 설정값 확인 필요"
        fi
    elif [ -n "$REUSE_PLUGIN" ]; then
        # 플러그인 존재하지만 비활성화
        RES="N"
        DESC="비밀번호 재사용 제한 플러그인(password_reuse_check)이 비활성화됨"
    else
        # 플러그인 미설치 - 수동 확인 필요
        RES="M"
        DESC="비밀번호 재사용 제한 설정 수동 확인 필요"
        DT="${DT}\n\n[참고]\npassword_reuse_check 플러그인이 설치되지 않았습니다.\nMariaDB 10.7.0 이상에서 기본 제공되며, 이전 버전은 별도 설치가 필요합니다.\n플러그인, 써드파티 솔루션, 내부 정책 등을 통해 비밀번호 재사용 제한 여부를 확인하세요."
    fi

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

    local RES="M"
    local DESC="사용자별 개별 계정 사용 여부 수동 확인 필요"

    local USER_LIST=$($MARIA_CMD -e "SELECT user, host FROM mysql.user WHERE user != '' ORDER BY user;" 2>/dev/null)

    DT="[계정 목록 - 공용 계정 여부 확인 필요]\n$USER_LIST\n\n※ 업무별/사용자별 개별 계정 사용 여부를 확인하세요."

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

    # MariaDB 프로세스 사용자 확인
    local MARIA_PROC=$(ps -ef | grep -E "mariadbd|mysqld" | grep -v grep | head -1)
    local PROC_USER=$(echo "$MARIA_PROC" | awk '{print $1}')

    DT="[MariaDB 프로세스]\n$MARIA_PROC"

    if [ -z "$MARIA_PROC" ]; then
        RES="N/A"
        DESC="MariaDB 프로세스를 찾을 수 없음"
    elif [ "$PROC_USER" == "root" ]; then
        RES="N"
        DESC="MariaDB가 root 권한으로 구동 중"
    else
        RES="Y"
        DESC="MariaDB가 일반 계정($PROC_USER)으로 구동 중"
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

    # 인증 플러그인 확인
    local AUTH_PLUGINS=$($MARIA_CMD -e "SELECT user, host, plugin FROM mysql.user;" 2>/dev/null)

    DT="[계정별 인증 플러그인]\n$AUTH_PLUGINS\n\n※ 권장 플러그인: unix_socket, ed25519, caching_sha2_password\n※ 허용 플러그인: mysql_native_password (SHA-1, 권고 강도 미달)\n※ 취약한 플러그인: mysql_old_password (MD5)"

    # mysql_old_password 사용 계정 확인 (MD5 기반으로 취약)
    local WEAK_AUTH=$(echo "$AUTH_PLUGINS" | grep -i "mysql_old_password")

    # mysql_native_password 사용 계정 확인 (SHA-1 기반, 권고 강도 미달)
    local NATIVE_AUTH=$($MARIA_CMD -e "
        SELECT CONCAT(user, '@', host) as account, plugin FROM mysql.user
        WHERE plugin = 'mysql_native_password'
        AND user NOT IN ('mariadb.sys', 'mysql.sys', 'mysql.session', 'mysql.infoschema')
        AND user != '';" 2>/dev/null)

    if [ -n "$WEAK_AUTH" ]; then
        RES="N"
        DESC="취약한 인증 플러그인(mysql_old_password) 사용 계정 존재"
        DT="${DT}\n\n[취약 계정 - mysql_old_password]\n$WEAK_AUTH"
    elif [ -n "$NATIVE_AUTH" ]; then
        RES="Y"
        DESC="mysql_native_password는 SHA-1 기반으로 KISA 권고 보안 강도(112비트 이상)에 미달하여, ed25519 또는 caching_sha2_password 방식으로의 전환을 권고함"
        DT="${DT}\n\n[mysql_native_password 사용 계정]\n$NATIVE_AUTH\n\n※ ed25519 또는 caching_sha2_password로 전환을 권고합니다."
    else
        RES="Y"
        DESC="안전한 인증 플러그인 사용 중"
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

    # MariaDB 10.4+ 여부 확인
    if [ "$IS_104_OR_HIGHER" == "1" ]; then
        # MariaDB 10.4.2+에서 max_password_errors 도입
        local MAX_ERRORS=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'max_password_errors';" 2>/dev/null)

        if [ -n "$MAX_ERRORS" ]; then
            local ERROR_VAL=$(echo "$MAX_ERRORS" | awk '{print $2}')
            DT="[로그인 실패 잠금 설정]\nmax_password_errors: $ERROR_VAL\n\n※ 기준: 5회 이하로 설정 필요"

            if [ "$ERROR_VAL" == "0" ] || [ "$ERROR_VAL" == "4294967295" ]; then
                RES="N"
                DESC="로그인 실패 잠금 정책이 설정되지 않음 (무제한)"
            elif [ "$ERROR_VAL" -gt 5 ] 2>/dev/null; then
                RES="N"
                DESC="로그인 실패 허용 횟수가 5회 초과 (현재: $ERROR_VAL)"
                DT="${DT}\n\n[취약] max_password_errors 값이 5회 초과로 설정됨"
            else
                RES="Y"
                DESC="로그인 실패 잠금 정책 설정됨 (max_password_errors: $ERROR_VAL)"
            fi
        else
            # max_password_errors 변수가 없는 경우 (10.4.0~10.4.1)
            RES="M"
            DESC="max_password_errors 변수 미확인 - 수동 확인 필요"
            DT="[참고]\nMariaDB 10.4.0~10.4.1 버전에서는 max_password_errors가 없을 수 있습니다.\n별도 플러그인 또는 솔루션을 통해 로그인 실패 잠금 정책을 확인하세요."
        fi
    else
        # MariaDB 10.4 미만: 수동 진단
        # connection_control 플러그인 확인 시도
        local CONN_CONTROL=$($MARIA_CMD -e "SHOW PLUGINS;" 2>/dev/null | grep -i "connection_control")
        local CONN_VARS=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'connection_control%';" 2>/dev/null)

        DT="[MariaDB 버전]\n$DB_VERSION (10.4 미만)\n\n[connection_control 플러그인]\n$CONN_CONTROL\n\n[설정값]\n$CONN_VARS"

        if echo "$CONN_CONTROL" | grep -qi "ACTIVE"; then
            # connection_control_failed_connections_threshold 값 확인
            local THRESHOLD=$(echo "$CONN_VARS" | grep -i "threshold" | awk '{print $2}')
            if [ -n "$THRESHOLD" ] && [ "$THRESHOLD" -le 5 ] 2>/dev/null; then
                RES="Y"
                DESC="connection_control 플러그인 활성화됨 (threshold: $THRESHOLD)"
            else
                RES="N"
                DESC="connection_control threshold 값이 5 초과 또는 미설정"
            fi
        else
            # 10.4 미만 버전에서 플러그인 미설치: 수동 진단 필요
            RES="M"
            DESC="MariaDB 10.4 미만 - 로그인 실패 잠금 정책 수동 확인 필요"
            DT="${DT}\n\n[수동 진단 필요]\nMariaDB 10.4 미만 버전은 자체적으로 로그인 실패 잠금 기능을 지원하지 않습니다.\n다음 사항을 확인하세요:\n1. connection_control 플러그인 설치 여부\n2. 방화벽, IPS 등 네트워크 장비의 brute-force 방어 설정\n3. fail2ban 등 외부 솔루션 사용 여부\n4. 애플리케이션 레벨의 로그인 시도 제한"
        fi
    fi

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

    local RES="M"
    local DESC="원격 접속 제한 설정 수동 확인 필요"

    # bind-address 확인
    local BIND_ADDR=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'bind_address';" 2>/dev/null)

    # 전체 계정 현황
    local ALL_ACCOUNTS=$($MARIA_CMD -e "SELECT user, host FROM mysql.user ORDER BY user, host;" 2>/dev/null)

    # '%' 호스트 허용 계정 확인
    local REMOTE_ACCOUNTS=$($MARIA_CMD -e "SELECT user, host FROM mysql.user WHERE host='%';" 2>/dev/null)

    # skip_networking 확인
    local SKIP_NET=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'skip_networking';" 2>/dev/null)

    DT="[bind_address 설정]\n$BIND_ADDR\n\n[skip_networking 설정]\n$SKIP_NET\n\n[전체 계정 현황]\n$ALL_ACCOUNTS\n\n[모든 호스트 접속 허용 계정 (host='%')]\n$REMOTE_ACCOUNTS\n\n[수동 확인 필요]\n1. 방화벽/네트워크 장비를 통한 접근 제어 설정 여부\n2. 허용된 원격 접속 계정의 업무 필요성\n3. bind_address가 특정 IP로 제한되어 있는지 확인"

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

    # mysql DB 스키마 권한 보유 계정 확인 (스키마 레벨)
    local MYSQL_DB_GRANTS=$($MARIA_CMD -e "
        SELECT DISTINCT GRANTEE
        FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
        WHERE TABLE_SCHEMA IN ('mysql', 'sys', 'information_schema', 'performance_schema')
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mariadb.%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    # mysql DB 테이블 권한 보유 계정 확인 (테이블 레벨)
    local TABLE_GRANTS=$($MARIA_CMD -e "
        SELECT DISTINCT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE
        FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES
        WHERE TABLE_SCHEMA IN ('mysql', 'sys', 'performance_schema')
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mariadb.%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    DT="[mysql DB 스키마 권한 보유 계정 (root 제외)]\n$MYSQL_DB_GRANTS\n\n[mysql DB 테이블 권한 보유 계정 (root 제외)]\n$TABLE_GRANTS"

    local HAS_VULN=0
    if [ -n "$MYSQL_DB_GRANTS" ]; then
        HAS_VULN=1
    fi
    if [ -n "$TABLE_GRANTS" ]; then
        HAS_VULN=1
    fi

    if [ "$HAS_VULN" -eq 0 ]; then
        RES="Y"
        DESC="일반 사용자에게 시스템 DB 접근 권한 없음"
    else
        RES="M"
        DESC="시스템 DB 접근 권한 수동 확인 필요"
        DT="${DT}\n\n※ 위 계정들의 시스템 테이블 접근 권한이 업무상 필요한지 확인하세요."
    fi

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
    local DESC="MariaDB는 리스너 개념이 없음 (Oracle 전용)"
    local DT="[참고]\nMariaDB는 Oracle과 달리 별도의 리스너(Listener) 프로세스가 없습니다.\nMariaDB는 서버 프로세스(mariadbd/mysqld)가 직접 클라이언트 연결을 처리합니다.\n\n이 점검 항목은 Oracle DBMS에만 해당됩니다."

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
    local DESC="MariaDB Linux 환경에서는 ODBC/OLE-DB 점검 대상 없음 (Windows 전용)"

    DT="[N/A 사유]\nODBC/OLE-DB 데이터 소스 및 드라이버 관리는 Windows 클라이언트 OS 영역입니다.\nMariaDB Linux 서버에서는 점검 대상이 없으므로 해당 항목이 적용되지 않습니다.\n\n해당 항목은 Windows MSSQL 전용 보안 항목입니다."

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

    local CHECKED_FILES=""
    local VULNERABLE_FILES=""

    # MariaDB 설정 파일 위치들
    for CNF_PATH in "/etc/my.cnf" "/etc/my.cnf.d/server.cnf" "/etc/mysql/my.cnf" "/etc/mysql/mariadb.conf.d/50-server.cnf" "$HOME/.my.cnf"; do
        if [ -e "$CNF_PATH" ]; then
            local REAL_PATH="$CNF_PATH"
            local SYMLINK_INFO=""

            # 심볼릭 링크인 경우 실제 파일 경로 확인
            if [ -L "$CNF_PATH" ]; then
                REAL_PATH=$(readlink -f "$CNF_PATH" 2>/dev/null)
                SYMLINK_INFO=" -> $REAL_PATH (symlink)"
            fi

            local FILE_PERM=$(stat -c "%a" "$REAL_PATH" 2>/dev/null)
            local FILE_OWNER=$(stat -c "%U:%G" "$REAL_PATH" 2>/dev/null)
            CHECKED_FILES="${CHECKED_FILES}${CNF_PATH}${SYMLINK_INFO}: ${FILE_PERM} (${FILE_OWNER})\n"

            # 권한 기준: 640 또는 600 이하 (other에게 읽기 권한 없어야 함)
            # 8진수 비교: 권한이 640(=416) 초과이면 취약
            # 실제로 other 권한이 있는지 확인 (마지막 자리가 0이 아니면 취약)
            local OTHER_PERM=$((FILE_PERM % 10))
            if [ "$OTHER_PERM" -gt 0 ] 2>/dev/null; then
                VULNERABLE_FILES="${VULNERABLE_FILES}${CNF_PATH}${SYMLINK_INFO}: ${FILE_PERM} (other 권한 존재)\n"
            elif [ "$FILE_PERM" -gt 640 ] 2>/dev/null; then
                VULNERABLE_FILES="${VULNERABLE_FILES}${CNF_PATH}${SYMLINK_INFO}: ${FILE_PERM} (640 초과)\n"
            fi
        fi
    done

    if [ -z "$CHECKED_FILES" ]; then
        RES="N/A"
        DESC="설정 파일을 찾을 수 없음"
        DT="MariaDB 설정 파일을 찾을 수 없습니다."
    elif [ -z "$VULNERABLE_FILES" ]; then
        RES="Y"
        DESC="주요 설정 파일 권한이 적절함 (640/600 이하)"
        DT="[파일 권한 현황]\n$CHECKED_FILES\n\n※ 권한 기준: 640(rw-r-----) 또는 600(rw-------) 이하"
    else
        RES="N"
        DESC="주요 설정 파일에 과도한 권한 존재 (640/600 초과)"
        DT="[취약 파일]\n$VULNERABLE_FILES\n[전체 파일]\n$CHECKED_FILES\n\n※ 권한 기준: 640(rw-r-----) 또는 600(rw-------) 이하 권장\n※ other(기타 사용자)에게 읽기 권한이 없어야 함"
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
    local DESC="MariaDB는 Oracle trace 파일이 없음 (Oracle 전용)"
    local DT="[참고]\nMariaDB는 Oracle의 trace 파일(.trc) 개념이 없습니다.\nMariaDB는 별도의 로그 파일(error log, slow query log, general log 등)을 사용합니다.\n\n이 점검 항목은 Oracle DBMS에만 해당됩니다."

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
    local DESC="MariaDB는 Windows 인증 모드가 없음 (MSSQL 전용)"
    local DT="[참고]\nWindows 인증 모드는 Microsoft SQL Server 전용 기능입니다.\nMariaDB는 자체 인증 플러그인(mysql_native_password, ed25519, unix_socket 등)을 사용합니다.\n\n이 점검 항목은 MSSQL에만 해당됩니다."

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
    local DESC="MariaDB는 Oracle AUD$ 테이블이 없음 (Oracle 전용)"
    local DT="[N/A 사유]\n해당 항목은 Oracle의 AUD$ 감사 테이블에 대한 접근 권한을 점검하는 항목입니다.\nMariaDB는 Oracle과 같은 AUD$ 테이블이 없으므로 본 항목은 적용되지 않습니다.\n\n※ MariaDB의 감사 기능은 server_audit 플러그인 또는 general_log를 사용합니다."

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
    local DESC="MariaDB는 Oracle PUBLIC Role 개념이 없음 (Oracle 전용)"
    local DT="[N/A 사유]\n해당 항목은 Oracle의 PUBLIC Role에 부여된 권한을 점검하는 항목입니다.\nMariaDB는 Oracle의 PUBLIC Role 개념이 없으며, 개별 사용자에게 직접 권한을 부여하는 방식을 사용합니다.\n\n해당 항목은 Oracle DBMS에만 해당됩니다."

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
    local DESC="MariaDB는 Oracle OS_ROLES 파라미터가 없음 (Oracle 전용)"
    local DT="[N/A 사유]\n해당 항목은 Oracle의 OS_ROLES, REMOTE_OS_AUTHENT, REMOTE_OS_ROLES 파라미터를\nFALSE로 설정했는지 점검하는 항목입니다.\nMariaDB는 이러한 파라미터가 없으므로 본 항목은 적용되지 않습니다.\n\n※ MariaDB에서 OS 인증은 unix_socket 플러그인을 통해 제한적으로 지원됩니다."

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
    local DESC="MariaDB는 Oracle Object Owner 개념이 다르게 적용됨 (Oracle 전용)"
    local DT="[N/A 사유]\n해당 항목은 Oracle의 스키마 기반 Object Owner를 점검하는 항목입니다.\nMariaDB는 Oracle과 같은 스키마 기반 Object Owner 개념이 다르며,\n데이터베이스(스키마) 단위로 권한을 관리합니다.\n\n해당 항목은 Oracle DBMS에만 해당됩니다."

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

    # mysql.user의 Grant_priv 확인 (전역 GRANT 권한)
    local GRANT_USERS=$($MARIA_CMD -e "
        SELECT CONCAT(user, '@', host) as account
        FROM mysql.user
        WHERE grant_priv = 'Y'
        AND user NOT IN ('root', 'mariadb.sys', 'mysql.sys', 'mysql.session', 'mysql.infoschema')
        AND user != '';" 2>/dev/null)

    # IS_GRANTABLE 확인 (WITH GRANT OPTION으로 부여된 권한)
    local IS_GRANTABLE=$($MARIA_CMD -e "
        SELECT DISTINCT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE
        FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
        WHERE IS_GRANTABLE = 'YES'
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mariadb.%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    # 테이블 레벨 IS_GRANTABLE 확인
    local TABLE_GRANTABLE=$($MARIA_CMD -e "
        SELECT DISTINCT GRANTEE, TABLE_SCHEMA, TABLE_NAME
        FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES
        WHERE IS_GRANTABLE = 'YES'
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mariadb.%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    DT="[전역 GRANT 권한 보유 계정]\n$GRANT_USERS\n\n[IS_GRANTABLE 설정된 스키마 권한]\n$IS_GRANTABLE\n\n[IS_GRANTABLE 설정된 테이블 권한]\n$TABLE_GRANTABLE"

    local HAS_ISSUE=0
    if [ -n "$GRANT_USERS" ]; then
        HAS_ISSUE=1
    fi
    if [ -n "$IS_GRANTABLE" ]; then
        HAS_ISSUE=1
    fi
    if [ -n "$TABLE_GRANTABLE" ]; then
        HAS_ISSUE=1
    fi

    if [ "$HAS_ISSUE" -eq 0 ]; then
        RES="Y"
        DESC="일반 사용자에게 GRANT 권한 없음"
    else
        RES="M"
        DESC="GRANT 권한 또는 IS_GRANTABLE 설정 수동 확인 필요"
        DT="${DT}\n\n※ 업무상 불필요하게 WITH GRANT OPTION이 설정된 권한이 있는지 확인하세요."
    fi

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
    local DESC="MariaDB는 sa 계정이 없음 (MSSQL 전용)"
    local DT="[참고]\nsa(System Administrator) 계정은 Microsoft SQL Server의 기본 관리자 계정입니다.\nMariaDB는 sa 계정이 없으며, 대신 root 계정을 사용합니다.\n\nMariaDB의 root 계정 보안은 D-01, D-07, D-10 항목에서 점검합니다."

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
    local DESC="MariaDB는 xp_cmdshell이 없음 (MSSQL 전용)"
    local DT="[참고]\nxp_cmdshell은 Microsoft SQL Server에서 운영체제 명령을 실행하는 확장 저장 프로시저입니다.\nMariaDB는 xp_cmdshell 기능을 지원하지 않습니다.\n\n이 점검 항목은 MSSQL에만 해당됩니다."

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
    local DESC="MariaDB는 SQL Server 에이전트가 없음 (MSSQL 전용)"
    local DT="[참고]\nSQL Server 에이전트는 Microsoft SQL Server의 작업 스케줄링 서비스입니다.\nMariaDB는 SQL Server 에이전트 기능이 없습니다.\n\nMariaDB에서 작업 스케줄링은 이벤트 스케줄러(Event Scheduler)를 통해 수행됩니다."

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

    DT="[현재 버전]\nMariaDB $DB_VERSION\n\n※ 최신 버전은 MariaDB 공식 사이트에서 확인\nhttps://mariadb.org/download/"

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

    # general_log 확인
    local GENERAL_LOG=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'general_log';" 2>/dev/null)
    local GENERAL_LOG_FILE=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'general_log_file';" 2>/dev/null)

    # MariaDB Audit Plugin (server_audit) 확인
    local AUDIT_PLUGIN=$($MARIA_CMD -e "SELECT plugin_name, plugin_status FROM information_schema.plugins WHERE plugin_name = 'SERVER_AUDIT';" 2>/dev/null)
    local AUDIT_VARS=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'server_audit%';" 2>/dev/null)

    # log_error 확인
    local ERROR_LOG=$($MARIA_CMD -e "SHOW VARIABLES LIKE 'log_error';" 2>/dev/null)

    DT="[General Log]\n$GENERAL_LOG\n$GENERAL_LOG_FILE\n\n[MariaDB Audit Plugin (server_audit)]\n$AUDIT_PLUGIN\n\n[Audit 설정]\n$AUDIT_VARS\n\n[Error Log]\n$ERROR_LOG"

    local GENERAL_ON=0
    local AUDIT_ON=0

    if echo "$GENERAL_LOG" | grep -qi "ON"; then
        GENERAL_ON=1
    fi

    if echo "$AUDIT_PLUGIN" | grep -qi "ACTIVE"; then
        AUDIT_ON=1
    fi

    if [ "$AUDIT_ON" -eq 1 ]; then
        # server_audit 플러그인 활성화 - 백업 여부 인터뷰 필요
        RES="M"
        DESC="server_audit 플러그인 활성화됨 - 백업 여부 확인 필요"
        DT="${DT}\n\n※ 감사 로그 수집은 확인됨. 주기적인 백업 실시 여부는 인터뷰를 통해 확인하세요."
    else
        RES="N"
        DESC="감사 로그가 비활성화됨 (server_audit 미활성화)"
        DT="${DT}\n\n※ general_log는 감사 로그가 아니므로 판단 기준에서 제외합니다.\n※ 운영 환경에서는 server_audit 플러그인 사용을 권고합니다."
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

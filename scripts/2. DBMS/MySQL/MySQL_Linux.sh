#!/bin/bash
#================================================================
# MySQL_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : MySQL_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="MySQL"
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
echo " MySQL 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# mysql 클라이언트 확인
MYSQL_CLIENT=$(which mysql 2>/dev/null)
if [ -z "$MYSQL_CLIENT" ]; then
    echo -n "MySQL Client Path (mysql not found): "
    read MYSQL_CLIENT
    if [ ! -x "$MYSQL_CLIENT" ]; then
        echo "[!] mysql 클라이언트를 찾을 수 없습니다."
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

echo -n "Password: "
read -s DB_PASS
echo ""

if [ -z "$DB_PASS" ]; then
    echo "[!] 비밀번호를 입력해주세요."
    exit 1
fi

# MySQL 연결 명령어
MYSQL_CMD="$MYSQL_CLIENT -h $DB_HOST -P $DB_PORT -u $DB_USER -p$DB_PASS -N -s"

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
DB_VERSION=$($MYSQL_CMD -e "SELECT VERSION();" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "[!] MySQL 연결 실패"
    exit 1
fi
echo "[OK] MySQL $DB_VERSION 연결 성공"
echo ""

# MySQL 버전 체크 (8.0 이상 여부)
MAJOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f1)
MINOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f2)
IS_80_OR_HIGHER=0
if [ "$MAJOR_VERSION" -ge 8 ] 2>/dev/null; then
    IS_80_OR_HIGHER=1
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

    # 전체 계정 현황 확인 (인증 플러그인 포함)
    local ALL_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host, plugin,
        CASE WHEN authentication_string='' OR authentication_string IS NULL THEN 'NO' ELSE 'YES' END as has_password,
        account_locked
        FROM mysql.user ORDER BY user;" 2>/dev/null)

    # root 계정 확인
    local ROOT_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host, plugin FROM mysql.user WHERE user='root';" 2>/dev/null)

    # 비밀번호 없는 계정 확인
    local NO_PASS_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL;" 2>/dev/null)

    DT="[전체 계정 현황]\n$ALL_ACCOUNTS\n\n[root 계정]\n$ROOT_ACCOUNTS\n\n[비밀번호 미설정 계정]\n${NO_PASS_ACCOUNTS:-없음}"

    if [ -z "$NO_PASS_ACCOUNTS" ] || [ "$NO_PASS_ACCOUNTS" = "user	host" ]; then
        RES="M"
        DESC="모든 계정에 비밀번호가 설정됨 - 패스워드 정책(복잡도, 만료기간 등) 수동 확인 필요"
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

    # 전체 계정 목록
    local ALL_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host, account_locked FROM mysql.user ORDER BY user;" 2>/dev/null)

    # 익명 계정 확인
    local ANON_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE user='';" 2>/dev/null)

    DT="[계정 목록]\n$ALL_ACCOUNTS\n\n[익명 계정]\n$ANON_ACCOUNTS"

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

    # validate_password 플러그인 확인
    local VALIDATE_PW=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'validate_password%';" 2>/dev/null)

    # 비밀번호 만료 설정 확인
    local PW_EXPIRE=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'default_password_lifetime';" 2>/dev/null)

    DT="[비밀번호 검증 설정]\n$VALIDATE_PW\n\n[비밀번호 만료 설정]\n$PW_EXPIRE"

    # 플러그인 존재 여부 확인
    if ! echo "$VALIDATE_PW" | grep -qi "validate_password"; then
        RES="N"
        DESC="비밀번호 검증 플러그인(validate_password)이 비활성화됨"
        return
    fi

    # 설정값 검증
    local VULN_REASONS=""

    # validate_password.length (또는 validate_password_length) >= 8
    local PW_LENGTH=$(echo "$VALIDATE_PW" | grep -i "length" | awk '{print $2}')
    if [ -n "$PW_LENGTH" ] && [ "$PW_LENGTH" -lt 8 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}비밀번호 최소 길이가 8 미만($PW_LENGTH)\n"
    fi

    # validate_password.policy (또는 validate_password_policy) >= MEDIUM (1)
    local PW_POLICY=$(echo "$VALIDATE_PW" | grep -i "policy" | awk '{print $2}')
    if [ -n "$PW_POLICY" ]; then
        # POLICY: 0=LOW, 1=MEDIUM, 2=STRONG
        # LOW 정책이면 독립적으로 취약 판정
        if [ "$PW_POLICY" == "LOW" ] || [ "$PW_POLICY" == "0" ]; then
            RES="N"
            DESC="비밀번호 정책이 LOW로 설정되어 취약함"
            DT="${DT}\n\n[취약 항목]\nvalidate_password.policy가 LOW로 설정됨 (최소 MEDIUM 이상 권장)"
            return
        fi
    fi

    # validate_password.mixed_case_count >= 1
    local MIXED_CASE=$(echo "$VALIDATE_PW" | grep -i "mixed_case" | awk '{print $2}')
    if [ -n "$MIXED_CASE" ] && [ "$MIXED_CASE" -lt 1 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}대소문자 혼합 요구 미설정(mixed_case_count=$MIXED_CASE)\n"
    fi

    # default_password_lifetime > 0 및 90일 이하 권장
    local PW_LIFETIME=$(echo "$PW_EXPIRE" | awk '{print $2}')
    if [ -n "$PW_LIFETIME" ] && [ "$PW_LIFETIME" -eq 0 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}비밀번호 만료 기간 미설정(lifetime=0)\n"
    elif [ -n "$PW_LIFETIME" ] && [ "$PW_LIFETIME" -gt 90 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}비밀번호 만료 기간이 90일 초과(lifetime=$PW_LIFETIME, 권장: 90일 이하)\n"
    fi

    # validate_password.special_char_count >= 1 (특수문자 요구)
    local SPECIAL_CHAR=$(echo "$VALIDATE_PW" | grep -i "special_char" | awk '{print $2}')
    if [ -n "$SPECIAL_CHAR" ] && [ "$SPECIAL_CHAR" -lt 1 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}특수문자 요구 미설정(special_char_count=$SPECIAL_CHAR)\n"
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
    local SUPER_USERS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE Super_priv='Y';" 2>/dev/null)

    # ALL PRIVILEGES 보유 계정
    local ALL_PRIV_USERS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE Select_priv='Y' AND Insert_priv='Y' AND Update_priv='Y' AND Delete_priv='Y' AND Create_priv='Y' AND Drop_priv='Y' AND Grant_priv='Y';" 2>/dev/null)

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

    if [ "$IS_80_OR_HIGHER" == "1" ]; then
        local PW_HISTORY=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'password_history';" 2>/dev/null | awk '{print $2}')
        local PW_REUSE_INTERVAL=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'password_reuse_interval';" 2>/dev/null | awk '{print $2}')

        DT="[비밀번호 재사용 제한 설정]\npassword_history: $PW_HISTORY\npassword_reuse_interval: $PW_REUSE_INTERVAL"

        # 둘 다 설정되어야 양호 (AND 조건)
        if [ "$PW_HISTORY" -gt 0 ] 2>/dev/null && [ "$PW_REUSE_INTERVAL" -gt 0 ] 2>/dev/null; then
            RES="Y"
            DESC="비밀번호 재사용 제한이 설정됨 (history: $PW_HISTORY, interval: $PW_REUSE_INTERVAL)"
        else
            RES="N"
            if [ "$PW_HISTORY" -eq 0 ] 2>/dev/null && [ "$PW_REUSE_INTERVAL" -eq 0 ] 2>/dev/null; then
                DESC="비밀번호 재사용 제한이 모두 설정되지 않음"
            elif [ "$PW_HISTORY" -eq 0 ] 2>/dev/null; then
                DESC="password_history가 설정되지 않음 (0)"
            else
                DESC="password_reuse_interval이 설정되지 않음 (0)"
            fi
        fi
    else
        RES="M"
        DESC="MySQL 5.7은 비밀번호 재사용 제한 미지원. 외부 인증 또는 애플리케이션에서 관리 여부 확인 필요"
        DT="[참고]\nMySQL 5.7 이하 버전은 비밀번호 재사용 제한 기능을 네이티브로 지원하지 않습니다.\n외부 인증 모듈 또는 애플리케이션 레벨에서 관리 여부를 확인하세요."
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

    local USER_LIST=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE user != '' ORDER BY user;" 2>/dev/null)

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

    # MySQL 프로세스 사용자 확인
    local MYSQL_PROC=$(ps -ef | grep mysqld | grep -v grep | head -1)
    local PROC_USER=$(echo "$MYSQL_PROC" | awk '{print $1}')

    DT="[MySQL 프로세스]\n$MYSQL_PROC"

    if [ -z "$MYSQL_PROC" ]; then
        RES="N/A"
        DESC="MySQL 프로세스를 찾을 수 없음"
    elif [ "$PROC_USER" == "root" ]; then
        RES="N"
        DESC="MySQL이 root 권한으로 구동 중"
    else
        RES="Y"
        DESC="MySQL이 일반 계정($PROC_USER)으로 구동 중"
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
    local AUTH_PLUGINS=$($MYSQL_CMD -e "SELECT user, host, plugin FROM mysql.user;" 2>/dev/null)

    # 기본 인증 플러그인 확인
    local DEFAULT_AUTH=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'default_authentication_plugin';" 2>/dev/null)

    DT="[계정별 인증 플러그인]\n$AUTH_PLUGINS\n\n[기본 인증 플러그인]\n$DEFAULT_AUTH"

    # mysql_native_password 사용 계정 확인 (시스템 계정 제외)
    # mysql.sys, mysql.session, mysql.infoschema는 시스템 계정으로 제외
    local NATIVE_AUTH=$($MYSQL_CMD -e "
        SELECT CONCAT(user, '@', host) as account, plugin
        FROM mysql.user
        WHERE plugin = 'mysql_native_password'
        AND user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
        AND user != '';" 2>/dev/null)

    # caching_sha2_password 사용 계정 확인
    local SHA2_AUTH=$($MYSQL_CMD -e "
        SELECT CONCAT(user, '@', host) as account, plugin
        FROM mysql.user
        WHERE plugin = 'caching_sha2_password'
        AND user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
        AND user != '';" 2>/dev/null)

    # 취약한 인증 플러그인 확인 (mysql_old_password 등)
    local WEAK_AUTH=$($MYSQL_CMD -e "
        SELECT CONCAT(user, '@', host) as account, plugin
        FROM mysql.user
        WHERE plugin NOT IN ('mysql_native_password', 'caching_sha2_password', 'sha256_password', 'auth_socket', 'unix_socket')
        AND user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
        AND user != ''
        AND plugin != '';" 2>/dev/null)

    if [ -n "$WEAK_AUTH" ] && [ "$WEAK_AUTH" != "account	plugin" ]; then
        RES="N"
        DESC="취약한 인증 플러그인 사용 계정 존재"
        DT="${DT}\n\n[취약 계정 목록 (mysql_old_password 등)]\n$WEAK_AUTH"
    elif [ -n "$NATIVE_AUTH" ] && [ "$NATIVE_AUTH" != "account	plugin" ]; then
        RES="Y"
        DESC="양호 (mysql_native_password 사용 - 전환 권고)"
        DT="${DT}\n\n[mysql_native_password 사용 계정]\n$NATIVE_AUTH\n\n[권고사항]\nmysql_native_password는 SHA-1 기반으로 KISA 권고 보안 강도(112비트 이상)에 미달하여,\ncaching_sha2_password 방식으로의 전환을 권고합니다.\n단, 일부 클라이언트/드라이버에서는 caching_sha2_password를 기본 지원하지 않아\n별도 설정이 필요할 수 있습니다."
    else
        RES="Y"
        DESC="안전한 암호화 알고리즘(caching_sha2_password) 사용 중"
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

    if [ "$IS_80_OR_HIGHER" == "1" ]; then
        # MySQL 8.0.19+ 계정 잠금 정책 확인
        # 활성 계정 수 (시스템 계정 및 잠긴 계정 제외)
        local ACTIVE_USERS=$($MYSQL_CMD -e "
            SELECT COUNT(*) FROM mysql.user
            WHERE user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint')
            AND user != ''
            AND account_locked != 'Y';" 2>/dev/null | tr -d '[:space:]')

        # 잠금 정책이 설정된 계정 (attempts <= 5, lock_days > 0)
        local LOCK_SETTINGS=$($MYSQL_CMD -e "
            SELECT user, host,
                JSON_EXTRACT(User_attributes, '\$.Password_locking.failed_login_attempts') as attempts,
                JSON_EXTRACT(User_attributes, '\$.Password_locking.password_lock_time_days') as lock_days
            FROM mysql.user
            WHERE user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint')
            AND user != ''
            AND account_locked != 'Y';" 2>/dev/null)

        # 취약한 설정 확인 (attempts > 5 또는 attempts = 0 또는 lock_days = 0 또는 설정 없음)
        # failed_login_attempts=0 은 무제한을 의미하므로 취약
        local VULN_USERS=$($MYSQL_CMD -e "
            SELECT CONCAT(user, '@', host) as account,
                COALESCE(JSON_EXTRACT(User_attributes, '\$.Password_locking.failed_login_attempts'), 'null') as attempts,
                COALESCE(JSON_EXTRACT(User_attributes, '\$.Password_locking.password_lock_time_days'), 'null') as lock_days
            FROM mysql.user
            WHERE user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint')
            AND user != ''
            AND account_locked != 'Y'
            AND (
                User_attributes IS NULL
                OR User_attributes = ''
                OR JSON_EXTRACT(User_attributes, '\$.Password_locking.failed_login_attempts') IS NULL
                OR JSON_EXTRACT(User_attributes, '\$.Password_locking.failed_login_attempts') = 0
                OR JSON_EXTRACT(User_attributes, '\$.Password_locking.failed_login_attempts') > 5
                OR JSON_EXTRACT(User_attributes, '\$.Password_locking.password_lock_time_days') IS NULL
                OR JSON_EXTRACT(User_attributes, '\$.Password_locking.password_lock_time_days') <= 0
            );" 2>/dev/null)

        DT="[활성 계정 수]\n$ACTIVE_USERS\n\n[계정별 잠금 정책]\n$LOCK_SETTINGS"

        if [ -n "$VULN_USERS" ]; then
            RES="N"
            DESC="잠금 정책이 미설정되거나 부적절한 계정 존재"
            DT="${DT}\n\n[취약 계정 (attempts=0/무제한, attempts>5, lock_days<=0 또는 미설정)]\n$VULN_USERS\n\n※ 기준: 1 <= failed_login_attempts <= 5, password_lock_time_days > 0"
        elif [ -z "$LOCK_SETTINGS" ] || [ "$ACTIVE_USERS" -eq 0 ] 2>/dev/null; then
            RES="N"
            DESC="로그인 실패 잠금 정책이 설정되지 않음"
        else
            RES="Y"
            DESC="모든 활성 계정에 적절한 잠금 정책 설정됨"
        fi
    else
        # MySQL 5.7.17+ connection_control 플러그인 확인
        local CONN_CONTROL=$($MYSQL_CMD -e "SHOW PLUGINS;" 2>/dev/null | grep -i "connection_control")
        local CONN_VARS=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'connection_control%';" 2>/dev/null)

        DT="[connection_control 플러그인]\n$CONN_CONTROL\n\n[설정값]\n$CONN_VARS"

        if echo "$CONN_CONTROL" | grep -qi "ACTIVE"; then
            # connection_control_failed_connections_threshold 값 확인
            local THRESHOLD=$(echo "$CONN_VARS" | grep -i "threshold" | awk '{print $2}')
            if [ -n "$THRESHOLD" ] && [ "$THRESHOLD" -le 5 ] 2>/dev/null; then
                RES="Y"
                DESC="connection_control 플러그인 활성화 (threshold: $THRESHOLD)"
            else
                RES="N"
                DESC="connection_control threshold 값이 5 초과 또는 미설정"
            fi
        else
            RES="M"
            DESC="MySQL 5.7에서 connection_control 플러그인 설치 여부 확인 필요"
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
    local DESC="원격 접속 제한 정책 수동 확인 필요"

    # bind-address 확인
    local BIND_ADDR=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'bind_address';" 2>/dev/null)

    # 전체 계정의 host 설정 확인
    local ALL_HOSTS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE user != '' ORDER BY user, host;" 2>/dev/null)

    # '%' 호스트 허용 계정 확인
    local REMOTE_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE host='%';" 2>/dev/null)

    DT="[bind_address 설정]\n$BIND_ADDR"
    DT="${DT}\n\n[전체 계정 접속 허용 호스트 현황]\n$ALL_HOSTS"
    DT="${DT}\n\n[모든 호스트 접속 허용 계정 (host='%')]\n${REMOTE_ACCOUNTS:-없음}"
    DT="${DT}\n\n※ 원격 접속 제한은 방화벽, 네트워크 ACL, bind_address 설정 등을 종합적으로 확인해야 합니다."
    DT="${DT}\n※ host='%' 계정이 있더라도 방화벽에서 차단되어 있을 수 있으므로 수동 확인이 필요합니다."

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

    # mysql DB 스키마 권한이 있는 일반 사용자 확인 (SCHEMA_PRIVILEGES)
    local MYSQL_DB_GRANTS=$($MYSQL_CMD -e "
        SELECT DISTINCT GRANTEE
        FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
        WHERE TABLE_SCHEMA = 'mysql'
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    # mysql DB 테이블 권한이 있는 일반 사용자 확인 (TABLE_PRIVILEGES)
    local MYSQL_TABLE_GRANTS=$($MYSQL_CMD -e "
        SELECT DISTINCT GRANTEE, TABLE_NAME, PRIVILEGE_TYPE
        FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES
        WHERE TABLE_SCHEMA = 'mysql'
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    DT="[mysql DB 스키마 권한 보유 계정 (root 제외)]\n$MYSQL_DB_GRANTS"
    DT="${DT}\n\n[mysql DB 테이블 권한 보유 계정 (root 제외)]\n$MYSQL_TABLE_GRANTS"

    if [ -z "$MYSQL_DB_GRANTS" ] && [ -z "$MYSQL_TABLE_GRANTS" ]; then
        RES="Y"
        DESC="일반 사용자에게 mysql DB 접근 권한 없음"
    else
        RES="N"
        DESC="일반 사용자에게 mysql DB 접근 권한 존재"
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
    local DESC="MySQL은 Oracle 리스너(Listener) 개념이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 TNS Listener와 같은 별도의 리스너 프로세스가 없습니다.\n리스너 비밀번호 설정은 Oracle 전용 보안 항목입니다."

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
    local DESC="N/A (MySQL은 ODBC/OLE-DB 드라이버 관리가 OS 영역)"

    DT="[N/A 사유]\nMySQL은 데이터베이스 서버이며, ODBC/OLE-DB 데이터 소스 및 드라이버 관리는 클라이언트 OS 영역입니다.\n서버 측에서 점검해야 할 ODBC/OLE-DB 설정이 없으므로, 해당 항목은 적용되지 않습니다.\n\n[참고]\n- ODBC 드라이버: 클라이언트 OS에서 관리 (Windows: ODBC 데이터 원본 관리자)\n- OLE-DB: Windows 클라이언트 전용 기술"

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

    # my.cnf 파일 위치들
    for CNF_PATH in "/etc/my.cnf" "/etc/mysql/my.cnf" "/etc/mysql/mysql.conf.d/mysqld.cnf" "$HOME/.my.cnf"; do
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

            # 권한이 640 또는 600이어야 양호 (그 외에는 취약)
            if [ "$FILE_PERM" != "640" ] && [ "$FILE_PERM" != "600" ]; then
                VULNERABLE_FILES="${VULNERABLE_FILES}${CNF_PATH}${SYMLINK_INFO}: ${FILE_PERM} (권장: 640 또는 600)\n"
            fi
        fi
    done

    if [ -z "$CHECKED_FILES" ]; then
        RES="N/A"
        DESC="설정 파일을 찾을 수 없음"
        DT="my.cnf 파일을 찾을 수 없습니다."
    elif [ -z "$VULNERABLE_FILES" ]; then
        RES="Y"
        DESC="주요 설정 파일 권한이 적절함 (640 또는 600)"
        DT="[파일 권한 현황]\n$CHECKED_FILES\n\n※ 양호 기준: 640 또는 600"
    else
        RES="N"
        DESC="주요 설정 파일에 부적절한 권한 존재 (640 또는 600 필요)"
        DT="[취약 파일]\n$VULNERABLE_FILES\n[전체 파일]\n$CHECKED_FILES\n\n※ 양호 기준: 640 또는 600"
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
    local DESC="MySQL은 Oracle 리스너/trace 파일이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 리스너 로그 및 trace 파일 개념이 없습니다.\nMySQL은 error log, general log, slow query log 등 별도의 로깅 체계를 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MySQL은 Windows 인증 모드를 지원하지 않아 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 MSSQL의 Windows 인증 모드(Integrated Security)를 지원하지 않습니다.\nMySQL은 자체 인증 플러그인(mysql_native_password, caching_sha2_password 등)을 사용합니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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
    local DESC="MySQL은 Oracle AUD$ 테이블이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 AUD\$ 테이블과 같은 감사 테이블이 없습니다.\nMySQL Enterprise Edition은 audit_log 플러그인을 제공하며,\nCommunity Edition은 general_log를 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MySQL은 Oracle PUBLIC Role 개념이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 PUBLIC Role 개념이 없습니다.\nMySQL은 권한을 개별 사용자 또는 역할(Role)에 직접 부여하는 방식을 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MySQL은 Oracle OS_ROLES 파라미터가 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 OS_ROLES, REMOTE_OS_AUTHENT, REMOTE_OS_ROLES 파라미터가 없습니다.\nOS 기반 인증은 MySQL PAM 플러그인 등을 통해 별도로 구성해야 합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MySQL은 Oracle Object Owner 개념이 다르게 적용되어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle과 같은 스키마 기반 Object Owner 개념이 다릅니다.\nMySQL에서는 데이터베이스(스키마) 단위로 권한을 관리하며,\n별도의 Object Owner 제한 파라미터가 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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

    # GRANT 권한 보유 계정 확인 (시스템 계정 제외)
    # debian-sys-maint: Debian/Ubuntu MySQL 서비스 관리용 시스템 계정
    local GRANT_USERS=$($MYSQL_CMD -e "
        SELECT CONCAT(user, '@', host) as account
        FROM mysql.user
        WHERE grant_priv = 'Y'
        AND user NOT IN ('root', 'mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint')
        AND user != '';" 2>/dev/null)

    # SCHEMA_PRIVILEGES에서 IS_GRANTABLE='YES' 확인 (시스템 계정 제외)
    local GRANTABLE_SCHEMA_PRIVS=$($MYSQL_CMD -e "
        SELECT DISTINCT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE
        FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
        WHERE IS_GRANTABLE = 'YES'
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mysql.%'
        AND GRANTEE NOT LIKE '''debian-sys-maint''%';" 2>/dev/null)

    DT="[GRANT 권한 보유 계정 (시스템 계정 제외)]\n$GRANT_USERS"
    DT="${DT}\n  ※ grant_priv: mysql.user 테이블의 권한 부여 자격 여부 (Y/N)"
    DT="${DT}\n\n[IS_GRANTABLE='YES' 스키마 권한 (시스템 계정 제외)]\n$GRANTABLE_SCHEMA_PRIVS"
    DT="${DT}\n  ※ IS_GRANTABLE (WITH GRANT OPTION): 실제 권한 위임 가능 상태 (YES/NO)"
    DT="${DT}\n\n[제외 계정] root, mysql.sys, mysql.session, mysql.infoschema, debian-sys-maint"

    if [ -z "$GRANT_USERS" ] && [ -z "$GRANTABLE_SCHEMA_PRIVS" ]; then
        RES="Y"
        DESC="일반 사용자에게 GRANT 권한 없음"
    else
        RES="N"
        DESC="일반 사용자에게 GRANT 권한 부여됨"
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
    local DESC="MySQL은 Oracle RESOURCE_LIMIT 파라미터가 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 RESOURCE_LIMIT 파라미터가 없습니다.\nMySQL은 max_connections, max_user_connections 등 별도의 자원 제한 파라미터를 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MySQL은 MSSQL xp_cmdshell 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 MSSQL의 xp_cmdshell 확장 저장 프로시저가 없습니다.\nMySQL에서는 UDF(User Defined Function) 등을 통해 시스템 명령을 실행할 수 있으나,\n기본적으로 xp_cmdshell과 같은 기능은 제공하지 않습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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
    local DESC="MySQL은 MSSQL Registry Procedure가 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 MSSQL의 Registry 접근 확장 저장 프로시저(xp_regread, xp_regwrite 등)가 없습니다.\nMySQL은 Windows Registry에 접근하는 내장 프로시저를 제공하지 않습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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

    DT="[현재 버전]\nMySQL $DB_VERSION\n\n※ 최신 버전은 MySQL 공식 사이트에서 확인\nhttps://dev.mysql.com/downloads/"

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
    local GENERAL_LOG=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'general_log';" 2>/dev/null)
    local GENERAL_LOG_FILE=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'general_log_file';" 2>/dev/null)

    # slow_query_log 확인
    local SLOW_LOG=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'slow_query_log';" 2>/dev/null)

    # log_error 확인
    local ERROR_LOG=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'log_error';" 2>/dev/null)

    # audit_log 플러그인 확인 (Enterprise Edition)
    local AUDIT_LOG_PLUGIN=$($MYSQL_CMD -e "SHOW PLUGINS;" 2>/dev/null | grep -i "audit_log")
    local AUDIT_LOG_VARS=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'audit_log%';" 2>/dev/null)

    DT="[Audit Log 플러그인 (감사 로그)]\n$AUDIT_LOG_PLUGIN\n$AUDIT_LOG_VARS"
    DT="${DT}\n\n[기타 로깅 설정 (참고용)]\n$GENERAL_LOG\n$GENERAL_LOG_FILE\n$SLOW_LOG\n$ERROR_LOG"
    DT="${DT}\n  ※ general_log: 일반 쿼리 로그 (개발/디버깅용, 감사 로그 아님)"
    DT="${DT}\n  ※ slow_query_log: 느린 쿼리 로그 (성능 분석용)"
    DT="${DT}\n  ※ log_error: 에러 로그"

    local AUDIT_ON=0

    if echo "$AUDIT_LOG_PLUGIN" | grep -qi "ACTIVE"; then
        AUDIT_ON=1
    fi

    if [ "$AUDIT_ON" -eq 1 ]; then
        # audit_log 플러그인 활성화됨
        RES="M"
        DESC="감사 로그(audit_log) 활성화됨 - 백업 여부 확인 필요"
        DT="${DT}\n\n※ audit_log 플러그인이 활성화되어 있습니다."
        DT="${DT}\n※ 주기적인 백업 실시 여부는 인터뷰를 통해 확인하세요."
    else
        RES="N"
        DESC="감사 로그(audit_log)가 비활성화됨"
        DT="${DT}\n\n[취약 사유]"
        DT="${DT}\n- MySQL Enterprise Edition의 audit_log 플러그인이 비활성화 상태입니다."
        DT="${DT}\n- MySQL Community 버전은 audit_log 플러그인을 제공하지 않습니다."
        DT="${DT}\n- Community 버전 사용 시 별도 감사 솔루션 도입을 권장합니다."
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
# MySQL_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : MySQL_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="MySQL"
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
echo " MySQL 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# mysql 클라이언트 확인
MYSQL_CLIENT=$(which mysql 2>/dev/null)
if [ -z "$MYSQL_CLIENT" ]; then
    echo -n "MySQL Client Path (mysql not found): "
    read MYSQL_CLIENT
    if [ ! -x "$MYSQL_CLIENT" ]; then
        echo "[!] mysql 클라이언트를 찾을 수 없습니다."
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

echo -n "Password: "
read -s DB_PASS
echo ""

if [ -z "$DB_PASS" ]; then
    echo "[!] 비밀번호를 입력해주세요."
    exit 1
fi

# MySQL 연결 명령어
MYSQL_CMD="$MYSQL_CLIENT -h $DB_HOST -P $DB_PORT -u $DB_USER -p$DB_PASS -N -s"

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
DB_VERSION=$($MYSQL_CMD -e "SELECT VERSION();" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "[!] MySQL 연결 실패"
    exit 1
fi
echo "[OK] MySQL $DB_VERSION 연결 성공"
echo ""

# MySQL 버전 체크 (8.0 이상 여부)
MAJOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f1)
MINOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f2)
IS_80_OR_HIGHER=0
if [ "$MAJOR_VERSION" -ge 8 ] 2>/dev/null; then
    IS_80_OR_HIGHER=1
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

    # 전체 계정 현황 확인 (인증 플러그인 포함)
    local ALL_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host, plugin,
        CASE WHEN authentication_string='' OR authentication_string IS NULL THEN 'NO' ELSE 'YES' END as has_password,
        account_locked
        FROM mysql.user ORDER BY user;" 2>/dev/null)

    # root 계정 확인
    local ROOT_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host, plugin FROM mysql.user WHERE user='root';" 2>/dev/null)

    # 비밀번호 없는 계정 확인
    local NO_PASS_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL;" 2>/dev/null)

    DT="[전체 계정 현황]\n$ALL_ACCOUNTS\n\n[root 계정]\n$ROOT_ACCOUNTS\n\n[비밀번호 미설정 계정]\n${NO_PASS_ACCOUNTS:-없음}"

    if [ -z "$NO_PASS_ACCOUNTS" ] || [ "$NO_PASS_ACCOUNTS" = "user	host" ]; then
        RES="M"
        DESC="모든 계정에 비밀번호가 설정됨 - 패스워드 정책(복잡도, 만료기간 등) 수동 확인 필요"
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

    # 전체 계정 목록
    local ALL_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host, account_locked FROM mysql.user ORDER BY user;" 2>/dev/null)

    # 익명 계정 확인
    local ANON_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE user='';" 2>/dev/null)

    DT="[계정 목록]\n$ALL_ACCOUNTS\n\n[익명 계정]\n$ANON_ACCOUNTS"

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

    # validate_password 플러그인 확인
    local VALIDATE_PW=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'validate_password%';" 2>/dev/null)

    # 비밀번호 만료 설정 확인
    local PW_EXPIRE=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'default_password_lifetime';" 2>/dev/null)

    DT="[비밀번호 검증 설정]\n$VALIDATE_PW\n\n[비밀번호 만료 설정]\n$PW_EXPIRE"

    # 플러그인 존재 여부 확인
    if ! echo "$VALIDATE_PW" | grep -qi "validate_password"; then
        RES="N"
        DESC="비밀번호 검증 플러그인(validate_password)이 비활성화됨"
        return
    fi

    # 설정값 검증
    local VULN_REASONS=""

    # validate_password.length (또는 validate_password_length) >= 8
    local PW_LENGTH=$(echo "$VALIDATE_PW" | grep -i "length" | awk '{print $2}')
    if [ -n "$PW_LENGTH" ] && [ "$PW_LENGTH" -lt 8 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}비밀번호 최소 길이가 8 미만($PW_LENGTH)\n"
    fi

    # validate_password.policy (또는 validate_password_policy) >= MEDIUM (1)
    local PW_POLICY=$(echo "$VALIDATE_PW" | grep -i "policy" | awk '{print $2}')
    if [ -n "$PW_POLICY" ]; then
        # POLICY: 0=LOW, 1=MEDIUM, 2=STRONG
        # LOW 정책이면 독립적으로 취약 판정
        if [ "$PW_POLICY" == "LOW" ] || [ "$PW_POLICY" == "0" ]; then
            RES="N"
            DESC="비밀번호 정책이 LOW로 설정되어 취약함"
            DT="${DT}\n\n[취약 항목]\nvalidate_password.policy가 LOW로 설정됨 (최소 MEDIUM 이상 권장)"
            return
        fi
    fi

    # validate_password.mixed_case_count >= 1
    local MIXED_CASE=$(echo "$VALIDATE_PW" | grep -i "mixed_case" | awk '{print $2}')
    if [ -n "$MIXED_CASE" ] && [ "$MIXED_CASE" -lt 1 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}대소문자 혼합 요구 미설정(mixed_case_count=$MIXED_CASE)\n"
    fi

    # default_password_lifetime > 0 및 90일 이하 권장
    local PW_LIFETIME=$(echo "$PW_EXPIRE" | awk '{print $2}')
    if [ -n "$PW_LIFETIME" ] && [ "$PW_LIFETIME" -eq 0 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}비밀번호 만료 기간 미설정(lifetime=0)\n"
    elif [ -n "$PW_LIFETIME" ] && [ "$PW_LIFETIME" -gt 90 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}비밀번호 만료 기간이 90일 초과(lifetime=$PW_LIFETIME, 권장: 90일 이하)\n"
    fi

    # validate_password.special_char_count >= 1 (특수문자 요구)
    local SPECIAL_CHAR=$(echo "$VALIDATE_PW" | grep -i "special_char" | awk '{print $2}')
    if [ -n "$SPECIAL_CHAR" ] && [ "$SPECIAL_CHAR" -lt 1 ] 2>/dev/null; then
        VULN_REASONS="${VULN_REASONS}특수문자 요구 미설정(special_char_count=$SPECIAL_CHAR)\n"
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
    local SUPER_USERS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE Super_priv='Y';" 2>/dev/null)

    # ALL PRIVILEGES 보유 계정
    local ALL_PRIV_USERS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE Select_priv='Y' AND Insert_priv='Y' AND Update_priv='Y' AND Delete_priv='Y' AND Create_priv='Y' AND Drop_priv='Y' AND Grant_priv='Y';" 2>/dev/null)

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

    if [ "$IS_80_OR_HIGHER" == "1" ]; then
        local PW_HISTORY=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'password_history';" 2>/dev/null | awk '{print $2}')
        local PW_REUSE_INTERVAL=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'password_reuse_interval';" 2>/dev/null | awk '{print $2}')

        DT="[비밀번호 재사용 제한 설정]\npassword_history: $PW_HISTORY\npassword_reuse_interval: $PW_REUSE_INTERVAL"

        # 둘 다 설정되어야 양호 (AND 조건)
        if [ "$PW_HISTORY" -gt 0 ] 2>/dev/null && [ "$PW_REUSE_INTERVAL" -gt 0 ] 2>/dev/null; then
            RES="Y"
            DESC="비밀번호 재사용 제한이 설정됨 (history: $PW_HISTORY, interval: $PW_REUSE_INTERVAL)"
        else
            RES="N"
            if [ "$PW_HISTORY" -eq 0 ] 2>/dev/null && [ "$PW_REUSE_INTERVAL" -eq 0 ] 2>/dev/null; then
                DESC="비밀번호 재사용 제한이 모두 설정되지 않음"
            elif [ "$PW_HISTORY" -eq 0 ] 2>/dev/null; then
                DESC="password_history가 설정되지 않음 (0)"
            else
                DESC="password_reuse_interval이 설정되지 않음 (0)"
            fi
        fi
    else
        RES="M"
        DESC="MySQL 5.7은 비밀번호 재사용 제한 미지원. 외부 인증 또는 애플리케이션에서 관리 여부 확인 필요"
        DT="[참고]\nMySQL 5.7 이하 버전은 비밀번호 재사용 제한 기능을 네이티브로 지원하지 않습니다.\n외부 인증 모듈 또는 애플리케이션 레벨에서 관리 여부를 확인하세요."
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

    local USER_LIST=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE user != '' ORDER BY user;" 2>/dev/null)

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

    # MySQL 프로세스 사용자 확인
    local MYSQL_PROC=$(ps -ef | grep mysqld | grep -v grep | head -1)
    local PROC_USER=$(echo "$MYSQL_PROC" | awk '{print $1}')

    DT="[MySQL 프로세스]\n$MYSQL_PROC"

    if [ -z "$MYSQL_PROC" ]; then
        RES="N/A"
        DESC="MySQL 프로세스를 찾을 수 없음"
    elif [ "$PROC_USER" == "root" ]; then
        RES="N"
        DESC="MySQL이 root 권한으로 구동 중"
    else
        RES="Y"
        DESC="MySQL이 일반 계정($PROC_USER)으로 구동 중"
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
    local AUTH_PLUGINS=$($MYSQL_CMD -e "SELECT user, host, plugin FROM mysql.user;" 2>/dev/null)

    # 기본 인증 플러그인 확인
    local DEFAULT_AUTH=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'default_authentication_plugin';" 2>/dev/null)

    DT="[계정별 인증 플러그인]\n$AUTH_PLUGINS\n\n[기본 인증 플러그인]\n$DEFAULT_AUTH"

    # mysql_native_password 사용 계정 확인 (시스템 계정 제외)
    # mysql.sys, mysql.session, mysql.infoschema는 시스템 계정으로 제외
    local NATIVE_AUTH=$($MYSQL_CMD -e "
        SELECT CONCAT(user, '@', host) as account, plugin
        FROM mysql.user
        WHERE plugin = 'mysql_native_password'
        AND user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
        AND user != '';" 2>/dev/null)

    # caching_sha2_password 사용 계정 확인
    local SHA2_AUTH=$($MYSQL_CMD -e "
        SELECT CONCAT(user, '@', host) as account, plugin
        FROM mysql.user
        WHERE plugin = 'caching_sha2_password'
        AND user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
        AND user != '';" 2>/dev/null)

    # 취약한 인증 플러그인 확인 (mysql_old_password 등)
    local WEAK_AUTH=$($MYSQL_CMD -e "
        SELECT CONCAT(user, '@', host) as account, plugin
        FROM mysql.user
        WHERE plugin NOT IN ('mysql_native_password', 'caching_sha2_password', 'sha256_password', 'auth_socket', 'unix_socket')
        AND user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
        AND user != ''
        AND plugin != '';" 2>/dev/null)

    if [ -n "$WEAK_AUTH" ] && [ "$WEAK_AUTH" != "account	plugin" ]; then
        RES="N"
        DESC="취약한 인증 플러그인 사용 계정 존재"
        DT="${DT}\n\n[취약 계정 목록 (mysql_old_password 등)]\n$WEAK_AUTH"
    elif [ -n "$NATIVE_AUTH" ] && [ "$NATIVE_AUTH" != "account	plugin" ]; then
        RES="Y"
        DESC="양호 (mysql_native_password 사용 - 전환 권고)"
        DT="${DT}\n\n[mysql_native_password 사용 계정]\n$NATIVE_AUTH\n\n[권고사항]\nmysql_native_password는 SHA-1 기반으로 KISA 권고 보안 강도(112비트 이상)에 미달하여,\ncaching_sha2_password 방식으로의 전환을 권고합니다.\n단, 일부 클라이언트/드라이버에서는 caching_sha2_password를 기본 지원하지 않아\n별도 설정이 필요할 수 있습니다."
    else
        RES="Y"
        DESC="안전한 암호화 알고리즘(caching_sha2_password) 사용 중"
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

    if [ "$IS_80_OR_HIGHER" == "1" ]; then
        # MySQL 8.0.19+ 계정 잠금 정책 확인
        # 활성 계정 수 (시스템 계정 및 잠긴 계정 제외)
        local ACTIVE_USERS=$($MYSQL_CMD -e "
            SELECT COUNT(*) FROM mysql.user
            WHERE user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint')
            AND user != ''
            AND account_locked != 'Y';" 2>/dev/null | tr -d '[:space:]')

        # 잠금 정책이 설정된 계정 (attempts <= 5, lock_days > 0)
        local LOCK_SETTINGS=$($MYSQL_CMD -e "
            SELECT user, host,
                JSON_EXTRACT(User_attributes, '\$.Password_locking.failed_login_attempts') as attempts,
                JSON_EXTRACT(User_attributes, '\$.Password_locking.password_lock_time_days') as lock_days
            FROM mysql.user
            WHERE user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint')
            AND user != ''
            AND account_locked != 'Y';" 2>/dev/null)

        # 취약한 설정 확인 (attempts > 5 또는 attempts = 0 또는 lock_days = 0 또는 설정 없음)
        # failed_login_attempts=0 은 무제한을 의미하므로 취약
        local VULN_USERS=$($MYSQL_CMD -e "
            SELECT CONCAT(user, '@', host) as account,
                COALESCE(JSON_EXTRACT(User_attributes, '\$.Password_locking.failed_login_attempts'), 'null') as attempts,
                COALESCE(JSON_EXTRACT(User_attributes, '\$.Password_locking.password_lock_time_days'), 'null') as lock_days
            FROM mysql.user
            WHERE user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint')
            AND user != ''
            AND account_locked != 'Y'
            AND (
                User_attributes IS NULL
                OR User_attributes = ''
                OR JSON_EXTRACT(User_attributes, '\$.Password_locking.failed_login_attempts') IS NULL
                OR JSON_EXTRACT(User_attributes, '\$.Password_locking.failed_login_attempts') = 0
                OR JSON_EXTRACT(User_attributes, '\$.Password_locking.failed_login_attempts') > 5
                OR JSON_EXTRACT(User_attributes, '\$.Password_locking.password_lock_time_days') IS NULL
                OR JSON_EXTRACT(User_attributes, '\$.Password_locking.password_lock_time_days') <= 0
            );" 2>/dev/null)

        DT="[활성 계정 수]\n$ACTIVE_USERS\n\n[계정별 잠금 정책]\n$LOCK_SETTINGS"

        if [ -n "$VULN_USERS" ]; then
            RES="N"
            DESC="잠금 정책이 미설정되거나 부적절한 계정 존재"
            DT="${DT}\n\n[취약 계정 (attempts=0/무제한, attempts>5, lock_days<=0 또는 미설정)]\n$VULN_USERS\n\n※ 기준: 1 <= failed_login_attempts <= 5, password_lock_time_days > 0"
        elif [ -z "$LOCK_SETTINGS" ] || [ "$ACTIVE_USERS" -eq 0 ] 2>/dev/null; then
            RES="N"
            DESC="로그인 실패 잠금 정책이 설정되지 않음"
        else
            RES="Y"
            DESC="모든 활성 계정에 적절한 잠금 정책 설정됨"
        fi
    else
        # MySQL 5.7.17+ connection_control 플러그인 확인
        local CONN_CONTROL=$($MYSQL_CMD -e "SHOW PLUGINS;" 2>/dev/null | grep -i "connection_control")
        local CONN_VARS=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'connection_control%';" 2>/dev/null)

        DT="[connection_control 플러그인]\n$CONN_CONTROL\n\n[설정값]\n$CONN_VARS"

        if echo "$CONN_CONTROL" | grep -qi "ACTIVE"; then
            # connection_control_failed_connections_threshold 값 확인
            local THRESHOLD=$(echo "$CONN_VARS" | grep -i "threshold" | awk '{print $2}')
            if [ -n "$THRESHOLD" ] && [ "$THRESHOLD" -le 5 ] 2>/dev/null; then
                RES="Y"
                DESC="connection_control 플러그인 활성화 (threshold: $THRESHOLD)"
            else
                RES="N"
                DESC="connection_control threshold 값이 5 초과 또는 미설정"
            fi
        else
            RES="M"
            DESC="MySQL 5.7에서 connection_control 플러그인 설치 여부 확인 필요"
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
    local DESC="원격 접속 제한 정책 수동 확인 필요"

    # bind-address 확인
    local BIND_ADDR=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'bind_address';" 2>/dev/null)

    # 전체 계정의 host 설정 확인
    local ALL_HOSTS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE user != '' ORDER BY user, host;" 2>/dev/null)

    # '%' 호스트 허용 계정 확인
    local REMOTE_ACCOUNTS=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE host='%';" 2>/dev/null)

    DT="[bind_address 설정]\n$BIND_ADDR"
    DT="${DT}\n\n[전체 계정 접속 허용 호스트 현황]\n$ALL_HOSTS"
    DT="${DT}\n\n[모든 호스트 접속 허용 계정 (host='%')]\n${REMOTE_ACCOUNTS:-없음}"
    DT="${DT}\n\n※ 원격 접속 제한은 방화벽, 네트워크 ACL, bind_address 설정 등을 종합적으로 확인해야 합니다."
    DT="${DT}\n※ host='%' 계정이 있더라도 방화벽에서 차단되어 있을 수 있으므로 수동 확인이 필요합니다."

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

    # mysql DB 스키마 권한이 있는 일반 사용자 확인 (SCHEMA_PRIVILEGES)
    local MYSQL_DB_GRANTS=$($MYSQL_CMD -e "
        SELECT DISTINCT GRANTEE
        FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
        WHERE TABLE_SCHEMA = 'mysql'
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    # mysql DB 테이블 권한이 있는 일반 사용자 확인 (TABLE_PRIVILEGES)
    local MYSQL_TABLE_GRANTS=$($MYSQL_CMD -e "
        SELECT DISTINCT GRANTEE, TABLE_NAME, PRIVILEGE_TYPE
        FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES
        WHERE TABLE_SCHEMA = 'mysql'
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mysql.%';" 2>/dev/null)

    DT="[mysql DB 스키마 권한 보유 계정 (root 제외)]\n$MYSQL_DB_GRANTS"
    DT="${DT}\n\n[mysql DB 테이블 권한 보유 계정 (root 제외)]\n$MYSQL_TABLE_GRANTS"

    if [ -z "$MYSQL_DB_GRANTS" ] && [ -z "$MYSQL_TABLE_GRANTS" ]; then
        RES="Y"
        DESC="일반 사용자에게 mysql DB 접근 권한 없음"
    else
        RES="N"
        DESC="일반 사용자에게 mysql DB 접근 권한 존재"
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
    local DESC="MySQL은 Oracle 리스너(Listener) 개념이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 TNS Listener와 같은 별도의 리스너 프로세스가 없습니다.\n리스너 비밀번호 설정은 Oracle 전용 보안 항목입니다."

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
    local DESC="N/A (MySQL은 ODBC/OLE-DB 드라이버 관리가 OS 영역)"

    DT="[N/A 사유]\nMySQL은 데이터베이스 서버이며, ODBC/OLE-DB 데이터 소스 및 드라이버 관리는 클라이언트 OS 영역입니다.\n서버 측에서 점검해야 할 ODBC/OLE-DB 설정이 없으므로, 해당 항목은 적용되지 않습니다.\n\n[참고]\n- ODBC 드라이버: 클라이언트 OS에서 관리 (Windows: ODBC 데이터 원본 관리자)\n- OLE-DB: Windows 클라이언트 전용 기술"

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

    # my.cnf 파일 위치들
    for CNF_PATH in "/etc/my.cnf" "/etc/mysql/my.cnf" "/etc/mysql/mysql.conf.d/mysqld.cnf" "$HOME/.my.cnf"; do
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

            # 권한이 640 또는 600이어야 양호 (그 외에는 취약)
            if [ "$FILE_PERM" != "640" ] && [ "$FILE_PERM" != "600" ]; then
                VULNERABLE_FILES="${VULNERABLE_FILES}${CNF_PATH}${SYMLINK_INFO}: ${FILE_PERM} (권장: 640 또는 600)\n"
            fi
        fi
    done

    if [ -z "$CHECKED_FILES" ]; then
        RES="N/A"
        DESC="설정 파일을 찾을 수 없음"
        DT="my.cnf 파일을 찾을 수 없습니다."
    elif [ -z "$VULNERABLE_FILES" ]; then
        RES="Y"
        DESC="주요 설정 파일 권한이 적절함 (640 또는 600)"
        DT="[파일 권한 현황]\n$CHECKED_FILES\n\n※ 양호 기준: 640 또는 600"
    else
        RES="N"
        DESC="주요 설정 파일에 부적절한 권한 존재 (640 또는 600 필요)"
        DT="[취약 파일]\n$VULNERABLE_FILES\n[전체 파일]\n$CHECKED_FILES\n\n※ 양호 기준: 640 또는 600"
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
    local DESC="MySQL은 Oracle 리스너/trace 파일이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 리스너 로그 및 trace 파일 개념이 없습니다.\nMySQL은 error log, general log, slow query log 등 별도의 로깅 체계를 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MySQL은 Windows 인증 모드를 지원하지 않아 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 MSSQL의 Windows 인증 모드(Integrated Security)를 지원하지 않습니다.\nMySQL은 자체 인증 플러그인(mysql_native_password, caching_sha2_password 등)을 사용합니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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
    local DESC="MySQL은 Oracle AUD$ 테이블이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 AUD\$ 테이블과 같은 감사 테이블이 없습니다.\nMySQL Enterprise Edition은 audit_log 플러그인을 제공하며,\nCommunity Edition은 general_log를 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MySQL은 Oracle PUBLIC Role 개념이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 PUBLIC Role 개념이 없습니다.\nMySQL은 권한을 개별 사용자 또는 역할(Role)에 직접 부여하는 방식을 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MySQL은 Oracle OS_ROLES 파라미터가 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 OS_ROLES, REMOTE_OS_AUTHENT, REMOTE_OS_ROLES 파라미터가 없습니다.\nOS 기반 인증은 MySQL PAM 플러그인 등을 통해 별도로 구성해야 합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MySQL은 Oracle Object Owner 개념이 다르게 적용되어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle과 같은 스키마 기반 Object Owner 개념이 다릅니다.\nMySQL에서는 데이터베이스(스키마) 단위로 권한을 관리하며,\n별도의 Object Owner 제한 파라미터가 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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

    # GRANT 권한 보유 계정 확인 (시스템 계정 제외)
    # debian-sys-maint: Debian/Ubuntu MySQL 서비스 관리용 시스템 계정
    local GRANT_USERS=$($MYSQL_CMD -e "
        SELECT CONCAT(user, '@', host) as account
        FROM mysql.user
        WHERE grant_priv = 'Y'
        AND user NOT IN ('root', 'mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint')
        AND user != '';" 2>/dev/null)

    # SCHEMA_PRIVILEGES에서 IS_GRANTABLE='YES' 확인 (시스템 계정 제외)
    local GRANTABLE_SCHEMA_PRIVS=$($MYSQL_CMD -e "
        SELECT DISTINCT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE
        FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
        WHERE IS_GRANTABLE = 'YES'
        AND GRANTEE NOT LIKE '''root''%'
        AND GRANTEE NOT LIKE '''mysql.%'
        AND GRANTEE NOT LIKE '''debian-sys-maint''%';" 2>/dev/null)

    DT="[GRANT 권한 보유 계정 (시스템 계정 제외)]\n$GRANT_USERS"
    DT="${DT}\n  ※ grant_priv: mysql.user 테이블의 권한 부여 자격 여부 (Y/N)"
    DT="${DT}\n\n[IS_GRANTABLE='YES' 스키마 권한 (시스템 계정 제외)]\n$GRANTABLE_SCHEMA_PRIVS"
    DT="${DT}\n  ※ IS_GRANTABLE (WITH GRANT OPTION): 실제 권한 위임 가능 상태 (YES/NO)"
    DT="${DT}\n\n[제외 계정] root, mysql.sys, mysql.session, mysql.infoschema, debian-sys-maint"

    if [ -z "$GRANT_USERS" ] && [ -z "$GRANTABLE_SCHEMA_PRIVS" ]; then
        RES="Y"
        DESC="일반 사용자에게 GRANT 권한 없음"
    else
        RES="N"
        DESC="일반 사용자에게 GRANT 권한 부여됨"
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
    local DESC="MySQL은 Oracle RESOURCE_LIMIT 파라미터가 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 Oracle의 RESOURCE_LIMIT 파라미터가 없습니다.\nMySQL은 max_connections, max_user_connections 등 별도의 자원 제한 파라미터를 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MySQL은 MSSQL xp_cmdshell 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 MSSQL의 xp_cmdshell 확장 저장 프로시저가 없습니다.\nMySQL에서는 UDF(User Defined Function) 등을 통해 시스템 명령을 실행할 수 있으나,\n기본적으로 xp_cmdshell과 같은 기능은 제공하지 않습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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
    local DESC="MySQL은 MSSQL Registry Procedure가 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMySQL은 MSSQL의 Registry 접근 확장 저장 프로시저(xp_regread, xp_regwrite 등)가 없습니다.\nMySQL은 Windows Registry에 접근하는 내장 프로시저를 제공하지 않습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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

    DT="[현재 버전]\nMySQL $DB_VERSION\n\n※ 최신 버전은 MySQL 공식 사이트에서 확인\nhttps://dev.mysql.com/downloads/"

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
    local GENERAL_LOG=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'general_log';" 2>/dev/null)
    local GENERAL_LOG_FILE=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'general_log_file';" 2>/dev/null)

    # slow_query_log 확인
    local SLOW_LOG=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'slow_query_log';" 2>/dev/null)

    # log_error 확인
    local ERROR_LOG=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'log_error';" 2>/dev/null)

    # audit_log 플러그인 확인 (Enterprise Edition)
    local AUDIT_LOG_PLUGIN=$($MYSQL_CMD -e "SHOW PLUGINS;" 2>/dev/null | grep -i "audit_log")
    local AUDIT_LOG_VARS=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'audit_log%';" 2>/dev/null)

    DT="[Audit Log 플러그인 (감사 로그)]\n$AUDIT_LOG_PLUGIN\n$AUDIT_LOG_VARS"
    DT="${DT}\n\n[기타 로깅 설정 (참고용)]\n$GENERAL_LOG\n$GENERAL_LOG_FILE\n$SLOW_LOG\n$ERROR_LOG"
    DT="${DT}\n  ※ general_log: 일반 쿼리 로그 (개발/디버깅용, 감사 로그 아님)"
    DT="${DT}\n  ※ slow_query_log: 느린 쿼리 로그 (성능 분석용)"
    DT="${DT}\n  ※ log_error: 에러 로그"

    local AUDIT_ON=0

    if echo "$AUDIT_LOG_PLUGIN" | grep -qi "ACTIVE"; then
        AUDIT_ON=1
    fi

    if [ "$AUDIT_ON" -eq 1 ]; then
        # audit_log 플러그인 활성화됨
        RES="M"
        DESC="감사 로그(audit_log) 활성화됨 - 백업 여부 확인 필요"
        DT="${DT}\n\n※ audit_log 플러그인이 활성화되어 있습니다."
        DT="${DT}\n※ 주기적인 백업 실시 여부는 인터뷰를 통해 확인하세요."
    else
        RES="N"
        DESC="감사 로그(audit_log)가 비활성화됨"
        DT="${DT}\n\n[취약 사유]"
        DT="${DT}\n- MySQL Enterprise Edition의 audit_log 플러그인이 비활성화 상태입니다."
        DT="${DT}\n- MySQL Community 버전은 audit_log 플러그인을 제공하지 않습니다."
        DT="${DT}\n- Community 버전 사용 시 별도 감사 솔루션 도입을 권장합니다."
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

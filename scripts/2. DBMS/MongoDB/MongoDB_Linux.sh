#!/bin/bash
#================================================================
# MongoDB_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : MongoDB_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="MongoDB"
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
echo " MongoDB 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# mongosh 또는 mongo 확인
MONGO_CLIENT=$(which mongosh 2>/dev/null)
if [ -z "$MONGO_CLIENT" ]; then
    MONGO_CLIENT=$(which mongo 2>/dev/null)
fi
if [ -z "$MONGO_CLIENT" ]; then
    echo -n "MongoDB Client Path (mongosh/mongo not found): "
    read MONGO_CLIENT
    if [ ! -x "$MONGO_CLIENT" ]; then
        echo "[!] MongoDB 클라이언트를 찾을 수 없습니다."
        exit 1
    fi
fi

# 클라이언트 타입 확인 (mongosh vs mongo)
CLIENT_TYPE="mongo"
if echo "$MONGO_CLIENT" | grep -q "mongosh"; then
    CLIENT_TYPE="mongosh"
fi

# 연결 정보 입력
echo -n "Host (default: localhost): "
read DB_HOST
DB_HOST=${DB_HOST:-localhost}

echo -n "Port (default: 27017): "
read DB_PORT
DB_PORT=${DB_PORT:-27017}

echo -n "Authentication Database (default: admin): "
read AUTH_DB
AUTH_DB=${AUTH_DB:-admin}

echo -n "User (Enter if no auth): "
read DB_USER

DB_PASS=""
if [ -n "$DB_USER" ]; then
    echo -n "Password: "
    read -s DB_PASS
    echo ""
fi

# MongoDB 연결 명령어 구성
if [ -n "$DB_USER" ] && [ -n "$DB_PASS" ]; then
    MONGO_URI="mongodb://$DB_USER:$DB_PASS@$DB_HOST:$DB_PORT/$AUTH_DB"
    MONGO_CMD="$MONGO_CLIENT --quiet --host $DB_HOST --port $DB_PORT -u $DB_USER -p $DB_PASS --authenticationDatabase $AUTH_DB"
else
    MONGO_URI="mongodb://$DB_HOST:$DB_PORT"
    MONGO_CMD="$MONGO_CLIENT --quiet --host $DB_HOST --port $DB_PORT"
fi

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
PING_RESULT=$($MONGO_CMD --eval "db.runCommand({ping:1}).ok" 2>&1)
if [ "$PING_RESULT" != "1" ]; then
    echo "[!] MongoDB 연결 실패: $PING_RESULT"
    exit 1
fi

# 버전 확인
DB_VERSION=$($MONGO_CMD --eval "db.version()" 2>/dev/null | tail -1)
echo "[OK] MongoDB $DB_VERSION 연결 성공"
echo ""

# AUTH 활성화 여부 확인
AUTH_ENABLED=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, authenticationMechanisms:1}).authenticationMechanisms" 2>/dev/null)

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


        # admin 데이터베이스의 사용자 목록 확인
        local ADMIN_USERS=$($MONGO_CMD --eval "db.getSiblingDB('admin').getUsers()" 2>/dev/null)

        # 인증 메커니즘 확인
        local AUTH_MECHS=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, authenticationMechanisms:1})" 2>/dev/null)

        DT="[admin 데이터베이스 사용자]\n$ADMIN_USERS\n\n[인증 메커니즘]\n$AUTH_MECHS"

        # 인증 없이 접속 가능한지 확인
        local NO_AUTH_TEST=$($MONGO_CLIENT --quiet --host $DB_HOST --port $DB_PORT --eval "db.runCommand({ping:1}).ok" 2>&1)

        if [ "$NO_AUTH_TEST" = "1" ] && [ -z "$DB_USER" ]; then
            RES="N"
            DESC="인증 없이 MongoDB에 접속 가능"
            DT="${DT}\n\n[취약 사유]\n인증 없이 MongoDB에 접속 가능합니다.\n--auth 옵션 또는 security.authorization 설정을 활성화하세요."
        elif [ -n "$DB_USER" ]; then
            RES="M"
            DESC="인증이 설정됨 - 비밀번호 복잡도 수동 확인 필요"
        else
            RES="M"
            DESC="인증 상태 수동 확인 필요"
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

    # 모든 데이터베이스의 사용자 목록 확인
    local ALL_DBS=$($MONGO_CMD --eval "db.adminCommand({listDatabases:1}).databases.map(d=>d.name)" 2>/dev/null)
    local USERS_INFO=""

    # admin 사용자 확인
    local ADMIN_USERS=$($MONGO_CMD --eval "JSON.stringify(db.getSiblingDB('admin').getUsers())" 2>/dev/null)
    USERS_INFO="[admin 데이터베이스 사용자]\n$ADMIN_USERS"

    # 시스템 사용자 확인
    local SYSTEM_USERS=$($MONGO_CMD --eval "db.getSiblingDB('admin').system.users.find().toArray().length" 2>/dev/null)

    DT="$USERS_INFO\n\n[전체 사용자 수]\n$SYSTEM_USERS\n\n[데이터베이스 목록]\n$ALL_DBS"

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

    local RES="M"
    local DESC="MongoDB는 자체 비밀번호 정책이 제한적 - 수동 확인 필요"

    DT="[참고 사항]\nMongoDB는 자체적인 비밀번호 복잡도 정책이나 만료 기간 설정 기능이 제한적입니다.\n\n권장 사항:\n1. 강력한 비밀번호 사용 (8자 이상, 대소문자/숫자/특수문자 조합)\n2. LDAP 또는 Kerberos 등 외부 인증 연동 고려\n3. MongoDB Enterprise에서 LDAP 인증 사용 시 LDAP 정책 적용 가능"

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

    # 관리자 역할을 가진 사용자 확인
    local ADMIN_ROLE_USERS=$($MONGO_CMD --eval "
        var users = db.getSiblingDB('admin').system.users.find().toArray();
        var adminUsers = users.filter(function(u) {
            return u.roles.some(function(r) {
                return r.role === 'root' || r.role === 'dbAdminAnyDatabase' ||
                       r.role === 'userAdminAnyDatabase' || r.role === 'readWriteAnyDatabase' ||
                       r.role === '__system';
            });
        });
        JSON.stringify(adminUsers.map(function(u) { return {user: u.user, roles: u.roles}; }), null, 2);
    " 2>/dev/null)

    local ADMIN_COUNT=$($MONGO_CMD --eval "
        var users = db.getSiblingDB('admin').system.users.find().toArray();
        users.filter(function(u) {
            return u.roles.some(function(r) {
                return r.role === 'root' || r.role === 'dbAdminAnyDatabase' ||
                       r.role === 'userAdminAnyDatabase';
            });
        }).length;
    " 2>/dev/null)

    DT="[관리자 권한 사용자 (root, dbAdminAnyDatabase, userAdminAnyDatabase)]\n$ADMIN_ROLE_USERS\n\n[관리자 권한 사용자 수]\n$ADMIN_COUNT"

    if [ -n "$ADMIN_COUNT" ] && [ "$ADMIN_COUNT" -gt 2 ] 2>/dev/null; then
        RES="M"
        DESC="관리자 권한 사용자 ${ADMIN_COUNT}명 - 필요 여부 확인 필요"
    else
        RES="Y"
        DESC="관리자 권한이 최소 사용자에게만 부여됨"
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
    local DESC="MongoDB는 비밀번호 히스토리 관리 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMongoDB는 비밀번호 히스토리를 관리하지 않습니다.\n비밀번호 재사용 제약 기능은 RDBMS 전용 보안 항목입니다."

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

    # 전체 사용자 수 확인
    local TOTAL_USERS=$($MONGO_CMD --eval "db.getSiblingDB('admin').system.users.find().toArray().length" 2>/dev/null)

    # 사용자별 인증 DB 확인
    local USER_DBS=$($MONGO_CMD --eval "
        var users = db.getSiblingDB('admin').system.users.find().toArray();
        users.map(function(u) { return u.user + '@' + u.db; }).join('\\n');
    " 2>/dev/null)

    DT="[전체 사용자 수]\n$TOTAL_USERS\n\n[사용자별 인증 데이터베이스]\n$USER_DBS"

    if [ -z "$TOTAL_USERS" ] || [ "$TOTAL_USERS" -eq 0 ] 2>/dev/null; then
        RES="N"
        DESC="사용자 계정이 설정되지 않음"
    elif [ "$TOTAL_USERS" -eq 1 ] 2>/dev/null; then
        RES="M"
        DESC="사용자가 1명만 존재 - 개별 계정 부여 여부 확인 필요"
    else
        RES="Y"
        DESC="다중 사용자 계정이 설정됨 (${TOTAL_USERS}명)"
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

    # mongod 프로세스 확인
    local MONGO_PROC=$(ps -ef 2>/dev/null | grep "[m]ongod" | head -5)
    local MONGO_USER=$(echo "$MONGO_PROC" | awk '{print $1}' | head -1)

    DT="[MongoDB 프로세스 정보]\n$MONGO_PROC\n\n[실행 사용자]\n${MONGO_USER:-확인불가}"

    if [ -z "$MONGO_USER" ]; then
        RES="M"
        DESC="MongoDB 프로세스를 확인할 수 없음 - 수동 확인 필요"
    elif [ "$MONGO_USER" = "root" ]; then
        RES="N"
        DESC="MongoDB가 root 권한으로 실행 중"
    else
        RES="Y"
        DESC="MongoDB가 일반 사용자($MONGO_USER)로 실행 중"
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
    local TLS_MODE=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, tlsMode:1}).tlsMode" 2>/dev/null)
    local SSL_MODE=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, sslMode:1}).sslMode" 2>/dev/null)

    # 인증 메커니즘 확인
    local AUTH_MECHS=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, authenticationMechanisms:1}).authenticationMechanisms" 2>/dev/null)

    DT="[TLS 설정]\ntlsMode: $TLS_MODE\nsslMode: $SSL_MODE\n\n[인증 메커니즘]\n$AUTH_MECHS"

    # TLS/SSL 설정 확인
    if [ "$TLS_MODE" = "requireTLS" ] || [ "$TLS_MODE" = "preferTLS" ] || \
       [ "$SSL_MODE" = "requireSSL" ] || [ "$SSL_MODE" = "preferSSL" ]; then
        RES="Y"
        DESC="TLS/SSL이 활성화됨"
    elif [ "$TLS_MODE" = "disabled" ] || [ "$SSL_MODE" = "disabled" ] || \
         [ -z "$TLS_MODE" ] || [ "$TLS_MODE" = "undefined" ]; then
        RES="N"
        DESC="TLS/SSL이 비활성화됨 - 평문 통신 사용"
    else
        RES="M"
        DESC="TLS/SSL 설정 수동 확인 필요"
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
    local DESC="MongoDB는 계정 잠금 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMongoDB는 로그인 실패 시 계정 잠금 기능을 제공하지 않습니다.\n로그인 시도 제한은 외부 방화벽이나 fail2ban 등을 활용해야 합니다."

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

    # bindIp 설정 확인
    local BIND_IP=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, 'net.bindIp':1})" 2>/dev/null)

    # 설정 파일에서 bindIp 확인
    local CONFIG_BIND=""
    if [ -f "/etc/mongod.conf" ]; then
        CONFIG_BIND=$(grep -E "^[[:space:]]*bindIp:" /etc/mongod.conf 2>/dev/null)
    fi

    DT="[bindIp 설정 (런타임)]\n$BIND_IP\n\n[설정 파일 bindIp]\n${CONFIG_BIND:-설정파일 없음 또는 bindIp 미설정}"

    # bindIp가 0.0.0.0이거나 없으면 취약
    if echo "$BIND_IP" | grep -qE "0\.0\.0\.0|\*"; then
        RES="N"
        DESC="모든 IP에서 접속 가능 (0.0.0.0)"
    elif echo "$BIND_IP" | grep -qE "127\.0\.0\.1|localhost"; then
        if echo "$BIND_IP" | grep -qE "0\.0\.0\.0|\*"; then
            RES="N"
            DESC="모든 IP에서 접속 가능"
        else
            RES="Y"
            DESC="로컬호스트로만 바인딩 제한됨"
        fi
    else
        RES="M"
        DESC="bindIp 설정 수동 확인 필요"
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
        local DESC="MongoDB는 시스템 테이블 개념이 없어 해당 항목 적용 불가"
        local DT="[N/A 사유]\nMongoDB는 RDBMS가 아닌 Document DB로 전통적인 시스템 테이블 개념이 없습니다.\nMongoDB는 system.* 컬렉션을 통해 메타데이터를 관리합니다."

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
    local DESC="MongoDB는 Oracle Listener 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 Oracle의 리스너(Listener) 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 ODBC/OLE-DB 드라이버가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 ODBC/OLE-DB 드라이버를 사용하지 않습니다.\nMongoDB는 자체 드라이버(MongoDB Driver)를 사용합니다.\n해당 항목은 Windows RDBMS 전용 보안 항목입니다."

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

    # MongoDB 설정 파일 및 데이터 디렉토리 확인
    local COMMON_CONFIGS="/etc/mongod.conf /etc/mongodb.conf"
    local DATA_DIR=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, dbPath:1}).dbPath" 2>/dev/null)

    DT="[설정 확인]\ndbPath: $DATA_DIR\n\n[주요 파일 권한]"

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

    # 데이터 디렉토리 권한 확인
    if [ -d "$DATA_DIR" ]; then
        local DATA_PERM=$(stat -c "%a" "$DATA_DIR" 2>/dev/null)
        local DATA_OWNER=$(stat -c "%U:%G" "$DATA_DIR" 2>/dev/null)
        DT="${DT}\n$DATA_DIR: $DATA_PERM ($DATA_OWNER)"
    fi

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
    local DESC="MongoDB는 Oracle Listener가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 Oracle의 리스너(Listener) 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 Windows 인증 모드가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 MSSQL의 Windows 인증 모드를 지원하지 않습니다.\nMongoDB는 SCRAM, x.509, LDAP, Kerberos 인증을 지원합니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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
    local DESC="MongoDB는 Audit Table이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 RDBMS의 Audit Table 개념이 없습니다.\nMongoDB Enterprise에서는 auditLog 기능을 제공합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 PUBLIC Role이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 RDBMS의 PUBLIC Role 개념이 없습니다.\nMongoDB는 Role-Based Access Control(RBAC)을 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 Oracle OS 인증 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 Oracle의 OS 인증 관련 파라미터가 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 Object Owner 개념이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 RDBMS의 스키마/Object Owner 개념이 없습니다.\nMongoDB는 데이터베이스 레벨의 권한 관리를 사용합니다.\n해당 항목은 RDBMS 전용 보안 항목입니다."

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
    local DESC="MongoDB는 GRANT OPTION이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 RDBMS의 GRANT OPTION 개념이 없습니다.\nMongoDB는 userAdmin 역할을 통해 사용자 관리 권한을 부여합니다.\n해당 항목은 RDBMS 전용 보안 항목입니다."

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
    local DESC="MongoDB는 Oracle RESOURCE_LIMIT 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 Oracle의 RESOURCE_LIMIT 파라미터가 없습니다.\nMongoDB는 maxIncomingConnections, wiredTiger.engineConfig.cacheSizeGB 등\n별도의 자원 제한 파라미터를 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 MSSQL xp_cmdshell 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 MSSQL의 xp_cmdshell 확장 저장 프로시저가 없습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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
    local DESC="MongoDB는 MSSQL Registry Procedure가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 MSSQL의 Registry 접근 확장 저장 프로시저가 없습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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

    # 상세 버전 정보
    local BUILD_INFO=$($MONGO_CMD --eval "db.adminCommand({buildInfo:1}).version" 2>/dev/null)

    DT="[현재 버전]\nMongoDB $DB_VERSION\n\n[빌드 정보]\n$BUILD_INFO\n\n※ 최신 버전은 MongoDB 공식 사이트에서 확인\nhttps://www.mongodb.com/try/download/community"

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

    # systemLog 설정 확인
    local LOG_PATH=""
    if [ -f "/etc/mongod.conf" ]; then
        LOG_PATH=$(grep -A5 "^systemLog:" /etc/mongod.conf 2>/dev/null | grep "path:" | awk '{print $2}')
    fi

    # auditLog 설정 확인 (Enterprise Edition)
    local AUDIT_LOG=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, auditLog:1})" 2>/dev/null)

    # 로그 레벨 확인
    local LOG_LEVEL=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, logLevel:1}).logLevel" 2>/dev/null)

    DT="[systemLog 설정]\npath: ${LOG_PATH:-설정파일에서 확인 불가}\nlogLevel: $LOG_LEVEL\n\n[auditLog 설정 (Enterprise)]\n$AUDIT_LOG"

    # Enterprise Edition의 auditLog 확인
    if echo "$AUDIT_LOG" | grep -qi "destination"; then
        RES="Y"
        DESC="감사 로그(auditLog)가 활성화됨"
    elif [ -n "$LOG_PATH" ]; then
        RES="M"
        DESC="systemLog만 설정됨 - 감사 로그(auditLog) 별도 확인 필요"
        DT="${DT}\n\n※ systemLog는 일반 로그입니다."
        DT="${DT}\n※ 감사 로그(auditLog)는 MongoDB Enterprise Edition에서만 지원됩니다."
        DT="${DT}\n※ Community Edition 사용 시 별도 감사 솔루션 도입을 권장합니다."
    else
        RES="N"
        DESC="로그 설정이 확인되지 않음"
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
# MongoDB_Linux 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : MongoDB_Linux
# 항목  : D-01 ~ D-26 (26개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="MongoDB"
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
echo " MongoDB 보안 진단 스크립트"
echo "============================================================"
echo ""
echo "[연결 정보 입력]"
echo ""

# mongosh 또는 mongo 확인
MONGO_CLIENT=$(which mongosh 2>/dev/null)
if [ -z "$MONGO_CLIENT" ]; then
    MONGO_CLIENT=$(which mongo 2>/dev/null)
fi
if [ -z "$MONGO_CLIENT" ]; then
    echo -n "MongoDB Client Path (mongosh/mongo not found): "
    read MONGO_CLIENT
    if [ ! -x "$MONGO_CLIENT" ]; then
        echo "[!] MongoDB 클라이언트를 찾을 수 없습니다."
        exit 1
    fi
fi

# 클라이언트 타입 확인 (mongosh vs mongo)
CLIENT_TYPE="mongo"
if echo "$MONGO_CLIENT" | grep -q "mongosh"; then
    CLIENT_TYPE="mongosh"
fi

# 연결 정보 입력
echo -n "Host (default: localhost): "
read DB_HOST
DB_HOST=${DB_HOST:-localhost}

echo -n "Port (default: 27017): "
read DB_PORT
DB_PORT=${DB_PORT:-27017}

echo -n "Authentication Database (default: admin): "
read AUTH_DB
AUTH_DB=${AUTH_DB:-admin}

echo -n "User (Enter if no auth): "
read DB_USER

DB_PASS=""
if [ -n "$DB_USER" ]; then
    echo -n "Password: "
    read -s DB_PASS
    echo ""
fi

# MongoDB 연결 명령어 구성
if [ -n "$DB_USER" ] && [ -n "$DB_PASS" ]; then
    MONGO_URI="mongodb://$DB_USER:$DB_PASS@$DB_HOST:$DB_PORT/$AUTH_DB"
    MONGO_CMD="$MONGO_CLIENT --quiet --host $DB_HOST --port $DB_PORT -u $DB_USER -p $DB_PASS --authenticationDatabase $AUTH_DB"
else
    MONGO_URI="mongodb://$DB_HOST:$DB_PORT"
    MONGO_CMD="$MONGO_CLIENT --quiet --host $DB_HOST --port $DB_PORT"
fi

# 연결 테스트
echo ""
echo "[연결 테스트 중...]"
PING_RESULT=$($MONGO_CMD --eval "db.runCommand({ping:1}).ok" 2>&1)
if [ "$PING_RESULT" != "1" ]; then
    echo "[!] MongoDB 연결 실패: $PING_RESULT"
    exit 1
fi

# 버전 확인
DB_VERSION=$($MONGO_CMD --eval "db.version()" 2>/dev/null | tail -1)
echo "[OK] MongoDB $DB_VERSION 연결 성공"
echo ""

# AUTH 활성화 여부 확인
AUTH_ENABLED=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, authenticationMechanisms:1}).authenticationMechanisms" 2>/dev/null)

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


        # admin 데이터베이스의 사용자 목록 확인
        local ADMIN_USERS=$($MONGO_CMD --eval "db.getSiblingDB('admin').getUsers()" 2>/dev/null)

        # 인증 메커니즘 확인
        local AUTH_MECHS=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, authenticationMechanisms:1})" 2>/dev/null)

        DT="[admin 데이터베이스 사용자]\n$ADMIN_USERS\n\n[인증 메커니즘]\n$AUTH_MECHS"

        # 인증 없이 접속 가능한지 확인
        local NO_AUTH_TEST=$($MONGO_CLIENT --quiet --host $DB_HOST --port $DB_PORT --eval "db.runCommand({ping:1}).ok" 2>&1)

        if [ "$NO_AUTH_TEST" = "1" ] && [ -z "$DB_USER" ]; then
            RES="N"
            DESC="인증 없이 MongoDB에 접속 가능"
            DT="${DT}\n\n[취약 사유]\n인증 없이 MongoDB에 접속 가능합니다.\n--auth 옵션 또는 security.authorization 설정을 활성화하세요."
        elif [ -n "$DB_USER" ]; then
            RES="M"
            DESC="인증이 설정됨 - 비밀번호 복잡도 수동 확인 필요"
        else
            RES="M"
            DESC="인증 상태 수동 확인 필요"
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

    # 모든 데이터베이스의 사용자 목록 확인
    local ALL_DBS=$($MONGO_CMD --eval "db.adminCommand({listDatabases:1}).databases.map(d=>d.name)" 2>/dev/null)
    local USERS_INFO=""

    # admin 사용자 확인
    local ADMIN_USERS=$($MONGO_CMD --eval "JSON.stringify(db.getSiblingDB('admin').getUsers())" 2>/dev/null)
    USERS_INFO="[admin 데이터베이스 사용자]\n$ADMIN_USERS"

    # 시스템 사용자 확인
    local SYSTEM_USERS=$($MONGO_CMD --eval "db.getSiblingDB('admin').system.users.find().toArray().length" 2>/dev/null)

    DT="$USERS_INFO\n\n[전체 사용자 수]\n$SYSTEM_USERS\n\n[데이터베이스 목록]\n$ALL_DBS"

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

    local RES="M"
    local DESC="MongoDB는 자체 비밀번호 정책이 제한적 - 수동 확인 필요"

    DT="[참고 사항]\nMongoDB는 자체적인 비밀번호 복잡도 정책이나 만료 기간 설정 기능이 제한적입니다.\n\n권장 사항:\n1. 강력한 비밀번호 사용 (8자 이상, 대소문자/숫자/특수문자 조합)\n2. LDAP 또는 Kerberos 등 외부 인증 연동 고려\n3. MongoDB Enterprise에서 LDAP 인증 사용 시 LDAP 정책 적용 가능"

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

    # 관리자 역할을 가진 사용자 확인
    local ADMIN_ROLE_USERS=$($MONGO_CMD --eval "
        var users = db.getSiblingDB('admin').system.users.find().toArray();
        var adminUsers = users.filter(function(u) {
            return u.roles.some(function(r) {
                return r.role === 'root' || r.role === 'dbAdminAnyDatabase' ||
                       r.role === 'userAdminAnyDatabase' || r.role === 'readWriteAnyDatabase' ||
                       r.role === '__system';
            });
        });
        JSON.stringify(adminUsers.map(function(u) { return {user: u.user, roles: u.roles}; }), null, 2);
    " 2>/dev/null)

    local ADMIN_COUNT=$($MONGO_CMD --eval "
        var users = db.getSiblingDB('admin').system.users.find().toArray();
        users.filter(function(u) {
            return u.roles.some(function(r) {
                return r.role === 'root' || r.role === 'dbAdminAnyDatabase' ||
                       r.role === 'userAdminAnyDatabase';
            });
        }).length;
    " 2>/dev/null)

    DT="[관리자 권한 사용자 (root, dbAdminAnyDatabase, userAdminAnyDatabase)]\n$ADMIN_ROLE_USERS\n\n[관리자 권한 사용자 수]\n$ADMIN_COUNT"

    if [ -n "$ADMIN_COUNT" ] && [ "$ADMIN_COUNT" -gt 2 ] 2>/dev/null; then
        RES="M"
        DESC="관리자 권한 사용자 ${ADMIN_COUNT}명 - 필요 여부 확인 필요"
    else
        RES="Y"
        DESC="관리자 권한이 최소 사용자에게만 부여됨"
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
    local DESC="MongoDB는 비밀번호 히스토리 관리 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMongoDB는 비밀번호 히스토리를 관리하지 않습니다.\n비밀번호 재사용 제약 기능은 RDBMS 전용 보안 항목입니다."

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

    # 전체 사용자 수 확인
    local TOTAL_USERS=$($MONGO_CMD --eval "db.getSiblingDB('admin').system.users.find().toArray().length" 2>/dev/null)

    # 사용자별 인증 DB 확인
    local USER_DBS=$($MONGO_CMD --eval "
        var users = db.getSiblingDB('admin').system.users.find().toArray();
        users.map(function(u) { return u.user + '@' + u.db; }).join('\\n');
    " 2>/dev/null)

    DT="[전체 사용자 수]\n$TOTAL_USERS\n\n[사용자별 인증 데이터베이스]\n$USER_DBS"

    if [ -z "$TOTAL_USERS" ] || [ "$TOTAL_USERS" -eq 0 ] 2>/dev/null; then
        RES="N"
        DESC="사용자 계정이 설정되지 않음"
    elif [ "$TOTAL_USERS" -eq 1 ] 2>/dev/null; then
        RES="M"
        DESC="사용자가 1명만 존재 - 개별 계정 부여 여부 확인 필요"
    else
        RES="Y"
        DESC="다중 사용자 계정이 설정됨 (${TOTAL_USERS}명)"
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

    # mongod 프로세스 확인
    local MONGO_PROC=$(ps -ef 2>/dev/null | grep "[m]ongod" | head -5)
    local MONGO_USER=$(echo "$MONGO_PROC" | awk '{print $1}' | head -1)

    DT="[MongoDB 프로세스 정보]\n$MONGO_PROC\n\n[실행 사용자]\n${MONGO_USER:-확인불가}"

    if [ -z "$MONGO_USER" ]; then
        RES="M"
        DESC="MongoDB 프로세스를 확인할 수 없음 - 수동 확인 필요"
    elif [ "$MONGO_USER" = "root" ]; then
        RES="N"
        DESC="MongoDB가 root 권한으로 실행 중"
    else
        RES="Y"
        DESC="MongoDB가 일반 사용자($MONGO_USER)로 실행 중"
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
    local TLS_MODE=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, tlsMode:1}).tlsMode" 2>/dev/null)
    local SSL_MODE=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, sslMode:1}).sslMode" 2>/dev/null)

    # 인증 메커니즘 확인
    local AUTH_MECHS=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, authenticationMechanisms:1}).authenticationMechanisms" 2>/dev/null)

    DT="[TLS 설정]\ntlsMode: $TLS_MODE\nsslMode: $SSL_MODE\n\n[인증 메커니즘]\n$AUTH_MECHS"

    # TLS/SSL 설정 확인
    if [ "$TLS_MODE" = "requireTLS" ] || [ "$TLS_MODE" = "preferTLS" ] || \
       [ "$SSL_MODE" = "requireSSL" ] || [ "$SSL_MODE" = "preferSSL" ]; then
        RES="Y"
        DESC="TLS/SSL이 활성화됨"
    elif [ "$TLS_MODE" = "disabled" ] || [ "$SSL_MODE" = "disabled" ] || \
         [ -z "$TLS_MODE" ] || [ "$TLS_MODE" = "undefined" ]; then
        RES="N"
        DESC="TLS/SSL이 비활성화됨 - 평문 통신 사용"
    else
        RES="M"
        DESC="TLS/SSL 설정 수동 확인 필요"
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
    local DESC="MongoDB는 계정 잠금 기능이 없어 해당 항목 적용 불가"

    DT="[N/A 사유]\nMongoDB는 로그인 실패 시 계정 잠금 기능을 제공하지 않습니다.\n로그인 시도 제한은 외부 방화벽이나 fail2ban 등을 활용해야 합니다."

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

    # bindIp 설정 확인
    local BIND_IP=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, 'net.bindIp':1})" 2>/dev/null)

    # 설정 파일에서 bindIp 확인
    local CONFIG_BIND=""
    if [ -f "/etc/mongod.conf" ]; then
        CONFIG_BIND=$(grep -E "^[[:space:]]*bindIp:" /etc/mongod.conf 2>/dev/null)
    fi

    DT="[bindIp 설정 (런타임)]\n$BIND_IP\n\n[설정 파일 bindIp]\n${CONFIG_BIND:-설정파일 없음 또는 bindIp 미설정}"

    # bindIp가 0.0.0.0이거나 없으면 취약
    if echo "$BIND_IP" | grep -qE "0\.0\.0\.0|\*"; then
        RES="N"
        DESC="모든 IP에서 접속 가능 (0.0.0.0)"
    elif echo "$BIND_IP" | grep -qE "127\.0\.0\.1|localhost"; then
        if echo "$BIND_IP" | grep -qE "0\.0\.0\.0|\*"; then
            RES="N"
            DESC="모든 IP에서 접속 가능"
        else
            RES="Y"
            DESC="로컬호스트로만 바인딩 제한됨"
        fi
    else
        RES="M"
        DESC="bindIp 설정 수동 확인 필요"
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
        local DESC="MongoDB는 시스템 테이블 개념이 없어 해당 항목 적용 불가"
        local DT="[N/A 사유]\nMongoDB는 RDBMS가 아닌 Document DB로 전통적인 시스템 테이블 개념이 없습니다.\nMongoDB는 system.* 컬렉션을 통해 메타데이터를 관리합니다."

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
    local DESC="MongoDB는 Oracle Listener 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 Oracle의 리스너(Listener) 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 ODBC/OLE-DB 드라이버가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 ODBC/OLE-DB 드라이버를 사용하지 않습니다.\nMongoDB는 자체 드라이버(MongoDB Driver)를 사용합니다.\n해당 항목은 Windows RDBMS 전용 보안 항목입니다."

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

    # MongoDB 설정 파일 및 데이터 디렉토리 확인
    local COMMON_CONFIGS="/etc/mongod.conf /etc/mongodb.conf"
    local DATA_DIR=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, dbPath:1}).dbPath" 2>/dev/null)

    DT="[설정 확인]\ndbPath: $DATA_DIR\n\n[주요 파일 권한]"

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

    # 데이터 디렉토리 권한 확인
    if [ -d "$DATA_DIR" ]; then
        local DATA_PERM=$(stat -c "%a" "$DATA_DIR" 2>/dev/null)
        local DATA_OWNER=$(stat -c "%U:%G" "$DATA_DIR" 2>/dev/null)
        DT="${DT}\n$DATA_DIR: $DATA_PERM ($DATA_OWNER)"
    fi

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
    local DESC="MongoDB는 Oracle Listener가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 Oracle의 리스너(Listener) 개념이 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 Windows 인증 모드가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 MSSQL의 Windows 인증 모드를 지원하지 않습니다.\nMongoDB는 SCRAM, x.509, LDAP, Kerberos 인증을 지원합니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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
    local DESC="MongoDB는 Audit Table이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 RDBMS의 Audit Table 개념이 없습니다.\nMongoDB Enterprise에서는 auditLog 기능을 제공합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 PUBLIC Role이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 RDBMS의 PUBLIC Role 개념이 없습니다.\nMongoDB는 Role-Based Access Control(RBAC)을 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 Oracle OS 인증 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 Oracle의 OS 인증 관련 파라미터가 없습니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 Object Owner 개념이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 RDBMS의 스키마/Object Owner 개념이 없습니다.\nMongoDB는 데이터베이스 레벨의 권한 관리를 사용합니다.\n해당 항목은 RDBMS 전용 보안 항목입니다."

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
    local DESC="MongoDB는 GRANT OPTION이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 RDBMS의 GRANT OPTION 개념이 없습니다.\nMongoDB는 userAdmin 역할을 통해 사용자 관리 권한을 부여합니다.\n해당 항목은 RDBMS 전용 보안 항목입니다."

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
    local DESC="MongoDB는 Oracle RESOURCE_LIMIT 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 Oracle의 RESOURCE_LIMIT 파라미터가 없습니다.\nMongoDB는 maxIncomingConnections, wiredTiger.engineConfig.cacheSizeGB 등\n별도의 자원 제한 파라미터를 사용합니다.\n해당 항목은 Oracle 전용 보안 항목입니다."

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
    local DESC="MongoDB는 MSSQL xp_cmdshell 기능이 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 MSSQL의 xp_cmdshell 확장 저장 프로시저가 없습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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
    local DESC="MongoDB는 MSSQL Registry Procedure가 없어 해당 항목 적용 불가"
    local DT="[N/A 사유]\nMongoDB는 MSSQL의 Registry 접근 확장 저장 프로시저가 없습니다.\n해당 항목은 MSSQL 전용 보안 항목입니다."

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

    # 상세 버전 정보
    local BUILD_INFO=$($MONGO_CMD --eval "db.adminCommand({buildInfo:1}).version" 2>/dev/null)

    DT="[현재 버전]\nMongoDB $DB_VERSION\n\n[빌드 정보]\n$BUILD_INFO\n\n※ 최신 버전은 MongoDB 공식 사이트에서 확인\nhttps://www.mongodb.com/try/download/community"

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

    # systemLog 설정 확인
    local LOG_PATH=""
    if [ -f "/etc/mongod.conf" ]; then
        LOG_PATH=$(grep -A5 "^systemLog:" /etc/mongod.conf 2>/dev/null | grep "path:" | awk '{print $2}')
    fi

    # auditLog 설정 확인 (Enterprise Edition)
    local AUDIT_LOG=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, auditLog:1})" 2>/dev/null)

    # 로그 레벨 확인
    local LOG_LEVEL=$($MONGO_CMD --eval "db.adminCommand({getParameter:1, logLevel:1}).logLevel" 2>/dev/null)

    DT="[systemLog 설정]\npath: ${LOG_PATH:-설정파일에서 확인 불가}\nlogLevel: $LOG_LEVEL\n\n[auditLog 설정 (Enterprise)]\n$AUDIT_LOG"

    # Enterprise Edition의 auditLog 확인
    if echo "$AUDIT_LOG" | grep -qi "destination"; then
        RES="Y"
        DESC="감사 로그(auditLog)가 활성화됨"
    elif [ -n "$LOG_PATH" ]; then
        RES="M"
        DESC="systemLog만 설정됨 - 감사 로그(auditLog) 별도 확인 필요"
        DT="${DT}\n\n※ systemLog는 일반 로그입니다."
        DT="${DT}\n※ 감사 로그(auditLog)는 MongoDB Enterprise Edition에서만 지원됩니다."
        DT="${DT}\n※ Community Edition 사용 시 별도 감사 솔루션 도입을 권장합니다."
    else
        RES="N"
        DESC="로그 설정이 확인되지 않음"
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
